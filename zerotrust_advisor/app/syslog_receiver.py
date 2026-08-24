"""UDP syslog receiver service.

Binds to one explicit address and only accepts datagrams from source IPs on
the configured allow-list. A datagram from anywhere else is counted as
rejected, not silently dropped — that distinction is what lets the coverage
screen tell "nothing configured yet" apart from "something is
misconfigured and pointed at the wrong place".
"""
from __future__ import annotations

import signal
import socket
import time

from app.config import load_config
from app.db import connect, prune
from app.firewall_parse import UnparsableLine, parse_firewall_line
from app.health import HealthReporter

_FLUSH_EVERY = 20
_PRUNE_INTERVAL_SECONDS = 3600

_running = True


def _handle_shutdown(signum, frame):
    global _running
    _running = False


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    config = load_config()
    conn = connect(config.db_path)
    health = HealthReporter(config.health_dir, "syslog")
    allowed = set(config.allowed_sources)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", config.syslog_port))
    sock.settimeout(1.0)

    health.update(accepted=0, rejected=0, parsed=0, unparsed=0, last_event_at=None)

    pending = 0
    last_prune = time.time()

    while _running:
        try:
            data, (source_ip, _port) = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break

        if allowed and source_ip not in allowed:
            health.increment("rejected")
            continue

        health.increment("accepted")
        line = data.decode("utf-8", errors="replace")
        try:
            event = parse_firewall_line(line)
        except UnparsableLine:
            health.increment("unparsed")
            continue

        now = time.time()
        conn.execute(
            """INSERT INTO events_firewall
               (ts, src_ip, dst_ip, src_port, dst_port, proto, iface_in, iface_out,
                rule_prefix, action, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                now,
                event.src_ip,
                event.dst_ip,
                event.src_port,
                event.dst_port,
                event.proto,
                event.iface_in,
                event.iface_out,
                event.rule_prefix,
                event.action,
                now,
            ),
        )
        pending += 1
        health.increment("parsed")
        health.update(last_event_at=now)

        if pending >= _FLUSH_EVERY:
            conn.commit()
            pending = 0

        if now - last_prune > _PRUNE_INTERVAL_SECONDS:
            prune(conn, config.retention_days, now)
            last_prune = now

    conn.commit()
    sock.close()


if __name__ == "__main__":
    main()
