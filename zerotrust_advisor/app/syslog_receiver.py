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

from app.analysis.noise_categories import CATEGORY_KEYS, classify_unparsed_line
from app.config import load_config
from app.db import connect, prune
from app.firewall_parse import UnparsableLine, parse_firewall_line
from app.health import HealthReporter, read_health

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

    # Counters carry forward from the previous run's health file rather than
    # resetting to zero, so a routine add-on restart doesn't make it look
    # like traffic stopped arriving — the underlying data (and the coverage
    # checks built on it) were never actually affected by the restart.
    previous = read_health(config.health_dir, "syslog") or {}
    health.update(
        accepted=previous.get("accepted", 0),
        rejected=previous.get("rejected", 0),
        parsed=previous.get("parsed", 0),
        unparsed=previous.get("unparsed", 0),
        last_event_at=previous.get("last_event_at"),
        **{f"noise_{key}": previous.get(f"noise_{key}", 0) for key in CATEGORY_KEYS},
    )

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
            category = classify_unparsed_line(line)
            if category:
                # Counted by category, never the line itself — this is
                # what lets a setup recommendation later say *which* router
                # logging option is worth turning down.
                health.increment(f"noise_{category}")
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
        # Committed immediately, not batched: this connection is one of
        # several independent writers sharing the database file (the other
        # receivers, the web process), and holding a transaction open
        # between UDP packets — which, on a quiet home network, could be
        # a long time — starves every other writer waiting on the same
        # SQLite write lock. A firewall log line is small; there's nothing
        # worth batching here.
        conn.commit()
        health.increment("parsed")
        health.update(last_event_at=now)

        if now - last_prune > _PRUNE_INTERVAL_SECONDS:
            prune(conn, config.retention_days, now)
            last_prune = now

    conn.commit()
    sock.close()


if __name__ == "__main__":
    main()
