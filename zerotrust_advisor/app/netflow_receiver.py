"""UDP NetFlow v9 / IPFIX receiver service. Same shape as the syslog
receiver — source-IP allow-list, atomic health status, batched writes — but
decoding is template-based rather than line-based; see netflow_decode.py.
"""
from __future__ import annotations

import signal
import socket
import time

from app.config import load_config
from app.db import connect, prune
from app.health import HealthReporter
from app.netflow_decode import TemplateCache, decode_packet

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
    health = HealthReporter(config.health_dir, "netflow")
    allowed = set(config.allowed_sources)
    templates = TemplateCache()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", config.netflow_port))
    sock.settimeout(1.0)

    health.update(accepted=0, rejected=0, decoded_flows=0, last_event_at=None)

    last_prune = time.time()

    while _running:
        try:
            data, (source_ip, _port) = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break

        if allowed and source_ip not in allowed:
            health.increment("rejected")
            continue

        health.increment("accepted")
        now = time.time()
        flows = decode_packet(data, source_ip, templates, now=now)

        for flow in flows:
            conn.execute(
                """INSERT INTO events_flow
                   (ts_start, ts_end, src_ip, dst_ip, src_port, dst_port, proto,
                    bytes, packets, exporter_ip, received_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    flow.ts_start,
                    flow.ts_end,
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    flow.proto,
                    flow.bytes,
                    flow.packets,
                    source_ip,
                    now,
                ),
            )

        if flows:
            # Committed once per packet, not batched across packets: this
            # connection is one of several independent writers sharing the
            # database file, and holding a transaction open between
            # exports (which, on a quiet home network, could be minutes)
            # starves every other writer waiting on the same SQLite write
            # lock. All flows from one packet still land in one commit.
            conn.commit()
            health.increment("decoded_flows", by=len(flows))
            health.update(last_event_at=now)

        if now - last_prune > _PRUNE_INTERVAL_SECONDS:
            prune(conn, config.retention_days, now)
            last_prune = now

    conn.commit()
    sock.close()


if __name__ == "__main__":
    main()
