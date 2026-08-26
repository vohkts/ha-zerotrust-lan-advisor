"""Optional, passive device-discovery service: mDNS for hostnames, the
kernel ARP table for MACs. This is the only service that needs host
networking (multicast doesn't cross a Docker bridge), which is why it's
disabled by default — everything else in the add-on works fine without it,
just with lower-confidence device classification.

Both signals are best-effort. mDNS only sees devices that are currently
announcing themselves, and the ARP table only has entries for hosts this
container has actually exchanged link-layer traffic with — neither is a
full inventory. Stage 2 (a future, optional read-only UniFi API connection)
is the real fix for that; this is a free improvement in the meantime.
"""
from __future__ import annotations

import signal
import socket
import struct
import time

from app.config import load_config
from app.db import connect
from app.health import HealthReporter, read_health
from app.sanitize.classify import classify

_MDNS_GROUP = "224.0.0.251"
_MDNS_PORT = 5353
_ARP_SCAN_INTERVAL_SECONDS = 60

_running = True


def _handle_shutdown(signum, frame):
    global _running
    _running = False


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Reads a (possibly compressed) DNS name starting at `offset`, and
    returns it along with the offset immediately after it in the original
    packet — which, for a compressed name, is *not* the same as the
    position the compression pointer jumped to."""
    labels: list[str] = []
    end_offset: int | None = None
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if end_offset is None:
                end_offset = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), (end_offset if end_offset is not None else offset)


def parse_mdns_answers(packet: bytes) -> list[tuple[str, str]]:
    """Extracts (hostname, ipv4) pairs from A records in an mDNS message's
    answer section. Anything that doesn't parse cleanly is dropped rather
    than guessed at, same discipline as the firewall/flow parsers."""
    if len(packet) < 12:
        return []
    try:
        _id, _flags, qdcount, ancount, _ns, _ar = struct.unpack_from(">HHHHHH", packet, 0)
        offset = 12
        for _ in range(qdcount):
            _, offset = _read_name(packet, offset)
            offset += 4  # qtype + qclass

        results: list[tuple[str, str]] = []
        for _ in range(ancount):
            name, offset = _read_name(packet, offset)
            rtype, _rclass, _ttl, rdlength = struct.unpack_from(">HHIH", packet, offset)
            offset += 10
            rdata = packet[offset : offset + rdlength]
            offset += rdlength
            if rtype == 1 and rdlength == 4:  # A record
                hostname = name[: -len(".local")] if name.endswith(".local") else name
                results.append((hostname, ".".join(str(b) for b in rdata)))
        return results
    except (struct.error, IndexError):
        return []


def _read_arp_table() -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)  # header line
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = parts[3]
    except OSError:
        pass
    return table


def _upsert_identity(conn, ip: str, hostname: str, mac: str | None, now: float) -> None:
    classification = classify(hostname=hostname, mac=mac)
    device_key = mac or ip
    conn.execute(
        """INSERT INTO identities (device_key, ip, mac, hostname, vendor, device_class, class_confidence,
                                    first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(device_key) DO UPDATE SET
               ip=excluded.ip, mac=excluded.mac, hostname=excluded.hostname, vendor=excluded.vendor,
               -- Never let a re-sync downgrade a better classification back
               -- to a worse one (e.g. the analysis pass's port-based guess,
               -- see classify_from_ports -- an mDNS re-broadcast carries no
               -- new signal and would otherwise stomp it back to
               -- Unclassified on every announce).
               device_class = CASE WHEN
                   COALESCE(CASE class_confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END, 0)
                   > COALESCE(CASE excluded.class_confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END, 0)
                 THEN device_class ELSE excluded.device_class END,
               class_confidence = CASE WHEN
                   COALESCE(CASE class_confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END, 0)
                   > COALESCE(CASE excluded.class_confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END, 0)
                 THEN class_confidence ELSE excluded.class_confidence END,
               last_seen=excluded.last_seen""",
        (
            device_key,
            ip,
            mac,
            hostname,
            classification.vendor,
            classification.device_class,
            classification.confidence,
            now,
            now,
        ),
    )


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    config = load_config()
    if not config.enable_mdns_classification:
        # Sleep rather than exit so s6 doesn't treat a disabled feature as a crash loop.
        while _running:
            time.sleep(3600)
        return

    conn = connect(config.db_path)
    health = HealthReporter(config.health_dir, "mdns")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", _MDNS_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(_MDNS_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(1.0)

    # Carries forward from the previous run rather than resetting to zero —
    # see syslog_receiver.py for why.
    previous = read_health(config.health_dir, "mdns") or {}
    health.update(hostnames_seen=previous.get("hostnames_seen", 0), last_event_at=previous.get("last_event_at"))
    last_arp_scan = 0.0
    arp_table: dict[str, str] = {}

    while _running:
        try:
            data, _addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break

        answers = parse_mdns_answers(data)
        if not answers:
            continue

        now = time.time()
        if now - last_arp_scan > _ARP_SCAN_INTERVAL_SECONDS:
            arp_table = _read_arp_table()
            last_arp_scan = now

        for hostname, ip in answers:
            _upsert_identity(conn, ip, hostname, arp_table.get(ip), now)

        conn.commit()
        health.increment("hostnames_seen", by=len(answers))
        health.update(last_event_at=now)

    conn.commit()
    sock.close()


if __name__ == "__main__":
    main()
