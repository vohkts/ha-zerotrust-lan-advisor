"""Traffic screen: a plain, structured view of what's actually been seen —
identified networks, hosts, the most common flows, and a sample of recent
distinct ones. Reads only the parsed, structured event tables (never raw
syslog text, which the receivers discard by design) and shows real local
IPs/hostnames — this page never leaves the box, so the pseudonymization
used for LLM calls doesn't apply here; showing the admin their own network
plainly is the point.
"""
from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass

from flask import Blueprint, current_app, render_template

from app.analysis.direction import count_directions
from app.analysis.known_ports import PROTO_NAMES, describe_port
from app.analysis.netlabels import label_for_ip, parse_network_labels
from app.web.db_context import get_db

traffic_bp = Blueprint("traffic", __name__)

_WINDOW_SECONDS = 7 * 86400
_MAX_ROWS_PER_TABLE = 20000
_TOP_FLOWS_LIMIT = 20
_RECENT_EXAMPLES_LIMIT = 100
_TOP_HOSTS_LIMIT = 50


@dataclass(frozen=True)
class _Event:
    ts: float
    src_ip: str
    dst_ip: str
    proto: int
    dst_port: int | None


def _load_events(conn, since: float) -> list[_Event]:
    """Newest first, each source bounded independently so a burst on one
    receiver can't starve the other out of the page entirely."""
    fw_rows = conn.execute(
        "SELECT ts, src_ip, dst_ip, proto, dst_port FROM events_firewall "
        "WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
        (since, _MAX_ROWS_PER_TABLE),
    ).fetchall()
    flow_rows = conn.execute(
        "SELECT ts_start, src_ip, dst_ip, proto, dst_port FROM events_flow "
        "WHERE ts_start >= ? ORDER BY ts_start DESC LIMIT ?",
        (since, _MAX_ROWS_PER_TABLE),
    ).fetchall()
    events = [_Event(*row) for row in fw_rows] + [_Event(*row) for row in flow_rows]
    events.sort(key=lambda e: e.ts, reverse=True)
    return events


def _load_identities(conn) -> dict[str, dict]:
    rows = conn.execute("SELECT ip, hostname, vendor, device_class, class_confidence FROM identities").fetchall()
    identities: dict[str, dict] = {}
    for ip, hostname, vendor, device_class, confidence in rows:
        if ip:
            identities[ip] = {
                "hostname": hostname,
                "vendor": vendor,
                "device_class": device_class,
                "confidence": confidence,
            }
    return identities


def _flow_row(src, dst, proto, port, count, last_seen, labels, identities) -> dict:
    return {
        "src": src,
        "src_network": label_for_ip(src, labels),
        "src_class": (identities.get(src) or {}).get("device_class"),
        "dst": dst,
        "dst_network": label_for_ip(dst, labels),
        "dst_class": (identities.get(dst) or {}).get("device_class"),
        "proto": PROTO_NAMES.get(proto, str(proto)),
        "port": port,
        "port_hint": describe_port(proto, port),
        "count": count,
        "last_seen": last_seen,
    }


def _build_network_rows(labels, events: list[_Event]) -> list[dict]:
    rows = []
    for entry in labels:
        hosts: set[str] = set()
        event_count = 0
        for e in events:
            src_match = label_for_ip(e.src_ip, labels) == entry.label
            dst_match = label_for_ip(e.dst_ip, labels) == entry.label
            if src_match:
                hosts.add(e.src_ip)
            if dst_match:
                hosts.add(e.dst_ip)
            if src_match or dst_match:
                event_count += 1
        rows.append({"label": entry.label, "cidr": str(entry.network), "hosts": len(hosts), "events": event_count})
    rows.sort(key=lambda r: -r["events"])
    return rows


def _build_host_rows(labels, identities, events: list[_Event]) -> list[dict]:
    counts: Counter = Counter()
    last_seen: dict[str, float] = {}
    first_seen: dict[str, float] = {}
    for e in events:  # events is newest-first
        for ip in (e.src_ip, e.dst_ip):
            counts[ip] += 1
            last_seen.setdefault(ip, e.ts)
            first_seen[ip] = e.ts  # overwritten every time; final value is the oldest in-window

    rows = []
    for ip, count in counts.most_common(_TOP_HOSTS_LIMIT):
        info = identities.get(ip) or {}
        rows.append(
            {
                "ip": ip,
                "network": label_for_ip(ip, labels),
                "device_class": info.get("device_class") or "Unclassified",
                "confidence": info.get("confidence") or "low",
                "events": count,
                "first_seen": first_seen.get(ip),
                "last_seen": last_seen.get(ip),
            }
        )
    return rows


def _build_flow_tables(labels, identities, events: list[_Event]) -> tuple[list[dict], list[dict]]:
    counts: Counter = Counter()
    last_seen: dict[tuple, float] = {}
    for e in events:  # newest-first
        key = (e.src_ip, e.dst_ip, e.proto, e.dst_port)
        counts[key] += 1
        last_seen.setdefault(key, e.ts)

    top_flows = [
        _flow_row(*key, count, last_seen[key], labels, identities) for key, count in counts.most_common(_TOP_FLOWS_LIMIT)
    ]

    seen: set[tuple] = set()
    recent_examples = []
    for e in events:
        key = (e.src_ip, e.dst_ip, e.proto, e.dst_port)
        if key in seen:
            continue
        seen.add(key)
        recent_examples.append(_flow_row(*key, counts[key], e.ts, labels, identities))
        if len(recent_examples) >= _RECENT_EXAMPLES_LIMIT:
            break

    return top_flows, recent_examples


@traffic_bp.route("/traffic")
def traffic_page():
    config = current_app.config["ZTA_CONFIG"]
    conn = get_db()
    now = time.time()
    since = now - _WINDOW_SECONDS

    labels = parse_network_labels(list(config.network_labels))
    events = _load_events(conn, since)
    identities = _load_identities(conn)

    direction_counts = count_directions([(e.src_ip, e.dst_ip) for e in events])
    network_rows = _build_network_rows(labels, events)
    host_rows = _build_host_rows(labels, identities, events)
    top_flows, recent_examples = _build_flow_tables(labels, identities, events)

    return render_template(
        "traffic.html",
        total_events=len(events),
        direction_counts=direction_counts,
        network_rows=network_rows,
        host_rows=host_rows,
        top_flows=top_flows,
        recent_examples=recent_examples,
        window_days=_WINDOW_SECONDS // 86400,
    )
