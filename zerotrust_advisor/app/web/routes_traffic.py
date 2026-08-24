"""Traffic screen: a plain, structured view of what's actually been seen —
auto-discovered networks, hosts, the most common flows, and a sample of
recent distinct ones. Reads only the parsed, structured event tables
(never raw syslog text, which the receivers discard by design) and shows
real local IPs/hostnames — this page never leaves the box, so the
pseudonymization used for LLM calls doesn't apply here; showing the admin
their own network plainly is the point.

Networks are discovered from traffic itself (see network_map.py) — no
manual subnet/VLAN entry required. A friendly name is an optional label on
top of a discovery, never a prerequisite for it.
"""
from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass

from flask import Blueprint, current_app, jsonify, render_template, request

from app.analysis.direction import count_directions
from app.analysis.known_ports import PROTO_NAMES, describe_port
from app.analysis.netlabels import parse_network_labels
from app.analysis.network_map import NetworkMap, build_network_map, load_friendly_names, resolve_label, set_friendly_name
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


def _flow_row(src, dst, proto, port, count, last_seen, network_map, friendly_names, manual_labels, identities) -> dict:
    return {
        "src": src,
        "src_network": resolve_label(src, network_map, friendly_names, manual_labels),
        "src_class": (identities.get(src) or {}).get("device_class"),
        "dst": dst,
        "dst_network": resolve_label(dst, network_map, friendly_names, manual_labels),
        "dst_class": (identities.get(dst) or {}).get("device_class"),
        "proto": PROTO_NAMES.get(proto, str(proto)),
        "port": port,
        "port_hint": describe_port(proto, port),
        "count": count,
        "last_seen": last_seen,
    }


def _build_network_rows(network_map: NetworkMap, friendly_names: dict[str, str]) -> list[dict]:
    # network_map.networks is already sorted by event volume, descending.
    return [
        {
            "key": net.key,
            "kind": net.kind,
            "display_name": friendly_names.get(net.key, net.key),
            "hosts": len(net.hosts),
            "events": net.event_count,
            "first_seen": net.first_seen,
            "last_seen": net.last_seen,
        }
        for net in network_map.networks
    ]


def _build_host_rows(network_map, friendly_names, manual_labels, identities, events: list[_Event]) -> list[dict]:
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
                "network": resolve_label(ip, network_map, friendly_names, manual_labels),
                "device_class": info.get("device_class") or "Unclassified",
                "confidence": info.get("confidence") or "low",
                "events": count,
                "first_seen": first_seen.get(ip),
                "last_seen": last_seen.get(ip),
            }
        )
    return rows


def _build_flow_tables(network_map, friendly_names, manual_labels, identities, events: list[_Event]) -> tuple[list[dict], list[dict]]:
    counts: Counter = Counter()
    last_seen: dict[tuple, float] = {}
    for e in events:  # newest-first
        key = (e.src_ip, e.dst_ip, e.proto, e.dst_port)
        counts[key] += 1
        last_seen.setdefault(key, e.ts)

    top_flows = [
        _flow_row(*key, count, last_seen[key], network_map, friendly_names, manual_labels, identities)
        for key, count in counts.most_common(_TOP_FLOWS_LIMIT)
    ]

    seen: set[tuple] = set()
    recent_examples = []
    for e in events:
        key = (e.src_ip, e.dst_ip, e.proto, e.dst_port)
        if key in seen:
            continue
        seen.add(key)
        recent_examples.append(
            _flow_row(*key, counts[key], e.ts, network_map, friendly_names, manual_labels, identities)
        )
        if len(recent_examples) >= _RECENT_EXAMPLES_LIMIT:
            break

    return top_flows, recent_examples


@traffic_bp.route("/traffic")
def traffic_page():
    config = current_app.config["ZTA_CONFIG"]
    conn = get_db()
    now = time.time()
    since = now - _WINDOW_SECONDS

    manual_labels = parse_network_labels(list(config.network_labels))
    network_map = build_network_map(conn, since=since)
    friendly_names = load_friendly_names(conn)
    events = _load_events(conn, since)
    identities = _load_identities(conn)

    direction_counts = count_directions([(e.src_ip, e.dst_ip) for e in events])
    network_rows = _build_network_rows(network_map, friendly_names)
    host_rows = _build_host_rows(network_map, friendly_names, manual_labels, identities, events)
    top_flows, recent_examples = _build_flow_tables(network_map, friendly_names, manual_labels, identities, events)

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


@traffic_bp.route("/traffic/rename", methods=["POST"])
def rename_network():
    discovery_key = request.form.get("discovery_key", "").strip()
    friendly_name = request.form.get("friendly_name", "")
    if not discovery_key:
        return jsonify({"error": "missing discovery_key"}), 400
    set_friendly_name(get_db(), discovery_key, friendly_name)
    return jsonify({"status": "ok"})
