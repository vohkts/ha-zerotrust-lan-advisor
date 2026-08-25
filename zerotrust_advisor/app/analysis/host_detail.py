"""On-demand behavior summary for a single host, for the Traffic screen's
expandable Hosts row: total events, top ports, top flow partners, and
recent distinct flows. Pure aggregation over already-parsed events — no
LLM involved here (see app/llm/prompts.py's device-guess prompt, built
from this module's output, for that separate on-demand piece).
"""
from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass, field

from app.analysis.known_ports import PROTO_NAMES, describe_port

_TOP_N = 8
_RECENT_FLOWS_LIMIT = 20


@dataclass(frozen=True)
class HostDetail:
    ip: str
    event_count: int
    first_seen: float | None
    last_seen: float | None
    top_ports: list[dict] = field(default_factory=list)  # [{proto, port, port_hint, count}]
    top_partners: list[tuple[str, int]] = field(default_factory=list)  # [(other_ip, count)]
    recent_flows: list[dict] = field(default_factory=list)  # [{src, dst, proto, port, port_hint, count}]


def load_host_detail(conn: sqlite3.Connection, ip: str, since: float) -> HostDetail:
    fw_rows = conn.execute(
        "SELECT ts, src_ip, dst_ip, proto, dst_port FROM events_firewall "
        "WHERE ts >= ? AND (src_ip = ? OR dst_ip = ?) ORDER BY ts DESC",
        (since, ip, ip),
    ).fetchall()
    flow_rows = conn.execute(
        "SELECT ts_start, src_ip, dst_ip, proto, dst_port FROM events_flow "
        "WHERE ts_start >= ? AND (src_ip = ? OR dst_ip = ?) ORDER BY ts_start DESC",
        (since, ip, ip),
    ).fetchall()
    events = sorted([*fw_rows, *flow_rows], key=lambda e: e[0], reverse=True)

    if not events:
        return HostDetail(ip=ip, event_count=0, first_seen=None, last_seen=None)

    port_counts: Counter = Counter()
    partner_counts: Counter = Counter()
    flow_counts: Counter = Counter()
    first_seen = events[-1][0]  # oldest, since events is newest-first
    last_seen = events[0][0]

    for ts, src, dst, proto, port in events:
        port_counts[(proto, port)] += 1
        partner_counts[dst if src == ip else src] += 1
        flow_counts[(src, dst, proto, port)] += 1

    top_ports = [
        {"proto": PROTO_NAMES.get(proto, str(proto)), "port": port, "port_hint": describe_port(proto, port), "count": count}
        for (proto, port), count in port_counts.most_common(_TOP_N)
    ]

    seen_flows: set[tuple] = set()
    recent_flows = []
    for ts, src, dst, proto, port in events:
        key = (src, dst, proto, port)
        if key in seen_flows:
            continue
        seen_flows.add(key)
        recent_flows.append(
            {
                "src": src,
                "dst": dst,
                "proto": PROTO_NAMES.get(proto, str(proto)),
                "port": port,
                "port_hint": describe_port(proto, port),
                "count": flow_counts[key],
            }
        )
        if len(recent_flows) >= _RECENT_FLOWS_LIMIT:
            break

    return HostDetail(
        ip=ip,
        event_count=len(events),
        first_seen=first_seen,
        last_seen=last_seen,
        top_ports=top_ports,
        top_partners=partner_counts.most_common(_TOP_N),
        recent_flows=recent_flows,
    )
