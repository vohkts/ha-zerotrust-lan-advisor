"""On-demand behavior summary for a single host, for the Traffic screen's
expandable Hosts row: total events, top ports, top flow partners, and
recent distinct flows. Pure aggregation over already-parsed events — no
LLM involved here (see app/llm/prompts.py's device-guess prompt, built
from this module's output, for that separate on-demand piece).

Unlike the main Traffic page (which deliberately shows everything, own-
receiver traffic included — that filtering is LLM-recommendation-only, see
engine.py), this view excludes it: found live on the add-on's own host,
where syslog-forwarding to this add-on's receiver port dominated the
summary at 3.75 million events, drowning out anything actually informative
about what kind of device it is. That exclusion only matters for firewall
events (a receiver port is a logging concept, not something NetFlow
exports would report a match against). The UniFi-console-traffic exclusion
does match the Traffic page's own behavior, applied to both sources there.
"""
from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass, field

from app.analysis.known_ports import PROTO_NAMES, describe_port
from app.analysis.noise import is_own_receiver_traffic

_TOP_N = 8
_RECENT_FLOWS_LIMIT = 20
_MAX_ROWS = 20000  # a busy host (e.g. this add-on's own) can have millions of matching rows


@dataclass(frozen=True)
class HostDetail:
    ip: str
    event_count: int
    event_count_capped: bool
    first_seen: float | None
    last_seen: float | None
    top_ports: list[dict] = field(default_factory=list)  # [{proto, port, port_hint, count}]
    top_partners: list[tuple[str, int]] = field(default_factory=list)  # [(other_ip, count)]
    recent_flows: list[dict] = field(default_factory=list)  # [{src, dst, proto, port, port_hint, count}]


def _query_one_side(conn: sqlite3.Connection, table: str, ts_col: str, side_col: str, ip: str, since: float, limit: int):
    return conn.execute(
        f"SELECT {ts_col}, src_ip, dst_ip, proto, dst_port FROM {table} "  # noqa: S608 -- table/columns are fixed literals, never user input
        f"WHERE {side_col} = ? AND {ts_col} >= ? ORDER BY {ts_col} DESC LIMIT ?",
        (ip, since, limit),
    ).fetchall()


def load_host_detail(
    conn: sqlite3.Connection,
    ip: str,
    since: float,
    *,
    host_ip: str | None = None,
    syslog_port: int = 514,
    netflow_port: int = 2055,
    unifi_console_host: str | None = None,
) -> HostDetail:
    # Two separately-indexed queries (one per side) instead of one
    # "src_ip = ? OR dst_ip = ?" -- confirmed live that this still took
    # 15s+ even after adding a plain index on each column, because ORDER
    # BY ts still has to sort *every* match before LIMIT applies for an OR
    # condition. A compound (ip, ts) index per side lets each query alone
    # scan already in ts order and stop as soon as it has _MAX_ROWS; the
    # merge-and-re-slice below is a cheap in-memory step over at most
    # 2 * _MAX_ROWS rows, not a query the database has to plan around.
    fw_rows = _query_one_side(conn, "events_firewall", "ts", "src_ip", ip, since, _MAX_ROWS)
    fw_rows += _query_one_side(conn, "events_firewall", "ts", "dst_ip", ip, since, _MAX_ROWS)
    fw_rows.sort(key=lambda r: r[0], reverse=True)
    event_count_capped = len(fw_rows) >= _MAX_ROWS
    fw_rows = fw_rows[:_MAX_ROWS]
    fw_rows = [
        r for r in fw_rows
        if not is_own_receiver_traffic(r[2], r[4], host_ip, syslog_port, netflow_port)
        and not (unifi_console_host and (r[1] == unifi_console_host or r[2] == unifi_console_host))
    ]

    flow_rows = _query_one_side(conn, "events_flow", "ts_start", "src_ip", ip, since, _MAX_ROWS)
    flow_rows += _query_one_side(conn, "events_flow", "ts_start", "dst_ip", ip, since, _MAX_ROWS)
    flow_rows.sort(key=lambda r: r[0], reverse=True)
    event_count_capped = event_count_capped or len(flow_rows) >= _MAX_ROWS
    flow_rows = flow_rows[:_MAX_ROWS]
    if unifi_console_host:
        flow_rows = [r for r in flow_rows if r[1] != unifi_console_host and r[2] != unifi_console_host]

    events = sorted([*fw_rows, *flow_rows], key=lambda e: e[0], reverse=True)

    if not events:
        return HostDetail(ip=ip, event_count=0, event_count_capped=False, first_seen=None, last_seen=None)

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
        event_count_capped=event_count_capped,
        first_seen=first_seen,
        last_seen=last_seen,
        top_ports=top_ports,
        top_partners=partner_counts.most_common(_TOP_N),
        recent_flows=recent_flows,
    )
