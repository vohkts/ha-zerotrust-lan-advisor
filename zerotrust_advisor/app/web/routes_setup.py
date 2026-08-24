"""Setup screen: live per-service health, and the coverage/gap warnings
that answer "what can this add-on actually see right now."
"""
from __future__ import annotations

import time

from flask import Blueprint, current_app, render_template

from app.analysis.coverage import CoverageInputs, evaluate_coverage
from app.analysis.direction import INTERNAL_INTERNAL, classify_direction
from app.analysis.network_map import NetworkMap, build_network_map
from app.health import read_health
from app.supervisor import get_host_ip
from app.web.db_context import get_db

setup_bp = Blueprint("setup", __name__)

_WINDOW_SECONDS = 7 * 86400
_MAX_ROWS_SCANNED = 5000  # bounds the inter-VLAN scan below; fine for Stage 1's scale


def _inter_vlan_count(rows, network_map: NetworkMap) -> int:
    """Compares discovered network *keys* directly (interface names or
    inferred prefixes) rather than display labels — two different networks
    are still two different networks whether or not either has a friendly
    name yet. An IP nothing was ever discovered for isn't counted; we can't
    claim to know it crossed a network boundary."""
    count = 0
    for src_ip, dst_ip in rows:
        src_key = network_map.ip_to_key.get(src_ip)
        dst_key = network_map.ip_to_key.get(dst_ip)
        if src_key and dst_key and src_key != dst_key:
            count += 1
    return count


def _gather_coverage_inputs(conn, config, now: float) -> CoverageInputs:
    since = now - _WINDOW_SECONDS

    last_fw = conn.execute("SELECT MAX(ts) FROM events_firewall").fetchone()[0]
    last_flow = conn.execute("SELECT MAX(ts_start) FROM events_flow").fetchone()[0]

    syslog_health = read_health(config.health_dir, "syslog") or {}
    netflow_health = read_health(config.health_dir, "netflow") or {}

    fw_rows = conn.execute(
        "SELECT src_ip, dst_ip FROM events_firewall WHERE ts >= ? LIMIT ?", (since, _MAX_ROWS_SCANNED)
    ).fetchall()
    flow_rows = conn.execute(
        "SELECT src_ip, dst_ip FROM events_flow WHERE ts_start >= ? LIMIT ?", (since, _MAX_ROWS_SCANNED)
    ).fetchall()
    all_rows = fw_rows + flow_rows
    internal_internal_matches = sum(
        1 for src, dst in all_rows if classify_direction(src, dst) == INTERNAL_INTERNAL
    )
    network_map = build_network_map(conn, since=since)

    return CoverageInputs(
        now=now,
        last_firewall_event_at=last_fw,
        last_flow_event_at=last_flow,
        rejected_syslog_count=syslog_health.get("rejected", 0),
        rejected_flow_count=netflow_health.get("rejected", 0),
        inter_vlan_firewall_matches=_inter_vlan_count(fw_rows, network_map),
        inter_vlan_flow_matches=_inter_vlan_count(flow_rows, network_map),
        total_matches=len(all_rows),
        internal_internal_matches=internal_internal_matches,
    )


@setup_bp.route("/setup")
def setup_page():
    config = current_app.config["ZTA_CONFIG"]
    conn = get_db()
    now = time.time()

    # "web" isn't listed here — its uptime is self-evident from this page
    # having loaded at all, so a self-reported health file would be redundant.
    services = ["syslog", "netflow", "mdns"]
    health = {service: read_health(config.health_dir, service) for service in services}
    warnings = evaluate_coverage(_gather_coverage_inputs(conn, config, now))
    host_ip = get_host_ip()

    return render_template(
        "setup.html",
        health=health,
        warnings=warnings,
        now=now,
        config=config,
        host_ip=host_ip,
        router_target_host=host_ip or "this add-on's host",
    )
