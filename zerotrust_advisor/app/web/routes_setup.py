"""Setup screen: live per-service health, and the coverage/gap warnings
that answer "what can this add-on actually see right now."
"""
from __future__ import annotations

import time

from flask import Blueprint, current_app, render_template

from app.analysis.coverage import CoverageInputs, evaluate_coverage
from app.analysis.netlabels import label_for_ip, parse_network_labels
from app.health import read_health

setup_bp = Blueprint("setup", __name__)

_WINDOW_SECONDS = 7 * 86400
_MAX_ROWS_SCANNED = 5000  # bounds the inter-VLAN scan below; fine for Stage 1's scale


def _inter_vlan_count(rows, labels) -> int:
    count = 0
    for src_ip, dst_ip in rows:
        src_label = label_for_ip(src_ip, labels)
        dst_label = label_for_ip(dst_ip, labels)
        # Only counts as "inter-VLAN" if both sides matched a *configured*
        # label — an IP that fell back to itself hasn't been placed on a
        # network yet, so we can't claim to know it crossed one.
        if src_label != dst_label and src_label != src_ip and dst_label != dst_ip:
            count += 1
    return count


def _gather_coverage_inputs(conn, config, now: float) -> CoverageInputs:
    since = now - _WINDOW_SECONDS
    labels = parse_network_labels(list(config.network_labels))

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

    return CoverageInputs(
        now=now,
        last_firewall_event_at=last_fw,
        last_flow_event_at=last_flow,
        rejected_syslog_count=syslog_health.get("rejected", 0),
        rejected_flow_count=netflow_health.get("rejected", 0),
        inter_vlan_firewall_matches=_inter_vlan_count(fw_rows, labels),
        inter_vlan_flow_matches=_inter_vlan_count(flow_rows, labels),
    )


@setup_bp.route("/setup")
def setup_page():
    config = current_app.config["ZTA_CONFIG"]
    conn = current_app.config["ZTA_DB"]
    now = time.time()

    services = ["syslog", "netflow", "mdns", "web"]
    health = {service: read_health(config.health_dir, service) for service in services}
    warnings = evaluate_coverage(_gather_coverage_inputs(conn, config, now))

    return render_template("setup.html", health=health, warnings=warnings, now=now, config=config)
