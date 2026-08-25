"""Setup & Settings screen: live per-service health, the coverage/gap
warnings that answer "what can this add-on actually see right now," and
every configurable option — one page, two tabs, since both are really the
same "get this add-on working" task from the user's point of view.

Settings persist through the Supervisor API (see supervisor.py) so they
show up identically in the normal Configuration tab; the remote-LLM and
UniFi API keys never do — they only ever touch /data/secrets, never the
options store, never a log line.
"""
from __future__ import annotations

import logging
import time

from flask import Blueprint, current_app, jsonify, render_template, request

from app.analysis.coverage import CoverageInputs, evaluate_coverage
from app.analysis.direction import INTERNAL_INTERNAL, classify_direction
from app.analysis.network_map import NetworkMap, build_network_map
from app.config import load_config, read_secret, remove_secret, write_secret
from app.health import read_health
from app.supervisor import get_host_ip
from app.unifi.capability_probe import probe
from app.unifi.client import UnifiClientAPI, UnifiError, UnifiUnreachable
from app.unifi.sync import load_probe_report
from app.web.db_context import get_db
from app.web.supervisor import restart_self, update_options

logger = logging.getLogger(__name__)

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


def _status_context(config, conn) -> dict:
    now = time.time()
    # "web" isn't listed here — its uptime is self-evident from this page
    # having loaded at all, so a self-reported health file would be redundant.
    services = ["syslog", "netflow", "mdns"]
    health = {service: read_health(config.health_dir, service) for service in services}
    warnings = evaluate_coverage(_gather_coverage_inputs(conn, config, now))
    host_ip = get_host_ip()
    return {
        "health": health,
        "warnings": warnings,
        "now": now,
        "host_ip": host_ip,
        "router_target_host": host_ip or "this add-on's host",
    }


def _lines(raw: str) -> list[str]:
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _api_key_error(key: str) -> str | None:
    """A real UniFi API key is plain ASCII; anything else is virtually
    always a copy-paste accident (a smart-quote, an em dash from
    surrounding label text) rather than an intentional key character —
    catching it here, before it's saved or sent anywhere, gives a clear
    reason instead of a cryptic encoding failure showing up later against
    a real network call (see client.py's UnicodeEncodeError handling,
    kept as a backstop for whatever reaches it some other way)."""
    if not key.isascii():
        return "This doesn't look like a valid API key — it contains a character outside plain ASCII. Check you copied only the key itself, with nothing extra around it."
    return None


def _report_to_json(report) -> dict:
    return {
        "checked_at": report.checked_at,
        "reachable": report.reachable,
        "site_id": report.site_id,
        "any_capability_ok": report.any_capability_ok,
        "capabilities": [
            {"key": c.key, "label": c.label, "ok": c.ok, "detail": c.detail} for c in report.capabilities
        ],
    }


def _settings_context(conn, saved: bool, restarting: bool, unifi_api_key_error: str | None) -> dict:
    return {
        "config": current_app.config["ZTA_CONFIG"],
        "saved": saved,
        "restarting": restarting,
        "unifi_has_key": bool(read_secret("unifi_api_key")),
        "unifi_last_probe": load_probe_report(conn),
        "unifi_api_key_error": unifi_api_key_error,
    }


@setup_bp.route("/setup")
def setup_page():
    config = current_app.config["ZTA_CONFIG"]
    conn = get_db()
    return render_template(
        "setup.html",
        active_tab="status",
        **_status_context(config, conn),
        **_settings_context(conn, saved=False, restarting=False, unifi_api_key_error=None),
    )


@setup_bp.route("/settings", methods=["POST"])
def save_settings():
    form = request.form

    api_key = form.get("llm_api_key", "").strip()
    if api_key:
        write_secret("llm_api_key", api_key)

    unifi_api_key = form.get("unifi_api_key", "").strip()
    unifi_api_key_error = None
    if unifi_api_key:
        unifi_api_key_error = _api_key_error(unifi_api_key)
        if unifi_api_key_error is None:
            write_secret("unifi_api_key", unifi_api_key)
        # Invalid: deliberately not saved — better to keep whatever worked
        # before (or nothing) than to persist a key that can never work.
    elif "unifi_api_key_clear" in form:
        # Typing a new key always wins over clearing — if both happened
        # (shouldn't, the checkbox is meant to be used on its own) treat it
        # as "replace", not "replace then immediately delete".
        remove_secret("unifi_api_key")

    update_options(
        {
            "syslog_port": int(form.get("syslog_port", 514)),
            "netflow_port": int(form.get("netflow_port", 2055)),
            "allowed_sources": _lines(form.get("allowed_sources", "")),
            "network_labels": _lines(form.get("network_labels", "")),
            "retention_days": int(form.get("retention_days", 90)),
            "min_recurring_days": int(form.get("min_recurring_days", 3)),
            "ignore_own_receiver_traffic": "ignore_own_receiver_traffic" in form,
            "enable_mdns_classification": "enable_mdns_classification" in form,
            "llm_mode": form.get("llm_mode", "local"),
            "llm_remote_base_url": form.get("llm_remote_base_url", "").strip(),
            "llm_model_path": form.get("llm_model_path", "").strip(),
            "unifi_enabled": "unifi_enabled" in form,
            "unifi_host": form.get("unifi_host", "").strip(),
            "unifi_verify_tls": "unifi_verify_tls" in form,
            "unifi_apply_mode": form.get("unifi_apply_mode", "manual"),
            "display_timezone_utc": "display_timezone_utc" in form,
            "ignore_unifi_console_traffic": "ignore_unifi_console_traffic" in form,
        }
    )

    current_app.config["ZTA_CONFIG"] = load_config()

    restarting = True
    try:
        restart_self()
    except Exception:
        # Saved options are real either way — Supervisor has them for the
        # next start regardless. Only the "takes effect immediately"
        # convenience is at risk here, so a hiccup calling the restart API
        # shouldn't turn a successful save into an error response.
        logger.exception("failed to trigger self-restart after settings save")
        restarting = False

    config = current_app.config["ZTA_CONFIG"]
    conn = get_db()
    return render_template(
        "setup.html",
        active_tab="settings",
        **_status_context(config, conn),
        **_settings_context(conn, saved=True, restarting=restarting, unifi_api_key_error=unifi_api_key_error),
    )


@setup_bp.route("/settings/unifi/test", methods=["POST"])
def test_unifi_connection():
    """Tests against whatever is in the form right now — host/verify-TLS
    from the request, and the API key from the request if one was typed,
    otherwise the already-saved secret. Nothing here is persisted; this is
    "can I connect", not "save and connect". See app/unifi/capability_probe.py
    for what "capability" means and why it's checked per-endpoint rather
    than as one pass/fail answer.
    """
    form = request.form
    host = form.get("unifi_host", "").strip()
    if not host:
        return jsonify({"error": "missing_host"}), 400

    api_key = form.get("unifi_api_key", "").strip() or read_secret("unifi_api_key")
    if not api_key:
        return jsonify({"error": "missing_api_key"}), 400

    key_error = _api_key_error(api_key)
    if key_error:
        return jsonify({"error": "invalid_api_key", "detail": key_error}), 400

    verify_tls = "unifi_verify_tls" in form

    try:
        client = UnifiClientAPI(host=host, api_key=api_key, verify_tls=verify_tls)
        report = probe(client)
    except (UnifiError, UnifiUnreachable) as exc:
        # probe() itself already catches these around every individual call
        # it makes — reaching here means something unexpected escaped that,
        # so report it rather than 500ing.
        return jsonify({"error": "probe_failed", "detail": str(exc)}), 502
    except Exception as exc:  # noqa: BLE001 - deliberately broad
        # A 500 here would hand the browser an HTML error page, which the
        # frontend's response.json() call can't parse — surfacing as an
        # opaque "something went wrong" with no way to tell what actually
        # broke. Always answer in JSON instead, even for a bug this code
        # didn't anticipate.
        return jsonify({"error": "unexpected", "detail": str(exc)}), 500

    return jsonify(_report_to_json(report))
