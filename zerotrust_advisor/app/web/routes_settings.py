"""Settings screen. Non-secret options round-trip through the Supervisor
API (see supervisor.py) so they show up identically in the normal
Configuration tab; the remote-LLM and UniFi API keys never do — they only
ever touch /data/secrets, never the options store, never a log line.
"""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

from app.config import load_config, read_secret, remove_secret, write_secret
from app.unifi.capability_probe import probe
from app.unifi.client import UnifiClientAPI, UnifiError, UnifiUnreachable
from app.unifi.sync import load_probe_report
from app.web.db_context import get_db
from app.web.supervisor import update_options

settings_bp = Blueprint("settings", __name__)


def _lines(raw: str) -> list[str]:
    return [line.strip() for line in raw.splitlines() if line.strip()]


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


@settings_bp.route("/settings", methods=["GET"])
def settings_page():
    conn = get_db()
    return render_template(
        "settings.html",
        config=current_app.config["ZTA_CONFIG"],
        saved=False,
        unifi_has_key=bool(read_secret("unifi_api_key")),
        unifi_last_probe=load_probe_report(conn),
    )


@settings_bp.route("/settings", methods=["POST"])
def save_settings():
    form = request.form

    api_key = form.get("llm_api_key", "").strip()
    if api_key:
        write_secret("llm_api_key", api_key)

    unifi_api_key = form.get("unifi_api_key", "").strip()
    if unifi_api_key:
        write_secret("unifi_api_key", unifi_api_key)
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
        }
    )

    current_app.config["ZTA_CONFIG"] = load_config()
    conn = get_db()
    return render_template(
        "settings.html",
        config=current_app.config["ZTA_CONFIG"],
        saved=True,
        unifi_has_key=bool(read_secret("unifi_api_key")),
        unifi_last_probe=load_probe_report(conn),
    )


@settings_bp.route("/settings/unifi/test", methods=["POST"])
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
