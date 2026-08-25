"""Settings screen. Non-secret options round-trip through the Supervisor
API (see supervisor.py) so they show up identically in the normal
Configuration tab; the remote-LLM and UniFi API keys never do — they only
ever touch /data/secrets, never the options store, never a log line.
"""
from __future__ import annotations

import logging

from flask import Blueprint, current_app, jsonify, render_template, request

from app.config import load_config, read_secret, remove_secret, write_secret
from app.unifi.capability_probe import probe
from app.unifi.client import UnifiClientAPI, UnifiError, UnifiUnreachable
from app.unifi.sync import load_probe_report
from app.web.db_context import get_db
from app.web.supervisor import restart_self, update_options

logger = logging.getLogger(__name__)

settings_bp = Blueprint("settings", __name__)


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


@settings_bp.route("/settings", methods=["GET"])
def settings_page():
    conn = get_db()
    return render_template(
        "settings.html",
        config=current_app.config["ZTA_CONFIG"],
        saved=False,
        restarting=False,
        unifi_has_key=bool(read_secret("unifi_api_key")),
        unifi_last_probe=load_probe_report(conn),
        unifi_api_key_error=None,
    )


@settings_bp.route("/settings", methods=["POST"])
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

    conn = get_db()
    return render_template(
        "settings.html",
        config=current_app.config["ZTA_CONFIG"],
        saved=True,
        restarting=restarting,
        unifi_has_key=bool(read_secret("unifi_api_key")),
        unifi_last_probe=load_probe_report(conn),
        unifi_api_key_error=unifi_api_key_error,
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
