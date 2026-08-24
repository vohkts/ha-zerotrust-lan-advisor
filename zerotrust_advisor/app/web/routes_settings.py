"""Settings screen. Non-secret options round-trip through the Supervisor
API (see supervisor.py) so they show up identically in the normal
Configuration tab; the remote-LLM API key never does — it only ever
touches /data/secrets, never the options store, never a log line.
"""
from __future__ import annotations

from flask import Blueprint, current_app, render_template, request

from app.config import load_config, write_secret
from app.web.supervisor import update_options

settings_bp = Blueprint("settings", __name__)


def _lines(raw: str) -> list[str]:
    return [line.strip() for line in raw.splitlines() if line.strip()]


@settings_bp.route("/settings", methods=["GET"])
def settings_page():
    return render_template("settings.html", config=current_app.config["ZTA_CONFIG"], saved=False)


@settings_bp.route("/settings", methods=["POST"])
def save_settings():
    form = request.form

    api_key = form.get("llm_api_key", "").strip()
    if api_key:
        write_secret("llm_api_key", api_key)

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
        }
    )

    current_app.config["ZTA_CONFIG"] = load_config()
    return render_template("settings.html", config=current_app.config["ZTA_CONFIG"], saved=True)
