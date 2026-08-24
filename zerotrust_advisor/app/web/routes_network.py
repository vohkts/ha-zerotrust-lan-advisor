"""Network screen: a read-only view of what UniFi itself reports — zones,
firewall policies, devices, connected clients — plus the cross-reference
findings in app/unifi/checks.py. Feature-flagged: this whole page is a
plain "not set up" state unless the integration is enabled and at least one
capability from the last probe actually worked (see
app/unifi/capability_probe.py). Nothing here is UniFi-specific plumbing
leaking into the rest of the UI — every other page renders identically
whether or not this is configured.
"""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template

from app.unifi import sync
from app.web.db_context import get_db

network_bp = Blueprint("network", __name__)


def unifi_available(config, conn) -> bool:
    if not config.unifi_enabled:
        return False
    report = sync.load_probe_report(conn)
    return bool(report and report["any_capability_ok"])


def _load_zones(conn) -> list[dict]:
    rows = conn.execute("SELECT id, name, fetched_at FROM unifi_zones ORDER BY name").fetchall()
    return [{"id": r[0], "name": r[1], "fetched_at": r[2]} for r in rows]


def _load_policies(conn) -> list[dict]:
    rows = conn.execute(
        """SELECT p.id, p.name, p.enabled, p.action, p.protocol, z1.name, z2.name, p.logging_enabled
           FROM unifi_policies p
           LEFT JOIN unifi_zones z1 ON z1.id = p.source_zone_id
           LEFT JOIN unifi_zones z2 ON z2.id = p.destination_zone_id
           ORDER BY p.enabled DESC, p.name"""
    ).fetchall()
    return [
        {
            "id": r[0],
            "name": r[1],
            "enabled": bool(r[2]),
            "action": r[3],
            "protocol": r[4],
            "source_zone": r[5] or "unknown",
            "destination_zone": r[6] or "unknown",
            "logging_enabled": None if r[7] is None else bool(r[7]),
        }
        for r in rows
    ]


def _load_devices(conn) -> list[dict]:
    rows = conn.execute("SELECT id, name, model, mac, ip, state FROM unifi_devices ORDER BY name").fetchall()
    return [{"id": r[0], "name": r[1], "model": r[2], "mac": r[3], "ip": r[4], "state": r[5]} for r in rows]


def _load_clients(conn) -> list[dict]:
    rows = conn.execute("SELECT id, name, mac, ip, network_id FROM unifi_clients ORDER BY name").fetchall()
    return [{"id": r[0], "name": r[1], "mac": r[2], "ip": r[3], "network_id": r[4]} for r in rows]


@network_bp.route("/network")
def network_page():
    config = current_app.config["ZTA_CONFIG"]
    conn = get_db()
    probe = sync.load_probe_report(conn)
    available = unifi_available(config, conn)

    if not available:
        return render_template("network.html", available=False, unifi_enabled=config.unifi_enabled, probe=probe)

    policies = _load_policies(conn)
    return render_template(
        "network.html",
        available=True,
        unifi_enabled=True,
        probe=probe,
        zones=_load_zones(conn),
        policies=policies,
        devices=_load_devices(conn),
        clients=_load_clients(conn),
        logging_off_count=sum(1 for p in policies if p["enabled"] and p["logging_enabled"] is False),
    )


@network_bp.route("/network/refresh", methods=["POST"])
def refresh_now():
    conn = get_db()
    config = current_app.config["ZTA_CONFIG"]
    report = sync.refresh(conn, config)
    if report is None:
        return jsonify({"status": "not_configured"}), 409
    return jsonify({"status": "ok", "any_capability_ok": report.any_capability_ok})
