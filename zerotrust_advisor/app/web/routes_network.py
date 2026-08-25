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

import json
import time
from datetime import datetime

from flask import Blueprint, current_app, jsonify, render_template, request

from app.sanitize.oui import lookup_vendor
from app.unifi import sync
from app.web.db_context import get_db

network_bp = Blueprint("network", __name__)

_POLICY_EVENT_WINDOW_SECONDS = 7 * 86400


def unifi_available(config, conn) -> bool:
    if not config.unifi_enabled:
        return False
    report = sync.load_probe_report(conn)
    return bool(report and report["any_capability_ok"])


def _load_networks(conn) -> list[dict]:
    rows = conn.execute(
        """SELECT n.id, n.name, n.vlan_id, n.subnet,
                  (SELECT COUNT(*) FROM unifi_clients c WHERE c.network_id = n.id) AS client_count
           FROM unifi_networks n ORDER BY n.name"""
    ).fetchall()
    return [{"id": r[0], "name": r[1], "vlan_id": r[2], "subnet": r[3], "client_count": r[4]} for r in rows]


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


def _parse_connected_at(value) -> float | None:
    """The API's connectedAt is ISO 8601 (e.g. "2024-01-01T00:00:00Z");
    stored as-is in the database, parsed here for sorting/staleness/display.
    A value that doesn't parse is treated the same as one that's missing —
    reject, don't guess."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _load_clients(conn) -> list[dict]:
    """The Integration API's clients endpoint is specifically "list
    *connected* clients" — it already only returns clients that are online
    right now, there is no separate offline/historical list mixed in. Hid
    anything with an old connectedAt as "stale" before this, on the wrong
    assumption that connectedAt meant "last seen" — corrected live: it's
    when the *current* session started, so a wired desktop or printer with
    a long-running, perfectly healthy connection has an old connectedAt
    and is very much online. Show everything the API returns; connectedAt
    is informational only now, not a filter."""
    rows = conn.execute(
        "SELECT id, name, mac, ip, network_id, connected_at, client_type FROM unifi_clients ORDER BY name"
    ).fetchall()
    return [
        {
            "id": r[0], "name": r[1], "mac": r[2], "ip": r[3], "network_id": r[4],
            "connected_at": _parse_connected_at(r[5]), "client_type": r[6],
            # Same OUI lookup this add-on already uses for its own device
            # classification — UniFi's own console shows vendor the same
            # way (inferred from the MAC), it isn't a field the API sends.
            "vendor": lookup_vendor(r[2]) if r[2] else None,
        }
        for r in rows
    ]


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
        networks=_load_networks(conn),
        zones=_load_zones(conn),
        policies=policies,
        devices=_load_devices(conn),
        clients=_load_clients(conn),
        logging_off_count=sum(1 for p in policies if p["enabled"] and p["logging_enabled"] is False),
    )


def _like_pattern(text: str) -> str:
    """Escapes SQL LIKE wildcards (%, _) in a policy name before using it
    as a substring pattern -- an admin-chosen name containing either
    character would otherwise be silently (mis)interpreted as a wildcard
    rather than a literal match."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@network_bp.route("/network/policy-detail")
def policy_detail():
    """On-demand only -- computed per policy on click, not folded into the
    main /network render, which would mean one extra query per policy on
    every page load for something most policies are never expanded to see.

    event_count is best-effort: there's no field anywhere in the
    Integration API tying an observed firewall log line to the specific
    policy that matched it, so this matches by whether the policy's own
    name appears in the log's auto-generated rule name -- true whenever
    the console's rule-naming convention includes it (common, not
    guaranteed), and honestly labeled as approximate in the response
    rather than asserted as exact."""
    policy_id = request.args.get("id", "").strip()
    if not policy_id:
        return jsonify({"error": "missing_id"}), 400

    conn = get_db()
    row = conn.execute(
        """SELECT p.id, p.name, p.enabled, p.action, p.protocol, z1.name, z2.name, p.logging_enabled, p.raw_json
           FROM unifi_policies p
           LEFT JOIN unifi_zones z1 ON z1.id = p.source_zone_id
           LEFT JOIN unifi_zones z2 ON z2.id = p.destination_zone_id
           WHERE p.id = ?""",
        (policy_id,),
    ).fetchone()
    if row is None:
        return jsonify({"error": "not_found"}), 404

    since = time.time() - _POLICY_EVENT_WINDOW_SECONDS
    event_count = conn.execute(
        "SELECT COUNT(*) FROM events_firewall WHERE ts >= ? AND rule_prefix LIKE ? ESCAPE '\\'",
        (since, _like_pattern(row[1])),
    ).fetchone()[0]

    return jsonify(
        {
            "id": row[0],
            "name": row[1],
            "enabled": bool(row[2]),
            "action": row[3],
            "protocol": row[4],
            "source_zone": row[5] or "unknown",
            "destination_zone": row[6] or "unknown",
            "logging_enabled": None if row[7] is None else bool(row[7]),
            "raw": json.loads(row[8]),
            "event_count": event_count,
            "event_count_window_days": _POLICY_EVENT_WINDOW_SECONDS // 86400,
        }
    )


@network_bp.route("/network/refresh", methods=["POST"])
def refresh_now():
    conn = get_db()
    config = current_app.config["ZTA_CONFIG"]
    report = sync.refresh(conn, config)
    if report is None:
        return jsonify({"status": "not_configured"}), 409
    return jsonify({"status": "ok", "any_capability_ok": report.any_capability_ok})
