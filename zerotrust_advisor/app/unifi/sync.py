"""Orchestrates a UniFi read-only refresh: probe capabilities, store the
report, and — for every capability that's actually working — refresh that
data's cache. Triggered manually (the Network screen's "Refresh now") and
on the same background timer as the LLM analysis pass; this is a handful
of cheap GETs, not worth its own schedule.

Inert by design when UniFi isn't configured: every function here returns
None immediately if `unifi_enabled` is off or the host/key aren't set, so
this module does nothing at all — no network calls, no DB writes — on any
install that hasn't opted in.
"""
from __future__ import annotations

import json
import sqlite3
import time

from app.config import Config, read_secret
from app.unifi.capability_probe import ProbeReport, probe
from app.unifi.client import UnifiClientAPI


def _build_client(config: Config) -> UnifiClientAPI | None:
    if not config.unifi_enabled or not config.unifi_host:
        return None
    api_key = read_secret("unifi_api_key")
    if not api_key:
        return None
    return UnifiClientAPI(host=config.unifi_host, api_key=api_key, verify_tls=config.unifi_verify_tls)


def store_probe_report(conn: sqlite3.Connection, report: ProbeReport) -> None:
    conn.execute("DELETE FROM unifi_capability_report")
    conn.execute(
        "INSERT INTO unifi_capability_report (checked_at, reachable, site_id, capabilities_json) VALUES (?, ?, ?, ?)",
        (
            report.checked_at,
            int(report.reachable),
            report.site_id,
            json.dumps([{"key": c.key, "label": c.label, "ok": c.ok, "detail": c.detail} for c in report.capabilities]),
        ),
    )
    conn.commit()


def load_probe_report(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute(
        "SELECT checked_at, reachable, site_id, capabilities_json FROM unifi_capability_report "
        "ORDER BY checked_at DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    checked_at, reachable, site_id, capabilities_json = row
    capabilities = json.loads(capabilities_json)
    return {
        "checked_at": checked_at,
        "reachable": bool(reachable),
        "site_id": site_id,
        "capabilities": capabilities,
        "any_capability_ok": any(c["ok"] for c in capabilities),
    }


def test_connection(config: Config) -> ProbeReport | None:
    """A fresh probe with nothing cached — the Settings screen's "Test
    Connection" button wants an immediate answer, not yesterday's."""
    client = _build_client(config)
    if client is None:
        return None
    return probe(client)


def refresh(conn: sqlite3.Connection, config: Config) -> ProbeReport | None:
    client = _build_client(config)
    if client is None:
        return None

    report = probe(client)
    store_probe_report(conn, report)
    if report.site_id is None:
        return report

    ok_keys = {c.key for c in report.capabilities if c.ok}
    now = time.time()

    if "devices" in ok_keys:
        conn.execute("DELETE FROM unifi_devices")
        for d in client.list_devices(report.site_id):
            conn.execute(
                "INSERT INTO unifi_devices (id, name, model, mac, ip, state, raw_json, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (d.id, d.name, d.model, d.mac, d.ip, d.state, json.dumps(d.raw), now),
            )

    if "clients" in ok_keys:
        conn.execute("DELETE FROM unifi_clients")
        for c in client.list_clients(report.site_id):
            conn.execute(
                "INSERT INTO unifi_clients (id, name, mac, ip, network_id, raw_json, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (c.id, c.name, c.mac, c.ip, c.network_id, json.dumps(c.raw), now),
            )

    if "firewall_zones" in ok_keys:
        conn.execute("DELETE FROM unifi_zones")
        for z in client.list_firewall_zones(report.site_id):
            conn.execute(
                "INSERT INTO unifi_zones (id, name, raw_json, fetched_at) VALUES (?, ?, ?, ?)",
                (z.id, z.name, json.dumps(z.raw), now),
            )

    if "firewall_policies" in ok_keys:
        conn.execute("DELETE FROM unifi_policies")
        for p in client.list_firewall_policies(report.site_id):
            conn.execute(
                "INSERT INTO unifi_policies (id, name, enabled, action, protocol, source_zone_id, "
                "destination_zone_id, logging_enabled, raw_json, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    p.id,
                    p.name,
                    int(p.enabled),
                    p.action,
                    p.protocol,
                    p.source_zone_id,
                    p.destination_zone_id,
                    None if p.logging_enabled is None else int(p.logging_enabled),
                    json.dumps(p.raw),
                    now,
                ),
            )

    conn.commit()
    return report
