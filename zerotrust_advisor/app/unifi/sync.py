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
from app.sanitize.classify import classify
from app.unifi.capability_probe import ProbeReport, probe
from app.unifi.client import UnifiClientAPI


def _scalar(value):
    """Coerce anything that isn't already a SQLite-bindable primitive
    (str/int/float/bool/None) into a compact JSON string, instead of
    crashing the whole sync. Hit live: a field client.py expects to be a
    plain string (e.g. a policy's action) came back from a real console as
    a nested object — a shape the Integration API docs don't fully pin
    down (see client.py's own note on this). The untouched original value
    is always kept separately in raw_json regardless of what happens here.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value)


def _upsert_identity_from_unifi_client(conn: sqlite3.Connection, unifi_client, now: float) -> None:
    """UniFi's own client name is a real device-classification signal
    (classify.py's hostname patterns match "Johns-iPhone" just as well as
    an mDNS-sourced one) that never reached the identities table before —
    which is why Traffic's device class stayed "Unclassified" for hosts
    even with the integration configured and working. Same upsert shape as
    mdns_listener.py's _upsert_identity: last writer wins, no merge logic,
    consistent with how every other identity source already behaves here.
    """
    if not unifi_client.ip:
        return
    classification = classify(hostname=unifi_client.name, mac=unifi_client.mac)
    device_key = unifi_client.mac or unifi_client.ip
    conn.execute(
        """INSERT INTO identities (device_key, ip, mac, hostname, vendor, device_class, class_confidence,
                                    first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(device_key) DO UPDATE SET
               ip=excluded.ip, mac=excluded.mac, hostname=excluded.hostname, vendor=excluded.vendor,
               device_class=excluded.device_class, class_confidence=excluded.class_confidence,
               last_seen=excluded.last_seen""",
        (
            device_key,
            unifi_client.ip,
            unifi_client.mac,
            unifi_client.name,
            classification.vendor,
            classification.device_class,
            classification.confidence,
            now,
            now,
        ),
    )


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
                (_scalar(d.id), _scalar(d.name), _scalar(d.model), _scalar(d.mac), _scalar(d.ip),
                 _scalar(d.state), json.dumps(d.raw), now),
            )

    if "clients" in ok_keys:
        conn.execute("DELETE FROM unifi_clients")
        for c in client.list_clients(report.site_id):
            conn.execute(
                "INSERT INTO unifi_clients (id, name, mac, ip, network_id, connected_at, raw_json, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (_scalar(c.id), _scalar(c.name), _scalar(c.mac), _scalar(c.ip), _scalar(c.network_id),
                 _scalar(c.connected_at), json.dumps(c.raw), now),
            )
            _upsert_identity_from_unifi_client(conn, c, now)

    if "networks" in ok_keys:
        conn.execute("DELETE FROM unifi_networks")
        for n in client.list_networks(report.site_id):
            conn.execute(
                "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (_scalar(n.id), _scalar(n.name), n.vlan_id, _scalar(n.subnet), json.dumps(n.raw), now),
            )

    if "firewall_zones" in ok_keys:
        conn.execute("DELETE FROM unifi_zones")
        for z in client.list_firewall_zones(report.site_id):
            conn.execute(
                "INSERT INTO unifi_zones (id, name, raw_json, fetched_at) VALUES (?, ?, ?, ?)",
                (_scalar(z.id), _scalar(z.name), json.dumps(z.raw), now),
            )

    if "firewall_policies" in ok_keys:
        conn.execute("DELETE FROM unifi_policies")
        for p in client.list_firewall_policies(report.site_id):
            conn.execute(
                "INSERT INTO unifi_policies (id, name, enabled, action, protocol, source_zone_id, "
                "destination_zone_id, logging_enabled, raw_json, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    _scalar(p.id),
                    _scalar(p.name),
                    int(p.enabled),
                    _scalar(p.action),
                    _scalar(p.protocol),
                    _scalar(p.source_zone_id),
                    _scalar(p.destination_zone_id),
                    None if p.logging_enabled is None else int(p.logging_enabled),
                    json.dumps(p.raw),
                    now,
                ),
            )

    conn.commit()
    return report
