import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db
from app.unifi import sync
from app.unifi.capability_probe import CapabilityResult, ProbeReport
from app.web.routes_network import (
    _like_pattern,
    _load_clients,
    _load_devices,
    _load_networks,
    _load_policies,
    _load_zones,
    unifi_available,
)

NOW = time.time()


class _Config:
    def __init__(self, unifi_enabled=True):
        self.unifi_enabled = unifi_enabled


def test_unavailable_when_disabled(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    assert unifi_available(_Config(unifi_enabled=False), conn) is False


def test_unavailable_when_no_probe_yet(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    assert unifi_available(_Config(unifi_enabled=True), conn) is False


def test_unavailable_when_last_probe_had_no_working_capability(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    sync.store_probe_report(
        conn,
        ProbeReport(checked_at=NOW, reachable=True, site_id=None, capabilities=[
            CapabilityResult("auth", "Authenticate", False, "401"),
        ]),
    )
    assert unifi_available(_Config(unifi_enabled=True), conn) is False


def test_available_when_last_probe_has_a_working_capability(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    sync.store_probe_report(
        conn,
        ProbeReport(checked_at=NOW, reachable=True, site_id="s1", capabilities=[
            CapabilityResult("devices", "Read devices", True, "3 item(s)"),
        ]),
    )
    assert unifi_available(_Config(unifi_enabled=True), conn) is True


def test_load_zones_and_policies_join_zone_names(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    conn.execute("INSERT INTO unifi_zones (id, name, raw_json, fetched_at) VALUES ('z1', 'Internal', '{}', ?)", (NOW,))
    conn.execute("INSERT INTO unifi_zones (id, name, raw_json, fetched_at) VALUES ('z2', 'IoT', '{}', ?)", (NOW,))
    conn.execute(
        """INSERT INTO unifi_policies
           (id, name, enabled, action, protocol, source_zone_id, destination_zone_id, logging_enabled,
            raw_json, fetched_at)
           VALUES ('p1', 'Allow AirPlay', 1, 'ALLOW', 'tcp', 'z1', 'z2', 0, '{}', ?)""",
        (NOW,),
    )
    conn.commit()

    zones = _load_zones(conn)
    assert {z["name"] for z in zones} == {"Internal", "IoT"}

    policies = _load_policies(conn)
    assert len(policies) == 1
    assert policies[0]["source_zone"] == "Internal"
    assert policies[0]["destination_zone"] == "IoT"
    assert policies[0]["logging_enabled"] is False


def test_load_policies_reports_unknown_zone_when_zone_id_missing(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    conn.execute(
        """INSERT INTO unifi_policies
           (id, name, enabled, action, protocol, source_zone_id, destination_zone_id, logging_enabled,
            raw_json, fetched_at)
           VALUES ('p1', 'Orphan rule', 1, 'BLOCK', 'tcp', 'missing', NULL, NULL, '{}', ?)""",
        (NOW,),
    )
    conn.commit()
    policies = _load_policies(conn)
    assert policies[0]["source_zone"] == "unknown"
    assert policies[0]["destination_zone"] == "unknown"
    assert policies[0]["logging_enabled"] is None


def test_load_devices(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    conn.execute(
        "INSERT INTO unifi_devices (id, name, model, mac, ip, state, raw_json, fetched_at) "
        "VALUES ('d1', 'Switch', 'USW', 'aa:bb', '10.0.0.5', 'ONLINE', '{}', ?)",
        (NOW,),
    )
    conn.commit()
    devices = _load_devices(conn)
    assert devices == [{"id": "d1", "name": "Switch", "model": "USW", "mac": "aa:bb", "ip": "10.0.0.5", "state": "ONLINE"}]


def _insert_client(conn, id_, connected_at, client_type=None):
    conn.execute(
        "INSERT INTO unifi_clients (id, name, mac, ip, network_id, connected_at, client_type, raw_json, fetched_at) "
        "VALUES (?, ?, 'aa:bb', '10.0.0.9', 'net-1', ?, ?, '{}', ?)",
        (id_, f"Client{id_}", connected_at, client_type, NOW),
    )


def test_load_clients_never_hides_anything_the_api_returned(tmp_path):
    # Real bug, corrected live: the clients endpoint only ever returns
    # currently-connected clients in the first place -- there is no
    # separate "offline" set to filter. A long-running, healthy wired
    # connection has an old connectedAt and is still online; hiding it as
    # "stale" was actively wrong (real online devices disappeared).
    conn = db.connect(tmp_path / "zerotrust.db")
    from datetime import datetime, timezone

    old = datetime.fromtimestamp(NOW - 30 * 86400, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    _insert_client(conn, "long-running", old, client_type="WIRED")
    conn.commit()

    clients = _load_clients(conn)
    assert {c["id"] for c in clients} == {"long-running"}
    assert clients[0]["client_type"] == "WIRED"


def test_load_clients_ignores_an_unparseable_connected_at(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_client(conn, "weird", "not-a-real-timestamp")
    conn.commit()

    clients = _load_clients(conn)
    assert clients[0]["connected_at"] is None


def test_load_clients_includes_vendor_from_mac(tmp_path, monkeypatch):
    # UniFi's own console shows vendor the same way -- inferred from the
    # MAC's OUI, not a field the API itself sends.
    import app.web.routes_network as routes_network

    monkeypatch.setattr(routes_network, "lookup_vendor", lambda mac: "Apple, Inc." if mac == "aa:bb" else None)
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_client(conn, "c1", None)
    conn.commit()

    clients = _load_clients(conn)
    assert clients[0]["vendor"] == "Apple, Inc."


def test_load_networks_includes_client_count(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    conn.execute(
        "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) "
        "VALUES ('n1', 'IoT', 10, '192.168.10.0/24', '{}', ?)", (NOW,),
    )
    conn.execute(
        "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) "
        "VALUES ('n2', 'Guest', 20, '192.168.20.0/24', '{}', ?)", (NOW,),
    )
    _insert_client(conn, "c1", None)
    conn.execute("UPDATE unifi_clients SET network_id = 'n1' WHERE id = 'c1'")
    _insert_client(conn, "c2", None)
    conn.execute("UPDATE unifi_clients SET network_id = 'n1' WHERE id = 'c2'")
    conn.commit()

    networks = _load_networks(conn)
    by_name = {n["name"]: n["client_count"] for n in networks}
    assert by_name == {"IoT": 2, "Guest": 0}


def test_like_pattern_escapes_percent_and_underscore():
    assert _like_pattern("Allow_All") == "%Allow\\_All%"
    assert _like_pattern("100%") == "%100\\%%"
    assert _like_pattern("Plain") == "%Plain%"


def _client(tmp_path, monkeypatch):
    import app.config as config_module
    from app.web.server import create_app

    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_module, "OPTIONS_PATH", tmp_path / "options.json")
    monkeypatch.setattr(config_module, "SECRETS_DIR", tmp_path / "secrets")
    app = create_app()
    app.testing = True
    return app.test_client()


def test_not_set_up_page_links_to_a_real_reachable_settings_page(tmp_path, monkeypatch):
    # Real bug found live: this page linked to href="settings", but
    # /settings only ever accepts POST (it's the form-save target, not a
    # page) -- clicking that link 405'd. The real page is /setup.
    client = _client(tmp_path, monkeypatch)
    body = client.get("/network").get_data(as_text=True)
    assert 'href="settings"' not in body
    assert 'href="setup"' in body
    assert client.get("/setup").status_code == 200


def test_policy_detail_requires_id(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/network/policy-detail")
    assert resp.status_code == 400


def test_policy_detail_404s_for_an_unknown_id(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/network/policy-detail?id=missing")
    assert resp.status_code == 404


def test_policy_detail_returns_raw_and_best_effort_event_count(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = db.connect(client.application.config["ZTA_CONFIG"].db_path)
        conn.execute(
            "INSERT INTO unifi_zones (id, name, raw_json, fetched_at) VALUES ('z1', 'Internal', '{}', ?)", (NOW,),
        )
        conn.execute(
            """INSERT INTO unifi_policies
               (id, name, enabled, action, protocol, source_zone_id, destination_zone_id, logging_enabled,
                raw_json, fetched_at)
               VALUES ('p1', 'Allow AirPlay', 1, 'ALLOW', 'tcp', 'z1', 'z1', 1, '{"foo": "bar"}', ?)""",
            (NOW,),
        )
        conn.execute(
            "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, rule_prefix, action, received_at) "
            "VALUES (?, '192.168.10.5', '192.168.10.6', 6, 'LAN_IN-Allow AirPlay-2147483647', 'ALLOW', ?)",
            (NOW, NOW),
        )
        conn.execute(
            "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, rule_prefix, action, received_at) "
            "VALUES (?, '192.168.10.5', '192.168.10.6', 6, 'LAN_IN-Unrelated Rule-1', 'ALLOW', ?)",
            (NOW, NOW),
        )
        conn.commit()

    body = client.get("/network/policy-detail?id=p1").get_json()
    assert body["name"] == "Allow AirPlay"
    assert body["source_zone"] == "Internal"
    assert body["raw"] == {"foo": "bar"}
    assert body["event_count"] == 1  # only the matching rule_prefix, not the unrelated one


def test_policy_detail_event_count_ignores_underscore_as_a_wildcard(tmp_path, monkeypatch):
    # A policy literally named "Allow_All" must not match a log line for
    # some unrelated "AllowXAll" rule just because '_' is a SQL LIKE
    # single-character wildcard when left unescaped.
    client = _client(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = db.connect(client.application.config["ZTA_CONFIG"].db_path)
        conn.execute(
            """INSERT INTO unifi_policies
               (id, name, enabled, action, protocol, source_zone_id, destination_zone_id, logging_enabled,
                raw_json, fetched_at)
               VALUES ('p1', 'Allow_All', 1, 'ALLOW', 'tcp', NULL, NULL, 1, '{}', ?)""",
            (NOW,),
        )
        conn.execute(
            "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, rule_prefix, action, received_at) "
            "VALUES (?, '192.168.10.5', '192.168.10.6', 6, 'LAN_IN-AllowXAll-1', 'ALLOW', ?)",
            (NOW, NOW),
        )
        conn.commit()

    body = client.get("/network/policy-detail?id=p1").get_json()
    assert body["event_count"] == 0
