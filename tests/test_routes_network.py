import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db
from app.unifi import sync
from app.unifi.capability_probe import CapabilityResult, ProbeReport
from app.web.routes_network import _load_clients, _load_devices, _load_policies, _load_zones, unifi_available

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


def _insert_client(conn, id_, connected_at):
    conn.execute(
        "INSERT INTO unifi_clients (id, name, mac, ip, network_id, connected_at, raw_json, fetched_at) "
        "VALUES (?, ?, 'aa:bb', '10.0.0.9', 'net-1', ?, '{}', ?)",
        (id_, f"Client{id_}", connected_at, NOW),
    )


def test_load_clients_hides_ones_stale_beyond_three_days(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    from datetime import datetime, timezone

    recent = datetime.fromtimestamp(NOW - 3600, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    stale = datetime.fromtimestamp(NOW - 10 * 86400, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    _insert_client(conn, "recent", recent)
    _insert_client(conn, "stale", stale)
    conn.commit()

    visible, stale_count = _load_clients(conn, now=NOW)
    assert {c["id"] for c in visible} == {"recent"}
    assert stale_count == 1


def test_load_clients_keeps_clients_with_no_connected_at_at_all(tmp_path):
    # Missing data is not evidence of staleness -- reject/hide only on
    # positive evidence the client hasn't been seen recently.
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_client(conn, "unknown", None)
    conn.commit()

    visible, stale_count = _load_clients(conn, now=NOW)
    assert {c["id"] for c in visible} == {"unknown"}
    assert stale_count == 0


def test_load_clients_ignores_an_unparseable_connected_at(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_client(conn, "weird", "not-a-real-timestamp")
    conn.commit()

    visible, stale_count = _load_clients(conn, now=NOW)
    assert {c["id"] for c in visible} == {"weird"}
    assert stale_count == 0
