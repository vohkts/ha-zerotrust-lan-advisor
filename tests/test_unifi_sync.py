import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db
from app.config import Config
from app.unifi import sync
from app.unifi.client import FirewallPolicy, FirewallZone, UnifiClient, UnifiDevice, UnifiNetwork


class _Site:
    def __init__(self, id_):
        self.id = id_


class _FakeClient:
    """A fake implementing every method probe()/refresh() call — success
    on all of them, so the real probe() logic can run unmodified against it."""

    def __init__(self):
        self.devices = [UnifiDevice(id="d1", name="Switch", model="USW", mac="aa", ip="10.0.0.5", state="ONLINE")]
        self.clients = [
            UnifiClient(id="c1", name="iPhone", mac="bb", ip="10.0.0.9", network_id="net-1",
                        connected_at="2026-08-20T10:00:00Z", client_type="WIRELESS")
        ]
        self.networks = [UnifiNetwork(id="n1", name="IoT", vlan_id=10, subnet="192.168.10.0/24")]
        self.zones = [FirewallZone(id="z1", name="Internal")]
        self.policies = [
            FirewallPolicy(
                id="p1", name="Allow AirPlay", enabled=True, action="ALLOW", protocol="tcp",
                source_zone_id="z1", destination_zone_id="z1", logging_enabled=False,
            )
        ]

    def get_info(self):
        return {"applicationVersion": "10.1.84"}

    def list_sites(self):
        return [_Site("site-1")]

    def list_devices(self, site_id):
        return self.devices

    def list_clients(self, site_id):
        return self.clients

    def list_networks(self, site_id):
        return self.networks

    def list_firewall_zones(self, site_id):
        return self.zones

    def list_firewall_policies(self, site_id):
        return self.policies


def _config(**overrides):
    base = dict(
        syslog_port=514, netflow_port=2055, allowed_sources=(), network_labels=(),
        retention_days=90, min_recurring_days=3, ignore_own_receiver_traffic=True,
        enable_mdns_classification=False, llm_mode="local", llm_remote_base_url="", llm_model_path="", llm_send_real_identifiers=False,
        unifi_enabled=True, unifi_host="192.168.1.1", unifi_verify_tls=False, unifi_apply_mode="manual",
        display_timezone_utc=False, ignore_unifi_console_traffic=True,
    )
    base.update(overrides)
    return Config(**base)


def test_refresh_disabled_does_nothing(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    result = sync.refresh(conn, _config(unifi_enabled=False))
    assert result is None
    assert conn.execute("SELECT COUNT(*) FROM unifi_capability_report").fetchone()[0] == 0


def test_refresh_with_no_api_key_does_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(sync, "read_secret", lambda name: None)
    conn = db.connect(tmp_path / "zerotrust.db")
    result = sync.refresh(conn, _config())
    assert result is None


def test_refresh_populates_all_caches_on_full_success(tmp_path, monkeypatch):
    monkeypatch.setattr(sync, "read_secret", lambda name: "fake-key")
    fake_client = _FakeClient()
    monkeypatch.setattr(sync, "_build_client", lambda config: fake_client)

    conn = db.connect(tmp_path / "zerotrust.db")
    report = sync.refresh(conn, _config())

    assert report.site_id == "site-1"
    assert conn.execute("SELECT COUNT(*) FROM unifi_devices").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM unifi_clients").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM unifi_networks").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM unifi_zones").fetchone()[0] == 1

    row = conn.execute("SELECT logging_enabled FROM unifi_policies WHERE id = 'p1'").fetchone()
    assert row[0] == 0  # False stored as 0, not NULL — the field was known

    row = conn.execute("SELECT name, vlan_id, subnet FROM unifi_networks WHERE id = 'n1'").fetchone()
    assert row == ("IoT", 10, "192.168.10.0/24")


def test_refresh_feeds_unifi_client_names_into_identities_for_classification(tmp_path, monkeypatch):
    # Real gap: UniFi client data never reached the identities table, so
    # Traffic's device class stayed "Unclassified" even with a working
    # integration -- classify.py never saw the client's own name.
    monkeypatch.setattr(sync, "read_secret", lambda name: "fake-key")
    fake_client = _FakeClient()
    fake_client.clients[0] = UnifiClient(
        id="c1", name="Johns-iPhone", mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.9",
        network_id="net-1", connected_at="2026-08-20T10:00:00Z", client_type="WIRELESS",
    )
    monkeypatch.setattr(sync, "_build_client", lambda config: fake_client)

    conn = db.connect(tmp_path / "zerotrust.db")
    sync.refresh(conn, _config())

    row = conn.execute(
        "SELECT hostname, device_class, class_confidence FROM identities WHERE ip = '10.0.0.9'"
    ).fetchone()
    assert row[0] == "Johns-iPhone"
    assert row[1] == "iPhone"
    assert row[2] == "high"


def test_refresh_survives_an_unexpectedly_object_shaped_field(tmp_path, monkeypatch):
    # Hit live: a real console returned a nested object for a policy's
    # `action`, a field client.py expects to be a plain string -- crashed
    # sqlite3 with "Error binding parameter 4: type 'dict' is not
    # supported" before _scalar() existed. Any field could turn out this
    # way; this is deliberately not specific to `action`.
    monkeypatch.setattr(sync, "read_secret", lambda name: "fake-key")
    fake_client = _FakeClient()
    fake_client.policies[0] = FirewallPolicy(
        id="p1", name="Odd rule", enabled=True, action={"type": "ALLOW"}, protocol="tcp",
        source_zone_id="z1", destination_zone_id="z1", logging_enabled=None,
    )
    monkeypatch.setattr(sync, "_build_client", lambda config: fake_client)

    conn = db.connect(tmp_path / "zerotrust.db")
    report = sync.refresh(conn, _config())  # must not raise

    assert report.site_id == "site-1"
    row = conn.execute("SELECT action FROM unifi_policies WHERE id = 'p1'").fetchone()
    assert row[0] == '{"type": "ALLOW"}'


def test_store_and_load_probe_report_round_trips(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    from app.unifi.capability_probe import CapabilityResult, ProbeReport

    report = ProbeReport(
        checked_at=time.time(),
        reachable=True,
        site_id="site-1",
        capabilities=[CapabilityResult("devices", "Read devices", True, "3 item(s)")],
    )
    sync.store_probe_report(conn, report)

    loaded = sync.load_probe_report(conn)
    assert loaded["site_id"] == "site-1"
    assert loaded["capabilities"][0]["key"] == "devices"


def test_store_probe_report_replaces_not_accumulates(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    from app.unifi.capability_probe import ProbeReport

    sync.store_probe_report(conn, ProbeReport(checked_at=1.0, reachable=True, site_id="a", capabilities=[]))
    sync.store_probe_report(conn, ProbeReport(checked_at=2.0, reachable=True, site_id="b", capabilities=[]))
    assert conn.execute("SELECT COUNT(*) FROM unifi_capability_report").fetchone()[0] == 1
    assert sync.load_probe_report(conn)["site_id"] == "b"
