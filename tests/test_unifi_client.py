import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.unifi.client import UnifiClientAPI, UnifiError, UnifiUnreachable


class _FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode()

    def __enter__(self):
        return io.BytesIO(self._body)

    def __exit__(self, *exc):
        return False


def _client(monkeypatch, payload):
    monkeypatch.setattr("app.unifi.client.urllib.request.urlopen", lambda *a, **k: _FakeResponse(payload))
    return UnifiClientAPI(host="192.168.1.1", api_key="test-key")


def test_get_info_returns_raw_payload(monkeypatch):
    client = _client(monkeypatch, {"applicationVersion": "10.1.84"})
    assert client.get_info()["applicationVersion"] == "10.1.84"


def test_list_clients_paginates_through_all_pages(monkeypatch):
    # Real bug, hit live: the Integration API defaults to limit=25 and
    # nothing here asked for more or followed totalCount — a site with 71
    # real clients silently showed only 25. 450 items forces three pages
    # (200 + 200 + 50) through the real _get_all loop, not just a bigger
    # single page.
    all_clients = [{"id": f"c{i}", "name": f"Client{i}"} for i in range(450)]

    def _fake_urlopen(request, timeout=None, context=None):
        query = request.full_url.split("?", 1)[1] if "?" in request.full_url else ""
        params = dict(p.split("=") for p in query.split("&") if p)
        offset = int(params.get("offset", 0))
        page = all_clients[offset : offset + 200]
        body = {"data": page, "offset": offset, "limit": 200, "count": len(page), "totalCount": len(all_clients)}
        return _FakeResponse(body)

    monkeypatch.setattr("app.unifi.client.urllib.request.urlopen", _fake_urlopen)
    client = UnifiClientAPI(host="192.168.1.1", api_key="test-key")
    clients = client.list_clients("site-1")

    assert len(clients) == 450
    assert clients[0].id == "c0"
    assert clients[-1].id == "c449"


def test_pagination_stops_on_a_short_page_even_without_total_count(monkeypatch):
    # Defensive fallback for a response missing totalCount entirely.
    def _fake_urlopen(request, timeout=None, context=None):
        return _FakeResponse({"data": [{"id": "only-one"}]})  # shorter than the page size, no totalCount

    monkeypatch.setattr("app.unifi.client.urllib.request.urlopen", _fake_urlopen)
    client = UnifiClientAPI(host="192.168.1.1", api_key="test-key")
    clients = client.list_clients("site-1")
    assert len(clients) == 1


def test_list_sites_parses_envelope(monkeypatch):
    client = _client(monkeypatch, {"data": [{"id": "abc", "name": "Default"}]})
    sites = client.list_sites()
    assert sites[0].id == "abc"
    assert sites[0].name == "Default"


def test_list_sites_tolerates_a_bare_list(monkeypatch):
    client = _client(monkeypatch, [{"id": "abc", "name": "Default"}])
    sites = client.list_sites()
    assert sites[0].id == "abc"


def test_list_devices_maps_alternate_field_names(monkeypatch):
    client = _client(
        monkeypatch,
        {"data": [{"id": "d1", "name": "Switch", "model": "USW-24", "macAddress": "aa:bb", "ipAddress": "10.0.0.5", "state": "ONLINE"}]},
    )
    devices = client.list_devices("default")
    assert devices[0].mac == "aa:bb"
    assert devices[0].ip == "10.0.0.5"
    assert devices[0].state == "ONLINE"


def test_list_clients_network_id_never_falls_back_to_uplink_device_id(monkeypatch):
    # Confirmed live against a real console: uplinkDeviceId is the AP/switch
    # a client is connected *through*, not its network -- using it as a
    # network_id fallback silently produced a value that never matched any
    # real unifi_networks.id, which is why every network's client count
    # showed 0. A real client payload with no networkId at all should leave
    # network_id as None, not populate it with the wrong kind of ID.
    client = _client(
        monkeypatch,
        {"data": [{"id": "c1", "ipAddress": "10.0.0.9", "uplinkDeviceId": "ap-1"}]},
    )
    clients = client.list_clients("default")
    assert clients[0].network_id is None


def test_list_clients_falls_back_to_hostname_and_mac(monkeypatch):
    client = _client(monkeypatch, {"data": [{"id": "c1", "hostname": "iPhone", "mac": "cc:dd", "ip": "10.0.0.9"}]})
    clients = client.list_clients("default")
    assert clients[0].name == "iPhone"
    assert clients[0].mac == "cc:dd"


def test_list_clients_parses_a_top_level_type_field(monkeypatch):
    client = _client(monkeypatch, {"data": [{"id": "c1", "name": "Desktop", "type": "WIRED"}]})
    clients = client.list_clients("default")
    assert clients[0].client_type == "WIRED"


def test_list_clients_falls_back_to_a_nested_access_type(monkeypatch):
    client = _client(monkeypatch, {"data": [{"id": "c1", "name": "Phone", "access": {"type": "WIRELESS"}}]})
    clients = client.list_clients("default")
    assert clients[0].client_type == "WIRELESS"


def test_list_clients_type_is_none_when_absent(monkeypatch):
    client = _client(monkeypatch, {"data": [{"id": "c1", "name": "Unknown"}]})
    clients = client.list_clients("default")
    assert clients[0].client_type is None


def test_list_networks_parses_vlan_and_subnet(monkeypatch):
    client = _client(
        monkeypatch,
        {"data": [{"id": "n1", "name": "IoT", "vlanId": 10, "ipv4Subnet": "192.168.10.0/24"}]},
    )
    networks = client.list_networks("default")
    assert networks[0].id == "n1"
    assert networks[0].name == "IoT"
    assert networks[0].vlan_id == 10
    assert networks[0].subnet == "192.168.10.0/24"


def test_list_networks_tolerates_a_missing_vlan_id(monkeypatch):
    # The default/native network typically isn't tagged with a VLAN.
    client = _client(monkeypatch, {"data": [{"id": "n1", "name": "Default", "ipv4Subnet": "192.168.1.0/24"}]})
    networks = client.list_networks("default")
    assert networks[0].vlan_id is None


def test_list_firewall_zones_parses_id_and_name(monkeypatch):
    client = _client(monkeypatch, {"data": [{"id": "z1", "name": "Internal"}]})
    zones = client.list_firewall_zones("default")
    assert zones[0].id == "z1"
    assert zones[0].name == "Internal"


@pytest.mark.parametrize("field_name", ["loggingEnabled", "logging_enabled", "logging", "logEnabled"])
def test_firewall_policy_logging_field_tries_multiple_names(monkeypatch, field_name):
    client = _client(
        monkeypatch,
        {"data": [{"id": "p1", "name": "Allow AirPlay", "enabled": True, "action": "ALLOW", field_name: True}]},
    )
    policies = client.list_firewall_policies("default")
    assert policies[0].logging_enabled is True


def test_firewall_policy_logging_field_none_when_absent(monkeypatch):
    client = _client(monkeypatch, {"data": [{"id": "p1", "name": "Allow AirPlay", "enabled": True}]})
    policies = client.list_firewall_policies("default")
    assert policies[0].logging_enabled is None


def test_firewall_policy_zone_refs_handle_string_and_object_shapes(monkeypatch):
    client = _client(
        monkeypatch,
        {
            "data": [
                {"id": "p1", "name": "A", "source": "zone-1", "destination": {"zoneId": "zone-2"}},
                {"id": "p2", "name": "B", "source": {"id": "zone-3"}, "destination": None},
            ]
        },
    )
    policies = client.list_firewall_policies("default")
    assert policies[0].source_zone_id == "zone-1"
    assert policies[0].destination_zone_id == "zone-2"
    assert policies[1].source_zone_id == "zone-3"
    assert policies[1].destination_zone_id is None


def test_firewall_policy_action_handles_object_and_string_shapes(monkeypatch):
    # {"type": "ALLOW", "allowReturnTraffic": false} is the real shape on a
    # live console, confirmed 2026-08-25 — the plain-string assumption this
    # code originally made crashed sync.py trying to store the whole dict.
    client = _client(
        monkeypatch,
        {
            "data": [
                {"id": "p1", "name": "A", "action": {"type": "ALLOW", "allowReturnTraffic": False}},
                {"id": "p2", "name": "B", "action": "BLOCK"},
                {"id": "p3", "name": "C", "action": None},
            ]
        },
    )
    policies = client.list_firewall_policies("default")
    assert policies[0].action == "ALLOW"
    assert policies[1].action == "BLOCK"
    assert policies[2].action is None


def test_http_error_raises_unifi_error(monkeypatch):
    def _boom(*a, **k):
        raise urllib.error.HTTPError("url", 403, "Forbidden", {}, None)

    monkeypatch.setattr("app.unifi.client.urllib.request.urlopen", _boom)
    client = UnifiClientAPI(host="192.168.1.1", api_key="bad-key")
    with pytest.raises(UnifiError):
        client.get_info()


def test_connection_error_raises_unifi_unreachable(monkeypatch):
    def _boom(*a, **k):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr("app.unifi.client.urllib.request.urlopen", _boom)
    client = UnifiClientAPI(host="192.168.1.1", api_key="test-key")
    with pytest.raises(UnifiUnreachable):
        client.get_info()


def test_non_ascii_api_key_raises_a_readable_unifi_error_not_a_raw_encode_error(monkeypatch):
    # Real bug, hit live: a header value must be latin-1-encodable. A key
    # with a stray em dash (copy-paste picked up surrounding text) crashed
    # with a bare "'latin-1' codec can't encode character..." — this is
    # http.client's own header-encoding step, triggered inside urlopen().
    def _boom(*a, **k):
        raise UnicodeEncodeError("latin-1", "abc—xyz", 3, 4, "ordinal not in range(256)")

    monkeypatch.setattr("app.unifi.client.urllib.request.urlopen", _boom)
    client = UnifiClientAPI(host="192.168.1.1", api_key="abc—xyz")
    with pytest.raises(UnifiError, match="plain ASCII"):
        client.get_info()
