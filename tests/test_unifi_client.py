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


def test_list_clients_falls_back_to_hostname_and_mac(monkeypatch):
    client = _client(monkeypatch, {"data": [{"id": "c1", "hostname": "iPhone", "mac": "cc:dd", "ip": "10.0.0.9"}]})
    clients = client.list_clients("default")
    assert clients[0].name == "iPhone"
    assert clients[0].mac == "cc:dd"


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
