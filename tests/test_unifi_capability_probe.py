import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.unifi.capability_probe import probe
from app.unifi.client import UnifiError, UnifiUnreachable


class _FakeClient:
    def __init__(self, info=None, info_error=None, sites=None, sites_error=None, **method_results):
        self._info = info
        self._info_error = info_error
        self._sites = sites if sites is not None else []
        self._sites_error = sites_error
        self._method_results = method_results  # name -> value or Exception instance

    def get_info(self):
        if self._info_error:
            raise self._info_error
        return self._info or {"applicationVersion": "10.1.84"}

    def list_sites(self):
        if self._sites_error:
            raise self._sites_error
        return self._sites

    def _resolve(self, name, site_id):
        result = self._method_results.get(name, [])
        if isinstance(result, Exception):
            raise result
        return result

    def list_devices(self, site_id):
        return self._resolve("devices", site_id)

    def list_clients(self, site_id):
        return self._resolve("clients", site_id)

    def list_firewall_zones(self, site_id):
        return self._resolve("firewall_zones", site_id)

    def list_firewall_policies(self, site_id):
        return self._resolve("firewall_policies", site_id)


class _Site:
    def __init__(self, id_):
        self.id = id_


def test_unreachable_console_reports_a_single_reach_failure():
    client = _FakeClient(info_error=UnifiUnreachable("no route to host"))
    report = probe(client)
    assert report.reachable is False
    assert len(report.capabilities) == 1
    assert report.capabilities[0].key == "reach"
    assert report.capabilities[0].ok is False


def test_bad_key_reports_reachable_but_auth_failed():
    client = _FakeClient(info_error=UnifiError("401 Unauthorized"))
    report = probe(client)
    assert report.reachable is True
    assert report.capabilities[0].key == "auth"
    assert report.capabilities[0].ok is False


def test_401_auth_failure_explains_the_console_vs_network_app_key_mixup():
    client = _FakeClient(info_error=UnifiError("401 Unauthorized"))
    report = probe(client)
    detail = report.capabilities[0].detail
    assert "401 Unauthorized" in detail  # raw error kept, not replaced
    assert "console level" in detail
    assert "Network application" in detail


def test_403_auth_failure_gets_the_same_guidance():
    client = _FakeClient(info_error=UnifiError("403 Forbidden"))
    report = probe(client)
    assert "console level" in report.capabilities[0].detail


def test_other_auth_failures_are_not_given_the_key_placement_guidance():
    client = _FakeClient(info_error=UnifiError("500 Internal Server Error"))
    report = probe(client)
    assert report.capabilities[0].detail == "500 Internal Server Error"


def test_no_sites_available_marks_everything_else_untested():
    client = _FakeClient(sites=[])
    report = probe(client)
    keys_ok = {c.key: c.ok for c in report.capabilities}
    assert keys_ok["reach"] is True
    assert keys_ok["sites"] is True  # the call succeeded, it just returned nothing
    assert keys_ok["devices"] is False
    assert keys_ok["firewall_policies"] is False
    assert report.site_id is None


def test_full_success_reports_every_capability_ok():
    client = _FakeClient(
        sites=[_Site("site-1")],
        devices=[1, 2],
        clients=[1],
        firewall_zones=[1, 2, 3],
        firewall_policies=[1],
    )
    report = probe(client)
    assert report.site_id == "site-1"
    assert report.any_capability_ok is True
    assert all(c.ok for c in report.capabilities)


def test_partial_failure_is_granular_not_all_or_nothing():
    # An older Network Application without zone-based firewalling: devices
    # and clients work, firewall endpoints 404.
    client = _FakeClient(
        sites=[_Site("site-1")],
        devices=[1],
        clients=[1],
        firewall_zones=UnifiError("404 Not Found"),
        firewall_policies=UnifiError("404 Not Found"),
    )
    report = probe(client)
    by_key = {c.key: c.ok for c in report.capabilities}
    assert by_key["devices"] is True
    assert by_key["firewall_zones"] is False
    assert by_key["firewall_policies"] is False
    assert report.any_capability_ok is True
