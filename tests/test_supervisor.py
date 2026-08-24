import io
import json
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import supervisor


class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode()

    def __enter__(self):
        return io.BytesIO(self._body)

    def __exit__(self, *exc):
        return False


def test_returns_primary_connected_interface_ip(monkeypatch):
    payload = {
        "data": {
            "interfaces": [
                {"primary": False, "connected": True, "ipv4": {"address": ["10.0.0.5/24"]}},
                {"primary": True, "connected": True, "ipv4": {"address": ["192.168.0.68/24"]}},
            ]
        }
    }
    monkeypatch.setattr(supervisor.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(payload))
    assert supervisor.get_host_ip() == "192.168.0.68"


def test_no_primary_interface_returns_none(monkeypatch):
    payload = {"data": {"interfaces": [{"primary": False, "connected": True, "ipv4": {"address": ["10.0.0.5/24"]}}]}}
    monkeypatch.setattr(supervisor.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(payload))
    assert supervisor.get_host_ip() is None


def test_primary_but_disconnected_returns_none(monkeypatch):
    payload = {"data": {"interfaces": [{"primary": True, "connected": False, "ipv4": {"address": ["10.0.0.5/24"]}}]}}
    monkeypatch.setattr(supervisor.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(payload))
    assert supervisor.get_host_ip() is None


def test_unreachable_supervisor_returns_none_not_raises(monkeypatch):
    def _boom(*a, **k):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(supervisor.urllib.request, "urlopen", _boom)
    assert supervisor.get_host_ip() is None
