import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.web import routes_setup
from app.web.routes_setup import _api_key_error
from app.web.server import create_app


def test_ascii_key_is_valid():
    assert _api_key_error("aBc123XyZ") is None


def test_key_with_an_em_dash_is_rejected():
    # The real bug: a header value must be latin-1, and this crashed with
    # a bare UnicodeEncodeError before it was caught here — see client.py.
    assert _api_key_error("abc123—xyz") is not None


def test_key_with_a_smart_quote_is_rejected():
    assert _api_key_error("abc’123") is not None


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("ZTA_DATA_DIR", str(tmp_path))
    import app.config as config_module

    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_module, "OPTIONS_PATH", tmp_path / "options.json")
    monkeypatch.setattr(config_module, "SECRETS_DIR", tmp_path / "secrets")
    app = create_app()
    app.testing = True
    return app.test_client()


def test_setup_page_shows_capacity_check_in_local_llm_mode(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/setup")
    assert "Local hardware check" in resp.get_data(as_text=True)


def test_setup_page_hides_capacity_check_in_remote_llm_mode(tmp_path, monkeypatch):
    import json

    monkeypatch.setenv("ZTA_DATA_DIR", str(tmp_path))
    import app.config as config_module

    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_module, "OPTIONS_PATH", tmp_path / "options.json")
    monkeypatch.setattr(config_module, "SECRETS_DIR", tmp_path / "secrets")
    (tmp_path / "options.json").write_text(json.dumps({"llm_mode": "remote"}))

    app = create_app()
    app.testing = True
    client = app.test_client()

    resp = client.get("/setup")
    assert "Local hardware check" not in resp.get_data(as_text=True)


def test_save_triggers_a_restart_and_says_so(tmp_path, monkeypatch):
    # Real bug, reported live: calling restart_self() inline, before this
    # response was even rendered, raced Supervisor tearing the container
    # down against the response still being written -- through real
    # Ingress that lost race was an outright 502, not a graceful "saved,
    # restarting" page. Fixed with a short delay on a background thread;
    # this test waits for that delayed call rather than expecting it to
    # have already happened by the time the response comes back.
    monkeypatch.setattr(routes_setup, "update_options", lambda opts: None)
    monkeypatch.setattr(routes_setup.time, "sleep", lambda seconds: None)  # don't actually wait 1.5s in tests
    restarted = threading.Event()
    monkeypatch.setattr(routes_setup, "restart_self", lambda: restarted.set())

    client = _client(tmp_path, monkeypatch)
    resp = client.post("/settings", data={"unifi_host": "1.2.3.4"})

    assert "restarting now" in resp.get_data(as_text=True)
    assert restarted.wait(timeout=2)


def test_save_still_succeeds_when_the_restart_trigger_fails(tmp_path, monkeypatch):
    # The restart call now happens after this response is already on its
    # way to the client (see above), so a failure in it can no longer
    # change this response's own text -- it's only ever logged. The
    # response must still come back clean regardless.
    monkeypatch.setattr(routes_setup, "update_options", lambda opts: None)
    monkeypatch.setattr(routes_setup.time, "sleep", lambda seconds: None)

    def _boom():
        raise RuntimeError("supervisor unreachable")

    monkeypatch.setattr(routes_setup, "restart_self", _boom)

    client = _client(tmp_path, monkeypatch)
    resp = client.post("/settings", data={"unifi_host": "1.2.3.4"})

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Saved" in body
    assert "restarting now" in body
