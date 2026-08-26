import sys
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
    monkeypatch.setattr(routes_setup, "update_options", lambda opts: None)
    restarted = []
    monkeypatch.setattr(routes_setup, "restart_self", lambda: restarted.append(True))

    client = _client(tmp_path, monkeypatch)
    resp = client.post("/settings", data={"unifi_host": "1.2.3.4"})

    assert restarted == [True]
    assert "restarting now" in resp.get_data(as_text=True)


def test_save_still_succeeds_when_the_restart_trigger_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(routes_setup, "update_options", lambda opts: None)

    def _boom():
        raise RuntimeError("supervisor unreachable")

    monkeypatch.setattr(routes_setup, "restart_self", _boom)

    client = _client(tmp_path, monkeypatch)
    resp = client.post("/settings", data={"unifi_host": "1.2.3.4"})

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Saved" in body
    assert "couldn't trigger a restart automatically" in body
