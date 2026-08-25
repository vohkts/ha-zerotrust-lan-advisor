import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.db import connect
from app.web import routes_traffic
from app.web.server import create_app

NOW = time.time()


def _client(tmp_path, monkeypatch):
    import app.config as config_module

    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_module, "OPTIONS_PATH", tmp_path / "options.json")
    monkeypatch.setattr(config_module, "SECRETS_DIR", tmp_path / "secrets")
    app = create_app()
    app.testing = True
    return app.test_client()


def _seed_events(app):
    with app.app_context():
        conn = connect(app.config["ZTA_CONFIG"].db_path)
        conn.execute(
            "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, dst_port, action, received_at) "
            "VALUES (?, '192.168.10.5', '192.168.20.9', 6, 7000, 'ALLOW', ?)",
            (NOW, NOW),
        )
        conn.commit()


def test_host_detail_requires_ip(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/traffic/host-detail")
    assert resp.status_code == 400


def test_host_detail_returns_stats_for_a_known_ip(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _seed_events(client.application)

    body = client.get("/traffic/host-detail?ip=192.168.10.5").get_json()
    assert body["ip"] == "192.168.10.5"
    assert body["event_count"] == 1
    assert body["device_class"] == "Unclassified device"
    assert body["llm_guess"] is None
    assert body["guess_in_progress"] is False
    assert len(body["top_partners"]) == 1
    assert body["top_partners"][0]["ip"] == "192.168.20.9"


def test_guess_requires_ip(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.post("/traffic/host-detail/guess")
    assert resp.status_code == 400


def test_guess_starts_in_background_and_caches_the_result(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _seed_events(client.application)

    monkeypatch.setattr(routes_traffic, "chat_completion", lambda *a, **k: json.dumps({"guess": "Probably a smart plug"}))

    resp = client.post("/traffic/host-detail/guess?ip=192.168.10.5")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "started"}

    # Poll until the background thread finishes (bounded wait, not a sleep).
    deadline = time.time() + 3
    while time.time() < deadline:
        body = client.get("/traffic/host-detail?ip=192.168.10.5").get_json()
        if body["llm_guess"]:
            break
        time.sleep(0.05)
    else:
        raise AssertionError("guess never landed")

    assert body["llm_guess"] == "Probably a smart plug"
    assert body["guess_in_progress"] is False


def test_guess_reports_already_running_for_a_duplicate_request(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    routes_traffic._guess_in_progress.add("192.168.10.5")
    try:
        resp = client.post("/traffic/host-detail/guess?ip=192.168.10.5")
        assert resp.status_code == 409
        assert resp.get_json() == {"status": "already_running"}
    finally:
        routes_traffic._guess_in_progress.discard("192.168.10.5")


def test_guess_creates_an_identity_row_when_none_existed(tmp_path, monkeypatch):
    # A host with observed traffic but no mDNS/UniFi-sourced identity row
    # at all -- the guess must still persist, not silently vanish.
    client = _client(tmp_path, monkeypatch)
    _seed_events(client.application)
    monkeypatch.setattr(routes_traffic, "chat_completion", lambda *a, **k: json.dumps({"guess": "A media device"}))

    client.post("/traffic/host-detail/guess?ip=192.168.20.9")

    deadline = time.time() + 3
    body = {}
    while time.time() < deadline:
        body = client.get("/traffic/host-detail?ip=192.168.20.9").get_json()
        if body["llm_guess"]:
            break
        time.sleep(0.05)
    assert body["llm_guess"] == "A media device"
