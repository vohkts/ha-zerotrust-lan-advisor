import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

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


def _insert_event(conn, src, dst, action="ALLOW", dst_port=443, proto=6, ts=None):
    conn.execute(
        "INSERT INTO events_firewall (ts, src_ip, dst_ip, src_port, dst_port, proto, action, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ts or NOW, src, dst, 51000, dst_port, proto, action, ts or NOW),
    )


def test_live_page_loads(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/live")
    assert resp.status_code == 200


def test_bootstrap_call_returns_no_events_just_the_current_max_id(tmp_path, monkeypatch):
    from app.db import connect

    client = _client(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        _insert_event(conn, "192.168.10.5", "192.168.20.9")
        conn.commit()

    resp = client.get("/live/events")  # no since_id -- bootstrap
    body = resp.get_json()
    assert body["events"] == []
    assert body["max_id"] == 1


def test_polling_with_a_cursor_returns_only_newer_events(tmp_path, monkeypatch):
    from app.db import connect

    client = _client(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        _insert_event(conn, "192.168.10.5", "192.168.20.9", action="ALLOW")
        conn.commit()

    bootstrap = client.get("/live/events").get_json()
    cursor = bootstrap["max_id"]

    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        _insert_event(conn, "192.168.10.6", "1.1.1.1", action="DROP", dst_port=22)
        conn.commit()

    body = client.get(f"/live/events?since_id={cursor}").get_json()
    assert len(body["events"]) == 1
    assert body["events"][0]["src_ip"] == "192.168.10.6"
    assert body["events"][0]["blocked"] is True
    assert body["max_id"] == cursor + 1


def test_polling_finds_nothing_new_keeps_the_same_max_id(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    body = client.get("/live/events?since_id=5").get_json()
    assert body["events"] == []
    assert body["max_id"] == 5


def test_own_receiver_traffic_is_filtered_but_cursor_still_advances(tmp_path, monkeypatch):
    """A gateway forwarding its own syslog to this add-on's receiver port
    shouldn't dominate Live View -- and even when an entire poll window is
    nothing but that noise, since_id must still move past it, or the next
    poll re-fetches the same noisy rows forever."""
    from app.db import connect
    from app.web import routes_live

    client = _client(tmp_path, monkeypatch)
    host_ip = "192.168.0.68"
    monkeypatch.setattr(routes_live, "get_host_ip", lambda: host_ip)
    syslog_port = client.application.config["ZTA_CONFIG"].syslog_port

    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        _insert_event(conn, "192.168.0.1", host_ip, dst_port=syslog_port)
        conn.commit()

    bootstrap = client.get("/live/events").get_json()
    cursor = bootstrap["max_id"]

    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        _insert_event(conn, "192.168.0.1", host_ip, dst_port=syslog_port)
        conn.commit()

    body = client.get(f"/live/events?since_id={cursor}").get_json()
    assert body["events"] == []
    assert body["max_id"] == cursor + 1
