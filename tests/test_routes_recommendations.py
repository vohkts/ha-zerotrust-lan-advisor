import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis import runner
from app.web import routes_recommendations
from app.web.server import create_app


def _client(tmp_path, monkeypatch):
    import app.config as config_module

    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_module, "OPTIONS_PATH", tmp_path / "options.json")
    monkeypatch.setattr(config_module, "SECRETS_DIR", tmp_path / "secrets")
    app = create_app()
    app.testing = True
    return app.test_client()


def test_is_running_false_when_no_pass_is_active():
    assert runner.is_running() is False


def test_is_running_true_while_the_lock_is_held():
    assert runner._lock.acquire(blocking=False)
    try:
        assert runner.is_running() is True
    finally:
        runner._lock.release()


def test_progress_route_reports_counts_and_running_state(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    body = client.get("/recommendations/progress").get_json()
    assert body == {"running": False, "zero_trust_count": 0, "setup_count": 0}

    assert runner._lock.acquire(blocking=False)
    try:
        body = client.get("/recommendations/progress").get_json()
        assert body["running"] is True
    finally:
        runner._lock.release()


def test_run_now_returns_immediately_without_waiting_for_the_pass(tmp_path, monkeypatch):
    # Real bug, reported live: waiting on the full pass here got the
    # request killed with a 504 by the proxy chain in front of this
    # add-on. The response must come back long before a slow pass finishes.
    finished = threading.Event()

    def _slow_pass(conn, config):
        time.sleep(0.3)
        finished.set()

    monkeypatch.setattr(routes_recommendations, "run_analysis_now", _slow_pass)
    client = _client(tmp_path, monkeypatch)

    resp = client.post("/recommendations/run-now")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "started"}
    assert not finished.is_set()

    assert finished.wait(timeout=2)  # background thread does eventually run it


def test_run_now_reports_already_running_without_starting_a_second_pass(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(routes_recommendations, "run_analysis_now", lambda conn, config: calls.append(1))
    client = _client(tmp_path, monkeypatch)

    assert runner._lock.acquire(blocking=False)
    try:
        resp = client.post("/recommendations/run-now")
        assert resp.status_code == 409
        assert resp.get_json() == {"status": "already_running"}
        assert calls == []
    finally:
        runner._lock.release()
