import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis import runner
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
