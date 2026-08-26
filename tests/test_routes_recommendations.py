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


def test_accepted_recommendation_shows_as_implemented_once_a_matching_rule_exists(tmp_path, monkeypatch):
    import json

    from app.db import connect

    client = _client(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        conn.execute(
            """INSERT INTO recommendations
               (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                confidence, evidence_event_ids)
               VALUES (?, 'accepted', 'zero_trust', 'IoT|Server|Unclassified|Unclassified|17|123',
                       'NTP query', '{}', 'medium', '[]')""",
            (time.time(),),
        )
        conn.execute(
            "INSERT INTO unifi_policies (id, name, enabled, action, protocol, raw_json, fetched_at) "
            "VALUES ('p1', 'Allow NTP', 1, 'ALLOW', 'udp', ?, ?)",
            (
                json.dumps(
                    {
                        "action": {"type": "ALLOW"},
                        "destination": {"trafficFilter": {"portFilter": {"items": [{"type": "PORT_NUMBER", "value": 123}]}}},
                    }
                ),
                time.time(),
            ),
        )
        conn.commit()

    body = client.get("/recommendations").get_data(as_text=True)
    assert "Implemented" in body


def test_pending_items_are_the_default_view_accepted_and_dismissed_move_to_reviewed(tmp_path, monkeypatch):
    from app.db import connect

    client = _client(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        for i, (status, summary) in enumerate(
            (("pending", "still open"), ("accepted", "already accepted"), ("dismissed", "already dismissed"))
        ):
            conn.execute(
                """INSERT INTO recommendations
                   (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                    confidence, evidence_event_ids)
                   VALUES (?, ?, 'zero_trust', ?, ?, '{}', 'low', '[]')""",
                (time.time(), status, f"IoT|Home|A|B|6|{7000 + i}", summary),
            )
        conn.commit()

    body = client.get("/recommendations").get_data(as_text=True)
    assert "still open" in body
    # Accepted/dismissed items are still present on the page (the reviewed
    # tab), just not inside the pending zero_trust tab-panel -- delimited
    # by the next sibling tab-panel's opening tag, not a generic </div>,
    # since the panel itself contains further nested divs.
    import re

    zero_trust_panel = re.search(
        r'<div class="tab-panel" data-tab-panel="zero_trust">.*?(?=<div class="tab-panel")', body, re.S
    )
    assert zero_trust_panel is not None
    assert "already accepted" not in zero_trust_panel.group()
    assert "already dismissed" not in zero_trust_panel.group()
    assert "already accepted" in body
    assert "already dismissed" in body


def test_reopen_sets_status_back_to_pending(tmp_path, monkeypatch):
    from app.db import connect

    client = _client(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        conn.execute(
            """INSERT INTO recommendations
               (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                confidence, evidence_event_ids)
               VALUES (?, 'dismissed', 'zero_trust', 'IoT|Home|A|B|6|7000', 'x', '{}', 'low', '[]')""",
            (time.time(),),
        )
        conn.commit()
        rec_id = conn.execute("SELECT id FROM recommendations").fetchone()[0]

    resp = client.post(f"/recommendations/{rec_id}/reopen")
    assert resp.get_json() == {"status": "pending"}

    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        assert conn.execute("SELECT status FROM recommendations WHERE id = ?", (rec_id,)).fetchone()[0] == "pending"


def test_implemented_item_exposes_the_matched_policy_id_for_a_detail_link(tmp_path, monkeypatch):
    import json

    from app.db import connect

    client = _client(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        conn.execute(
            """INSERT INTO recommendations
               (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                confidence, evidence_event_ids)
               VALUES (?, 'accepted', 'zero_trust', 'IoT|Server|A|B|17|123', 'x', '{}', 'medium', '[]')""",
            (time.time(),),
        )
        conn.execute(
            "INSERT INTO unifi_policies (id, name, enabled, action, protocol, raw_json, fetched_at) "
            "VALUES ('p1', 'Allow NTP', 1, 'ALLOW', 'udp', ?, ?)",
            (
                json.dumps(
                    {
                        "action": {"type": "ALLOW"},
                        "destination": {"trafficFilter": {"portFilter": {"items": [{"type": "PORT_NUMBER", "value": 123}]}}},
                    }
                ),
                time.time(),
            ),
        )
        conn.commit()

    body = client.get("/recommendations").get_data(as_text=True)
    assert 'data-policy-id="p1"' in body


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
