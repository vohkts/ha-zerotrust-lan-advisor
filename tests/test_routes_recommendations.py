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


def test_zero_trust_card_shows_the_real_device_behind_the_pattern(tmp_path, monkeypatch):
    # Reported live: the recommendation text alone ("a single,
    # consistently the same device") gave no way to tell which real
    # device that actually was -- this never leaves the box, same as the
    # Traffic page, so there's no reason not to show it.
    import json as jsonlib

    from app.db import connect

    client = _client(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        conn.execute(
            "INSERT INTO events_firewall (ts, src_ip, dst_ip, src_port, dst_port, proto, action, received_at) "
            "VALUES (?, '192.168.10.5', '192.168.20.9', 51000, 443, 6, 'ALLOW', ?)",
            (time.time(), time.time()),
        )
        conn.execute(
            "INSERT INTO identities (device_key, ip, hostname, first_seen, last_seen) "
            "VALUES ('192.168.10.5', '192.168.10.5', 'kitchen-echo', ?, ?)",
            (time.time(), time.time()),
        )
        conn.execute(
            """INSERT INTO recommendations
               (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                confidence, evidence_event_ids)
               VALUES (?, 'pending', 'zero_trust', 'IoT|Home|A|B|6|443', 'x', '{}', 'low', ?)""",
            (time.time(), jsonlib.dumps([1])),
        )
        conn.commit()

    body = client.get("/recommendations").get_data(as_text=True)
    assert "kitchen-echo" in body
    assert "192.168.20.9" in body


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


# --- Stage 3: apply -----------------------------------------------------


def _client_apply_gated_open(tmp_path, monkeypatch):
    """A client with all three STAGE3_APPLY_GOVERNANCE.md §5 conditions
    satisfied -- used to test the actual apply flow. Individual gate
    tests below start from the plain (fully closed) _client instead."""
    import json as jsonlib

    import app.config as config_module

    monkeypatch.setenv("ZTA_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_module, "OPTIONS_PATH", tmp_path / "options.json")
    monkeypatch.setattr(config_module, "SECRETS_DIR", tmp_path / "secrets")
    (tmp_path / "options.json").write_text(
        jsonlib.dumps(
            {
                "unifi_apply_mode": "manual",
                "unifi_apply_acknowledged": True,
                "unifi_enabled": True,
                "unifi_host": "192.168.1.1",
            }
        )
    )
    config_module.write_secret("unifi_api_key", "test-key")

    from app.web.server import create_app as _create_app

    app = _create_app()
    app.testing = True
    return app.test_client()


def test_apply_gate_default_is_fully_closed(tmp_path, monkeypatch):
    # unifi_apply_mode already defaults to "manual" (from Stage 2) -- the
    # acknowledgment gate is the one actually stopping a fresh install.
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/recommendations/1/apply-preview")
    assert resp.status_code == 403
    assert "acknowledged" in resp.get_json()["error"]


def test_apply_gate_requires_acknowledgment_even_with_manual_mode_and_unifi_configured(tmp_path, monkeypatch):
    import json as jsonlib

    import app.config as config_module

    monkeypatch.setenv("ZTA_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_module, "OPTIONS_PATH", tmp_path / "options.json")
    monkeypatch.setattr(config_module, "SECRETS_DIR", tmp_path / "secrets")
    (tmp_path / "options.json").write_text(
        jsonlib.dumps({"unifi_apply_mode": "manual", "unifi_enabled": True, "unifi_host": "192.168.1.1"})
    )
    config_module.write_secret("unifi_api_key", "test-key")

    from app.web.server import create_app as _create_app

    app = _create_app()
    app.testing = True
    resp = app.test_client().get("/recommendations/1/apply-preview")
    assert resp.status_code == 403
    assert "acknowledged" in resp.get_json()["error"]


def test_apply_preview_404s_for_an_unknown_recommendation(tmp_path, monkeypatch):
    client = _client_apply_gated_open(tmp_path, monkeypatch)
    resp = client.get("/recommendations/999/apply-preview")
    assert resp.status_code == 404


def test_apply_preview_refuses_a_pending_not_yet_accepted_recommendation(tmp_path, monkeypatch):
    from app.db import connect

    client = _client_apply_gated_open(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        conn.execute(
            """INSERT INTO recommendations
               (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                confidence, evidence_event_ids)
               VALUES (?, 'pending', 'zero_trust', 'IoT|Server|A|B|17|123', 'x', '{}', 'low', '[]')""",
            (time.time(),),
        )
        conn.commit()
        rec_id = conn.execute("SELECT id FROM recommendations").fetchone()[0]

    resp = client.get(f"/recommendations/{rec_id}/apply-preview")
    assert resp.status_code == 400
    assert "accepted" in resp.get_json()["error"]


def test_apply_preview_refuses_when_no_real_network_can_be_confirmed(tmp_path, monkeypatch):
    from app.db import connect

    client = _client_apply_gated_open(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        conn.execute(
            """INSERT INTO recommendations
               (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                confidence, evidence_event_ids)
               VALUES (?, 'accepted', 'zero_trust', 'IoT|Server|A|B|17|123', 'x',
                       '{"action": "allow", "rule_source": "IoT", "rule_destination": "Server"}',
                       'low', '[]')""",
            (time.time(),),
        )
        conn.commit()
        rec_id = conn.execute("SELECT id FROM recommendations").fetchone()[0]

    resp = client.get(f"/recommendations/{rec_id}/apply-preview")
    assert resp.status_code == 422
    assert "No real device IPs" in resp.get_json()["error"]


def test_apply_succeeds_and_records_the_real_policy_id(tmp_path, monkeypatch):
    import json as jsonlib

    from app.db import connect

    client = _client_apply_gated_open(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        conn.execute(
            "INSERT INTO events_firewall (ts, src_ip, dst_ip, src_port, dst_port, proto, iface_in, iface_out, action, received_at) "
            "VALUES (?, '192.168.10.5', '192.168.20.9', 51000, 123, 17, 'br1', 'br2', 'ALLOW', ?)",
            (time.time(), time.time()),
        )
        conn.execute(
            "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) VALUES "
            "('net-iot', 'IoT', 1, NULL, ?, ?)",
            (jsonlib.dumps({"zoneId": "zone-iot"}), time.time()),
        )
        conn.execute(
            "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) VALUES "
            "('net-server', 'Server', 2, NULL, ?, ?)",
            (jsonlib.dumps({"zoneId": "zone-server"}), time.time()),
        )
        conn.execute(
            """INSERT INTO recommendations
               (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                confidence, evidence_event_ids)
               VALUES (?, 'accepted', 'zero_trust', 'IoT|Server|A|B|17|123', 'x',
                       '{"action": "allow", "rule_source": "IoT", "rule_destination": "the Pi-hole"}',
                       'low', ?)""",
            (time.time(), jsonlib.dumps([1])),
        )
        conn.execute(
            "INSERT INTO unifi_capability_report (checked_at, reachable, site_id, capabilities_json) "
            "VALUES (?, 1, 'site-1', '[]')",
            (time.time(),),
        )
        conn.commit()
        rec_id = conn.execute("SELECT id FROM recommendations WHERE category = 'zero_trust'").fetchone()[0]

    monkeypatch.setattr(
        routes_recommendations,
        "create_policy",
        lambda client, site_id, payload: {"id": "created-policy-id", **payload},
    )

    resp = client.post(f"/recommendations/{rec_id}/apply")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body == {"status": "applied", "policy_id": "created-policy-id"}

    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        row = conn.execute(
            "SELECT applied_policy_id, applied_at FROM recommendations WHERE id = ?", (rec_id,)
        ).fetchone()
        assert row[0] == "created-policy-id"
        assert row[1] is not None


def test_apply_refuses_a_duplicate_when_a_covering_policy_already_exists(tmp_path, monkeypatch):
    import json as jsonlib

    from app.db import connect

    client = _client_apply_gated_open(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        conn.execute(
            """INSERT INTO recommendations
               (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                confidence, evidence_event_ids)
               VALUES (?, 'accepted', 'zero_trust', 'IoT|Server|A|B|17|123', 'x',
                       '{"action": "allow"}', 'low', '[]')""",
            (time.time(),),
        )
        conn.execute(
            "INSERT INTO unifi_policies (id, name, enabled, action, protocol, raw_json, fetched_at) "
            "VALUES ('p1', 'Already there', 1, 'ALLOW', 'udp', ?, ?)",
            (
                jsonlib.dumps(
                    {
                        "action": {"type": "ALLOW"},
                        "destination": {"trafficFilter": {"portFilter": {"items": [{"type": "PORT_NUMBER", "value": 123}]}}},
                    }
                ),
                time.time(),
            ),
        )
        conn.commit()
        rec_id = conn.execute("SELECT id FROM recommendations WHERE category = 'zero_trust'").fetchone()[0]

    called = []
    monkeypatch.setattr(routes_recommendations, "create_policy", lambda *a, **k: called.append(1))

    resp = client.post(f"/recommendations/{rec_id}/apply")
    assert resp.status_code == 409
    assert called == []


def test_apply_surfaces_a_real_unifi_error_without_marking_it_applied(tmp_path, monkeypatch):
    import json as jsonlib

    from app.db import connect
    from app.unifi.client import UnifiError

    client = _client_apply_gated_open(tmp_path, monkeypatch)
    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        conn.execute(
            "INSERT INTO events_firewall (ts, src_ip, dst_ip, src_port, dst_port, proto, iface_in, iface_out, action, received_at) "
            "VALUES (?, '192.168.10.5', '192.168.20.9', 51000, 123, 17, 'br1', 'br2', 'ALLOW', ?)",
            (time.time(), time.time()),
        )
        conn.execute(
            "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) VALUES "
            "('net-iot', 'IoT', 1, NULL, ?, ?)",
            (jsonlib.dumps({"zoneId": "zone-iot"}), time.time()),
        )
        conn.execute(
            "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) VALUES "
            "('net-server', 'Server', 2, NULL, ?, ?)",
            (jsonlib.dumps({"zoneId": "zone-server"}), time.time()),
        )
        conn.execute(
            """INSERT INTO recommendations
               (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                confidence, evidence_event_ids)
               VALUES (?, 'accepted', 'zero_trust', 'IoT|Server|A|B|17|123', 'x',
                       '{"action": "allow"}', 'low', ?)""",
            (time.time(), jsonlib.dumps([1])),
        )
        conn.execute(
            "INSERT INTO unifi_capability_report (checked_at, reachable, site_id, capabilities_json) "
            "VALUES (?, 1, 'site-1', '[]')",
            (time.time(),),
        )
        conn.commit()
        rec_id = conn.execute("SELECT id FROM recommendations WHERE category = 'zero_trust'").fetchone()[0]

    def _boom(client, site_id, payload):
        raise UnifiError("403 Forbidden for /sites/site-1/firewall/policies: insufficient scope")

    monkeypatch.setattr(routes_recommendations, "create_policy", _boom)

    resp = client.post(f"/recommendations/{rec_id}/apply")
    assert resp.status_code == 502
    assert "insufficient scope" in resp.get_json()["error"]

    with client.application.app_context():
        conn = connect(client.application.config["ZTA_CONFIG"].db_path)
        row = conn.execute("SELECT applied_at FROM recommendations WHERE id = ?", (rec_id,)).fetchone()
        assert row[0] is None
