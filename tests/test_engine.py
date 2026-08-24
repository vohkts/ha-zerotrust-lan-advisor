import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db
from app.analysis import engine
from app.config import Config


@pytest.fixture(autouse=True)
def _no_supervisor_call(monkeypatch):
    # get_host_ip() hits the real Supervisor API; tests have none to talk
    # to, so default it to "unknown" (None) unless a test overrides it.
    monkeypatch.setattr(engine, "get_host_ip", lambda: None)


FAKE_RECOMMENDATION = {
    "plain_language_summary": "Looks like AirPlay from a HomePod to an iPhone.",
    "likely_purpose": "AirPlay audio streaming",
    "suggested_rule_scope": "Allow TCP/7000 from IoT HomePod to Home iPhone only",
    "confidence": "medium",
    "caveats": ["Device classification is vendor-based, not device-model-based."],
}


def _config(**overrides):
    base = dict(
        syslog_port=514,
        netflow_port=2055,
        allowed_sources=(),
        network_labels=("192.168.10.0/24=IoT", "192.168.20.0/24=Home"),
        retention_days=90,
        min_recurring_days=3,
        enable_mdns_classification=False,
        llm_mode="local",
        llm_remote_base_url="",
        llm_model_path="",
    )
    base.update(overrides)
    return Config(**base)


def _seed_recurring_pattern(conn, days=3):
    base_ts = time.time() - days * 86400
    for day in range(days):
        conn.execute(
            """INSERT INTO events_firewall
               (ts, src_ip, dst_ip, src_port, dst_port, proto, action, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (base_ts + day * 86400, "192.168.10.5", "192.168.20.9", 51000 + day, 7000, 6, "DROP", base_ts),
        )
    conn.commit()


def test_run_analysis_pass_writes_one_recommendation(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_recurring_pattern(conn)

    monkeypatch.setattr(engine, "chat_completion", lambda *a, **k: json.dumps(FAKE_RECOMMENDATION))

    written = engine.run_analysis_pass(conn, _config())
    assert written == 1

    rows = conn.execute("SELECT status, pattern_summary_text FROM recommendations").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "pending"
    assert "AirPlay" in rows[0][1]


def test_second_pass_does_not_duplicate_existing_recommendation(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_recurring_pattern(conn)
    monkeypatch.setattr(engine, "chat_completion", lambda *a, **k: json.dumps(FAKE_RECOMMENDATION))

    engine.run_analysis_pass(conn, _config())
    second_pass_written = engine.run_analysis_pass(conn, _config())

    assert second_pass_written == 0
    assert conn.execute("SELECT COUNT(*) FROM recommendations").fetchone()[0] == 1


def test_pattern_below_recurrence_threshold_produces_nothing(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_recurring_pattern(conn, days=1)  # only one distinct day
    monkeypatch.setattr(engine, "chat_completion", lambda *a, **k: json.dumps(FAKE_RECOMMENDATION))

    written = engine.run_analysis_pass(conn, _config(min_recurring_days=3))
    assert written == 0


def test_own_receiver_traffic_never_becomes_a_recommendation(tmp_path, monkeypatch):
    # The router logging its own syslog-forwarding traffic to this add-on's
    # receiver port — found in production as the single highest-volume
    # "pattern" the engine ever saw, and not a real segmentation decision.
    monkeypatch.setattr(engine, "get_host_ip", lambda: "192.168.0.68")
    monkeypatch.setattr(engine, "chat_completion", lambda *a, **k: json.dumps(FAKE_RECOMMENDATION))

    conn = db.connect(tmp_path / "zerotrust.db")
    base_ts = time.time() - 3 * 86400
    for day in range(3):
        conn.execute(
            """INSERT INTO events_firewall
               (ts, src_ip, dst_ip, src_port, dst_port, proto, action, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (base_ts + day * 86400, "192.168.0.1", "192.168.0.68", 51000, 514, 17, "DROP", base_ts),
        )
    conn.commit()

    written = engine.run_analysis_pass(conn, _config())
    assert written == 0
    assert conn.execute("SELECT COUNT(*) FROM recommendations").fetchone()[0] == 0


def test_llm_failure_is_skipped_not_raised(tmp_path, monkeypatch):
    from app.llm.client import LLMError

    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_recurring_pattern(conn)

    def _boom(*a, **k):
        raise LLMError("endpoint unreachable")

    monkeypatch.setattr(engine, "chat_completion", _boom)

    written = engine.run_analysis_pass(conn, _config())
    assert written == 0
    assert conn.execute("SELECT COUNT(*) FROM recommendations").fetchone()[0] == 0
