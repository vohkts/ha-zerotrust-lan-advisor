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
        ignore_own_receiver_traffic=True,
        enable_mdns_classification=False,
        llm_mode="local",
        llm_remote_base_url="",
        llm_model_path="",
        unifi_enabled=False,
        unifi_host="",
        unifi_verify_tls=False,
        unifi_apply_mode="manual",
        display_timezone_utc=False,
        ignore_unifi_console_traffic=True,
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

    result = engine.run_analysis_pass(conn, _config())
    assert result.zero_trust_written == 1
    assert result.setup_written == 0

    rows = conn.execute("SELECT status, category, pattern_summary_text FROM recommendations").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "pending"
    assert rows[0][1] == "zero_trust"
    assert "AirPlay" in rows[0][2]


def test_second_pass_does_not_duplicate_existing_recommendation(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_recurring_pattern(conn)
    monkeypatch.setattr(engine, "chat_completion", lambda *a, **k: json.dumps(FAKE_RECOMMENDATION))

    engine.run_analysis_pass(conn, _config())
    second_pass = engine.run_analysis_pass(conn, _config())

    assert second_pass.zero_trust_written == 0
    assert conn.execute("SELECT COUNT(*) FROM recommendations").fetchone()[0] == 1


def test_pattern_below_recurrence_threshold_produces_nothing(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_recurring_pattern(conn, days=1)  # only one distinct day
    monkeypatch.setattr(engine, "chat_completion", lambda *a, **k: json.dumps(FAKE_RECOMMENDATION))

    result = engine.run_analysis_pass(conn, _config(min_recurring_days=3))
    assert result.zero_trust_written == 0


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

    result = engine.run_analysis_pass(conn, _config())
    assert result.zero_trust_written == 0
    assert conn.execute("SELECT COUNT(*) FROM recommendations").fetchone()[0] == 0


def test_unifi_console_traffic_never_becomes_a_recommendation(tmp_path, monkeypatch):
    # The UDM console's own management IP -- DNS/DHCP served to every
    # device, health checks, etc. -- same "infrastructure noise, not a
    # segmentation decision" reasoning as own-receiver traffic.
    monkeypatch.setattr(engine, "get_host_ip", lambda: None)
    monkeypatch.setattr(engine, "chat_completion", lambda *a, **k: json.dumps(FAKE_RECOMMENDATION))

    conn = db.connect(tmp_path / "zerotrust.db")
    base_ts = time.time() - 3 * 86400
    for day in range(3):
        conn.execute(
            """INSERT INTO events_firewall
               (ts, src_ip, dst_ip, src_port, dst_port, proto, action, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (base_ts + day * 86400, "192.168.10.5", "192.168.1.1", 51000, 53, 17, "ALLOW", base_ts),
        )
    conn.commit()

    result = engine.run_analysis_pass(conn, _config(unifi_host="192.168.1.1", ignore_unifi_console_traffic=True))
    assert result.zero_trust_written == 0
    assert conn.execute("SELECT COUNT(*) FROM recommendations").fetchone()[0] == 0


def test_unifi_console_traffic_toggle_off_lets_it_through(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "get_host_ip", lambda: None)
    monkeypatch.setattr(engine, "chat_completion", lambda *a, **k: json.dumps(FAKE_RECOMMENDATION))

    conn = db.connect(tmp_path / "zerotrust.db")
    base_ts = time.time() - 3 * 86400
    for day in range(3):
        conn.execute(
            """INSERT INTO events_firewall
               (ts, src_ip, dst_ip, src_port, dst_port, proto, action, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (base_ts + day * 86400, "192.168.10.5", "192.168.1.1", 51000, 53, 17, "ALLOW", base_ts),
        )
    conn.commit()

    result = engine.run_analysis_pass(conn, _config(unifi_host="192.168.1.1", ignore_unifi_console_traffic=False))
    assert result.zero_trust_written == 1


def test_ignore_own_receiver_traffic_toggle_off_lets_it_through(tmp_path, monkeypatch):
    # Same seed as the test above, but with the setting explicitly disabled.
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

    result = engine.run_analysis_pass(conn, _config(ignore_own_receiver_traffic=False))
    assert result.zero_trust_written == 1


def test_stale_own_receiver_recommendation_is_purged_on_next_pass(tmp_path, monkeypatch):
    # Simulates a recommendation created before ignore_own_receiver_traffic
    # existed — sitting there with the raw host IP as its destination label
    # (no network map existed yet either) and the syslog port.
    monkeypatch.setattr(engine, "get_host_ip", lambda: "192.168.0.68")
    monkeypatch.setattr(engine, "chat_completion", lambda *a, **k: json.dumps(FAKE_RECOMMENDATION))

    conn = db.connect(tmp_path / "zerotrust.db")
    conn.execute(
        """INSERT INTO recommendations
           (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
            confidence, evidence_event_ids)
           VALUES (?, 'pending', 'zero_trust', '192.168.0.1|192.168.0.68|Unclassified|Unclassified|17|514',
                   'stale', '{}', 'low', '[]')""",
        (time.time(),),
    )
    # An unrelated recommendation that happens to share the same port —
    # must survive the purge since its destination isn't this host.
    conn.execute(
        """INSERT INTO recommendations
           (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
            confidence, evidence_event_ids)
           VALUES (?, 'pending', 'zero_trust', 'IoT|Home|Unclassified|Unclassified|17|514',
                   'unrelated', '{}', 'low', '[]')""",
        (time.time(),),
    )
    conn.commit()

    engine.run_analysis_pass(conn, _config())

    remaining = conn.execute("SELECT pattern_signature FROM recommendations WHERE category = 'zero_trust'").fetchall()
    signatures = {row[0] for row in remaining}
    assert "192.168.0.1|192.168.0.68|Unclassified|Unclassified|17|514" not in signatures
    assert "IoT|Home|Unclassified|Unclassified|17|514" in signatures


def test_llm_failure_is_skipped_not_raised(tmp_path, monkeypatch):
    from app.llm.client import LLMError

    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_recurring_pattern(conn)

    def _boom(*a, **k):
        raise LLMError("endpoint unreachable")

    monkeypatch.setattr(engine, "chat_completion", _boom)

    result = engine.run_analysis_pass(conn, _config())
    assert result.zero_trust_written == 0
    assert conn.execute("SELECT COUNT(*) FROM recommendations").fetchone()[0] == 0
