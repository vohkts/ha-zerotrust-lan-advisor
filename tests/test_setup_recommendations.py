import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

import app.config as config_module
from app import db
from app.analysis.setup_recommendations import generate_setup_recommendations
from app.config import Config

NOW = time.time()


def _config(tmp_path, monkeypatch, **overrides):
    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    base = dict(
        syslog_port=514, netflow_port=2055, allowed_sources=(), network_labels=(),
        retention_days=90, min_recurring_days=3, ignore_own_receiver_traffic=True,
        enable_mdns_classification=False, llm_mode="local", llm_remote_base_url="", llm_model_path="", llm_send_real_identifiers=False,
        unifi_enabled=False, unifi_host="", unifi_verify_tls=False, unifi_apply_mode="manual", unifi_apply_acknowledged=False,
        display_timezone_utc=False, ignore_unifi_console_traffic=True,
    )
    base.update(overrides)
    return Config(**base)


def _write_health(tmp_path, **fields):
    health_dir = tmp_path / "health"
    health_dir.mkdir(parents=True, exist_ok=True)
    (health_dir / "syslog.json").write_text(json.dumps(fields))


def test_noisy_category_above_threshold_produces_a_finding(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    config = _config(tmp_path, monkeypatch)
    _write_health(tmp_path, noise_ap_client_events=600)

    written = generate_setup_recommendations(conn, config, now=NOW)
    assert written == 1

    row = conn.execute("SELECT category, pattern_signature, pattern_summary_text FROM recommendations").fetchone()
    assert row[0] == "setup"
    assert row[1] == "noise:ap_client_events"
    assert "roaming" in row[2]


def test_below_threshold_produces_nothing(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    config = _config(tmp_path, monkeypatch)
    _write_health(tmp_path, noise_ap_client_events=10)

    written = generate_setup_recommendations(conn, config, now=NOW)
    assert written == 0


def test_second_pass_does_not_duplicate(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    config = _config(tmp_path, monkeypatch)
    _write_health(tmp_path, noise_ap_client_events=600)

    generate_setup_recommendations(conn, config, now=NOW)
    second_pass = generate_setup_recommendations(conn, config, now=NOW)

    assert second_pass == 0
    assert conn.execute("SELECT COUNT(*) FROM recommendations").fetchone()[0] == 1


def test_no_health_file_at_all_produces_nothing(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    config = _config(tmp_path, monkeypatch)
    written = generate_setup_recommendations(conn, config, now=NOW)
    assert written == 0
