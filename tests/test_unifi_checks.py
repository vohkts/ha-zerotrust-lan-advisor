import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db
from app.unifi.checks import generate_unifi_setup_findings

NOW = time.time()


def _insert_zone(conn, id_, name):
    conn.execute(
        "INSERT INTO unifi_zones (id, name, raw_json, fetched_at) VALUES (?, ?, '{}', ?)",
        (id_, name, NOW),
    )


def _insert_policy(conn, id_, name, enabled, logging_enabled, action="ALLOW", src="z1", dst="z2"):
    conn.execute(
        """INSERT INTO unifi_policies
           (id, name, enabled, action, protocol, source_zone_id, destination_zone_id, logging_enabled,
            raw_json, fetched_at)
           VALUES (?, ?, ?, ?, 'tcp', ?, ?, ?, '{}', ?)""",
        (id_, name, int(enabled), action, src, dst, None if logging_enabled is None else int(logging_enabled), NOW),
    )


def test_enabled_policy_with_logging_off_produces_a_finding(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_zone(conn, "z1", "Internal")
    _insert_zone(conn, "z2", "IoT")
    _insert_policy(conn, "p1", "Allow AirPlay", enabled=True, logging_enabled=False)
    conn.commit()

    written = generate_unifi_setup_findings(conn, now=NOW)
    assert written == 1

    row = conn.execute("SELECT pattern_summary_text FROM recommendations WHERE category = 'setup'").fetchone()
    assert "Allow AirPlay" in row[0]
    assert "Internal" in row[0] and "IoT" in row[0]


def test_disabled_policy_is_not_flagged(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_policy(conn, "p1", "Old rule", enabled=False, logging_enabled=False)
    conn.commit()
    assert generate_unifi_setup_findings(conn, now=NOW) == 0


def test_logging_enabled_policy_is_not_flagged(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_policy(conn, "p1", "Fine rule", enabled=True, logging_enabled=True)
    conn.commit()
    assert generate_unifi_setup_findings(conn, now=NOW) == 0


def test_unknown_logging_state_is_not_flagged(tmp_path):
    # NULL means "the API response didn't have a field we recognized" —
    # not "logging is off". Flagging it would be a false claim.
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_policy(conn, "p1", "Unclear rule", enabled=True, logging_enabled=None)
    conn.commit()
    assert generate_unifi_setup_findings(conn, now=NOW) == 0


def test_second_pass_does_not_duplicate(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_policy(conn, "p1", "Allow AirPlay", enabled=True, logging_enabled=False)
    conn.commit()
    assert generate_unifi_setup_findings(conn, now=NOW) == 1
    assert generate_unifi_setup_findings(conn, now=NOW) == 0


def test_no_unifi_data_produces_nothing(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    assert generate_unifi_setup_findings(conn, now=NOW) == 0
