import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db
from app.analysis.rule_match import find_covering_policy, load_parsed_policies

NOW = time.time()


def _insert_policy(conn, policy_id, name, enabled, raw):
    conn.execute(
        "INSERT INTO unifi_policies (id, name, enabled, action, protocol, raw_json, fetched_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (policy_id, name, 1 if enabled else 0, "ALLOW", "tcp", json.dumps(raw), NOW),
    )


def _narrow_allow_raw(port):
    return {
        "action": {"type": "ALLOW"},
        "destination": {
            "trafficFilter": {
                "portFilter": {"items": [{"type": "PORT_NUMBER", "value": port}]},
            }
        },
    }


def _broad_allow_raw():
    # A real "allow everything to this destination" rule -- no port filter
    # at all, exactly the shape that must NOT count as coverage.
    return {"action": {"type": "ALLOW"}, "destination": {"trafficFilter": {}}}


def test_load_parsed_policies_extracts_real_port_filter_shape(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_policy(conn, "p1", "Allow NTP", True, _narrow_allow_raw(123))
    conn.commit()

    policies = load_parsed_policies(conn)
    assert policies[0].ports == frozenset({123})
    assert policies[0].action == "ALLOW"
    assert policies[0].enabled is True


def test_find_covering_policy_matches_a_narrow_enabled_allow_rule(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_policy(conn, "p1", "Allow NTP", True, _narrow_allow_raw(123))
    conn.commit()

    policies = load_parsed_policies(conn)
    assert find_covering_policy(policies, 123) is not None
    assert find_covering_policy(policies, 999) is None


def test_a_broad_allow_all_rule_never_counts_as_coverage(tmp_path):
    # The exact case the user explicitly called out: "Not the allow all of
    # course" -- a catch-all rule must never make every future
    # recommendation for that destination look pre-implemented.
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_policy(conn, "p1", "Allow all to Server", True, _broad_allow_raw())
    conn.commit()

    policies = load_parsed_policies(conn)
    assert find_covering_policy(policies, 123) is None
    assert find_covering_policy(policies, 8086) is None


def test_a_disabled_policy_never_counts_as_coverage(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_policy(conn, "p1", "Allow NTP (disabled)", False, _narrow_allow_raw(123))
    conn.commit()

    policies = load_parsed_policies(conn)
    assert find_covering_policy(policies, 123) is None


def test_a_block_policy_never_counts_as_coverage(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    raw = _narrow_allow_raw(123)
    raw["action"] = {"type": "BLOCK"}
    _insert_policy(conn, "p1", "Block something", True, raw)
    conn.commit()

    policies = load_parsed_policies(conn)
    assert find_covering_policy(policies, 123) is None


def test_no_port_pattern_never_matches_anything(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_policy(conn, "p1", "Allow NTP", True, _narrow_allow_raw(123))
    conn.commit()

    policies = load_parsed_policies(conn)
    assert find_covering_policy(policies, None) is None
