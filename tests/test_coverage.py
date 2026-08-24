import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis.coverage import CoverageInputs, evaluate_coverage

NOW = 1_700_000_000.0


def _inputs(**overrides):
    base = dict(
        now=NOW,
        last_firewall_event_at=NOW - 60,
        last_flow_event_at=NOW - 60,
        rejected_syslog_count=0,
        rejected_flow_count=0,
        inter_vlan_firewall_matches=0,
        inter_vlan_flow_matches=0,
        total_matches=0,
        internal_internal_matches=0,
    )
    base.update(overrides)
    return CoverageInputs(**base)


def test_fully_healthy_state_has_no_warnings():
    assert evaluate_coverage(_inputs()) == []


def test_no_syslog_ever_and_no_rejects_gives_generic_setup_warning():
    warnings = evaluate_coverage(_inputs(last_firewall_event_at=None))
    codes = [w.code for w in warnings]
    assert "syslog_none" in codes


def test_no_syslog_but_rejects_present_points_at_source_ip_mismatch():
    warnings = evaluate_coverage(_inputs(last_firewall_event_at=None, rejected_syslog_count=42))
    codes = [w.code for w in warnings]
    assert "syslog_wrong_source" in codes
    assert "syslog_none" not in codes


def test_stale_syslog_feed_is_flagged():
    warnings = evaluate_coverage(_inputs(last_firewall_event_at=NOW - 7200))
    assert "syslog_stale" in [w.code for w in warnings]


def test_no_flow_data_mirrors_syslog_logic():
    warnings = evaluate_coverage(_inputs(last_flow_event_at=None, rejected_flow_count=5))
    assert "flow_wrong_source" in [w.code for w in warnings]


def test_no_internal_traffic_flagged_when_everything_is_external():
    warnings = evaluate_coverage(_inputs(total_matches=500, internal_internal_matches=0))
    codes = [w.code for w in warnings]
    assert "no_internal_traffic_seen" in codes
    warning = next(w for w in warnings if w.code == "no_internal_traffic_seen")
    assert warning.severity == "info"


def test_no_internal_traffic_not_flagged_once_any_internal_traffic_seen():
    warnings = evaluate_coverage(_inputs(total_matches=500, internal_internal_matches=1))
    assert "no_internal_traffic_seen" not in [w.code for w in warnings]


def test_no_internal_traffic_not_flagged_with_no_data_at_all():
    # Nothing observed yet at all — the generic syslog_none/flow_none
    # warnings already cover that; this check shouldn't pile on.
    warnings = evaluate_coverage(
        _inputs(last_firewall_event_at=None, last_flow_event_at=None, total_matches=0, internal_internal_matches=0)
    )
    assert "no_internal_traffic_seen" not in [w.code for w in warnings]


def test_east_west_gap_detected_when_firewall_sees_it_but_flow_never_does():
    warnings = evaluate_coverage(
        _inputs(inter_vlan_firewall_matches=20, inter_vlan_flow_matches=0)
    )
    codes = [w.code for w in warnings]
    assert "no_east_west_flow_evidence" in codes
    warning = next(w for w in warnings if w.code == "no_east_west_flow_evidence")
    assert warning.severity == "info"


def test_east_west_gap_not_flagged_once_flow_data_confirms_it():
    warnings = evaluate_coverage(
        _inputs(inter_vlan_firewall_matches=20, inter_vlan_flow_matches=3)
    )
    assert "no_east_west_flow_evidence" not in [w.code for w in warnings]


def test_east_west_gap_not_flagged_with_no_inter_vlan_firewall_evidence_at_all():
    # No inter-VLAN firewall matches yet at all — nothing to be missing from flow data.
    warnings = evaluate_coverage(
        _inputs(inter_vlan_firewall_matches=0, inter_vlan_flow_matches=0)
    )
    assert "no_east_west_flow_evidence" not in [w.code for w in warnings]
