import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis.netlabels import parse_network_labels
from app.web.routes_traffic import _Event, _build_flow_tables, _build_host_rows, _build_network_rows

LABELS = parse_network_labels(["192.168.10.0/24=IoT", "192.168.20.0/24=Home"])


def _events():
    # Newest first, matching how _load_events hands data to the builders.
    return [
        _Event(ts=300, src_ip="192.168.10.5", dst_ip="192.168.20.9", proto=6, dst_port=7000),
        _Event(ts=200, src_ip="192.168.10.5", dst_ip="192.168.20.9", proto=6, dst_port=7000),
        _Event(ts=100, src_ip="192.168.10.6", dst_ip="8.8.8.8", proto=17, dst_port=53),
    ]


def test_network_rows_count_hosts_and_events_per_label():
    rows = _build_network_rows(LABELS, _events())
    by_label = {r["label"]: r for r in rows}

    assert by_label["IoT"]["hosts"] == 2  # .10.5 and .10.6
    assert by_label["IoT"]["events"] == 3  # all three events touch IoT
    assert by_label["Home"]["hosts"] == 1  # .20.9 only
    assert by_label["Home"]["events"] == 2


def test_host_rows_ranked_by_event_count_with_first_last_seen():
    rows = _build_host_rows(LABELS, {}, _events())
    by_ip = {r["ip"]: r for r in rows}

    assert by_ip["192.168.10.5"]["events"] == 2
    assert by_ip["192.168.10.5"]["last_seen"] == 300
    assert by_ip["192.168.10.5"]["first_seen"] == 200
    assert by_ip["192.168.10.5"]["device_class"] == "Unclassified"


def test_host_rows_use_identity_when_available():
    identities = {"192.168.10.5": {"device_class": "Apple HomePod / smart speaker", "confidence": "high"}}
    rows = _build_host_rows(LABELS, identities, _events())
    row = next(r for r in rows if r["ip"] == "192.168.10.5")
    assert row["device_class"] == "Apple HomePod / smart speaker"
    assert row["confidence"] == "high"


def test_top_flows_aggregates_by_full_key_and_counts_occurrences():
    top_flows, _ = _build_flow_tables(LABELS, {}, _events())
    assert len(top_flows) == 2  # two distinct (src,dst,proto,port) combinations
    busiest = top_flows[0]
    assert busiest["src"] == "192.168.10.5"
    assert busiest["dst"] == "192.168.20.9"
    assert busiest["count"] == 2
    assert busiest["proto"] == "TCP"
    assert busiest["port_hint"] == "AirPlay"


def test_recent_examples_deduplicated_and_capped():
    events = [_Event(ts=100 + i, src_ip="192.168.10.5", dst_ip="192.168.20.9", proto=6, dst_port=7000) for i in range(150)]
    _, recent = _build_flow_tables(LABELS, {}, events)
    assert len(recent) == 1  # only one distinct (src,dst,proto,port) combination exists
    assert recent[0]["count"] == 150
