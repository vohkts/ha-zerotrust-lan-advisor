import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis.netlabels import parse_network_labels
from app.analysis.network_map import DiscoveredNetwork, NetworkMap
from app.web.routes_traffic import _Event, _build_flow_tables, _build_host_rows, _build_network_rows

NETWORK_MAP = NetworkMap(
    networks=[
        DiscoveredNetwork(
            key="br1", kind="interface", hosts=frozenset({"192.168.10.5", "192.168.10.6"}),
            event_count=3, first_seen=100, last_seen=300,
        ),
        DiscoveredNetwork(
            key="br2", kind="interface", hosts=frozenset({"192.168.20.9"}),
            event_count=2, first_seen=200, last_seen=300,
        ),
    ],
    ip_to_key={"192.168.10.5": "br1", "192.168.10.6": "br1", "192.168.20.9": "br2"},
)
FRIENDLY_NAMES = {"br1": "IoT", "br2": "Home"}
NO_MANUAL_LABELS = parse_network_labels([])


def _events():
    # Newest first, matching how _load_events hands data to the builders.
    return [
        _Event(ts=300, src_ip="192.168.10.5", dst_ip="192.168.20.9", proto=6, dst_port=7000),
        _Event(ts=200, src_ip="192.168.10.5", dst_ip="192.168.20.9", proto=6, dst_port=7000),
        _Event(ts=100, src_ip="192.168.10.6", dst_ip="8.8.8.8", proto=17, dst_port=53),
    ]


def test_network_rows_reflect_discovered_networks_with_friendly_names():
    rows = _build_network_rows(NETWORK_MAP, FRIENDLY_NAMES)
    by_key = {r["key"]: r for r in rows}

    assert by_key["br1"]["display_name"] == "IoT"
    assert by_key["br1"]["hosts"] == 2  # .10.5 and .10.6
    assert by_key["br1"]["events"] == 3
    assert by_key["br2"]["display_name"] == "Home"
    assert by_key["br2"]["hosts"] == 1  # .20.9 only


def test_network_rows_fall_back_to_key_without_a_friendly_name():
    rows = _build_network_rows(NETWORK_MAP, {})
    assert {r["key"]: r["display_name"] for r in rows} == {"br1": "br1", "br2": "br2"}


def test_host_rows_ranked_by_event_count_with_first_last_seen():
    rows = _build_host_rows(NETWORK_MAP, FRIENDLY_NAMES, NO_MANUAL_LABELS, {}, _events())
    by_ip = {r["ip"]: r for r in rows}

    assert by_ip["192.168.10.5"]["events"] == 2
    assert by_ip["192.168.10.5"]["last_seen"] == 300
    assert by_ip["192.168.10.5"]["first_seen"] == 200
    assert by_ip["192.168.10.5"]["network"] == "IoT"
    assert by_ip["192.168.10.5"]["device_class"] == "Unclassified"


def test_host_rows_use_identity_when_available():
    identities = {"192.168.10.5": {"device_class": "Apple HomePod / smart speaker", "confidence": "high"}}
    rows = _build_host_rows(NETWORK_MAP, FRIENDLY_NAMES, NO_MANUAL_LABELS, identities, _events())
    row = next(r for r in rows if r["ip"] == "192.168.10.5")
    assert row["device_class"] == "Apple HomePod / smart speaker"
    assert row["confidence"] == "high"


def test_manual_label_override_wins_over_discovered_network():
    manual = parse_network_labels(["192.168.10.0/24=ManualOverride"])
    rows = _build_host_rows(NETWORK_MAP, FRIENDLY_NAMES, manual, {}, _events())
    row = next(r for r in rows if r["ip"] == "192.168.10.5")
    assert row["network"] == "ManualOverride"


def test_top_flows_aggregates_by_full_key_and_counts_occurrences():
    top_flows, _ = _build_flow_tables(NETWORK_MAP, FRIENDLY_NAMES, NO_MANUAL_LABELS, {}, _events())
    assert len(top_flows) == 2  # two distinct (src,dst,proto,port) combinations
    busiest = top_flows[0]
    assert busiest["src"] == "192.168.10.5"
    assert busiest["src_network"] == "IoT"
    assert busiest["dst"] == "192.168.20.9"
    assert busiest["dst_network"] == "Home"
    assert busiest["count"] == 2
    assert busiest["proto"] == "TCP"
    assert busiest["port_hint"] == "AirPlay"


def test_recent_examples_deduplicated_and_capped():
    events = [_Event(ts=100 + i, src_ip="192.168.10.5", dst_ip="192.168.20.9", proto=6, dst_port=7000) for i in range(150)]
    _, recent = _build_flow_tables(NETWORK_MAP, FRIENDLY_NAMES, NO_MANUAL_LABELS, {}, events)
    assert len(recent) == 1  # only one distinct (src,dst,proto,port) combination exists
    assert recent[0]["count"] == 150
