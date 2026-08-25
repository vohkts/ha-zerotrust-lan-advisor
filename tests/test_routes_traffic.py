import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

import ipaddress

from app.analysis.netlabels import parse_network_labels
from app.analysis.network_map import DiscoveredNetwork, NetworkMap, UnifiNetworkInfo
from app.db import connect
from app.web.routes_traffic import _Event, _build_flow_tables, _build_host_rows, _build_network_rows, _count_events

NETWORK_MAP = NetworkMap(
    networks=[
        DiscoveredNetwork(
            key="br1", kind="interface", hosts=frozenset({"192.168.10.5", "192.168.10.6"}),
            event_count=3, first_seen=100, last_seen=300, guessed_range="192.168.10.0/24",
        ),
        DiscoveredNetwork(
            key="br2", kind="interface", hosts=frozenset({"192.168.20.9"}),
            event_count=2, first_seen=200, last_seen=300, guessed_range="192.168.20.0/24",
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
    rows, hidden = _build_network_rows(NETWORK_MAP, FRIENDLY_NAMES)
    by_key = {r["key"]: r for r in rows}
    assert hidden == 0

    assert by_key["br1"]["display_name"] == "IoT"
    assert by_key["br1"]["hosts"] == 2  # .10.5 and .10.6
    assert by_key["br1"]["events"] == 3
    assert by_key["br2"]["display_name"] == "Home"
    assert by_key["br2"]["hosts"] == 1  # .20.9 only


def test_network_rows_fall_back_to_guessed_range_without_a_friendly_name():
    # Not the raw interface name — "br1" means nothing to a user.
    rows, _hidden = _build_network_rows(NETWORK_MAP, {})
    assert {r["key"]: r["display_name"] for r in rows} == {
        "br1": "192.168.10.0/24",
        "br2": "192.168.20.0/24",
    }


def test_network_rows_hides_single_host_prefix_guesses_as_noise():
    # A random external IP that got its own /24 guess is not a real
    # network — interface-confirmed groupings are never filtered this way,
    # regardless of host count.
    noisy_map = NetworkMap(
        networks=[
            *NETWORK_MAP.networks,
            DiscoveredNetwork(
                key="8.8.8.0/24", kind="prefix", hosts=frozenset({"8.8.8.8"}),
                event_count=1, first_seen=100, last_seen=100, guessed_range="8.8.8.0/24",
            ),
        ],
        ip_to_key={**NETWORK_MAP.ip_to_key, "8.8.8.8": "8.8.8.0/24"},
    )
    rows, hidden = _build_network_rows(noisy_map, {})
    assert {r["key"] for r in rows} == {"br1", "br2"}
    assert hidden == 1


def test_network_rows_hides_a_multi_host_public_ip_cluster_as_noise():
    # The original filter only caught a *single*-host public grouping --
    # missed exactly this case (several public IPs sharing a /24, e.g.
    # behind the same CDN), reported live as "still 100+ entries with
    # UniFi active." None of them are a network of the user's at all.
    noisy_map = NetworkMap(
        networks=[
            *NETWORK_MAP.networks,
            DiscoveredNetwork(
                key="8.8.8.0/24", kind="prefix", hosts=frozenset({"8.8.8.4", "8.8.8.9"}),
                event_count=4, first_seen=100, last_seen=100, guessed_range="8.8.8.0/24",
            ),
        ],
        ip_to_key={**NETWORK_MAP.ip_to_key, "8.8.8.4": "8.8.8.0/24", "8.8.8.9": "8.8.8.0/24"},
    )
    rows, hidden = _build_network_rows(noisy_map, {})
    assert {r["key"] for r in rows} == {"br1", "br2"}
    assert hidden == 1


def test_network_rows_hides_a_public_ip_cluster_even_when_interface_confirmed():
    # A WAN-facing interface can log IN=/OUT= too -- interface confirmation
    # is about grouping confidence, not about whether the hosts are local.
    noisy_map = NetworkMap(
        networks=[
            *NETWORK_MAP.networks,
            DiscoveredNetwork(
                key="wan0", kind="interface", hosts=frozenset({"8.8.8.4", "8.8.8.9"}),
                event_count=4, first_seen=100, last_seen=100, guessed_range="8.8.8.0/24",
            ),
        ],
        ip_to_key={**NETWORK_MAP.ip_to_key, "8.8.8.4": "wan0", "8.8.8.9": "wan0"},
    )
    rows, hidden = _build_network_rows(noisy_map, {})
    assert {r["key"] for r in rows} == {"br1", "br2"}
    assert hidden == 1


def test_network_rows_hides_a_guess_once_unifi_confirms_that_range():
    unifi_networks = [UnifiNetworkInfo(name="IoT VLAN", network=ipaddress.ip_network("192.168.10.0/24"))]
    rows, hidden = _build_network_rows(NETWORK_MAP, {}, unifi_networks)
    assert {r["key"] for r in rows} == {"br2"}  # br1 (192.168.10.0/24) is now redundant
    assert hidden == 1


def test_host_rows_ranked_by_event_count_with_first_last_seen():
    rows, _hidden = _build_host_rows(NETWORK_MAP, FRIENDLY_NAMES, NO_MANUAL_LABELS, {}, _events())
    by_ip = {r["ip"]: r for r in rows}

    assert by_ip["192.168.10.5"]["events"] == 2
    assert by_ip["192.168.10.5"]["last_seen"] == 300
    assert by_ip["192.168.10.5"]["first_seen"] == 200
    assert by_ip["192.168.10.5"]["network"] == "IoT"
    assert by_ip["192.168.10.5"]["device_class"] == "Unclassified"


def test_host_rows_use_identity_when_available():
    identities = {"192.168.10.5": {"device_class": "Apple HomePod / smart speaker", "confidence": "high"}}
    rows, _hidden = _build_host_rows(NETWORK_MAP, FRIENDLY_NAMES, NO_MANUAL_LABELS, identities, _events())
    row = next(r for r in rows if r["ip"] == "192.168.10.5")
    assert row["device_class"] == "Apple HomePod / smart speaker"
    assert row["confidence"] == "high"


def test_manual_label_override_wins_over_discovered_network():
    manual = parse_network_labels(["192.168.10.0/24=ManualOverride"])
    rows, _hidden = _build_host_rows(NETWORK_MAP, FRIENDLY_NAMES, manual, {}, _events())
    row = next(r for r in rows if r["ip"] == "192.168.10.5")
    assert row["network"] == "ManualOverride"


def test_host_rows_excludes_public_ips_and_counts_them_hidden():
    # A public IP like 8.8.8.8 is a flow endpoint, not a "host" on this
    # network — it must not appear in the inventory, and must not crowd a
    # real local device out of the top-N ranking either.
    rows, hidden = _build_host_rows(NETWORK_MAP, FRIENDLY_NAMES, NO_MANUAL_LABELS, {}, _events())
    assert "8.8.8.8" not in {r["ip"] for r in rows}
    assert hidden == 1


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


def test_top_flows_include_known_device_name_and_class():
    identities = {"192.168.10.5": {"hostname": "Johns-iPhone", "device_class": "iPhone", "confidence": "high"}}
    top_flows, _ = _build_flow_tables(NETWORK_MAP, FRIENDLY_NAMES, NO_MANUAL_LABELS, identities, _events())
    busiest = top_flows[0]
    assert busiest["src_name"] == "Johns-iPhone"
    assert busiest["src_class"] == "iPhone"
    assert busiest["dst_name"] is None  # 192.168.20.9 has no identity known


def test_recent_examples_deduplicated_and_capped():
    events = [_Event(ts=100 + i, src_ip="192.168.10.5", dst_ip="192.168.20.9", proto=6, dst_port=7000) for i in range(150)]
    _, recent = _build_flow_tables(NETWORK_MAP, FRIENDLY_NAMES, NO_MANUAL_LABELS, {}, events)
    assert len(recent) == 1  # only one distinct (src,dst,proto,port) combination exists
    assert recent[0]["count"] == 150


def test_count_events_reports_the_true_total_not_a_capped_sample(tmp_path):
    # Real bug: the headline "N events" figure used len(_load_events(...)),
    # which is capped per-table for rendering performance — indistinguishable
    # from a genuinely quiet network once a busy one hit that cap.
    conn = connect(tmp_path / "zerotrust.db")
    for i in range(5):
        conn.execute(
            "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, iface_in, iface_out, rule_prefix, action, received_at) "
            "VALUES (?, '10.0.0.1', '10.0.0.2', 6, NULL, NULL, NULL, 'ALLOW', ?)",
            (100 + i, 100 + i),
        )
    for i in range(3):
        conn.execute(
            "INSERT INTO events_flow (ts_start, ts_end, src_ip, dst_ip, proto, exporter_ip, received_at) "
            "VALUES (?, ?, '10.0.0.1', '10.0.0.2', 6, '10.0.0.254', ?)",
            (100 + i, 100 + i, 100 + i),
        )
    conn.commit()
    assert _count_events(conn, since=0) == 8
