import ipaddress
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db
from app.analysis.netlabels import parse_network_labels
from app.analysis.network_map import (
    UnifiNetworkInfo,
    build_network_map,
    infer_ip_keys,
    load_friendly_names,
    load_unifi_networks,
    load_unifi_vlan_names,
    resolve_label,
    set_friendly_name,
    unifi_network_for_interface,
)

NOW = time.time()


def test_infer_ip_keys_uses_most_common_interface_vote():
    rows = [
        ("10.0.0.5", "10.0.0.9", "br1", "br2"),
        ("10.0.0.5", "10.0.0.9", "br1", "br2"),
        ("10.0.0.5", "10.0.0.9", "br9", "br2"),  # a rarer, outlier observation
    ]
    resolved = infer_ip_keys(rows, {"10.0.0.5", "10.0.0.9"})
    assert resolved["10.0.0.5"] == ("br1", "interface")
    assert resolved["10.0.0.9"] == ("br2", "interface")


def test_infer_ip_keys_falls_back_to_prefix_when_no_interface_seen():
    resolved = infer_ip_keys([], {"192.168.10.5"})
    assert resolved["192.168.10.5"] == ("192.168.10.0/24", "prefix")


def test_infer_ip_keys_ipv6_without_interface_is_unresolved():
    resolved = infer_ip_keys([], {"2a11:fb80::1"})
    assert "2a11:fb80::1" not in resolved


def _seed_db(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    conn.execute(
        "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, iface_in, iface_out, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (NOW, "192.168.10.5", "192.168.20.9", 6, "br1", "br2", NOW),
    )
    conn.execute(
        "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, iface_in, iface_out, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (NOW, "192.168.10.6", "192.168.20.9", 6, "br1", "br2", NOW),
    )
    # A flow-only IP never seen with interface info at all.
    conn.execute(
        "INSERT INTO events_flow (ts_start, ts_end, src_ip, dst_ip, proto, exporter_ip, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (NOW, NOW, "192.168.30.1", "8.8.8.8", 17, "192.168.0.1", NOW),
    )
    conn.commit()
    return conn


def test_build_network_map_groups_hosts_by_interface(tmp_path):
    conn = _seed_db(tmp_path)
    result = build_network_map(conn, since=NOW - 60)
    by_key = {n.key: n for n in result.networks}

    assert by_key["br1"].hosts == frozenset({"192.168.10.5", "192.168.10.6"})
    assert by_key["br1"].event_count == 2
    assert by_key["br2"].hosts == frozenset({"192.168.20.9"})
    assert result.ip_to_key["192.168.10.5"] == "br1"


def test_build_network_map_derives_a_guessed_range_for_interface_networks(tmp_path):
    conn = _seed_db(tmp_path)
    result = build_network_map(conn, since=NOW - 60)
    by_key = {n.key: n for n in result.networks}

    # br1's hosts (192.168.10.5, .6) both fall in the same /24 — a clean guess.
    assert by_key["br1"].guessed_range == "192.168.10.0/24"
    assert by_key["br1"].kind == "interface"
    # For kind="prefix" networks the key already *is* the guessed range.
    assert by_key["192.168.30.0/24"].guessed_range == "192.168.30.0/24"


def test_build_network_map_prefix_fallback_for_flow_only_ips(tmp_path):
    conn = _seed_db(tmp_path)
    result = build_network_map(conn, since=NOW - 60)
    assert result.ip_to_key["192.168.30.1"] == "192.168.30.0/24"
    # A pure public IP with no local prefix meaning still gets a /24 key —
    # that's fine, resolve_label falls back further for display purposes
    # only when nothing was ever discovered for an IP at all.
    assert "8.8.8.8" in result.ip_to_key


def test_resolve_label_priority_manual_then_friendly_then_guessed_range_then_raw_ip(tmp_path):
    conn = _seed_db(tmp_path)
    network_map = build_network_map(conn, since=NOW - 60)

    # Nothing set yet: falls back to the guessed IP range, not the raw
    # interface name — "br1" means nothing to a user, "192.168.10.0/24" does.
    assert resolve_label("192.168.10.5", network_map, {}) == "192.168.10.0/24"

    # A friendly name overrides the guessed range.
    set_friendly_name(conn, "br1", "IoT")
    friendly = load_friendly_names(conn)
    assert resolve_label("192.168.10.5", network_map, friendly) == "IoT"

    # An explicit manual label (Settings override) wins over both.
    manual = parse_network_labels(["192.168.10.0/24=ManualOverride"])
    assert resolve_label("192.168.10.5", network_map, friendly, manual) == "ManualOverride"

    # An IP nothing was ever discovered for falls back to itself.
    assert resolve_label("203.0.113.1", network_map, friendly) == "203.0.113.1"


def test_resolve_label_prefers_a_real_unifi_network_over_a_guessed_range(tmp_path):
    conn = _seed_db(tmp_path)
    network_map = build_network_map(conn, since=NOW - 60)
    unifi_networks = [UnifiNetworkInfo(name="IoT VLAN", network=ipaddress.ip_network("192.168.10.0/24"))]

    assert resolve_label("192.168.10.5", network_map, {}, unifi_networks=unifi_networks) == "IoT VLAN"


def test_resolve_label_an_explicit_friendly_name_still_wins_over_unifi():
    # A friendly name is a deliberate per-network customization, same as a
    # manual override -- UniFi becomes the default source of truth, not a
    # silent override of something the user already named on purpose.
    from app.analysis.network_map import DiscoveredNetwork, NetworkMap

    network_map = NetworkMap(
        networks=[DiscoveredNetwork(key="br1", kind="interface", hosts=frozenset({"192.168.10.5"}),
                                     event_count=1, first_seen=0, last_seen=0, guessed_range="192.168.10.0/24")],
        ip_to_key={"192.168.10.5": "br1"},
    )
    unifi_networks = [UnifiNetworkInfo(name="IoT VLAN", network=ipaddress.ip_network("192.168.10.0/24"))]

    assert resolve_label("192.168.10.5", network_map, {"br1": "Kids devices"}, unifi_networks=unifi_networks) == "Kids devices"


def test_resolve_label_manual_override_still_wins_over_unifi(tmp_path):
    conn = _seed_db(tmp_path)
    network_map = build_network_map(conn, since=NOW - 60)
    unifi_networks = [UnifiNetworkInfo(name="IoT VLAN", network=ipaddress.ip_network("192.168.10.0/24"))]
    manual = parse_network_labels(["192.168.10.0/24=ManualOverride"])

    assert resolve_label("192.168.10.5", network_map, {}, manual, unifi_networks) == "ManualOverride"


def test_load_unifi_networks_skips_an_unparseable_subnet(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    conn.execute(
        "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) "
        "VALUES ('n1', 'Bad', NULL, 'not-a-subnet', '{}', ?)", (NOW,),
    )
    conn.execute(
        "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) "
        "VALUES ('n2', 'Good', 10, '192.168.10.0/24', '{}', ?)", (NOW,),
    )
    conn.commit()
    networks = load_unifi_networks(conn)
    assert [n.name for n in networks] == ["Good"]


def test_unifi_network_for_interface_matches_br_prefix_to_vlan_id():
    # Confirmed live against a real console: br<vlanId> is UniFi's own
    # bridge-naming convention, and reliable even when the network API's
    # subnet field is entirely absent (which it was, on that console).
    vlan_names = {22: "IoT", 2: "Home", 1: "Management"}
    assert unifi_network_for_interface("br22", vlan_names) == "IoT"
    assert unifi_network_for_interface("br2", vlan_names) == "Home"
    assert unifi_network_for_interface("br0", vlan_names) == "Management"  # native/untagged -> VLAN 1
    assert unifi_network_for_interface("wgsrv1", vlan_names) is None  # not a bridge at all
    assert unifi_network_for_interface("br99", vlan_names) is None  # no matching vlan_id


def test_load_unifi_vlan_names_works_without_any_subnet_data(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    conn.execute(
        "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) "
        "VALUES ('n1', 'IoT', 22, NULL, '{}', ?)", (NOW,),
    )
    conn.commit()
    assert load_unifi_vlan_names(conn) == {22: "IoT"}


def test_resolve_label_falls_back_to_interface_vlan_match_when_no_subnet_data(tmp_path):
    # The actual bug found live: unifi_network_for_ip() alone is a no-op
    # when the API returns no subnet, so real network names never resolved
    # at all -- even though vlan_id (and this add-on's own interface
    # discovery) were both available the whole time.
    conn = _seed_db(tmp_path)
    network_map = build_network_map(conn, since=NOW - 60)
    vlan_names = {1: "IoT"}  # br1 -> vlan 1 -> "IoT", per the seeded br1/br2 interfaces

    assert resolve_label("192.168.10.5", network_map, {}, vlan_names=vlan_names) == "IoT"


def test_resolve_label_prefers_unifi_subnet_match_over_interface_vlan_match(tmp_path):
    conn = _seed_db(tmp_path)
    network_map = build_network_map(conn, since=NOW - 60)
    unifi_networks = [UnifiNetworkInfo(name="From subnet", network=ipaddress.ip_network("192.168.10.0/24"))]
    vlan_names = {1: "From vlan"}

    assert (
        resolve_label("192.168.10.5", network_map, {}, unifi_networks=unifi_networks, vlan_names=vlan_names)
        == "From subnet"
    )


def test_set_friendly_name_empty_string_clears_it(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    set_friendly_name(conn, "br1", "IoT")
    assert load_friendly_names(conn) == {"br1": "IoT"}
    set_friendly_name(conn, "br1", "   ")
    assert load_friendly_names(conn) == {}
