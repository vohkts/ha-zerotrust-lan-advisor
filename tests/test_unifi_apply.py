import ipaddress
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db
from app.analysis.network_map import DiscoveredNetwork, NetworkMap, UnifiNetworkInfo
from app.unifi import apply as apply_module
from app.unifi.apply import ApplyNotPossible, build_policy_payload

NOW = time.time()

# br1 -> the "IoT" network (vlan 1, via interface match); no subnet data,
# matching the real production console this add-on was actually tested
# against (see zerotrust-advisor-perf-and-recommendation-quality memory).
NETWORK_MAP = NetworkMap(
    networks=[
        DiscoveredNetwork(key="br1", kind="interface", hosts=frozenset({"192.168.10.5", "192.168.10.6"}),
                           event_count=2, first_seen=0, last_seen=0, guessed_range="192.168.10.0/24"),
        DiscoveredNetwork(key="br2", kind="interface", hosts=frozenset({"192.168.20.9"}),
                           event_count=1, first_seen=0, last_seen=0, guessed_range="192.168.20.0/24"),
    ],
    ip_to_key={"192.168.10.5": "br1", "192.168.10.6": "br1", "192.168.20.9": "br2"},
)
VLAN_NAMES = {1: "IoT", 2: "Server"}


def _seed_networks(conn):
    conn.execute(
        "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) VALUES "
        "('net-iot', 'IoT', 1, NULL, ?, ?)",
        (json.dumps({"zoneId": "zone-iot"}), NOW),
    )
    conn.execute(
        "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) VALUES "
        "('net-server', 'Server', 2, NULL, ?, ?)",
        (json.dumps({"zoneId": "zone-server"}), NOW),
    )
    conn.commit()


def test_rules_are_currently_created_disabled_for_safe_live_testing():
    # A deliberate, temporary flag -- flip it only on purpose. If this
    # test starts failing because someone flipped CREATE_RULES_ENABLED to
    # True, that's the point: it's a reminder this was a live-testing
    # safety measure, not a permanent design decision.
    assert apply_module.CREATE_RULES_ENABLED is False


def test_population_source_to_single_device_destination(tmp_path):
    # The exact shape this whole project's recommendation phrasing was
    # built around: "devices on the IoT network" -> "the Pi-hole".
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_networks(conn)

    payload = build_policy_payload(
        conn,
        name="Allow IoT to Pi-hole",
        action="allow",
        proto=17,
        port=53,
        src_ips=["192.168.10.5", "192.168.10.6"],
        dst_ips=["192.168.20.9"],
        network_map=NETWORK_MAP,
        unifi_networks=[],
        vlan_names=VLAN_NAMES,
    )

    assert payload["source"]["zoneId"] == "zone-iot"
    assert payload["source"]["trafficFilter"]["type"] == "NETWORK"
    assert payload["source"]["trafficFilter"]["networkFilter"]["networkIds"] == ["net-iot"]
    assert "portFilter" not in payload["source"]["trafficFilter"]

    assert payload["destination"]["zoneId"] == "zone-server"
    assert payload["destination"]["trafficFilter"]["type"] == "IP_ADDRESS"
    assert payload["destination"]["trafficFilter"]["ipAddressFilter"]["items"] == [
        {"type": "IP_ADDRESS", "value": "192.168.20.9"}
    ]
    assert payload["destination"]["trafficFilter"]["portFilter"]["items"] == [{"type": "PORT_NUMBER", "value": 53}]

    assert payload["action"] == {"type": "ALLOW", "allowReturnTraffic": True}
    assert payload["ipProtocolScope"] == {
        "ipVersion": "IPV4_AND_IPV6",
        "protocolFilter": {"type": "PROTOCOL_NUMBER", "matchOpposite": False, "protocolNumber": 17},
    }
    # Temporary safety measure while validating the write flow live: every
    # created rule starts disabled, zero traffic impact either way -- see
    # apply.CREATE_RULES_ENABLED's own docstring. Update this assertion
    # deliberately, not incidentally, once that flips back.
    assert payload["enabled"] is False
    assert payload["name"] == "Allow IoT to Pi-hole"


def test_block_action_has_no_allow_return_traffic_field(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_networks(conn)

    payload = build_policy_payload(
        conn, name="Block it", action="block", proto=6, port=22,
        src_ips=["192.168.10.5"], dst_ips=["192.168.20.9"],
        network_map=NETWORK_MAP, unifi_networks=[], vlan_names=VLAN_NAMES,
    )
    assert payload["action"] == {"type": "BLOCK"}


def test_refuses_an_unsupported_action(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_networks(conn)

    with pytest.raises(ApplyNotPossible, match="Unsupported action"):
        build_policy_payload(
            conn, name="x", action="reject", proto=6, port=22,
            src_ips=["192.168.10.5"], dst_ips=["192.168.20.9"],
            network_map=NETWORK_MAP, unifi_networks=[], vlan_names=VLAN_NAMES,
        )


def test_refuses_when_no_real_ip_can_be_resolved(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_networks(conn)

    with pytest.raises(ApplyNotPossible, match="No real device IPs"):
        build_policy_payload(
            conn, name="x", action="allow", proto=6, port=22,
            src_ips=[], dst_ips=["192.168.20.9"],
            network_map=NETWORK_MAP, unifi_networks=[], vlan_names=VLAN_NAMES,
        )


def test_refuses_when_an_ip_confirms_to_no_real_unifi_network(tmp_path):
    # A real, but never-UniFi-confirmed IP -- e.g. purely traffic-guessed,
    # no interface vote and no subnet match. Must refuse, not fall back to
    # the guessed range.
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_networks(conn)

    with pytest.raises(ApplyNotPossible, match="isn't confirmed against a real UniFi network"):
        build_policy_payload(
            conn, name="x", action="allow", proto=6, port=22,
            src_ips=["203.0.113.9"], dst_ips=["192.168.20.9"],
            network_map=NETWORK_MAP, unifi_networks=[], vlan_names=VLAN_NAMES,
        )


def test_refuses_when_a_populations_ips_disagree_on_network(tmp_path):
    # Evidence spanning two different confirmed networks on the same side
    # -- must not silently pick one.
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_networks(conn)

    with pytest.raises(ApplyNotPossible, match="more than one network"):
        build_policy_payload(
            conn, name="x", action="allow", proto=6, port=22,
            src_ips=["192.168.10.5", "192.168.20.9"], dst_ips=["192.168.20.9"],
            network_map=NETWORK_MAP, unifi_networks=[], vlan_names=VLAN_NAMES,
        )


def test_refuses_when_the_confirmed_network_has_no_zone_on_record(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    conn.execute(
        "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) VALUES "
        "('net-iot', 'IoT', 1, NULL, ?, ?)",
        (json.dumps({}), NOW),  # no zoneId at all
    )
    conn.execute(
        "INSERT INTO unifi_networks (id, name, vlan_id, subnet, raw_json, fetched_at) VALUES "
        "('net-server', 'Server', 2, NULL, ?, ?)",
        (json.dumps({"zoneId": "zone-server"}), NOW),
    )
    conn.commit()

    with pytest.raises(ApplyNotPossible, match="no zone on record"):
        build_policy_payload(
            conn, name="x", action="allow", proto=6, port=22,
            src_ips=["192.168.10.5"], dst_ips=["192.168.20.9"],
            network_map=NETWORK_MAP, unifi_networks=[], vlan_names=VLAN_NAMES,
        )


def test_subnet_confirmed_network_is_preferred_over_interface_match(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_networks(conn)
    unifi_networks = [UnifiNetworkInfo(name="IoT", network=ipaddress.ip_network("192.168.10.0/24"))]

    payload = build_policy_payload(
        conn, name="x", action="allow", proto=6, port=443,
        src_ips=["192.168.10.5"], dst_ips=["192.168.20.9"],
        network_map=NETWORK_MAP, unifi_networks=unifi_networks, vlan_names=VLAN_NAMES,
    )
    assert payload["source"]["zoneId"] == "zone-iot"


def test_two_single_devices_both_get_ip_address_filters(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _seed_networks(conn)

    payload = build_policy_payload(
        conn, name="x", action="allow", proto=6, port=443,
        src_ips=["192.168.10.5"], dst_ips=["192.168.20.9"],
        network_map=NETWORK_MAP, unifi_networks=[], vlan_names=VLAN_NAMES,
    )
    assert payload["source"]["trafficFilter"]["type"] == "IP_ADDRESS"
    assert payload["destination"]["trafficFilter"]["type"] == "IP_ADDRESS"
