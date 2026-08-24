import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db
from app.analysis.netlabels import parse_network_labels
from app.analysis.network_map import (
    build_network_map,
    infer_ip_keys,
    load_friendly_names,
    resolve_label,
    set_friendly_name,
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


def test_build_network_map_prefix_fallback_for_flow_only_ips(tmp_path):
    conn = _seed_db(tmp_path)
    result = build_network_map(conn, since=NOW - 60)
    assert result.ip_to_key["192.168.30.1"] == "192.168.30.0/24"
    # A pure public IP with no local prefix meaning still gets a /24 key —
    # that's fine, resolve_label falls back further for display purposes
    # only when nothing was ever discovered for an IP at all.
    assert "8.8.8.8" in result.ip_to_key


def test_resolve_label_priority_manual_then_friendly_then_key_then_raw_ip(tmp_path):
    conn = _seed_db(tmp_path)
    network_map = build_network_map(conn, since=NOW - 60)

    # Nothing set yet: falls back to the discovered key itself.
    assert resolve_label("192.168.10.5", network_map, {}) == "br1"

    # A friendly name overrides the raw key.
    set_friendly_name(conn, "br1", "IoT")
    friendly = load_friendly_names(conn)
    assert resolve_label("192.168.10.5", network_map, friendly) == "IoT"

    # An explicit manual label (Settings override) wins over both.
    manual = parse_network_labels(["192.168.10.0/24=ManualOverride"])
    assert resolve_label("192.168.10.5", network_map, friendly, manual) == "ManualOverride"

    # An IP nothing was ever discovered for falls back to itself.
    assert resolve_label("203.0.113.1", network_map, friendly) == "203.0.113.1"


def test_set_friendly_name_empty_string_clears_it(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    set_friendly_name(conn, "br1", "IoT")
    assert load_friendly_names(conn) == {"br1": "IoT"}
    set_friendly_name(conn, "br1", "   ")
    assert load_friendly_names(conn) == {}
