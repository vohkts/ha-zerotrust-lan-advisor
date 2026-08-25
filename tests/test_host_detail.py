import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db
from app.analysis.host_detail import load_host_detail

NOW = time.time()


def _insert_fw(conn, ts, src, dst, proto=6, port=443):
    conn.execute(
        "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, dst_port, action, received_at) "
        "VALUES (?, ?, ?, ?, ?, 'ALLOW', ?)",
        (ts, src, dst, proto, port, ts),
    )


def test_no_events_returns_empty_detail(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    detail = load_host_detail(conn, "192.168.10.5", since=0)
    assert detail.event_count == 0
    assert detail.first_seen is None
    assert detail.top_ports == []


def test_aggregates_ports_partners_and_recent_flows(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_fw(conn, NOW - 300, "192.168.10.5", "192.168.20.9", proto=6, port=7000)
    _insert_fw(conn, NOW - 200, "192.168.10.5", "192.168.20.9", proto=6, port=7000)
    _insert_fw(conn, NOW - 100, "8.8.8.8", "192.168.10.5", proto=17, port=53)
    conn.commit()

    detail = load_host_detail(conn, "192.168.10.5", since=0)
    assert detail.event_count == 3
    assert detail.first_seen == NOW - 300
    assert detail.last_seen == NOW - 100

    ports_by_key = {(p["proto"], p["port"]): p["count"] for p in detail.top_ports}
    assert ports_by_key[("TCP", 7000)] == 2
    assert ports_by_key[("UDP", 53)] == 1

    partners = dict(detail.top_partners)
    assert partners["192.168.20.9"] == 2
    assert partners["8.8.8.8"] == 1

    assert len(detail.recent_flows) == 2  # two distinct (src,dst,proto,port) combinations
    busiest = detail.recent_flows[0]  # most recent first
    assert busiest["src"] == "8.8.8.8"
    assert busiest["count"] == 1


def test_includes_flow_export_events_too(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    conn.execute(
        "INSERT INTO events_flow (ts_start, ts_end, src_ip, dst_ip, proto, dst_port, exporter_ip, received_at) "
        "VALUES (?, ?, '192.168.10.5', '1.1.1.1', 17, 53, '192.168.1.1', ?)",
        (NOW, NOW, NOW),
    )
    conn.commit()
    detail = load_host_detail(conn, "192.168.10.5", since=0)
    assert detail.event_count == 1


def test_window_excludes_events_before_since(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    _insert_fw(conn, NOW - 1000, "192.168.10.5", "192.168.20.9")
    conn.commit()
    detail = load_host_detail(conn, "192.168.10.5", since=NOW - 100)
    assert detail.event_count == 0
