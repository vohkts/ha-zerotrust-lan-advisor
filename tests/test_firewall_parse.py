import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

import pytest
from app.firewall_parse import UnparsableLine, parse_firewall_line


def test_parses_generic_netfilter_style_line():
    line = (
        "kernel: [Internal->Internal::Block] IN=br1 OUT=br2 SRC=192.168.10.5 "
        "DST=192.168.20.9 PROTO=TCP SPT=51823 DPT=8009 ACTION=DROP"
    )
    event = parse_firewall_line(line)
    assert event.src_ip == "192.168.10.5"
    assert event.dst_ip == "192.168.20.9"
    assert event.proto == 6
    assert event.src_port == 51823
    assert event.dst_port == 8009
    assert event.rule_prefix == "Internal->Internal::Block"
    assert event.action == "DROP"


def test_parses_line_with_numeric_proto_and_no_rule_prefix():
    line = "SRC=10.0.0.1 DST=10.0.0.2 PROTO=17 SPT=53 DPT=54321"
    event = parse_firewall_line(line)
    assert event.proto == 17
    assert event.rule_prefix is None


@pytest.mark.parametrize(
    "line",
    [
        "",
        "a" * 5000,
        "SRC=10.0.0.1 PROTO=TCP",  # missing DST
        "SRC=not-an-ip DST=10.0.0.2 PROTO=TCP",  # invalid SRC
        "SRC=10.0.0.1 DST=10.0.0.2",  # missing PROTO
        "SRC=10.0.0.1 DST=10.0.0.2 PROTO=notaproto",
    ],
)
def test_rejects_rather_than_guesses(line):
    with pytest.raises(UnparsableLine):
        parse_firewall_line(line)


def test_ports_out_of_range_are_dropped_not_the_whole_line():
    line = "SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP SPT=99999 DPT=80"
    event = parse_firewall_line(line)
    assert event.src_port is None
    assert event.dst_port == 80
