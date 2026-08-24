import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.mdns_listener import parse_mdns_answers


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _answer_bytes(name_bytes: bytes, ip: str) -> bytes:
    rdata = bytes(int(o) for o in ip.split("."))
    return name_bytes + struct.pack(">HHIH", 1, 1, 120, len(rdata)) + rdata


def test_single_a_record_strips_dot_local():
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    packet = header + _answer_bytes(_encode_name("HomePod.local"), "192.168.10.5")

    assert parse_mdns_answers(packet) == [("HomePod", "192.168.10.5")]


def test_hostname_without_local_suffix_is_kept_as_is():
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    packet = header + _answer_bytes(_encode_name("plain-host"), "10.0.0.9")

    assert parse_mdns_answers(packet) == [("plain-host", "10.0.0.9")]


def test_compressed_name_pointer_resolves_correctly():
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 2, 0, 0)
    first_name = _encode_name("HomePod.local")
    first_answer = _answer_bytes(first_name, "192.168.10.5")

    # Second answer's name is a pure compression pointer back to offset 12
    # (the start of the first answer's name, right after the 12-byte header).
    pointer = struct.pack(">H", 0xC000 | 12)
    rdata = bytes(int(o) for o in "192.168.10.6".split("."))
    second_answer = pointer + struct.pack(">HHIH", 1, 1, 120, len(rdata)) + rdata

    packet = header + first_answer + second_answer
    result = parse_mdns_answers(packet)

    assert result == [("HomePod", "192.168.10.5"), ("HomePod", "192.168.10.6")]


def test_non_a_records_are_ignored():
    # type 28 = AAAA, rdlength 16 — not something this decoder handles.
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    name = _encode_name("some-host.local")
    rdata = b"\x00" * 16
    packet = header + name + struct.pack(">HHIH", 28, 1, 120, len(rdata)) + rdata

    assert parse_mdns_answers(packet) == []


def test_truncated_packet_returns_empty_list_not_an_exception():
    assert parse_mdns_answers(b"\x00\x00\x84\x00\x00\x00\x00\x05\x00\x00\x00\x00") == []
    assert parse_mdns_answers(b"") == []
