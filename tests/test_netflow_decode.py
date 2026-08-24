import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.netflow_decode import TemplateCache, decode_packet

EXPORTER = "192.168.1.1"

# (information_element_id, length) — a realistic v9/IPFIX flow template.
FIELDS_V1 = [
    (8, 4),  # sourceIPv4Address
    (12, 4),  # destinationIPv4Address
    (7, 2),  # sourceTransportPort
    (11, 2),  # destinationTransportPort
    (4, 1),  # protocolIdentifier
    (1, 4),  # octetDeltaCount
    (2, 4),  # packetDeltaCount
    (150, 4),  # flowStartSeconds
    (151, 4),  # flowEndSeconds
]

# A second layout used to test a mid-stream template refresh: same fields,
# reordered, plus one dropped — decoding must follow whatever layout was
# most recently announced for this template ID, not the original one.
FIELDS_V2 = [
    (8, 4),
    (12, 4),
    (4, 1),
    (7, 2),
    (11, 2),
    (1, 4),
    (2, 4),
]


def _ipv4(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def _v9_header(count: int) -> bytes:
    return struct.pack(">HHIIII", 9, count, 0, int(time.time()), 1, 1)


def _ipfix_header(total_len: int) -> bytes:
    return struct.pack(">HHIII", 10, total_len, int(time.time()), 1, 1)


def _template_set(template_id: int, fields: list[tuple[int, int]], ipfix: bool) -> bytes:
    set_id = 2 if ipfix else 0
    body = struct.pack(">HH", template_id, len(fields))
    for ie_id, length in fields:
        body += struct.pack(">HH", ie_id, length)
    return struct.pack(">HH", set_id, 4 + len(body)) + body


def _pack_field(ie_id: int, length: int, values: dict) -> bytes:
    if ie_id in (8, 12):
        return _ipv4(values[ie_id])
    fmt = {1: ">B", 2: ">H", 4: ">I"}[length]
    return struct.pack(fmt, values[ie_id])


def _record(fields: list[tuple[int, int]], values: dict) -> bytes:
    return b"".join(_pack_field(ie_id, length, values) for ie_id, length in fields)


def _data_set(template_id: int, records: list[bytes]) -> bytes:
    body = b"".join(records)
    return struct.pack(">HH", template_id, 4 + len(body)) + body


SAMPLE_VALUES = {
    8: "192.168.10.5",
    12: "192.168.20.9",
    7: 51823,
    11: 8009,
    4: 6,
    1: 4096,
    2: 12,
    150: 1000,
    151: 1010,
}


def test_v9_template_and_data_in_separate_packets():
    templates = TemplateCache()
    tmpl_packet = _v9_header(0) + _template_set(256, FIELDS_V1, ipfix=False)
    assert decode_packet(tmpl_packet, EXPORTER, templates) == []

    record = _record(FIELDS_V1, SAMPLE_VALUES)
    data_packet = _v9_header(1) + _data_set(256, [record])
    flows = decode_packet(data_packet, EXPORTER, templates)

    assert len(flows) == 1
    flow = flows[0]
    assert flow.src_ip == "192.168.10.5"
    assert flow.dst_ip == "192.168.20.9"
    assert flow.src_port == 51823
    assert flow.dst_port == 8009
    assert flow.proto == 6
    assert flow.bytes == 4096
    assert flow.packets == 12


def test_ipfix_template_and_data_in_same_packet():
    templates = TemplateCache()
    tmpl_set = _template_set(300, FIELDS_V1, ipfix=True)
    record = _record(FIELDS_V1, SAMPLE_VALUES)
    data_set = _data_set(300, [record])
    packet = _ipfix_header(16 + len(tmpl_set) + len(data_set)) + tmpl_set + data_set

    flows = decode_packet(packet, EXPORTER, templates)
    assert len(flows) == 1
    assert flows[0].src_ip == "192.168.10.5"


def test_mid_stream_template_refresh_changes_decoding():
    templates = TemplateCache()
    decode_packet(_v9_header(0) + _template_set(256, FIELDS_V1, ipfix=False), EXPORTER, templates)

    # Refresh the same template ID with a different field layout.
    decode_packet(_v9_header(0) + _template_set(256, FIELDS_V2, ipfix=False), EXPORTER, templates)

    record = _record(FIELDS_V2, SAMPLE_VALUES)
    flows = decode_packet(_v9_header(1) + _data_set(256, [record]), EXPORTER, templates)

    assert len(flows) == 1
    assert flows[0].src_port == 51823
    assert flows[0].bytes == 4096
    # FIELDS_V2 has no flowEnd/flowStart fields, so decode falls back to "now".
    assert flows[0].ts_end > 0


def test_data_for_unseen_template_is_dropped_not_stored():
    templates = TemplateCache()
    record = _record(FIELDS_V1, SAMPLE_VALUES)
    flows = decode_packet(_v9_header(1) + _data_set(999, [record]), EXPORTER, templates)
    assert flows == []


def test_trailing_partial_record_is_ignored():
    templates = TemplateCache()
    decode_packet(_v9_header(0) + _template_set(256, FIELDS_V1, ipfix=False), EXPORTER, templates)

    full_record = _record(FIELDS_V1, SAMPLE_VALUES)
    truncated = full_record[:5]  # not a full record's worth of bytes
    flows = decode_packet(_v9_header(1) + _data_set(256, [full_record]) + truncated, EXPORTER, templates)
    assert len(flows) == 1


def test_options_template_without_ip_fields_yields_no_records():
    templates = TemplateCache()
    options_fields = [(1, 4), (2, 4)]  # byte/packet counters only, no addresses
    decode_packet(_v9_header(0) + _template_set(400, options_fields, ipfix=False), EXPORTER, templates)

    record = _record(options_fields, SAMPLE_VALUES)
    flows = decode_packet(_v9_header(1) + _data_set(400, [record]), EXPORTER, templates)
    assert flows == []
