"""A small, focused NetFlow v9 / IPFIX decoder.

Both formats share the same skeleton: a packet header, followed by a
sequence of sets. A set is either a *template* (defines the field layout for
a numeric template ID) or *data* (a run of records laid out according to a
template seen earlier — possibly in an earlier packet). Exporters resend
templates periodically, so a template cache keyed by (exporter, template id)
is required to decode anything at all.

Stage 1 only needs enough fields to place a flow on a device-class ↔
device-class ↔ port/proto grid: source/destination IPv4, ports, protocol,
byte/packet counts, and flow start/end. Anything else in a record is parsed
(to keep the byte offset correct) but discarded. A record built from an
unrecognized template, or one that doesn't decode cleanly, is dropped rather
than guessed at — same discipline as the firewall log parser.

Only IPv4 field types are handled; IPv6 flow records are skipped for now
rather than mis-decoded.
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass

V9_TEMPLATE_FLOWSET_ID = 0
V9_OPTIONS_TEMPLATE_FLOWSET_ID = 1
IPFIX_TEMPLATE_SET_ID = 2
IPFIX_OPTIONS_TEMPLATE_SET_ID = 3

# IPFIX Information Elements (also reused by v9, which defines the same
# numbers for the fields we care about).
IE_OCTET_DELTA_COUNT = 1
IE_PACKET_DELTA_COUNT = 2
IE_PROTOCOL_IDENTIFIER = 4
IE_SOURCE_TRANSPORT_PORT = 7
IE_SOURCE_IPV4_ADDRESS = 8
IE_DESTINATION_TRANSPORT_PORT = 11
IE_DESTINATION_IPV4_ADDRESS = 12
IE_FLOW_START_SYS_UP_TIME = 22
IE_FLOW_END_SYS_UP_TIME = 21
IE_FLOW_START_SECONDS = 150
IE_FLOW_END_SECONDS = 151

_KNOWN_FIELDS = {
    IE_OCTET_DELTA_COUNT,
    IE_PACKET_DELTA_COUNT,
    IE_PROTOCOL_IDENTIFIER,
    IE_SOURCE_TRANSPORT_PORT,
    IE_SOURCE_IPV4_ADDRESS,
    IE_DESTINATION_TRANSPORT_PORT,
    IE_DESTINATION_IPV4_ADDRESS,
    IE_FLOW_START_SYS_UP_TIME,
    IE_FLOW_END_SYS_UP_TIME,
    IE_FLOW_START_SECONDS,
    IE_FLOW_END_SECONDS,
}


class UndecodableRecord(ValueError):
    """Raised for a record that must not be stored: unknown template, or a
    length/offset mismatch that means the field layout can't be trusted."""


@dataclass(frozen=True)
class Template:
    fields: list[tuple[int, int]]  # (information_element_id, length)

    @property
    def record_length(self) -> int:
        return sum(length for _, length in self.fields)


@dataclass(frozen=True)
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    proto: int
    bytes: int | None
    packets: int | None
    ts_start: float
    ts_end: float


class TemplateCache:
    """Templates are scoped per exporter — two routers could reuse the same
    template ID for different layouts."""

    def __init__(self):
        self._templates: dict[tuple[str, int], Template] = {}

    def put(self, exporter_ip: str, template_id: int, template: Template) -> None:
        self._templates[(exporter_ip, template_id)] = template

    def get(self, exporter_ip: str, template_id: int) -> Template | None:
        return self._templates.get((exporter_ip, template_id))


def _parse_ipv4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _decode_template_set(body: bytes) -> dict[int, Template]:
    templates: dict[int, Template] = {}
    offset = 0
    while offset + 4 <= len(body):
        template_id, field_count = struct.unpack_from(">HH", body, offset)
        offset += 4
        fields: list[tuple[int, int]] = []
        for _ in range(field_count):
            if offset + 4 > len(body):
                raise UndecodableRecord("truncated template field")
            ie_id, length = struct.unpack_from(">HH", body, offset)
            offset += 4
            if ie_id & 0x8000:  # enterprise-specific bit; skip the enterprise number
                offset += 4
            fields.append((ie_id, length))
        if template_id >= 256:
            templates[template_id] = Template(fields=fields)
    return templates


def _decode_data_record(raw: bytes, template: Template, exporter_ip: str, now: float) -> FlowRecord:
    if len(raw) < template.record_length:
        raise UndecodableRecord("data record shorter than its template")

    values: dict[int, bytes] = {}
    offset = 0
    for ie_id, length in template.fields:
        values[ie_id] = raw[offset : offset + length]
        offset += length

    if IE_SOURCE_IPV4_ADDRESS not in values or IE_DESTINATION_IPV4_ADDRESS not in values:
        raise UndecodableRecord("no IPv4 address fields in this template")

    proto_raw = values.get(IE_PROTOCOL_IDENTIFIER)
    if not proto_raw:
        raise UndecodableRecord("missing protocol field")

    def _int(field_bytes: bytes | None) -> int | None:
        return int.from_bytes(field_bytes, "big") if field_bytes else None

    ts_start_raw = values.get(IE_FLOW_START_SECONDS)
    ts_end_raw = values.get(IE_FLOW_END_SECONDS)
    ts_start = float(_int(ts_start_raw)) if ts_start_raw else now
    ts_end = float(_int(ts_end_raw)) if ts_end_raw else now

    return FlowRecord(
        src_ip=_parse_ipv4(values[IE_SOURCE_IPV4_ADDRESS]),
        dst_ip=_parse_ipv4(values[IE_DESTINATION_IPV4_ADDRESS]),
        src_port=_int(values.get(IE_SOURCE_TRANSPORT_PORT)),
        dst_port=_int(values.get(IE_DESTINATION_TRANSPORT_PORT)),
        proto=_int(proto_raw),
        bytes=_int(values.get(IE_OCTET_DELTA_COUNT)),
        packets=_int(values.get(IE_PACKET_DELTA_COUNT)),
        ts_start=ts_start,
        ts_end=ts_end,
    )


def decode_packet(
    packet: bytes, exporter_ip: str, templates: TemplateCache, now: float | None = None
) -> list[FlowRecord]:
    """Decodes one UDP payload. Template sets update `templates` in place;
    data sets are decoded against whatever template is already cached (which
    may be from an earlier packet). Records from an as-yet-unseen template
    are silently dropped, not stored — the exporter will resend the template
    shortly, and there's nothing trustworthy to do with the record before
    that.
    """
    if now is None:
        now = time.time()
    if len(packet) < 4:
        return []

    version = struct.unpack_from(">H", packet, 0)[0]
    if version == 9:
        header_len = 20
    elif version == 10:  # IPFIX
        header_len = 16
    else:
        return []
    if len(packet) < header_len:
        return []

    records: list[FlowRecord] = []
    offset = header_len
    while offset + 4 <= len(packet):
        set_id, set_length = struct.unpack_from(">HH", packet, offset)
        if set_length < 4 or offset + set_length > len(packet):
            break  # malformed set framing; stop rather than misread the rest
        body = packet[offset + 4 : offset + set_length]

        is_template_set = (version == 9 and set_id in (V9_TEMPLATE_FLOWSET_ID, V9_OPTIONS_TEMPLATE_FLOWSET_ID)) or (
            version == 10 and set_id in (IPFIX_TEMPLATE_SET_ID, IPFIX_OPTIONS_TEMPLATE_SET_ID)
        )
        if is_template_set:
            for template_id, template in _decode_template_set(body).items():
                templates.put(exporter_ip, template_id, template)
        elif set_id >= 256:
            template = templates.get(exporter_ip, set_id)
            if template is None or template.record_length == 0:
                offset += set_length
                continue
            record_offset = 0
            while record_offset + template.record_length <= len(body):
                raw = body[record_offset : record_offset + template.record_length]
                record_offset += template.record_length
                try:
                    records.append(_decode_data_record(raw, template, exporter_ip, now))
                except UndecodableRecord:
                    continue  # skip just this record, not the whole packet

        offset += set_length

    return records
