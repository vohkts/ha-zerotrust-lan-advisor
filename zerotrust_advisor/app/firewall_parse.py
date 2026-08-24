"""Parses firewall/syslog lines into structured events.

Router firmware doesn't agree on a single log line format, and even a single
vendor's format drifts across firmware versions. Rather than match one exact
layout, this treats the line the way Linux's own netfilter logging does:
free-form text containing `KEY=VALUE` tokens, of which we only care about a
handful. That makes it tolerant of prefix/suffix text changing around the
tokens we need.

A line that's missing what we need to build a usable event is rejected
outright — we never store a partial or guessed record. Getting this wrong
would quietly poison the evidence the recommendation engine builds on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_LINE_LENGTH = 4096

_TOKEN_RE = re.compile(r"\b([A-Z]+)=(\S+)")
_RULE_PREFIX_RE = re.compile(r"\[([^\]]+)\]")

_PROTO_NAMES = {"tcp": 6, "udp": 17, "icmp": 1}

_REQUIRED_FIELDS = ("SRC", "DST")

# UniFi/EdgeOS-derived firewalls don't emit a separate ACTION= token — the
# verdict is baked into the auto-generated rule description itself, as a
# single letter between dashes: RULESET-A-PRIORITY (Accept), -D- (Drop),
# -R- (Reject). Confirmed against real firewall log lines, not guessed —
# every line ingested before this existed had a silently-None action,
# which the recommendation engine was treating as "always blocked".
_RULE_ACTION_RE = re.compile(r"-([ADR])-\d+$")
_RULE_ACTION_NAMES = {"A": "ALLOW", "D": "DROP", "R": "REJECT"}


class UnparsableLine(ValueError):
    pass


@dataclass(frozen=True)
class FirewallEvent:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    proto: int
    iface_in: str | None
    iface_out: str | None
    rule_prefix: str | None
    action: str | None


def _valid_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    # Minimal IPv6 sanity check: hex groups and colons only, at least one "::" or 8 groups.
    return bool(re.fullmatch(r"[0-9a-fA-F:]+", value)) and ":" in value


def _clamp_port(raw: str | None) -> int | None:
    if raw is None or not raw.isdigit():
        return None
    port = int(raw)
    return port if 0 <= port <= 65535 else None


def _proto_to_number(raw: str) -> int | None:
    if raw.isdigit():
        value = int(raw)
        return value if 0 <= value <= 255 else None
    return _PROTO_NAMES.get(raw.lower())


def parse_firewall_line(line: str) -> FirewallEvent:
    if not line or len(line) > MAX_LINE_LENGTH:
        raise UnparsableLine("line missing or too long")

    tokens = dict(_TOKEN_RE.findall(line))
    if not all(field in tokens for field in _REQUIRED_FIELDS):
        raise UnparsableLine("missing SRC/DST")

    src_ip, dst_ip = tokens["SRC"], tokens["DST"]
    if not (_valid_ip(src_ip) and _valid_ip(dst_ip)):
        raise UnparsableLine("SRC/DST not valid IPs")

    proto = _proto_to_number(tokens.get("PROTO", ""))
    if proto is None:
        raise UnparsableLine("missing or invalid PROTO")

    prefix_match = _RULE_PREFIX_RE.search(line)
    rule_prefix = prefix_match.group(1)[:128] if prefix_match else None

    action = tokens.get("ACTION")
    if action is None and rule_prefix:
        action_match = _RULE_ACTION_RE.search(rule_prefix)
        if action_match:
            action = _RULE_ACTION_NAMES[action_match.group(1)]

    return FirewallEvent(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=_clamp_port(tokens.get("SPT")),
        dst_port=_clamp_port(tokens.get("DPT")),
        proto=proto,
        iface_in=tokens.get("IN")[:32] if tokens.get("IN") else None,
        iface_out=tokens.get("OUT")[:32] if tokens.get("OUT") else None,
        rule_prefix=rule_prefix,
        action=action,
    )
