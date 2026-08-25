"""Builds the prompt and response schema used to turn one candidate traffic
pattern into a structured recommendation. This is the only place prompt
text lives, so wording changes don't need to be hunted across the codebase.
"""
from __future__ import annotations

from app.analysis.grouping import CandidatePattern
from app.analysis.known_ports import PROTO_NAMES, describe_port

RECOMMENDATION_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "zero_trust_recommendation",
        "schema": {
            "type": "object",
            "properties": {
                "plain_language_summary": {"type": "string"},
                "likely_purpose": {"type": "string"},
                "suggested_rule_scope": {"type": "string"},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                "caveats": {"type": "array", "items": {"type": "string"}},
            },
            "required": [
                "plain_language_summary",
                "likely_purpose",
                "suggested_rule_scope",
                "confidence",
                "caveats",
            ],
            "additionalProperties": False,
        },
    },
}

_SYSTEM_PROMPT = (
    "You help a home network owner move toward a zero-trust firewall. You are given one "
    "recurring, pseudonymized traffic pattern observed between two device classes on two "
    "networks. Explain in plain language what it's most likely for, and suggest the narrowest "
    "firewall rule that would cover it — scoped to the specific networks, protocol and port "
    "given, never a broad allow. You are never told real device names, IPs or MACs, only "
    "device classes and a confidence level for each — reflect that uncertainty in your answer "
    "rather than stating a guess as fact. If you don't recognize the pattern, say so honestly "
    "instead of inventing a plausible-sounding purpose."
)


def build_recommendation_messages(
    pattern: CandidatePattern,
    src_confidence: str,
    dst_confidence: str,
) -> list[dict]:
    port_hint = describe_port(pattern.proto, pattern.dst_port)
    proto_name = PROTO_NAMES.get(pattern.proto, str(pattern.proto))
    port_desc = pattern.dst_port if pattern.dst_port is not None else "any"

    lines = [
        f"Source: {pattern.src_class} (classification confidence: {src_confidence}) "
        f"on network '{pattern.src_net_label}'",
        f"Destination: {pattern.dst_class} (classification confidence: {dst_confidence}) "
        f"on network '{pattern.dst_net_label}'",
        f"Protocol/port: {proto_name}/{port_desc}",
        f"Observed on {pattern.distinct_days} distinct days, {pattern.occurrence_count} times total.",
        f"Currently blocked by an existing rule: {'yes' if pattern.saw_blocked else 'no'}.",
    ]
    if port_hint:
        lines.append(f"This port is commonly associated with: {port_hint} (a hint, not a certainty).")

    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": "\n".join(lines)},
    ]


DEVICE_GUESS_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "device_guess",
        "schema": {
            "type": "object",
            "properties": {"guess": {"type": "string"}},
            "required": ["guess"],
            "additionalProperties": False,
        },
    },
}

_DEVICE_GUESS_SYSTEM_PROMPT = (
    "You help a home network owner figure out what an unidentified device on their network "
    "probably is, from nothing but its observed network behavior. You are never told the "
    "device's real IP, MAC or hostname — only its network hardware vendor (if known) and a "
    "summary of what it talks to. In 2-4 sentences, give your best guess at what kind of device "
    "this is and explain what in the evidence points that way. If the evidence is too thin or "
    "generic to guess anything specific, say so plainly rather than inventing a confident-sounding "
    "answer — 'not enough information to guess' is a better answer than a wrong one."
)


def build_device_guess_messages(
    vendor: str | None,
    event_count: int,
    top_ports: list[tuple[str, int, str | None]],
    top_partners: list[tuple[str, str | None, int]],
) -> list[dict]:
    """`top_ports`: (proto_name, port_or_None, port_hint_or_None) most
    common destinations this device connects to, each with an occurrence
    count already folded into the ordering. `top_partners`: (network_label,
    device_class_or_None, count) — who it talks to, never a real IP/MAC."""
    lines = [f"Vendor (from MAC OUI): {vendor or 'unknown'}", f"Total observed events: {event_count}"]

    if top_ports:
        lines.append("Most common destination ports:")
        for proto, port, hint in top_ports:
            port_desc = port if port is not None else "any"
            hint_text = f" ({hint})" if hint else ""
            lines.append(f"  - {proto}/{port_desc}{hint_text}")
    else:
        lines.append("No destination port data available.")

    if top_partners:
        lines.append("Most common things it talks to:")
        for network, device_class, count in top_partners:
            partner_desc = device_class or "an unclassified device"
            lines.append(f"  - {partner_desc} on network '{network}', {count} time(s)")

    return [
        {"role": "system", "content": _DEVICE_GUESS_SYSTEM_PROMPT},
        {"role": "user", "content": "\n".join(lines)},
    ]
