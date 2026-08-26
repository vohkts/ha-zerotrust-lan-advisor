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
                "action": {"type": "string", "enum": ["allow", "block"]},
                "rule_source": {"type": "string"},
                "rule_destination": {"type": "string"},
                "rule_protocol_port": {"type": "string"},
                "suggested_rule_scope": {"type": "string"},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                "caveats": {"type": "array", "items": {"type": "string"}},
            },
            "required": [
                "plain_language_summary",
                "likely_purpose",
                "action",
                "rule_source",
                "rule_destination",
                "rule_protocol_port",
                "suggested_rule_scope",
                "confidence",
                "caveats",
            ],
            "additionalProperties": False,
        },
    },
}

_SYSTEM_PROMPT = (
    "You help a home network owner move toward a zero-trust firewall: default-deny, with narrow, "
    "explicit allow rules for the traffic they actually rely on. You are given one recurring, "
    "pseudonymized traffic pattern this add-on has actually observed happening, repeatedly, over "
    "multiple days — it is not hypothetical.\n\n"
    "Your job is almost always to recommend the narrow ALLOW rule that legitimizes it, not to "
    "block it: a pattern that recurs across many distinct days, on one well-known port, is what "
    "normal, wanted usage looks like — e.g. several devices repeatedly querying a DNS resolver on "
    "udp/53 is exactly the kind of traffic zero-trust segmentation should explicitly allow, not "
    "block. Only recommend 'block' when the evidence itself looks wrong for what it claims to be "
    "(an unexpected port for the stated purpose, a destination that doesn't fit the device classes "
    "involved) — and say exactly why in caveats. Recurring, expected-looking traffic is not, by "
    "itself, a reason to block it.\n\n"
    "Scope the rule as narrowly as the evidence actually supports, never as a broad convenience. "
    "You will be told whether each side of the pattern is one single stable device or a population "
    "of several — when a side is a single device, scope the rule to that device specifically "
    "(referring to it by its class, e.g. 'the Pi-hole', never 'the whole network'); only scope to an "
    "entire network when you're told multiple distinct devices are genuinely behind that side. Never "
    "widen the port beyond the one actually observed, and never suggest 'any port' as a shortcut — "
    "'allow this whole subnet to that whole subnet on any port' is exactly the kind of broad rule "
    "zero-trust exists to avoid.\n\n"
    "rule_source, rule_destination and rule_protocol_port must be short, concrete fragments (e.g. "
    "'devices on the IoT network', 'the Pi-hole on the Home network', 'udp/53') that could be read "
    "straight out of your own suggested_rule_scope sentence — they exist so the rule can be shown "
    "as a compact chip alongside the explanation. Usually you're only told device classes and "
    "network labels, never real identifiers — reflect that uncertainty rather than stating a guess "
    "as fact. Occasionally (only when the user has explicitly opted in) you'll be given real "
    "hostnames or IP addresses instead of just classes for one or both sides — when that happens, "
    "use them directly and specifically (e.g. 'kitchen-echo', not 'the device') instead of the "
    "generic class language. If you don't recognize the pattern, say so honestly instead of "
    "inventing a plausible-sounding purpose."
)


def _ip_count_phrase(count: int) -> str:
    if count == 1:
        return "a single, consistently the same device"
    return f"{count} different devices seen"


def build_recommendation_messages(
    pattern: CandidatePattern,
    src_confidence: str,
    dst_confidence: str,
    src_identifiers: list[str] | None = None,
    dst_identifiers: list[str] | None = None,
) -> list[dict]:
    """`src_identifiers`/`dst_identifiers`: real hostnames (or IPs, for
    whichever sample events had no known hostname) actually seen behind
    this pattern -- only ever populated by the caller when the user has
    explicitly opted into `llm_send_real_identifiers`. None/empty means
    "stay pseudonymized", the default, regardless of LLM mode."""
    port_hint = describe_port(pattern.proto, pattern.dst_port)
    proto_name = PROTO_NAMES.get(pattern.proto, str(pattern.proto))
    port_desc = pattern.dst_port if pattern.dst_port is not None else "any"

    lines = [
        f"Source: {pattern.src_class} (classification confidence: {src_confidence}) "
        f"on network '{pattern.src_net_label}' — {_ip_count_phrase(pattern.src_ip_count)}.",
        f"Destination: {pattern.dst_class} (classification confidence: {dst_confidence}) "
        f"on network '{pattern.dst_net_label}' — {_ip_count_phrase(pattern.dst_ip_count)}.",
        f"Protocol/port: {proto_name}/{port_desc}",
        f"Observed on {pattern.distinct_days} distinct days, {pattern.occurrence_count} times total.",
        f"Currently blocked by an existing rule: {'yes' if pattern.saw_blocked else 'no'}.",
    ]
    if port_hint:
        lines.append(f"This port is commonly associated with: {port_hint} (a hint, not a certainty).")
    if src_identifiers:
        lines.append(f"Real source device name(s) seen: {', '.join(src_identifiers)}.")
    if dst_identifiers:
        lines.append(f"Real destination device name(s) seen: {', '.join(dst_identifiers)}.")

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
    "probably is, from its observed network behavior. Usually you're never told the device's "
    "real IP, MAC or hostname — only its network hardware vendor (if known) and a summary of "
    "what it talks to. Occasionally (only when the user has explicitly opted in) you'll also be "
    "given its real hostname or IP — when given, treat it as a real clue (a hostname often names "
    "the device or its purpose directly) rather than ignoring it. In 2-4 sentences, give your best "
    "guess at what kind of device this is and explain what in the evidence points that way. If the "
    "evidence is too thin or generic to guess anything specific, say so plainly rather than "
    "inventing a confident-sounding answer — 'not enough information to guess' is a better answer "
    "than a wrong one."
)


def build_device_guess_messages(
    vendor: str | None,
    event_count: int,
    top_ports: list[tuple[str, int, str | None]],
    top_partners: list[tuple[str, str | None, int]],
    real_identifier: str | None = None,
) -> list[dict]:
    """`top_ports`: (proto_name, port_or_None, port_hint_or_None) most
    common destinations this device connects to, each with an occurrence
    count already folded into the ordering. `top_partners`: (network_label,
    device_class_or_None, count) — who it talks to, never a real IP/MAC.
    `real_identifier`: this device's own real hostname (or IP, if no
    hostname is known) -- only ever populated when the user has explicitly
    opted into `llm_send_real_identifiers`; None means stay pseudonymized,
    the default regardless of LLM mode."""
    lines = [f"Vendor (from MAC OUI): {vendor or 'unknown'}", f"Total observed events: {event_count}"]
    if real_identifier:
        lines.append(f"Real device name/IP: {real_identifier}")

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
