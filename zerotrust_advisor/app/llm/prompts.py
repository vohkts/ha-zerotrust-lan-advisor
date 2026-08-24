"""Builds the prompt and response schema used to turn one candidate traffic
pattern into a structured recommendation. This is the only place prompt
text lives, so wording changes don't need to be hunted across the codebase.
"""
from __future__ import annotations

from app.analysis.grouping import CandidatePattern
from app.analysis.known_ports import describe_port

_PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}

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
    proto_name = _PROTO_NAMES.get(pattern.proto, str(pattern.proto))
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
