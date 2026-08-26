"""Matches a candidate zero-trust pattern (or an already-accepted
recommendation) against the real, currently-synced UniFi ruleset.

Two uses: skip recommending something a narrow rule already covers (so
recommendations stay aware of what's already been implemented, not just
raw traffic), and show whether an accepted recommendation's rule has
actually shown up in the real ruleset yet.

Only the port scope is matched -- confirmed live that a real policy's raw
JSON carries genuine per-port data (`destination.trafficFilter.portFilter
.items[].value`), which earlier work in this project didn't know existed.
Source/destination network scope is deliberately NOT matched: a
recommendation's network label is a display name, not a raw UniFi network
ID, and reconstructing that mapping precisely isn't worth the complexity
port-matching alone already delivers real value.

Deliberately excludes any policy with no port filter at all (an "allow
everything" or otherwise broad rule) from counting as coverage -- the
whole point of a zero-trust recommendation is to replace exactly that
kind of rule with something narrow, so a broad rule must never silently
make every future recommendation for that destination look "already
handled".
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class ParsedPolicy:
    id: str
    name: str
    enabled: bool
    action: str  # "ALLOW" | "BLOCK" | "REJECT", best-effort from action.type
    ports: frozenset[int] | None  # None means "no explicit port filter"


def _parse_ports(trigger_side: dict) -> frozenset[int] | None:
    traffic_filter = (trigger_side or {}).get("trafficFilter") or {}
    port_filter = traffic_filter.get("portFilter")
    if not port_filter:
        return None
    ports = {
        item["value"]
        for item in port_filter.get("items", [])
        if item.get("type") == "PORT_NUMBER" and isinstance(item.get("value"), int)
    }
    return frozenset(ports) if ports else None


def load_parsed_policies(conn: sqlite3.Connection) -> list[ParsedPolicy]:
    rows = conn.execute("SELECT id, name, enabled, raw_json FROM unifi_policies").fetchall()
    parsed = []
    for policy_id, name, enabled, raw_json in rows:
        try:
            raw = json.loads(raw_json)
        except (TypeError, json.JSONDecodeError):
            continue
        action = ((raw.get("action") or {}).get("type")) or "ALLOW"
        parsed.append(
            ParsedPolicy(
                id=policy_id,
                name=name,
                enabled=bool(enabled),
                action=action,
                ports=_parse_ports(raw.get("destination") or {}),
            )
        )
    return parsed


def find_covering_policy(policies: list[ParsedPolicy], port: int | None) -> ParsedPolicy | None:
    """An enabled ALLOW policy with an explicit port scope that includes
    this port is treated as already covering it. A policy with no port
    filter at all never counts, regardless of port -- see module
    docstring. `port=None` (a pattern with no specific port) never
    matches anything, since there's no narrow rule to check it against."""
    if port is None:
        return None
    for policy in policies:
        if not policy.enabled or policy.action != "ALLOW" or policy.ports is None:
            continue
        if port in policy.ports:
            return policy
    return None
