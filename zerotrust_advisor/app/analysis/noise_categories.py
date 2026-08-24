"""Classifies syslog lines that fail to parse as firewall events into a
small set of known, named noise categories — without ever storing the raw
line itself, matching this add-on's "never store raw text" rule (see
firewall_parse.py). Counting by category, not just a single "unparsed"
total, is what lets a setup recommendation say *which* router logging
option is worth turning down instead of just "something is noisy."

Patterns are deliberately narrow and evidence-based — each one here was
confirmed against real captured UniFi syslog lines, not guessed. A line
that matches none of them is genuinely unclassified, not silently assumed
to be one of these.
"""
from __future__ import annotations

import re

# (key, pattern, human-readable description used in setup recommendations)
_CATEGORIES: list[tuple[str, re.Pattern, str]] = [
    (
        "ap_client_events",
        re.compile(r"Send NULL to STA-|\bSTA-[0-9a-f]{2}(:[0-9a-f]{2}){5}\b", re.I),
        "access-point client roaming/idle events (STA join/leave, idle timeouts)",
    ),
    (
        "syslog_transport_status",
        re.compile(r"syslog-ng\[|Syslog connection (broken|established)", re.I),
        "syslog-ng's own connection status messages",
    ),
    (
        "logread_status",
        re.compile(r"\blogread\[", re.I),
        "logread's own connection announcements",
    ),
    (
        "mcad_wan_health",
        re.compile(r"\bmcad\[|geo_info|wan\.wan_geoinfo", re.I),
        "UniFi's mcad WAN health/geo-info diagnostics",
    ),
]

CATEGORY_KEYS = [key for key, _pattern, _description in _CATEGORIES]


def classify_unparsed_line(line: str) -> str | None:
    """Returns a category key if `line` matches a known noise pattern,
    else None — genuinely unrecognized, or worth a closer look manually."""
    for key, pattern, _description in _CATEGORIES:
        if pattern.search(line):
            return key
    return None


def category_description(key: str) -> str | None:
    for cat_key, _pattern, description in _CATEGORIES:
        if cat_key == key:
            return description
    return None
