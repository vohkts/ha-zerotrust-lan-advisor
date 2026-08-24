"""Turns a hostname/MAC/network into a device *class* — enough behavioral
context for the LLM to reason about ("this is a HomePod-class device")
without ever needing the device's real, personally-identifying name.

Signals are tried in order of how much they're worth trusting: a hostname
that clearly names a known device type beats a vendor guessed from the MAC,
which beats "we have nothing but which network it's on." The confidence
tier travels with the classification so that uncertainty reaches the LLM
prompt as uncertainty, rather than as an asserted fact.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.sanitize.oui import lookup_vendor

# Ordered: first match wins. Patterns are intentionally coarse (device
# *type*, not model number) — that's all the recommendation engine needs.
_HOSTNAME_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"homepod", re.I), "Apple HomePod / smart speaker"),
    (re.compile(r"apple-?tv", re.I), "Apple TV / media player"),
    (re.compile(r"iphone", re.I), "iPhone"),
    (re.compile(r"ipad", re.I), "iPad"),
    (re.compile(r"macbook|imac|mac-?mini|mac-?pro", re.I), "Mac computer"),
    (re.compile(r"echo|alexa", re.I), "Amazon Echo / smart speaker"),
    (re.compile(r"sonos", re.I), "Sonos speaker"),
    (re.compile(r"chromecast|google-?home|nest-?hub|nest-?mini", re.I), "Google Cast / smart speaker"),
    (re.compile(r"hue-?bridge|philips-?hue", re.I), "Philips Hue bridge"),
    (re.compile(r"reolink|hikvision|dahua|amcrest", re.I), "IP camera"),
    (re.compile(r"printer|^hp-|epson|brother-", re.I), "Printer"),
]

_VENDOR_TO_CLASS = {
    "Apple, Inc.": "Apple device (model unknown)",
    "Amazon Technologies Inc.": "Amazon device (model unknown)",
    "Google LLC": "Google device (model unknown)",
    "Sonos, Inc.": "Sonos speaker",
    "Samsung Electronics Co.,Ltd": "Samsung device (model unknown)",
    "Ubiquiti Inc.": "UniFi network device",
    "Nest Labs Inc.": "Google Nest device",
    "Philips Lighting BV": "Philips Hue device",
    "Raspberry Pi Foundation": "Raspberry Pi",
    "Raspberry Pi Trading Ltd": "Raspberry Pi",
    "Espressif Inc.": "Generic IoT device (ESP-based)",
    "Shenzhen Reolink Technology Co.,Ltd": "IP camera",
}


@dataclass(frozen=True)
class Classification:
    device_class: str
    confidence: str  # "high" | "medium" | "low"
    vendor: str | None


def classify(hostname: str | None, mac: str | None, network_label: str | None = None) -> Classification:
    vendor = lookup_vendor(mac) if mac else None

    if hostname:
        for pattern, device_class in _HOSTNAME_PATTERNS:
            if pattern.search(hostname):
                return Classification(device_class=device_class, confidence="high", vendor=vendor)

    if vendor and vendor in _VENDOR_TO_CLASS:
        return Classification(device_class=_VENDOR_TO_CLASS[vendor], confidence="medium", vendor=vendor)

    fallback = f"Unclassified device on {network_label}" if network_label else "Unclassified device"
    return Classification(device_class=fallback, confidence="low", vendor=vendor)
