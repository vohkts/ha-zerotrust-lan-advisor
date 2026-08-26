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
    # Self-hosted/homelab services -- a hostname is a much stronger, much
    # more specific signal than the generic consumer-IoT patterns above,
    # and this whole category was missing entirely: reported live as
    # "I named nearly every device in UniFi but most show as unclassified"
    # for exactly this kind of device (an InfluxDB host, by name).
    (re.compile(r"pi-?hole", re.I), "Pi-hole (DNS resolver)"),
    (re.compile(r"influx-?db", re.I), "InfluxDB (metrics database)"),
    (re.compile(r"grafana", re.I), "Grafana (dashboard/monitoring)"),
    (re.compile(r"home-?assistant|hassio|\bhaos\b", re.I), "Home Assistant"),
    (re.compile(r"proxmox|\bpve\b", re.I), "Proxmox host"),
    (re.compile(r"portainer", re.I), "Portainer (Docker management)"),
    (re.compile(r"truenas|unraid|synology|\bnas\b", re.I), "NAS (network storage)"),
    (re.compile(r"jellyfin", re.I), "Jellyfin media server"),
    (re.compile(r"\bplex\b", re.I), "Plex media server"),
    (re.compile(r"sonarr", re.I), "Sonarr (media automation)"),
    (re.compile(r"radarr", re.I), "Radarr (media automation)"),
    (re.compile(r"prometheus", re.I), "Prometheus (monitoring)"),
    (re.compile(r"mosquitto|\bmqtt\b", re.I), "MQTT broker"),
    (re.compile(r"node-?red", re.I), "Node-RED"),
    (re.compile(r"esphome", re.I), "ESPHome device"),
    (re.compile(r"zigbee2mqtt", re.I), "Zigbee2MQTT"),
    (re.compile(r"\budm\b|\busg\b|unifi|cloudkey", re.I), "UniFi network device"),
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


# A deterministic fallback for devices with no useful hostname or vendor
# signal at all: what a host mostly gets *connected to it* on is real
# behavioral evidence of what it's running, hostname or not. Keyed on
# destination port only (protocol is almost always TCP for these; the few
# that aren't -- MQTT can run either -- aren't worth splitting the table
# over). Deliberately small and specific: only ports that are close to
# unambiguous for a home-network context, not a generic IANA port list.
_PORT_TO_CLASS = {
    8086: "InfluxDB (metrics database)",
    3000: "Grafana (dashboard/monitoring)",
    8123: "Home Assistant",
    8006: "Proxmox host",
    9000: "Portainer (Docker management)",
    32400: "Plex media server",
    8096: "Jellyfin media server",
    1883: "MQTT broker",
    1880: "Node-RED",
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


def classify_from_ports(
    dst_port_counts: dict[int, int], vendor: str | None = None, min_count: int = 5, min_share: float = 0.6
) -> Classification | None:
    """Best-effort re-classification for a host that stayed "Unclassified"
    from hostname/vendor alone: if most of what it *answers on* is one
    well-known self-hosted-service port, that's a real, if inferred,
    identity -- e.g. "answers most inbound connections on 8086/tcp" is
    InfluxDB whether or not it was ever given a matching hostname.
    Requires enough evidence (min_count) and dominance (min_share) to be
    worth asserting; returns None rather than guessing on thin evidence.
    Confidence is capped at "medium": this is inferred from behavior, not
    an asserted identity the way a hostname match is."""
    total = sum(dst_port_counts.values())
    if total < min_count:
        return None
    port, count = max(dst_port_counts.items(), key=lambda kv: kv[1])
    if count / total < min_share:
        return None
    device_class = _PORT_TO_CLASS.get(port)
    if device_class is None:
        return None
    return Classification(device_class=device_class, confidence="medium", vendor=vendor)
