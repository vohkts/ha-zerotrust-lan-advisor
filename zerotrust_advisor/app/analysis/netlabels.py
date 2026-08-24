"""Maps an IP to the friendly network label the user configured for it
(e.g. 192.168.10.0/24 -> "IoT"), so recommendations talk about "IoT" and
"Home" instead of raw subnets. An IP outside every configured range is
labelled with the subnet itself — still useful context, just less friendly.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkLabel:
    network: ipaddress.IPv4Network
    label: str


def parse_network_labels(raw: list[str]) -> list[NetworkLabel]:
    """Each entry is "CIDR=Label", e.g. "192.168.10.0/24=IoT". Malformed
    entries are skipped rather than raising — a typo in one label shouldn't
    take the whole feature down."""
    labels: list[NetworkLabel] = []
    for entry in raw:
        if "=" not in entry:
            continue
        cidr, _, label = entry.partition("=")
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            continue
        if label.strip():
            labels.append(NetworkLabel(network=network, label=label.strip()))
    return labels


def label_for_ip(ip: str, labels: list[NetworkLabel]) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    for entry in labels:
        if address in entry.network:
            return entry.label
    return ip
