"""Classifies an observed src/dst pair by whether it stayed entirely inside
private address space or crossed the WAN boundary — the simplest, first
question worth answering about what this add-on is actually seeing: is
there any real traffic *between* devices on your own networks, or is
everything just WAN-facing?

Deliberately independent of the user's configured network labels (see
netlabels.py): this only needs to know "private vs. public IP," so it gives
a useful signal even before any labels are set up, and doesn't get fooled
by an IP that simply hasn't been labelled yet.
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from functools import lru_cache

INTERNAL_INTERNAL = "internal_internal"
INTERNAL_EXTERNAL = "internal_external"
EXTERNAL_EXTERNAL = "external_external"


@lru_cache(maxsize=4096)
def is_private_ip(ip: str) -> bool:
    # Cached: a home network's traffic is dominated by a small, repeated
    # set of distinct IPs, but this got called once per *event* — tens of
    # thousands of redundant ipaddress.ip_address() parses of the same
    # handful of strings on every Traffic page load, measured as a real
    # contributor to the page's 1-2s load lag. Private/public-ness of a
    # given IP string never changes, so caching it is always safe.
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def classify_direction(src_ip: str, dst_ip: str) -> str:
    src_private = is_private_ip(src_ip)
    dst_private = is_private_ip(dst_ip)
    if src_private and dst_private:
        return INTERNAL_INTERNAL
    if not src_private and not dst_private:
        return EXTERNAL_EXTERNAL
    return INTERNAL_EXTERNAL


def count_directions(pairs: list[tuple[str, str]]) -> Counter:
    """Returns a Counter keyed by the classify_direction() categories."""
    return Counter(classify_direction(src, dst) for src, dst in pairs)
