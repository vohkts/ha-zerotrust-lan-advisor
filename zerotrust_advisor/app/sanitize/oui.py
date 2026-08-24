"""MAC vendor lookup against a bundled, offline snapshot.

This ships a small curated subset of the IEEE MA-L registry — common
home/IoT vendors only, not the full ~50k-entry registry — to keep the
add-on's image small. `scripts/update_oui.py` documents how to regenerate a
larger snapshot from the authoritative IEEE source if that turns out to
matter in practice. Looking this up is never a network call at runtime.
"""
from __future__ import annotations

import csv
from functools import lru_cache
from pathlib import Path

_SNAPSHOT_PATH = Path(__file__).resolve().parent.parent / "data" / "oui_snapshot.csv"


@lru_cache(maxsize=1)
def _load() -> dict[str, str]:
    table: dict[str, str] = {}
    with _SNAPSHOT_PATH.open(newline="") as f:
        for row in csv.DictReader(f):
            table[row["oui"].upper()] = row["vendor"]
    return table


def lookup_vendor(mac: str) -> str | None:
    """`mac` may be any common separator style; only the first 3 octets
    (the OUI) are used."""
    normalized = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(normalized) < 6:
        return None
    return _load().get(normalized[:6])
