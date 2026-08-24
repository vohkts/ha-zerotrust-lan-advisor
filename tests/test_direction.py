import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis.direction import (
    EXTERNAL_EXTERNAL,
    INTERNAL_EXTERNAL,
    INTERNAL_INTERNAL,
    classify_direction,
    count_directions,
)


def test_both_private_is_internal_internal():
    assert classify_direction("192.168.10.5", "192.168.20.9") == INTERNAL_INTERNAL
    assert classify_direction("10.0.0.1", "172.16.0.1") == INTERNAL_INTERNAL


def test_one_public_is_internal_external():
    assert classify_direction("192.168.10.5", "8.8.8.8") == INTERNAL_EXTERNAL
    assert classify_direction("1.1.1.1", "192.168.10.5") == INTERNAL_EXTERNAL


def test_both_public_is_external_external():
    assert classify_direction("8.8.8.8", "1.1.1.1") == EXTERNAL_EXTERNAL


def test_invalid_ip_treated_as_public_not_private():
    # An unparseable address shouldn't be silently assumed "safe"/internal.
    assert classify_direction("not-an-ip", "192.168.10.5") == INTERNAL_EXTERNAL


def test_count_directions_tallies_correctly():
    pairs = [
        ("192.168.10.5", "192.168.20.9"),
        ("192.168.10.6", "192.168.20.9"),
        ("192.168.10.5", "8.8.8.8"),
    ]
    counts = count_directions(pairs)
    assert counts[INTERNAL_INTERNAL] == 2
    assert counts[INTERNAL_EXTERNAL] == 1
    assert counts[EXTERNAL_EXTERNAL] == 0
