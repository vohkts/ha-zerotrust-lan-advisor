import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis.netlabels import label_for_ip, parse_network_labels


def test_matches_configured_network():
    labels = parse_network_labels(["192.168.10.0/24=IoT", "192.168.20.0/24=Home"])
    assert label_for_ip("192.168.10.5", labels) == "IoT"
    assert label_for_ip("192.168.20.9", labels) == "Home"


def test_unmatched_ip_falls_back_to_raw_ip():
    labels = parse_network_labels(["192.168.10.0/24=IoT"])
    assert label_for_ip("10.0.0.1", labels) == "10.0.0.1"


def test_malformed_entries_are_skipped_not_fatal():
    labels = parse_network_labels(["not-a-cidr=Broken", "192.168.10.0/24=IoT", "no-equals-sign"])
    assert len(labels) == 1
    assert labels[0].label == "IoT"


def test_invalid_ip_returns_itself():
    labels = parse_network_labels(["192.168.10.0/24=IoT"])
    assert label_for_ip("not-an-ip", labels) == "not-an-ip"
