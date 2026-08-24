import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.sanitize.classify import classify


def test_hostname_match_wins_with_high_confidence():
    result = classify(hostname="Livingroom-HomePod", mac="A8:5B:78:11:22:33")
    assert result.device_class == "Apple HomePod / smart speaker"
    assert result.confidence == "high"


def test_falls_back_to_vendor_with_medium_confidence():
    result = classify(hostname="unnamed-device-42", mac="A8:5B:78:11:22:33")
    assert result.device_class == "Apple device (model unknown)"
    assert result.confidence == "medium"


def test_falls_back_to_network_label_with_low_confidence():
    result = classify(hostname=None, mac="AA:BB:CC:11:22:33", network_label="IoT")
    assert result.device_class == "Unclassified device on IoT"
    assert result.confidence == "low"


def test_no_signals_at_all():
    result = classify(hostname=None, mac=None)
    assert result.device_class == "Unclassified device"
    assert result.confidence == "low"
    assert result.vendor is None
