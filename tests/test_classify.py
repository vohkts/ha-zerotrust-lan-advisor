import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.sanitize.classify import classify, classify_from_ports


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


def test_self_hosted_service_hostnames_are_recognized():
    # Reported live: "I named nearly every device in UniFi but most show as
    # unclassified" -- the pattern list only ever covered consumer IoT
    # brands, never a homelab's own self-hosted services.
    assert classify(hostname="influxdb", mac=None).device_class == "InfluxDB (metrics database)"
    assert classify(hostname="pi-hole", mac=None).device_class == "Pi-hole (DNS resolver)"
    assert classify(hostname="Home-Assistant", mac=None).device_class == "Home Assistant"
    for name in ("influxdb", "pi-hole", "Home-Assistant"):
        assert classify(hostname=name, mac=None).confidence == "high"


def test_classify_from_ports_recognizes_a_dominant_service_port():
    # A host with no useful hostname/vendor signal at all can still be
    # identified from what it mostly *answers on* -- e.g. InfluxDB's
    # default port, requested explicitly: "based on name and the detected
    # flow pattern is possible."
    result = classify_from_ports({8086: 40, 22: 2})
    assert result is not None
    assert result.device_class == "InfluxDB (metrics database)"
    assert result.confidence == "medium"


def test_classify_from_ports_refuses_thin_or_mixed_evidence():
    assert classify_from_ports({8086: 2}) is None  # below min_count
    assert classify_from_ports({8086: 10, 22: 10}) is None  # no dominant port
    assert classify_from_ports({4242: 50}) is None  # not a known service port
