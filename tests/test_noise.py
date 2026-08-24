import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis.noise import is_own_receiver_traffic


def test_matches_syslog_port_on_the_host():
    assert is_own_receiver_traffic("192.168.0.68", 514, "192.168.0.68", 514, 2055) is True


def test_matches_netflow_port_on_the_host():
    assert is_own_receiver_traffic("192.168.0.68", 2055, "192.168.0.68", 514, 2055) is True


def test_other_port_on_the_host_is_not_suppressed():
    assert is_own_receiver_traffic("192.168.0.68", 22, "192.168.0.68", 514, 2055) is False


def test_matching_port_on_a_different_host_is_not_suppressed():
    assert is_own_receiver_traffic("192.168.0.99", 514, "192.168.0.68", 514, 2055) is False


def test_unknown_host_ip_never_suppresses_anything():
    assert is_own_receiver_traffic("192.168.0.68", 514, None, 514, 2055) is False
