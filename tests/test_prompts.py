import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis.grouping import CandidatePattern
from app.llm.prompts import build_device_guess_messages, build_recommendation_messages

PATTERN = CandidatePattern(
    signature="IoT|Home|Apple HomePod / smart speaker|iPhone|6|7000",
    src_class="Apple HomePod / smart speaker",
    dst_class="iPhone",
    src_net_label="IoT",
    dst_net_label="Home",
    proto=6,
    dst_port=7000,
    occurrence_count=14,
    distinct_days=5,
    first_seen=1.0,
    last_seen=2.0,
    saw_blocked=True,
    saw_allowed=False,
    sample_event_ids=[1, 2, 3],
    src_ip_count=3,
    dst_ip_count=1,
)


def test_messages_include_pseudonymized_context_only():
    messages = build_recommendation_messages(PATTERN, src_confidence="high", dst_confidence="medium")
    assert messages[0]["role"] == "system"
    user_text = messages[1]["content"]
    assert "Apple HomePod / smart speaker" in user_text
    assert "IoT" in user_text and "Home" in user_text
    assert "AirPlay" in user_text  # known-port hint for TCP/7000
    # No raw IPs/MACs should ever appear — the pattern itself never carries them.
    assert "192.168" not in user_text


def test_messages_convey_whether_a_side_is_one_device_or_several():
    messages = build_recommendation_messages(PATTERN, src_confidence="high", dst_confidence="medium")
    user_text = messages[1]["content"]
    assert "3 different devices" in user_text
    assert "a single, consistently the same device" in user_text


def test_system_prompt_frames_allow_as_the_default_and_asks_for_structured_fields():
    messages = build_recommendation_messages(PATTERN, src_confidence="high", dst_confidence="medium")
    system_text = messages[0]["content"]
    assert "ALLOW" in system_text
    assert "rule_source" in system_text and "rule_destination" in system_text and "rule_protocol_port" in system_text


def test_device_guess_messages_include_evidence_and_no_identity():
    messages = build_device_guess_messages(
        vendor="Synology, Inc.",
        event_count=42,
        top_ports=[("TCP", 445, "SMB"), ("UDP", 5353, "mDNS")],
        top_partners=[("IoT", "iPhone", 10), ("Home", None, 3)],
    )
    assert messages[0]["role"] == "system"
    user_text = messages[1]["content"]
    assert "Synology, Inc." in user_text
    assert "42" in user_text
    assert "445" in user_text and "SMB" in user_text
    assert "IoT" in user_text and "iPhone" in user_text
    # Never given a real IP/MAC to work with.
    assert "192.168" not in user_text


def test_device_guess_messages_handle_no_evidence_at_all():
    messages = build_device_guess_messages(vendor=None, event_count=0, top_ports=[], top_partners=[])
    user_text = messages[1]["content"]
    assert "unknown" in user_text
    assert "No destination port data available" in user_text


def test_real_identifiers_are_omitted_by_default():
    messages = build_recommendation_messages(PATTERN, src_confidence="high", dst_confidence="medium")
    user_text = messages[1]["content"]
    assert "Real source device" not in user_text
    assert "Real destination device" not in user_text


def test_real_identifiers_appear_only_when_explicitly_passed():
    messages = build_recommendation_messages(
        PATTERN, src_confidence="high", dst_confidence="medium",
        src_identifiers=["kitchen-echo", "bedroom-echo"], dst_identifiers=["influxdb.local"],
    )
    user_text = messages[1]["content"]
    assert "kitchen-echo" in user_text and "bedroom-echo" in user_text
    assert "influxdb.local" in user_text


def test_device_guess_real_identifier_omitted_by_default():
    messages = build_device_guess_messages(vendor="Synology, Inc.", event_count=1, top_ports=[], top_partners=[])
    user_text = messages[1]["content"]
    assert "Real device name/IP" not in user_text


def test_device_guess_real_identifier_appears_only_when_explicitly_passed():
    messages = build_device_guess_messages(
        vendor="Synology, Inc.", event_count=1, top_ports=[], top_partners=[], real_identifier="nas.local",
    )
    user_text = messages[1]["content"]
    assert "nas.local" in user_text
