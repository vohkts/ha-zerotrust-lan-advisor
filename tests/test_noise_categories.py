import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis.noise_categories import category_description, classify_unparsed_line

# Real lines captured from production during this add-on's own development.
AP_CLIENT_LINE = (
    "<4>Aug 24 20:07:01 AP-HWR f492bfa8ad88,U6-Lite-6.7.54+15663: kernel: "
    "[1219886.764489] ra1: Send NULL to STA-2c:f8:ec:20:6f:6d idle(60) timeout(180)"
)
SYSLOG_TRANSPORT_LINE = (
    "<45>Aug 24 20:06:48 UDM-Pro UDM-Pro syslog-ng[206887]: Syslog connection broken; "
    "fd='38', server='AF_INET(192.168.0.68:514)', time_reopen='60'"
)
LOGREAD_LINE = "<30>Aug 24 20:07:05 AP-Bro f492bfa8bcd0,U6-Lite-6.7.54+15663: logread[29188]: Logread connected to 192.168.0.68:514"
MCAD_LINE_1 = "<14>Aug 24 20:07:06 UDM-Pro UDM-Pro mcad[2802]: ace_reporter.geo_info_send(): Sending geo-info request from eth8"
MCAD_LINE_2 = "<11>Aug 24 20:07:06 UDM-Pro UDM-Pro mcad[2802]: wan.wan_geoinfo_error_cb(): Processing GeoInfo error err-code=3 wan=0:WAN:eth8"


def test_classifies_real_captured_ap_client_event():
    assert classify_unparsed_line(AP_CLIENT_LINE) == "ap_client_events"


def test_classifies_real_captured_syslog_transport_status():
    assert classify_unparsed_line(SYSLOG_TRANSPORT_LINE) == "syslog_transport_status"


def test_classifies_real_captured_logread_status():
    assert classify_unparsed_line(LOGREAD_LINE) == "logread_status"


def test_classifies_real_captured_mcad_lines():
    assert classify_unparsed_line(MCAD_LINE_1) == "mcad_wan_health"
    assert classify_unparsed_line(MCAD_LINE_2) == "mcad_wan_health"


def test_unrecognized_line_returns_none():
    assert classify_unparsed_line("something entirely unrelated happened here") is None


def test_every_category_has_a_description():
    from app.analysis.noise_categories import CATEGORY_KEYS

    for key in CATEGORY_KEYS:
        assert category_description(key)
    assert category_description("not_a_real_category") is None
