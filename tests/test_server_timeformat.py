import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.web.server import format_timestamp

TS = 1735689600.0  # 2025-01-01 00:00:00 UTC


def test_none_timestamp_reads_never():
    assert format_timestamp(None, display_timezone_utc=False, tz_name="Europe/Berlin") == "never"


def test_defaults_to_the_configured_timezone():
    result = format_timestamp(TS, display_timezone_utc=False, tz_name="Europe/Berlin")
    assert "01:00" in result  # UTC+1 in January
    assert "UTC" not in result


def test_utc_setting_overrides_the_configured_timezone():
    result = format_timestamp(TS, display_timezone_utc=True, tz_name="Europe/Berlin")
    assert result == "2025-01-01 00:00 UTC"


def test_missing_timezone_name_falls_back_to_utc():
    result = format_timestamp(TS, display_timezone_utc=False, tz_name=None)
    assert result == "2025-01-01 00:00 UTC"


def test_invalid_timezone_name_falls_back_to_utc_instead_of_crashing():
    # Supervisor's own timezone lookup is best-effort and could plausibly
    # return something odd — must never take the whole page down over it.
    result = format_timestamp(TS, display_timezone_utc=False, tz_name="Not/AZone")
    assert result == "2025-01-01 00:00 UTC"
