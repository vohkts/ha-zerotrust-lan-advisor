import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.web.routes_settings import _api_key_error


def test_ascii_key_is_valid():
    assert _api_key_error("aBc123XyZ") is None


def test_key_with_an_em_dash_is_rejected():
    # The real bug: a header value must be latin-1, and this crashed with
    # a bare UnicodeEncodeError before it was caught here — see client.py.
    assert _api_key_error("abc123—xyz") is not None


def test_key_with_a_smart_quote_is_rejected():
    assert _api_key_error("abc’123") is not None
