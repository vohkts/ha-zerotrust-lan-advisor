import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db
from app.sanitize.pseudonymize import Pseudonymizer


def _pseudonymizer(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    salt = b"\x01" * 32
    return Pseudonymizer(conn, salt)


def test_same_real_key_always_yields_same_token(tmp_path):
    p = _pseudonymizer(tmp_path)
    first = p.token_for("aa:bb:cc:dd:ee:ff", kind="device")
    second = p.token_for("aa:bb:cc:dd:ee:ff", kind="device")
    assert first == second
    assert first.startswith("device-")


def test_different_keys_yield_different_tokens(tmp_path):
    p = _pseudonymizer(tmp_path)
    a = p.token_for("aa:bb:cc:dd:ee:ff", kind="device")
    b = p.token_for("11:22:33:44:55:66", kind="device")
    assert a != b


def test_network_kind_gets_net_prefix(tmp_path):
    p = _pseudonymizer(tmp_path)
    token = p.token_for("192.168.10.0/24", kind="network")
    assert token.startswith("net-")


def test_token_is_reversible_locally(tmp_path):
    p = _pseudonymizer(tmp_path)
    token = p.token_for("aa:bb:cc:dd:ee:ff", kind="device")
    assert p.real_key_for(token) == "aa:bb:cc:dd:ee:ff"


def test_different_salt_yields_different_token(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    p1 = Pseudonymizer(conn, b"\x01" * 32)
    p2 = Pseudonymizer(conn, b"\x02" * 32)
    assert p1.token_for("aa:bb:cc:dd:ee:ff", kind="device") != p2.token_for(
        "aa:bb:cc:dd:ee:ff", kind="device"
    )
