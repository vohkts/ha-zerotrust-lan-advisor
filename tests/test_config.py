import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import config as config_module


def test_read_secret_returns_none_when_never_written(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_module, "SECRETS_DIR", tmp_path / "secrets")
    assert config_module.read_secret("unifi_api_key") is None


def test_write_then_read_round_trips(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "SECRETS_DIR", tmp_path / "secrets")
    config_module.write_secret("unifi_api_key", "abc123")
    assert config_module.read_secret("unifi_api_key") == "abc123"


def test_remove_secret_clears_a_saved_value(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "SECRETS_DIR", tmp_path / "secrets")
    config_module.write_secret("unifi_api_key", "abc123")
    config_module.remove_secret("unifi_api_key")
    assert config_module.read_secret("unifi_api_key") is None


def test_remove_secret_is_a_no_op_when_nothing_was_saved(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "SECRETS_DIR", tmp_path / "secrets")
    config_module.remove_secret("unifi_api_key")  # must not raise
    assert config_module.read_secret("unifi_api_key") is None
