"""Reads the add-on's configuration.

Two sources, deliberately kept separate:
- /data/options.json: the Supervisor-managed settings (also editable from the
  in-app Settings screen, which just calls the Supervisor API to update it).
- /data/secrets/: things that must never round-trip through the Supervisor's
  options store or be visible in a support-bundle export, namely the remote
  LLM API key and the pseudonymization salt.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(os.environ.get("ZTA_DATA_DIR", "/data"))
OPTIONS_PATH = DATA_DIR / "options.json"
SECRETS_DIR = DATA_DIR / "secrets"

DEFAULTS = {
    "syslog_port": 514,
    "netflow_port": 2055,
    "allowed_sources": [],
    "network_labels": [],
    "retention_days": 90,
    "min_recurring_days": 3,
    "ignore_own_receiver_traffic": True,
    "enable_mdns_classification": False,
    "llm_mode": "local",
    "llm_remote_base_url": "",
    "llm_model_path": "",
}


@dataclass(frozen=True)
class Config:
    syslog_port: int
    netflow_port: int
    allowed_sources: tuple[str, ...]
    network_labels: tuple[str, ...]
    retention_days: int
    min_recurring_days: int
    ignore_own_receiver_traffic: bool
    enable_mdns_classification: bool
    llm_mode: str
    llm_remote_base_url: str
    llm_model_path: str

    @property
    def db_path(self) -> Path:
        return DATA_DIR / "zerotrust.db"

    @property
    def health_dir(self) -> Path:
        return DATA_DIR / "health"

    @property
    def models_dir(self) -> Path:
        return DATA_DIR / "models"


def load_config() -> Config:
    raw = dict(DEFAULTS)
    if OPTIONS_PATH.exists():
        raw.update(json.loads(OPTIONS_PATH.read_text()))
    return Config(
        syslog_port=int(raw["syslog_port"]),
        netflow_port=int(raw["netflow_port"]),
        allowed_sources=tuple(raw["allowed_sources"]),
        network_labels=tuple(raw["network_labels"]),
        retention_days=int(raw["retention_days"]),
        min_recurring_days=int(raw["min_recurring_days"]),
        ignore_own_receiver_traffic=bool(raw["ignore_own_receiver_traffic"]),
        enable_mdns_classification=bool(raw["enable_mdns_classification"]),
        llm_mode=str(raw["llm_mode"]),
        llm_remote_base_url=str(raw["llm_remote_base_url"]),
        llm_model_path=str(raw["llm_model_path"]),
    )


def read_secret(name: str) -> str | None:
    path = SECRETS_DIR / name
    if not path.exists():
        return None
    return path.read_text().strip() or None


def write_secret(name: str, value: str) -> None:
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    path = SECRETS_DIR / name
    path.write_text(value)
    path.chmod(0o600)
