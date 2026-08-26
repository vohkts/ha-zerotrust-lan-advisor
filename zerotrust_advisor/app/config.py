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
    "llm_send_real_identifiers": False,
    "unifi_enabled": False,
    "unifi_host": "",
    "unifi_verify_tls": False,
    "unifi_apply_mode": "manual",
    "display_timezone_utc": False,
    "ignore_unifi_console_traffic": True,
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
    # Off by default: every LLM prompt (local or remote) speaks only in
    # device classes and network labels, never real hostnames/IPs/MACs --
    # see app/llm/prompts.py. Turning this on sends real identifiers too,
    # for anyone whose configured endpoint (local or remote) never leaves
    # their own network, e.g. a self-hosted Ollama instance, and wants
    # more specific recommendations in exchange. Meaningless, and
    # dangerous, if the endpoint is an actual third-party service --
    # the Settings copy says so.
    llm_send_real_identifiers: bool
    # Stage 2 (UniFi UDM-only, optional, off by default — see app/unifi/).
    # unifi_apply_mode is Stage 3 prep: "manual" is the only mode with any
    # real behavior today. "automatic" is stored and shown in Settings but
    # nothing in this codebase acts on it yet — no write path exists.
    unifi_enabled: bool
    unifi_host: str
    unifi_verify_tls: bool
    unifi_apply_mode: str
    # Every timestamp in this UI defaults to Home Assistant's own configured
    # timezone (read from the Supervisor, see app/supervisor.py's
    # get_timezone()), falling back to UTC if that can't be determined.
    # This flips the default back to plain UTC for anyone who prefers it.
    display_timezone_utc: bool
    # The UDM console's own management IP dominates Hosts/flow tables with
    # infrastructure noise (DNS/DHCP served to every device, health checks,
    # etc.) that isn't a segmentation decision — same "expected, not
    # interesting" reasoning as ignore_own_receiver_traffic, just for a
    # different known-infrastructure address. Only takes effect once
    # unifi_host is actually set.
    ignore_unifi_console_traffic: bool

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
        llm_send_real_identifiers=bool(raw["llm_send_real_identifiers"]),
        unifi_enabled=bool(raw["unifi_enabled"]),
        unifi_host=str(raw["unifi_host"]),
        unifi_verify_tls=bool(raw["unifi_verify_tls"]),
        unifi_apply_mode=str(raw["unifi_apply_mode"]),
        display_timezone_utc=bool(raw["display_timezone_utc"]),
        ignore_unifi_console_traffic=bool(raw["ignore_unifi_console_traffic"]),
    )


def read_secret(name: str) -> str | None:
    path = SECRETS_DIR / name
    if not path.exists():
        return None
    return path.read_text().strip() or None


def remove_secret(name: str) -> None:
    (SECRETS_DIR / name).unlink(missing_ok=True)


def write_secret(name: str, value: str) -> None:
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    path = SECRETS_DIR / name
    path.write_text(value)
    path.chmod(0o600)
