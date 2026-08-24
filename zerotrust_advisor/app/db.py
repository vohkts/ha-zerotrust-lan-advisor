"""SQLite storage. WAL mode so the receivers (writers) and the web app
(reader, mostly) don't block each other.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events_firewall (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    proto INTEGER NOT NULL,
    iface_in TEXT,
    iface_out TEXT,
    rule_prefix TEXT,
    action TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_firewall_ts ON events_firewall(ts);
CREATE INDEX IF NOT EXISTS idx_events_firewall_pair ON events_firewall(src_ip, dst_ip);

CREATE TABLE IF NOT EXISTS events_flow (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_start REAL NOT NULL,
    ts_end REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    proto INTEGER NOT NULL,
    bytes INTEGER,
    packets INTEGER,
    exporter_ip TEXT NOT NULL,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_flow_ts ON events_flow(ts_start);
CREATE INDEX IF NOT EXISTS idx_events_flow_pair ON events_flow(src_ip, dst_ip);

-- device_key is the MAC when known, otherwise the IP — a stable local
-- handle for "the same device", independent of the pseudonym token used
-- when anything about this device is sent to the LLM (see pseudonym_map).
CREATE TABLE IF NOT EXISTS identities (
    device_key TEXT PRIMARY KEY,
    ip TEXT,
    mac TEXT,
    hostname TEXT,
    vendor TEXT,
    device_class TEXT,
    class_confidence TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_identities_ip ON identities(ip);

CREATE TABLE IF NOT EXISTS pseudonym_map (
    real_key TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    kind TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    pattern_signature TEXT NOT NULL UNIQUE,
    pattern_summary_text TEXT NOT NULL,
    structured_json TEXT NOT NULL,
    llm_model_used TEXT,
    confidence TEXT,
    evidence_event_ids TEXT
);

CREATE TABLE IF NOT EXISTS coverage_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at REAL NOT NULL,
    last_firewall_event_at REAL,
    last_flow_event_at REAL,
    rejected_syslog_count INTEGER NOT NULL DEFAULT 0,
    rejected_flow_count INTEGER NOT NULL DEFAULT 0,
    east_west_evidence_seen INTEGER NOT NULL DEFAULT 0,
    gap_flags_json TEXT
);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    """Every service (syslog/netflow/mDNS receivers, the web process) opens
    its own connection independently at container startup, so the first
    schema-creation statements can race even with WAL mode and a busy
    timeout set — switching journal mode is itself a brief exclusive
    operation. `CREATE TABLE IF NOT EXISTS` is naturally idempotent, so a
    short retry here is enough; there's nothing to coordinate beyond that.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")

    delay = 0.2
    for attempt in range(5):
        try:
            conn.executescript(SCHEMA)
            conn.commit()
            break
        except sqlite3.OperationalError:
            if attempt == 4:
                raise
            time.sleep(delay)
            delay *= 2

    return conn


def prune(conn: sqlite3.Connection, retention_days: int, now: float) -> None:
    cutoff = now - retention_days * 86400
    conn.execute("DELETE FROM events_firewall WHERE ts < ?", (cutoff,))
    conn.execute("DELETE FROM events_flow WHERE ts_start < ?", (cutoff,))
    conn.commit()
