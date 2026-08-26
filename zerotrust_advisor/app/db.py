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
-- host-detail's query is "WHERE (src_ip=? OR dst_ip=?) AND ts>=? ORDER BY
-- ts DESC LIMIT N". A single-column index on src_ip/dst_ip alone (tried
-- first, measured live) lets SQLite's OR-optimization find matching rows
-- without a full scan, but ORDER BY ts still has to sort *every* match
-- before LIMIT can apply -- on a host with millions of matching rows
-- (confirmed live: this add-on's own host, 15s+) that sort dominates.
-- A compound (ip, ts) index lets it scan already ts-ordered for a fixed
-- IP and stop as soon as it has N rows, which is what actually fixes it.
DROP INDEX IF EXISTS idx_events_firewall_src;
DROP INDEX IF EXISTS idx_events_firewall_dst;
CREATE INDEX IF NOT EXISTS idx_events_firewall_src_ts ON events_firewall(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_firewall_dst_ts ON events_firewall(dst_ip, ts);

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
DROP INDEX IF EXISTS idx_events_flow_src;
DROP INDEX IF EXISTS idx_events_flow_dst;
CREATE INDEX IF NOT EXISTS idx_events_flow_src_ts ON events_flow(src_ip, ts_start);
CREATE INDEX IF NOT EXISTS idx_events_flow_dst_ts ON events_flow(dst_ip, ts_start);

-- device_key is the MAC when known, otherwise the IP — a stable local
-- handle for "the same device", independent of the pseudonym token used
-- when anything about this device is sent to the LLM (see pseudonym_map).
-- llm_guess/llm_guess_at: an on-demand, cached LLM guess at what an
-- Unclassified device might be, from its observed ports/flows -- never
-- generated automatically (an LLM call is slow), only when the user asks
-- for one from the Hosts table's expanded detail view. NULL until then.
CREATE TABLE IF NOT EXISTS identities (
    device_key TEXT PRIMARY KEY,
    ip TEXT,
    mac TEXT,
    hostname TEXT,
    vendor TEXT,
    device_class TEXT,
    class_confidence TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    llm_guess TEXT,
    llm_guess_at REAL
);
CREATE INDEX IF NOT EXISTS idx_identities_ip ON identities(ip);

CREATE TABLE IF NOT EXISTS pseudonym_map (
    real_key TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    kind TEXT NOT NULL
);

-- category distinguishes real zero-trust firewall-rule suggestions
-- ("zero_trust", LLM-derived from traffic patterns) from observability
-- tuning findings ("setup", deterministic — noise to reduce, gaps to fix;
-- see app/analysis/setup_recommendations.py). Kept in one table since both
-- share the same review/dismiss workflow; the UI splits them into tabs.
CREATE TABLE IF NOT EXISTS recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    category TEXT NOT NULL DEFAULT 'zero_trust',
    pattern_signature TEXT NOT NULL UNIQUE,
    pattern_summary_text TEXT NOT NULL,
    structured_json TEXT NOT NULL,
    llm_model_used TEXT,
    confidence TEXT,
    evidence_event_ids TEXT,
    applied_at REAL,
    applied_policy_id TEXT
);
-- No index on `category` here: on a database that predates this column,
-- CREATE TABLE IF NOT EXISTS is a no-op (the table already exists), so an
-- index on a column that doesn't exist yet would fail this whole script
-- before _apply_column_migrations() ever runs. Created in Python instead,
-- after the migration below guarantees the column exists — confirmed live
-- in production: this exact ordering crashed every service on first
-- deploy of the category column.

-- Optional friendly names for auto-discovered networks (see
-- app/analysis/network_map.py). discovery_key is the stable identifier a
-- network was discovered under (an interface name like "br21", or an
-- inferred CIDR like "192.168.10.0/24" when no interface signal exists) —
-- naming a network is a display-only convenience, never required for
-- discovery or recommendations to work.
CREATE TABLE IF NOT EXISTS network_names (
    discovery_key TEXT PRIMARY KEY,
    friendly_name TEXT NOT NULL
);

-- Stage 2 (UniFi-only, optional, read-only — see app/unifi/). One row,
-- replaced on every probe: the most recent answer to "what can this API
-- key actually do."
CREATE TABLE IF NOT EXISTS unifi_capability_report (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at REAL NOT NULL,
    reachable INTEGER NOT NULL,
    site_id TEXT,
    capabilities_json TEXT NOT NULL
);

-- Cached, read-only mirrors of UniFi API data, refreshed wholesale (not
-- diffed) on each sync — small collections on any home network, not worth
-- the complexity of incremental updates.
CREATE TABLE IF NOT EXISTS unifi_devices (
    id TEXT PRIMARY KEY,
    name TEXT,
    model TEXT,
    mac TEXT,
    ip TEXT,
    state TEXT,
    raw_json TEXT NOT NULL,
    fetched_at REAL NOT NULL
);

-- connected_at: the client's own connectedAt from the API (ISO 8601
-- string, stored as-is) -- when its current session started. This
-- endpoint only ever returns currently-connected clients in the first
-- place (there's no separate offline list mixed in), so a long-running,
-- healthy connection can have an old connected_at -- it is NOT a "last
-- seen" signal and must never be used to decide a client is stale.
-- client_type: "WIRED"/"WIRELESS"/"VPN"/"GUEST" per the API's docs.
-- Both NULL on a database that predates these columns until the next sync
-- backfills them.
CREATE TABLE IF NOT EXISTS unifi_clients (
    id TEXT PRIMARY KEY,
    name TEXT,
    mac TEXT,
    ip TEXT,
    network_id TEXT,
    connected_at TEXT,
    client_type TEXT,
    raw_json TEXT NOT NULL,
    fetched_at REAL NOT NULL
);

-- A real, configured VLAN/network from UniFi -- distinct from a firewall
-- zone, which groups several networks together for policy purposes. This
-- is the authoritative alternative to a traffic-guessed network: an IP
-- inside a known network's subnet gets that network's real name instead
-- of an unconfirmed /24 guess (see network_map.py's UniFi cross-reference).
CREATE TABLE IF NOT EXISTS unifi_networks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    vlan_id INTEGER,
    subnet TEXT,
    raw_json TEXT NOT NULL,
    fetched_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS unifi_zones (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    fetched_at REAL NOT NULL
);

-- logging_enabled: NULL means "couldn't tell" (see client.py's field-name
-- fallback), not "logging is off" — keep that distinction, don't coerce.
CREATE TABLE IF NOT EXISTS unifi_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    action TEXT,
    protocol TEXT,
    source_zone_id TEXT,
    destination_zone_id TEXT,
    logging_enabled INTEGER,
    raw_json TEXT NOT NULL,
    fetched_at REAL NOT NULL
);
"""

# (table, column, DDL for the new column) — CREATE TABLE IF NOT EXISTS above
# only creates a table from scratch; a column added to an existing table's
# definition needs its own ALTER TABLE, applied once, for every database
# that predates the column.
_COLUMN_MIGRATIONS = [
    ("recommendations", "category", "TEXT NOT NULL DEFAULT 'zero_trust'"),
    ("unifi_clients", "connected_at", "TEXT"),
    ("unifi_clients", "client_type", "TEXT"),
    ("identities", "llm_guess", "TEXT"),
    ("identities", "llm_guess_at", "REAL"),
    # Stage 3 (see STAGE3_APPLY_GOVERNANCE.md) -- both null until a
    # recommendation is actually applied; applied_policy_id is the real
    # UniFi-assigned id, used from then on as a direct lookup instead of
    # the port-based best-effort "Implemented" match everything else uses.
    ("recommendations", "applied_at", "REAL"),
    ("recommendations", "applied_policy_id", "TEXT"),
]


def _apply_column_migrations(conn: sqlite3.Connection) -> None:
    for table, column, ddl in _COLUMN_MIGRATIONS:
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    # Only safe to run once every migration above has applied — see the
    # comment by the recommendations table in SCHEMA for why this can't
    # just live in that script.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_recommendations_category ON recommendations(category)")


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
            _apply_column_migrations(conn)
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
