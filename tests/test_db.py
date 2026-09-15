import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app import db


def test_connect_on_a_fresh_database_creates_full_schema(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(recommendations)")}
    assert "category" in columns


def test_connect_migrates_an_existing_database_missing_the_category_column(tmp_path):
    # Simulates a real production database created before `category` was
    # added — CREATE TABLE IF NOT EXISTS alone is a no-op against it, which
    # is exactly what broke every service on first deploy of that column:
    # a CREATE INDEX in the same script referenced the not-yet-existing
    # column and crashed the whole executescript before the migration
    # step ever got a chance to run.
    db_path = tmp_path / "zerotrust.db"
    old_conn = sqlite3.connect(db_path)
    old_conn.execute(
        """CREATE TABLE recommendations (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               created_at REAL NOT NULL,
               status TEXT NOT NULL DEFAULT 'pending',
               pattern_signature TEXT NOT NULL UNIQUE,
               pattern_summary_text TEXT NOT NULL,
               structured_json TEXT NOT NULL,
               llm_model_used TEXT,
               confidence TEXT,
               evidence_event_ids TEXT
           )"""
    )
    old_conn.execute(
        """INSERT INTO recommendations
           (created_at, pattern_signature, pattern_summary_text, structured_json)
           VALUES (1700000000, 'sig1', 'a pre-existing recommendation', '{}')"""
    )
    old_conn.commit()
    old_conn.close()

    conn = db.connect(db_path)  # must not raise

    columns = {row[1] for row in conn.execute("PRAGMA table_info(recommendations)")}
    assert "category" in columns

    row = conn.execute("SELECT category, pattern_summary_text FROM recommendations").fetchone()
    assert row[0] == "zero_trust"  # the column's DEFAULT, applied retroactively
    assert row[1] == "a pre-existing recommendation"  # the old row survived intact

    # The index that depends on the migrated column must also exist now.
    indexes = {row[1] for row in conn.execute("PRAGMA index_list(recommendations)")}
    assert "idx_recommendations_category" in indexes


def test_connect_migrates_an_existing_unifi_clients_table_missing_connected_at(tmp_path):
    # Simulates a real production database from before connected_at existed
    # -- unifi_clients is fully DELETE+re-INSERT'd on every sync, but the
    # migration still has to run cleanly against whatever the table looked
    # like the last time this add-on started.
    db_path = tmp_path / "zerotrust.db"
    old_conn = sqlite3.connect(db_path)
    old_conn.execute(
        """CREATE TABLE unifi_clients (
               id TEXT PRIMARY KEY,
               name TEXT,
               mac TEXT,
               ip TEXT,
               network_id TEXT,
               raw_json TEXT NOT NULL,
               fetched_at REAL NOT NULL
           )"""
    )
    old_conn.execute(
        "INSERT INTO unifi_clients (id, name, mac, ip, network_id, raw_json, fetched_at) "
        "VALUES ('c1', 'iPhone', 'aa:bb', '10.0.0.9', 'net-1', '{}', 1700000000)"
    )
    old_conn.commit()
    old_conn.close()

    conn = db.connect(db_path)  # must not raise

    columns = {row[1] for row in conn.execute("PRAGMA table_info(unifi_clients)")}
    assert "connected_at" in columns

    row = conn.execute("SELECT name, connected_at FROM unifi_clients WHERE id = 'c1'").fetchone()
    assert row[0] == "iPhone"  # the old row survived intact
    assert row[1] is None  # backfilled NULL, not a guessed value


def test_connect_migrates_an_existing_unifi_clients_table_missing_client_type(tmp_path):
    # The actual real-world sequence: a database that already has
    # connected_at (from the prior migration) but predates client_type.
    db_path = tmp_path / "zerotrust.db"
    old_conn = sqlite3.connect(db_path)
    old_conn.execute(
        """CREATE TABLE unifi_clients (
               id TEXT PRIMARY KEY,
               name TEXT,
               mac TEXT,
               ip TEXT,
               network_id TEXT,
               connected_at TEXT,
               raw_json TEXT NOT NULL,
               fetched_at REAL NOT NULL
           )"""
    )
    old_conn.execute(
        "INSERT INTO unifi_clients (id, name, mac, ip, network_id, connected_at, raw_json, fetched_at) "
        "VALUES ('c1', 'iPhone', 'aa:bb', '10.0.0.9', 'net-1', '2026-08-20T10:00:00Z', '{}', 1700000000)"
    )
    old_conn.commit()
    old_conn.close()

    conn = db.connect(db_path)  # must not raise

    columns = {row[1] for row in conn.execute("PRAGMA table_info(unifi_clients)")}
    assert "client_type" in columns

    row = conn.execute("SELECT connected_at, client_type FROM unifi_clients WHERE id = 'c1'").fetchone()
    assert row[0] == "2026-08-20T10:00:00Z"  # the old row survived intact
    assert row[1] is None


def test_connect_migrates_an_existing_identities_table_missing_llm_guess_columns(tmp_path):
    db_path = tmp_path / "zerotrust.db"
    old_conn = sqlite3.connect(db_path)
    old_conn.execute(
        """CREATE TABLE identities (
               device_key TEXT PRIMARY KEY,
               ip TEXT,
               mac TEXT,
               hostname TEXT,
               vendor TEXT,
               device_class TEXT,
               class_confidence TEXT,
               first_seen REAL NOT NULL,
               last_seen REAL NOT NULL
           )"""
    )
    old_conn.execute(
        "INSERT INTO identities (device_key, ip, hostname, device_class, class_confidence, first_seen, last_seen) "
        "VALUES ('d1', '10.0.0.9', 'iPhone', 'iPhone', 'high', 1700000000, 1700000000)"
    )
    old_conn.commit()
    old_conn.close()

    conn = db.connect(db_path)  # must not raise

    columns = {row[1] for row in conn.execute("PRAGMA table_info(identities)")}
    assert {"llm_guess", "llm_guess_at"} <= columns

    row = conn.execute("SELECT hostname, llm_guess FROM identities WHERE device_key = 'd1'").fetchone()
    assert row[0] == "iPhone"  # the old row survived intact
    assert row[1] is None


def test_connect_migrates_an_existing_recommendations_table_missing_applied_columns(tmp_path):
    db_path = tmp_path / "zerotrust.db"
    old_conn = sqlite3.connect(db_path)
    old_conn.execute(
        """CREATE TABLE recommendations (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               created_at REAL NOT NULL,
               status TEXT NOT NULL DEFAULT 'pending',
               category TEXT NOT NULL DEFAULT 'zero_trust',
               pattern_signature TEXT NOT NULL UNIQUE,
               pattern_summary_text TEXT NOT NULL,
               structured_json TEXT NOT NULL,
               llm_model_used TEXT,
               confidence TEXT,
               evidence_event_ids TEXT
           )"""
    )
    old_conn.execute(
        "INSERT INTO recommendations (created_at, pattern_signature, pattern_summary_text, structured_json) "
        "VALUES (1700000000, 'sig1', 'summary', '{}')"
    )
    old_conn.commit()
    old_conn.close()

    conn = db.connect(db_path)  # must not raise

    columns = {row[1] for row in conn.execute("PRAGMA table_info(recommendations)")}
    assert {"applied_at", "applied_policy_id"} <= columns

    row = conn.execute("SELECT pattern_summary_text, applied_at, applied_policy_id FROM recommendations").fetchone()
    assert row[0] == "summary"  # the old row survived intact
    assert row[1] is None
    assert row[2] is None


def test_connect_is_idempotent_on_an_already_migrated_database(tmp_path):
    db_path = tmp_path / "zerotrust.db"
    db.connect(db_path)
    conn = db.connect(db_path)  # a second connect() must not raise or duplicate anything
    columns = [row[1] for row in conn.execute("PRAGMA table_info(recommendations)")]
    assert columns.count("category") == 1


def test_connect_converts_a_fresh_database_to_incremental_auto_vacuum(tmp_path):
    conn = db.connect(tmp_path / "zerotrust.db")
    assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2  # 2 == incremental


def test_connect_converts_a_pre_existing_auto_vacuum_none_database(tmp_path):
    # Simulates every real database created before this existed: default
    # auto_vacuum=NONE, already holding data.
    db_path = tmp_path / "zerotrust.db"
    old_conn = sqlite3.connect(db_path)
    old_conn.execute(
        "CREATE TABLE events_firewall (id INTEGER PRIMARY KEY, ts REAL NOT NULL, "
        "src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, src_port INTEGER, dst_port INTEGER, "
        "proto INTEGER NOT NULL, iface_in TEXT, iface_out TEXT, rule_prefix TEXT, "
        "action TEXT, received_at REAL NOT NULL)"
    )
    old_conn.execute(
        "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, received_at) "
        "VALUES (1700000000, '10.0.0.1', '10.0.0.2', 6, 1700000000)"
    )
    old_conn.commit()
    old_conn.close()
    assert sqlite3.connect(db_path).execute("PRAGMA auto_vacuum").fetchone()[0] == 0  # NONE

    conn = db.connect(db_path)  # must not raise, and must convert

    assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
    # The pre-existing row must survive the VACUUM this conversion runs.
    row = conn.execute("SELECT src_ip, dst_ip FROM events_firewall").fetchone()
    assert row == ("10.0.0.1", "10.0.0.2")


def test_prune_if_low_disk_does_nothing_when_free_space_is_above_the_buffer(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    conn.execute(
        "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, received_at) "
        "VALUES (1000, '10.0.0.1', '10.0.0.2', 6, 1000)"
    )
    conn.commit()

    monkeypatch.setattr(
        db.shutil, "disk_usage", lambda path: type("Usage", (), {"free": 10 * 1024 * 1024 * 1024})()
    )

    result = db.prune_if_low_disk(conn, tmp_path / "zerotrust.db", buffer_mb=2048, now=100_000)

    assert result is None
    assert conn.execute("SELECT count(*) FROM events_firewall").fetchone()[0] == 1


def test_prune_if_low_disk_deletes_oldest_data_first_when_below_the_buffer(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    now = 1_000_000
    # One row a day apart for 10 days, oldest first.
    for day in range(10):
        ts = now - day * 86400
        conn.execute(
            "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, received_at) "
            "VALUES (?, '10.0.0.1', '10.0.0.2', 6, ?)",
            (ts, ts),
        )
    conn.commit()

    # Free space never recovers above the buffer in this test, so pruning
    # runs until it hits min_retain_seconds -- confirms it stops there
    # rather than deleting everything.
    monkeypatch.setattr(
        db.shutil, "disk_usage", lambda path: type("Usage", (), {"free": 0})()
    )

    db.prune_if_low_disk(conn, tmp_path / "zerotrust.db", buffer_mb=2048, now=now, min_retain_seconds=3600)

    remaining = [row[0] for row in conn.execute("SELECT ts FROM events_firewall ORDER BY ts")]
    assert remaining  # the most recent row(s), inside min_retain_seconds, must survive
    assert min(remaining) >= now - 3600 - 21600  # oldest surviving row is within one step of the floor
    assert len(remaining) < 10  # older rows were actually removed


def test_prune_if_low_disk_stops_once_free_space_recovers(tmp_path, monkeypatch):
    conn = db.connect(tmp_path / "zerotrust.db")
    now = 1_000_000
    for day in range(10):
        ts = now - day * 86400
        conn.execute(
            "INSERT INTO events_firewall (ts, src_ip, dst_ip, proto, received_at) "
            "VALUES (?, '10.0.0.1', '10.0.0.2', 6, ?)",
            (ts, ts),
        )
    conn.commit()

    # Reports as below the buffer exactly once, then recovered -- as if
    # the first deleted chunk was enough.
    calls = {"n": 0}

    def fake_disk_usage(path):
        calls["n"] += 1
        # Call 1 is the entry check, call 2 is the first loop iteration's
        # pre-delete check -- both report low so exactly one chunk gets
        # deleted; call 3 (the next iteration's pre-delete check) reports
        # recovered, so the loop stops there.
        free = 0 if calls["n"] <= 2 else 10 * 1024 * 1024 * 1024
        return type("Usage", (), {"free": free})()

    monkeypatch.setattr(db.shutil, "disk_usage", fake_disk_usage)

    db.prune_if_low_disk(conn, tmp_path / "zerotrust.db", buffer_mb=2048, now=now)

    remaining = conn.execute("SELECT count(*) FROM events_firewall").fetchone()[0]
    assert remaining == 9  # only the single oldest 6-hour chunk was removed
