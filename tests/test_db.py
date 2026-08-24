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


def test_connect_is_idempotent_on_an_already_migrated_database(tmp_path):
    db_path = tmp_path / "zerotrust.db"
    db.connect(db_path)
    conn = db.connect(db_path)  # a second connect() must not raise or duplicate anything
    columns = [row[1] for row in conn.execute("PRAGMA table_info(recommendations)")]
    assert columns.count("category") == 1
