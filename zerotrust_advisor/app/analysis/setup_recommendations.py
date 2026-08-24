"""Generates deterministic, LLM-free "setup & tuning" findings — distinct
from engine.py's LLM-derived zero-trust firewall-rule recommendations.
Both land in the same `recommendations` table (category="setup" vs.
"zero_trust") and share the same review/accept/dismiss workflow, but the
Recommendations screen shows them as separate tabs: one is "here's a real
segmentation decision to consider," the other is "here's how to make this
add-on's own view of your network more accurate."

Currently: recognizing noisy router logging categories worth turning down,
from the per-category counters syslog_receiver.py already tracks (see
noise_categories.py). No LLM call, no extra event scan needed beyond
what's already in health.json — cheap enough to run on every analysis pass,
local-only regardless of the configured LLM mode.
"""
from __future__ import annotations

import json
import sqlite3
import time

from app.analysis.noise_categories import CATEGORY_KEYS, category_description
from app.config import Config
from app.health import read_health

# A category needs to show up at least this often before it's worth
# surfacing — a handful of AP roaming events isn't worth a recommendation.
_NOISE_THRESHOLD = 500


def _existing_setup_signatures(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT pattern_signature FROM recommendations WHERE category = 'setup'").fetchall()
    return {row[0] for row in rows}


def generate_setup_recommendations(conn: sqlite3.Connection, config: Config, now: float | None = None) -> int:
    """Returns the number of new setup recommendations written."""
    now = now or time.time()
    syslog_health = read_health(config.health_dir, "syslog") or {}
    existing = _existing_setup_signatures(conn)

    written = 0
    for key in CATEGORY_KEYS:
        count = syslog_health.get(f"noise_{key}", 0)
        if count < _NOISE_THRESHOLD:
            continue
        signature = f"noise:{key}"
        if signature in existing:
            continue

        description = category_description(key)
        structured = {
            "plain_language_summary": (
                f"Seeing a lot of {description} — {count:,} messages so far. This isn't firewall/traffic "
                "data and doesn't help with zero-trust recommendations; consider turning this logging "
                "category off (or routing it elsewhere) on your router to reduce noise."
            ),
            "likely_purpose": description,
            "suggested_rule_scope": "N/A — this is a router logging setting, not a firewall rule.",
            "confidence": "high",
            "caveats": [
                "This only reduces noise in this add-on's own view — it doesn't change your firewall.",
                "If you use this log category elsewhere too (e.g. another SIEM), point that traffic "
                "somewhere other than this add-on's syslog port instead of disabling it outright.",
            ],
        }
        conn.execute(
            """INSERT INTO recommendations
               (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                llm_model_used, confidence, evidence_event_ids)
               VALUES (?, 'pending', 'setup', ?, ?, ?, NULL, ?, '[]')""",
            (
                now,
                signature,
                structured["plain_language_summary"],
                json.dumps(structured),
                structured["confidence"],
            ),
        )
        conn.commit()
        written += 1

    return written
