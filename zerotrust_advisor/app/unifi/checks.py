"""Deterministic, UniFi-only cross-reference checks — a no-op unless the
integration is enabled and at least one UniFi sync has actually populated
the cache (see app/unifi/sync.py). Findings land in the same `recommendations`
table as app/analysis/setup_recommendations.py, category="setup": these are
observability-tuning findings about the router's own configuration, not
zero-trust rule suggestions.

Kept intentionally narrow tonight to one well-grounded check rather than a
long list of speculative ones — the Integration API only confirms a
policy's own fields (enabled, logging_enabled, the zone pair), not which of
this add-on's observed events a given policy actually matched, so any
finding here has to be honest about what it can and can't prove.
"""
from __future__ import annotations

import json
import sqlite3
import time


def _existing_signatures(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT pattern_signature FROM recommendations WHERE category = 'setup' AND pattern_signature LIKE 'unifi:%'"
    ).fetchall()
    return {row[0] for row in rows}


def generate_unifi_setup_findings(conn: sqlite3.Connection, now: float | None = None) -> int:
    """Flags enabled UniFi firewall policies that have logging turned off.

    An active policy with logging disabled matches traffic silently — this
    add-on (and anything else watching the syslog feed) never sees that it
    happened. That's invisible by design until someone goes looking for a
    specific flow and can't find it. Surfacing it here, once, as a setup
    finding is cheaper than that debugging session.
    """
    now = now or time.time()
    existing = _existing_signatures(conn)

    rows = conn.execute(
        """SELECT p.id, p.name, p.action, z1.name, z2.name
           FROM unifi_policies p
           LEFT JOIN unifi_zones z1 ON z1.id = p.source_zone_id
           LEFT JOIN unifi_zones z2 ON z2.id = p.destination_zone_id
           WHERE p.enabled = 1 AND p.logging_enabled = 0"""
    ).fetchall()

    written = 0
    for policy_id, name, action, src_zone, dst_zone in rows:
        signature = f"unifi:logging_off:{policy_id}"
        if signature in existing:
            continue

        zones = f"{src_zone or 'unknown zone'} → {dst_zone or 'unknown zone'}"
        structured = {
            "plain_language_summary": (
                f'UniFi firewall policy "{name}" ({action or "unknown action"}, {zones}) is active but has '
                "logging turned off. If it's matching real traffic, that traffic never reaches this add-on "
                "(or anywhere else watching your logs) — it happens silently. Turning logging on for this "
                "policy is the only way to find out whether it's actually being used."
            ),
            "likely_purpose": f"UniFi firewall policy: {name}",
            "suggested_rule_scope": "N/A — this is a router logging setting, not a firewall rule.",
            "confidence": "high",
            "caveats": [
                "This is a configuration audit finding, not proof the policy has matched anything.",
                "Fetched read-only from the UniFi Integration API; it reflects the console's state as of "
                "the last sync, not necessarily right now.",
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
