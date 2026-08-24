"""Ties the pieces together: pull recent events, group them into candidate
patterns, ask the LLM about the new ones, store the result.

This is orchestration, not logic — the interesting decisions (what counts
as a pattern, what the prompt says, how identity gets sanitized) all live in
the modules it calls. Runs from the `web` service's background thread, one
pass at a time, guarded against overlap by the caller.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass

from app.analysis.grouping import GroupableEvent, group_candidate_patterns
from app.analysis.netlabels import parse_network_labels
from app.analysis.network_map import NetworkMap, build_network_map, load_friendly_names, resolve_label
from app.analysis.noise import is_own_receiver_traffic
from app.analysis.setup_recommendations import generate_setup_recommendations
from app.config import Config, read_secret
from app.llm.client import LLMError, chat_completion
from app.llm.prompts import RECOMMENDATION_SCHEMA, build_recommendation_messages
from app.sanitize.classify import Classification, classify
from app.supervisor import get_host_ip

logger = logging.getLogger(__name__)

_LOOKBACK_SECONDS = 30 * 86400


def _identity_for_ip(conn: sqlite3.Connection, ip: str, network_label: str) -> Classification:
    row = conn.execute(
        "SELECT hostname, mac FROM identities WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
    ).fetchone()
    if row is None:
        return classify(hostname=None, mac=None, network_label=network_label)
    hostname, mac = row
    return classify(hostname=hostname, mac=mac, network_label=network_label)


def _load_events(
    conn: sqlite3.Connection,
    network_map: NetworkMap,
    friendly_names: dict[str, str],
    manual_labels: list,
    since: float,
    host_ip: str | None,
    syslog_port: int,
    netflow_port: int,
    ignore_own_receiver_traffic: bool,
) -> list[GroupableEvent]:
    events: list[GroupableEvent] = []

    firewall_rows = conn.execute(
        "SELECT id, ts, src_ip, dst_ip, proto, dst_port, action FROM events_firewall WHERE ts >= ?",
        (since,),
    ).fetchall()
    for event_id, ts, src_ip, dst_ip, proto, dst_port, action in firewall_rows:
        if ignore_own_receiver_traffic and is_own_receiver_traffic(
            dst_ip, dst_port, host_ip, syslog_port, netflow_port
        ):
            # The router logging its own log-forwarding traffic to this
            # add-on's receiver — expected and intentional, not a
            # segmentation decision worth a recommendation.
            continue
        src_label = resolve_label(src_ip, network_map, friendly_names, manual_labels)
        dst_label = resolve_label(dst_ip, network_map, friendly_names, manual_labels)
        events.append(
            GroupableEvent(
                event_id=event_id,
                ts=ts,
                src_class=_identity_for_ip(conn, src_ip, src_label).device_class,
                dst_class=_identity_for_ip(conn, dst_ip, dst_label).device_class,
                src_net_label=src_label,
                dst_net_label=dst_label,
                proto=proto,
                dst_port=dst_port,
                was_blocked=(action or "").upper() != "ALLOW",
            )
        )

    return events


def _existing_signatures(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT pattern_signature FROM recommendations").fetchall()
    return {row[0] for row in rows}


def _purge_stale_receiver_recommendations(conn: sqlite3.Connection, config: Config, host_ip: str | None) -> int:
    """A zero-trust recommendation whose destination is exactly this
    add-on's own receiver can already exist from before
    ignore_own_receiver_traffic was introduced (or from a run where it was
    off) — found live in production as the single highest-volume
    "recommendation" ever generated. It would otherwise sit "pending"
    forever, since recommendations are never re-evaluated once written.
    Matches only on the pattern's exact destination label + port (UDP-only,
    the only protocol either receiver listens on), not a broad port-only
    match — a coincidental, unrelated flow on the same port number that
    wasn't actually headed to this host must not get swept up too."""
    if not config.ignore_own_receiver_traffic or host_ip is None:
        return 0

    removed = 0
    rows = conn.execute("SELECT id, pattern_signature FROM recommendations WHERE category = 'zero_trust'").fetchall()
    for rec_id, signature in rows:
        parts = signature.split("|")
        if len(parts) != 6:
            continue
        _src_label, dst_label, _src_class, _dst_class, proto, port = parts
        if dst_label == host_ip and proto == "17" and port in (str(config.syslog_port), str(config.netflow_port)):
            conn.execute("DELETE FROM recommendations WHERE id = ?", (rec_id,))
            removed += 1
    if removed:
        conn.commit()
    return removed


def _confidence_for(conn: sqlite3.Connection, device_class: str) -> str:
    row = conn.execute(
        "SELECT class_confidence FROM identities WHERE device_class = ? LIMIT 1", (device_class,)
    ).fetchone()
    return row[0] if row else "low"


def _llm_base_url(config: Config) -> tuple[str, str | None]:
    if config.llm_mode == "remote":
        return config.llm_remote_base_url, read_secret("llm_api_key")
    return "http://127.0.0.1:8080/v1", None


@dataclass(frozen=True)
class AnalysisPassResult:
    zero_trust_written: int
    setup_written: int


def run_analysis_pass(conn: sqlite3.Connection, config: Config, now: float | None = None) -> AnalysisPassResult:
    now = now or time.time()

    # Deterministic and cheap (no LLM, no event scan beyond what's already
    # in health.json) — runs first so it's never skipped by a slow or
    # unreachable LLM endpoint.
    setup_written = generate_setup_recommendations(conn, config, now=now)

    since = now - _LOOKBACK_SECONDS
    manual_labels = parse_network_labels(list(config.network_labels))
    network_map = build_network_map(conn, since=since)
    friendly_names = load_friendly_names(conn)
    host_ip = get_host_ip()
    _purge_stale_receiver_recommendations(conn, config, host_ip)
    events = _load_events(
        conn, network_map, friendly_names, manual_labels, since=since, host_ip=host_ip,
        syslog_port=config.syslog_port, netflow_port=config.netflow_port,
        ignore_own_receiver_traffic=config.ignore_own_receiver_traffic,
    )
    patterns = group_candidate_patterns(events, min_recurring_days=config.min_recurring_days)

    known_signatures = _existing_signatures(conn)
    new_patterns = [p for p in patterns if p.signature not in known_signatures]

    base_url, api_key = _llm_base_url(config)
    written = 0
    for pattern in new_patterns:
        src_confidence = _confidence_for(conn, pattern.src_class)
        dst_confidence = _confidence_for(conn, pattern.dst_class)
        messages = build_recommendation_messages(pattern, src_confidence, dst_confidence)
        try:
            reply = chat_completion(
                base_url, messages, api_key=api_key, response_format=RECOMMENDATION_SCHEMA
            )
            structured = json.loads(reply)
        except (LLMError, json.JSONDecodeError) as exc:
            logger.warning("skipping pattern %s: %s", pattern.signature, exc)
            continue

        conn.execute(
            """INSERT INTO recommendations
               (created_at, status, category, pattern_signature, pattern_summary_text, structured_json,
                llm_model_used, confidence, evidence_event_ids)
               VALUES (?, 'pending', 'zero_trust', ?, ?, ?, ?, ?, ?)""",
            (
                now,
                pattern.signature,
                structured.get("plain_language_summary", ""),
                json.dumps(structured),
                config.llm_mode,
                structured.get("confidence", "low"),
                json.dumps(pattern.sample_event_ids),
            ),
        )
        # Committed per pattern, right away: an LLM call can take anywhere
        # from a second to a minute, and holding the write transaction open
        # across every remaining pattern's call would starve the receivers'
        # writes to the same database for the whole analysis pass.
        conn.commit()
        written += 1

    return AnalysisPassResult(zero_trust_written=written, setup_written=setup_written)
