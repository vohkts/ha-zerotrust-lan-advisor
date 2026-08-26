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
from collections import Counter
from dataclasses import dataclass

from app.analysis.direction import is_private_ip
from app.analysis.grouping import GroupableEvent, group_candidate_patterns
from app.analysis.netlabels import parse_network_labels
from app.analysis.network_map import (
    NetworkMap,
    build_network_map,
    load_friendly_names,
    load_unifi_networks,
    load_unifi_vlan_names,
    resolve_label,
)
from app.analysis.noise import is_own_receiver_traffic
from app.analysis.rule_match import find_covering_policy, load_parsed_policies
from app.analysis.setup_recommendations import generate_setup_recommendations
from app.config import Config, read_secret
from app.llm.client import LLMError, chat_completion
from app.llm.prompts import RECOMMENDATION_SCHEMA, build_recommendation_messages
from app.sanitize.classify import Classification, classify, classify_from_ports
from app.sanitize.oui import lookup_vendor
from app.supervisor import get_host_ip
from app.unifi.checks import generate_unifi_setup_findings

logger = logging.getLogger(__name__)

_LOOKBACK_SECONDS = 30 * 86400
_RECLASSIFY_ROW_LIMIT = 2000  # per host, per table -- bounded like every other per-host scan


def _identity_for_ip(conn: sqlite3.Connection, ip: str, network_label: str) -> Classification:
    row = conn.execute(
        "SELECT hostname, mac, device_class, class_confidence FROM identities "
        "WHERE ip = ? ORDER BY last_seen DESC LIMIT 1",
        (ip,),
    ).fetchone()
    if row is None:
        return classify(hostname=None, mac=None, network_label=network_label)
    hostname, mac, device_class, confidence = row
    # A stored classification can be better than a blind hostname/mac
    # recompute -- it may already reflect a port-based guess (see
    # classify_from_ports below) that classify() has no way to reproduce
    # from hostname/mac alone. Only trust it once it's actually resolved
    # to something, though; "Unclassified*" is worth re-trying every time
    # in case a fresher hostname has since shown up.
    if device_class and confidence and not device_class.startswith("Unclassified"):
        return Classification(device_class=device_class, confidence=confidence, vendor=lookup_vendor(mac) if mac else None)
    return classify(hostname=hostname, mac=mac, network_label=network_label)


def _reclassify_unclassified_hosts(conn: sqlite3.Connection, since: float) -> int:
    """A deterministic, LLM-free pass: for every host still Unclassified
    from hostname/vendor alone, see if its own traffic settles the
    question (see classify_from_ports) -- e.g. a host with no helpful
    hostname that mostly answers connections on 8086/tcp is InfluxDB
    whether or not anything ever named it that. Persisted into identities
    (guarded against being immediately overwritten again -- see the
    upsert changes in mdns_listener.py/unifi/sync.py) so it sticks, and so
    both the Hosts table and _identity_for_ip above pick it up."""
    rows = conn.execute(
        "SELECT ip, vendor FROM identities WHERE ip IS NOT NULL "
        "AND (device_class IS NULL OR device_class LIKE 'Unclassified%')"
    ).fetchall()
    updated = 0
    for ip, vendor in rows:
        port_counts: Counter = Counter()
        for table, ts_col in (("events_firewall", "ts"), ("events_flow", "ts_start")):
            port_rows = conn.execute(
                f"SELECT dst_port FROM {table} WHERE dst_ip = ? AND {ts_col} >= ? "
                "AND dst_port IS NOT NULL LIMIT ?",
                (ip, since, _RECLASSIFY_ROW_LIMIT),
            ).fetchall()
            port_counts.update(p for (p,) in port_rows)
        guess = classify_from_ports(dict(port_counts), vendor=vendor)
        if guess is None:
            continue
        conn.execute(
            "UPDATE identities SET device_class = ?, class_confidence = ? WHERE ip = ?",
            (guess.device_class, guess.confidence, ip),
        )
        updated += 1
    if updated:
        conn.commit()
    return updated


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
    unifi_networks: list | None = None,
    unifi_console_host: str | None = None,
    vlan_names: dict[int, str] | None = None,
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
        if unifi_console_host and (src_ip == unifi_console_host or dst_ip == unifi_console_host):
            # Same reasoning as the receiver-traffic skip above, for the
            # UDM console's own management IP — infrastructure noise
            # (DNS/DHCP served to every device, health checks), not a
            # segmentation decision worth a recommendation.
            continue
        if not is_private_ip(src_ip) and not is_private_ip(dst_ip):
            # Real bug, reported live: recommendations like "allow ICMP
            # from 89.58.82.0/24 to 85.217.149.0/24" -- two public ranges,
            # neither touching any of the user's own network zones at
            # all. This is the same EXTERNAL_EXTERNAL case the Traffic
            # page already tracks separately (see direction.py) -- normal
            # background internet noise or pre-NAT logging quirks, never
            # a zero-trust segmentation decision the user's own firewall
            # can act on. An internal<->external pattern (one real local
            # device, one external service) is still a legitimate
            # recommendation and stays in.
            continue
        src_label = resolve_label(src_ip, network_map, friendly_names, manual_labels, unifi_networks, vlan_names)
        dst_label = resolve_label(dst_ip, network_map, friendly_names, manual_labels, unifi_networks, vlan_names)
        events.append(
            GroupableEvent(
                event_id=event_id,
                ts=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
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


def _real_identifiers_for_pattern(conn: sqlite3.Connection, pattern) -> tuple[list[str], list[str]]:
    """Real hostnames (or IPs, when no hostname is known) actually seen
    behind a pattern's sample events -- only ever called when the user has
    explicitly opted into llm_send_real_identifiers (see
    build_recommendation_messages' docstring). Bounded by however many
    sample_event_ids grouping.py already kept, so at most a handful of
    lookups regardless of how many times the pattern actually occurred."""
    if not pattern.sample_event_ids:
        return [], []
    placeholders = ",".join("?" * len(pattern.sample_event_ids))
    rows = conn.execute(
        f"SELECT src_ip, dst_ip FROM events_firewall WHERE id IN ({placeholders})",  # noqa: S608 -- placeholders only, no interpolated values
        pattern.sample_event_ids,
    ).fetchall()

    def _label(ip: str) -> str:
        row = conn.execute(
            "SELECT hostname FROM identities WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
        ).fetchone()
        return row[0] if row and row[0] else ip

    return sorted({_label(r[0]) for r in rows}), sorted({_label(r[1]) for r in rows})


def _confidence_for(conn: sqlite3.Connection, device_class: str) -> str:
    row = conn.execute(
        "SELECT class_confidence FROM identities WHERE device_class = ? LIMIT 1", (device_class,)
    ).fetchone()
    return row[0] if row else "low"


def llm_base_url(config: Config) -> tuple[str, str | None]:
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
    # UniFi cache is only ever populated when the integration is enabled and
    # working (see app/unifi/sync.py) — an empty unifi_policies table makes
    # this a no-op, no config.unifi_enabled check needed here.
    setup_written += generate_unifi_setup_findings(conn, now=now)

    since = now - _LOOKBACK_SECONDS
    _reclassify_unclassified_hosts(conn, since)
    manual_labels = parse_network_labels(list(config.network_labels))
    network_map = build_network_map(conn, since=since)
    friendly_names = load_friendly_names(conn)
    unifi_networks = load_unifi_networks(conn)
    vlan_names = load_unifi_vlan_names(conn)
    host_ip = get_host_ip()
    _purge_stale_receiver_recommendations(conn, config, host_ip)
    events = _load_events(
        conn, network_map, friendly_names, manual_labels, since=since, host_ip=host_ip,
        syslog_port=config.syslog_port, netflow_port=config.netflow_port,
        ignore_own_receiver_traffic=config.ignore_own_receiver_traffic,
        unifi_networks=unifi_networks,
        unifi_console_host=config.unifi_host if config.ignore_unifi_console_traffic else None,
        vlan_names=vlan_names,
    )
    patterns = group_candidate_patterns(events, min_recurring_days=config.min_recurring_days)

    known_signatures = _existing_signatures(conn)
    real_policies = load_parsed_policies(conn)
    new_patterns = [
        p
        for p in patterns
        if p.signature not in known_signatures and find_covering_policy(real_policies, p.dst_port) is None
    ]

    base_url, api_key = llm_base_url(config)
    written = 0
    for pattern in new_patterns:
        src_confidence = _confidence_for(conn, pattern.src_class)
        dst_confidence = _confidence_for(conn, pattern.dst_class)
        src_identifiers, dst_identifiers = (
            _real_identifiers_for_pattern(conn, pattern) if config.llm_send_real_identifiers else ([], [])
        )
        messages = build_recommendation_messages(
            pattern, src_confidence, dst_confidence, src_identifiers, dst_identifiers
        )
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
