"""Recommendations review screen. Accept/dismiss is purely local
bookkeeping — Stage 1 has no code path that ever writes to the router.

Split into two categories, shown as separate tabs: "zero_trust" (real
firewall-rule suggestions, LLM-derived from traffic patterns) and "setup"
(deterministic observability-tuning findings — noise to reduce, gaps to
fix; see app/analysis/setup_recommendations.py). Mixing "here's a real
segmentation decision" with "here's how to make your logging setup better"
in one list made the former harder to act on.

Mutating actions respond with a small JSON body rather than a redirect and
are called from the page via fetch() (see static/app.js); the browser's
address bar never leaves /recommendations, which sidesteps having to
compute correct relative-URL depth for an Ingress-prefixed redirect.
"""
from __future__ import annotations

import json
import logging
import threading
import time

from flask import Blueprint, current_app, jsonify, render_template, request

from app.analysis.network_map import build_network_map, load_unifi_networks, load_unifi_vlan_names
from app.analysis.rule_match import find_covering_policy, load_parsed_policies
from app.analysis.runner import is_running, run_analysis_now
from app.config import read_secret
from app.db import connect
from app.unifi import sync
from app.unifi.apply import ApplyNotPossible, build_policy_payload, create_policy
from app.unifi.client import UnifiClientAPI, UnifiError, UnifiUnreachable
from app.web.db_context import get_db

logger = logging.getLogger(__name__)

recommendations_bp = Blueprint("recommendations", __name__)


def _implemented_status(pattern_signature: str, real_policies: list) -> tuple[bool | None, str | None, str | None]:
    """(implemented, matched_policy_id, matched_policy_name). implemented
    is None (shown as "unknown") only when the pattern has no specific
    port to check -- "no rule found" is a real False, not an unknown.
    matched_policy_id lets the UI link straight to that rule's own detail
    view (see rule_match.py for what "covers" means here)."""
    parts = pattern_signature.split("|")
    if len(parts) != 6:
        return None, None, None
    try:
        port = int(parts[5])
    except ValueError:
        return None, None, None
    policy = find_covering_policy(real_policies, port)
    if policy is None:
        return False, None, None
    return True, policy.id, policy.name


def _real_ips_for_evidence(conn, evidence_event_ids: list[int]) -> tuple[list[str], list[str]]:
    """Real (src_ips, dst_ips) behind a pattern's stored sample evidence.
    Bounded by however many sample_event_ids grouping.py kept in the
    first place (a handful), regardless of how many times the pattern
    actually occurred."""
    if not evidence_event_ids:
        return [], []
    placeholders = ",".join("?" * len(evidence_event_ids))
    rows = conn.execute(
        f"SELECT src_ip, dst_ip FROM events_firewall WHERE id IN ({placeholders})",  # noqa: S608 -- placeholders only
        evidence_event_ids,
    ).fetchall()
    return sorted({r[0] for r in rows}), sorted({r[1] for r in rows})


def _real_identity_label(conn, ips: list[str]) -> str | None:
    """A compact, real, local-only label for one side of a pattern --
    hostname (or bare IP) for a single device, or a real device count
    with example IPs for a population. This is a completely different
    privacy boundary than what ever reaches the LLM (see
    llm_send_real_identifiers in prompts.py): this page never leaves the
    box, same reasoning the Traffic page already relies on to show real
    IPs/hostnames directly. Reported live: recommendation text alone
    ("a single, consistently the same device") gave no way to tell which
    real device that actually was."""
    if not ips:
        return None

    def _label(ip: str) -> str:
        row = conn.execute(
            "SELECT hostname FROM identities WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
        ).fetchone()
        return f"{ip} ({row[0]})" if row and row[0] else ip

    if len(ips) == 1:
        return _label(ips[0])
    shown = ", ".join(_label(ip) for ip in ips[:3])
    more = f", +{len(ips) - 3} more" if len(ips) > 3 else ""
    return f"{len(ips)} devices: {shown}{more}"


def _load_items(conn, category: str, real_policies: list | None = None):
    rows = conn.execute(
        """SELECT id, created_at, status, pattern_summary_text, structured_json, confidence, pattern_signature,
                  applied_at, applied_policy_id, evidence_event_ids
           FROM recommendations WHERE category = ? ORDER BY created_at DESC""",
        (category,),
    ).fetchall()
    items = []
    for row in rows:
        applied_policy_id = row[8]
        item = {
            "id": row[0],
            "created_at": row[1],
            "status": row[2],
            "summary": row[3],
            "structured": json.loads(row[4]),
            "confidence": row[5],
            "applied_at": row[7],
            "implemented": None,
            "matched_policy_id": None,
            "matched_policy_name": None,
            "real_source": None,
            "real_destination": None,
        }
        if applied_policy_id:
            # Applied through this add-on itself (Stage 3) -- a direct,
            # exact lookup by the real id UniFi returned, not the
            # port-based best-effort match everything else here uses.
            item["implemented"] = True
            item["matched_policy_id"] = applied_policy_id
        elif real_policies is not None and item["status"] == "accepted":
            # Only worth checking for recommendations the user has
            # actually accepted -- a pending or dismissed one being
            # "implemented" or not isn't a meaningful question yet.
            item["implemented"], item["matched_policy_id"], item["matched_policy_name"] = _implemented_status(
                row[6], real_policies
            )
        if category == "zero_trust":
            src_ips, dst_ips = _real_ips_for_evidence(conn, json.loads(row[9] or "[]"))
            item["real_source"] = _real_identity_label(conn, src_ips)
            item["real_destination"] = _real_identity_label(conn, dst_ips)
        items.append(item)
    return items


def _apply_gate_error(config) -> str | None:
    """None if all three independent conditions from
    STAGE3_APPLY_GOVERNANCE.md §5 are met; otherwise the specific reason
    Apply isn't reachable at all right now. Checked on every apply-related
    request, not just once at page load -- a setting can change between
    opening the page and clicking the button."""
    if config.unifi_apply_mode != "manual":
        return "UniFi rule apply mode isn't set to \"manual\" in Settings."
    if not config.unifi_apply_acknowledged:
        return "You haven't acknowledged that this add-on can write to your firewall yet (Settings)."
    if not config.unifi_enabled or not config.unifi_host:
        return "The UniFi integration isn't enabled/configured (Settings)."
    if not read_secret("unifi_api_key"):
        return "No UniFi API key is configured (Settings)."
    return None


def _load_applicable_recommendation(conn, rec_id: int) -> tuple[dict | None, str | None]:
    """(row_as_dict, error). error is a plain-English reason this specific
    recommendation can't be applied -- distinct from _apply_gate_error,
    which is about whether Apply is reachable *at all* right now."""
    row = conn.execute(
        """SELECT status, category, pattern_signature, structured_json, evidence_event_ids, applied_at
           FROM recommendations WHERE id = ?""",
        (rec_id,),
    ).fetchone()
    if row is None:
        return None, "not_found"
    status, category, pattern_signature, structured_json, evidence_event_ids, applied_at = row
    if category != "zero_trust":
        return None, "Only zero-trust rule recommendations can be applied."
    if applied_at:
        return None, "This recommendation has already been applied."
    if status != "accepted":
        return None, "Only an accepted recommendation can be applied — accept it first."
    return {
        "pattern_signature": pattern_signature,
        "structured": json.loads(structured_json),
        "evidence_event_ids": json.loads(evidence_event_ids or "[]"),
    }, None


def _build_payload(conn, rec: dict) -> tuple[dict, str]:
    """(payload, rule_name). Real IPs behind the recommendation are
    re-derived from its stored evidence_event_ids, the same way
    engine.py's real-identifiers option does -- never stored on the
    recommendation itself. Raises ApplyNotPossible (from apply.py) when
    either side can't be confidently resolved against the real,
    currently-synced UniFi ruleset."""
    parts = rec["pattern_signature"].split("|")
    if len(parts) != 6:
        raise ApplyNotPossible("This recommendation's pattern can't be parsed anymore.")
    _src_label, _dst_label, _src_class, _dst_class, proto_s, port_s = parts
    proto = int(proto_s)
    port = None if port_s == "None" else int(port_s)

    src_ips, dst_ips = _real_ips_for_evidence(conn, rec["evidence_event_ids"])

    since = time.time() - 30 * 86400
    network_map = build_network_map(conn, since=since)
    unifi_networks = load_unifi_networks(conn)
    vlan_names = load_unifi_vlan_names(conn)

    structured = rec["structured"]
    name = f"ZTA: {structured.get('rule_source', '?')} -> {structured.get('rule_destination', '?')}"[:255]

    payload = build_policy_payload(
        conn,
        name=name,
        action=structured.get("action", "allow"),
        proto=proto,
        port=port,
        src_ips=src_ips,
        dst_ips=dst_ips,
        network_map=network_map,
        unifi_networks=unifi_networks,
        vlan_names=vlan_names,
    )
    return payload, name


@recommendations_bp.route("/recommendations")
def list_recommendations():
    # Both categories render on this one page with a client-side tab
    # toggle (see static/app.js) rather than a second route at a different
    # URL depth — every other link in this app is deliberately kept flat
    # (one segment) so relative URLs resolve correctly under whatever path
    # prefix Ingress assigns; see base.html.
    #
    # Open (pending) items are the default view per category; anything
    # already accepted or dismissed moves to one combined "Accepted &
    # Dismissed" tab instead of cluttering the working list -- reported
    # live as wanting a clear separation, plus a way to reopen one.
    conn = get_db()
    real_policies = load_parsed_policies(conn)
    zero_trust_all = _load_items(conn, "zero_trust", real_policies)
    setup_all = _load_items(conn, "setup")

    reviewed = [dict(item, category="zero_trust", category_label="Zero-Trust Rule") for item in zero_trust_all if item["status"] != "pending"]
    reviewed += [dict(item, category="setup", category_label="Setup & Tuning") for item in setup_all if item["status"] != "pending"]
    reviewed.sort(key=lambda item: item["created_at"], reverse=True)

    return render_template(
        "recommendations.html",
        zero_trust_items=[item for item in zero_trust_all if item["status"] == "pending"],
        setup_items=[item for item in setup_all if item["status"] == "pending"],
        reviewed_items=reviewed,
    )


@recommendations_bp.route("/recommendations/<int:rec_id>/<action>", methods=["POST"])
def update_recommendation(rec_id: int, action: str):
    status_for_action = {"accept": "accepted", "dismiss": "dismissed", "reopen": "pending"}
    if action not in status_for_action:
        return jsonify({"error": "unknown action"}), 400

    status = status_for_action[action]
    conn = get_db()
    conn.execute("UPDATE recommendations SET status = ? WHERE id = ?", (status, rec_id))
    conn.commit()
    return jsonify({"status": status})


@recommendations_bp.route("/recommendations/<int:rec_id>/apply-preview")
def apply_preview(rec_id: int):
    """Read-only: builds and returns the exact payload Apply would send,
    without sending it. See STAGE3_APPLY_GOVERNANCE.md §3 step 3 — the UI
    must show this literal payload, not just the recommendation's prose,
    before a human can confirm anything."""
    config = current_app.config["ZTA_CONFIG"]
    gate_error = _apply_gate_error(config)
    if gate_error:
        return jsonify({"error": gate_error}), 403

    conn = get_db()
    rec, error = _load_applicable_recommendation(conn, rec_id)
    if error:
        return jsonify({"error": error}), 404 if error == "not_found" else 400

    try:
        payload, name = _build_payload(conn, rec)
    except ApplyNotPossible as exc:
        return jsonify({"error": str(exc)}), 422

    return jsonify({"name": name, "payload": payload})


@recommendations_bp.route("/recommendations/<int:rec_id>/apply", methods=["POST"])
def apply_recommendation(rec_id: int):
    """The one place in this add-on's web layer that can trigger a write
    to UniFi. Synchronous, not fire-and-poll like the LLM calls elsewhere
    — see governance §3 step 6: a write this consequential must not
    happen invisibly while the user is looking at something else. Always
    re-derives and re-validates the payload itself rather than trusting
    anything the client could have sent, and re-checks the live ruleset
    for a newly-created duplicate immediately before sending."""
    config = current_app.config["ZTA_CONFIG"]
    gate_error = _apply_gate_error(config)
    if gate_error:
        return jsonify({"error": gate_error}), 403

    conn = get_db()
    rec, error = _load_applicable_recommendation(conn, rec_id)
    if error:
        return jsonify({"error": error}), 404 if error == "not_found" else 400

    real_policies = load_parsed_policies(conn)
    parts = rec["pattern_signature"].split("|")
    port = None if len(parts) != 6 or parts[5] == "None" else int(parts[5])
    if find_covering_policy(real_policies, port) is not None:
        return jsonify({"error": "A matching rule already exists — refusing to create a duplicate."}), 409

    try:
        payload, _name = _build_payload(conn, rec)
    except ApplyNotPossible as exc:
        return jsonify({"error": str(exc)}), 422

    probe = sync.load_probe_report(conn)
    site_id = probe["site_id"] if probe else None
    if not site_id:
        return jsonify({"error": "No UniFi site is on record — run a Test Connection from Settings first."}), 400

    client = UnifiClientAPI(host=config.unifi_host, api_key=read_secret("unifi_api_key"), verify_tls=config.unifi_verify_tls)
    try:
        created = create_policy(client, site_id, payload)
    except (UnifiError, UnifiUnreachable) as exc:
        logger.warning("apply failed for recommendation %s: %s", rec_id, exc)
        return jsonify({"error": str(exc)}), 502

    policy_id = created.get("id")
    conn.execute(
        "UPDATE recommendations SET applied_at = ?, applied_policy_id = ? WHERE id = ?",
        (time.time(), policy_id, rec_id),
    )
    conn.commit()
    return jsonify({"status": "applied", "policy_id": policy_id})


@recommendations_bp.route("/recommendations/progress")
def progress():
    """Polled from the GUI while a run is in flight — see static/app.js.
    Each recommendation commits to the database the moment it's found (see
    engine.py), so the counts here climbing in real time is a genuine
    progress signal, not a fake spinner. Cheap COUNT queries, safe to poll
    every few seconds."""
    conn = get_db()
    zero_trust_count = conn.execute(
        "SELECT COUNT(*) FROM recommendations WHERE category = 'zero_trust'"
    ).fetchone()[0]
    setup_count = conn.execute("SELECT COUNT(*) FROM recommendations WHERE category = 'setup'").fetchone()[0]
    return jsonify({"running": is_running(), "zero_trust_count": zero_trust_count, "setup_count": setup_count})


@recommendations_bp.route("/recommendations/run-now", methods=["POST"])
def run_now():
    """Starts the pass in a background thread and returns immediately —
    reported live: waiting on the full pass here (potentially many
    minutes; each new pattern needs its own LLM call) got the request
    killed with a 504 by the proxy chain in front of this add-on before
    Flask ever finished responding. The GUI already polls
    /recommendations/progress for live counts (see static/app.js); that
    same poll now also detects completion via `running` flipping back to
    False, so nothing here needs to wait on the pass to answer.

    A fresh, separate database connection — not the request-scoped one
    from get_db() — since that one is closed when this request ends
    (see db_context.py), long before the background thread is done with
    it; same one-connection-per-thread rule as server.py's own
    background loop.
    """
    if is_running():
        return jsonify({"status": "already_running"}), 409

    config = current_app.config["ZTA_CONFIG"]

    def _run() -> None:
        conn = connect(config.db_path)
        try:
            run_analysis_now(conn, config)
        except Exception:
            logger.exception("background analysis pass failed")
        finally:
            conn.close()

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started"})
