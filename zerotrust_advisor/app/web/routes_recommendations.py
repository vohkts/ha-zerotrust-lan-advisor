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

from flask import Blueprint, current_app, jsonify, render_template

from app.analysis.rule_match import find_covering_policy, load_parsed_policies
from app.analysis.runner import is_running, run_analysis_now
from app.db import connect
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


def _load_items(conn, category: str, real_policies: list | None = None):
    rows = conn.execute(
        """SELECT id, created_at, status, pattern_summary_text, structured_json, confidence, pattern_signature
           FROM recommendations WHERE category = ? ORDER BY created_at DESC""",
        (category,),
    ).fetchall()
    items = []
    for row in rows:
        item = {
            "id": row[0],
            "created_at": row[1],
            "status": row[2],
            "summary": row[3],
            "structured": json.loads(row[4]),
            "confidence": row[5],
            "implemented": None,
            "matched_policy_id": None,
            "matched_policy_name": None,
        }
        # Only worth checking for recommendations the user has actually
        # accepted -- a pending or dismissed one being "implemented" or
        # not isn't a meaningful question yet.
        if real_policies is not None and item["status"] == "accepted":
            item["implemented"], item["matched_policy_id"], item["matched_policy_name"] = _implemented_status(
                row[6], real_policies
            )
        items.append(item)
    return items


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
