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

from flask import Blueprint, current_app, jsonify, render_template

from app.analysis.runner import run_analysis_now
from app.web.db_context import get_db

recommendations_bp = Blueprint("recommendations", __name__)


def _load_items(conn, category: str):
    rows = conn.execute(
        """SELECT id, created_at, status, pattern_summary_text, structured_json, confidence
           FROM recommendations WHERE category = ? ORDER BY created_at DESC""",
        (category,),
    ).fetchall()
    return [
        {
            "id": row[0],
            "created_at": row[1],
            "status": row[2],
            "summary": row[3],
            "structured": json.loads(row[4]),
            "confidence": row[5],
        }
        for row in rows
    ]


@recommendations_bp.route("/recommendations")
def list_recommendations():
    # Both categories render on this one page with a client-side tab
    # toggle (see static/app.js) rather than a second route at a different
    # URL depth — every other link in this app is deliberately kept flat
    # (one segment) so relative URLs resolve correctly under whatever path
    # prefix Ingress assigns; see base.html.
    conn = get_db()
    return render_template(
        "recommendations.html",
        zero_trust_items=_load_items(conn, "zero_trust"),
        setup_items=_load_items(conn, "setup"),
    )


@recommendations_bp.route("/recommendations/<int:rec_id>/<action>", methods=["POST"])
def update_recommendation(rec_id: int, action: str):
    if action not in ("accept", "dismiss"):
        return jsonify({"error": "unknown action"}), 400

    status = "accepted" if action == "accept" else "dismissed"
    conn = get_db()
    conn.execute("UPDATE recommendations SET status = ? WHERE id = ?", (status, rec_id))
    conn.commit()
    return jsonify({"status": status})


@recommendations_bp.route("/recommendations/run-now", methods=["POST"])
def run_now():
    conn = get_db()
    config = current_app.config["ZTA_CONFIG"]
    result = run_analysis_now(conn, config)
    if result is None:
        return jsonify({"status": "already_running"}), 409
    return jsonify(
        {
            "status": "ok",
            "new_recommendations": result.zero_trust_written,
            "new_setup_findings": result.setup_written,
        }
    )
