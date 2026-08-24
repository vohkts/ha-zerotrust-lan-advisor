"""Recommendations review screen. Accept/dismiss is purely local
bookkeeping — Stage 1 has no code path that ever writes to the router.

Mutating actions respond with a small JSON body rather than a redirect and
are called from the page via fetch() (see static/app.js); the browser's
address bar never leaves /recommendations, which sidesteps having to
compute correct relative-URL depth for an Ingress-prefixed redirect.
"""
from __future__ import annotations

import json

from flask import Blueprint, current_app, jsonify, render_template

from app.analysis.runner import run_analysis_now

recommendations_bp = Blueprint("recommendations", __name__)


def _load_items(conn):
    rows = conn.execute(
        """SELECT id, created_at, status, pattern_summary_text, structured_json, confidence
           FROM recommendations ORDER BY created_at DESC"""
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
    conn = current_app.config["ZTA_DB"]
    return render_template("recommendations.html", items=_load_items(conn))


@recommendations_bp.route("/recommendations/<int:rec_id>/<action>", methods=["POST"])
def update_recommendation(rec_id: int, action: str):
    if action not in ("accept", "dismiss"):
        return jsonify({"error": "unknown action"}), 400

    status = "accepted" if action == "accept" else "dismissed"
    conn = current_app.config["ZTA_DB"]
    conn.execute("UPDATE recommendations SET status = ? WHERE id = ?", (status, rec_id))
    conn.commit()
    return jsonify({"status": status})


@recommendations_bp.route("/recommendations/run-now", methods=["POST"])
def run_now():
    conn = current_app.config["ZTA_DB"]
    config = current_app.config["ZTA_CONFIG"]
    written = run_analysis_now(conn, config)
    if written < 0:
        return jsonify({"status": "already_running"}), 409
    return jsonify({"status": "ok", "new_recommendations": written})
