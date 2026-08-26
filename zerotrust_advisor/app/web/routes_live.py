"""Live View: a real-time (polled, not streaming) view of firewall events
as they arrive — source, destination, port, and the allow/block verdict.
Deliberately events_firewall only, not events_flow: flow records carry no
allow/block verdict at all (NetFlow doesn't have the concept), so a "status
in red/green" table only makes sense for the logged firewall side.

Polling, not Server-Sent Events or a WebSocket: this is a small, local,
single-page-at-a-time tool, and waitress's synchronous worker model makes
a long-held streaming connection more complexity than the payoff is worth
here. A ~1.5s poll interval on a single cheap indexed query is plenty
responsive for a home network and keeps the whole feature stdlib-simple.
"""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

from app.analysis.known_ports import PROTO_NAMES, describe_port
from app.analysis.noise import is_own_receiver_traffic
from app.supervisor import get_host_ip
from app.web.db_context import get_db

live_bp = Blueprint("live", __name__)

_MAX_EVENTS_PER_POLL = 200


@live_bp.route("/live")
def live_page():
    return render_template("live.html")


@live_bp.route("/live/events")
def live_events():
    """`since_id` omitted or 0: a bootstrap call — establishes the current
    high-water mark without returning any backlog, so clicking Start
    shows events from that moment on, not a replay of history. Given a
    real `since_id`, returns events newer than it, oldest-first, capped
    per poll so a burst can't hand back an enormous payload in one go —
    the next poll picks up whatever didn't fit."""
    conn = get_db()
    since_id = request.args.get("since_id", type=int) or 0

    if since_id == 0:
        max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events_firewall").fetchone()[0]
        return jsonify({"events": [], "max_id": max_id})

    config = current_app.config["ZTA_CONFIG"]
    host_ip = get_host_ip()
    console_host = config.unifi_host if config.ignore_unifi_console_traffic else None

    rows = conn.execute(
        """SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, action
           FROM events_firewall WHERE id > ? ORDER BY id ASC LIMIT ?""",
        (since_id, _MAX_EVENTS_PER_POLL),
    ).fetchall()

    # The cursor must advance by the *raw* rows fetched, not the filtered
    # ones -- otherwise a poll window that's entirely noise (e.g. a burst
    # of syslog-forwarding to this add-on's own receiver port) never moves
    # since_id forward and the same noisy rows get re-fetched every poll.
    max_id = rows[-1][0] if rows else since_id

    events = []
    for r in rows:
        _id, ts, src_ip, dst_ip, src_port, dst_port, proto, action = r
        if is_own_receiver_traffic(dst_ip, dst_port, host_ip, config.syslog_port, config.netflow_port):
            continue
        if console_host and (src_ip == console_host or dst_ip == console_host):
            continue
        events.append(
            {
                "id": _id,
                "ts": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "proto": PROTO_NAMES.get(proto, str(proto)),
                "port_hint": describe_port(proto, dst_port),
                "action": action,
                "blocked": (action or "").upper() != "ALLOW",
            }
        )
    return jsonify({"events": events, "max_id": max_id})
