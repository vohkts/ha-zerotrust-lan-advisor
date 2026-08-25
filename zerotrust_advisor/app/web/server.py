"""Flask app factory + waitress entrypoint for the Ingress-embedded GUI.
Also drives the background analysis loop — the web process is the only one
running continuously that isn't a raw-socket receiver, so it owns this.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Flask, current_app, redirect
from waitress import serve

from app.analysis.runner import run_analysis_now
from app.config import Config, load_config
from app.db import connect
from app.supervisor import get_timezone
from app.web.db_context import close_db, get_db
from app.web.routes_live import live_bp
from app.web.routes_network import network_bp, unifi_available
from app.web.routes_recommendations import recommendations_bp
from app.web.routes_setup import setup_bp
from app.web.routes_traffic import traffic_bp

logger = logging.getLogger(__name__)

_ANALYSIS_INTERVAL_SECONDS = 3600
_LISTEN_PORT = 8099

# Home Assistant's configured timezone barely ever changes mid-run, and
# fetching it is a Supervisor API call — looked up once per process and
# cached, not once per timestamp rendered.
_cached_tz_name: str | None = None
_tz_lookup_attempted = False


def _resolve_tz_name() -> str | None:
    global _cached_tz_name, _tz_lookup_attempted
    if not _tz_lookup_attempted:
        _tz_lookup_attempted = True
        _cached_tz_name = get_timezone()
    return _cached_tz_name


def format_timestamp(ts: float | None, display_timezone_utc: bool, tz_name: str | None) -> str:
    """Defaults to Home Assistant's own configured timezone rather than a
    fixed UTC nobody actually asked for; `display_timezone_utc` (a Settings
    toggle) or a missing/invalid `tz_name` both fall back to plain UTC."""
    if not ts:
        return "never"
    if not display_timezone_utc and tz_name:
        try:
            return datetime.fromtimestamp(ts, tz=ZoneInfo(tz_name)).strftime("%Y-%m-%d %H:%M %Z")
        except (ZoneInfoNotFoundError, ValueError):
            pass
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _format_timestamp(ts: float | None) -> str:
    config = current_app.config["ZTA_CONFIG"]
    return format_timestamp(ts, config.display_timezone_utc, _resolve_tz_name())


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["ZTA_CONFIG"] = load_config()

    app.register_blueprint(setup_bp)
    app.register_blueprint(traffic_bp)
    app.register_blueprint(recommendations_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(live_bp)

    app.teardown_appcontext(close_db)
    app.jinja_env.filters["fmt_time"] = _format_timestamp

    @app.context_processor
    def inject_nav_flags():
        # Drives whether base.html shows the "Network" nav link at all — the
        # rest of the UI stays exactly as it is today unless UniFi is both
        # enabled and demonstrably working (see routes_network.py).
        config = current_app.config["ZTA_CONFIG"]
        return {"show_network_nav": unifi_available(config, get_db())}

    @app.route("/")
    def index():
        # A relative redirect, not url_for(...) — Ingress serves this app
        # under a per-install path prefix it never tells the app about, so
        # any absolute, leading-slash path would point the browser at the
        # wrong place. See templates/base.html for the same rule applied
        # to every link this app renders. Live View is the landing page
        # (loads with monitoring off — see live.html — so this has no
        # extra cost over any other page until the user clicks Start).
        return redirect("live")

    return app


def _background_loop(config: Config) -> None:
    # One connection for this thread's whole life, separate from any
    # request's — sqlite3 connections must stay on the thread that made them.
    conn = connect(config.db_path)
    while True:
        time.sleep(_ANALYSIS_INTERVAL_SECONDS)
        try:
            run_analysis_now(conn, config)
        except Exception:
            logger.exception("scheduled analysis pass failed")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    threading.Thread(target=_background_loop, args=(app.config["ZTA_CONFIG"],), daemon=True).start()
    # Ingress reaches this container over Supervisor's internal docker
    # network, not localhost — binding to loopback here (unlike
    # llama-server, which genuinely should stay loopback-only) would make
    # the GUI unreachable from outside the container.
    serve(app, listen=f"0.0.0.0:{_LISTEN_PORT}")


if __name__ == "__main__":
    main()
