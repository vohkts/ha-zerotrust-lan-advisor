"""Flask app factory + waitress entrypoint for the Ingress-embedded GUI.
Also drives the background analysis loop — the web process is the only one
running continuously that isn't a raw-socket receiver, so it owns this.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

from flask import Flask, redirect
from waitress import serve

from app.analysis.runner import run_analysis_now
from app.config import Config, load_config
from app.db import connect
from app.web.db_context import close_db
from app.web.routes_recommendations import recommendations_bp
from app.web.routes_settings import settings_bp
from app.web.routes_setup import setup_bp
from app.web.routes_traffic import traffic_bp

logger = logging.getLogger(__name__)

_ANALYSIS_INTERVAL_SECONDS = 3600
_LISTEN_PORT = 8099


def _format_timestamp(ts: float | None) -> str:
    if not ts:
        return "never"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["ZTA_CONFIG"] = load_config()

    app.register_blueprint(setup_bp)
    app.register_blueprint(traffic_bp)
    app.register_blueprint(recommendations_bp)
    app.register_blueprint(settings_bp)

    app.teardown_appcontext(close_db)
    app.jinja_env.filters["fmt_time"] = _format_timestamp

    @app.route("/")
    def index():
        # A relative redirect, not url_for("setup.setup_page") — Ingress
        # serves this app under a per-install path prefix it never tells
        # the app about, so any absolute, leading-slash path would point
        # the browser at the wrong place. See templates/base.html for the
        # same rule applied to every link this app renders.
        return redirect("setup")

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
