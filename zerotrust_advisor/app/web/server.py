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
from app.config import load_config
from app.db import connect
from app.web.routes_recommendations import recommendations_bp
from app.web.routes_settings import settings_bp
from app.web.routes_setup import setup_bp

logger = logging.getLogger(__name__)

_ANALYSIS_INTERVAL_SECONDS = 3600
_LISTEN_PORT = 8099


def _format_timestamp(ts: float | None) -> str:
    if not ts:
        return "never"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def create_app() -> Flask:
    app = Flask(__name__)
    config = load_config()
    app.config["ZTA_CONFIG"] = config
    app.config["ZTA_DB"] = connect(config.db_path)

    app.register_blueprint(setup_bp)
    app.register_blueprint(recommendations_bp)
    app.register_blueprint(settings_bp)

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


def _background_loop(app: Flask) -> None:
    while True:
        time.sleep(_ANALYSIS_INTERVAL_SECONDS)
        try:
            run_analysis_now(app.config["ZTA_DB"], app.config["ZTA_CONFIG"])
        except Exception:
            logger.exception("scheduled analysis pass failed")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    threading.Thread(target=_background_loop, args=(app,), daemon=True).start()
    serve(app, listen=f"127.0.0.1:{_LISTEN_PORT}")


if __name__ == "__main__":
    main()
