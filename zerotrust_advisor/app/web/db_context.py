"""Per-request SQLite connections.

sqlite3 connections can't be shared across threads, and waitress serves
requests from a thread pool — so each request gets its own connection via
Flask's application-context `g`, opened on first use and closed
automatically when the request ends. The background analysis thread (see
server.py) keeps its own separate, long-lived connection for the same
reason: one connection object, one thread, for its whole life.
"""
from __future__ import annotations

from flask import current_app, g

from app.db import connect


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["ZTA_CONFIG"].db_path)
    return g.db


def close_db(exception: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()
