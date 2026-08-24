"""Serializes analysis passes so the background hourly timer and a manual
"run now" click from the GUI can never run at the same time."""
from __future__ import annotations

import logging
import threading

from app.analysis.engine import AnalysisPassResult, run_analysis_pass
from app.unifi import sync as unifi_sync

logger = logging.getLogger(__name__)

_lock = threading.Lock()


def run_analysis_now(conn, config) -> AnalysisPassResult | None:
    """Returns None if a pass was already in progress."""
    if not _lock.acquire(blocking=False):
        return None
    try:
        # A handful of cheap read-only GETs against the console, if UniFi is
        # configured (see app/unifi/sync.py) — a no-op otherwise. Kept in its
        # own try/except so a UniFi hiccup (console rebooting, a bad key)
        # never blocks the LLM analysis pass, which doesn't depend on it.
        try:
            unifi_sync.refresh(conn, config)
        except Exception:
            logger.exception("UniFi refresh failed")
        return run_analysis_pass(conn, config)
    finally:
        _lock.release()
