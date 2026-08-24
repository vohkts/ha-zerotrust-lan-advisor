"""Serializes analysis passes so the background hourly timer and a manual
"run now" click from the GUI can never run at the same time."""
from __future__ import annotations

import threading

from app.analysis.engine import run_analysis_pass

_lock = threading.Lock()


def run_analysis_now(conn, config) -> int:
    """Returns the number of new recommendations written, or -1 if a pass
    was already in progress."""
    if not _lock.acquire(blocking=False):
        return -1
    try:
        return run_analysis_pass(conn, config)
    finally:
        _lock.release()
