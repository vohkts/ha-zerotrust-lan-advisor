"""Persists add-on option changes through the Supervisor API, so a change
made from this add-on's own Settings screen shows up identically in Home
Assistant's normal Settings -> Add-ons -> Configuration tab too, instead of
forking into a second, hidden source of truth. See app/supervisor.py for
the read-only side shared with the analysis engine.
"""
from __future__ import annotations

import json
import os
import urllib.request

_SUPERVISOR_OPTIONS_URL = "http://supervisor/addons/self/options"
_SUPERVISOR_RESTART_URL = "http://supervisor/addons/self/restart"


def update_options(options: dict) -> None:
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    body = json.dumps({"options": options}).encode()
    request = urllib.request.Request(
        _SUPERVISOR_OPTIONS_URL,
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    urllib.request.urlopen(request, timeout=10).read()


def restart_self() -> None:
    """Saved options only take effect for the *next* start — Supervisor
    writes them to this add-on's own options.json but never hot-reloads
    the already-running process. Confirmed live: saving a setting and
    reloading the page still showed the old value until a manual restart.
    Since "no manual steps" is this add-on's whole design goal, the
    Settings save now triggers this itself instead of asking the user to
    go do it — Supervisor gives the current request a grace period to
    finish before the container actually stops, so the "Saved" response
    still reaches the browser first."""
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    request = urllib.request.Request(
        _SUPERVISOR_RESTART_URL,
        data=b"",
        method="POST",
        headers={"Authorization": f"Bearer {token}"},
    )
    urllib.request.urlopen(request, timeout=10).read()
