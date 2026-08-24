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
