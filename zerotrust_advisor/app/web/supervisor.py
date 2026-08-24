"""Persists add-on option changes through the Supervisor API, so a change
made from this add-on's own Settings screen shows up identically in Home
Assistant's normal Settings -> Add-ons -> Configuration tab too, instead of
forking into a second, hidden source of truth.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

_SUPERVISOR_OPTIONS_URL = "http://supervisor/addons/self/options"
_SUPERVISOR_NETWORK_INFO_URL = "http://supervisor/network/info"


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


def get_host_ip() -> str | None:
    """The setup screen needs to tell the user what IP to point their
    router's syslog/NetFlow export at — that's the HAOS host's own LAN
    address, not this container's internal docker-bridge IP (add-on ports
    are published on the host, not reachable at the container's own
    address). Best-effort: returns None if Supervisor can't be reached or
    no primary connected interface is found, and the setup screen falls
    back to generic wording rather than failing the page.
    """
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    request = urllib.request.Request(
        _SUPERVISOR_NETWORK_INFO_URL,
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None

    for interface in payload.get("data", {}).get("interfaces", []):
        if not (interface.get("primary") and interface.get("connected")):
            continue
        addresses = (interface.get("ipv4") or {}).get("address") or []
        if addresses:
            return addresses[0].split("/")[0]
    return None
