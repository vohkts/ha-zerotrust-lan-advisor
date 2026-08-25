"""Read-only Supervisor API access shared by both the web layer and the
analysis engine — kept out of app/web so the analysis engine doesn't have
to depend on the web package for it. See app/web/supervisor.py for the
write side (persisting Settings-screen changes), which is web-specific.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

_SUPERVISOR_NETWORK_INFO_URL = "http://supervisor/network/info"
_SUPERVISOR_INFO_URL = "http://supervisor/info"


def get_host_ip() -> str | None:
    """The HAOS host's own LAN address — the setup screen needs it to tell
    the user what IP to point their router's syslog/NetFlow export at, and
    the analysis engine needs it to recognize (and filter out) the router
    logging its own log-forwarding traffic to this add-on's receiver ports.
    Neither is this container's internal docker-bridge IP; add-on ports are
    published on the host, not reachable at the container's own address.
    Best-effort: returns None if Supervisor can't be reached or no primary
    connected interface is found, and callers fall back to generic
    behavior rather than failing outright.
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


def get_timezone() -> str | None:
    """The IANA timezone name Home Assistant itself is configured with
    (e.g. "Europe/Berlin"), from the root Supervisor /info endpoint — only
    needs the same hassio_api grant get_host_ip() already relies on, no
    extra permission. Used so this add-on's own timestamps read in the
    same timezone as the rest of Home Assistant by default, instead of a
    fixed UTC nobody configured. Best-effort, same as get_host_ip(): None
    if Supervisor can't be reached, so callers fall back to UTC rather
    than failing outright.
    """
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    request = urllib.request.Request(
        _SUPERVISOR_INFO_URL,
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None
    return payload.get("data", {}).get("timezone")
