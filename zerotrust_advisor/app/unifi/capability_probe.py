"""Answers "what can this API key actually do" by attempting a small,
fixed set of read-only calls and recording which succeeded — there is no
documented endpoint that reports a key's granted scopes directly, so this
probes for real instead of asking. Each capability is independent: a key
missing firewall-policy access (an older Network Application version, or a
key created before zone-based firewalling existed) can still be useful for
device/client visibility, and the UI should be able to say so precisely
rather than an all-or-nothing pass/fail.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.unifi.client import UnifiClientAPI, UnifiError, UnifiUnreachable


@dataclass(frozen=True)
class CapabilityResult:
    key: str
    label: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class ProbeReport:
    checked_at: float
    reachable: bool
    site_id: str | None
    capabilities: list[CapabilityResult] = field(default_factory=list)

    @property
    def any_capability_ok(self) -> bool:
        return any(c.ok for c in self.capabilities)


def probe(client: UnifiClientAPI) -> ProbeReport:
    now = time.time()

    try:
        info = client.get_info()
    except UnifiUnreachable as exc:
        return ProbeReport(checked_at=now, reachable=False, site_id=None, capabilities=[
            CapabilityResult("reach", "Reach the console", False, str(exc)),
        ])
    except UnifiError as exc:
        # Reached the console, but auth (or something else) failed —
        # distinct from "unreachable" so the UI can say "wrong key" rather
        # than "wrong IP".
        return ProbeReport(checked_at=now, reachable=True, site_id=None, capabilities=[
            CapabilityResult("auth", "Authenticate with this API key", False, _explain_auth_failure(exc)),
        ])

    version = info.get("applicationVersion", "unknown")
    capabilities = [CapabilityResult("reach", "Reach the console", True, f"Network Application {version}")]

    site_id = None
    try:
        sites = client.list_sites()
        site_id = sites[0].id if sites else None
        capabilities.append(
            CapabilityResult("sites", "List sites", True, f"{len(sites)} site(s)")
        )
    except (UnifiError, UnifiUnreachable) as exc:
        capabilities.append(CapabilityResult("sites", "List sites", False, str(exc)))

    if site_id is None:
        # Nothing below this point can be checked without a site to check
        # it against — report each as untested rather than guessing.
        for key, label in (
            ("devices", "Read devices"),
            ("clients", "Read connected clients"),
            ("networks", "Read networks/VLANs"),
            ("firewall_zones", "Read firewall zones"),
            ("firewall_policies", "Read firewall policies"),
        ):
            capabilities.append(CapabilityResult(key, label, False, "no site available to check against"))
        return ProbeReport(checked_at=now, reachable=True, site_id=None, capabilities=capabilities)

    for key, label, call in (
        ("devices", "Read devices", lambda: client.list_devices(site_id)),
        ("clients", "Read connected clients", lambda: client.list_clients(site_id)),
        ("networks", "Read networks/VLANs", lambda: client.list_networks(site_id)),
        ("firewall_zones", "Read firewall zones", lambda: client.list_firewall_zones(site_id)),
        ("firewall_policies", "Read firewall policies", lambda: client.list_firewall_policies(site_id)),
    ):
        try:
            items = call()
            capabilities.append(CapabilityResult(key, label, True, f"{len(items)} item(s)"))
        except (UnifiError, UnifiUnreachable) as exc:
            capabilities.append(CapabilityResult(key, label, False, str(exc)))

    return ProbeReport(checked_at=now, reachable=True, site_id=site_id, capabilities=capabilities)


def _explain_auth_failure(exc: UnifiError) -> str:
    """A 401/403 on the very first call (/info) has one dominant real-world
    cause, confirmed against a live console: the key was created inside the
    Network application's own settings instead of at the console (UniFi OS)
    level. Only the console-level key screen lets you grant it access to a
    specific application (Network) in the first place — a key made inside
    the Network application isn't the right kind of key for this API at
    all, and UniFi's own error here is just "401", with nothing pointing
    the user at that distinction. Appending the guidance directly to the
    detail text, not replacing it — the raw status is still worth showing.
    """
    detail = str(exc)
    if "401" in detail or "403" in detail:
        return (
            f"{detail}\nThis usually means the key was created in the wrong place: inside the "
            "Network application's own settings, rather than at the console level. Create the key "
            "from the console's own settings (UniFi OS → Control Plane → Integrations, not "
            "inside the Network application) — that's the only place you can grant it access to the "
            "Network application."
        )
    return detail
