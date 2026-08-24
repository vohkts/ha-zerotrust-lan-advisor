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
            CapabilityResult("auth", "Authenticate with this API key", False, str(exc)),
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
            ("firewall_zones", "Read firewall zones"),
            ("firewall_policies", "Read firewall policies"),
        ):
            capabilities.append(CapabilityResult(key, label, False, "no site available to check against"))
        return ProbeReport(checked_at=now, reachable=True, site_id=None, capabilities=capabilities)

    for key, label, call in (
        ("devices", "Read devices", lambda: client.list_devices(site_id)),
        ("clients", "Read connected clients", lambda: client.list_clients(site_id)),
        ("firewall_zones", "Read firewall zones", lambda: client.list_firewall_zones(site_id)),
        ("firewall_policies", "Read firewall policies", lambda: client.list_firewall_policies(site_id)),
    ):
        try:
            items = call()
            capabilities.append(CapabilityResult(key, label, True, f"{len(items)} item(s)"))
        except (UnifiError, UnifiUnreachable) as exc:
            capabilities.append(CapabilityResult(key, label, False, str(exc)))

    return ProbeReport(checked_at=now, reachable=True, site_id=site_id, capabilities=capabilities)
