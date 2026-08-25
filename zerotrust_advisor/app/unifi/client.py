"""A read-only client for the official UniFi Network Integration API
(API-key auth — Settings -> Control Plane -> Integrations on the console
itself, or via unifi.ui.com -> API Keys). UDM-class consoles only, by
design: `X-API-Key` auth over `/proxy/network/integration/v1/...` is a
UniFi-OS-console feature, not something a standalone software controller
or another vendor's gear exposes.

Deliberately does not touch the older "Classic" cookie-session API (local
admin username/password, CSRF tokens, `/proxy/network/api/...`) even
though it exposes more — trading completeness for staying inside Home
Assistant's read-only, credential-light integration model documented for
the official API. Nothing in this module issues a non-GET request; there
is no write path here at all, matching Stage 1/2's read-only scope.

Field-shape note: `X-API-Key` auth and the endpoints below (`/info`,
`/sites`, `/devices`, `/clients`, `/firewall/zones`, `/firewall/policies`)
are confirmed against Ubiquiti's own developer documentation and reference
material. Exact field names inside a firewall policy object — especially
anything logging-related — were not fully confirmed from docs alone (no
live console was available to verify against while building this), so
`FirewallPolicy` keeps the full raw response alongside the fields this
code is confident about, and `logging_enabled` tries several plausible
field names rather than assuming one. Verify against a real console and
adjust `_LOGGING_FIELD_CANDIDATES` if none of them match.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

DEFAULT_TIMEOUT = 10.0

_LOGGING_FIELD_CANDIDATES = ("loggingEnabled", "logging_enabled", "logging", "logEnabled")


class UnifiError(RuntimeError):
    """A request reached the console but failed (auth, not-found, etc.)."""


class UnifiUnreachable(RuntimeError):
    """The console couldn't be reached at all (network, TLS, timeout)."""


@dataclass(frozen=True)
class UnifiSite:
    id: str
    name: str
    raw: dict = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class UnifiDevice:
    id: str
    name: str
    model: str | None
    mac: str | None
    ip: str | None
    state: str | None
    raw: dict = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class UnifiClient:
    id: str
    name: str | None
    mac: str | None
    ip: str | None
    network_id: str | None
    raw: dict = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class FirewallZone:
    id: str
    name: str
    raw: dict = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class FirewallPolicy:
    id: str
    name: str
    enabled: bool
    action: str | None
    protocol: str | None
    source_zone_id: str | None
    destination_zone_id: str | None
    logging_enabled: bool | None  # None: couldn't tell from any known field name
    raw: dict = field(default_factory=dict, repr=False)


class UnifiClientAPI:
    """One connection to one console. Every method is a plain GET; nothing
    here ever mutates the console's configuration."""

    def __init__(self, host: str, api_key: str, verify_tls: bool = False, timeout: float = DEFAULT_TIMEOUT):
        self._base_url = f"https://{host}/proxy/network/integration/v1"
        self._api_key = api_key
        self._timeout = timeout
        # UDM consoles typically present a self-signed cert on the LAN;
        # verifying against a real CA isn't meaningful for a local-only
        # connection, so this defaults to off — same trust model as
        # visiting https://<udm-ip> in a browser and clicking through the
        # warning. Left as an option, not hidden, since it's a real
        # trade-off worth the user being able to see and reason about.
        self._ssl_context = ssl.create_default_context()
        if not verify_tls:
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

    def _get(self, path: str, params: dict[str, str] | None = None) -> dict:
        url = f"{self._base_url}{path}"
        if params:
            query = "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in params.items())
            url = f"{url}?{query}"
        request = urllib.request.Request(
            url, headers={"X-API-Key": self._api_key, "Accept": "application/json"}, method="GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout, context=self._ssl_context) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            raise UnifiError(f"{exc.code} {exc.reason} for {path}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise UnifiUnreachable(f"could not reach {self._base_url}: {exc}") from exc
        except UnicodeEncodeError as exc:
            # HTTP header values are latin-1 only. A real UniFi API key is
            # plain ASCII; hitting this means the pasted value picked up a
            # stray character from wherever it was copied (a smart-quote,
            # an em dash from surrounding label text, etc.) — surfaced here
            # as a bare "'latin-1' codec can't encode..." otherwise, which
            # tells the user nothing about what to actually do about it.
            raise UnifiError(
                "the API key contains a character that isn't valid in an HTTP header (only plain ASCII "
                "is allowed) — check you copied only the key itself, with nothing extra around it"
            ) from exc

        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise UnifiError(f"non-JSON response from {path}") from exc

    @staticmethod
    def _items(payload: dict) -> list[dict]:
        """The v1 Integration API wraps collections in a pagination
        envelope (`data`); tolerate a bare list too rather than assume."""
        if isinstance(payload, list):
            return payload
        return payload.get("data", [])

    def get_info(self) -> dict:
        """Console/application version info — the cheapest possible
        reachability + auth check, used first by the capability probe."""
        return self._get("/info")

    def list_sites(self) -> list[UnifiSite]:
        return [
            UnifiSite(id=item.get("id", ""), name=item.get("name", item.get("id", "")), raw=item)
            for item in self._items(self._get("/sites"))
        ]

    def list_devices(self, site_id: str) -> list[UnifiDevice]:
        items = self._items(self._get(f"/sites/{site_id}/devices"))
        devices = []
        for item in items:
            devices.append(
                UnifiDevice(
                    id=item.get("id", ""),
                    name=item.get("name", ""),
                    model=item.get("model"),
                    mac=item.get("macAddress") or item.get("mac"),
                    ip=item.get("ipAddress") or item.get("ip"),
                    state=item.get("state"),
                    raw=item,
                )
            )
        return devices

    def list_clients(self, site_id: str) -> list[UnifiClient]:
        items = self._items(self._get(f"/sites/{site_id}/clients"))
        clients = []
        for item in items:
            clients.append(
                UnifiClient(
                    id=item.get("id", ""),
                    name=item.get("name") or item.get("hostname"),
                    mac=item.get("macAddress") or item.get("mac"),
                    ip=item.get("ipAddress") or item.get("ip"),
                    network_id=item.get("networkId") or item.get("uplinkDeviceId"),
                    raw=item,
                )
            )
        return clients

    def list_firewall_zones(self, site_id: str) -> list[FirewallZone]:
        items = self._items(self._get(f"/sites/{site_id}/firewall/zones"))
        return [FirewallZone(id=item.get("id", ""), name=item.get("name", ""), raw=item) for item in items]

    def list_firewall_policies(self, site_id: str) -> list[FirewallPolicy]:
        items = self._items(self._get(f"/sites/{site_id}/firewall/policies"))
        policies = []
        for item in items:
            policies.append(
                FirewallPolicy(
                    id=item.get("id", ""),
                    name=item.get("name", ""),
                    enabled=bool(item.get("enabled", True)),
                    action=item.get("action"),
                    protocol=item.get("protocol"),
                    source_zone_id=_zone_id(item.get("source")),
                    destination_zone_id=_zone_id(item.get("destination")),
                    logging_enabled=_first_present(item, _LOGGING_FIELD_CANDIDATES),
                    raw=item,
                )
            )
        return policies


def _zone_id(zone_ref: Any) -> str | None:
    """A source/destination reference inside a firewall policy is
    documented inconsistently across UniFi API versions — sometimes a
    plain zone ID string, sometimes an object with the ID nested inside.
    Handle both rather than assume."""
    if zone_ref is None:
        return None
    if isinstance(zone_ref, str):
        return zone_ref
    if isinstance(zone_ref, dict):
        return zone_ref.get("zoneId") or zone_ref.get("id")
    return None


def _first_present(item: dict, field_names: tuple[str, ...]) -> bool | None:
    for name in field_names:
        if name in item:
            return bool(item[name])
    return None
