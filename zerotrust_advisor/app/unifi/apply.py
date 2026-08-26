"""Stage 3: the only module in this codebase that ever writes to UniFi.
See ../../STAGE3_APPLY_GOVERNANCE.md for the full contract this
implements -- create-only, one policy per call, always previewed and
explicitly confirmed by a human first. Nothing here runs unattended;
nothing here is reachable in the UI unless all three gates in governance
§5 are satisfied (checked by the caller, see routes_recommendations.py).

Payload shape confirmed against UniFi's own OpenAPI spec for
`POST /v1/sites/{siteId}/firewall/policies` (the "Create or update
firewall policy" schema) -- not guessed, unlike some earlier assumptions
in this project that turned out wrong against real consoles. Every side
(source and destination) needs a real UniFi zoneId, which only exists for
a network this add-on has actually confirmed via the UniFi API -- see
_confirmed_network_name() below, which deliberately reuses the exact same
two confirmation paths already proven live elsewhere in this add-on
(network_map.py's subnet match and br<vlanId> interface match) and
nothing weaker. A pattern whose source or destination can't be confirmed
this way has nothing solid to build a real payload from, and Apply is
refused for it (ApplyNotPossible) rather than guessing a scope that might
be wrong on a real firewall.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from app.analysis.network_map import (
    NetworkMap,
    UnifiNetworkInfo,
    unifi_network_for_interface,
    unifi_network_for_ip,
)
from app.unifi.client import UnifiClientAPI


class ApplyNotPossible(Exception):
    """A recommendation can't be turned into a confidently-scoped UniFi
    payload right now. Always caught and shown as this message directly,
    never wrapped into a generic error -- the reason is the point."""


# TEMPORARY, deliberate safety measure for validating the real write path
# against a real console: every created policy starts disabled, so it has
# zero effect on real traffic no matter what it's scoped to, while the
# user tries applying a handful of recommendations for real and confirms
# they land correctly. Flip to True once that's been confirmed working --
# nothing else about the flow changes either way; this only controls the
# one field. See STAGE3_APPLY_GOVERNANCE.md's "Current testing mode" note.
CREATE_RULES_ENABLED = False


@dataclass(frozen=True)
class PreparedPolicy:
    """Everything needed to show an honest preview and, if confirmed, to
    send exactly this and nothing else."""
    payload: dict
    site_id: str


def _confirmed_network_name(
    ip: str, network_map: NetworkMap, unifi_networks: list[UnifiNetworkInfo], vlan_names: dict[int, str]
) -> str | None:
    """The same two ways a real UniFi network name gets confirmed
    everywhere else in this add-on (see network_map.resolve_label) --
    minus the guessed-range fallback, since a guess isn't a real UniFi
    entity to scope a firewall write against."""
    name = unifi_network_for_ip(ip, unifi_networks)
    if name:
        return name
    key = network_map.ip_to_key.get(ip)
    if key and vlan_names:
        return unifi_network_for_interface(key, vlan_names)
    return None


def _network_and_zone(conn: sqlite3.Connection, name: str) -> tuple[str, str] | None:
    """(network_id, zone_id) for a real, already-synced UniFi network by
    name. zoneId only ever lives inside raw_json -- nothing before this
    needed its own column for it."""
    row = conn.execute("SELECT id, raw_json FROM unifi_networks WHERE name = ?", (name,)).fetchone()
    if row is None:
        return None
    try:
        zone_id = json.loads(row[1]).get("zoneId")
    except (TypeError, json.JSONDecodeError):
        return None
    return (row[0], zone_id) if zone_id else None


def _resolve_side(
    conn: sqlite3.Connection,
    ips: list[str],
    network_map: NetworkMap,
    unifi_networks: list[UnifiNetworkInfo],
    vlan_names: dict[int, str],
    port: int | None,
    *,
    is_source: bool,
) -> tuple[str, dict]:
    """Returns (zone_id, traffic_filter). Every real IP behind this side
    of the pattern must confirm to the *same* real UniFi network -- if
    they don't agree, or none confirm at all, this refuses rather than
    picking one arbitrarily. Exactly one distinct IP scopes to that
    device specifically (an IP_ADDRESS filter); more than one scopes to
    the whole confirmed network (a NETWORK filter) -- same "one device or
    a population" distinction already used to phrase LLM prompts."""
    if not ips:
        raise ApplyNotPossible("No real device IPs could be recovered from this recommendation's evidence anymore.")

    names = {_confirmed_network_name(ip, network_map, unifi_networks, vlan_names) for ip in ips}
    names.discard(None)
    if len(names) != 1:
        raise ApplyNotPossible(
            "This side of the recommendation isn't confirmed against a real UniFi network "
            "(either nothing matched, or the evidence spans more than one network) -- refusing "
            "to guess which one to scope the rule to."
        )
    network_name = names.pop()
    resolved = _network_and_zone(conn, network_name)
    if resolved is None:
        raise ApplyNotPossible(f"UniFi network \"{network_name}\" has no zone on record -- can't build a real rule for it.")
    network_id, zone_id = resolved

    port_filter = None
    if port is not None:
        port_filter = {"type": "PORTS", "matchOpposite": False, "items": [{"type": "PORT_NUMBER", "value": port}]}

    if len(ips) == 1:
        traffic_filter = {
            "type": "IP_ADDRESS",
            "ipAddressFilter": {
                "type": "IP_ADDRESSES",
                "matchOpposite": False,
                "items": [{"type": "IP_ADDRESS", "value": ips[0]}],
            },
        }
    else:
        traffic_filter = {
            "type": "NETWORK",
            "networkFilter": {"matchOpposite": False, "networkIds": [network_id]},
        }
    if port_filter is not None and not is_source:
        # The API only documents portFilter on the destination side of a
        # policy (matches how every real captured example looked) --
        # source-side port scoping isn't attempted here.
        traffic_filter["portFilter"] = port_filter

    return zone_id, traffic_filter


def build_policy_payload(
    conn: sqlite3.Connection,
    *,
    name: str,
    action: str,
    proto: int,
    port: int | None,
    src_ips: list[str],
    dst_ips: list[str],
    network_map: NetworkMap,
    unifi_networks: list[UnifiNetworkInfo],
    vlan_names: dict[int, str],
) -> dict:
    """The exact request body for POST .../firewall/policies. Raises
    ApplyNotPossible (never returns a partial/best-guess payload) when
    either side can't be confidently resolved against the real UniFi
    ruleset -- see _resolve_side."""
    if action not in ("allow", "block"):
        raise ApplyNotPossible(f"Unsupported action \"{action}\" -- only allow/block recommendations can be applied.")

    src_zone, src_filter = _resolve_side(conn, src_ips, network_map, unifi_networks, vlan_names, port, is_source=True)
    dst_zone, dst_filter = _resolve_side(conn, dst_ips, network_map, unifi_networks, vlan_names, port, is_source=False)

    action_payload = {"type": "ALLOW", "allowReturnTraffic": True} if action == "allow" else {"type": "BLOCK"}

    return {
        "name": name,
        "enabled": CREATE_RULES_ENABLED,
        "loggingEnabled": True,
        "action": action_payload,
        "ipProtocolScope": {
            "ipVersion": "IPV4_AND_IPV6",
            "protocolFilter": {"type": "PROTOCOL_NUMBER", "matchOpposite": False, "protocolNumber": proto},
        },
        "source": {"zoneId": src_zone, "trafficFilter": src_filter},
        "destination": {"zoneId": dst_zone, "trafficFilter": dst_filter},
    }


def create_policy(client: UnifiClientAPI, site_id: str, payload: dict) -> dict:
    """The one write call in this codebase. Returns UniFi's own response
    (the full created policy object, including its real id) on success;
    raises whatever UnifiClientAPI already raises for a failed request
    (see client.py) on failure -- callers surface that verbatim rather
    than translating it into a generic message, per governance §3 step 6."""
    return client.create_firewall_policy(site_id, payload)
