"""Builds a picture of the local network purely from observed traffic — no
manual subnet/VLAN configuration required, matching Stage 1's "just watch
and learn" scope (Stage 2's read-only router API is a different, later
thing).

The strongest signal is one already being stored and, until now, never
used for this: real UniFi/EdgeOS firewall logs carry `IN=`/`OUT=` — the
bridge/VLAN interface a packet arrived on or is leaving through. A source
IP's `IN=` interface (and a destination IP's `OUT=` interface) is a direct,
repeated, first-party observation of which local segment that device
actually lives on — far more reliable than guessing from the IP alone.

IPs never seen with interface info (flow-only data, since NetFlow doesn't
carry this, or firewall lines without it) fall back to a /24-prefix
grouping — a weaker, IP-only heuristic, kept clearly distinguished
(`kind="prefix"` vs `"interface"`) so callers and the UI can be honest
about which is which.

Optional manual `network_labels` (Settings) and per-network friendly names
(the `network_names` table, set from the Traffic screen) are both pure
display overrides on top of this — discovery and recommendations work
without either.
"""
from __future__ import annotations

import ipaddress
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from app.analysis.netlabels import NetworkLabel, label_for_ip

_MAX_ROWS = 50000


@dataclass(frozen=True)
class DiscoveredNetwork:
    key: str  # stable grouping identity: an interface name ("br21") or, for
    # kind="prefix", the same value as guessed_range — used for friendly-name
    # storage and the ip_to_key lookup, never shown to a user on its own.
    kind: str  # "interface" | "prefix" — confidence of the *grouping* (are
    # these hosts really one network?), independent of the range guess below.
    hosts: frozenset[str]
    event_count: int
    first_seen: float
    last_seen: float
    guessed_range: str | None  # the /24 a human would actually recognize —
    # always a guess in Stage 1 (no router API to confirm the real subnet
    # mask), even when the *grouping* itself is interface-confirmed.


@dataclass(frozen=True)
class NetworkMap:
    networks: list[DiscoveredNetwork]
    ip_to_key: dict[str, str] = field(default_factory=dict)

    @property
    def by_key(self) -> dict[str, DiscoveredNetwork]:
        return {n.key: n for n in self.networks}


def _prefix_key(ip: str) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        return None  # a naive /24-style prefix heuristic doesn't translate to IPv6
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def _dominant_ipv4_range(hosts: frozenset[str]) -> str | None:
    """The /24 most of this network's hosts actually fall in — a "good
    guess" per real-world VLANs almost always being /24s, but still a
    guess: nothing here confirms the router's actual configured mask."""
    prefixes = Counter(p for ip in hosts if (p := _prefix_key(ip)) is not None)
    if not prefixes:
        return None
    return prefixes.most_common(1)[0][0]


def infer_ip_keys(
    firewall_iface_rows: list[tuple[str, str, str | None, str | None]],
    all_ips: set[str],
) -> dict[str, tuple[str, str]]:
    """`firewall_iface_rows`: (src_ip, dst_ip, iface_in, iface_out).
    `all_ips`: every IP that should get a key, including ones with no
    interface info at all (flow-only IPs). Returns ip -> (key, kind)."""
    votes: dict[str, Counter] = defaultdict(Counter)
    for src_ip, dst_ip, iface_in, iface_out in firewall_iface_rows:
        if iface_in:
            votes[src_ip][iface_in] += 1
        if iface_out:
            votes[dst_ip][iface_out] += 1

    resolved: dict[str, tuple[str, str]] = {}
    for ip in all_ips:
        if ip in votes:
            resolved[ip] = (votes[ip].most_common(1)[0][0], "interface")
            continue
        prefix = _prefix_key(ip)
        if prefix:
            resolved[ip] = (prefix, "prefix")
    return resolved


def build_network_map(conn: sqlite3.Connection, since: float, max_rows: int = _MAX_ROWS) -> NetworkMap:
    fw_rows = conn.execute(
        "SELECT ts, src_ip, dst_ip, iface_in, iface_out FROM events_firewall "
        "WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
        (since, max_rows),
    ).fetchall()
    flow_rows = conn.execute(
        "SELECT ts_start, src_ip, dst_ip FROM events_flow WHERE ts_start >= ? ORDER BY ts_start DESC LIMIT ?",
        (since, max_rows),
    ).fetchall()

    all_ips = {ip for _, src, dst, _, _ in fw_rows for ip in (src, dst)}
    all_ips |= {ip for _, src, dst in flow_rows for ip in (src, dst)}
    ip_to_key_kind = infer_ip_keys([(src, dst, iface_in, iface_out) for _, src, dst, iface_in, iface_out in fw_rows], all_ips)

    stats: dict[str, dict] = {}
    for ts, src, dst, _, _ in fw_rows:
        for ip in (src, dst):
            resolved = ip_to_key_kind.get(ip)
            if resolved:
                _touch(stats, resolved, ip, ts)
    for ts, src, dst in flow_rows:
        for ip in (src, dst):
            resolved = ip_to_key_kind.get(ip)
            if resolved:
                _touch(stats, resolved, ip, ts)

    networks = []
    for key, entry in stats.items():
        hosts = frozenset(entry["hosts"])
        # For kind="prefix" the key already *is* the guessed range; for
        # kind="interface" it's a bridge name, so derive the range from
        # whichever /24 most of its hosts actually fall in.
        guessed_range = key if entry["kind"] == "prefix" else _dominant_ipv4_range(hosts)
        networks.append(
            DiscoveredNetwork(
                key=key,
                kind=entry["kind"],
                hosts=hosts,
                event_count=entry["count"],
                first_seen=entry["first"],
                last_seen=entry["last"],
                guessed_range=guessed_range,
            )
        )
    networks.sort(key=lambda n: -n.event_count)

    return NetworkMap(networks=networks, ip_to_key={ip: key for ip, (key, _kind) in ip_to_key_kind.items()})


def _touch(stats: dict[str, dict], resolved: tuple[str, str], ip: str, ts: float) -> None:
    key, kind = resolved
    entry = stats.setdefault(key, {"hosts": set(), "count": 0, "first": ts, "last": ts, "kind": kind})
    entry["hosts"].add(ip)
    entry["count"] += 1
    entry["first"] = min(entry["first"], ts)
    entry["last"] = max(entry["last"], ts)


def load_friendly_names(conn: sqlite3.Connection) -> dict[str, str]:
    rows = conn.execute("SELECT discovery_key, friendly_name FROM network_names").fetchall()
    return dict(rows)


def set_friendly_name(conn: sqlite3.Connection, discovery_key: str, friendly_name: str) -> None:
    if friendly_name.strip():
        conn.execute(
            "INSERT INTO network_names (discovery_key, friendly_name) VALUES (?, ?) "
            "ON CONFLICT(discovery_key) DO UPDATE SET friendly_name = excluded.friendly_name",
            (discovery_key, friendly_name.strip()),
        )
    else:
        conn.execute("DELETE FROM network_names WHERE discovery_key = ?", (discovery_key,))
    conn.commit()


@dataclass(frozen=True)
class UnifiNetworkInfo:
    name: str
    network: "ipaddress.IPv4Network | ipaddress.IPv6Network"


def load_unifi_networks(conn: sqlite3.Connection) -> list[UnifiNetworkInfo]:
    """Real, UniFi-confirmed networks (see app/unifi/) — the authoritative
    alternative to a traffic-guessed range once the console integration is
    configured and working. Empty (not an error) if UniFi isn't set up;
    every caller already treats "no UniFi data" as the normal case. A
    subnet that doesn't parse is skipped, not guessed at."""
    rows = conn.execute("SELECT name, subnet FROM unifi_networks WHERE subnet IS NOT NULL").fetchall()
    networks = []
    for name, subnet in rows:
        try:
            networks.append(UnifiNetworkInfo(name=name, network=ipaddress.ip_network(subnet, strict=False)))
        except ValueError:
            continue
    return networks


def unifi_network_for_ip(ip: str, unifi_networks: list[UnifiNetworkInfo]) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net in unifi_networks:
        if address in net.network:
            return net.name
    return None


def load_unifi_vlan_names(conn: sqlite3.Connection) -> dict[int, str]:
    """vlan_id -> real network name, for every synced network -- unlike
    load_unifi_networks() above, this doesn't require subnet data at all
    (confirmed live: vlan_id is reliably populated even on a console whose
    network objects carry no subnet field whatsoever). Pairs with
    unifi_network_for_interface() below."""
    rows = conn.execute("SELECT vlan_id, name FROM unifi_networks WHERE vlan_id IS NOT NULL").fetchall()
    return {vlan_id: name for vlan_id, name in rows}


_BRIDGE_VLAN_RE = re.compile(r"^br(\d+)$")


def unifi_network_for_interface(iface: str, vlan_names: dict[int, str]) -> str | None:
    """UniFi's own bridge interfaces are named br<vlanId> -- confirmed live
    against a real console's actual captured IN=/OUT= interface names
    (br22, br2, br50, ...) matched one-to-one against that console's real
    vlan_id per network. br0 carries the native/untagged VLAN, which is
    conventionally VLAN 1. This resolves real network names from data this
    add-on already captures (firewall log interfaces) and a field that's
    reliably present (vlan_id), entirely sidestepping the missing-subnet
    problem unifi_network_for_ip() has on this console."""
    match = _BRIDGE_VLAN_RE.match(iface)
    if not match:
        return None
    vlan_id = int(match.group(1)) or 1
    return vlan_names.get(vlan_id)


def unifi_gateway_ips(unifi_networks: list[UnifiNetworkInfo]) -> set[str]:
    """The Integration API exposes a network's subnet but no explicit
    gateway-IP field -- so this leans on UniFi's own convention (true for
    the overwhelming majority of real deployments, including every VLAN a
    UniFi controller itself provisions): the gateway is the first usable
    host address in the subnet. Every VLAN has one, and none of them are
    "a device on your network" in any inventory sense -- reported live as
    "every subnet's .1 shows up as an unknown device".

    In practice (confirmed against a real production console) not every
    UniFi Network Application version returns a subnet on this endpoint at
    all -- see guessed_gateway_ips() below for the traffic-derived
    fallback that doesn't depend on it."""
    ips: set[str] = set()
    for net in unifi_networks:
        try:
            ips.add(str(next(net.network.hosts())))
        except (StopIteration, ValueError):
            continue
    return ips


def guessed_gateway_ips(network_map: NetworkMap) -> set[str]:
    """Same idea as unifi_gateway_ips(), but from this add-on's own
    traffic-derived network discovery instead of the UniFi API -- works
    regardless of whether the integration is configured, or (confirmed
    live: a real console's Integration API network objects carried no
    subnet field whatsoever, on any network, so unifi_gateway_ips() alone
    was a no-op there) whether the API actually exposes subnet data.
    Every DiscoveredNetwork with a guessed /24-ish range is treated the
    same way: first usable address = likely gateway."""
    ips: set[str] = set()
    for net in network_map.networks:
        if not net.guessed_range:
            continue
        try:
            ips.add(str(next(ipaddress.ip_network(net.guessed_range, strict=False).hosts())))
        except (StopIteration, ValueError):
            continue
    return ips


def resolve_label(
    ip: str,
    network_map: NetworkMap,
    friendly_names: dict[str, str],
    manual_labels: list[NetworkLabel] | None = None,
    unifi_networks: list[UnifiNetworkInfo] | None = None,
    vlan_names: dict[int, str] | None = None,
) -> str:
    """The one place display-name resolution happens, in priority order:
    an explicit manual CIDR=Label override (Settings, optional) > a
    friendly name given to an auto-discovered network (a deliberate
    per-network customization, same spirit as a manual override) > a real
    UniFi-confirmed network name, from either the network's subnet (see
    load_unifi_networks) or, when that's unavailable (confirmed live: not
    every UniFi Network Application version returns one), its interface's
    br<vlanId> name matched against vlan_names (see load_unifi_vlan_names)
    > that network's guessed IP range (a bridge name like "br21" means
    nothing to a user, or to a recommendation's prose, on its own) > the
    discovered key itself, only if no IPv4 range could be guessed at all
    > the raw IP, when nothing was ever discovered for it (e.g. a WAN
    address never seen locally)."""
    if manual_labels:
        manual = label_for_ip(ip, manual_labels)
        if manual != ip:
            return manual

    key = network_map.ip_to_key.get(ip)
    if key is not None and key in friendly_names:
        return friendly_names[key]

    if unifi_networks:
        unifi_name = unifi_network_for_ip(ip, unifi_networks)
        if unifi_name:
            return unifi_name

    if key is not None and vlan_names:
        iface_name = unifi_network_for_interface(key, vlan_names)
        if iface_name:
            return iface_name

    if key is None:
        return ip

    network = network_map.by_key.get(key)
    if network and network.guessed_range:
        return network.guessed_range
    return key
