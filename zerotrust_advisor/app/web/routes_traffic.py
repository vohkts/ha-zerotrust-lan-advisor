"""Traffic screen: a plain, structured view of what's actually been seen —
auto-discovered networks, hosts, the most common flows, and a sample of
recent distinct ones. Reads only the parsed, structured event tables
(never raw syslog text, which the receivers discard by design) and shows
real local IPs/hostnames — this page never leaves the box, so the
pseudonymization used for LLM calls doesn't apply here; showing the admin
their own network plainly is the point.

Networks are discovered from traffic itself (see network_map.py) — no
manual subnet/VLAN entry required. A friendly name is an optional label on
top of a discovery, never a prerequisite for it.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass

from flask import Blueprint, current_app, jsonify, render_template, request

from app.analysis.direction import count_directions, is_private_ip
from app.analysis.engine import llm_base_url
from app.analysis.host_detail import load_host_detail
from app.analysis.known_ports import PROTO_NAMES, describe_port
from app.analysis.netlabels import parse_network_labels
from app.analysis.network_map import (
    NetworkMap,
    build_network_map,
    guessed_gateway_ips,
    load_friendly_names,
    load_unifi_networks,
    load_unifi_vlan_names,
    resolve_label,
    set_friendly_name,
    unifi_gateway_ips,
    unifi_network_for_interface,
    unifi_network_for_ip,
)
from app.db import connect
from app.llm.client import LLMError, chat_completion
from app.llm.prompts import DEVICE_GUESS_SCHEMA, build_device_guess_messages
from app.supervisor import get_host_ip
from app.web.db_context import get_db

logger = logging.getLogger(__name__)

traffic_bp = Blueprint("traffic", __name__)

# Tracks IPs a guess request is currently in flight for, so a double-click
# (or two browser tabs) can't kick off two LLM calls for the same host —
# same "one in flight at a time" spirit as the analysis pass's own lock,
# just per-host instead of global.
_guess_in_progress: set[str] = set()
_guess_lock = threading.Lock()

_WINDOW_SECONDS = 7 * 86400
_MAX_ROWS_PER_TABLE = 20000
_TOP_FLOWS_LIMIT = 20
_RECENT_EXAMPLES_LIMIT = 100
_TOP_HOSTS_LIMIT = 50


@dataclass(frozen=True)
class _Event:
    ts: float
    src_ip: str
    dst_ip: str
    proto: int
    dst_port: int | None


def _load_events(conn, since: float, unifi_host: str | None = None) -> tuple[list[_Event], int]:
    """Newest first, each source bounded independently so a burst on one
    receiver can't starve the other out of the page entirely. Returns
    (events, count excluded as UDM console traffic) — the console's own
    management IP (DNS/DHCP served to every device, health checks, etc.)
    is infrastructure noise, not a segmentation decision, same reasoning
    as the existing own-receiver-traffic filter. `_count_events`'s
    headline total deliberately does *not* apply this filter — same
    "honest total vs. what's shown" split as the external-IP host filter."""
    fw_rows = conn.execute(
        "SELECT ts, src_ip, dst_ip, proto, dst_port FROM events_firewall "
        "WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
        (since, _MAX_ROWS_PER_TABLE),
    ).fetchall()
    flow_rows = conn.execute(
        "SELECT ts_start, src_ip, dst_ip, proto, dst_port FROM events_flow "
        "WHERE ts_start >= ? ORDER BY ts_start DESC LIMIT ?",
        (since, _MAX_ROWS_PER_TABLE),
    ).fetchall()
    events = [_Event(*row) for row in fw_rows] + [_Event(*row) for row in flow_rows]

    hidden = 0
    if unifi_host:
        filtered = []
        for e in events:
            if e.src_ip == unifi_host or e.dst_ip == unifi_host:
                hidden += 1
                continue
            filtered.append(e)
        events = filtered

    events.sort(key=lambda e: e.ts, reverse=True)
    return events, hidden


def _count_events(conn, since: float) -> int:
    """The true total in-window, independent of `_load_events`'s per-table
    cap — that cap exists to bound how much this page has to sort/render,
    not to hide how much data actually exists. Reported live: the headline
    "N events" number silently was `_MAX_ROWS_PER_TABLE * 2` on any busy
    network, indistinguishable from a genuinely quiet one at that count."""
    fw_count = conn.execute("SELECT COUNT(*) FROM events_firewall WHERE ts >= ?", (since,)).fetchone()[0]
    flow_count = conn.execute("SELECT COUNT(*) FROM events_flow WHERE ts_start >= ?", (since,)).fetchone()[0]
    return fw_count + flow_count


def _load_identities(conn) -> dict[str, dict]:
    rows = conn.execute("SELECT ip, hostname, vendor, device_class, class_confidence FROM identities").fetchall()
    identities: dict[str, dict] = {}
    for ip, hostname, vendor, device_class, confidence in rows:
        if ip:
            identities[ip] = {
                "hostname": hostname,
                "vendor": vendor,
                "device_class": device_class,
                "confidence": confidence,
            }
    return identities


def _flow_row(src, dst, proto, port, count, last_seen, network_map, friendly_names, manual_labels, identities, unifi_networks=(), vlan_names=None) -> dict:
    src_info = identities.get(src) or {}
    dst_info = identities.get(dst) or {}
    return {
        "src": src,
        "src_network": resolve_label(src, network_map, friendly_names, manual_labels, unifi_networks, vlan_names),
        "src_name": src_info.get("hostname"),
        "src_class": src_info.get("device_class"),
        "dst": dst,
        "dst_network": resolve_label(dst, network_map, friendly_names, manual_labels, unifi_networks, vlan_names),
        "dst_name": dst_info.get("hostname"),
        "dst_class": dst_info.get("device_class"),
        "proto": PROTO_NAMES.get(proto, str(proto)),
        "port": port,
        "port_hint": describe_port(proto, port),
        "count": count,
        "last_seen": last_seen,
    }


def _build_network_rows(network_map: NetworkMap, friendly_names: dict[str, str], unifi_networks=(), vlan_names=None) -> tuple[list[dict], int]:
    """Returns (rows, count hidden as noise). Three kinds of noise filtered
    out, not just capped:

    1. Entirely public-IP groupings aren't a network of yours at all — a
       cluster of internet destinations that happened to share a /24 guess
       (very common: several servers behind the same CDN or cloud range),
       not a real local segment. The original version of this filter only
       caught a *single*-host public grouping, which missed exactly this
       case — still showing 100+ entries with UniFi active, reported live.
       RFC1918 ranges don't overlap with public ones, so checking any one
       host is enough to classify the whole grouping.
    2. A single-host "prefix" grouping, even a private one, is weak enough
       evidence it's not worth showing as a "network" on its own.
    3. Once UniFi confirms a network's real name for a range, the guessed
       entry for that range is redundant — resolve_label() already prefers
       the real name everywhere a host/flow in that range gets labeled.

    Interface-confirmed groupings skip check 2 (real evidence regardless
    of host count) but not check 1 — a WAN-facing interface can log
    IN=/OUT= just as a LAN one does, and its hosts are still public IPs,
    not a network of yours."""
    rows = []
    hidden = 0
    for net in network_map.networks:  # already sorted by event volume, descending
        sample_ip = next(iter(net.hosts), None)
        if sample_ip is not None and not is_private_ip(sample_ip):
            hidden += 1
            continue
        if net.kind == "prefix" and len(net.hosts) <= 1:
            hidden += 1
            continue
        if unifi_networks and sample_ip is not None and unifi_network_for_ip(sample_ip, unifi_networks):
            hidden += 1
            continue
        if vlan_names and unifi_network_for_interface(net.key, vlan_names):
            hidden += 1
            continue
        rows.append(
            {
                "key": net.key,
                "kind": net.kind,
                "guessed_range": net.guessed_range,
                "display_name": friendly_names.get(net.key, net.guessed_range or net.key),
                "hosts": len(net.hosts),
                "events": net.event_count,
                "first_seen": net.first_seen,
                "last_seen": net.last_seen,
            }
        )
    return rows, hidden


def _build_host_rows(network_map, friendly_names, manual_labels, identities, events: list[_Event], unifi_networks=(), vlan_names=None) -> tuple[list[dict], int]:
    """Returns (rows, count hidden as external). A public IP like 1.1.1.1
    shows up constantly as a flow endpoint (it's a hugely popular DNS
    resolver) but isn't a "host" in any inventory sense — it's not a
    device on this network. Filtered out before ranking (not after), so a
    high-volume external destination can't crowd real local devices out of
    the top N. The flow/network tables still show every IP; this one
    specifically answers "what's on my network," not "what did it talk to."
    """
    counts: Counter = Counter()
    last_seen: dict[str, float] = {}
    first_seen: dict[str, float] = {}
    external_ips: set[str] = set()
    for e in events:  # events is newest-first
        for ip in (e.src_ip, e.dst_ip):
            if not is_private_ip(ip):
                external_ips.add(ip)
                continue
            counts[ip] += 1
            last_seen.setdefault(ip, e.ts)
            first_seen[ip] = e.ts  # overwritten every time; final value is the oldest in-window

    gateway_ips = unifi_gateway_ips(unifi_networks) | guessed_gateway_ips(network_map)
    rows = []
    for ip, count in counts.most_common(_TOP_HOSTS_LIMIT):
        info = identities.get(ip) or {}
        is_gateway = ip in gateway_ips
        rows.append(
            {
                "ip": ip,
                "name": info.get("hostname") or ("Network gateway" if is_gateway else None),
                "network": resolve_label(ip, network_map, friendly_names, manual_labels, unifi_networks, vlan_names),
                "device_class": info.get("device_class") or ("Network gateway" if is_gateway else "Unclassified"),
                "vendor": info.get("vendor"),
                "confidence": info.get("confidence") or ("high" if is_gateway else "low"),
                "events": count,
                "first_seen": first_seen.get(ip),
                "last_seen": last_seen.get(ip),
            }
        )
    return rows, len(external_ips)


def _build_flow_tables(network_map, friendly_names, manual_labels, identities, events: list[_Event], unifi_networks=(), vlan_names=None) -> tuple[list[dict], list[dict]]:
    counts: Counter = Counter()
    last_seen: dict[tuple, float] = {}
    for e in events:  # newest-first
        key = (e.src_ip, e.dst_ip, e.proto, e.dst_port)
        counts[key] += 1
        last_seen.setdefault(key, e.ts)

    top_flows = [
        _flow_row(*key, count, last_seen[key], network_map, friendly_names, manual_labels, identities, unifi_networks, vlan_names)
        for key, count in counts.most_common(_TOP_FLOWS_LIMIT)
    ]

    seen: set[tuple] = set()
    recent_examples = []
    for e in events:
        key = (e.src_ip, e.dst_ip, e.proto, e.dst_port)
        if key in seen:
            continue
        seen.add(key)
        recent_examples.append(
            _flow_row(*key, counts[key], e.ts, network_map, friendly_names, manual_labels, identities, unifi_networks, vlan_names)
        )
        if len(recent_examples) >= _RECENT_EXAMPLES_LIMIT:
            break

    return top_flows, recent_examples


@traffic_bp.route("/traffic")
def traffic_page():
    """Just the page shell, on purpose: every real query this screen needs
    (network map, host rows, flow tables) lives behind /traffic/sections
    instead, fetched async by static/app.js once the shell has already
    painted. Reported live as a 1-2s (later 5-6s, as the DB grew) delay
    before anything appeared at all -- with everything computed inline
    here, the whole page waited on the slowest query before the browser
    had anything to render."""
    return render_template("traffic.html")


@traffic_bp.route("/traffic/sections")
def traffic_sections():
    config = current_app.config["ZTA_CONFIG"]
    conn = get_db()
    now = time.time()
    since = now - _WINDOW_SECONDS

    manual_labels = parse_network_labels(list(config.network_labels))
    network_map = build_network_map(conn, since=since)
    friendly_names = load_friendly_names(conn)
    unifi_networks = load_unifi_networks(conn)
    vlan_names = load_unifi_vlan_names(conn)
    console_filter = config.unifi_host if config.ignore_unifi_console_traffic else None
    events, hidden_console_count = _load_events(conn, since, console_filter)
    identities = _load_identities(conn)

    direction_counts = count_directions([(e.src_ip, e.dst_ip) for e in events])
    network_rows, hidden_network_count = _build_network_rows(network_map, friendly_names, unifi_networks, vlan_names)
    host_rows, hidden_external_host_count = _build_host_rows(
        network_map, friendly_names, manual_labels, identities, events, unifi_networks, vlan_names
    )
    top_flows, recent_examples = _build_flow_tables(
        network_map, friendly_names, manual_labels, identities, events, unifi_networks, vlan_names
    )

    return render_template(
        "traffic_sections.html",
        total_events=_count_events(conn, since),
        sampled_events=len(events),
        hidden_console_count=hidden_console_count,
        direction_counts=direction_counts,
        network_rows=network_rows,
        hidden_network_count=hidden_network_count,
        unifi_networks_active=bool(unifi_networks) or bool(vlan_names),
        host_rows=host_rows,
        hidden_external_host_count=hidden_external_host_count,
        top_flows=top_flows,
        recent_examples=recent_examples,
        window_days=_WINDOW_SECONDS // 86400,
    )


@traffic_bp.route("/traffic/rename", methods=["POST"])
def rename_network():
    discovery_key = request.form.get("discovery_key", "").strip()
    friendly_name = request.form.get("friendly_name", "")
    if not discovery_key:
        return jsonify({"error": "missing discovery_key"}), 400
    set_friendly_name(get_db(), discovery_key, friendly_name)
    return jsonify({"status": "ok"})


@traffic_bp.route("/traffic/host-detail")
def host_detail():
    """Backs the Hosts table's expand-on-click row (see static/app.js) —
    total traffic, top ports, top flow partners, recent distinct flows,
    and whatever LLM guess state currently exists for this host. Fetched
    on demand, not folded into the main /traffic render, since most hosts
    are never expanded."""
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "missing_ip"}), 400

    config = current_app.config["ZTA_CONFIG"]
    conn = get_db()
    since = time.time() - _WINDOW_SECONDS

    manual_labels = parse_network_labels(list(config.network_labels))
    network_map = build_network_map(conn, since=since)
    friendly_names = load_friendly_names(conn)
    unifi_networks = load_unifi_networks(conn)
    vlan_names = load_unifi_vlan_names(conn)
    identities = _load_identities(conn)
    info = identities.get(ip) or {}
    is_gateway = ip in (unifi_gateway_ips(unifi_networks) | guessed_gateway_ips(network_map))

    console_host = config.unifi_host if config.ignore_unifi_console_traffic else None
    detail = load_host_detail(
        conn, ip, since,
        host_ip=get_host_ip(), syslog_port=config.syslog_port, netflow_port=config.netflow_port,
        unifi_console_host=console_host,
    )

    def _label(other_ip: str) -> str:
        return resolve_label(other_ip, network_map, friendly_names, manual_labels, unifi_networks, vlan_names)

    top_partners = [
        {
            "ip": partner_ip,
            "name": (identities.get(partner_ip) or {}).get("hostname"),
            "device_class": (identities.get(partner_ip) or {}).get("device_class"),
            "network": _label(partner_ip),
            "count": count,
        }
        for partner_ip, count in detail.top_partners
    ]
    recent_flows = [
        {**f, "src_network": _label(f["src"]), "dst_network": _label(f["dst"])} for f in detail.recent_flows
    ]

    guess_row = conn.execute(
        "SELECT llm_guess, llm_guess_at FROM identities WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
    ).fetchone()
    llm_guess, llm_guess_at = guess_row if guess_row else (None, None)

    return jsonify(
        {
            "ip": ip,
            "name": info.get("hostname") or ("Network gateway" if is_gateway else None),
            "device_class": info.get("device_class") or ("Network gateway" if is_gateway else "Unclassified device"),
            "vendor": info.get("vendor"),
            "confidence": info.get("confidence") or ("high" if is_gateway else "low"),
            "network": _label(ip),
            "event_count": detail.event_count,
            "event_count_capped": detail.event_count_capped,
            "first_seen": detail.first_seen,
            "last_seen": detail.last_seen,
            "top_ports": detail.top_ports,
            "top_partners": top_partners,
            "recent_flows": recent_flows,
            "llm_guess": llm_guess,
            "llm_guess_at": llm_guess_at,
            "guess_in_progress": ip in _guess_in_progress,
            "window_days": _WINDOW_SECONDS // 86400,
        }
    )


@traffic_bp.route("/traffic/host-detail/guess", methods=["POST"])
def host_detail_guess():
    """Starts an on-demand LLM guess at what an Unclassified device might
    be, in a background thread — same fire-and-poll shape as
    /recommendations/run-now, and for the same reason: an LLM call can
    take upward of a minute, and waiting on it here would risk the same
    504 that fix addressed. The frontend polls /traffic/host-detail
    afterward and picks up the cached guess once it lands (see
    static/app.js). Never runs automatically; only ever triggered by an
    explicit click, since it's a real (if local, in local mode) LLM call."""
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "missing_ip"}), 400

    with _guess_lock:
        if ip in _guess_in_progress:
            return jsonify({"status": "already_running"}), 409
        _guess_in_progress.add(ip)

    config = current_app.config["ZTA_CONFIG"]
    since = time.time() - _WINDOW_SECONDS

    def _run() -> None:
        conn = connect(config.db_path)
        try:
            info = conn.execute(
                "SELECT vendor, hostname FROM identities WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
            ).fetchone()
            vendor = info[0] if info else None
            real_identifier = None
            if config.llm_send_real_identifiers:
                real_identifier = (info[1] if info else None) or ip
            console_host = config.unifi_host if config.ignore_unifi_console_traffic else None
            detail = load_host_detail(
                conn, ip, since,
                host_ip=get_host_ip(), syslog_port=config.syslog_port, netflow_port=config.netflow_port,
                unifi_console_host=console_host,
            )
            top_ports = [(p["proto"], p["port"], p["port_hint"]) for p in detail.top_ports]

            network_map = build_network_map(conn, since=since)
            friendly_names = load_friendly_names(conn)
            unifi_networks = load_unifi_networks(conn)
            vlan_names = load_unifi_vlan_names(conn)
            manual_labels = parse_network_labels(list(config.network_labels))
            identities = _load_identities(conn)
            top_partners = [
                (
                    resolve_label(partner_ip, network_map, friendly_names, manual_labels, unifi_networks, vlan_names),
                    (identities.get(partner_ip) or {}).get("device_class"),
                    count,
                )
                for partner_ip, count in detail.top_partners
            ]

            messages = build_device_guess_messages(vendor, detail.event_count, top_ports, top_partners, real_identifier)
            base_url, api_key = llm_base_url(config)
            reply = chat_completion(base_url, messages, api_key=api_key, response_format=DEVICE_GUESS_SCHEMA)
            guess = json.loads(reply).get("guess", "").strip()

            now = time.time()
            existing = conn.execute(
                "SELECT device_key FROM identities WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE identities SET llm_guess = ?, llm_guess_at = ? WHERE device_key = ?",
                    (guess or None, now, existing[0]),
                )
            else:
                # A host with observed traffic but no identity row at all
                # (never seen via mDNS or as a UniFi client) — without this,
                # the guess would silently vanish: the UPDATE above would
                # match zero rows for a host like this.
                conn.execute(
                    """INSERT INTO identities
                       (device_key, ip, device_class, class_confidence, first_seen, last_seen, llm_guess, llm_guess_at)
                       VALUES (?, ?, 'Unclassified device', 'low', ?, ?, ?, ?)""",
                    (ip, ip, now, now, guess or None, now),
                )
            conn.commit()
        except (LLMError, json.JSONDecodeError):
            logger.exception("device guess failed for %s", ip)
        except Exception:
            logger.exception("unexpected error generating device guess for %s", ip)
        finally:
            conn.close()
            with _guess_lock:
                _guess_in_progress.discard(ip)

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started"})
