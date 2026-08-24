"""Filters out traffic that's an artifact of this add-on's own logging
pipeline, not genuine host-to-host behavior worth a zero-trust
recommendation.

Found in production: the single highest-volume "pattern" the engine ever
saw (284,786 occurrences) was the router logging its own syslog-forwarding
traffic to this add-on's receiver port — a broad "log everything" firewall
rule re-reports the log-shipping packets themselves as if they were
ordinary traffic. That's expected and intentional (the user configured the
forwarding on purpose); it isn't a segmentation decision to recommend a
rule for.
"""
from __future__ import annotations


def is_own_receiver_traffic(
    dst_ip: str,
    dst_port: int | None,
    host_ip: str | None,
    syslog_port: int,
    netflow_port: int,
) -> bool:
    """True if this event is traffic destined for this add-on's own
    syslog/NetFlow receiver, on the host it's actually running on.
    `host_ip` is best-effort (from the Supervisor network API) — when it's
    unknown, this never suppresses anything rather than risk a false match
    on a port number alone.
    """
    if host_ip is None or dst_ip != host_ip:
        return False
    return dst_port in (syslog_port, netflow_port)
