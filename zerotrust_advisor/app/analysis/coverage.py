"""Detects and explains what the add-on can and can't currently see, based
on what has (and hasn't) arrived.

The case that matters most: on hardware like a UniFi UDM Pro, NetFlow only
ever reports WAN-crossing traffic, because inter-VLAN routing is hardware-
offloaded and structurally never generates flow records — this was verified
empirically (twenty generated inter-VLAN connections, zero of them ever
appeared in flow data). Per-rule firewall logging is the only reliable
east-west evidence source on that class of hardware. Rather than silently
missing this and drawing conclusions from WAN-only data, the add-on watches
for exactly this shape of gap and says so.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CoverageInputs:
    now: float
    last_firewall_event_at: float | None
    last_flow_event_at: float | None
    rejected_syslog_count: int
    rejected_flow_count: int
    inter_vlan_firewall_matches: int
    inter_vlan_flow_matches: int
    total_matches: int
    internal_internal_matches: int
    stale_after_seconds: int = 3600


@dataclass(frozen=True)
class GapWarning:
    code: str
    severity: str  # "info" | "warning"
    message: str


def evaluate_coverage(inputs: CoverageInputs) -> list[GapWarning]:
    warnings: list[GapWarning] = []

    if inputs.last_firewall_event_at is None:
        if inputs.rejected_syslog_count > 0:
            warnings.append(
                GapWarning(
                    "syslog_wrong_source",
                    "warning",
                    f"Receiving syslog traffic, but all {inputs.rejected_syslog_count} messages came from an "
                    "unrecognized source IP. Check the allowed-sources setting against your router's actual IP.",
                )
            )
        else:
            warnings.append(
                GapWarning(
                    "syslog_none",
                    "warning",
                    "No firewall/syslog events received yet. See the setup guide for what to enable on your router.",
                )
            )
    elif inputs.now - inputs.last_firewall_event_at > inputs.stale_after_seconds:
        warnings.append(
            GapWarning(
                "syslog_stale",
                "warning",
                f"No firewall/syslog events in over {inputs.stale_after_seconds // 60} minutes — "
                "check the router is still forwarding logs.",
            )
        )

    if inputs.last_flow_event_at is None:
        if inputs.rejected_flow_count > 0:
            warnings.append(
                GapWarning(
                    "flow_wrong_source",
                    "warning",
                    f"Receiving NetFlow/IPFIX traffic, but all {inputs.rejected_flow_count} packets came from an "
                    "unrecognized source IP. Check the allowed-sources setting.",
                )
            )
        else:
            warnings.append(
                GapWarning(
                    "flow_none",
                    "warning",
                    "No NetFlow/IPFIX data received yet. See the setup guide for what to enable on your router.",
                )
            )
    elif inputs.now - inputs.last_flow_event_at > inputs.stale_after_seconds:
        warnings.append(
            GapWarning(
                "flow_stale",
                "warning",
                f"No flow data in over {inputs.stale_after_seconds // 60} minutes — "
                "check the export is still configured.",
            )
        )

    if inputs.total_matches > 0 and inputs.internal_internal_matches == 0:
        warnings.append(
            GapWarning(
                "no_internal_traffic_seen",
                "info",
                "Everything seen so far is to or from a public IP — no confirmed traffic between two devices "
                "on your own private networks yet. Expected briefly right after setup; if it persists, check "
                "that logging covers LAN-to-LAN rules too, not just WAN-facing ones.",
            )
        )

    if inputs.inter_vlan_firewall_matches > 0 and inputs.inter_vlan_flow_matches == 0:
        warnings.append(
            GapWarning(
                "no_east_west_flow_evidence",
                "info",
                "Firewall logs show inter-VLAN traffic, but none of it shows up in flow data. This is expected "
                "on hardware that offloads inter-VLAN routing — NetFlow/IPFIX structurally can't see "
                "hardware-offloaded traffic. Per-rule firewall logging, not flow export, is your reliable "
                "east-west evidence source; make sure logging is enabled on your inter-VLAN rules specifically.",
            )
        )

    return warnings
