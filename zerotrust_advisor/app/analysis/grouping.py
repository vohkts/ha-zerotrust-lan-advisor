"""Buckets pseudonymized, classified events into recurring traffic patterns
worth asking the LLM about.

A pattern only becomes a candidate once it's shown up on enough distinct
calendar days — a single burst of a few hundred packets in one afternoon is
noise, not a habit worth codifying into a firewall rule.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class GroupableEvent:
    event_id: int
    ts: float
    src_class: str
    dst_class: str
    src_net_label: str
    dst_net_label: str
    proto: int
    dst_port: int | None
    was_blocked: bool


@dataclass(frozen=True)
class CandidatePattern:
    signature: str
    src_class: str
    dst_class: str
    src_net_label: str
    dst_net_label: str
    proto: int
    dst_port: int | None
    occurrence_count: int
    distinct_days: int
    first_seen: float
    last_seen: float
    saw_blocked: bool
    saw_allowed: bool
    sample_event_ids: list[int]


def _day_key(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def _signature(event: GroupableEvent) -> str:
    return "|".join(
        str(part)
        for part in (
            event.src_net_label,
            event.dst_net_label,
            event.src_class,
            event.dst_class,
            event.proto,
            event.dst_port,
        )
    )


def group_candidate_patterns(
    events: list[GroupableEvent],
    min_recurring_days: int,
    max_samples: int = 10,
) -> list[CandidatePattern]:
    buckets: dict[str, list[GroupableEvent]] = defaultdict(list)
    for event in events:
        buckets[_signature(event)].append(event)

    patterns: list[CandidatePattern] = []
    for signature, bucket in buckets.items():
        distinct_days = len({_day_key(e.ts) for e in bucket})
        if distinct_days < min_recurring_days:
            continue

        bucket.sort(key=lambda e: e.ts)
        first, last = bucket[0], bucket[-1]
        patterns.append(
            CandidatePattern(
                signature=signature,
                src_class=first.src_class,
                dst_class=first.dst_class,
                src_net_label=first.src_net_label,
                dst_net_label=first.dst_net_label,
                proto=first.proto,
                dst_port=first.dst_port,
                occurrence_count=len(bucket),
                distinct_days=distinct_days,
                first_seen=first.ts,
                last_seen=last.ts,
                saw_blocked=any(e.was_blocked for e in bucket),
                saw_allowed=any(not e.was_blocked for e in bucket),
                sample_event_ids=[e.event_id for e in bucket[:max_samples]],
            )
        )

    patterns.sort(key=lambda p: (-p.occurrence_count, p.signature))
    return patterns
