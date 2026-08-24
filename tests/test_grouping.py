import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis.grouping import GroupableEvent, group_candidate_patterns

DAY0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ts(day_offset: int, hour: int = 12) -> float:
    return (DAY0 + timedelta(days=day_offset, hours=hour)).timestamp()


def _event(event_id, day_offset, blocked=True, dst_port=7000):
    return GroupableEvent(
        event_id=event_id,
        ts=_ts(day_offset),
        src_class="Apple HomePod / smart speaker",
        dst_class="iPhone",
        src_net_label="IoT",
        dst_net_label="Home",
        proto=6,
        dst_port=dst_port,
        was_blocked=blocked,
    )


def test_pattern_below_min_recurring_days_is_dropped():
    events = [_event(1, day_offset=0), _event(2, day_offset=0)]  # same day, twice
    patterns = group_candidate_patterns(events, min_recurring_days=2)
    assert patterns == []


def test_pattern_across_enough_distinct_days_is_kept():
    events = [_event(1, day_offset=0), _event(2, day_offset=1), _event(3, day_offset=2)]
    patterns = group_candidate_patterns(events, min_recurring_days=3)
    assert len(patterns) == 1
    pattern = patterns[0]
    assert pattern.occurrence_count == 3
    assert pattern.distinct_days == 3
    assert pattern.src_class == "Apple HomePod / smart speaker"
    assert pattern.dst_port == 7000
    assert pattern.saw_blocked is True
    assert pattern.saw_allowed is False


def test_different_ports_produce_separate_patterns():
    events = [
        _event(1, day_offset=0, dst_port=7000),
        _event(2, day_offset=1, dst_port=7000),
        _event(3, day_offset=0, dst_port=8009),
        _event(4, day_offset=1, dst_port=8009),
    ]
    patterns = group_candidate_patterns(events, min_recurring_days=2)
    assert len(patterns) == 2
    ports = {p.dst_port for p in patterns}
    assert ports == {7000, 8009}


def test_mixed_blocked_and_allowed_is_reflected():
    events = [_event(1, day_offset=0, blocked=True), _event(2, day_offset=1, blocked=False)]
    patterns = group_candidate_patterns(events, min_recurring_days=2)
    assert patterns[0].saw_blocked is True
    assert patterns[0].saw_allowed is True


def test_sample_event_ids_are_capped():
    events = [_event(i, day_offset=i % 5) for i in range(20)]
    patterns = group_candidate_patterns(events, min_recurring_days=1, max_samples=3)
    assert len(patterns[0].sample_event_ids) == 3
