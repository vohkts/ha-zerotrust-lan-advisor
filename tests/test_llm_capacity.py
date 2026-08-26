import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zerotrust_advisor"))

from app.analysis import llm_capacity


def test_comfortable_resources_produce_no_warning(monkeypatch):
    monkeypatch.setattr(llm_capacity.os, "cpu_count", lambda: 4)
    monkeypatch.setattr(llm_capacity, "_read_meminfo", lambda: (8.0, 6.0))

    result = llm_capacity.check_host_capacity()
    assert result.below_recommended is False
    assert result.reasons == []


def test_low_cpu_count_is_flagged(monkeypatch):
    monkeypatch.setattr(llm_capacity.os, "cpu_count", lambda: 2)
    monkeypatch.setattr(llm_capacity, "_read_meminfo", lambda: (8.0, 6.0))

    result = llm_capacity.check_host_capacity()
    assert result.below_recommended is True
    assert any("2 CPU core" in r for r in result.reasons)


def test_low_ram_is_flagged(monkeypatch):
    monkeypatch.setattr(llm_capacity.os, "cpu_count", lambda: 4)
    monkeypatch.setattr(llm_capacity, "_read_meminfo", lambda: (2.0, 1.0))

    result = llm_capacity.check_host_capacity()
    assert result.below_recommended is True
    assert any("2.0 GB RAM" in r for r in result.reasons)


def test_unreadable_meminfo_does_not_crash_or_false_flag(tmp_path, monkeypatch):
    # A container without /proc/meminfo visible (unlikely, but this must
    # degrade to "unknown", not a crash or a false "below recommended".
    def _boom():
        raise OSError("no such file")

    monkeypatch.setattr(llm_capacity, "_read_meminfo", lambda: (None, None))
    monkeypatch.setattr(llm_capacity.os, "cpu_count", lambda: 4)

    result = llm_capacity.check_host_capacity()
    assert result.ram_total_gb is None
    assert result.below_recommended is False


def test_performance_samples_include_exactly_one_measured_row():
    measured = [s for s in llm_capacity.PERFORMANCE_SAMPLES if s.measured]
    assert len(measured) == 1
    assert measured[0].cores == "4"
