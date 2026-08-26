"""Best-effort local-LLM capacity check, shown on Settings: how many CPU
cores and how much RAM this host has, whether that's comfortable for the
bundled model, and a plain-language expectation of what that buys in
generation speed.

Deliberately a rough estimate, not a promise: there's no official minimum
spec for running a 3B GGUF model well, actual speed depends on more than
core count (memory bandwidth, thermal throttling, what else is sharing the
box), and `os.cpu_count()`/`/proc/meminfo` inside a container reflect the
host's real resources only because this add-on isn't itself CPU/memory
limited by Supervisor -- true for a normal install, not guaranteed. Only
meaningful in local LLM mode; remote mode's speed depends on the remote
provider, not this host, and callers should skip showing it there.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

_MIN_COMFORTABLE_CORES = 4
_MIN_COMFORTABLE_RAM_GB = 4.0


@dataclass(frozen=True)
class HostCapacity:
    cpu_cores: int | None
    ram_total_gb: float | None
    ram_available_gb: float | None
    below_recommended: bool
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PerformanceSample:
    cores: str
    tokens_per_sec: str
    seconds_per_recommendation: str
    note: str
    measured: bool


# One real anchor point (measured live on this project's own production
# hardware, 4 real CPU threads, the bundled Qwen2.5-3B Q4_K_M model,
# grammar-constrained structured output) -- everything else is a rough,
# clearly-labeled scaling estimate around it, not a second measurement.
# CPU inference on a small model scales sub-linearly past ~8 threads
# (memory bandwidth becomes the bottleneck before core count does), which
# is why the higher tiers don't just keep doubling.
PERFORMANCE_SAMPLES: list[PerformanceSample] = [
    PerformanceSample(
        cores="2",
        tokens_per_sec="~2-3",
        seconds_per_recommendation="~90-150s+",
        note="Usable, but every \"Run analysis now\" click is a long wait -- remote mode "
        "will feel much more responsive on hardware this size.",
        measured=False,
    ),
    PerformanceSample(
        cores="4",
        tokens_per_sec="~4.7-5.1",
        seconds_per_recommendation="~50-70s",
        note="Measured directly on this project's own production hardware.",
        measured=True,
    ),
    PerformanceSample(
        cores="8",
        tokens_per_sec="~7-9 (rough estimate)",
        seconds_per_recommendation="~25-40s",
        note="Sub-linear scaling from the 4-core figure, not a second measurement.",
        measured=False,
    ),
    PerformanceSample(
        cores="16+",
        tokens_per_sec="~9-12 (rough estimate)",
        seconds_per_recommendation="~20-30s",
        note="Diminishing returns beyond about 8 threads for a model this small -- memory "
        "bandwidth limits it before core count does.",
        measured=False,
    ),
]


def _read_meminfo() -> tuple[float | None, float | None]:
    try:
        values: dict[str, str] = {}
        with open("/proc/meminfo") as f:
            for line in f:
                key, _, rest = line.partition(":")
                values[key] = rest.strip()
        total_kb = int(values["MemTotal"].split()[0])
        available_kb = int(values.get("MemAvailable", values["MemTotal"]).split()[0])
        return total_kb / 1024 / 1024, available_kb / 1024 / 1024
    except (OSError, KeyError, ValueError, IndexError):
        return None, None


def check_host_capacity() -> HostCapacity:
    cpu_cores = os.cpu_count()
    ram_total_gb, ram_available_gb = _read_meminfo()

    reasons = []
    if cpu_cores is not None and cpu_cores < _MIN_COMFORTABLE_CORES:
        reasons.append(
            f"Only {cpu_cores} CPU core(s) visible to this add-on -- generation will be "
            f"noticeably slower than the ~50-70s/recommendation measured on {_MIN_COMFORTABLE_CORES} "
            "cores; consider remote mode if that's too slow to be useful."
        )
    if ram_total_gb is not None and ram_total_gb < _MIN_COMFORTABLE_RAM_GB:
        reasons.append(
            f"Only {ram_total_gb:.1f} GB RAM total -- the bundled 3B Q4 model needs roughly "
            "2-3 GB by itself, leaving little headroom for Home Assistant and other add-ons; "
            "if the host starts swapping, generation can slow down by an order of magnitude, "
            "not just proportionally."
        )

    return HostCapacity(
        cpu_cores=cpu_cores,
        ram_total_gb=ram_total_gb,
        ram_available_gb=ram_available_gb,
        below_recommended=bool(reasons),
        reasons=reasons,
    )
