"""Per-service health status, written as a small JSON file.

Kept out of SQLite deliberately: the setup screen polls this constantly, and
a receiver crashing mid-write to its own status file must never be able to
corrupt state another service depends on. The write is atomic (temp file +
fsync + rename) so a reader never sees a half-written file.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


class HealthReporter:
    def __init__(self, health_dir: Path, service: str):
        self._path = health_dir / f"{service}.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._state: dict[str, Any] = {"service": service, "started_at": time.time()}

    def update(self, **fields: Any) -> None:
        self._state.update(fields)
        self._state["updated_at"] = time.time()
        self._write()

    def increment(self, field: str, by: int = 1) -> None:
        self._state[field] = self._state.get(field, 0) + by
        self._state["updated_at"] = time.time()
        self._write()

    def _write(self) -> None:
        fd, tmp_path = tempfile.mkstemp(dir=self._path.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self._state, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self._path)
        except BaseException:
            Path(tmp_path).unlink(missing_ok=True)
            raise


def read_health(health_dir: Path, service: str) -> dict[str, Any] | None:
    path = health_dir / f"{service}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
