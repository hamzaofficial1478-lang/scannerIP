"""Append-only scan history, tagged with the rotating ID rather than the device.

If this file ever leaks, the scans in it can't be traced back to your machine
or even linked to each other across rotations.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from .analyzer import Report
from .identity import IdentitySnapshot, app_home


class ScanLog:
    def __init__(self, path: Path | None = None):
        self.path = path or app_home() / "scan_log.jsonl"
        self._lock = threading.Lock()

    def record(self, fmt: str, report: Report, snapshot: IdentitySnapshot | None) -> dict:
        entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "rotating_id": snapshot.rotating_id if snapshot else None,
            "format": fmt,
            "kind": report.payload.kind,
            "level": report.level,
            "score": report.score,
            "content": report.payload.raw[:500],
            "findings": [f"{f.severity}: {f.message}" for f in report.findings],
        }
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry
