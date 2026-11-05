"""Prometheus metrics via the node-exporter textfile collector (no extra port, no scrape job needed)."""

from __future__ import annotations

import time
from pathlib import Path

from .util import atomic_write

STATUS_CODES = {"up_to_date": 0, "update_available": 1, "ready": 2, "held": 3, "test_failed": 4,
                "notify_only": 5, "ignored": 6, "error": 7, "rolled_back": 8, "candidate": 9}


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def render(state: dict, history_counts: dict) -> str:
    lines = []

    def metric(name, help_, typ, samples):
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} {typ}")
        for labels, value in samples:
            lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items())
            lines.append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")

    g = state.get("global", {})
    metric("update_airlock_last_run_timestamp_seconds", "Unix time of the last run per kind", "gauge",
           [({"kind": k}, v) for k, v in sorted((g.get("last_run") or {}).items())])
    metric("update_airlock_last_run_success", "1 if the last run of this kind finished without error", "gauge",
           [({"kind": k}, int(bool(v))) for k, v in sorted((g.get("last_ok") or {}).items())])
    metric("update_airlock_source_failures", "Consecutive failures reading a source (registry / release notes)",
           "gauge", [({"source": k}, v) for k, v in sorted((g.get("failures") or {}).items())])
    metric("update_airlock_sandbox_isolation_ok", "1 if the last isolation proof passed", "gauge",
           [({}, int(bool(g.get("isolation_ok", 0))))])
    cs = state.get("containers", {})
    metric("update_airlock_container_status", "Status code: " + ", ".join(f"{k}={v}" for k, v in STATUS_CODES.items()),
           "gauge", [({"container": n, "status": c.get("status", "?")}, STATUS_CODES.get(c.get("status"), -1))
                     for n, c in sorted(cs.items())])
    metric("update_airlock_update_available", "1 if a newer image exists", "gauge",
           [({"container": n, "kind": c.get("kind") or "none", "current": c.get("current_version") or "",
              "available": c.get("available_version") or ""}, int(bool(c.get("available_version"))))
            for n, c in sorted(cs.items())])
    metric("update_airlock_last_test_passed", "1 if the last sandbox test passed, 0 if failed", "gauge",
           [({"container": n}, int(c["last_test_passed"])) for n, c in sorted(cs.items())
            if c.get("last_test_passed") is not None])
    metric("update_airlock_last_update_timestamp_seconds", "Unix time of the last real update", "gauge",
           [({"container": n}, c["last_update_ts"]) for n, c in sorted(cs.items()) if c.get("last_update_ts")])
    metric("update_airlock_events_total", "Events by action and result (from the history)", "counter",
           [({"action": a, "result": r}, v) for (a, r), v in sorted(history_counts.items())])
    metric("update_airlock_metrics_written_timestamp_seconds", "When this file was written", "gauge",
           [({}, int(time.time()))])
    return "\n".join(lines) + "\n"


def write(path: str, state: dict, history_counts: dict) -> None:
    if not path:
        return
    p = Path(path)
    if not p.parent.exists():
        return
    atomic_write(p, render(state, history_counts), 0o644)
