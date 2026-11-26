"""Host-level compute guards: machine-wide heavy worker cap + CPU steal / load backoff.

Burstable hosts (e.g. Lightsail / t3 class) earn CPU credits only below their baseline; once credits hit zero the
hypervisor throttles the whole VM (visible as CPU steal), which starves interactive desktop / SSH sessions too.
These helpers keep the dispatcher from stacking heavy workers on such a host. All checks are zero-token.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import default_config_root

# Unit kinds that run full writer/verify pipelines (worker-exec / delegated-exec); routines stay exempt.
HEAVY_UNIT_KINDS: tuple[str, ...] = ("issue", "delegated")

DEFAULT_MAX_GLOBAL_IN_PROGRESS = 1
DEFAULT_MAX_STEAL_PCT = 15.0
DEFAULT_MAX_LOAD1 = 4.0
DEFAULT_SAMPLE_SEC = 1.0

# Default child-process fan-out caps injected into tool/verify sandboxes (callers' explicit env still wins).
CPU_FANOUT_LIMIT_ENV: dict[str, str] = {
    "GOMAXPROCS": "2",
    "RAYON_NUM_THREADS": "2",
    "UV_THREADPOOL_SIZE": "2",
    "PLAYWRIGHT_WORKERS": "1",
}


@dataclass(frozen=True)
class GlobalLimits:
    max_global_in_progress: int = DEFAULT_MAX_GLOBAL_IN_PROGRESS
    max_steal_pct: float = DEFAULT_MAX_STEAL_PCT
    max_load1: float = DEFAULT_MAX_LOAD1
    sample_sec: float = DEFAULT_SAMPLE_SEC


def global_settings_path(config_root: Path | None = None) -> Path:
    return (config_root or default_config_root()) / "global.json"


def _num(raw: Any, cast: type, default: Any, lo: Any) -> Any:
    try:
        val = cast(raw)
    except (TypeError, ValueError):
        return default
    if val != val or val < lo:  # NaN / below floor -> keep the safe default
        return default
    return val


def load_global_limits(config_root: Path | None = None) -> GlobalLimits:
    """Read `<config>/global.json` (optional) then env overrides; malformed values fall back to safe defaults."""
    data: dict[str, Any] = {}
    p = global_settings_path(config_root)
    try:
        loaded = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            data = loaded
    except (OSError, ValueError):
        data = {}
    env = os.environ
    cap = _num(env.get("AGENT_AUTOPILOT_MAX_GLOBAL_IN_PROGRESS", data.get("max_global_in_progress")), int,
               DEFAULT_MAX_GLOBAL_IN_PROGRESS, 1)
    steal = _num(env.get("AGENT_AUTOPILOT_HOST_MAX_STEAL_PCT", data.get("host_max_steal_pct")), float,
                 DEFAULT_MAX_STEAL_PCT, 0.0)
    load1 = _num(env.get("AGENT_AUTOPILOT_HOST_MAX_LOAD1", data.get("host_max_load1")), float, DEFAULT_MAX_LOAD1, 0.0)
    samp = _num(env.get("AGENT_AUTOPILOT_HOST_SAMPLE_SEC", data.get("host_sample_sec")), float, DEFAULT_SAMPLE_SEC, 0.0)
    return GlobalLimits(max_global_in_progress=cap, max_steal_pct=steal, max_load1=load1, sample_sec=min(samp, 5.0))


def count_global_heavy_claims(conn: sqlite3.Connection) -> int:
    """Count claims whose worker may still burn CPU. `reclaiming` claims are excluded on purpose: their worker unit is
    already terminated, and a reclaim stuck for human inspection must not wedge every project behind the global cap."""
    marks = ",".join("?" for _ in HEAVY_UNIT_KINDS)
    row = conn.execute(
        f"SELECT COUNT(*) AS c FROM run_claims WHERE state = 'active' AND unit_kind IN ({marks})",
        HEAVY_UNIT_KINDS,
    ).fetchone()
    return int(row[0])


def _read_cpu_ticks(stat_path: Path) -> tuple[int, int] | None:
    """Return (total, steal) jiffies from the aggregate `cpu` line of /proc/stat."""
    try:
        for line in stat_path.read_text(encoding="ascii", errors="replace").splitlines():
            if line.startswith("cpu "):
                vals = [int(x) for x in line.split()[1:]]
                # user nice system idle iowait irq softirq steal [guest guest_nice] -- guest is already in user.
                total = sum(vals[:8])
                steal = vals[7] if len(vals) > 7 else 0
                return total, steal
    except (OSError, ValueError):
        return None
    return None


def _read_load1(loadavg_path: Path) -> float | None:
    try:
        return float(loadavg_path.read_text(encoding="ascii").split()[0])
    except (OSError, ValueError, IndexError):
        return None


def sample_host_pressure(
    limits: GlobalLimits,
    *,
    stat_path: Path = Path("/proc/stat"),
    loadavg_path: Path = Path("/proc/loadavg"),
    sleep: Any = time.sleep,
) -> dict[str, Any]:
    """Sample steal% over `limits.sample_sec` plus 1-minute load; `pressured=True` means hold new heavy workers.

    Unreadable metrics never block dispatch (fail-open on observability, the global cap still bounds concurrency).
    """
    t0 = _read_cpu_ticks(stat_path)
    if limits.sample_sec > 0:
        sleep(limits.sample_sec)
    t1 = _read_cpu_ticks(stat_path)
    steal_pct: float | None = None
    if t0 is not None and t1 is not None and t1[0] > t0[0]:
        steal_pct = round(100.0 * max(0, t1[1] - t0[1]) / (t1[0] - t0[0]), 1)
    load1 = _read_load1(loadavg_path)
    reasons: list[str] = []
    if steal_pct is not None and steal_pct > limits.max_steal_pct:
        reasons.append(f"cpu_steal_pct:{steal_pct}>{limits.max_steal_pct}")
    if load1 is not None and load1 > limits.max_load1:
        reasons.append(f"load1:{load1}>{limits.max_load1}")
    return {
        "pressured": bool(reasons),
        "reasons": reasons,
        "steal_pct": steal_pct,
        "load1": load1,
        "max_steal_pct": limits.max_steal_pct,
        "max_load1": limits.max_load1,
        "sampled_at": time.time(),
    }
