"""Daily Dream consolidation and closed-loop zero-token self-evolution engine."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import statistics
from pathlib import Path
from typing import Any, Callable

from .db import AutopilotDB
from .host_guard import _read_load1, load_global_limits
from .models import (
    AutopilotError,
    POLICY_MANIFEST,
    WorkflowConfig,
    default_cache_root,
    default_config_root,
    default_state_root,
    ensure_secure_dir,
    now_iso,
    now_utc,
    parse_workflow_file,
    resolve_cross_family_referees,
    sanitize_terminal_text,
)

_SEVERITY_ORDER = {"high": 0, "med": 1, "low": 2}
_DEFAULT_EXPERIMENT_TTL_DAYS = 7
_DEFAULT_REVIEW_HOURS = 24
_STALE_CACHE_AGE_DAYS = 7


def _parse_iso_utc(raw: Any) -> dt.datetime | None:
    if not raw:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _detect_host_cli_families(host_cli_families: set[str] | None) -> set[str]:
    if host_cli_families is not None:
        return {str(f).strip().lower() for f in host_cli_families if str(f).strip()}
    found: set[str] = set()
    for fam, exe in (("codex", "codex"), ("claude", "claude"), ("agy", "agy")):
        if shutil.which(exe):
            found.add(fam)
    return found


def _workflow_file_path(project_id: str, config_root: Path | None = None) -> Path:
    croot = config_root or default_config_root()
    return croot / "projects" / project_id / "WORKFLOW.md"


def _read_workflow_frontmatter(wf_path: Path) -> tuple[dict[str, Any], str]:
    if not wf_path.is_file() or wf_path.is_symlink():
        raise AutopilotError(f"WORKFLOW.md missing or symlink: {wf_path}")
    raw = wf_path.read_text(encoding="utf-8")
    if not raw.startswith("---\n"):
        raise AutopilotError(f"WORKFLOW.md missing frontmatter delimiter: {wf_path}")
    rest = raw[4:]
    sep_idx = rest.find("\n---")
    if sep_idx < 0:
        raise AutopilotError(f"WORKFLOW.md missing closing frontmatter delimiter: {wf_path}")
    data = json.loads(rest[:sep_idx])
    if not isinstance(data, dict):
        raise AutopilotError(f"WORKFLOW.md frontmatter is not a JSON object: {wf_path}")
    return data, rest[sep_idx:]


def _update_workflow_frontmatter(
    wf_path: Path,
    updates: dict[str, Any],
    *,
    expected_current: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Atomically update & schema-validate `WORKFLOW.md` (`0600`). Skips keys modified externally if `expected_current` is set."""
    data, tail = _read_workflow_frontmatter(wf_path)
    previous: dict[str, Any] = {}
    skipped_keys: list[str] = []
    for k, v in updates.items():
        cur_val = data.get(k) if k in data else "__MISSING__"
        if expected_current is not None and k in expected_current and cur_val != expected_current[k]:
            skipped_keys.append(k)
            continue
        previous[k] = cur_val
        if v == "__MISSING__":
            data.pop(k, None)
        else:
            data[k] = v
    if not previous:
        return {}, skipped_keys
    new_text = "---\n" + json.dumps(data, ensure_ascii=False, indent=2) + tail
    tmp = wf_path.with_name(f".{wf_path.name}.tmp.{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        try:
            os.write(fd, new_text.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        parse_workflow_file(tmp)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    os.replace(tmp, wf_path)
    return previous, skipped_keys


def _scan_deep_stale_cache_dirs(db: AutopilotDB, cache_root: Path, ref_now: dt.datetime) -> list[str]:
    """Scan nested `claim-*` run dirs older than 7d NOT referenced by active/reclaiming claims (never touches git worktrees)."""
    if not cache_root.is_dir():
        return []
    active_paths: set[str] = set()
    for row in db._conn.execute(
        "SELECT run_dir, worktree_path FROM run_claims WHERE state IN ('active', 'reclaiming')"
    ).fetchall():
        for col in ("run_dir", "worktree_path"):
            val = str(row[col] or "").strip()
            if val:
                try:
                    active_paths.add(os.path.normpath(str(Path(val).resolve())))
                except OSError:
                    active_paths.add(os.path.normpath(val))
    cutoff_ts = ref_now.timestamp() - _STALE_CACHE_AGE_DAYS * 86400
    root_real = cache_root.resolve()
    candidates: list[Path] = []
    patterns = (
        ("delegated", "*", "claim-*"),
        ("*", "runs", "claim-*"),
        ("*", "*", "runs", "claim-*"),
    )
    for pat in patterns:
        for p in root_real.glob("/".join(pat)):
            if p.is_dir() and not p.is_symlink():
                candidates.append(p)
    stale: list[str] = []
    seen: set[str] = set()
    for p in sorted(candidates):
        try:
            real_p = str(p.resolve())
        except OSError:
            continue
        norm_p = os.path.normpath(real_p)
        if norm_p in seen or norm_p in active_paths:
            continue
        seen.add(norm_p)
        try:
            if not real_p.startswith(str(root_real) + os.sep):
                continue
            if p.stat().st_mtime < cutoff_ts:
                stale.append(norm_p)
        except OSError:
            continue
    return stale


def sync_project_pitfalls_markdown(
    db: AutopilotDB,
    project_id: str,
    *,
    state_root: Path | None = None,
    advisory_dir: Path | None = None,
) -> Path:
    """Immediately refresh `PITFALLS.md` from SQLite so the very next issue run inherits newly learned code pitfalls."""
    max_chars = int(POLICY_MANIFEST["chef_pipeline"]["max_pitfall_rule_chars"])
    rows = db._conn.execute(
        "SELECT * FROM pitfalls WHERE project_id = ? ORDER BY hits DESC, updated_at DESC LIMIT 50",
        (project_id,),
    ).fetchall()
    adv_dir = ensure_secure_dir(
        advisory_dir if advisory_dir is not None else ((state_root or default_state_root()) / "advisory" / project_id),
        0o700,
    )
    pit_md = adv_dir / "PITFALLS.md"
    lines = [
        f"# {project_id} Pitfall Rules (Advisory — Excluded from Referee & Visual)",
        "",
    ]
    for r in rows:
        sym = sanitize_terminal_text(r["symptom"], max_chars)
        rul = sanitize_terminal_text(r["rule_text"], max_chars)
        lines.append(f"- [{r['target_area']}] {sym} -> {rul} (hits={r['hits']})")
    pit_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return pit_md


def count_matureable_runs(db: AutopilotDB, *, now: dt.datetime | None = None) -> int:
    """Count clean published runs eligible for Dream 48h maturation (shared by precheck and consolidator)."""
    ref_now = now or now_utc()
    maturity_hours = int(POLICY_MANIFEST["chef_pipeline"]["staircase_maturity_hours"])
    cutoff_iso = (ref_now - dt.timedelta(hours=maturity_hours)).replace(microsecond=0).isoformat()
    row = db._conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM run_history h
        JOIN work_units u ON u.unit_key = h.unit_key
        WHERE h.status = 'published'
          AND h.matured_clean = 0
          AND h.completed_at <= ?
          AND u.veto_pending = 0
          AND COALESCE(u.terminal_state, '') != 'needs-human'
        """,
        (cutoff_iso,),
    ).fetchone()
    return int(row["c"]) if row else 0


def _compute_system_metrics(
    db: AutopilotDB,
    *,
    state_root: Path,
    workflows: list[WorkflowConfig],
    host_cli_families: set[str],
    ref_now: dt.datetime,
    disk_usage_fn: Callable[[Path], tuple[int, int, int]] | None = None,
    load1_fn: Callable[[], float | None] | None = None,
    cache_root: Path | None = None,
) -> dict[str, Any]:
    """Compute ratio + rolling-7d-baseline metrics per project and host (100% read-only, zero LLM tokens)."""
    cutoff_24h = (ref_now - dt.timedelta(hours=24)).replace(microsecond=0).isoformat()
    cutoff_7d = (ref_now - dt.timedelta(days=7)).replace(microsecond=0).isoformat()
    wf_by_id = {w.project_id: w for w in workflows}
    proj_rows = {str(r["project_id"]): dict(r) for r in db._conn.execute("SELECT * FROM projects").fetchall()}
    limits = load_global_limits()
    load1 = load1_fn() if load1_fn is not None else _read_load1(Path("/proc/loadavg"))

    claims_7d = db._conn.execute(
        """
        SELECT claim_epoch, project_id, unit_key, unit_kind, state, outcome, created_at, released_at
        FROM run_claims
        WHERE created_at >= ?
        """,
        (cutoff_7d,),
    ).fetchall()
    claims_by_proj: dict[str, list[dict[str, Any]]] = {}
    for c in claims_7d:
        claims_by_proj.setdefault(str(c["project_id"]), []).append(dict(c))

    # Turn usage grouped by claim_epoch (7d)
    turn_rows = db._conn.execute(
        """
        SELECT project_id, claim_epoch,
               COUNT(*) AS turns,
               COALESCE(SUM(cache_read_tokens), 0) AS cache_read,
               COALESCE(SUM(CASE WHEN cost_known = 1 THEN COALESCE(cost_usd, 0.0) ELSE 0.0 END), 0.0) AS cost_usd,
               MAX(cost_known) AS any_cost_known,
               MIN(created_at) AS first_at
        FROM turn_usage_ledger
        WHERE created_at >= ?
        GROUP BY project_id, claim_epoch
        """,
        (cutoff_7d,),
    ).fetchall()
    usage_by_proj: dict[str, list[dict[str, Any]]] = {}
    for tr in turn_rows:
        usage_by_proj.setdefault(str(tr["project_id"]), []).append(dict(tr))

    # Settled review attempts (7d)
    rev_rows = db._conn.execute(
        """
        SELECT u.project_id AS project_id,
               COUNT(*) AS total,
               SUM(CASE WHEN ra.state = 'revise' THEN 1 ELSE 0 END) AS rejected
        FROM review_attempts ra
        JOIN work_units u ON u.unit_key = ra.unit_key
        WHERE ra.created_at >= ?
          AND ra.state IN ('approved', 'revise')
        GROUP BY u.project_id
        """,
        (cutoff_7d,),
    ).fetchall()
    rev_by_proj = {str(r["project_id"]): (int(r["total"]), int(r["rejected"] or 0)) for r in rev_rows}

    wu_rework_rows = db._conn.execute(
        """
        SELECT project_id, COUNT(*) AS high_round_units
        FROM work_units
        WHERE updated_at >= ? AND review_rounds_used >= 3
        GROUP BY project_id
        """,
        (cutoff_7d,),
    ).fetchall()
    high_round_by_proj = {str(r["project_id"]): int(r["high_round_units"]) for r in wu_rework_rows}

    pub_24h_rows = db._conn.execute(
        """
        SELECT u.project_id AS project_id, COUNT(DISTINCT h.unit_key) AS pub_units
        FROM run_history h
        JOIN work_units u ON u.unit_key = h.unit_key
        WHERE h.completed_at >= ?
          AND h.status IN ('published', 'merged', 'closed', 'done')
        GROUP BY u.project_id
        """,
        (cutoff_24h,),
    ).fetchall()
    pub_units_24h_by_proj = {str(r["project_id"]): int(r["pub_units"] or 0) for r in pub_24h_rows}

    all_pids = sorted(set(proj_rows.keys()) | set(wf_by_id.keys()) | set(claims_by_proj.keys()))
    per_project: dict[str, dict[str, Any]] = {}
    min_clean = int(POLICY_MANIFEST["chef_pipeline"]["staircase_min_clean_runs"])

    for pid in all_pids:
        wf = wf_by_id.get(pid)
        prow = proj_rows.get(pid)
        ukind = wf.kind if wf else (str(prow["kind"]) if prow else "")
        if ukind == "routine":
            continue
        enabled = bool(wf.enabled) if wf is not None else bool(prow["enabled"] if prow else True)
        if not enabled:
            continue

        clist = claims_by_proj.get(pid, [])
        rel_7d = [c for c in clist if c["state"] == "released"]
        rel_24h = [c for c in rel_7d if str(c["created_at"] or "") >= cutoff_24h]

        null_cnt_7d = sum(1 for c in rel_7d if not str(c.get("outcome") or "").strip())
        null_rate_7d = (null_cnt_7d / len(rel_7d)) if rel_7d else 0.0

        fail_or_nh_7d = sum(
            1
            for c in rel_7d
            if str(c.get("outcome") or "").startswith("failed") or "needs-human" in str(c.get("outcome") or "")
        )
        fail_rate_7d = (fail_or_nh_7d / len(rel_7d)) if rel_7d else 0.0

        dur_24h: list[float] = []
        productive_24h = 0
        unit_stats_24h: dict[str, list[float]] = {}
        for c in rel_24h:
            st_dt = _parse_iso_utc(c["created_at"])
            en_dt = _parse_iso_utc(c["released_at"])
            if st_dt and en_dt and en_dt >= st_dt:
                secs = (en_dt - st_dt).total_seconds()
                dur_24h.append(secs)
                uk = str(c.get("unit_key") or "")
                if uk:
                    unit_stats_24h.setdefault(uk, []).append(secs)
                out_s = str(c.get("outcome") or "")
                if secs >= 180.0 and (out_s.startswith("succeeded") or out_s == "published"):
                    productive_24h += 1
        short_cnt_24h = sum(1 for s in dur_24h if s < 180.0)
        short_spin_rate_24h = (short_cnt_24h / len(dur_24h)) if dur_24h else 0.0
        long_runs_24h = sum(1 for s in dur_24h if s >= 180.0)
        slot_hours_24h = sum(dur_24h) / 3600.0
        pub_units_24h = pub_units_24h_by_proj.get(pid, 0)
        max_unit_runs_24h = 0
        max_unit_slot_hours_24h = 0.0
        max_unit_key_24h = ""
        for uk, u_durs in unit_stats_24h.items():
            uh = sum(u_durs) / 3600.0
            if (len(u_durs), uh) > (max_unit_runs_24h, max_unit_slot_hours_24h):
                max_unit_runs_24h = len(u_durs)
                max_unit_slot_hours_24h = uh
                max_unit_key_24h = uk

        substantial_7d = 0
        for c in rel_7d:
            st_dt = _parse_iso_utc(c["created_at"])
            en_dt = _parse_iso_utc(c["released_at"])
            if st_dt and en_dt and (en_dt - st_dt).total_seconds() >= 60.0:
                substantial_7d += 1

        # Effective cap
        eff_cap = int(prow["max_in_progress"]) if prow is not None else (int(wf.max_in_progress) if wf else 1)
        if ukind == "delegated" and wf is not None and wf.extra.get("delegated_multi_slot") is not True:
            eff_cap = 1
        clean_matured = int(prow["clean_matured_runs"]) if prow is not None else 0

        # Rolling 7d baseline vs recent 24h cost/cache_read/turns
        u_list = usage_by_proj.get(pid, [])
        base_u = [u for u in u_list if str(u["first_at"] or "") < cutoff_24h]
        rec_u = [u for u in u_list if str(u["first_at"] or "") >= cutoff_24h]
        cost_ratio = 0.0
        cache_ratio = 0.0
        turns_ratio = 0.0
        rec_med_cache = 0.0
        rec_med_cost = 0.0
        rec_med_turns = 0.0
        if len(base_u) >= 3 and len(rec_u) >= 1:
            base_cache = statistics.median(float(u["cache_read"] or 0) for u in base_u)
            rec_med_cache = statistics.median(float(u["cache_read"] or 0) for u in rec_u)
            if base_cache > 0:
                cache_ratio = rec_med_cache / base_cache

            base_turns = statistics.median(float(u["turns"] or 0) for u in base_u)
            rec_med_turns = statistics.median(float(u["turns"] or 0) for u in rec_u)
            if base_turns > 0:
                turns_ratio = rec_med_turns / base_turns

            base_costs = [float(u["cost_usd"]) for u in base_u if int(u["any_cost_known"] or 0) == 1]
            rec_costs = [float(u["cost_usd"]) for u in rec_u if int(u["any_cost_known"] or 0) == 1]
            if len(base_costs) >= 3 and rec_costs:
                bc_med = statistics.median(base_costs)
                rec_med_cost = statistics.median(rec_costs)
                if bc_med > 0:
                    cost_ratio = rec_med_cost / bc_med

        rev_tot, rev_rej = rev_by_proj.get(pid, (0, 0))
        rev_rej_rate = (rev_rej / rev_tot) if rev_tot else 0.0
        high_round_units = high_round_by_proj.get(pid, 0)

        cost_reg_flag = (
            (cache_ratio >= 2.0 and rec_med_cache >= 2_000_000)
            or (cost_ratio >= 2.0 and rec_med_cost >= 1.0)
            or (turns_ratio >= 2.0 and rec_med_turns >= 15.0)
        )
        rework_flag = (rev_tot >= 4 and rev_rej_rate > 0.60) or high_round_units >= 2
        issue_zero_delivery_burn = (
            ukind == "issue"
            and (
                (slot_hours_24h >= 3.0 and long_runs_24h >= 6 and pub_units_24h == 0)
                or (max_unit_runs_24h >= 8 and max_unit_slot_hours_24h >= 3.0)
            )
        )
        delegated_heavy_burn = ukind == "delegated" and slot_hours_24h >= 6.0 and long_runs_24h >= 8
        unhealthy = (
            (len(rel_7d) >= 4 and null_rate_7d >= 0.20)
            or (len(rel_7d) >= 4 and fail_rate_7d >= 0.35)
            or (len(dur_24h) >= 6 and short_spin_rate_24h >= 0.35)
            or cost_reg_flag
            or rework_flag
            or issue_zero_delivery_burn
        )

        refs = resolve_cross_family_referees(wf.writer_family, wf.referee_families) if wf is not None else ()
        per_project[pid] = {
            "project_id": pid,
            "kind": ukind,
            "effective_cap": eff_cap,
            "clean_matured_runs": clean_matured,
            "staircase_min_clean": min_clean,
            "released_7d": len(rel_7d),
            "null_outcome_cnt_7d": null_cnt_7d,
            "null_outcome_rate_7d": round(null_rate_7d, 4),
            "fail_or_nh_cnt_7d": fail_or_nh_7d,
            "fail_or_nh_rate_7d": round(fail_rate_7d, 4),
            "timed_claims_24h": len(dur_24h),
            "short_spin_cnt_24h": short_cnt_24h,
            "short_spin_rate_24h": round(short_spin_rate_24h, 4),
            "long_runs_24h": long_runs_24h,
            "slot_hours_24h": round(slot_hours_24h, 2),
            "published_units_24h": pub_units_24h,
            "max_unit_runs_24h": max_unit_runs_24h,
            "max_unit_slot_hours_24h": round(max_unit_slot_hours_24h, 2),
            "max_unit_key_24h": max_unit_key_24h,
            "issue_zero_delivery_burn": issue_zero_delivery_burn,
            "delegated_heavy_burn": delegated_heavy_burn,
            "productive_24h": productive_24h,
            "substantial_7d": substantial_7d,
            "usage_runs_7d": len(u_list),
            "cost_ratio_vs_7d": round(cost_ratio, 3),
            "cache_ratio_vs_7d": round(cache_ratio, 3),
            "turns_ratio_vs_7d": round(turns_ratio, 3),
            "recent_med_cache_read": round(rec_med_cache, 1),
            "recent_med_cost_usd": round(rec_med_cost, 4),
            "recent_med_turns": round(rec_med_turns, 2),
            "review_attempts_7d": rev_tot,
            "review_rejected_7d": rev_rej,
            "review_reject_rate_7d": round(rev_rej_rate, 4),
            "high_round_units_7d": high_round_units,
            "referee_families": list(refs),
            "writer_family": wf.writer_family if wf is not None else "",
            "schedule_interval_sec": int(wf.schedule_interval_sec) if wf is not None else 0,
            "delegated_multi_slot": bool(wf.extra.get("delegated_multi_slot") is True) if wf is not None else False,
            "unhealthy": unhealthy,
        }

    # Host disk & deep stale cache
    used_pct = 0.0
    free_gb = 0.0
    try:
        if disk_usage_fn is not None:
            total_b, used_b, free_b = disk_usage_fn(state_root)
        else:
            du = shutil.disk_usage(state_root if state_root.exists() else Path("/"))
            total_b, used_b, free_b = du.total, du.used, du.free
        used_pct = round(100.0 * used_b / total_b, 2) if total_b > 0 else 0.0
        free_gb = round(free_b / (1024**3), 2)
    except OSError:
        pass

    croot = cache_root if cache_root is not None else default_cache_root()
    stale_cache_dirs = _scan_deep_stale_cache_dirs(db, croot, ref_now)

    return {
        "checked_at": ref_now.replace(microsecond=0).isoformat(),
        "host_load1": load1,
        "host_max_load1": limits.max_load1,
        "available_cli_families": sorted(host_cli_families),
        "disk_used_pct": used_pct,
        "disk_free_gb": free_gb,
        "stale_cache_count": len(stale_cache_dirs),
        "stale_cache_dirs": stale_cache_dirs,
        "projects": per_project,
    }


def _metric_value_for_experiment(metrics: dict[str, Any], project_id: str, metric_name: str) -> float | None:
    if project_id == "__host__":
        if metric_name == "disk_used_pct":
            return float(metrics["disk_used_pct"])
        if metric_name == "stale_cache_count":
            return float(metrics["stale_cache_count"])
        return None
    pm = metrics["projects"].get(project_id)
    if not pm:
        return None
    val = pm.get(metric_name)
    return float(val) if isinstance(val, (int, float)) else None


def apply_evolution_experiment(
    db: AutopilotDB,
    exp_id: str,
    *,
    config_root: Path | None = None,
    cache_root: Path | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Execute the machine-actionable change for a `proposed` experiment and record rollback state + review window."""
    ref_now = now or now_utc()
    ts = ref_now.replace(microsecond=0).isoformat()
    exp = db.get_evolution_experiment(exp_id)
    if exp is None:
        raise AutopilotError(f"Unknown evolution experiment: {exp_id}")
    if exp["state"] != "proposed":
        raise AutopilotError(f"Experiment {exp_id} is in state={exp['state']!r}, expected 'proposed'")

    action = str(exp["action_kind"])
    payload = dict(exp.get("action_payload") or {})
    pid = str(exp["project_id"])
    rollback_payload: dict[str, Any] = {}
    review_after = (ref_now + dt.timedelta(hours=_DEFAULT_REVIEW_HOURS)).replace(microsecond=0).isoformat()

    if action == "promote_concurrency":
        with db.immediate_tx():
            prow = db.get_project_row(pid)
            if prow is None:
                raise AutopilotError(f"Project {pid!r} not registered in DB")
            rollback_payload = {
                "project_id": pid,
                "max_in_progress": int(prow["max_in_progress"]),
                "current_step_idx": int(prow["current_step_idx"]),
                "clean_matured_runs": int(prow["clean_matured_runs"]),
            }
            force = bool(payload.get("force", False))
            target_cap = int(payload["target_cap"]) if (force and payload.get("target_cap") is not None) else None
            db.approve_concurrency_promotion(pid, force=force, target_cap=target_cap)
            return db.update_evolution_experiment(
                exp_id,
                state="applied",
                expected_states=("proposed",),
                review_after=review_after,
                rollback_payload=rollback_payload,
                now_str=ts,
            )
    elif action == "adjust_cooldown":
        wf_path = _workflow_file_path(pid, config_root)
        cur_data, _ = _read_workflow_frontmatter(wf_path)
        new_sec = int(payload["new_schedule_interval_sec"])
        prev_snap = {"schedule_interval_sec": cur_data.get("schedule_interval_sec", "__MISSING__")}
        applied_snap = {"schedule_interval_sec": new_sec}
        rollback_payload = {"workflow_path": str(wf_path), "updates": prev_snap, "applied_values": applied_snap}
        # Persist `applied` + rollback state BEFORE writing file so a crash never loses the original rollback snapshot.
        db.update_evolution_experiment(
            exp_id,
            state="applied",
            expected_states=("proposed",),
            review_after=review_after,
            rollback_payload=rollback_payload,
            now_str=ts,
        )
        try:
            _update_workflow_frontmatter(wf_path, applied_snap)
        except Exception:
            db.update_evolution_experiment(
                exp_id,
                state="proposed",
                expected_states=("applied",),
                review_after="",
                rollback_payload={},
                now_str=ts,
            )
            raise
        out_exp = db.get_evolution_experiment(exp_id)
        assert out_exp is not None
        return out_exp
    elif action == "enable_dual_referee":
        wf_path = _workflow_file_path(pid, config_root)
        cur_data, _ = _read_workflow_frontmatter(wf_path)
        new_refs = list(payload["new_referee_families"])
        prev_snap = {"referee_families": cur_data.get("referee_families", "__MISSING__")}
        applied_snap = {"referee_families": new_refs}
        rollback_payload = {"workflow_path": str(wf_path), "updates": prev_snap, "applied_values": applied_snap}
        db.update_evolution_experiment(
            exp_id,
            state="applied",
            expected_states=("proposed",),
            review_after=review_after,
            rollback_payload=rollback_payload,
            now_str=ts,
        )
        try:
            _update_workflow_frontmatter(wf_path, applied_snap)
        except Exception:
            db.update_evolution_experiment(
                exp_id,
                state="proposed",
                expected_states=("applied",),
                review_after="",
                rollback_payload={},
                now_str=ts,
            )
            raise
        out_exp = db.get_evolution_experiment(exp_id)
        assert out_exp is not None
        return out_exp
    elif action == "prune_stale_cache":
        croot = (cache_root if cache_root is not None else default_cache_root()).resolve()
        # Re-verify live active/reclaiming claims right before deleting anything.
        live_stale = set(_scan_deep_stale_cache_dirs(db, croot, ref_now))
        removed: list[str] = []
        for raw_dir in payload.get("dirs") or []:
            norm_d = os.path.normpath(str(raw_dir))
            if norm_d not in live_stale:
                continue
            p = Path(norm_d)
            if p.is_dir() and not p.is_symlink() and str(p.resolve()).startswith(str(croot) + os.sep):
                shutil.rmtree(p, ignore_errors=False)
                removed.append(norm_d)
        rollback_payload = {"pruned_count": len(removed), "irreversible": True}
        return db.update_evolution_experiment(
            exp_id,
            state="applied",
            expected_states=("proposed",),
            review_after=review_after,
            rollback_payload=rollback_payload,
            now_str=ts,
        )
    else:
        raise AutopilotError(f"Experiment {exp_id} action_kind={action!r} is diagnostic-only and not auto-executable")


def rollback_evolution_experiment(
    db: AutopilotDB,
    exp_id: str,
    *,
    latest_value: float | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Revert an `applied` experiment using its stored `rollback_payload` (skipping keys edited externally) and mark it `rolled_back`."""
    ref_now = now or now_utc()
    ts = ref_now.replace(microsecond=0).isoformat()
    exp = db.get_evolution_experiment(exp_id)
    if exp is None:
        raise AutopilotError(f"Unknown evolution experiment: {exp_id}")
    if exp["state"] != "applied":
        raise AutopilotError(f"Cannot rollback experiment {exp_id} in state={exp['state']!r}; expected 'applied'")
    action = str(exp["action_kind"])
    rb = dict(exp.get("rollback_payload") or {})

    if action == "promote_concurrency" and rb.get("project_id"):
        with db.immediate_tx():
            updated = db.update_evolution_experiment(
                exp_id,
                state="rolled_back",
                expected_states=("applied",),
                latest_value=latest_value,
                settled_at=ts,
                now_str=ts,
            )
            db._conn.execute(
                "UPDATE projects SET max_in_progress = ?, current_step_idx = ?, clean_matured_runs = ?, updated_at = ? WHERE project_id = ?",
                (
                    int(rb["max_in_progress"]),
                    int(rb["current_step_idx"]),
                    int(rb.get("clean_matured_runs", 0)),
                    ts,
                    str(rb["project_id"]),
                ),
            )
        return updated

    # Claim transition atomically FIRST (CAS on state == 'applied') to prevent double-rollback races;
    # if file restore fails, revert state back to 'applied' so the next audit retries cleanly!
    updated = db.update_evolution_experiment(
        exp_id,
        state="rolled_back",
        expected_states=("applied",),
        latest_value=latest_value,
        settled_at=ts,
        now_str=ts,
    )
    if action in ("adjust_cooldown", "enable_dual_referee") and rb.get("workflow_path") and isinstance(rb.get("updates"), dict):
        wf_path = Path(str(rb["workflow_path"]))
        if wf_path.is_file() and not wf_path.is_symlink():
            exp_cur = rb.get("applied_values") if isinstance(rb.get("applied_values"), dict) else None
            try:
                _update_workflow_frontmatter(wf_path, rb["updates"], expected_current=exp_cur)
            except Exception:
                db.update_evolution_experiment(
                    exp_id,
                    state="applied",
                    expected_states=("rolled_back",),
                    settled_at="",
                    now_str=ts,
                )
                raise

    return updated


def dismiss_evolution_experiment(db: AutopilotDB, exp_id: str, *, now: dt.datetime | None = None) -> dict[str, Any]:
    ref_now = now or now_utc()
    ts = ref_now.replace(microsecond=0).isoformat()
    return db.update_evolution_experiment(
        exp_id,
        state="dismissed",
        expected_states=("proposed",),
        settled_at=ts,
        now_str=ts,
    )


def run_system_efficiency_audit(
    db: AutopilotDB,
    *,
    state_root: Path | None = None,
    workflows: list[WorkflowConfig] | None = None,
    host_cli_families: set[str] | None = None,
    now: dt.datetime | None = None,
    readonly: bool = False,
    disk_usage_fn: Callable[[Path], tuple[int, int, int]] | None = None,
    load1_fn: Callable[[], float | None] | None = None,
    cache_root: Path | None = None,
) -> dict[str, Any]:
    """Closed-loop zero-token efficiency audit: measures ratio+baseline metrics, verifies/rolls back applied experiments, and persists new proposals."""
    sroot = state_root or default_state_root()
    ref_now = now or now_utc()
    ts = ref_now.replace(microsecond=0).isoformat()
    expires_at = (ref_now + dt.timedelta(days=_DEFAULT_EXPERIMENT_TTL_DAYS)).replace(microsecond=0).isoformat()
    wf_list = list(workflows or [])
    avail_families = _detect_host_cli_families(host_cli_families)

    metrics = _compute_system_metrics(
        db,
        state_root=sroot,
        workflows=wf_list,
        host_cli_families=avail_families,
        ref_now=ref_now,
        disk_usage_fn=disk_usage_fn,
        load1_fn=load1_fn,
        cache_root=cache_root,
    )

    findings: list[dict[str, Any]] = []

    def add_finding(
        *,
        project_id: str,
        kind: str,
        severity: str,
        metric_name: str,
        baseline_value: float,
        summary: str,
        evidence: dict[str, Any],
        action_kind: str,
        action_payload: dict[str, Any],
    ) -> None:
        findings.append(
            {
                "project_id": project_id,
                "kind": kind,
                "severity": severity,
                "metric_name": metric_name,
                "baseline_value": round(float(baseline_value), 4),
                "summary": summary,
                "evidence": evidence,
                "action_kind": action_kind,
                "action_payload": action_payload,
            }
        )

    load1 = metrics["host_load1"]
    max_load1 = float(metrics["host_max_load1"])

    for pid, pm in sorted(metrics["projects"].items()):
        # 1. NULL outcome rate (crashes / silent reclaims)
        if pm["released_7d"] >= 4 and pm["null_outcome_rate_7d"] >= 0.20:
            add_finding(
                project_id=pid,
                kind="null_outcome_rate",
                severity="high",
                metric_name="null_outcome_rate_7d",
                baseline_value=pm["null_outcome_rate_7d"],
                summary=f"{pid} has {pm['null_outcome_cnt_7d']}/{pm['released_7d']} ({round(100 * pm['null_outcome_rate_7d'], 1)}%) released claims with NULL outcome in 7d",
                evidence={"null_cnt_7d": pm["null_outcome_cnt_7d"], "released_7d": pm["released_7d"]},
                action_kind="investigate_reclaim",
                action_payload={"command": "agent-autopilot top"},
            )

        # 2. Short idle spin rate (<3 min claims)
        if pm["timed_claims_24h"] >= 6 and pm["short_spin_rate_24h"] >= 0.35:
            cur_int = int(pm["schedule_interval_sec"] or 300)
            new_int = min(1800, max(cur_int + 300, 600))
            can_adjust = pm["kind"] == "delegated" and new_int > cur_int
            add_finding(
                project_id=pid,
                kind="short_spin_rate",
                severity="high",
                metric_name="short_spin_rate_24h",
                baseline_value=pm["short_spin_rate_24h"],
                summary=f"{pid} had {pm['short_spin_cnt_24h']}/{pm['timed_claims_24h']} ({round(100 * pm['short_spin_rate_24h'], 1)}%) short (<3m) spins in 24h",
                evidence={"short_cnt_24h": pm["short_spin_cnt_24h"], "timed_claims_24h": pm["timed_claims_24h"], "schedule_interval_sec": cur_int},
                action_kind="adjust_cooldown" if can_adjust else "investigate_spin",
                action_payload={"new_schedule_interval_sec": new_int} if can_adjust else {"command": "agent-autopilot top"},
            )

        # 3. High failure / needs-human rate
        if pm["released_7d"] >= 4 and pm["fail_or_nh_rate_7d"] >= 0.35:
            add_finding(
                project_id=pid,
                kind="needs_human_or_failure_rate",
                severity="high",
                metric_name="fail_or_nh_rate_7d",
                baseline_value=pm["fail_or_nh_rate_7d"],
                summary=f"{pid} failure/needs-human rate is {pm['fail_or_nh_cnt_7d']}/{pm['released_7d']} ({round(100 * pm['fail_or_nh_rate_7d'], 1)}%) in 7d",
                evidence={"fail_or_nh_cnt_7d": pm["fail_or_nh_cnt_7d"], "released_7d": pm["released_7d"]},
                action_kind="investigate_failures",
                action_payload={"command": "agent-autopilot top"},
            )

        # 4. Slot underutilization (STRICT mutual-exclusion: ONLY when project is healthy and multi-slot is actually supported!)
        multi_slot_ready = pm["kind"] != "delegated" or pm["delegated_multi_slot"]
        if (
            not pm["unhealthy"]
            and multi_slot_ready
            and pm["effective_cap"] <= 1
            and (load1 is None or load1 < max_load1 * 0.5)
            and (pm["clean_matured_runs"] >= pm["staircase_min_clean"] or pm["productive_24h"] >= 6)
        ):
            needs_force = pm["clean_matured_runs"] < pm["staircase_min_clean"]
            cmd_hint = (
                f"agent-autopilot approve-promotion {pid} --force --target 2"
                if needs_force
                else f"agent-autopilot approve-promotion {pid}"
            )
            act_pay: dict[str, Any] = {"project_id": pid, "force": needs_force, "command": cmd_hint}
            if needs_force:
                act_pay["target_cap"] = 2
            add_finding(
                project_id=pid,
                kind="slot_underutilization",
                severity="med",
                metric_name="effective_cap",
                baseline_value=float(pm["effective_cap"]),
                summary=f"Healthy project {pid} ran {pm['productive_24h']} productive runs in 24h (matured={pm['clean_matured_runs']}) on 1 slot while host load1={load1}",
                evidence={
                    "productive_24h": pm["productive_24h"],
                    "clean_matured_runs": pm["clean_matured_runs"],
                    "load1": load1,
                    "command": cmd_hint,
                },
                action_kind="promote_concurrency",
                action_payload=act_pay,
            )

        # 5. Telemetry gap (make both delegated and issue projects observable!)
        if pm["substantial_7d"] >= 4 and pm["usage_runs_7d"] == 0:
            is_del = pm["kind"] == "delegated"
            add_finding(
                project_id=pid,
                kind="delegated_telemetry_missing" if is_del else "telemetry_missing",
                severity="med",
                metric_name="usage_runs_7d",
                baseline_value=0.0,
                summary=f"{pm['kind'].title()} project {pid} had {pm['substantial_7d']} runs (>=60s) in 7d with 0 rows in turn_usage_ledger",
                evidence={"substantial_7d": pm["substantial_7d"], "kind": pm["kind"]},
                action_kind="enable_delegated_telemetry" if is_del else "inspect_telemetry",
                action_payload={"env_var": "AUTOPILOT_TELEMETRY_OUT"} if is_del else {"command": "agent-autopilot doctor"},
            )

        # 6. Own-7d-baseline cost / cache_read / turns regression (>=2x own median + noise floor)
        cache_reg = pm["cache_ratio_vs_7d"] >= 2.0 and pm["recent_med_cache_read"] >= 2_000_000
        cost_reg = pm["cost_ratio_vs_7d"] >= 2.0 and pm["recent_med_cost_usd"] >= 1.0
        turns_reg = pm["turns_ratio_vs_7d"] >= 2.0 and pm["recent_med_turns"] >= 15.0
        if cache_reg or cost_reg or turns_reg:
            metric_n = "cost_ratio_vs_7d" if cost_reg else ("cache_ratio_vs_7d" if cache_reg else "turns_ratio_vs_7d")
            add_finding(
                project_id=pid,
                kind="cost_or_turns_regression",
                severity="high",
                metric_name=metric_n,
                baseline_value=float(pm[metric_n]),
                summary=(
                    f"{pid} 24h median usage regressed >=2x vs 7d baseline "
                    f"(cost_x={pm['cost_ratio_vs_7d']}, cache_x={pm['cache_ratio_vs_7d']}, turns_x={pm['turns_ratio_vs_7d']})"
                ),
                evidence={
                    "cost_ratio_vs_7d": pm["cost_ratio_vs_7d"],
                    "cache_ratio_vs_7d": pm["cache_ratio_vs_7d"],
                    "turns_ratio_vs_7d": pm["turns_ratio_vs_7d"],
                    "recent_med_cache_read": pm["recent_med_cache_read"],
                    "recent_med_cost_usd": pm["recent_med_cost_usd"],
                    "recent_med_turns": pm["recent_med_turns"],
                },
                action_kind="inspect_cost_regression",
                action_payload={"command": "agent-autopilot top"},
            )

        # 7. High review rework (>60% rejection over >=4 settled attempts, or >=2 units hitting >=3 rounds)
        by_rate = pm["review_attempts_7d"] >= 4 and pm["review_reject_rate_7d"] > 0.60
        if by_rate or pm["high_round_units_7d"] >= 2:
            rw_metric = "review_reject_rate_7d" if by_rate else "high_round_units_7d"
            rw_base = float(pm["review_reject_rate_7d"]) if by_rate else float(pm["high_round_units_7d"])
            add_finding(
                project_id=pid,
                kind="high_review_rework",
                severity="high",
                metric_name=rw_metric,
                baseline_value=rw_base,
                summary=(
                    f"{pid} review rework elevated in 7d: "
                    f"{pm['review_rejected_7d']}/{pm['review_attempts_7d']} rejected, {pm['high_round_units_7d']} units >=3 rounds"
                ),
                evidence={
                    "review_attempts_7d": pm["review_attempts_7d"],
                    "review_rejected_7d": pm["review_rejected_7d"],
                    "high_round_units_7d": pm["high_round_units_7d"],
                },
                action_kind="inspect_rework",
                action_payload={"command": "agent-autopilot top"},
            )

        # 8. Underconfigured cross-family review when >=3 CLIs installed
        if pm["kind"] == "issue" and len(avail_families) >= 3 and len(pm["referee_families"]) < 2:
            extra_ref = sorted(avail_families - {pm["writer_family"]} - set(pm["referee_families"]))
            if extra_ref:
                new_refs = sorted(set(pm["referee_families"]) | {extra_ref[0]})
                add_finding(
                    project_id=pid,
                    kind="cross_family_gap",
                    severity="med",
                    metric_name="referee_count",
                    baseline_value=float(len(pm["referee_families"])),
                    summary=f"{pid} runs {len(pm['referee_families'])} referee ({pm['referee_families']}) while host supports {sorted(avail_families)}",
                    evidence={"current_referees": pm["referee_families"], "available_cli_families": sorted(avail_families)},
                    action_kind="enable_dual_referee",
                    action_payload={"new_referee_families": new_refs},
                )

        # 8b. North-Star throughput / time-budget burn detector (catches "all runs succeeded but 0 deliveries / runaway ceremony")
        if pm["issue_zero_delivery_burn"] or pm["delegated_heavy_burn"]:
            is_del = pm["kind"] == "delegated"
            summary_txt = (
                f"Delegated project {pid} burned {pm['slot_hours_24h']} slot-hours across {pm['long_runs_24h']} long runs "
                f"({pm['timed_claims_24h']} total) in 24h — audit ceremony/rework overhead"
                if is_del
                else (
                    f"{pid} burned {pm['slot_hours_24h']} slot-hours ({pm['long_runs_24h']} long runs) in 24h "
                    f"with {pm['published_units_24h']} deliveries (top unit {pm['max_unit_key_24h']}: "
                    f"{pm['max_unit_runs_24h']} runs / {pm['max_unit_slot_hours_24h']}h)"
                )
            )
            add_finding(
                project_id=pid,
                kind="throughput_burn_stall",
                severity="high",
                metric_name="slot_hours_24h",
                baseline_value=float(pm["slot_hours_24h"]),
                summary=summary_txt,
                evidence={
                    "slot_hours_24h": pm["slot_hours_24h"],
                    "long_runs_24h": pm["long_runs_24h"],
                    "timed_claims_24h": pm["timed_claims_24h"],
                    "published_units_24h": pm["published_units_24h"],
                    "max_unit_key_24h": pm["max_unit_key_24h"],
                    "max_unit_runs_24h": pm["max_unit_runs_24h"],
                    "max_unit_slot_hours_24h": pm["max_unit_slot_hours_24h"],
                },
                action_kind="investigate_throughput",
                action_payload={"command": "agent-autopilot top"},
            )

    # 9. Host disk pressure & deep stale cache dirs
    if metrics["disk_used_pct"] >= 80.0:
        add_finding(
            project_id="__host__",
            kind="disk_pressure",
            severity="high" if metrics["disk_used_pct"] >= 90.0 else "med",
            metric_name="disk_used_pct",
            baseline_value=metrics["disk_used_pct"],
            summary=f"Host disk usage at {metrics['disk_used_pct']}% ({metrics['disk_free_gb']} GB free)",
            evidence={"disk_used_pct": metrics["disk_used_pct"], "disk_free_gb": metrics["disk_free_gb"]},
            action_kind="investigate_disk",
            action_payload={"command": "df -h"},
        )
    if metrics["stale_cache_count"] >= 5:
        add_finding(
            project_id="__host__",
            kind="deep_stale_cache",
            severity="med",
            metric_name="stale_cache_count",
            baseline_value=float(metrics["stale_cache_count"]),
            summary=f"{metrics['stale_cache_count']} unreferenced stale (>7d) claim/worktree dirs in local cache",
            evidence={"stale_cache_count": metrics["stale_cache_count"], "sample": metrics["stale_cache_dirs"][:10]},
            action_kind="prune_stale_cache",
            action_payload={"dirs": metrics["stale_cache_dirs"]},
        )

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["project_id"], f["kind"]))

    verified_experiments: list[dict[str, Any]] = []
    rolled_back_experiments: list[dict[str, Any]] = []
    resolved_experiments: list[dict[str, Any]] = []
    synced_experiments: list[dict[str, Any]] = []

    if not readonly and not db.readonly:
        active_pairs = {(f["project_id"], f["kind"]) for f in findings}
        existing = db.list_evolution_experiments(states=("proposed", "applied"))
        for exp in existing:
            exp_id = str(exp["exp_id"])
            pid = str(exp["project_id"])
            kind = str(exp["kind"])
            if exp["state"] == "proposed":
                exp_dt = _parse_iso_utc(exp.get("expires_at"))
                if (pid, kind) not in active_pairs or (exp_dt is not None and ref_now >= exp_dt):
                    try:
                        resolved_experiments.append(
                            db.update_evolution_experiment(
                                exp_id, state="resolved", expected_states=("proposed",), settled_at=ts, now_str=ts
                            )
                        )
                    except AutopilotError:
                        continue
            elif exp["state"] == "applied":
                rev_dt = _parse_iso_utc(exp.get("review_after"))
                if rev_dt is None or ref_now < rev_dt:
                    continue
                latest = _metric_value_for_experiment(metrics, pid, str(exp["metric_name"]))
                base_val = float(exp["baseline_value"])
                action = str(exp["action_kind"])
                improved = False
                if action == "promote_concurrency":
                    pm = metrics["projects"].get(pid)
                    improved = bool(pm is not None and pm["effective_cap"] > base_val and not pm["unhealthy"])
                elif action == "enable_dual_referee":
                    pm = metrics["projects"].get(pid)
                    improved = bool(pm is not None and len(pm["referee_families"]) >= 2 and not pm["unhealthy"])
                elif latest is not None:
                    improved = (latest == 0.0) or (base_val > 0.0 and latest <= base_val * 0.80)

                try:
                    if improved:
                        verified_experiments.append(
                            db.update_evolution_experiment(
                                exp_id,
                                state="verified_better",
                                expected_states=("applied",),
                                latest_value=latest,
                                settled_at=ts,
                                now_str=ts,
                            )
                        )
                    else:
                        rolled_back_experiments.append(
                            rollback_evolution_experiment(db, exp_id, latest_value=latest, now=ref_now)
                        )
                except AutopilotError:
                    continue

        for f in findings:
            up = db.upsert_evolution_experiment(
                project_id=f["project_id"],
                kind=f["kind"],
                severity=f["severity"],
                metric_name=f["metric_name"],
                baseline_value=f["baseline_value"],
                summary=f["summary"],
                evidence=f["evidence"],
                action_kind=f["action_kind"],
                action_payload=f["action_payload"],
                expires_at=expires_at,
                now_str=ts,
            )
            if up is not None:
                synced_experiments.append(up)

    return {
        "checked_at": ts,
        "readonly": bool(readonly or db.readonly),
        "host_load1": load1,
        "available_cli_families": sorted(avail_families),
        "finding_count": len(findings),
        "high_count": sum(1 for f in findings if f["severity"] == "high"),
        "findings": findings,
        "experiments_synced": [e["exp_id"] for e in synced_experiments],
        "experiments_verified_better": [e["exp_id"] for e in verified_experiments],
        "experiments_rolled_back": [e["exp_id"] for e in rolled_back_experiments],
        "experiments_resolved": [e["exp_id"] for e in resolved_experiments],
    }


def run_dream_consolidation(
    db: AutopilotDB,
    *,
    state_root: Path | None = None,
    workflows: list[WorkflowConfig] | None = None,
    host_cli_families: set[str] | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Route code pitfalls to advisory PITFALLS.md, mature >=48h clean runs, and run closed-loop self-evolution audit."""
    sroot = state_root or default_state_root()
    ref_now = now or now_utc()
    maturity_hours = int(POLICY_MANIFEST["chef_pipeline"]["staircase_maturity_hours"])
    max_chars = int(POLICY_MANIFEST["chef_pipeline"]["max_pitfall_rule_chars"])

    # 1. Mature clean runs older than 48h without subsequent veto/rollback on the same unit
    cutoff_iso = (ref_now - dt.timedelta(hours=maturity_hours)).replace(microsecond=0).isoformat()
    matured_count = 0
    with db.immediate_tx():
        rows = db._conn.execute(
            """
            SELECT h.run_id, h.project_id, h.unit_key
            FROM run_history h
            JOIN work_units u ON u.unit_key = h.unit_key
            WHERE h.status = 'published'
              AND h.matured_clean = 0
              AND h.completed_at <= ?
              AND u.veto_pending = 0
              AND COALESCE(u.terminal_state, '') != 'needs-human'
            """,
            (cutoff_iso,),
        ).fetchall()
        for r in rows:
            db._conn.execute("UPDATE run_history SET matured_clean = 1 WHERE run_id = ?", (r["run_id"],))
            db._conn.execute(
                "UPDATE projects SET clean_matured_runs = clean_matured_runs + 1, updated_at = ? WHERE project_id = ?",
                (now_iso(), r["project_id"]),
            )
            matured_count += 1

    # 2. Route code pitfalls per Principle 03 (strictly code pitfalls only — systemic experiments live in evolution_experiments)
    pit_rows = db._conn.execute("SELECT * FROM pitfalls ORDER BY hits DESC, updated_at DESC").fetchall()
    by_project: dict[str, list[dict[str, Any]]] = {}
    by_rule_projects: dict[str, set[str]] = {}
    gate_proposals: list[str] = []
    lesson_proposals: list[str] = []

    for prow in pit_rows:
        p = dict(prow)
        by_project.setdefault(p["project_id"], []).append(p)
        by_rule_projects.setdefault(p["rule_text"], set()).add(p["project_id"])

    for pid, items in by_project.items():
        adv_dir = ensure_secure_dir(sroot / "advisory" / pid, 0o700)
        pit_md = adv_dir / "PITFALLS.md"
        lines = [
            f"# {pid} Pitfall Rules (Advisory — Excluded from Referee & Visual)",
            "",
        ]
        for it in items[:50]:
            sym = sanitize_terminal_text(it["symptom"], max_chars)
            rul = sanitize_terminal_text(it["rule_text"], max_chars)
            lines.append(f"- [{it['target_area']}] {sym} -> {rul} (hits={it['hits']})")

            if int(it["hits"]) >= 2:
                prop_dir = ensure_secure_dir(sroot / "proposals" / it["sig"], 0o700)
                gate_payload = {
                    "sig": it["sig"],
                    "project_id": pid,
                    "target_area": it["target_area"],
                    "hits": int(it["hits"]),
                    "proposed_rule": rul,
                    "requires_human_approval": True,
                }
                raw_json = json.dumps(gate_payload, ensure_ascii=False, indent=2) + "\n"
                gate_payload["sha256"] = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
                gp = prop_dir / "gate_patch.json"
                gp.write_text(json.dumps(gate_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                gate_proposals.append(str(gp))

            if len(by_rule_projects.get(it["rule_text"], set())) >= 2:
                prop_dir = ensure_secure_dir(sroot / "proposals" / it["sig"], 0o700)
                lp = prop_dir / "LESSONS_LEARNED.patch"
                patch_txt = f"+ - **坑点**：{sym} → **规矩**：{rul}\n"
                lp.write_text(patch_txt, encoding="utf-8")
                lesson_proposals.append(str(lp))

        pit_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 3. Check staircase promotion eligibility
    min_clean = int(POLICY_MANIFEST["chef_pipeline"]["staircase_min_clean_runs"])
    steps = POLICY_MANIFEST["chef_pipeline"]["staircase_concurrency_steps"]
    eligible_promotions: list[dict[str, Any]] = []
    for pr in db._conn.execute("SELECT * FROM projects").fetchall():
        idx = int(pr["current_step_idx"])
        if int(pr["clean_matured_runs"]) >= min_clean and idx + 1 < len(steps):
            eligible_promotions.append(
                {
                    "project_id": pr["project_id"],
                    "current_max_in_progress": pr["max_in_progress"],
                    "proposed_max_in_progress": steps[idx + 1],
                    "clean_matured_runs": pr["clean_matured_runs"],
                }
            )

    # 4. Run closed-loop zero-token self-evolution audit
    evolution_audit = run_system_efficiency_audit(
        db,
        state_root=sroot,
        workflows=workflows,
        host_cli_families=host_cli_families,
        now=ref_now,
        readonly=False,
    )

    return {
        "matured_runs": matured_count,
        "projects_updated": sorted(by_project.keys()),
        "gate_proposals": gate_proposals,
        "lesson_proposals": lesson_proposals,
        "eligible_promotions": eligible_promotions,
        "evolution_audit": evolution_audit,
    }
