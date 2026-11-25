"""Zero-token precheck probes and routine execution (Lark payments ops, GitHub issue probe, delegated runner)."""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
from email.utils import parseaddr
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .db import AutopilotDB
from .models import AutopilotError, WorkflowConfig, read_nonempty_token_file, sanitize_terminal_text

_KNOWN_MAIL_NOISE = frozenset(
    {
        "no-reply@sns.amazonaws.com",
        "hello@team.novu.co",
        "notifications@github.com",
    }
)


def probe_github_issues_zero_token(cfg: WorkflowConfig, db: AutopilotDB) -> dict[str, Any]:
    """Zero-LLM-token probe for actionable GitHub issues across project repos."""
    if not cfg.enabled:
        return {"actionable": False, "reason": "project_disabled", "candidates": []}

    prow = db.get_project_row(cfg.project_id)
    if prow is not None:
        if not int(prow["enabled"]):
            return {"actionable": False, "reason": "project_disabled_in_db", "candidates": []}
        cap = int(prow["max_in_progress"]) if int(prow["current_step_idx"]) > 0 else min(cfg.max_in_progress, int(prow["max_in_progress"]))
    else:
        cap = cfg.max_in_progress
    active_cnt = db._conn.execute(
        "SELECT COUNT(*) AS c FROM run_claims WHERE project_id = ? AND state IN ('active', 'reclaiming')",
        (cfg.project_id,),
    ).fetchone()["c"]
    if int(active_cnt) >= cap:
        return {"actionable": False, "reason": f"wip_limit_reached:{active_cnt}/{cap}", "candidates": []}
    if cfg.max_per_day > 0:
        day_start = dt.datetime.now(dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        today_cnt = db._conn.execute(
            "SELECT COUNT(*) AS c FROM run_claims WHERE project_id = ? AND created_at >= ?",
            (cfg.project_id, day_start),
        ).fetchone()["c"]
        if int(today_cnt) >= cfg.max_per_day:
            return {"actionable": False, "reason": f"daily_cap_reached:{today_cnt}/{cfg.max_per_day}", "candidates": []}

    env = dict(os.environ)
    env["GH_PROMPT_DISABLED"] = "1"
    if cfg.token_file:
        try:
            tok = read_nonempty_token_file(cfg.token_file)
        except AutopilotError:
            return {
                "actionable": False,
                "reason": f"waiting_token:{Path(cfg.token_file).expanduser()}",
                "candidates": [],
            }
        env.pop("GITHUB_TOKEN", None)
        env["GH_TOKEN"] = tok

    candidates: list[dict[str, Any]] = []
    blocked_units: list[str] = []
    repo_errors: dict[str, str] = {}
    skip_set = {s.lower() for s in cfg.skip_labels}
    prio_set = {s.lower() for s in cfg.priority_labels}

    for repo in cfg.repos:
        cmd = [
            "gh",
            "issue",
            "list",
            "--repo",
            repo,
            "--state",
            "open",
            "--limit",
            "25",
            "--json",
            "number,title,labels,assignees,updatedAt",
        ]
        if cfg.assignee:
            cmd.extend(["--assignee", cfg.assignee])
        try:
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=25, check=False)
        except (subprocess.SubprocessError, OSError) as exc:
            repo_errors[repo] = f"gh_probe_timeout_or_os_error({repo}): {sanitize_terminal_text(str(exc), 200)}"
            continue
        if proc.returncode != 0:
            repo_errors[repo] = f"gh_probe_error({repo}): {sanitize_terminal_text(proc.stderr, 200)}"
            continue
        try:
            issues = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as exc:
            repo_errors[repo] = f"gh_probe_bad_json({repo}): {exc}"
            continue
        for item in issues:
            num = int(item["number"])
            ukey = f"{repo}#{num}"
            lbls = {str(l.get("name") or "").lower() for l in (item.get("labels") or [])}
            if lbls & skip_set:
                continue
            existing = db.get_unit(ukey)
            if existing:
                if existing["terminal_state"] in ("done", "needs-human") or int(existing["veto_pending"]):
                    continue
                if existing["status"] in ("running", "published"):
                    continue
                if existing["waiting_until"] and str(existing["waiting_until"]) > dt.datetime.now(dt.timezone.utc).isoformat():
                    continue
                scope = db.resolve_unit_scope_and_pending(ukey)
                if scope.any_veto != 0 or scope.pending_cnt != 0:
                    blocked_units.append(ukey)
                    continue
            candidates.append(
                {
                    "unit_key": ukey,
                    "repo": repo,
                    "number": num,
                    "title": item.get("title") or "",
                    "priority": 0 if (lbls & prio_set) else 1,
                }
            )

    candidates.sort(key=lambda c: (c["priority"], c["number"]))
    if candidates:
        reason = "found_open_issues"
    elif blocked_units:
        reason = "blocked_pending_ops"
    elif repo_errors:
        reason = next(iter(repo_errors.values()))
    else:
        reason = "no_open_issues"
    return {
        "actionable": len(candidates) > 0,
        "reason": reason,
        "candidates": candidates,
        "blocked_units": blocked_units,
        "repo_errors": repo_errors,
    }


def probe_lark_payments_zero_token(cfg: WorkflowConfig, db: AutopilotDB) -> dict[str, Any]:
    """Zero-token inbox probe for Lark mail routines configured via `WORKFLOW.md` `extra.mailbox`."""
    if not cfg.enabled:
        return {"actionable": False, "reason": "project_disabled", "pending_ids": []}

    ws = Path(cfg.workspace_path).expanduser().resolve()
    mailbox = str(cfg.extra.get("mailbox") or os.environ.get("AUTOPILOT_LARK_MAILBOX") or "").strip()
    if not mailbox:
        return {"actionable": False, "reason": "missing_mailbox_in_workflow_extra", "pending_ids": []}
    noise_set = _KNOWN_MAIL_NOISE | {str(s).strip().lower() for s in (cfg.extra.get("ignore_senders") or []) if str(s).strip()}
    zone = ZoneInfo(str(cfg.extra.get("timezone") or "America/Los_Angeles"))
    last_run_file = ws / "last_full_run"
    processed_file = ws / "processed_ids.txt"
    now = dt.datetime.now(zone)

    last = (
        dt.datetime.fromtimestamp(last_run_file.stat().st_mtime, zone)
        if last_run_file.exists()
        else now - dt.timedelta(days=7)
    )
    since = last - dt.timedelta(days=1)
    due_followup = (now - last) >= dt.timedelta(days=1)
    seen = set(processed_file.read_text(encoding="utf-8").splitlines()) if processed_file.exists() else set()

    # Check if an autopilot claim is already active or daily cap is reached for this routine
    active = db._conn.execute(
        "SELECT COUNT(*) AS c FROM run_claims WHERE project_id = ? AND state IN ('active', 'reclaiming')",
        (cfg.project_id,),
    ).fetchone()["c"]
    if int(active) > 0:
        return {"actionable": False, "reason": "already_running_in_autopilot", "pending_ids": []}
    if cfg.max_per_day > 0:
        day_start = dt.datetime.now(dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        today_cnt = db._conn.execute(
            "SELECT COUNT(*) AS c FROM run_claims WHERE project_id = ? AND created_at >= ?",
            (cfg.project_id, day_start),
        ).fetchone()["c"]
        if int(today_cnt) >= cfg.max_per_day:
            return {"actionable": False, "reason": f"daily_cap_reached:{today_cnt}/{cfg.max_per_day}", "pending_ids": []}

    pending: list[str] = []
    tokens: set[str] = set()
    page_token: str | None = None
    try:
        while True:
            cmd = [
                "lark-cli",
                "mail",
                "+triage",
                "--mailbox",
                mailbox,
                "--folder",
                "INBOX",
                "--max",
                "30",
                "--format",
                "json",
            ]
            if page_token:
                cmd.extend(["--page-token", page_token])
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=40, check=True)
            data = json.loads(res.stdout)
            if data.get("mailbox_id") != mailbox or not isinstance(data.get("messages"), list):
                raise AutopilotError("Unexpected lark-cli mailbox response")
            past_window = False
            for msg in data["messages"]:
                received = dt.datetime.fromisoformat(msg["date"])
                if received.tzinfo is None:
                    received = received.replace(tzinfo=zone)
                if received < since:
                    past_window = True
                    continue
                mid = str(msg["message_id"])
                sender = parseaddr(msg.get("from", ""))[1].lower()
                if mid not in seen and sender not in noise_set:
                    pending.append(mid)
                    seen.add(mid)
            if pending or due_followup:
                break
            if past_window or not data.get("has_more"):
                break
            page_token = data.get("page_token")
            if not page_token or page_token in tokens:
                break
            tokens.add(page_token)
    except Exception as exc:
        return {"actionable": False, "reason": f"lark_probe_deferred:{type(exc).__name__}", "pending_ids": []}

    actionable = bool(pending or due_followup)
    return {
        "actionable": actionable,
        "reason": "new_mail_or_daily_due" if actionable else "inbox_quiescent",
        "pending_ids": pending,
        "due_followup": due_followup,
        "checked_at": now.strftime("%Y-%m-%d %H:%M %Z"),
    }


def probe_delegated_zero_token(cfg: WorkflowConfig, db: AutopilotDB) -> dict[str, Any]:
    """Zero-token probe for delegated repo runners with optional dedicated token requirement."""
    if not cfg.enabled:
        return {"actionable": False, "reason": "project_disabled"}
    if cfg.token_file:
        try:
            read_nonempty_token_file(cfg.token_file)
        except AutopilotError:
            return {"actionable": False, "reason": f"waiting_dedicated_token:{Path(cfg.token_file).expanduser()}"}

    ws = Path(cfg.workspace_path).expanduser().resolve()
    ap_cfg = ws / "config" / "autopilot.json"
    if ap_cfg.is_file():
        raw = json.loads(ap_cfg.read_text(encoding="utf-8"))
        if not (raw.get("runner") or {}).get("enabled", False):
            return {"actionable": False, "reason": "delegated_runner_disabled_in_repo_config"}
    return probe_github_issues_zero_token(cfg, db)


def probe_project_zero_token(cfg: WorkflowConfig, db: AutopilotDB) -> dict[str, Any]:
    """Dispatch zero-token precheck for any project kind without waking any LLM."""
    if cfg.kind == "issue":
        return probe_github_issues_zero_token(cfg, db)
    if cfg.kind == "delegated":
        return probe_delegated_zero_token(cfg, db)
    if cfg.kind == "routine":
        if cfg.routine_driver == "lark_payments":
            return probe_lark_payments_zero_token(cfg, db)
        if cfg.routine_driver == "dream":
            cnt = db._conn.execute("SELECT COUNT(*) AS c FROM pitfalls").fetchone()["c"]
            hist = db._conn.execute("SELECT COUNT(*) AS c FROM run_history WHERE matured_clean = 0").fetchone()["c"]
            return {
                "actionable": int(cnt) > 0 or int(hist) > 0,
                "reason": f"pitfalls={cnt},unmatured_runs={hist}",
            }
    return {"actionable": False, "reason": f"unknown_driver:{cfg.kind}/{cfg.routine_driver}"}
