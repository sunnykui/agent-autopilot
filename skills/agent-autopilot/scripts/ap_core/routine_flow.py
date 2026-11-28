"""Zero-token precheck probes and routine execution (Lark payments ops, GitHub issue probe, delegated runner)."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
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


def probe_github_issues_zero_token(
    cfg: WorkflowConfig,
    db: AutopilotDB,
    *,
    extra_require_labels: tuple[str, ...] = (),
) -> dict[str, Any]:
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
    req_labels_ordered: list[str] = []
    seen_req: set[str] = set()
    for raw_r in (*cfg.require_labels, *extra_require_labels):
        clean_r = str(raw_r or "").strip()
        if clean_r and clean_r.lower() not in seen_req:
            seen_req.add(clean_r.lower())
            req_labels_ordered.append(clean_r)
    req_set = set(seen_req)

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
            "100",
            "--json",
            "number,title,labels,assignees,updatedAt",
        ]
        if cfg.assignee and cfg.assignee not in ("*", "all", "ALL"):
            cmd.extend(["--assignee", cfg.assignee])
        for req_lbl in req_labels_ordered:
            cmd.extend(["--label", req_lbl])
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
            if req_set and not req_set.issubset(lbls):
                continue
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


def _resolve_verified_git_metadata_fds(ws_real: Path) -> list[tuple[int, str]]:
    """Open verified linked-worktree gitdir/commondir fds ONLY when proven to be genuine Git metadata directories."""
    from .models import open_dir_nofollow

    dot_git = ws_real / ".git"
    if not dot_git.is_file() or dot_git.is_symlink():
        return []
    txt = dot_git.read_text(encoding="utf-8", errors="replace").strip()
    if not txt.startswith("gitdir:"):
        return []
    raw_gd = txt[len("gitdir:") :].strip()
    gd = (ws_real / raw_gd).resolve() if not os.path.isabs(raw_gd) else Path(raw_gd).resolve()
    opened: list[tuple[int, str]] = []
    try:
        gd_fd = open_dir_nofollow(gd, create=False)
        gd_pin = Path(f"/proc/{os.getpid()}/fd/{gd_fd}")
        gd_real_str = os.readlink(f"/proc/self/fd/{gd_fd}")
        gitdir_back = gd_pin / "gitdir"
        if not (gd_pin / "HEAD").is_file() or not gitdir_back.is_file() or gitdir_back.is_symlink():
            os.close(gd_fd)
            raise AutopilotError(f"Linked worktree gitdir {gd} lacks HEAD/gitdir backpointer; refusing precheck mount")
        reg_back = Path(os.path.normpath(gitdir_back.read_text(encoding="utf-8", errors="replace").strip()))
        exp_back = Path(os.path.normpath(str(ws_real / ".git")))
        if reg_back != exp_back:
            os.close(gd_fd)
            raise AutopilotError(f"Linked worktree gitdir backpointer {reg_back} != {exp_back}; refusing foreign gitdir mount")
        opened.append((gd_fd, gd_real_str))
        comm = gd_pin / "commondir"
        if not comm.is_file() or comm.is_symlink():
            raise AutopilotError(f"Linked worktree gitdir {gd} missing regular commondir file; refusing precheck mount")
        rel_c = comm.read_text(encoding="utf-8", errors="replace").strip()
        cd = (Path(gd_real_str) / rel_c).resolve() if not os.path.isabs(rel_c) else Path(rel_c).resolve()
        if str(cd) == gd_real_str:
            raise AutopilotError(f"Linked worktree commondir {cd} self-references gitdir; refusing precheck mount")
        cd_fd = open_dir_nofollow(cd, create=False)
        cd_pin = Path(f"/proc/{os.getpid()}/fd/{cd_fd}")
        cd_real_str = os.readlink(f"/proc/self/fd/{cd_fd}")
        exp_wt_parent = str(Path(cd_real_str) / "worktrees")
        if not (
            (cd_pin / "objects").is_dir()
            and (cd_pin / "refs").is_dir()
            and (cd_pin / "HEAD").is_file()
            and str(Path(gd_real_str).parent) == exp_wt_parent
        ):
            os.close(cd_fd)
            raise AutopilotError(f"Linked worktree commondir {cd} does not own {gd_real_str}; refusing precheck mount")
        opened.append((cd_fd, cd_real_str))
        return opened
    except BaseException:
        for fd_c, _ in opened:
            try:
                os.close(fd_c)
            except OSError:
                pass
        raise


def _run_readonly_credential_free_precheck(ws: Path, precheck_cmd: str, *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """Execute `precheck_cmd` strictly inside a credential-free, `--unshare-net`, read-only `bwrap` sandbox (fail-closed without `bwrap`)."""
    import contextlib as _ctx
    import shutil as _shutil
    from .models import open_dir_nofollow

    bwrap_bin = _shutil.which("bwrap")
    if not bwrap_bin:
        raise AutopilotError("delegated_precheck_requires_bwrap")

    ws_fd = open_dir_nofollow(ws.resolve(), create=False)
    retain_fds: list[int] = [ws_fd]
    try:
        ws_dest = os.readlink(f"/proc/self/fd/{ws_fd}")
        git_meta_fds = _resolve_verified_git_metadata_fds(Path(ws_dest))
        for gfd, _ in git_meta_fds:
            retain_fds.append(gfd)
        argv: list[str] = [
            bwrap_bin,
            "--die-with-parent",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-net",
            "--new-session",
            "--clearenv",
            "--proc", "/proc",
            "--dev", "/dev",
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64",
            "--tmpfs", "/tmp",
            "--ro-bind-fd", str(ws_fd), ws_dest,
        ]
        for gfd, gdest in git_meta_fds:
            argv.extend(["--ro-bind-fd", str(gfd), gdest])
        argv.extend(
            [
                "--chdir", ws_dest,
                "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
                "--setenv", "HOME", "/tmp",
                "--setenv", "LANG", "C.UTF-8",
                "--",
                "/bin/bash",
                "-c",
                precheck_cmd,
            ]
        )
        return subprocess.run(argv, capture_output=True, text=True, pass_fds=tuple(retain_fds), timeout=timeout, start_new_session=True, check=False)
    finally:
        for _rfd in retain_fds:
            with _ctx.suppress(OSError):
                os.close(_rfd)


def _delegated_open_pr_issue_numbers(cfg: WorkflowConfig, repo: str) -> set[int] | None:
    """Return issue numbers that already have an open PR in `repo`, or `None` if lookup failed/truncated."""
    env = dict(os.environ, GH_PROMPT_DISABLED="1")
    if cfg.token_file:
        try:
            tok = read_nonempty_token_file(cfg.token_file)
        except AutopilotError:
            return None
        env.pop("GITHUB_TOKEN", None)
        env["GH_TOKEN"] = tok
    try:
        proc = subprocess.run(
            [
                "gh",
                "pr",
                "list",
                "--repo",
                repo,
                "--state",
                "open",
                "--limit",
                "200",
                "--json",
                "headRefName,title,closingIssuesReferences",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0:
        return None
    try:
        prs = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return None
    if not isinstance(prs, list):
        return None
    nums: set[int] = set()
    pref = re.escape(cfg.branch_prefix or "agent/")
    branch_re = re.compile(rf"^{pref}(?:issue-)?([1-9][0-9]*)(?:$|[^0-9])")
    # Match `#<num>` in PR title only when not part of a cross-repo ref like `other/repo#42`.
    title_hash_re = re.compile(r"(?<![A-Za-z0-9_./-])#([1-9][0-9]*)(?![0-9])")
    repo_prefix = f"https://github.com/{repo.lower()}/issues/"
    for pr in prs:
        if not isinstance(pr, dict):
            continue
        head = str(pr.get("headRefName") or "")
        m = branch_re.match(head)
        if m:
            nums.add(int(m.group(1)))
        title = str(pr.get("title") or "")
        for hm in title_hash_re.finditer(title):
            nums.add(int(hm.group(1)))
        for ref in pr.get("closingIssuesReferences") or ():
            if not isinstance(ref, dict):
                continue
            r_num = ref.get("number")
            r_url = str(ref.get("url") or "").lower()
            if isinstance(r_num, int) and r_num > 0 and (not r_url or r_url.startswith(repo_prefix)):
                nums.add(r_num)
    if len(prs) >= 200:
        # Truncated list: callers treat None as unknown so cooldown still prevents tight spin.
        return None
    return nums


def delegated_precheck_cooldown_active(cfg: WorkflowConfig, db: AutopilotDB) -> bool:
    """True when the project's most recent claim is younger than `schedule_interval_sec` (continuation-only wakeups)."""
    if cfg.schedule_interval_sec <= 0:
        return False
    row = db._conn.execute("SELECT MAX(created_at) AS m FROM run_claims WHERE project_id = ?", (cfg.project_id,)).fetchone()
    last_iso = row["m"] if row else None
    if not last_iso:
        return False
    try:
        age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(str(last_iso))).total_seconds()
    except ValueError:
        return False
    return age < cfg.schedule_interval_sec


def probe_delegated_zero_token(cfg: WorkflowConfig, db: AutopilotDB) -> dict[str, Any]:
    """Universal zero-token probe for delegated runners (`require_labels` + WIP/daily caps + isolated `extra.precheck_cmd`)."""
    if not cfg.enabled:
        return {"actionable": False, "reason": "project_disabled", "candidates": []}
    prow = db.get_project_row(cfg.project_id)
    if prow is not None and not int(prow["enabled"]):
        return {"actionable": False, "reason": "project_disabled_in_db", "candidates": []}

    cap = (
        (int(prow["max_in_progress"]) if int(prow["current_step_idx"]) > 0 else min(cfg.max_in_progress, int(prow["max_in_progress"])))
        if prow is not None
        else cfg.max_in_progress
    )
    if cfg.extra.get("delegated_multi_slot") is not True:
        cap = 1
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

    if cfg.token_file:
        try:
            read_nonempty_token_file(cfg.token_file)
        except AutopilotError:
            return {"actionable": False, "reason": f"waiting_dedicated_token:{Path(cfg.token_file).expanduser()}", "candidates": []}

    if not cfg.workspace_path or not Path(cfg.workspace_path).expanduser().is_dir():
        return {"actionable": False, "reason": "delegated_workspace_missing", "candidates": []}
    ws = Path(cfg.workspace_path).expanduser().resolve()

    # Respect optional generic runner opt-out file if declared by repo or WORKFLOW.md `extra.runner_config_rel`:
    cfg_rel = str(cfg.extra.get("runner_config_rel") or "config/autopilot.json").strip()
    ap_cfg = ws / cfg_rel if cfg_rel and ".." not in Path(cfg_rel).parts else None
    repo_req_labels: tuple[str, ...] = ()
    if ap_cfg is not None and ap_cfg.is_file() and not ap_cfg.is_symlink():
        try:
            raw = json.loads(ap_cfg.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                if isinstance(raw.get("runner"), dict) and not raw["runner"].get("enabled", False):
                    return {"actionable": False, "reason": "delegated_runner_disabled_in_repo_config", "candidates": []}
                if not cfg.require_labels and isinstance(raw.get("require_labels"), list):
                    repo_req_labels = tuple(str(x).strip() for x in raw["require_labels"] if str(x).strip())
        except (OSError, json.JSONDecodeError):
            return {"actionable": False, "reason": "delegated_repo_config_invalid", "candidates": []}

    res = probe_github_issues_zero_token(cfg, db, extra_require_labels=repo_req_labels)
    if res.get("actionable") and res.get("candidates"):
        open_pr_by_repo: dict[str, set[int] | None] = {}
        confirmed_unstarted: list[dict[str, Any]] = []
        uncertain_unstarted: list[dict[str, Any]] = []
        for cand in res["candidates"]:
            c_repo = str(cand.get("repo") or "")
            if c_repo not in open_pr_by_repo:
                open_pr_by_repo[c_repo] = _delegated_open_pr_issue_numbers(cfg, c_repo)
            pr_nums = open_pr_by_repo[c_repo]
            if pr_nums is None:
                uncertain_unstarted.append(cand)
            elif int(cand["number"]) not in pr_nums:
                confirmed_unstarted.append(cand)
        if confirmed_unstarted:
            return {**res, "candidates": confirmed_unstarted}
        if uncertain_unstarted:
            if delegated_precheck_cooldown_active(cfg, db):
                return {"actionable": False, "reason": "delegated_pr_probe_within_interval", "candidates": []}
            return {**res, "candidates": uncertain_unstarted}
        res = {**res, "actionable": False, "reason": "open_issues_have_open_prs", "candidates": []}
    if res.get("blocked_units"):
        return res

    precheck_cmd = str(cfg.extra.get("precheck_cmd") or "").strip()
    if precheck_cmd:
        # Continuation-only wakeups honor `schedule_interval_sec` (new actionable issues above are never delayed).
        if delegated_precheck_cooldown_active(cfg, db):
            return {"actionable": False, "reason": "delegated_precheck_within_interval", "candidates": []}
        try:
            proc = _run_readonly_credential_free_precheck(ws, precheck_cmd, timeout=30)
        except (subprocess.SubprocessError, OSError, AutopilotError) as exc:
            return {"actionable": False, "reason": f"delegated_precheck_error:{sanitize_terminal_text(str(exc), 160)}", "candidates": []}
        if proc.returncode == 0:
            return {"actionable": True, "reason": "delegated_precheck_matched", "candidates": []}
    return res


def probe_custom_routine_zero_token(cfg: WorkflowConfig, db: AutopilotDB) -> dict[str, Any]:
    """Universal zero-LLM-token probe for any custom scheduled routine (`--kind routine`)."""
    if not cfg.enabled:
        return {"actionable": False, "reason": "project_disabled"}
    active = db._conn.execute(
        "SELECT COUNT(*) AS c FROM run_claims WHERE project_id = ? AND state IN ('active', 'reclaiming')",
        (cfg.project_id,),
    ).fetchone()["c"]
    if int(active) > 0:
        return {"actionable": False, "reason": "already_running_in_autopilot"}
    if cfg.max_per_day > 0:
        day_start = dt.datetime.now(dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        today_cnt = db._conn.execute(
            "SELECT COUNT(*) AS c FROM run_claims WHERE project_id = ? AND created_at >= ?",
            (cfg.project_id, day_start),
        ).fetchone()["c"]
        if int(today_cnt) >= cfg.max_per_day:
            return {"actionable": False, "reason": f"daily_cap_reached:{today_cnt}/{cfg.max_per_day}"}

    precheck_cmd = str(cfg.extra.get("precheck_cmd") or "").strip()
    if not precheck_cmd:
        return {"actionable": True, "reason": "scheduled_interval_due"}

    ws = Path(cfg.workspace_path).expanduser().resolve()
    try:
        proc = subprocess.run(
            ["/bin/bash", "-lc", precheck_cmd],
            cwd=str(ws) if ws.is_dir() else None,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return {"actionable": False, "reason": f"precheck_error:{sanitize_terminal_text(str(exc), 160)}"}
    if proc.returncode == 0:
        return {"actionable": True, "reason": "precheck_cmd_matched"}
    return {"actionable": False, "reason": f"precheck_quiescent:rc={proc.returncode}"}


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
            from .dream import count_matureable_runs

            cnt = db._conn.execute("SELECT COUNT(*) AS c FROM pitfalls").fetchone()["c"]
            hist = count_matureable_runs(db)
            cutoff_7d = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)).replace(microsecond=0).isoformat()
            claims_7d = db._conn.execute(
                "SELECT COUNT(*) AS c FROM run_claims WHERE created_at >= ?",
                (cutoff_7d,),
            ).fetchone()["c"]
            due_exp = 0
            if db._has_evolution_table():
                due_exp = db._conn.execute(
                    "SELECT COUNT(*) AS c FROM evolution_experiments WHERE state = 'applied' AND review_after IS NOT NULL AND review_after <= ?",
                    (dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),),
                ).fetchone()["c"]
            return {
                "actionable": int(cnt) > 0 or int(hist) > 0 or int(claims_7d) > 0 or int(due_exp) > 0,
                "reason": f"pitfalls={cnt},unmatured_runs={hist},claims_7d={claims_7d},due_experiments={due_exp}",
            }
        if cfg.routine_driver in ("custom", ""):
            return probe_custom_routine_zero_token(cfg, db)
    return {"actionable": False, "reason": f"unknown_driver:{cfg.kind}/{cfg.routine_driver}"}
