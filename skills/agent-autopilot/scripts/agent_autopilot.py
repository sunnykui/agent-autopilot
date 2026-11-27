#!/usr/bin/env python3
"""agent-autopilot CLI: Universal 24x7 self-evolving autonomous issue & routine engine."""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ap_core import SCHEMA_VERSION, __version__  # noqa: E402
from ap_core.chef_loop import ModelTurnResult, execute_chef_issue_pipeline  # noqa: E402
from ap_core.db import AutopilotDB  # noqa: E402
from ap_core.dream import run_dream_consolidation  # noqa: E402
from ap_core.git_gate import (  # noqa: E402
    check_autopilot_scope,
    ensure_managed_bare_repo,
    fetch_authorized_base_into_managed,
    prepare_trusted_base_cache,
    prepare_trusted_base_cache_fd,
    scrub_worktree_to_base,
    validate_raw_git_path,
    verify_worktree_clean,
)
from ap_core.github_flow import (  # noqa: E402
    LiveGitHubCliTransport,
    execute_granted_op,
    fetch_pr_unveto_snapshot,
    reconcile_op,
)
from ap_core.models import (  # noqa: E402
    POLICY_MANIFEST,
    AutopilotError,
    QuotaExhaustedError,
    ScopeConflictError,
    ScopeViolationError,
    WorkflowConfig,
    default_cache_root,
    default_config_root,
    default_state_root,
    empty_and_fsync_dirfd,
    ensure_sealed_tokens_dir,
    ensure_secure_dir,
    now_iso,
    open_dir_nofollow,
    parse_workflow_file,
    pinned_proc_fd_path,
    read_nonempty_token_file,
    sanitize_terminal_text,
)
from ap_core.host_guard import (  # noqa: E402
    HEAVY_UNIT_KINDS,
    count_global_heavy_claims,
    load_global_limits,
    sample_host_pressure,
)
from ap_core.onboard import import_legacy_autopilot_state, onboard_project  # noqa: E402
from ap_core.routine_flow import delegated_precheck_cooldown_active, probe_project_zero_token  # noqa: E402
from ap_core.sandbox import (  # noqa: E402
    AllowlistConnectProxyServer,
    ToolExecServer,
    build_execution_ring_bwrap,
    build_model_ring_bwrap,
    check_linger_enabled,
    cleanup_sandbox_home,
    cleanup_sandbox_home_at_dirfd,
    expected_transient_cgroup_dir,
    prepare_sandbox_home,
    prepare_sandbox_home_fd,
    prepare_sandbox_home_memfds,
    safe_read_outbox_file,
    safe_read_outbox_file_fd,
    spawn_transient_unit_under_flock,
    verify_native_binaries,
    verify_self_in_expected_cgroup,
    verify_unit_terminated,
)


def resolve_native_bin_dir() -> Path:
    override = os.environ.get("AGENT_AUTOPILOT_BIN_DIR")
    if override:
        return Path(override).expanduser().resolve()
    candidates = [
        Path.home() / ".local" / "share" / "agent-autopilot" / "bin",
        Path.home() / ".cache" / "agent-work" / "auto-issue-fix" / "bin",
    ]
    for c in candidates:
        if (c / "ap-sandbox-init").is_file() and (c / "ap-safe-sh").is_file():
            return c.resolve()
    return candidates[0].resolve()


def resolve_host_binaries() -> dict[str, Path]:
    bdir = resolve_native_bin_dir()
    out: dict[str, Path] = {
        "ap_sandbox_init": bdir / "ap-sandbox-init",
        "ap_safe_sh": bdir / "ap-safe-sh",
    }
    codex_p = shutil.which("codex")
    if codex_p:
        out["codex_cli"] = Path(codex_p).resolve()
    cmh_p = shutil.which("codex-code-mode-host")
    if cmh_p:
        out["codex_code_mode_host"] = Path(cmh_p).resolve()
    claude_p = shutil.which("claude")
    if claude_p:
        out["claude_cli"] = Path(claude_p).resolve()
    return out


def repo_cache_dir(project_id: str, repo_slug: str) -> Path:
    safe_repo = repo_slug.replace("/", "__") if repo_slug else "_default"
    return ensure_secure_dir(default_cache_root() / project_id / safe_repo, 0o700)


def load_or_create_hmac_secret(state_root: Path) -> bytes:
    ensure_secure_dir(state_root, 0o700)
    key_file = state_root / "hmac.key"
    if key_file.is_file():
        return key_file.read_bytes()
    secret = secrets.token_bytes(32)
    key_file.write_bytes(secret)
    os.chmod(key_file, 0o600)
    return secret


def load_all_workflows(config_root: Path | None = None) -> list[WorkflowConfig]:
    croot = config_root or default_config_root()
    pdir = croot / "projects"
    if not pdir.is_dir():
        return []
    out: list[WorkflowConfig] = []
    for wf in sorted(pdir.glob("*/WORKFLOW.md")):
        out.append(parse_workflow_file(wf))
    return out


@contextlib.contextmanager
def acquire_dispatcher_lock(state_root: Path):
    ensure_secure_dir(state_root, 0o700)
    lock_path = state_root / "dispatcher.lock"
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AutopilotError(f"Another dispatcher already holds {lock_path}") from exc
        yield fd
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


@contextlib.contextmanager
def _try_acquire_slot_flocks(db: AutopilotDB, slot_keys: list[str]):
    """Acquire non-blocking LOCK_EX on every physical slot's .flock file in deterministic order."""
    fds: list[int] = []
    try:
        for sk in sorted(set(slot_keys)):
            lrow = db._conn.execute("SELECT flock_path FROM leases WHERE slot_key = ?", (sk,)).fetchone()
            if lrow is None or not lrow["flock_path"]:
                raise AutopilotError(f"Missing flock_path for lease slot {sk!r}")
            fd = os.open(str(lrow["flock_path"]), os.O_CREAT | os.O_RDWR, 0o600)
            fds.append(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield tuple(fds)
    finally:
        for fd in reversed(fds):
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(fd)


def _create_short_socket_dir() -> Path:
    """Create a private 0700 socket dir whose sun_path is guaranteed well below Linux 108-byte limit."""
    rt_env = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    rt_base = Path(rt_env)
    root = (rt_base / "ap-s") if (rt_base.is_dir() and os.access(rt_base, os.W_OK)) else (Path.home() / ".cache" / "ap-s")
    ensure_secure_dir(root, 0o700)
    sdir = ensure_secure_dir(root / uuid.uuid4().hex[:10], 0o700)
    return sdir


def _resolve_strict_project_gh_transport(
    db: AutopilotDB,
    project_id: str,
    workflows: dict[str, WorkflowConfig],
    *,
    cache_dir: Path | None = None,
) -> LiveGitHubCliTransport:
    """Enforce fail-closed dedicated token_file; verify reloaded project_id and derive mode strictly from valid disk config!"""
    cfg = workflows.get(project_id)
    prow = db.get_project_row(project_id)
    if cfg is not None:
        if cfg.project_id != project_id:
            raise AutopilotError(
                f"WorkflowConfig project_id={cfg.project_id!r} mismatches requested project_id={project_id!r}"
            )
        if cfg.source_path:
            sp = Path(cfg.source_path)
            if not sp.is_file():
                raise AutopilotError(f"Authoritative WORKFLOW.md missing at {sp} for project {project_id}")
            reloaded = parse_workflow_file(sp)
            if reloaded.project_id != project_id:
                raise AutopilotError(
                    f"Reloaded WORKFLOW.md at {sp} declares project_id={reloaded.project_id!r} != expected {project_id!r}"
                )
            cfg = reloaded
        elif prow is not None:
            # Guard programmatic callers passing a stale in-memory WorkflowConfig after DB project credentials rotated!
            db_tf = str(prow.get("token_file") or "").strip()
            cfg_tf = (cfg.token_file or "").strip()
            db_tm = str(prow.get("token_mode") or "")
            cfg_tm = "dedicated" if cfg_tf else "ambient"
            if (db_tm in ("ambient", "dedicated") and db_tm != cfg_tm) or (db_tf and db_tf != cfg_tf):
                raise AutopilotError(
                    f"Stale in-memory WorkflowConfig for {project_id} conflicts with rotated DB token configuration"
                )
        # Authoritative valid config present -> take credential mode EXCLUSIVELY from `cfg` (never resurrecting old DB token_file!)
        cfg_tf_clean = (cfg.token_file or "").strip()
        if cfg_tf_clean:
            tok = read_nonempty_token_file(cfg_tf_clean)
            return LiveGitHubCliTransport(token=tok, cache_dir=cache_dir, require_explicit_token=True)
        return LiveGitHubCliTransport(token=None, cache_dir=cache_dir, require_explicit_token=False)

    if prow is None or prow.get("token_mode") not in ("ambient", "dedicated"):
        raise AutopilotError(
            f"Project {project_id} has unknown historical token_mode without WORKFLOW.md; refusing ambient GH_TOKEN fallback"
        )
    if str(prow["token_mode"]) == "dedicated" or str(prow.get("token_file") or "").strip():
        req_tf = str(prow.get("token_file") or "").strip()
        if not req_tf:
            raise AutopilotError(f"Dedicated token_mode for {project_id} missing token_file path")
        tok = read_nonempty_token_file(req_tf)
        return LiveGitHubCliTransport(token=tok, cache_dir=cache_dir, require_explicit_token=True)
    return LiveGitHubCliTransport(token=None, cache_dir=cache_dir, require_explicit_token=False)


class LiveSandboxedModelRunner:
    """Runs Scout, Writer, and Referee inside bwrap + Landlock + CONNECT allowlist proxy + tool-exec rings."""

    def __init__(
        self,
        host_binaries: dict[str, Path],
        cache_root: Path,
        *,
        run_dir_fd: int | None = None,
        db: AutopilotDB | None = None,
        claim_epoch: int | None = None,
        trusted_base_cache_fd: int | None = None,
        repo_main_dir: Path | None = None,
        ro_workspace_deps: tuple[str, ...] = (),
    ) -> None:
        self.host_binaries = host_binaries
        self.cache_root = cache_root
        self.run_dir_fd = run_dir_fd
        self.db = db
        self.claim_epoch = claim_epoch
        self.trusted_base_cache_fd = trusted_base_cache_fd
        self.repo_main_dir = repo_main_dir
        self.ro_workspace_deps = ro_workspace_deps

    def _exec_role(
        self,
        *,
        role_key: str,
        family: str,
        model: str,
        prompt: str,
        run_dir: Path,
        worktree: Path | None = None,
        managed_gitdir: Path | None = None,
        repo_main_objects: Path | None = None,
        trusted_base_cache: Path | None = None,
        review_bundle_dir: Path | None = None,
        outbox_dir: Path | None = None,
    ) -> ModelTurnResult:
        eff_run_dir = pinned_proc_fd_path(self.run_dir_fd) if self.run_dir_fd is not None else ensure_secure_dir(run_dir, 0o700)
        sb_memfds: dict[str, int] = {}
        obox_fd: int | None = None
        model_retain_fds: list[int] = []
        obox = outbox_dir or ensure_secure_dir(eff_run_dir / f"outbox_{uuid.uuid4().hex[:6]}", 0o700)
        obox_fd = open_dir_nofollow(obox, create=True, mode=0o700)
        shared_tmp = ensure_secure_dir(eff_run_dir / "shared_tmp", 0o700)
        snaps = ensure_secure_dir(eff_run_dir / "shell_snapshots", 0o700)
        eph_cache = ensure_secure_dir(eff_run_dir / "ephemeral_tool_cache", 0o700)
        elf_stage = ensure_secure_dir(eff_run_dir / "elf_libs_stage", 0o700)
        sock_dir = _create_short_socket_dir()
        proxy_sock = sock_dir / "p.sock"
        tool_sock = sock_dir / "t.sock"

        proxy = AllowlistConnectProxyServer(proxy_sock)
        proxy.start()
        tool_srv: ToolExecServer | None = None
        try:
            sb_memfds = prepare_sandbox_home_memfds(family, role_key=role_key)
            if worktree is not None and role_key.endswith(":issue_model"):
                def _build_tool_cmd(cwd: Path, args: list[str]) -> tuple[list[str], list[int]]:
                    t_fds: list[int] = []
                    try:
                        t_argv = build_execution_ring_bwrap(
                            ring_kind="tool_ring",
                            inner_cmd=["/usr/bin/bash", *args],
                            cwd=cwd,
                            worktree=worktree,
                            managed_gitdir=managed_gitdir,
                            repo_main_objects=repo_main_objects,
                            trusted_base_cache=trusted_base_cache,
                            ephemeral_tool_cache=eph_cache,
                            shared_tmp=shared_tmp,
                            shell_snapshots=snaps,
                            retain_fds=t_fds,
                            trusted_base_cache_fd=self.trusted_base_cache_fd,
                            repo_main_dir=self.repo_main_dir,
                            ro_workspace_deps=self.ro_workspace_deps,
                        )
                        return t_argv, t_fds
                    except BaseException:
                        for _tf in t_fds:
                            with contextlib.suppress(OSError):
                                os.close(_tf)
                        raise

                tool_srv = ToolExecServer(
                    tool_sock,
                    worktree,
                    cmd_builder=_build_tool_cmd,
                )
                tool_srv.start()

            if family == "codex":
                inner = [
                    "/usr/local/bin/codex",
                    "exec",
                    "-m",
                    model,
                    "--dangerously-bypass-approvals-and-sandbox",
                    "--skip-git-repo-check",
                    "-c",
                    "features.multi_agent=false",
                    "-c",
                    "features.shell_snapshot=false",
                    "-o",
                    "/ap-outbox/verdict.json",
                    "-",
                ]
            else:
                inner = [
                    "/usr/local/bin/claude",
                    "-p",
                    "--model",
                    model,
                    "--output-format",
                    "text",
                ]

            argv = build_model_ring_bwrap(
                role_key=role_key,
                host_binaries=self.host_binaries,
                sandbox_home=eff_run_dir / "memfd_sandbox_home",
                outbox_dir=obox,
                proxy_sock=proxy_sock,
                inner_cmd=inner,
                worktree=worktree,
                shared_tmp=shared_tmp if role_key.endswith(":issue_model") else None,
                shell_snapshots=snaps if role_key.endswith(":issue_model") else None,
                tool_sock=tool_sock if tool_srv is not None else None,
                review_bundle_dir=review_bundle_dir,
                elf_lib_stage_dir=elf_stage,
                sandbox_file_fds=sb_memfds,
                outbox_fd=obox_fd,
                retain_fds=model_retain_fds,
            )
            proc = subprocess.run(
                argv,
                input=prompt,
                capture_output=True,
                text=True,
                pass_fds=tuple(model_retain_fds),
                timeout=2400,
                check=False,
            )
            obox_txt = safe_read_outbox_file_fd(obox_fd, "verdict.json") if family == "codex" else None
            return ModelTurnResult(
                raw_stdout=proc.stdout or "",
                raw_stderr=proc.stderr or "",
                outbox_verdict_json=obox_txt,
                exit_code=proc.returncode,
                model_used=model,
            )
        finally:
            for _mfd in model_retain_fds:
                with contextlib.suppress(OSError):
                    os.close(_mfd)
            for _smfd in sb_memfds.values():
                with contextlib.suppress(OSError):
                    os.close(_smfd)
            if obox_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(obox_fd)
            if tool_srv is not None:
                tool_srv.close()
            proxy.close()
            shutil.rmtree(sock_dir, ignore_errors=True)

    def run_scout(
        self,
        *,
        family: str,
        model: str,
        worktree: Path,
        prompt: str,
        run_dir: Path,
        managed_gitdir: Path | None = None,
        repo_main_objects: Path | None = None,
        trusted_base_cache: Path | None = None,
    ) -> ModelTurnResult:
        return self._exec_role(
            role_key=f"{family}:issue_model",
            family=family,
            model=model,
            prompt=prompt,
            run_dir=run_dir,
            worktree=worktree,
            managed_gitdir=managed_gitdir,
            repo_main_objects=repo_main_objects,
            trusted_base_cache=trusted_base_cache,
        )

    def run_writer(
        self,
        *,
        family: str,
        model: str,
        worktree: Path,
        prompt: str,
        run_dir: Path,
        managed_gitdir: Path | None = None,
        repo_main_objects: Path | None = None,
        trusted_base_cache: Path | None = None,
    ) -> ModelTurnResult:
        return self._exec_role(
            role_key=f"{family}:issue_model",
            family=family,
            model=model,
            prompt=prompt,
            run_dir=run_dir,
            worktree=worktree,
            managed_gitdir=managed_gitdir,
            repo_main_objects=repo_main_objects,
            trusted_base_cache=trusted_base_cache,
        )

    def run_referee(
        self,
        *,
        family: str,
        model: str,
        review_bundle_dir: Path,
        outbox_dir: Path,
        prompt: str,
        run_dir: Path,
    ) -> ModelTurnResult:
        return self._exec_role(
            role_key=f"{family}:readonly_model",
            family=family,
            model=model,
            prompt=prompt,
            run_dir=run_dir,
            review_bundle_dir=review_bundle_dir,
            outbox_dir=outbox_dir,
        )


def _effective_claim_cache_dir(claim_row: dict[str, Any]) -> Path:
    """Resolve frozen per-claim repo cache root so changing AGENT_AUTOPILOT_CACHE_DIR never wedges old claim cleanup!"""
    if claim_row.get("frozen_cache_dir"):
        return Path(os.path.normpath(str(claim_row["frozen_cache_dir"])))
    if claim_row.get("managed_gitdir"):
        return Path(os.path.normpath(str(claim_row["managed_gitdir"]))).parent
    return repo_cache_dir(str(claim_row["project_id"]), str(claim_row.get("repo") or "")).resolve()


def _open_verified_claim_cache_fd(claim_row: dict[str, Any], rcache: Path) -> int | None:
    """Open `rcache` from `/` with `O_DIRECTORY|O_NOFOLLOW`, verify `(frozen_cache_dev, frozen_cache_ino)`, and return retained fd!"""
    try:
        return open_dir_nofollow(
            rcache,
            create=False,
            expected_dev=claim_row.get("frozen_cache_dev"),
            expected_ino=claim_row.get("frozen_cache_ino"),
        )
    except (OSError, AutopilotError):
        return None


def _verify_frozen_cache_storage_mounted(claim_row: dict[str, Any], rcache: Path) -> bool:
    """Walk `rcache` from `/` with `O_DIRECTORY|O_NOFOLLOW` and verify `(frozen_cache_dev, frozen_cache_ino)` if recorded."""
    fd = _open_verified_claim_cache_fd(claim_row, rcache)
    if fd is None:
        return False
    os.close(fd)
    return True


def _are_all_scope_workers_terminated(db: AutopilotDB, scope_units: tuple[str, ...]) -> bool:
    u_marks = ",".join("?" for _ in scope_units)
    crows = db._conn.execute(
        f"SELECT worker_unit_name, expected_cgroup_dir FROM run_claims WHERE unit_key IN ({u_marks}) AND state IN ('active', 'reclaiming')",
        scope_units,
    ).fetchall()
    return all(verify_unit_terminated(r["worker_unit_name"], r["expected_cgroup_dir"]) for r in crows)


def _reclaim_single_claim_via_bounded_unit(
    db: AutopilotDB,
    claim_row: dict[str, Any],
    cfg: WorkflowConfig | None,
) -> bool:
    """Reclaim a dead claim while holding its physical slot .flocks and persisting cleanup unit identity."""
    ce = int(claim_row["claim_epoch"])
    if not verify_unit_terminated(claim_row["worker_unit_name"], claim_row["expected_cgroup_dir"]):
        return False

    # Verify any previously spawned cleanup unit has ALSO terminated before starting a new cleanup!
    if claim_row.get("cleanup_unit_name") and claim_row.get("cleanup_cgroup_dir"):
        if not verify_unit_terminated(claim_row["cleanup_unit_name"], claim_row["cleanup_cgroup_dir"]):
            return False

    slot_keys = json.loads(claim_row["slot_vector_json"])
    try:
        with _try_acquire_slot_flocks(db, slot_keys) as slot_fds:
            db.begin_reclaim_claim(ce)
            rcache = _effective_claim_cache_dir(claim_row)
            rcache_fd = _open_verified_claim_cache_fd(claim_row, rcache)
            # If the frozen cache storage volume is offline/unmounted or replaced, retain 'reclaiming' (NEVER release slot)!
            if rcache_fd is None:
                with db.immediate_tx():
                    db._conn.execute(
                        "UPDATE work_units SET last_error = ?, updated_at = ? WHERE unit_key = ?",
                        (f"reclaim_waiting_storage: frozen cache root {rcache} unmounted or device/inode drifted", now_iso(), claim_row["unit_key"]),
                    )
                return False
            try:
                pinned_rc = pinned_proc_fd_path(rcache_fd)
                raw_run_dir = Path(os.path.normpath(str(claim_row["run_dir"]))) if claim_row.get("run_dir") else (rcache / "runs" / f"claim-{ce}")
                sb_cleanup_ok = True
                if claim_row.get("ephemeral_token_file"):
                    etp = Path(str(claim_row["ephemeral_token_file"]))
                    if not etp.parent.is_dir() or etp.parent.is_symlink():
                        sb_cleanup_ok = False
                    else:
                        try:
                            etp.unlink(missing_ok=True)
                        except OSError:
                            sb_cleanup_ok = False
                        if etp.exists() or etp.is_symlink():
                            sb_cleanup_ok = False

                # Open and HOLD `rfd` (`run_dir`) with `O_DIRECTORY|O_NOFOLLOW` + `(run_dir_dev, run_dir_ino)` verification
                # until ALL credential cleanup AND post-purge rescan complete!
                rd_state = str(claim_row.get("run_dir_state") or "legacy_untracked")
                cred_tracked = int(claim_row.get("cred_ledger_tracked") or 0)
                persisted_unit_kind = str(claim_row.get("unit_kind") or "issue")
                exp_rdev = claim_row.get("run_dir_dev")
                exp_rino = claim_row.get("run_dir_ino")
                has_run_dir_identity = exp_rdev is not None and exp_rino is not None
                run_dir_exists_verified = False
                if raw_run_dir.is_relative_to(rcache):
                    cand_run_p = pinned_rc / raw_run_dir.relative_to(rcache)
                else:
                    cand_run_p = raw_run_dir
                rfd: int | None = None
                if rd_state == "legacy_untracked" and not has_run_dir_identity:
                    # Pre-upgrade active/reclaiming claim lacks original `run_dir` `(dev, ino)` proof -> retain `reclaiming`!
                    sb_cleanup_ok = False
                elif rd_state == "bound" and (
                    not has_run_dir_identity or (persisted_unit_kind == "issue" and cred_tracked < 2)
                ):
                    # Pre-v2 bound issue claim lacks full dir+subdir+file+owner_token ledger -> retain `reclaiming`!
                    sb_cleanup_ok = False
                elif persisted_unit_kind == "issue" and cred_tracked < 2 and rd_state != "uncreated":
                    sb_cleanup_ok = False
                else:
                    try:
                        rfd = open_dir_nofollow(
                            cand_run_p,
                            create=False,
                            expected_dev=exp_rdev,
                            expected_ino=exp_rino,
                        )
                        if rd_state == "uncreated":
                            # Claim crashed before recording `run_dir` identity -> only allow if 100% empty (zero credentials)!
                            with os.scandir(rfd) as un_it:
                                if any(True for _ in un_it):
                                    sb_cleanup_ok = False
                                else:
                                    run_dir_exists_verified = True
                        else:
                            run_dir_exists_verified = True
                            try:
                                os.unlink(".bound_gh_token", dir_fd=rfd)
                            except FileNotFoundError:
                                pass
                            except OSError:
                                sb_cleanup_ok = False

                            import stat as _stat_sbh
                            from ap_core.models import try_clean_crashed_qbox_at_dirfd, verify_cred_owner_token
                            from ap_core.sandbox import purge_credential_file_at_dirfd

                            all_cred_rows = db.list_all_claim_credential_dirs(ce)
                            unpurged_dir_tokens = {
                                (int(r["dir_dev"]), int(r["dir_ino"])): str(r.get("owner_token") or "")
                                for r in all_cred_rows
                                if r.get("entry_kind", "dir") == "dir" and int(r["purged"]) == 0
                            }
                            purged_dir_tokens = {
                                (int(r["dir_dev"]), int(r["dir_ino"])): str(r.get("owner_token") or "")
                                for r in all_cred_rows
                                if r.get("entry_kind", "dir") == "dir" and int(r["purged"]) == 1
                            }
                            unpurged_file_tokens = {
                                (int(r["dir_dev"]), int(r["dir_ino"])): str(r.get("owner_token") or "")
                                for r in all_cred_rows
                                if r.get("entry_kind") == "file" and int(r["purged"]) == 0
                            }
                            purged_file_tokens = {
                                (int(r["dir_dev"]), int(r["dir_ino"])): str(r.get("owner_token") or "")
                                for r in all_cred_rows
                                if r.get("entry_kind") == "file" and int(r["purged"]) == 1
                            }

                            targets_to_purge: list[tuple[str, int, int, str]] = []
                            files_to_purge: list[tuple[str, int, int, str]] = []
                            with os.scandir(rfd) as p_it:
                                for _pe in p_it:
                                    if _pe.name.startswith(".ap-qbox-"):
                                        if try_clean_crashed_qbox_at_dirfd(
                                            rfd,
                                            _pe.name,
                                            tracked_files=unpurged_file_tokens,
                                            purged_files=purged_file_tokens,
                                            on_file_purged=lambda d, i: db.mark_claim_credential_dir_purged(ce, d, i),
                                        ):
                                            continue
                                        sb_cleanup_ok = False
                                        continue
                                    try:
                                        _pst = os.stat(_pe.name, dir_fd=rfd, follow_symlinks=False)
                                    except OSError:
                                        sb_cleanup_ok = False
                                        continue
                                    key_di = (int(_pst.st_dev), int(_pst.st_ino))
                                    if key_di in unpurged_file_tokens:
                                        if _stat_sbh.S_ISREG(_pst.st_mode) and not _stat_sbh.S_ISLNK(_pst.st_mode):
                                            files_to_purge.append((_pe.name, key_di[0], key_di[1], unpurged_file_tokens[key_di]))
                                        else:
                                            sb_cleanup_ok = False
                                        continue

                                    is_unpurged_dir = key_di in unpurged_dir_tokens
                                    is_sbh_prefix = _pe.name.startswith("sandbox_home_")
                                    if not is_unpurged_dir and not is_sbh_prefix:
                                        if cred_tracked == 0 and persisted_unit_kind != "issue":
                                            sb_cleanup_ok = False
                                        continue
                                    if _stat_sbh.S_ISLNK(_pst.st_mode) or not _stat_sbh.S_ISDIR(_pst.st_mode):
                                        sb_cleanup_ok = False
                                        continue
                                    try:
                                        _chk_fd = os.open(_pe.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rfd)
                                        try:
                                            with os.scandir(_chk_fd) as _c_it:
                                                _non_empty = any(True for _ in _c_it)
                                            _tok_ok = (
                                                verify_cred_owner_token(_chk_fd, unpurged_dir_tokens[key_di])
                                                if is_unpurged_dir
                                                else False
                                            )
                                        finally:
                                            os.close(_chk_fd)
                                    except OSError:
                                        sb_cleanup_ok = False
                                        continue

                                    if is_unpurged_dir:
                                        if _tok_ok:
                                            targets_to_purge.append((_pe.name, key_di[0], key_di[1], unpurged_dir_tokens[key_di]))
                                        else:
                                            # Freed inode reused by an unrelated directory (`round-1`) lacking `owner_token`: preserve it!
                                            sb_cleanup_ok = False
                                    else:
                                        # `sandbox_home_*` NOT in `unpurged_dir_tokens` (either `purged==1` shell or stranger B):
                                        if not _non_empty:
                                            try:
                                                os.rmdir(_pe.name, dir_fd=rfd)
                                            except OSError:
                                                sb_cleanup_ok = False
                                        else:
                                            # Preserve non-empty replacement directory B untouched and block release!
                                            sb_cleanup_ok = False

                            for fname_p, fdev_p, fino_p, ftok_p in files_to_purge:
                                try:
                                    purge_credential_file_at_dirfd(
                                        rfd,
                                        fname_p,
                                        expected_dev=fdev_p,
                                        expected_ino=fino_p,
                                        expected_owner_token=ftok_p,
                                        on_purged=lambda d, i: db.mark_claim_credential_dir_purged(ce, d, i),
                                    )
                                except AutopilotError:
                                    sb_cleanup_ok = False

                            for sbh_name, sbh_dev, sbh_ino, sbh_tok_exp in targets_to_purge:
                                try:
                                    cleanup_sandbox_home_at_dirfd(
                                        rfd,
                                        sbh_name,
                                        expected_dev=sbh_dev,
                                        expected_ino=sbh_ino,
                                        expected_owner_token=sbh_tok_exp,
                                        allowed_child_dirs=unpurged_dir_tokens,
                                        purged_child_dirs=purged_dir_tokens,
                                        tracked_files=unpurged_file_tokens,
                                        purged_files=purged_file_tokens,
                                        on_emptied_before_rmdir=lambda d, i: db.mark_claim_credential_dir_purged(ce, d, i),
                                    )
                                except AutopilotError:
                                    sb_cleanup_ok = False

                            try:
                                os.fsync(rfd)
                            except OSError:
                                sb_cleanup_ok = False

                            # 3. Post-purge rescan of `rfd` AND SQLite ledger check: ANY unpurged credential dir blocks release forever!
                            with os.scandir(rfd) as rescan_it:
                                for rem_e in rescan_it:
                                    if rem_e.name == ".bound_gh_token" or rem_e.name.startswith("sandbox_home_"):
                                        sb_cleanup_ok = False
                                        break
                            if db.list_unpurged_claim_credential_dirs(ce):
                                sb_cleanup_ok = False
                    except FileNotFoundError:
                        if has_run_dir_identity or rd_state != "uncreated":
                            sb_cleanup_ok = False
                    except (AutopilotError, OSError):
                        sb_cleanup_ok = False
                    finally:
                        if rfd is not None:
                            with contextlib.suppress(OSError):
                                os.close(rfd)

                wt_cleanup_rc = 0
                wt_clean = True
                raw_mg = Path(os.path.normpath(str(claim_row["managed_gitdir"]))) if claim_row.get("managed_gitdir") else (rcache / "managed.git")
                raw_wt = Path(os.path.normpath(str(claim_row["worktree_path"]))) if claim_row.get("worktree_path") else (rcache / "worktrees" / f"wt-{ce}")
                mg_pin = (pinned_rc / raw_mg.relative_to(rcache)) if raw_mg.is_relative_to(rcache) else raw_mg
                wt_pin = (pinned_rc / raw_wt.relative_to(rcache)) if raw_wt.is_relative_to(rcache) else raw_wt
                wt_gd_pin = mg_pin / "worktrees" / raw_wt.name

                wt_or_gd_present = False
                with contextlib.suppress(OSError):
                    wt_or_gd_present = bool(wt_pin.exists() or wt_pin.is_symlink() or wt_gd_pin.exists() or wt_gd_pin.is_symlink())
                if wt_or_gd_present and not run_dir_exists_verified and claim_row.get("run_dir"):
                    # Worker materialized worktree/gitdir AFTER creating `run_dir`, so missing `run_dir` means `runs/` was moved/tampered!
                    sb_cleanup_ok = False

                is_issue_claim = bool((cfg and cfg.kind == "issue") or claim_row.get("unit_kind") == "issue" or wt_or_gd_present)
                path_recorded = int(claim_row.get("path_recorded") or 0)
                has_storage_identity = (
                    claim_row.get("frozen_cache_dev") is not None and claim_row.get("frozen_cache_ino") is not None
                )
                has_claim_dir_proof = False
                with contextlib.suppress(OSError):
                    if is_issue_claim:
                        has_claim_dir_proof = (
                            mg_pin.is_dir()
                            and not mg_pin.is_symlink()
                            and (mg_pin / "HEAD").is_file()
                            and (run_dir_exists_verified or (wt_gd_pin.is_dir() and not wt_gd_pin.is_symlink()))
                        )
                    else:
                        has_claim_dir_proof = run_dir_exists_verified

                if (path_recorded == 0 or not has_storage_identity) and not has_claim_dir_proof:
                    wt_cleanup_rc = 1
                    wt_clean = False
                    with db.immediate_tx():
                        db._conn.execute(
                            "UPDATE work_units SET last_error = ?, updated_at = ? WHERE unit_key = ?",
                            (f"reclaim_unproven_legacy_storage: missing device/inode and no claim artifacts under {rcache}", now_iso(), claim_row["unit_key"]),
                        )
                elif is_issue_claim:
                    try:
                        # Check symlinked ancestors on mg/wt/wt_gd AND check `git worktree lock` marker (`wt_gd_pin/locked`)!
                        if mg_pin.exists() or mg_pin.is_symlink():
                            os.close(open_dir_nofollow(mg_pin, create=False))
                        if wt_pin.parent.exists() or wt_pin.parent.is_symlink():
                            os.close(open_dir_nofollow(wt_pin.parent, create=False))
                        if wt_pin.is_symlink() or wt_gd_pin.is_symlink():
                            raise AutopilotError(f"Symlinked worktree or wt_gitdir: {raw_wt}")
                        if wt_gd_pin.exists():
                            os.close(open_dir_nofollow(wt_gd_pin, create=False))
                            try:
                                os.lstat(wt_gd_pin / "locked")
                            except FileNotFoundError:
                                pass
                            else:
                                raise AutopilotError(f"Worktree metadata {raw_wt / '.git'} is locked ({wt_gd_pin}/locked present)")
                    except (AutopilotError, OSError) as p_exc:
                        wt_cleanup_rc = 1
                        wt_clean = False
                        db.mark_unit_needs_human(
                            str(claim_row["unit_key"]),
                            f"Refusing to reclaim locked/symlinked/unreadable worktree {raw_wt} ({sanitize_terminal_text(str(p_exc), 200)}); retaining lease",
                            non_veto=True,
                        )
                    else:
                        if not wt_pin.exists():
                            # Before treating missing `wt_pin` as clean, verify `wt_gd_pin/gitdir` was NOT relocated and is readable!
                            if wt_gd_pin.exists():
                                relocated_or_bad = True
                                try:
                                    gitdir_ptr = wt_gd_pin / "gitdir"
                                    canon_exp_wt = pinned_rc.resolve() / raw_wt.relative_to(rcache) if raw_wt.is_relative_to(rcache) else raw_wt
                                    exp_ptr = Path(os.path.normpath(str(canon_exp_wt / ".git")))
                                    if gitdir_ptr.is_file() and not gitdir_ptr.is_symlink():
                                        reg_ptr = Path(os.path.normpath(gitdir_ptr.read_text(encoding="utf-8", errors="replace").strip()))
                                        if reg_ptr == exp_ptr and not reg_ptr.exists():
                                            relocated_or_bad = False
                                except OSError:
                                    relocated_or_bad = True
                                if relocated_or_bad:
                                    wt_cleanup_rc = 1
                                    wt_clean = False
                                    db.mark_unit_needs_human(
                                        str(claim_row["unit_key"]),
                                        f"Registered worktree {raw_wt} missing while metadata {wt_gd_pin} is unreadable or points elsewhere; retaining lease",
                                        non_veto=True,
                                    )
                                else:
                                    wt_clean = True
                            else:
                                wt_clean = True
                        elif not mg_pin.is_dir() or not wt_gd_pin.is_dir():
                            wt_cleanup_rc = 1
                            wt_clean = False
                        else:
                            cu_name = f"ap-cleanup-{ce}-{uuid.uuid4().hex[:6]}.service"
                            cu_cg = expected_transient_cgroup_dir(cu_name)
                            db.record_cleanup_unit(ce, cu_name, str(cu_cg))
                            cproc = spawn_transient_unit_under_flock(
                                unit_name=cu_name,
                                cmd=[
                                    sys.executable,
                                    str(Path(__file__).resolve()),
                                    "scrub-worktree",
                                    "--claim-epoch",
                                    str(ce),
                                ],
                                flock_fds=slot_fds,
                                wait=True,
                                unit_kind="cleanup",
                                extra_env=_worker_root_env(default_state_root()),
                            )
                            cu_term = verify_unit_terminated(cu_name, cu_cg)
                            wt_cleanup_rc = cproc.returncode if cu_term else 1
                            wt_clean = (wt_cleanup_rc == 0) and verify_worktree_clean(
                                managed_gitdir=mg_pin, wt_gitdir=wt_gd_pin, worktree=wt_pin
                            )
                            if not wt_clean:
                                db.mark_unit_needs_human(
                                    str(claim_row["unit_key"]),
                                    f"Worktree scrub failed or refused (rc={wt_cleanup_rc}) at {raw_wt}; retaining lease for inspection",
                                    non_veto=True,
                                )

                if not sb_cleanup_ok:
                    with db.immediate_tx():
                        db._conn.execute(
                            "UPDATE work_units SET last_error = ?, updated_at = ? WHERE unit_key = ?",
                            (f"reclaim_sandbox_cleanup_blocked: redirected/missing/unreadable run_dir {raw_run_dir}", now_iso(), claim_row["unit_key"]),
                        )
                final_cleanup_rc = 0 if (sb_cleanup_ok and wt_cleanup_rc == 0) else 1
                recheck_terminated = verify_unit_terminated(claim_row["worker_unit_name"], claim_row["expected_cgroup_dir"])
                return db.finish_reclaim_leases_free(
                    ce,
                    cleanup_rc=final_cleanup_rc,
                    unit_terminated=recheck_terminated,
                    worktree_clean=wt_clean,
                )
            finally:
                os.close(rcache_fd)
    except BlockingIOError:
        return False
    except (AutopilotError, OSError) as exc:
        with contextlib.suppress(Exception):
            with db.immediate_tx():
                db._conn.execute(
                    "UPDATE work_units SET last_error = ?, updated_at = ? WHERE unit_key = ?",
                    (f"reclaim_error_isolated: {sanitize_terminal_text(str(exc), 240)}", now_iso(), claim_row["unit_key"]),
                )
        return False


def _scope_has_unresolved_pr_mutating_worker_op(db: AutopilotDB, unit_key: str) -> bool:
    for sop in db.list_ops_for_scope(unit_key):
        if (
            sop["owner_kind"] == "worker"
            and sop["op_type"] in ("create_draft_pr", "mark_pr_ready", "enqueue_pr", "merge_pr")
            and sop["status"] in ("prepared_local", "in_flight", "unknown_paused")
        ):
            return True
    return False


def _quarantine_if_cross_project_scope(
    db: AutopilotDB,
    unit_key: str,
    pr_id: str | None,
    conflicted_units: set[str],
) -> bool:
    """Quarantine the ENTIRE connected component (`scope_quarantined=1`, `veto_remote_sync_pending=0`) if any conflict exists."""
    if unit_key in conflicted_units:
        return True
    ok_int, conn_units, reason = db.inspect_scope_integrity(unit_key, pr_id=pr_id)
    if not ok_int:
        targets = conn_units or ((unit_key,) if db.get_unit(unit_key) else ())
        if targets:
            ts = now_iso()
            um = ",".join("?" for _ in targets)
            with db.immediate_tx():
                db._conn.execute(
                    f"""
                    UPDATE work_units
                    SET veto_pending = 1,
                        veto_remote_sync_pending = 0,
                        scope_quarantined = 1,
                        status = 'paused',
                        terminal_state = 'needs-human',
                        pause_reason_kind = 'veto',
                        last_error = ?,
                        updated_at = ?
                    WHERE unit_key IN ({um})
                    """,
                    (f"{reason}; quarantining automatic recovery", ts, *targets),
                )
        for uk in targets:
            conflicted_units.add(uk)
        return True
    return False


def supervisor_recover_and_reconcile(
    db: AutopilotDB,
    dispatcher_epoch: int,
    workflows: dict[str, WorkflowConfig],
    *,
    transport_override: Any = None,
) -> dict[str, Any]:
    """Reclaim dead workers, reconcile ops, sync pending/unresolved remote vetoes, replace & execute current-epoch admin ops."""
    reclaimed_claims: list[int] = []
    replaced_admin_ops: list[str] = []
    reconciled_ops: list[str] = []
    executed_admin_ops: list[str] = []

    crows = [dict(r) for r in db._conn.execute("SELECT * FROM run_claims WHERE state IN ('active', 'reclaiming')").fetchall()]
    for cr in crows:
        cfg = workflows.get(cr["project_id"])
        try:
            if _reclaim_single_claim_via_bounded_unit(db, cr, cfg):
                reclaimed_claims.append(int(cr["claim_epoch"]))
        except (AutopilotError, OSError) as exc:
            with contextlib.suppress(Exception):
                with db.immediate_tx():
                    db._conn.execute(
                        "UPDATE work_units SET last_error = ?, updated_at = ? WHERE unit_key = ?",
                        (f"reclaim_isolated_exception: {sanitize_terminal_text(str(exc), 240)}", now_iso(), cr["unit_key"]),
                    )

    # Pre-scan ALL work_units and pending external_ops for PR-identity or cross-project ownership conflicts
    # (including released historical claims & two-sided PR conflicts); quarantine the entire connected component!
    conflicted_units: set[str] = set()
    for ur_scan in db._conn.execute("SELECT unit_key, pr_id FROM work_units").fetchall():
        _quarantine_if_cross_project_scope(db, ur_scan["unit_key"], ur_scan["pr_id"], conflicted_units)
    all_pend_scan = [
        dict(r)
        for r in db._conn.execute(
            "SELECT unit_key, pr_id FROM external_ops WHERE status IN ('prepared_local', 'in_flight', 'unknown_paused')"
        ).fetchall()
    ]
    for sop in all_pend_scan:
        _quarantine_if_cross_project_scope(db, sop["unit_key"], sop.get("pr_id"), conflicted_units)

    pend_ops = [dict(r) for r in db._conn.execute("SELECT * FROM external_ops WHERE status IN ('in_flight', 'unknown_paused') ORDER BY op_seq ASC").fetchall()]
    for op in pend_ops:
        if op["unit_key"] in conflicted_units:
            continue
        urow = db.get_unit(op["unit_key"])
        if not urow or not urow["repo"]:
            continue
        cl_for_op = db.get_claim(int(op["claim_epoch"])) if op.get("claim_epoch") is not None else None
        claim_pid = str(cl_for_op["project_id"]) if (cl_for_op and cl_for_op.get("project_id")) else ""
        eff_pid = str(op.get("project_id") or claim_pid or urow["project_id"])
        try:
            transport = transport_override or _resolve_strict_project_gh_transport(db, eff_pid, workflows)
        except AutopilotError:
            continue
        if op["owner_kind"] == "worker":
            sender_dead = cl_for_op is None or cl_for_op["state"] == "released" or verify_unit_terminated(cl_for_op["worker_unit_name"], cl_for_op["expected_cgroup_dir"])
        else:
            sender_dead = dispatcher_epoch > int(op["owner_epoch"])
        if sender_dead:
            try:
                res = reconcile_op(
                    db=db,
                    transport=transport,
                    repo=urow["repo"],
                    op_id=op["op_id"],
                    sender_confirmed_terminated=True,
                    dispatcher_epoch=dispatcher_epoch,
                )
            except ScopeConflictError as exc:
                _quarantine_if_cross_project_scope(db, op["unit_key"], op.get("pr_id"), conflicted_units)
                db.mark_unit_needs_human(op["unit_key"], f"reconcile_op scope conflict: {exc}", non_veto=False)
                continue
            reconciled_ops.append(op["op_id"])
            if res.get("_scope_quarantined"):
                _quarantine_if_cross_project_scope(db, op["unit_key"], op.get("pr_id"), conflicted_units)
                continue
            if (
                op["owner_kind"] == "supervisor_admin"
                and int(op["owner_epoch"]) < dispatcher_epoch
                and res["status"] == "unknown_paused"
                and (res.get("unsent_proof") or int(res.get("send_consumed") or 0) == 0)
            ):
                nid = db.replace_admin_op_for_retry(
                    old_op_id=op["op_id"],
                    new_dispatcher_epoch=dispatcher_epoch,
                    dispatcher_lock_held=True,
                )
                replaced_admin_ops.append(nid)

    # Re-inspect remote PR flags for ANY vetoed scope where sync is pending OR a PR-mutating worker op is still unresolved!
    vetoed_rows = [dict(r) for r in db._conn.execute("SELECT * FROM work_units WHERE veto_pending = 1").fetchall()]
    for urow in vetoed_rows:
        if _quarantine_if_cross_project_scope(db, urow["unit_key"], urow.get("pr_id"), conflicted_units):
            continue
        has_unres_worker = _scope_has_unresolved_pr_mutating_worker_op(db, urow["unit_key"])
        if not int(urow["veto_remote_sync_pending"]) and not has_unres_worker:
            continue
        scope = db.resolve_unit_scope_and_pending(urow["unit_key"])
        if any(uk in conflicted_units for uk in scope.scope_units):
            continue
        all_term = _are_all_scope_workers_terminated(db, scope.scope_units)
        if not scope.eff_pr_id or not urow["repo"]:
            if all_term and not has_unres_worker:
                db.mark_veto_remote_synced(urow["unit_key"])
            continue
        try:
            tr = transport_override or _resolve_strict_project_gh_transport(db, urow["project_id"], workflows)
        except AutopilotError:
            continue
        snap = tr.fetch_pr_snapshot(urow["repo"], scope.eff_pr_id, snapshot_seq=db.current_op_seq())
        if snap is not None:
            if snap.state == "OPEN":
                db.register_admin_revoke(
                    unit_key=urow["unit_key"],
                    dispatcher_epoch=dispatcher_epoch,
                    pr_id=scope.eff_pr_id,
                    need_dequeue=(snap.merge_queue_entry_id is not None),
                    need_disable_automerge=snap.auto_merge_enabled,
                    need_draft=(not snap.is_draft),
                    remote_sync_pending=(not all_term or has_unres_worker),
                    reason="deferred_veto_sync",
                )
            if all_term and not has_unres_worker:
                db.mark_veto_remote_synced(urow["unit_key"])

    old_prep = [
        dict(r)
        for r in db._conn.execute(
            "SELECT op_id, unit_key FROM external_ops WHERE owner_kind = 'supervisor_admin' AND status = 'prepared_local' AND owner_epoch < ?",
            (dispatcher_epoch,),
        ).fetchall()
    ]
    for row in old_prep:
        if row["unit_key"] in conflicted_units:
            continue
        nid = db.replace_admin_op_for_retry(
            old_op_id=row["op_id"],
            new_dispatcher_epoch=dispatcher_epoch,
            dispatcher_lock_held=True,
        )
        replaced_admin_ops.append(nid)

    cur_admin_prep = [
        dict(r)
        for r in db._conn.execute(
            "SELECT * FROM external_ops WHERE owner_kind = 'supervisor_admin' AND status = 'prepared_local' AND owner_epoch = ? ORDER BY op_seq ASC",
            (dispatcher_epoch,),
        ).fetchall()
    ]
    for arow in cur_admin_prep:
        if arow["unit_key"] in conflicted_units:
            continue
        urow = db.get_unit(arow["unit_key"])
        if not urow or not urow["repo"]:
            continue
        frozen_adm_pid = str(arow.get("project_id") or "")
        if frozen_adm_pid and urow.get("project_id") and frozen_adm_pid != str(urow["project_id"]):
            continue
        adm_pid = frozen_adm_pid or str(urow["project_id"])
        try:
            transport = transport_override or _resolve_strict_project_gh_transport(db, adm_pid, workflows)
        except AutopilotError:
            continue
        scope = db.resolve_unit_scope_and_pending(arow["unit_key"], pr_id=arow["pr_id"])
        all_term = _are_all_scope_workers_terminated(db, scope.scope_units)
        g = db.promote_op_to_in_flight(
            arow["op_id"],
            caller_owner_kind="supervisor_admin",
            caller_epoch=dispatcher_epoch,
            dispatcher_lock_held=True,
            all_scope_workers_terminated=all_term,
        )
        if g.granted:
            with contextlib.suppress(AutopilotError):
                execute_granted_op(grant=g, db=db, transport=transport, repo=urow["repo"])
                executed_admin_ops.append(arow["op_id"])

    return {
        "reclaimed_claims": reclaimed_claims,
        "replaced_admin_ops": replaced_admin_ops,
        "reconciled_ops": reconciled_ops,
        "executed_admin_ops": executed_admin_ops,
    }


def _execute_lark_payments_payload(cfg: WorkflowConfig, db: AutopilotDB, pending_ids: list[str]) -> tuple[bool, dict[str, Any]]:
    ws = Path(cfg.workspace_path).expanduser().resolve()
    zone = ZoneInfo(str(cfg.extra.get("timezone") or "America/Los_Angeles"))
    mailbox = str(cfg.extra.get("mailbox") or os.environ.get("AUTOPILOT_LARK_MAILBOX") or "").strip()
    now_str = dt.datetime.now(zone).strftime("%m-%d %H:%M %Z")
    codex_bin = shutil.which("codex") or "/usr/local/bin/codex"
    wf_body = (cfg.prompt_body or "").strip()
    owner_hint = f"指定邮箱 `{mailbox}`" if mailbox else "WORKFLOW.md 中指定的本人邮箱"
    prompt = (
        f"{wf_body}\n\n"
        f"---\n当前时间 {now_str}。执行邮件例行巡检（运行目录 {ws}）：\n"
        f"1. 待处理新邮件 ID：{json.dumps(pending_ids)}；严格阅读运行目录下 STATUS.md 与关联台账中的统一对外口径；\n"
        "2. 严禁向任何第三方发送邮件、提交表单、预约会议或上传文件！需要回复的外部收件人仅用 `lark-cli mail +draft-create` 在草稿箱创建草稿（创建前先查草稿箱防重复）；\n"
        "3. 将已处理的邮件 ID 追加写入 processed_ids.txt，更新 STATUS.md 台账与处理记录，全部待处理邮件处理成功后再更新 last_full_run；\n"
        f"4. 仅当本轮实际新建了草稿或新增了需要用户决定的待办时，才用 `lark-cli` 向 {owner_hint} 发送汇总提醒；若无新草稿且无新增待办，绝不发提醒邮件。"
    )
    before_mtime = (ws / "last_full_run").stat().st_mtime if (ws / "last_full_run").exists() else 0.0
    t0 = time.monotonic()
    proc = subprocess.run(
        [
            codex_bin,
            "exec",
            "-C",
            str(ws),
            "--dangerously-bypass-approvals-and-sandbox",
            "-c",
            "features.multi_agent=false",
            "--skip-git-repo-check",
            "-",
        ],
        input=prompt,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    dur_ms = int((time.monotonic() - t0) * 1000)
    after_mtime = (ws / "last_full_run").stat().st_mtime if (ws / "last_full_run").exists() else 0.0
    ok = proc.returncode == 0 and after_mtime > before_mtime
    if not ok:
        with db.immediate_tx():
            db._conn.execute("DELETE FROM routine_cursors WHERE project_id = ?", (cfg.project_id,))
    with db.immediate_tx():
        db._conn.execute(
            "INSERT INTO run_history(run_id, project_id, unit_key, status, duration_ms, completed_at) VALUES (?, ?, ?, ?, ?, ?)",
            (f"run-{uuid.uuid4().hex[:12]}", cfg.project_id, f"{cfg.project_id}:hourly", "succeeded" if ok else "failed", dur_ms, now_iso()),
        )
    return ok, {
        "project_id": cfg.project_id,
        "status": "executed_codex" if ok else "failed",
        "duration_ms": dur_ms,
        "pending_ids": pending_ids,
        "exit_code": proc.returncode,
    }


def _execute_custom_routine_payload(cfg: WorkflowConfig, db: AutopilotDB) -> tuple[bool, dict[str, Any]]:
    """Execute a universal custom routine via deterministic shell `routine_cmd` or sandboxed `codex exec` `routine_prompt`."""
    from ap_core.dream import sync_project_pitfalls_markdown

    ws = Path(cfg.workspace_path).expanduser().resolve()
    routine_cmd = str(cfg.extra.get("routine_cmd") or "").strip()
    routine_prompt = str(cfg.extra.get("routine_prompt") or cfg.prompt_body or "").strip()
    t0 = time.monotonic()
    if routine_cmd:
        proc = subprocess.run(
            ["/bin/bash", "-lc", routine_cmd],
            cwd=str(ws) if ws.is_dir() else None,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        mode = "routine_cmd"
    else:
        codex_bin = shutil.which("codex") or "/usr/local/bin/codex"
        proc = subprocess.run(
            [
                codex_bin,
                "exec",
                "-C",
                str(ws),
                "-s",
                "workspace-write",
                "-c",
                "features.multi_agent=false",
                "--skip-git-repo-check",
                "-",
            ],
            input=routine_prompt,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        mode = "routine_prompt"
    dur_ms = int((time.monotonic() - t0) * 1000)
    ok = proc.returncode == 0
    if not ok:
        with db.immediate_tx():
            db._conn.execute("DELETE FROM routine_cursors WHERE project_id = ?", (cfg.project_id,))
        db.record_pitfall(
            project_id=cfg.project_id,
            target_area="routine",
            symptom=f"Custom routine ({mode}) exited {proc.returncode}",
            rule_text=sanitize_terminal_text(proc.stderr or proc.stdout or "Verify routine command/prompt prerequisites", 180),
        )
        sync_project_pitfalls_markdown(db, cfg.project_id)
    with db.immediate_tx():
        db._conn.execute(
            "INSERT INTO run_history(run_id, project_id, unit_key, status, duration_ms, completed_at) VALUES (?, ?, ?, ?, ?, ?)",
            (f"run-{uuid.uuid4().hex[:12]}", cfg.project_id, f"{cfg.project_id}:routine", "succeeded" if ok else "failed", dur_ms, now_iso()),
        )
    return ok, {
        "project_id": cfg.project_id,
        "mode": mode,
        "status": "succeeded" if ok else "failed",
        "duration_ms": dur_ms,
        "exit_code": proc.returncode,
    }


def _worker_root_env(state_root: Path) -> dict[str, str]:
    return {
        "AGENT_AUTOPILOT_STATE_DIR": str(state_root.resolve()),
        "AGENT_AUTOPILOT_CONFIG_DIR": str(default_config_root()),
        "AGENT_AUTOPILOT_CACHE_DIR": str(default_cache_root()),
        "PYTHONUNBUFFERED": "1",
    }


def _submit_routine_worker_nonblocking(
    *,
    cfg: WorkflowConfig,
    db: AutopilotDB,
    state_root: Path,
    pending_ids: list[str],
) -> dict[str, Any]:
    """Atomically reserve slot + max_per_day under dispatcher.lock, then run routine outside dispatcher.lock!"""
    ukey = f"{cfg.project_id}:routine"
    db.ensure_work_unit(unit_key=ukey, project_id=cfg.project_id, repo="")
    slot_key = f"{cfg.project_id}:slot-1"
    db.ensure_lease_slots(cfg.project_id, [slot_key], state_root / "locks")
    uname = f"ap-routine-{cfg.project_id}-{uuid.uuid4().hex[:6]}.service"
    exp_cg = expected_transient_cgroup_dir(uname)
    r_tag = f"{int(time.time())}-{uuid.uuid4().hex[:6]}"
    r_parent = ensure_secure_dir(default_cache_root() / "routines" / cfg.project_id, 0o700)
    rp_fd = open_dir_nofollow(r_parent, create=False)
    try:
        st_rp = os.fstat(rp_fd)
    finally:
        os.close(rp_fd)
    r_dir = r_parent / f"claim-{r_tag}"

    with _try_acquire_slot_flocks(db, [slot_key]) as slot_fds:
        ce = db.claim_and_reserve(
            unit_key=ukey,
            cfg=cfg,
            slot_keys=[slot_key],
            worker_unit_name=uname,
            expected_cgroup_dir=str(exp_cg),
            base_sha="routine",
            authorized_head_ref=f"{cfg.branch_prefix}routine",
            run_dir=str(r_dir),
            frozen_cache_dir=str(r_parent.resolve()),
            frozen_cache_dev=int(st_rp.st_dev),
            frozen_cache_ino=int(st_rp.st_ino),
        )
        sd_proc = spawn_transient_unit_under_flock(
            unit_name=uname,
            cmd=[
                sys.executable,
                str(Path(__file__).resolve()),
                "routine-exec",
                "--project",
                cfg.project_id,
                "--claim-epoch",
                str(ce),
                f"--pending-ids-json={json.dumps(pending_ids)}",
            ],
            flock_fds=slot_fds,
            wait=False,
            unit_kind="worker",
            extra_env=_worker_root_env(state_root),
        )
        if sd_proc.returncode != 0:
            raise AutopilotError(f"routine systemd-run failed ({sd_proc.returncode}): {sd_proc.stderr.strip()}")
        return {
            "project_id": cfg.project_id,
            "unit_key": ukey,
            "claim_epoch": ce,
            "worker_unit_name": uname,
            "expected_cgroup_dir": str(exp_cg),
        }


def _resolve_project_gh_identity_unlocked(cfg: WorkflowConfig) -> tuple[str, str]:
    """Resolve immutable (gh_token, verified_login) OUTSIDE dispatcher.lock; reject if token or login cannot be proven!"""
    if cfg.token_file and cfg.token_file.strip():
        tok = read_nonempty_token_file(cfg.token_file)
    else:
        tok = (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()
        if not tok:
            env = dict(os.environ, GH_PROMPT_DISABLED="1")
            try:
                proc = subprocess.run(["gh", "auth", "token"], env=env, capture_output=True, text=True, timeout=30, check=False)
            except (subprocess.SubprocessError, OSError) as exc:
                raise AutopilotError(f"Failed to query `gh auth token` in ambient mode: {exc}") from exc
            tok = proc.stdout.strip() if proc.returncode == 0 else ""
        if not tok:
            raise AutopilotError(f"Unable to materialize GitHub token for {cfg.project_id}; refusing unverified reservation")
    login = LiveGitHubCliTransport(token=tok, require_explicit_token=True).bot_login or ""
    if not login:
        raise AutopilotError(f"Unable to verify GitHub login for {cfg.project_id}; refusing reservation with unknown identity")
    return tok, login


def _write_sealed_token_file(ephem_path: Path, tok: str) -> None:
    ensure_secure_dir(ephem_path.parent, 0o700)
    fd = os.open(str(ephem_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (tok + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _project_effective_cap(cfg: WorkflowConfig, db: AutopilotDB) -> int:
    prow = db.get_project_row(cfg.project_id)
    if prow is None:
        return max(1, int(cfg.max_in_progress))
    eff = (
        int(prow["max_in_progress"])
        if int(prow["current_step_idx"]) > 0
        else min(int(cfg.max_in_progress), int(prow["max_in_progress"]))
    )
    return max(1, eff)


def _submit_issue_worker_nonblocking(
    *,
    cfg: WorkflowConfig,
    db: AutopilotDB,
    state_root: Path,
    cand: dict[str, Any],
    prefetched_bases: dict[str, tuple[Path, str]],
    pre_resolved_gh: tuple[str, str],
) -> dict[str, Any]:
    """Fast non-blocking submission under dispatcher.lock (ZERO network I/O; token file written ONLY after claim succeeds!)."""
    ukey = cand["unit_key"]
    repo = cand["repo"]
    inum = int(cand["number"])
    if repo not in prefetched_bases:
        raise AutopilotError(f"Missing prefetched base for {repo}")
    mg, base_sha = prefetched_bases[repo]
    resolved_tok, verified_login = pre_resolved_gh

    db.ensure_work_unit(unit_key=ukey, project_id=cfg.project_id, repo=repo, issue_number=inum)
    scope = db.resolve_unit_scope_and_pending(ukey)
    if scope.any_veto != 0 or scope.pending_cnt != 0:
        raise AutopilotError(f"Unit {ukey} blocked by veto/pending external_ops")
    eff_cap = _project_effective_cap(cfg, db)
    slot_pool = [f"{cfg.project_id}:slot-{idx}" for idx in range(1, eff_cap + 1)]
    db.ensure_lease_slots(cfg.project_id, slot_pool, state_root / "locks")
    free_set = {
        str(r["slot_key"])
        for r in db._conn.execute(
            f"SELECT slot_key FROM leases WHERE slot_key IN ({','.join('?' for _ in slot_pool)}) AND state = 'free'",
            slot_pool,
        ).fetchall()
    }
    ordered_free_slots = [sk for sk in slot_pool if sk in free_set]
    if not ordered_free_slots:
        raise AutopilotError(f"All lease slots busy for {cfg.project_id}: {slot_pool}")

    rcache = repo_cache_dir(cfg.project_id, repo)
    rc_fd = open_dir_nofollow(rcache, create=False)
    try:
        st_rc = os.fstat(rc_fd)
    finally:
        os.close(rc_fd)
    head_ref = f"{cfg.branch_prefix}issue-{inum}"
    sealed_dir = ensure_sealed_tokens_dir(state_root)

    last_slot_err: Exception | None = None
    for slot_key in ordered_free_slots:
        tag = f"{inum}-{uuid.uuid4().hex[:8]}"
        uname = f"ap-worker-{cfg.project_id}-{tag}.service"
        exp_cg = expected_transient_cgroup_dir(uname)
        persisted_run_dir = rcache / "runs" / f"claim-{tag}"
        persisted_wt_dir = rcache / "worktrees" / f"wt-{tag}"
        ephem_tok_path = str(sealed_dir / f"claim-{cfg.project_id}-{tag}.gh_token")
        with contextlib.ExitStack() as stack:
            try:
                slot_fds = stack.enter_context(_try_acquire_slot_flocks(db, [slot_key]))
            except (AutopilotError, OSError) as flock_exc:
                last_slot_err = flock_exc
                continue
            # Persist run_claim FIRST so rejected claims leave ZERO token files on disk, and accepted claims track cleanup!
            ce = db.claim_and_reserve(
                unit_key=ukey,
                cfg=cfg,
                slot_keys=[slot_key],
                worker_unit_name=uname,
                expected_cgroup_dir=str(exp_cg),
                base_sha=base_sha,
                authorized_head_ref=head_ref,
                run_dir=str(persisted_run_dir),
                worktree_path=str(persisted_wt_dir),
                managed_gitdir=str(mg),
                frozen_cache_dir=str(rcache.resolve()),
                frozen_cache_dev=int(st_rc.st_dev),
                frozen_cache_ino=int(st_rc.st_ino),
                bound_gh_login=verified_login,
                ephemeral_token_file=ephem_tok_path,
            )
            try:
                if ephem_tok_path:
                    _write_sealed_token_file(Path(ephem_tok_path), resolved_tok)
                sd_proc = spawn_transient_unit_under_flock(
                    unit_name=uname,
                    cmd=[
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "worker-exec",
                        "--project",
                        cfg.project_id,
                        "--unit-key",
                        ukey,
                        "--claim-epoch",
                        str(ce),
                        f"--issue-title={cand.get('title') or ''}",
                    ],
                    flock_fds=slot_fds,
                    wait=False,
                    unit_kind="worker",
                    extra_env=_worker_root_env(state_root),
                    timeout_overrides={"runtime_max_sec": 7200, "wrapper_sigterm_sec": 7260},
                )
                if sd_proc.returncode != 0:
                    raise AutopilotError(f"systemd-run submission failed ({sd_proc.returncode}): {sd_proc.stderr.strip()}")
            except BaseException:
                if ephem_tok_path:
                    with contextlib.suppress(OSError):
                        Path(ephem_tok_path).unlink(missing_ok=True)
                raise
            return {
                "project_id": cfg.project_id,
                "unit_key": ukey,
                "slot_key": slot_key,
                "claim_epoch": ce,
                "worker_unit_name": uname,
                "expected_cgroup_dir": str(exp_cg),
            }

    raise AutopilotError(f"All free lease slots flock-busy for {cfg.project_id}: {last_slot_err}")


def _submit_delegated_worker_nonblocking(
    *,
    cfg: WorkflowConfig,
    db: AutopilotDB,
    state_root: Path,
    pre_resolved_gh: tuple[str, str],
) -> dict[str, Any]:
    """Claim an exclusive slot for delegated projects; seal token ONLY after claim_and_reserve succeeds!"""
    resolved_tok, verified_login = pre_resolved_gh
    ukey = f"{cfg.project_id}:delegated"
    db.ensure_work_unit(unit_key=ukey, project_id=cfg.project_id, repo=cfg.repos[0] if cfg.repos else "")
    slot_key = f"{cfg.project_id}:slot-1"
    db.ensure_lease_slots(cfg.project_id, [slot_key], state_root / "locks")

    uname = f"ap-delegated-{cfg.project_id}-{uuid.uuid4().hex[:6]}.service"
    exp_cg = expected_transient_cgroup_dir(uname)
    is_dedicated = bool(cfg.token_file and cfg.token_file.strip())
    tpath = str(Path(cfg.token_file.strip()).expanduser().resolve()) if is_dedicated else ""
    d_cmd = cfg.delegated_cmd or f"python3 {Path(cfg.workspace_path) / 'scripts/autopilot_run.py'}"
    d_tag = uuid.uuid4().hex[:8]
    d_parent = ensure_secure_dir(default_cache_root() / "delegated" / cfg.project_id, 0o700)
    dp_fd = open_dir_nofollow(d_parent, create=False)
    try:
        st_dp = os.fstat(dp_fd)
    finally:
        os.close(dp_fd)
    r_dir = d_parent / f"claim-{d_tag}"
    sealed_dir_d = ensure_sealed_tokens_dir(state_root)
    ephem_tok_d = str(sealed_dir_d / f"delegated-{cfg.project_id}-{d_tag}.gh_token")

    with _try_acquire_slot_flocks(db, [slot_key]) as slot_fds:
        ce = db.claim_and_reserve(
            unit_key=ukey,
            cfg=cfg,
            slot_keys=[slot_key],
            worker_unit_name=uname,
            expected_cgroup_dir=str(exp_cg),
            base_sha="delegated",
            authorized_head_ref=f"{cfg.branch_prefix}delegated",
            run_dir=str(r_dir),
            frozen_cache_dir=str(d_parent.resolve()),
            frozen_cache_dev=int(st_dp.st_dev),
            frozen_cache_ino=int(st_dp.st_ino),
            bound_gh_login=verified_login,
            ephemeral_token_file=ephem_tok_d,
        )
        try:
            if ephem_tok_d:
                _write_sealed_token_file(Path(ephem_tok_d), resolved_tok)
            sd_proc = spawn_transient_unit_under_flock(
                unit_name=uname,
                cmd=[
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "delegated-exec",
                    "--claim-epoch",
                    str(ce),
                    "--token-file",
                    tpath,
                    "--cmd",
                    d_cmd,
                ],
                flock_fds=slot_fds,
                wait=False,
                unit_kind="worker",
                extra_env=_worker_root_env(state_root),
                timeout_overrides={"runtime_max_sec": 14400, "wrapper_sigterm_sec": 14460},
            )
            if sd_proc.returncode != 0:
                raise AutopilotError(f"delegated systemd-run failed ({sd_proc.returncode}): {sd_proc.stderr.strip()}")
        except BaseException:
            if ephem_tok_d:
                with contextlib.suppress(OSError):
                    Path(ephem_tok_d).unlink(missing_ok=True)
            raise
        return {
            "project_id": cfg.project_id,
            "unit_key": ukey,
            "claim_epoch": ce,
            "worker_unit_name": uname,
            "expected_cgroup_dir": str(exp_cg),
        }


def _prepare_worker_pinned_paths(
    cl: dict[str, Any],
    ce: int,
    rcache: Path,
    rcache_fd: int,
    *,
    db: AutopilotDB | None = None,
) -> tuple[Path, Path, Path, Path, int]:
    """Derive `(pinned_rc, mg, pinned_run_dir, wt_dir, run_dir_fd)` retaining BOTH `rcache_fd` AND `run_dir_fd` open!"""
    raw_mg = Path(os.path.normpath(str(cl["managed_gitdir"]))) if cl.get("managed_gitdir") else (rcache / "managed.git")
    raw_run_dir = Path(os.path.normpath(str(cl["run_dir"]))) if cl.get("run_dir") else (rcache / "runs" / f"claim-{ce}")
    raw_wt_dir = Path(os.path.normpath(str(cl["worktree_path"]))) if cl.get("worktree_path") else (rcache / "worktrees" / f"wt-{ce}")
    if raw_mg.parent != rcache or raw_run_dir.parent != (rcache / "runs") or raw_wt_dir.parent != (rcache / "worktrees"):
        raise AutopilotError(
            f"Refusing worker-exec with paths outside verified cache root {rcache}: mg={raw_mg}, run_dir={raw_run_dir}, wt={raw_wt_dir}"
        )
    pinned_rc = pinned_proc_fd_path(rcache_fd)
    mg = pinned_rc / "managed.git"
    os.close(open_dir_nofollow(mg, create=False))
    rfd = open_dir_nofollow(
        pinned_rc / "runs" / raw_run_dir.name,
        create=True,
        mode=0o700,
        expected_dev=cl.get("run_dir_dev"),
        expected_ino=cl.get("run_dir_ino"),
        fsync_ancestors=True,
    )
    try:
        st_rd = os.fstat(rfd)
        if db is not None:
            db.record_claim_run_dir_identity(ce, int(st_rd.st_dev), int(st_rd.st_ino))
    except BaseException:
        os.close(rfd)
        raise
    pinned_run_dir = pinned_proc_fd_path(rfd)
    wt_dir = pinned_rc / "worktrees" / raw_wt_dir.name
    return pinned_rc, mg, pinned_run_dir, wt_dir, rfd


def cmd_worker_exec(args: argparse.Namespace) -> int:
    """Internal worker entrypoint: verifies real cgroup identity & retains verified cache + run_dir fds BEFORE running pipeline!"""
    sroot = default_state_root()
    db = AutopilotDB(sroot / "autopilot.db")
    rcache_fd: int | None = None
    run_dir_fd: int | None = None
    tbc_fd: int | None = None
    try:
        wfs = {w.project_id: w for w in load_all_workflows()}
        if args.project not in wfs:
            raise AutopilotError(f"Unknown project {args.project!r}")
        cfg = wfs[args.project]
        ce = int(args.claim_epoch)
        cl = db.get_claim(ce)
        if not cl or cl["state"] != "active" or cl["project_id"] != args.project or cl["unit_key"] != args.unit_key:
            raise AutopilotError(f"Claim mismatch or inactive in worker-exec (claim_epoch={ce})")
        if not verify_self_in_expected_cgroup(cl["expected_cgroup_dir"]):
            raise AutopilotError(
                f"Refusing worker-exec outside registered cgroup {cl['expected_cgroup_dir']}"
            )
        repo = str(cl["repo"])
        rcache = _effective_claim_cache_dir(cl)
        rcache_fd = _open_verified_claim_cache_fd(cl, rcache)
        if rcache_fd is None:
            raise AutopilotError(
                f"Refusing worker-exec: frozen cache root {rcache} unmounted, symlinked, or device/inode drifted"
            )
        pinned_rc, mg, run_dir, wt_dir, run_dir_fd = _prepare_worker_pinned_paths(cl, ce, rcache, rcache_fd, db=db)
        ws = Path(cfg.workspace_path).expanduser().resolve() if (cfg.workspace_path and len(cfg.repos) <= 1) else None
        bins = resolve_host_binaries()
        if cfg.token_file and cfg.token_file.strip():
            # Enforce dedicated token_file still exists & is non-empty, then use the sealed claim-bound credential!
            read_nonempty_token_file(cfg.token_file)
        bound_login_w = str(cl.get("bound_gh_login") or "").strip()
        ephem_tf_w = str(cl.get("ephemeral_token_file") or "").strip()
        if not bound_login_w or not ephem_tf_w:
            raise AutopilotError(
                f"Legacy active claim_epoch={ce} missing bound_gh_login or ephemeral_token_file; refusing execution until reclaimed"
            )
        ephem_tok = read_nonempty_token_file(ephem_tf_w)
        gh_tr = LiveGitHubCliTransport(token=ephem_tok, cache_dir=pinned_rc, require_explicit_token=True)
        actual_login = gh_tr.bot_login
        if not actual_login or actual_login != bound_login_w:
            raise AutopilotError(
                f"Worker GitHub identity {actual_login!r} mismatches claim bound_gh_login {bound_login_w!r}"
            )
        tbc, tbc_fd = prepare_trusted_base_cache_fd(managed_gitdir=mg, base_sha=str(cl["base_sha"]), cache_root=pinned_rc)
        ro_ws_deps_w = tuple(str(x).strip() for x in (cfg.extra.get("ro_workspace_deps") or []) if str(x).strip())
        runner = LiveSandboxedModelRunner(
            bins,
            default_cache_root(),
            run_dir_fd=run_dir_fd,
            db=db,
            claim_epoch=ce,
            trusted_base_cache_fd=tbc_fd,
            repo_main_dir=ws,
            ro_workspace_deps=ro_ws_deps_w,
        )
        if tbc_fd is not None and (pinned_proc_fd_path(tbc_fd) / "cargo_home").is_dir():
            # Pre-model toolchain smoke check: retain `ct_smoke_fd` and `vo_smoke_fd` open (`skip_clean_tree_copy=True`), empty via fd, and ONLY `os.rmdir` empty shells!
            assert run_dir_fd is not None
            smoke_tag = uuid.uuid4().hex[:10]
            ct_name = f".cargo-smoke-ct-{smoke_tag}"
            vo_name = f".cargo-smoke-vo-{smoke_tag}"
            os.mkdir(ct_name, 0o700, dir_fd=run_dir_fd)
            ct_smoke_fd = os.open(ct_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=run_dir_fd)
            try:
                os.mkdir(vo_name, 0o700, dir_fd=run_dir_fd)
                vo_smoke_fd = os.open(vo_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=run_dir_fd)
            except BaseException:
                os.close(ct_smoke_fd)
                with contextlib.suppress(OSError):
                    os.rmdir(ct_name, dir_fd=run_dir_fd)
                raise
            smoke_ct = pinned_proc_fd_path(ct_smoke_fd)
            smoke_vo = pinned_proc_fd_path(vo_smoke_fd)
            smoke_fds: list[int] = []
            try:
                c_argv = build_execution_ring_bwrap(
                    ring_kind="verify_ring",
                    inner_cmd=["/bin/bash", "-lc", "cargo --version"],
                    cwd=smoke_vo,
                    clean_tree=smoke_ct,
                    verify_out_dir=smoke_vo,
                    trusted_base_cache=tbc,
                    skip_clean_tree_copy=True,
                    retain_fds=smoke_fds,
                    clean_tree_fd=ct_smoke_fd,
                    verify_out_fd=vo_smoke_fd,
                    trusted_base_cache_fd=tbc_fd,
                )
                c_chk = subprocess.run(
                    c_argv,
                    capture_output=True,
                    text=True,
                    pass_fds=tuple(smoke_fds),
                    timeout=20,
                    check=False,
                )
            finally:
                for _sfd in smoke_fds:
                    with contextlib.suppress(OSError):
                        os.close(_sfd)
                for _fd_sm, _nm_sm in ((ct_smoke_fd, ct_name), (vo_smoke_fd, vo_name)):
                    with contextlib.suppress(Exception):
                        empty_and_fsync_dirfd(_fd_sm)
                    with contextlib.suppress(OSError):
                        os.close(_fd_sm)
                    with contextlib.suppress(OSError):
                        os.rmdir(_nm_sm, dir_fd=run_dir_fd)
            if c_chk.returncode != 0:
                raise AutopilotError(f"Pre-model verify_ring cargo toolchain check failed: {c_chk.stderr or c_chk.stdout}")
        secret = load_or_create_hmac_secret(sroot)
        urow_w = db.get_unit(args.unit_key)
        issue_num_w = int(urow_w["issue_number"]) if (urow_w and urow_w.get("issue_number")) else 0
        rich_issue_md = (
            gh_tr.fetch_issue_context_markdown(repo, issue_num_w, fallback_title=args.issue_title)
            if issue_num_w > 0
            else f"{args.unit_key}: {args.issue_title}"
        )
        try:
            res = execute_chef_issue_pipeline(
                db=db,
                cfg=cfg,
                unit_key=args.unit_key,
                repo=repo,
                issue_summary=rich_issue_md,
                claim_epoch=ce,
                managed_gitdir=mg,
                worktree_dir=wt_dir,
                repo_main=ws,
                run_dir=run_dir,
                advisory_dir=sroot / "advisory" / cfg.project_id,
                model_runner=runner,
                gh_transport=gh_tr,
                hmac_secret=secret,
                use_bwrap_verify=True,
                trusted_base_cache=tbc,
                trusted_base_cache_fd=tbc_fd,
            )
        except QuotaExhaustedError as qexc:
            db.record_claim_outcome(ce, f"waiting_quota:{qexc.wake_at_iso}")
            print(json.dumps({"status": "waiting_quota", "wake_at": qexc.wake_at_iso, "family": qexc.family}, ensure_ascii=False))
            return 0
        ok_pub = res.get("status") == "published"
        db.record_claim_outcome(ce, "succeeded" if ok_pub else f"failed:{res.get('status')}")
        print(json.dumps(res, ensure_ascii=False))
        return 0 if ok_pub else 1
    finally:
        if tbc_fd is not None:
            with contextlib.suppress(OSError):
                os.close(tbc_fd)
        if run_dir_fd is not None:
            with contextlib.suppress(OSError):
                os.close(run_dir_fd)
        if rcache_fd is not None:
            with contextlib.suppress(OSError):
                os.close(rcache_fd)
        db.close()


def cmd_routine_exec(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    db = AutopilotDB(sroot / "autopilot.db")
    try:
        wfs = {w.project_id: w for w in load_all_workflows()}
        if args.project not in wfs:
            raise AutopilotError(f"Unknown project {args.project!r}")
        cfg = wfs[args.project]
        ce = int(args.claim_epoch)
        cl = db.get_claim(ce)
        if not cl or cl["state"] != "active" or not verify_self_in_expected_cgroup(cl["expected_cgroup_dir"]):
            raise AutopilotError("Refusing routine-exec outside registered active cgroup")
        pending_ids = json.loads(args.pending_ids_json or "[]")
        if cfg.routine_driver == "lark_payments":
            ok, payload = _execute_lark_payments_payload(cfg, db, pending_ids)
        else:
            ok, payload = _execute_custom_routine_payload(cfg, db)
        with db.immediate_tx():
            if ok:
                db._conn.execute(
                    "UPDATE work_units SET status = 'queued', failure_streak = 0, updated_at = ? WHERE unit_key = ?",
                    (now_iso(), cl["unit_key"]),
                )
            db.record_claim_outcome(ce, "succeeded" if ok else "failed")
        print(json.dumps(payload, ensure_ascii=False))
        return 0 if ok else 1
    finally:
        db.close()


def cmd_delegated_exec(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    db = AutopilotDB(sroot / "autopilot.db")
    try:
        ce = int(args.claim_epoch)
        cl = db.get_claim(ce)
        if not cl or cl["state"] != "active" or not verify_self_in_expected_cgroup(cl["expected_cgroup_dir"]):
            raise AutopilotError("Refusing delegated-exec outside registered active cgroup")
        prow = db.get_project_row(str(cl["project_id"]))
        req_tf = args.token_file.strip() or (str(prow["token_file"]).strip() if (prow and prow.get("token_file")) else "")
        need_dedicated = bool(req_tf or (prow and prow.get("token_mode") == "dedicated"))
        ephem_tf = str(cl.get("ephemeral_token_file") or "").strip()
        bound_login = str(cl.get("bound_gh_login") or "").strip()
    finally:
        db.close()

    env = dict(os.environ)
    if not bound_login or not ephem_tf:
        raise AutopilotError("Legacy delegated claim missing bound_gh_login or ephemeral_token_file; refusing execution until reclaimed")
    if need_dedicated:
        read_nonempty_token_file(req_tf)
    tok = read_nonempty_token_file(ephem_tf)
    env.pop("GITHUB_TOKEN", None)
    env["GH_TOKEN"] = tok
    chk_login = LiveGitHubCliTransport(token=env["GH_TOKEN"], require_explicit_token=True).bot_login
    if not chk_login or chk_login != bound_login:
        raise AutopilotError(f"delegated-exec GitHub identity {chk_login!r} != bound_gh_login {bound_login!r}")
    shell_cmd = args.delegated_shell_cmd if hasattr(args, "delegated_shell_cmd") else args.cmd
    proc = subprocess.run(["/bin/bash", "-lc", shell_cmd], env=env, check=False)
    db2 = AutopilotDB(sroot / "autopilot.db")
    try:
        cl2 = db2.get_claim(int(args.claim_epoch))
        if cl2:
            if proc.returncode == 0:
                with db2.immediate_tx():
                    db2._conn.execute("UPDATE work_units SET status = 'queued', failure_streak = 0, updated_at = ? WHERE unit_key = ?", (now_iso(), cl2["unit_key"]))
                    db2.record_claim_outcome(int(args.claim_epoch), "succeeded")
            else:
                db2.record_claim_outcome(int(args.claim_epoch), f"failed:{proc.returncode}")
    finally:
        db2.close()
    return proc.returncode


def cmd_scrub_worktree(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    db = AutopilotDB(sroot / "autopilot.db", readonly=True)
    rcache_fd: int | None = None
    try:
        ce = int(args.claim_epoch)
        cl = db.get_claim(ce)
        if not cl or cl.get("state") != "reclaiming":
            raise AutopilotError(f"Refusing scrub-worktree: claim_epoch={ce} is not in 'reclaiming' state")
        cu_cg = str(cl.get("cleanup_cgroup_dir") or "").strip()
        if not cu_cg or not verify_self_in_expected_cgroup(cu_cg):
            raise AutopilotError(f"Refusing scrub-worktree outside registered cleanup cgroup {cu_cg!r}")
        raw_rcache = _effective_claim_cache_dir(cl)
        rcache_fd = _open_verified_claim_cache_fd(cl, raw_rcache)
        if rcache_fd is None:
            raise AutopilotError(f"Frozen cache root {raw_rcache} is unmounted, missing, or device/inode drifted")
        raw_mg = Path(os.path.normpath(str(cl["managed_gitdir"]))) if cl.get("managed_gitdir") else (raw_rcache / "managed.git")
        raw_wt = Path(os.path.normpath(str(cl["worktree_path"]))) if cl.get("worktree_path") else (raw_rcache / "worktrees" / f"wt-{ce}")
        if raw_mg.parent != raw_rcache or raw_wt.parent != (raw_rcache / "worktrees"):
            raise AutopilotError(f"Refusing scrub-worktree outside frozen cache root {raw_rcache}: wt={raw_wt}, mg={raw_mg}")
        registered_wt_name = raw_wt.name
        pinned_rc = pinned_proc_fd_path(rcache_fd)
        mg = pinned_rc / "managed.git"
        wt_gd = mg / "worktrees" / registered_wt_name
        wt = pinned_rc / "worktrees" / registered_wt_name
        base_sha = str(cl["base_sha"])
        db.close()
        return scrub_worktree_to_base(
            managed_gitdir=mg,
            wt_gitdir=wt_gd,
            worktree=wt,
            base_sha=base_sha,
        )
    finally:
        db.close()
        if rcache_fd is not None:
            with contextlib.suppress(OSError):
                os.close(rcache_fd)


def cmd_doctor(args: argparse.Namespace) -> int:
    bins = resolve_host_binaries()
    native_ok = False
    native_err = ""
    try:
        verify_native_binaries(bins["ap_sandbox_init"], bins["ap_safe_sh"])
        native_ok = True
    except Exception as exc:
        native_err = str(exc)

    linger_ok = check_linger_enabled()
    bwrap_ok = shutil.which("bwrap") is not None
    sd_run_ok = shutil.which("systemd-run") is not None
    gh_ok = shutil.which("gh") is not None
    lark_ok = shutil.which("lark-cli") is not None
    workflows = load_all_workflows()

    report = {
        "version": __version__,
        "schema_version": SCHEMA_VERSION,
        "ready": bool(native_ok and linger_ok and bwrap_ok and sd_run_ok and ("codex_cli" in bins or "claude_cli" in bins)),
        "linger_enabled": linger_ok,
        "bwrap": bwrap_ok,
        "systemd_run": sd_run_ok,
        "gh_cli": gh_ok,
        "lark_cli": lark_ok,
        "native_binaries_ok": native_ok,
        "native_error": native_err or None,
        "binaries": {k: str(v) for k, v in bins.items()},
        "projects": [
            {"project_id": w.project_id, "kind": w.kind, "enabled": w.enabled, "tier": w.trust_tier}
            for w in workflows
        ],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ready"] else 1


def cmd_selftest(args: argparse.Namespace) -> int:
    m = POLICY_MANIFEST
    for raw_bad in m["expected_raw_invalid_path_samples"]:
        try:
            validate_raw_git_path(raw_bad)
        except ScopeViolationError:
            pass
        else:
            raise AutopilotError(f"Failed to reject invalid raw path: {raw_bad!r}")

    for hs in m["expected_hard_stop_samples"]:
        try:
            check_autopilot_scope([hs], ["**"])
        except ScopeViolationError:
            pass
        else:
            raise AutopilotError(f"Failed to block hard-stop sample: {hs!r}")

    check_autopilot_scope(list(m["expected_allow_samples"]), ["src/**", "apps/server/src/**", "packages/ui/src/**"])

    live_details: dict[str, Any] = {}
    if args.live:
        bins = resolve_host_binaries()
        verify_native_binaries(bins["ap_sandbox_init"], bins["ap_safe_sh"])
        if not check_linger_enabled():
            raise AutopilotError("systemd linger is not enabled")
        sroot = default_state_root()
        ensure_secure_dir(sroot, 0o700)
        lf = sroot / "selftest.flock"
        lfd = os.open(str(lf), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            uname = f"ap-selftest-{uuid.uuid4().hex[:8]}.service"
            exp_cg = expected_transient_cgroup_dir(uname)
            proc = spawn_transient_unit_under_flock(
                unit_name=uname,
                cmd=["/bin/true"],
                flock_fd=lfd,
                wait=True,
                unit_kind="cleanup",
            )
            term_ok = verify_unit_terminated(uname, exp_cg)
            if proc.returncode != 0 or not term_ok:
                raise AutopilotError(f"Live systemd transient unit selftest failed: rc={proc.returncode}, terminated={term_ok}")
            live_details["systemd_transient_unit"] = "ok"
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(lfd, fcntl.LOCK_UN)
            os.close(lfd)

    print(
        json.dumps(
            {
                "selftest": "OK",
                "schema_version": SCHEMA_VERSION,
                "raw_invalid_rejected": len(m["expected_raw_invalid_path_samples"]),
                "hard_stop_blocked": len(m["expected_hard_stop_samples"]),
                "allow_passed": len(m["expected_allow_samples"]),
                "live": live_details if args.live else False,
            },
            indent=2,
        )
    )
    return 0


def cmd_onboard(args: argparse.Namespace) -> int:
    repos = [r.strip() for r in (args.repos or "").split(",") if r.strip()]
    scope = [s.strip() for s in (args.write_scope or "").split(",") if s.strip()] or None
    req_lbls = [s.strip() for s in (getattr(args, "require_labels", "") or "").split(",") if s.strip()] or None
    extra: dict[str, Any] = {}
    if getattr(args, "precheck_cmd", ""):
        extra["precheck_cmd"] = args.precheck_cmd
    if getattr(args, "routine_cmd", ""):
        extra["routine_cmd"] = args.routine_cmd
    if getattr(args, "routine_prompt", ""):
        extra["routine_prompt"] = args.routine_prompt
    res = onboard_project(
        project_id=args.project_id,
        kind=args.kind,
        workspace_path=Path(args.workspace),
        repos=repos,
        authorized_base_ref=args.base_ref,
        branch_prefix=args.branch_prefix,
        trust_tier=args.tier,
        writer_family=args.writer_family,
        verify_cmd=args.verify_cmd,
        write_scope=scope,
        routine_driver=args.routine_driver,
        delegated_cmd=getattr(args, "delegated_cmd", ""),
        token_file=args.token_file,
        assignee=getattr(args, "assignee", "@me"),
        require_labels=req_lbls,
        schedule_interval_sec=args.interval_sec,
        enabled=not args.disabled,
        extra=extra or None,
        prompt_body=getattr(args, "routine_prompt", ""),
        overwrite=args.overwrite,
    )
    db = AutopilotDB(default_state_root() / "autopilot.db")
    try:
        wf = parse_workflow_file(Path(res["workflow_path"]))
        db.upsert_project(wf)
    finally:
        db.close()
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    db = AutopilotDB(sroot / "autopilot.db", readonly=True)
    try:
        workflows = load_all_workflows()
        results: dict[str, Any] = {}
        for wf in workflows:
            if args.project and wf.project_id != args.project:
                continue
            results[wf.project_id] = probe_project_zero_token(wf, db)
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0
    finally:
        db.close()


def cmd_run_once(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    wfs = {w.project_id: w for w in load_all_workflows()}
    if args.project not in wfs:
        raise AutopilotError(f"Unknown project_id: {args.project!r}")
    cfg = wfs[args.project]

    if args.probe_only:
        db_ro = AutopilotDB(sroot / "autopilot.db", readonly=True)
        try:
            prb = probe_project_zero_token(cfg, db_ro)
            print(json.dumps({"project_id": cfg.project_id, "status": "probe_only", "probe": prb}, ensure_ascii=False, indent=2))
            return 0
        finally:
            db_ro.close()

    probed_policy_ver = cfg.policy_version

    # Phase 1: Fast recovery under dispatcher.lock, then RELEASE lock before slow network/mail probes!
    with acquire_dispatcher_lock(sroot):
        db = AutopilotDB(sroot / "autopilot.db")
        try:
            disp_epoch = db.bump_dispatcher_epoch()
            db.upsert_project(cfg)
            rec = supervisor_recover_and_reconcile(db, disp_epoch, wfs)
            if cfg.kind == "routine" and cfg.routine_driver == "dream":
                dres = run_dream_consolidation(db, state_root=sroot)
                print(json.dumps({"project_id": cfg.project_id, "recovery": rec, "dream": dres}, ensure_ascii=False, indent=2))
                return 0
        finally:
            db.close()

    # Phase 2: Run potentially slow mail pagination / GitHub probe & base fetch OUTSIDE dispatcher.lock so `veto` NEVER blocks!
    db_probe_ro = AutopilotDB(sroot / "autopilot.db", readonly=True)
    try:
        probe = probe_project_zero_token(cfg, db_probe_ro)
    finally:
        db_probe_ro.close()

    if not probe.get("actionable"):
        st_label = "quiescent_zero_token" if cfg.kind == "routine" else "idle_zero_token"
        print(json.dumps({"project_id": cfg.project_id, "status": st_label, "probe": probe, "recovery": rec}, ensure_ascii=False, indent=2))
        return 0

    prefetched: dict[str, tuple[Path, str]] = {}
    pre_gh: tuple[str, str] | None = None
    if cfg.kind in ("issue", "delegated"):
        pre_gh = _resolve_project_gh_identity_unlocked(cfg)
    if cfg.kind == "issue" and probe.get("candidates"):
        assert pre_gh is not None
        # Pass pre-resolved token into unlocked prefetch so fetch uses identical credential!
        out_pf: dict[str, tuple[Path, str]] = {}
        seen_r: set[str] = set()
        last_pf_err: Exception | None = None
        for c in probe["candidates"]:
            r = c["repo"]
            if r in seen_r:
                continue
            seen_r.add(r)
            try:
                rc = repo_cache_dir(cfg.project_id, r)
                ws_pf = Path(cfg.workspace_path).expanduser().resolve() if cfg.workspace_path else None
                lws = ws_pf if (ws_pf and len(cfg.repos) <= 1) else None
                mg_pf = ensure_managed_bare_repo(lws, rc / "managed.git")
                bsha = fetch_authorized_base_into_managed(
                    managed_gitdir=mg_pf, repo_slug=r, authorized_base_ref=cfg.authorized_base_ref, gh_token=pre_gh[0]
                )
                out_pf[r] = (mg_pf, bsha)
            except (AutopilotError, subprocess.SubprocessError, OSError) as exc:
                last_pf_err = exc
                continue
        if not out_pf and last_pf_err is not None:
            raise AutopilotError(f"All candidate repositories failed base fetch: {last_pf_err}") from last_pf_err
        prefetched = out_pf

    # Phase 3: Re-acquire dispatcher.lock, RE-READ WORKFLOW.md to detect concurrent policy tightening, and submit!
    submitted: dict[str, Any] | None = None
    with acquire_dispatcher_lock(sroot):
        db = AutopilotDB(sroot / "autopilot.db")
        try:
            db.bump_dispatcher_epoch()
            fresh_wfs = {w.project_id: w for w in load_all_workflows()}
            fresh_cfg = fresh_wfs.get(cfg.project_id)
            if fresh_cfg is None or not fresh_cfg.enabled or fresh_cfg.policy_version != probed_policy_ver:
                raise AutopilotError(
                    f"WORKFLOW.md for {cfg.project_id} changed or was disabled during precheck; discarding stale probe"
                )
            db.upsert_project(fresh_cfg)
            if fresh_cfg.kind == "routine" and fresh_cfg.routine_driver in ("lark_payments", "custom", ""):
                submitted = _submit_routine_worker_nonblocking(
                    cfg=fresh_cfg, db=db, state_root=sroot, pending_ids=list(probe.get("pending_ids") or [])
                )
            elif fresh_cfg.kind == "delegated":
                assert pre_gh is not None
                submitted = _submit_delegated_worker_nonblocking(
                    cfg=fresh_cfg, db=db, state_root=sroot, pre_resolved_gh=pre_gh
                )
            else:
                assert pre_gh is not None
                last_err: Exception | None = None
                for cand in probe["candidates"]:
                    if cand["repo"] not in prefetched:
                        continue
                    try:
                        submitted = _submit_issue_worker_nonblocking(
                            cfg=fresh_cfg,
                            db=db,
                            state_root=sroot,
                            cand=cand,
                            prefetched_bases=prefetched,
                            pre_resolved_gh=pre_gh,
                        )
                        break
                    except (AutopilotError, subprocess.SubprocessError, OSError) as exc:
                        last_err = exc
                if submitted is None:
                    raise AutopilotError(f"All candidate claims skipped/rejected: {last_err}")
            submitted["recovery"] = rec
        finally:
            db.close()

    # Wait WITHOUT holding dispatcher.lock so `agent-autopilot veto` can preempt immediately!
    assert submitted is not None
    deadline = time.monotonic() + 3690.0
    while time.monotonic() < deadline:
        if verify_unit_terminated(submitted["worker_unit_name"], submitted["expected_cgroup_dir"]):
            break
        time.sleep(1.0)

    # Re-acquire dispatcher.lock, RE-LOAD fresh WORKFLOW.md (never using stale pre-wait `wfs`!), and reclaim!
    with acquire_dispatcher_lock(sroot):
        db2 = AutopilotDB(sroot / "autopilot.db")
        try:
            ep2 = db2.bump_dispatcher_epoch()
            fresh_wfs_end = {w.project_id: w for w in load_all_workflows()}
            for fw_end in fresh_wfs_end.values():
                db2.upsert_project(fw_end)
            supervisor_recover_and_reconcile(db2, ep2, fresh_wfs_end)
            urow_fin = db2.get_unit(submitted["unit_key"])
            cl_fin = db2.get_claim(int(submitted["claim_epoch"]))
            fin_status = urow_fin["status"] if urow_fin else "unknown"
            claim_outcome = cl_fin.get("outcome") if cl_fin else None
            claim_state = cl_fin.get("state") if cl_fin else None
            submitted["final_unit_status"] = fin_status
            submitted["claim_outcome"] = claim_outcome
            submitted["claim_state"] = claim_state
            print(json.dumps(submitted, ensure_ascii=False, indent=2))
            return 0 if (claim_outcome == "succeeded" and claim_state == "released") else 1
        finally:
            db2.close()


def _host_admission_gate(db_ro: AutopilotDB, wfs: dict[str, WorkflowConfig]) -> dict[str, Any]:
    """Zero-token gate for heavy (issue/delegated) workers: machine-wide WIP cap, then CPU steal / load backoff.

    A non-empty `hold_reason` is an ordinary wait (re-evaluated on the next dispatch tick), never a needs-human block.
    """
    limits = load_global_limits()
    g_active = count_global_heavy_claims(db_ro._conn)
    gate: dict[str, Any] = {
        "max_global_in_progress": limits.max_global_in_progress,
        "global_heavy_active": g_active,
        "hold_reason": "",
    }
    if not any(w.enabled and w.kind in HEAVY_UNIT_KINDS for w in wfs.values()):
        return gate
    if g_active >= limits.max_global_in_progress:
        gate["hold_reason"] = f"global_wip_limit_reached:{g_active}/{limits.max_global_in_progress}"
        return gate
    hp = sample_host_pressure(limits)
    gate["host_pressure"] = hp
    if hp["pressured"]:
        gate["hold_reason"] = "waiting_host_capacity:" + ",".join(hp["reasons"])
    return gate


def _record_host_gate(state_root: Path, gate: dict[str, Any]) -> None:
    """Persist the latest gate verdict for `top`/operators; best-effort, never fails dispatch."""
    rec = dict(gate, checked_at=now_iso(), waiting=bool(gate.get("hold_reason")))
    tmp = state_root / f".host_gate.json.{os.getpid()}.tmp"
    with contextlib.suppress(OSError):
        tmp.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, state_root / "host_gate.json")


def cmd_dispatch(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    wfs = {w.project_id: w for w in load_all_workflows()}

    if args.dry_run:
        db_ro = AutopilotDB(sroot / "autopilot.db", readonly=True)
        try:
            now_ts = time.time()
            plan: list[dict[str, Any]] = []
            gate_ro = _host_admission_gate(db_ro, wfs)
            for pid, wf in sorted(wfs.items()):
                if not wf.enabled:
                    continue
                if wf.kind in HEAVY_UNIT_KINDS and gate_ro["hold_reason"]:
                    plan.append({"project_id": pid, "actionable": False, "reason": gate_ro["hold_reason"]})
                    continue
                if wf.kind == "routine" and wf.schedule_interval_sec > 180:
                    crow = db_ro._conn.execute("SELECT last_full_run_ts FROM routine_cursors WHERE project_id = ?", (pid,)).fetchone()
                    if crow and crow["last_full_run_ts"] and (now_ts - float(crow["last_full_run_ts"])) < wf.schedule_interval_sec:
                        plan.append({"project_id": pid, "actionable": False, "reason": "within_schedule_interval"})
                        continue
                plan.append({"project_id": pid, **probe_project_zero_token(wf, db_ro)})
            print(json.dumps({"dry_run": True, "dispatcher_epoch": db_ro.get_dispatcher_epoch(), "host_gate": gate_ro, "probe_plan": plan}, ensure_ascii=False, indent=2))
            return 0
        finally:
            db_ro.close()

    # Phase 1: Fast recovery under dispatcher.lock, then RELEASE lock before slow mail pagination / GitHub probes / git fetch!
    with acquire_dispatcher_lock(sroot):
        db = AutopilotDB(sroot / "autopilot.db")
        try:
            disp_epoch = db.bump_dispatcher_epoch()
            for wf in wfs.values():
                db.upsert_project(wf)
            rec = supervisor_recover_and_reconcile(db, disp_epoch, wfs)
        finally:
            db.close()

    # Phase 2: Probe, resolve immutable GitHub identity, & prefetch OUTSIDE dispatcher.lock so `veto` preempts in <50ms!
    plan: list[dict[str, Any]] = []
    probed_map: dict[str, dict[str, Any]] = {}
    probed_policy_vers: dict[str, str] = {}
    prefetched_by_proj: dict[str, dict[str, tuple[Path, str]]] = {}
    resolved_gh_by_proj: dict[str, tuple[str, str]] = {}
    now_ts = time.time()
    db_ro_p = AutopilotDB(sroot / "autopilot.db", readonly=True)
    try:
        host_gate = _host_admission_gate(db_ro_p, wfs)
        _record_host_gate(sroot, host_gate)
        for pid, wf in sorted(wfs.items()):
            if not wf.enabled:
                continue
            if wf.kind in HEAVY_UNIT_KINDS and host_gate["hold_reason"]:
                # Ordinary wait: skip probe/prefetch/claim this tick; the next timer tick re-samples and resumes.
                plan.append({"project_id": pid, "actionable": False, "reason": host_gate["hold_reason"]})
                continue
            if wf.kind == "routine" and wf.schedule_interval_sec > 180:
                crow = db_ro_p._conn.execute("SELECT last_full_run_ts FROM routine_cursors WHERE project_id = ?", (pid,)).fetchone()
                if crow and crow["last_full_run_ts"] and (now_ts - float(crow["last_full_run_ts"])) < wf.schedule_interval_sec:
                    plan.append({"project_id": pid, "actionable": False, "reason": "within_schedule_interval"})
                    continue
            try:
                prb = probe_project_zero_token(wf, db_ro_p)
            except (AutopilotError, subprocess.SubprocessError, OSError) as exc:
                plan.append({"project_id": pid, "actionable": False, "reason": f"probe_error:{exc}"})
                continue
            if prb.get("actionable") and wf.kind in ("issue", "delegated"):
                try:
                    resolved_gh_by_proj[pid] = _resolve_project_gh_identity_unlocked(wf)
                except (AutopilotError, subprocess.SubprocessError, OSError) as exc:
                    plan.append({"project_id": pid, "actionable": False, "reason": f"gh_identity_error:{exc}"})
                    continue
            plan.append({"project_id": pid, **prb})
            probed_map[pid] = prb
            probed_policy_vers[pid] = wf.policy_version
            if prb.get("actionable") and wf.kind == "issue" and prb.get("candidates"):
                pf_map: dict[str, tuple[Path, str]] = {}
                seen_rp: set[str] = set()
                tok_d = resolved_gh_by_proj[pid][0]
                for c in prb["candidates"]:
                    rp = c["repo"]
                    if rp in seen_rp:
                        continue
                    seen_rp.add(rp)
                    try:
                        rc_d = repo_cache_dir(wf.project_id, rp)
                        ws_d = Path(wf.workspace_path).expanduser().resolve() if wf.workspace_path else None
                        lws_d = ws_d if (ws_d and len(wf.repos) <= 1) else None
                        mg_d = ensure_managed_bare_repo(lws_d, rc_d / "managed.git")
                        bsha_d = fetch_authorized_base_into_managed(
                            managed_gitdir=mg_d, repo_slug=rp, authorized_base_ref=wf.authorized_base_ref, gh_token=tok_d
                        )
                        pf_map[rp] = (mg_d, bsha_d)
                    except (AutopilotError, subprocess.SubprocessError, OSError):
                        continue
                prefetched_by_proj[pid] = pf_map
    finally:
        db_ro_p.close()

    # Phase 3: Re-acquire dispatcher.lock, RE-READ WORKFLOW.md to reject concurrent policy changes, and submit!
    with acquire_dispatcher_lock(sroot):
        db = AutopilotDB(sroot / "autopilot.db")
        try:
            disp_epoch = db.bump_dispatcher_epoch()
            fresh_wfs = {w.project_id: w for w in load_all_workflows()}
            executed: list[dict[str, Any]] = []
            for pid in sorted(probed_map.keys()):
                fresh_wf = fresh_wfs.get(pid)
                if fresh_wf is None or not fresh_wf.enabled or fresh_wf.policy_version != probed_policy_vers.get(pid):
                    continue
                db.upsert_project(fresh_wf)
                prb = probed_map[pid]
                prow_chk = db.get_project_row(pid)
                if prow_chk is not None and not int(prow_chk["enabled"]):
                    continue
                if fresh_wf.kind == "routine" and fresh_wf.schedule_interval_sec > 180:
                    crow2 = db._conn.execute("SELECT last_full_run_ts FROM routine_cursors WHERE project_id = ?", (pid,)).fetchone()
                    if crow2 and crow2["last_full_run_ts"] and (now_ts - float(crow2["last_full_run_ts"])) < fresh_wf.schedule_interval_sec:
                        continue
                    with db.immediate_tx():
                        db._conn.execute(
                            "INSERT OR REPLACE INTO routine_cursors(project_id, last_full_run_ts, updated_at) VALUES (?, ?, ?)",
                            (pid, now_ts, now_iso()),
                        )
                if not prb.get("actionable"):
                    continue

                if fresh_wf.kind == "routine" and fresh_wf.routine_driver == "dream":
                    executed.append({"project_id": pid, "dream": run_dream_consolidation(db, state_root=sroot)})
                elif fresh_wf.kind == "routine" and fresh_wf.routine_driver in ("lark_payments", "custom", ""):
                    with contextlib.suppress(AutopilotError, subprocess.SubprocessError, OSError):
                        executed.append(
                            _submit_routine_worker_nonblocking(
                                cfg=fresh_wf, db=db, state_root=sroot, pending_ids=list(prb.get("pending_ids") or [])
                            )
                        )
                elif fresh_wf.kind == "issue" and prb.get("candidates") and pid in resolved_gh_by_proj:
                    pf_d = prefetched_by_proj.get(pid, {})
                    pre_gh_d = resolved_gh_by_proj[pid]
                    eff_cap_d = _project_effective_cap(fresh_wf, db)
                    active_now = int(
                        db._conn.execute(
                            "SELECT COUNT(*) AS c FROM run_claims WHERE project_id = ? AND state IN ('active', 'reclaiming')",
                            (pid,),
                        ).fetchone()["c"]
                    )
                    avail_slots = max(0, eff_cap_d - active_now)
                    submitted_cnt = 0
                    for cand in prb["candidates"]:
                        if submitted_cnt >= avail_slots:
                            break
                        if cand["repo"] not in pf_d:
                            continue
                        try:
                            executed.append(
                                _submit_issue_worker_nonblocking(
                                    cfg=fresh_wf,
                                    db=db,
                                    state_root=sroot,
                                    cand=cand,
                                    prefetched_bases=pf_d,
                                    pre_resolved_gh=pre_gh_d,
                                )
                            )
                            submitted_cnt += 1
                        except (AutopilotError, subprocess.SubprocessError, OSError):
                            continue
                elif fresh_wf.kind == "delegated" and pid in resolved_gh_by_proj:
                    # Re-check the continuation cooldown under dispatcher.lock (the probe ran outside it).
                    if prb.get("reason") == "delegated_precheck_matched" and delegated_precheck_cooldown_active(fresh_wf, db):
                        continue
                    with contextlib.suppress(AutopilotError, subprocess.SubprocessError, OSError):
                        executed.append(
                            _submit_delegated_worker_nonblocking(
                                cfg=fresh_wf, db=db, state_root=sroot, pre_resolved_gh=resolved_gh_by_proj[pid]
                            )
                        )

            print(
                json.dumps(
                    {
                        "dispatcher_epoch": disp_epoch,
                        "dry_run": False,
                        "recovery": rec,
                        "host_gate": host_gate,
                        "probe_plan": plan,
                        "executed": executed,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        finally:
            db.close()


def cmd_top(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    db = AutopilotDB(sroot / "autopilot.db", readonly=True)
    try:
        projects = [dict(r) for r in db._conn.execute("SELECT * FROM projects ORDER BY project_id").fetchall()]
        leases_raw = [dict(r) for r in db._conn.execute("SELECT * FROM leases ORDER BY slot_key").fetchall()]
        for l in leases_raw:
            if l["worker_unit_name"] and l["expected_cgroup_dir"]:
                l["live_cgroup_terminated"] = verify_unit_terminated(l["worker_unit_name"], l["expected_cgroup_dir"])
        units = [
            dict(r)
            for r in db._conn.execute(
                "SELECT unit_key, project_id, status, terminal_state, pr_id, veto_pending, review_rounds_used, waiting_until, updated_at "
                "FROM work_units ORDER BY updated_at DESC LIMIT 30"
            ).fetchall()
        ]
        pending_ops = [
            dict(r)
            for r in db._conn.execute(
                "SELECT op_id, unit_key, pr_id, op_type, owner_kind, status, updated_at FROM external_ops "
                "WHERE status IN ('prepared_local', 'in_flight', 'unknown_paused') ORDER BY op_seq ASC"
            ).fetchall()
        ]
        timer_show = subprocess.run(
            ["systemctl", "--user", "is-active", "agent-autopilot-dispatch.timer"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        out = {
            "checked_at": now_iso(),
            "dispatcher_epoch": db.get_dispatcher_epoch(),
            "dispatch_timer_state": timer_show.stdout.strip() or "inactive",
            "projects": projects,
            "leases": leases_raw,
            "pending_external_ops": pending_ops,
            "recent_units": units,
        }
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    finally:
        db.close()


def cmd_veto(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    with acquire_dispatcher_lock(sroot):
        db = AutopilotDB(sroot / "autopilot.db")
        try:
            epoch = db.bump_dispatcher_epoch()
            urow = db.get_unit(args.unit_key)
            if not urow:
                raise AutopilotError(f"Unknown unit_key: {args.unit_key}")
            ok_int, conn_units, int_reason = db.inspect_scope_integrity(args.unit_key, pr_id=urow.get("pr_id"))
            if not ok_int:
                # Freeze ALL connected units locally (`veto_pending=1`, `needs-human`) and STOP active workers,
                # WITHOUT selecting credentials or issuing cross-project remote GitHub mutations!
                ts = now_iso()
                targets = conn_units or (args.unit_key,)
                u_marks = ",".join("?" for _ in targets)
                with db.immediate_tx():
                    db._conn.execute(
                        f"""
                        UPDATE work_units
                        SET veto_pending = 1,
                            veto_remote_sync_pending = 0,
                            scope_quarantined = 1,
                            status = 'paused',
                            terminal_state = 'needs-human',
                            pause_reason_kind = 'veto',
                            last_error = ?,
                            updated_at = ?
                        WHERE unit_key IN ({u_marks})
                        """,
                        (f"manual_veto_quarantined: {int_reason}", ts, *targets),
                    )
                    seq_ab = db._next_counter_in_tx("op_seq")
                    db._conn.execute(
                        f"UPDATE external_ops SET status = 'aborted_pre_send', op_seq = ?, updated_at = ? WHERE owner_kind = 'worker' AND status = 'prepared_local' AND unit_key IN ({u_marks})",
                        (seq_ab, ts, *targets),
                    )
                crows_q = db._conn.execute(
                    f"SELECT worker_unit_name FROM run_claims WHERE unit_key IN ({u_marks}) AND state IN ('active', 'reclaiming')",
                    targets,
                ).fetchall()
                for cr in crows_q:
                    with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                        subprocess.run(["systemctl", "--user", "stop", cr["worker_unit_name"]], capture_output=True, timeout=20, check=False)
                print(
                    json.dumps(
                        {
                            "vetoed": args.unit_key,
                            "quarantined_scope_conflict": True,
                            "reason": int_reason,
                            "quarantined_units": list(targets),
                            "admin_ops": [],
                            "results": [],
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                )
                return 0

            scope = db.resolve_unit_scope_and_pending(args.unit_key)

            # STEP 1: Atomically freeze local writes (`veto_pending = 1`, `veto_remote_sync_pending = 1` if PR bound) FIRST!
            db.register_admin_revoke(
                unit_key=args.unit_key,
                dispatcher_epoch=epoch,
                pr_id=scope.eff_pr_id,
                remote_sync_pending=(scope.eff_pr_id is not None),
                reason=args.reason or "manual_veto",
            )

            # STEP 2: Best-effort stop active scope worker units, then check real cgroup termination
            u_marks = ",".join("?" for _ in scope.scope_units)
            crows = db._conn.execute(
                f"SELECT worker_unit_name FROM run_claims WHERE unit_key IN ({u_marks}) AND state IN ('active', 'reclaiming')",
                scope.scope_units,
            ).fetchall()
            for cr in crows:
                with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                    subprocess.run(
                        ["systemctl", "--user", "stop", cr["worker_unit_name"]],
                        capture_output=True,
                        timeout=20,
                        check=False,
                    )
            all_term = _are_all_scope_workers_terminated(db, scope.scope_units)

            # STEP 3: Inspect live PR snapshot and register per-flag compensations
            op_ids: list[str] = []
            results: list[dict[str, Any]] = []
            wfs = {w.project_id: w for w in load_all_workflows()}
            has_unres_worker = _scope_has_unresolved_pr_mutating_worker_op(db, args.unit_key)
            tr: LiveGitHubCliTransport | None = None
            with contextlib.suppress(AutopilotError):
                tr = _resolve_strict_project_gh_transport(db, urow["project_id"], wfs)

            if scope.eff_pr_id and urow["repo"]:
                if tr is not None:
                    snap = tr.fetch_pr_snapshot(urow["repo"], scope.eff_pr_id, snapshot_seq=db.current_op_seq())
                    if snap is not None:
                        if snap.state == "OPEN":
                            op_ids = db.register_admin_revoke(
                                unit_key=args.unit_key,
                                dispatcher_epoch=epoch,
                                pr_id=scope.eff_pr_id,
                                need_dequeue=(snap.merge_queue_entry_id is not None),
                                need_disable_automerge=snap.auto_merge_enabled,
                                need_draft=(not snap.is_draft),
                                remote_sync_pending=(not all_term or has_unres_worker),
                                reason=args.reason or "manual_veto",
                            )
                        if all_term and not has_unres_worker:
                            db.mark_veto_remote_synced(args.unit_key)
            else:
                if all_term and not has_unres_worker:
                    db.mark_veto_remote_synced(args.unit_key)

            for oid in op_ids:
                g = db.promote_op_to_in_flight(
                    oid,
                    caller_owner_kind="supervisor_admin",
                    caller_epoch=epoch,
                    dispatcher_lock_held=True,
                    all_scope_workers_terminated=all_term,
                )
                if g.granted and urow["repo"] and tr is not None:
                    with contextlib.suppress(AutopilotError):
                        results.append(execute_granted_op(grant=g, db=db, transport=tr, repo=urow["repo"]))
            print(
                json.dumps(
                    {
                        "vetoed": args.unit_key,
                        "all_scope_workers_terminated": all_term,
                        "admin_ops": op_ids,
                        "results": results,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        finally:
            db.close()


def cmd_clear_veto(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    with acquire_dispatcher_lock(sroot):
        db = AutopilotDB(sroot / "autopilot.db")
        try:
            db.bump_dispatcher_epoch()
            urow = db.get_unit(args.unit_key)
            if not urow:
                raise AutopilotError(f"Unknown unit_key: {args.unit_key}")
            scope = db.resolve_unit_scope_and_pending(args.unit_key)
            snap = None
            if scope.eff_pr_id:
                wfs = {w.project_id: w for w in load_all_workflows()}
                tr = _resolve_strict_project_gh_transport(db, urow["project_id"], wfs)
                snap = fetch_pr_unveto_snapshot(tr, db, urow["repo"], scope.eff_pr_id)
            cleared = db.clear_veto_and_resume(args.unit_key, pr_snapshot=snap)
            print(json.dumps({"cleared_units": list(cleared)}, ensure_ascii=False, indent=2))
            return 0
        finally:
            db.close()


def cmd_resolve_op(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    with acquire_dispatcher_lock(sroot):
        db = AutopilotDB(sroot / "autopilot.db")
        try:
            epoch = db.bump_dispatcher_epoch()
            row = db.get_op(args.op_id)
            if not row:
                raise AutopilotError(f"Unknown op_id: {args.op_id}")
            if row["owner_kind"] == "worker":
                ce = row["claim_epoch"]
                cl = db.get_claim(int(ce)) if ce is not None else None
                sender_dead = cl is None or cl["state"] == "released" or verify_unit_terminated(cl["worker_unit_name"], cl["expected_cgroup_dir"])
            else:
                sender_dead = epoch > int(row["owner_epoch"])
            res = db.operator_resolve_op(
                args.op_id,
                new_status=args.status,
                sender_confirmed_terminated=sender_dead,
                receipt_id=args.receipt_id,
                unsent_proof=args.unsent_proof,
            )
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 0
        finally:
            db.close()


def cmd_dream(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    db = AutopilotDB(sroot / "autopilot.db")
    try:
        res = run_dream_consolidation(db, state_root=sroot)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0
    finally:
        db.close()


def cmd_approve_promotion(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    with acquire_dispatcher_lock(sroot):
        db = AutopilotDB(sroot / "autopilot.db")
        try:
            new_cap = db.approve_concurrency_promotion(
                args.project_id,
                force=bool(getattr(args, "force", False)),
                target_cap=getattr(args, "target", None),
            )
            print(json.dumps({"project_id": args.project_id, "new_max_in_progress": new_cap}, indent=2))
            return 0
        finally:
            db.close()


def cmd_approve_paths(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    with acquire_dispatcher_lock(sroot):
        db = AutopilotDB(sroot / "autopilot.db")
        try:
            res = db.approve_unit_protected_paths(args.unit_key, list(args.allow or []))
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 0
        finally:
            db.close()


def cmd_import_legacy(args: argparse.Namespace) -> int:
    sroot = default_state_root()
    db = AutopilotDB(sroot / "autopilot.db")
    try:
        res = import_legacy_autopilot_state(
            db=db,
            legacy_state_dir=Path(args.legacy_dir).expanduser().resolve(),
            backup_dir=Path(args.backup_dir).expanduser().resolve(),
            project_id=args.project_id,
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0
    finally:
        db.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent-autopilot", description="Universal 24x7 self-evolving autonomous agent engine.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="Verify environment, bwrap/Landlock binaries, linger, and configured workflows.")
    st = sub.add_parser("selftest", help="Run policy manifest parity and optional live sandbox/systemd self-tests.")
    st.add_argument("--live", action="store_true", help="Run live systemd transient unit + native binary checks.")

    ob = sub.add_parser("onboard", help="Onboard a repository or routine into WORKFLOW.md + advisory maps.")
    ob.add_argument("--project-id", required=True)
    ob.add_argument("--kind", choices=["issue", "routine", "delegated"], required=True)
    ob.add_argument("--workspace", required=True)
    ob.add_argument("--repos", default="")
    ob.add_argument("--base-ref", default="main")
    ob.add_argument("--branch-prefix", default="agent/")
    ob.add_argument("--tier", choices=["T1", "T2", "T3", "T4"], default="T1")
    ob.add_argument("--writer-family", choices=["codex", "claude"], default="codex")
    ob.add_argument("--verify-cmd", default=None)
    ob.add_argument("--write-scope", default="")
    ob.add_argument("--routine-driver", default="")
    ob.add_argument("--precheck-cmd", default="", help="Optional zero-token shell precheck for custom routines (exit 0 = run, non-zero = skip).")
    ob.add_argument("--routine-cmd", default="", help="Optional shell command to run for custom routines.")
    ob.add_argument("--routine-prompt", default="", help="Optional LLM prompt for custom routines when no --routine-cmd is set.")
    ob.add_argument("--delegated-cmd", default="", help="Command for --kind delegated.")
    ob.add_argument("--assignee", default="@me", help="GitHub assignee filter ('@me', username, or '*' for all open issues).")
    ob.add_argument("--require-labels", default="", help="Optional comma-separated required labels (e.g. 'agent:auto').")
    ob.add_argument("--token-file", default="")
    ob.add_argument("--interval-sec", type=int, default=300)
    ob.add_argument("--disabled", action="store_true")
    ob.add_argument("--overwrite", action="store_true")

    prb = sub.add_parser("probe", help="Run zero-LLM-token prechecks across enabled projects.")
    prb.add_argument("--project", default=None)

    ro = sub.add_parser("run-once", help="Run a single deterministic cycle for one project.")
    ro.add_argument("--project", required=True)
    ro.add_argument("--probe-only", action="store_true")

    dp = sub.add_parser("dispatch", help="Supervisor tick: recover dead workers, probe all projects, and dispatch.")
    dp.add_argument("--dry-run", action="store_true")

    sub.add_parser("top", help="Inspect live SQLite + real systemd/cgroup status.")
    sub.add_parser("status", help="Alias for top.")
    sub.add_parser("dream", help="Consolidate pitfalls and evaluate 48h-matured concurrency promotions.")

    vt = sub.add_parser("veto", help="Atomically pause a unit/PR and execute single-mutation compensations.")
    vt.add_argument("unit_key")
    vt.add_argument("--reason", default="manual_veto")

    cv = sub.add_parser("clear-veto", help="Verify live PR quiescence snapshot and clear veto across scope.")
    cv.add_argument("unit_key")

    rs = sub.add_parser("resolve-op", help="Manually resolve an unknown_paused external operation to an evidenced terminal status.")
    rs.add_argument("op_id")
    rs.add_argument("--status", required=True)
    rs.add_argument("--receipt-id", default=None)
    rs.add_argument("--unsent-proof", default=None)

    ap = sub.add_parser("approve-promotion", help="Approve staircase concurrency step-up (or set explicit cap with --force --target).")
    ap.add_argument("project_id")
    ap.add_argument("--force", action="store_true", help="Operator override without waiting for 48h-matured clean run count.")
    ap.add_argument("--target", type=int, default=None, help="Explicit target concurrency step (requires --force).")

    app = sub.add_parser(
        "approve-paths",
        help="Approve narrow schema/migration protected path globs for one unit and resume non-veto needs-human pause.",
    )
    app.add_argument("unit_key")
    app.add_argument("--allow", action="append", required=True, help="Protected schema/migration path glob to approve (repeatable).")

    il = sub.add_parser("import-legacy", help="Backup and import legacy autopilot terminal issues.")
    il.add_argument("--legacy-dir", default="~/.local/state/legacy-autopilot")
    il.add_argument("--backup-dir", default="~/.local/state/agent-autopilot/backups/legacy-autopilot")
    il.add_argument("--project-id", default="default")

    we = sub.add_parser("worker-exec", help=argparse.SUPPRESS)
    we.add_argument("--project", required=True)
    we.add_argument("--unit-key", required=True)
    we.add_argument("--claim-epoch", required=True)
    we.add_argument("--issue-title", default="")

    de = sub.add_parser("delegated-exec", help=argparse.SUPPRESS)
    de.add_argument("--claim-epoch", required=True)
    de.add_argument("--token-file", default="")
    de.add_argument("--cmd", dest="delegated_shell_cmd", required=True)

    re_p = sub.add_parser("routine-exec", help=argparse.SUPPRESS)
    re_p.add_argument("--project", required=True)
    re_p.add_argument("--claim-epoch", required=True)
    re_p.add_argument("--pending-ids-json", default="[]")

    sw = sub.add_parser("scrub-worktree", help=argparse.SUPPRESS)
    sw.add_argument("--claim-epoch", required=True)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "doctor": cmd_doctor,
        "selftest": cmd_selftest,
        "onboard": cmd_onboard,
        "probe": cmd_probe,
        "run-once": cmd_run_once,
        "dispatch": cmd_dispatch,
        "top": cmd_top,
        "status": cmd_top,
        "dream": cmd_dream,
        "veto": cmd_veto,
        "clear-veto": cmd_clear_veto,
        "resolve-op": cmd_resolve_op,
        "approve-promotion": cmd_approve_promotion,
        "approve-paths": cmd_approve_paths,
        "import-legacy": cmd_import_legacy,
        "worker-exec": cmd_worker_exec,
        "delegated-exec": cmd_delegated_exec,
        "routine-exec": cmd_routine_exec,
        "scrub-worktree": cmd_scrub_worktree,
    }
    try:
        return handlers[args.cmd](args)
    except AutopilotError as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
