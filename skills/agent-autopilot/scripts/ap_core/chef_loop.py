"""Chef 6-Principle execution loop: Scout -> Executable DoD -> Writer -> verify_ring -> Cross-Family Referee (<=3 rounds)."""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .db import AutopilotDB
from .dream import sync_project_pitfalls_markdown
from .git_gate import CandidateGateResult, prepare_isolated_worktree, resolve_repo_common_objects_dir, sample_and_gate_worktree
from .github_flow import GitHubTransport, execute_granted_op
from .models import (
    POLICY_MANIFEST,
    AutopilotError,
    QuotaExhaustedError,
    ScopeViolationError,
    WorkflowConfig,
    compute_ref_id_hmac,
    ensure_secure_dir,
    extract_json_object,
    parse_quota_reset,
    resolve_cross_family_referee,
    sanitize_terminal_text,
    validate_referee_output,
    validate_scout_output,
    validate_writer_output,
)
from .sandbox import (
    cleanup_workspace_node_modules_mountpoints,
    copy_clean_tree_no_hardlinks,
    run_optional_ui_verify,
)


@dataclass(frozen=True)
class ModelTurnResult:
    raw_stdout: str
    raw_stderr: str = ""
    outbox_verdict_json: str | None = None
    exit_code: int = 0
    model_used: str = ""


class ModelRunner(Protocol):
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
    ) -> ModelTurnResult: ...

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
    ) -> ModelTurnResult: ...

    def run_referee(
        self,
        *,
        family: str,
        model: str,
        review_bundle_dir: Path,
        outbox_dir: Path,
        prompt: str,
        run_dir: Path,
    ) -> ModelTurnResult: ...


def load_advisory_context_for_scout_or_writer(advisory_dir: Path) -> str:
    """Load non-authoritative 5-second map, golden exemplars, and pitfalls (NEVER passed to Referee/Visual!)."""
    parts: list[str] = []
    map_p = advisory_dir / "PROJECT_MAP.md"
    if map_p.is_file():
        parts.append("<project_map>\n" + map_p.read_text(encoding="utf-8", errors="replace").strip() + "\n</project_map>")
    fmap_p = advisory_dir / "feature-map.json"
    if fmap_p.is_file():
        parts.append("<exemplar_map>\n" + fmap_p.read_text(encoding="utf-8", errors="replace").strip() + "\n</exemplar_map>")
    pit_p = advisory_dir / "PITFALLS.md"
    if pit_p.is_file():
        parts.append("<pitfalls>\n" + pit_p.read_text(encoding="utf-8", errors="replace").strip() + "\n</pitfalls>")
    return "\n\n".join(parts)


def collect_referee_verdict(turn: ModelTurnResult, *, referee_family: str, expected_round: int) -> dict[str, Any]:
    """Validate referee verdict strictly from the family's authorized channel (never mixing stderr!)."""
    if turn.exit_code != 0:
        combined = turn.raw_stdout + ("\n" + turn.raw_stderr if turn.raw_stderr else "")
        wake = parse_quota_reset(combined)
        if wake:
            raise QuotaExhaustedError("Referee hit quota window", wake_at_iso=wake, family=referee_family)
        raise AutopilotError(f"Referee exited with code {turn.exit_code}: {sanitize_terminal_text(combined, 500)}")

    if referee_family == "claude":
        # claude:readonly_model has Read/Glob/Grep only -> strictly parse controlled stdout JSON (ignore outbox & stderr!)
        try:
            parsed = extract_json_object(turn.raw_stdout)
        except AutopilotError:
            wake0 = parse_quota_reset(turn.raw_stdout + ("\n" + turn.raw_stderr if turn.raw_stderr else ""))
            if wake0:
                raise QuotaExhaustedError("Referee hit quota window", wake_at_iso=wake0, family=referee_family)
            raise
    elif referee_family == "codex":
        # codex:readonly_model MUST write non-empty /ap-outbox/verdict.json (NEVER fall back to stdout!)
        if not turn.outbox_verdict_json or not turn.outbox_verdict_json.strip():
            raise AutopilotError("Codex referee missing required non-empty /ap-outbox/verdict.json")
        parsed = extract_json_object(turn.outbox_verdict_json)
    else:
        raise AutopilotError(f"Unsupported referee_family: {referee_family!r}")
    return validate_referee_output(parsed, expected_round=expected_round)


_RESERVED_VERIFY_ENV_PREFIXES: tuple[str, ...] = ("LD_", "AP_", "CARGO_", "GO", "RUST", "GIT_")
_RESERVED_VERIFY_ENV_KEYS: frozenset[str] = frozenset({"PATH", "HOME", "SHELL", "USER", "LOGNAME", "IFS", "BASH_ENV", "ENV"})


def _build_safe_verify_env(
    touched_paths: tuple[str, ...],
    extra_verify_env: dict[str, str] | None,
) -> dict[str, str]:
    merged: dict[str, str] = {}
    if extra_verify_env:
        for raw_k, raw_v in extra_verify_env.items():
            k = str(raw_k or "").strip()
            if not k or raw_v is None:
                continue
            k_up = k.upper()
            if k_up in _RESERVED_VERIFY_ENV_KEYS or any(k_up.startswith(pfx) for pfx in _RESERVED_VERIFY_ENV_PREFIXES):
                continue
            merged[k] = str(raw_v)
    kept: list[str] = []
    used_bytes = 0
    truncated = False
    for p in touched_paths:
        if "\n" in p or "\r" in p or "\x00" in p:
            continue
        enc_len = len(p.encode("utf-8")) + 1
        if used_bytes + enc_len > 32768:
            truncated = True
            break
        kept.append(p)
        used_bytes += enc_len
    merged["AP_TOUCHED_FILES"] = "\n".join(kept)
    merged["AP_TOUCHED_FILES_TRUNCATED"] = "1" if truncated else "0"
    return merged


def run_verify_ring_command(
    *,
    clean_tree_dir: Path,
    verify_out_dir: Path,
    dod_cmd: str,
    enable_ui_verify: bool = False,
    ui_verify_url: str = "",
    use_bwrap: bool = False,
    trusted_base_cache: Path | None = None,
    clean_tree_fd: int | None = None,
    trusted_base_cache_fd: int | None = None,
    touched_paths: tuple[str, ...] = (),
    extra_verify_env: dict[str, str] | None = None,
    repo_main_dir: Path | None = None,
    ro_workspace_deps: tuple[str, ...] = (),
) -> tuple[int, bool, str]:
    """Run executable DoD (+ optional loopback UI check in the SAME verify_ring namespace)."""
    merged_extra_env = _build_safe_verify_env(touched_paths, extra_verify_env)
    if enable_ui_verify and ui_verify_url:
        ui_res = run_optional_ui_verify(
            clean_tree_dir=clean_tree_dir,
            verify_out_dir=verify_out_dir,
            ui_url=ui_verify_url,
            dod_and_server_cmd=dod_cmd,
            trusted_base_cache=trusted_base_cache,
            clean_tree_fd=clean_tree_fd,
            trusted_base_cache_fd=trusted_base_cache_fd,
            extra_env=merged_extra_env,
            repo_main_dir=repo_main_dir,
            ro_workspace_deps=ro_workspace_deps,
        )
        if not ui_res["ok"]:
            return 1, False, f"UI/DoD verification failed: {ui_res}"
        return 0, True, str(ui_res.get("stdout") or "ui_verified")

    if use_bwrap or ((trusted_base_cache is not None or trusted_base_cache_fd is not None) and shutil.which("bwrap")):
        import contextlib as _ctx
        import os as _os
        from .sandbox import build_execution_ring_bwrap

        retain_fds: list[int] = []
        try:
            argv = build_execution_ring_bwrap(
                ring_kind="verify_ring",
                inner_cmd=["/bin/bash", "-lc", dod_cmd],
                cwd=verify_out_dir,
                clean_tree=clean_tree_dir,
                verify_out_dir=verify_out_dir,
                trusted_base_cache=trusted_base_cache,
                enable_ui_verify=False,
                retain_fds=retain_fds,
                clean_tree_fd=clean_tree_fd,
                trusted_base_cache_fd=trusted_base_cache_fd,
                extra_env=merged_extra_env,
                repo_main_dir=repo_main_dir,
                ro_workspace_deps=ro_workspace_deps,
            )
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                pass_fds=tuple(retain_fds),
                timeout=300,
                check=False,
            )
        finally:
            for _fd in retain_fds:
                with _ctx.suppress(OSError):
                    _os.close(_fd)
    else:
        from .sandbox import copy_clean_tree_no_hardlinks_fds
        import os as _os

        _ct_fd, _vo_fd = copy_clean_tree_no_hardlinks_fds(
            clean_tree_dir, verify_out_dir, source_clean_tree_fd=clean_tree_fd
        )
        try:
            vo_exec = Path(_os.readlink(f"/proc/self/fd/{_vo_fd}"))
            extra_paths = [str(Path.home() / ".local" / "bin"), str(Path.home() / ".cargo" / "bin")]
            if trusted_base_cache and (trusted_base_cache / "node_modules" / ".bin").is_dir():
                extra_paths.insert(0, str((trusted_base_cache / "node_modules" / ".bin").resolve()))
            env = {
                "PATH": ":".join([*extra_paths, "/usr/local/bin:/usr/bin:/bin"]),
                "HOME": str(vo_exec),
                "LANG": "C.UTF-8",
                "CI": "1",
                **merged_extra_env,
            }
            proc = subprocess.run(
                ["/bin/bash", "-lc", dod_cmd],
                cwd=str(vo_exec),
                env=env,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        finally:
            _os.close(_vo_fd)
            _os.close(_ct_fd)

    output_summary = sanitize_terminal_text(proc.stdout + "\n" + proc.stderr, 2000)
    if proc.returncode != 0:
        return proc.returncode, False, output_summary
    return 0, False, output_summary


def execute_chef_issue_pipeline(
    *,
    db: AutopilotDB,
    cfg: WorkflowConfig,
    unit_key: str,
    repo: str,
    issue_summary: str,
    claim_epoch: int,
    managed_gitdir: Path,
    worktree_dir: Path,
    repo_main: Path | None,
    run_dir: Path,
    advisory_dir: Path,
    model_runner: ModelRunner,
    gh_transport: GitHubTransport,
    hmac_secret: bytes,
    use_bwrap_verify: bool = False,
    trusted_base_cache: Path | None = None,
    trusted_base_cache_fd: int | None = None,
) -> dict[str, Any]:
    """Execute full Scout -> Writer -> verify_ring -> Cross-Family Referee (<=3 persistent rounds) -> Publish pipeline."""
    t_start = time.monotonic()
    claim = db.get_claim(claim_epoch)
    if claim is None or claim["state"] != "active":
        raise AutopilotError(f"Inactive claim_epoch={claim_epoch}")

    max_rounds = int(POLICY_MANIFEST["chef_pipeline"]["max_review_rounds"])
    urow_init = db.get_unit(unit_key)
    if urow_init and int(urow_init["review_rounds_used"]) >= max_rounds:
        db.mark_unit_needs_human(unit_key, f"Persistent review_rounds_used already reached {max_rounds}", non_veto=True)
        return {"status": "needs-human", "reason": "review_rounds_exhausted", "defect_trajectory": []}

    base_sha = str(claim["base_sha"])
    frozen_scope = json.loads(claim["frozen_write_scope_json"])
    writer_family = cfg.writer_family
    referee_family = resolve_cross_family_referee(writer_family)
    models_cfg = POLICY_MANIFEST["chef_pipeline"]["configurable_models"]
    scout_model = str(models_cfg[f"{writer_family}_scout"])
    writer_model = str(models_cfg[f"{writer_family}_writer"])
    referee_model = str(models_cfg[f"{referee_family}_referee"])
    main_obj = resolve_repo_common_objects_dir(repo_main) if repo_main is not None else None

    wt, wt_gitdir = prepare_isolated_worktree(
        managed_gitdir=managed_gitdir,
        worktree_dir=worktree_dir,
        wt_name=worktree_dir.name,
        base_sha=base_sha,
    )
    advisory_ctx = load_advisory_context_for_scout_or_writer(advisory_dir)

    ro_ws_deps = tuple(str(x).strip() for x in (cfg.extra.get("ro_workspace_deps") or []) if str(x).strip())
    scout_prompt = (
        f"{advisory_ctx}\n\n<issue>\n{issue_summary}\n</issue>\n"
        "Output JSON matching required_fill_in_schemas.scout: "
        '{"root_cause":"...","target_area":"...","exemplar_files":[...],"dod_check":"...","ui_verify_needed":false,"uncertainties":[...]}'
    )
    try:
        scout_turn = model_runner.run_scout(
            family=writer_family,
            model=scout_model,
            worktree=wt,
            prompt=scout_prompt,
            run_dir=run_dir,
            managed_gitdir=managed_gitdir,
            repo_main_objects=main_obj,
            trusted_base_cache=trusted_base_cache,
        )
    finally:
        cleanup_workspace_node_modules_mountpoints(trusted_base_cache, wt, extra_rel_mounts=ro_ws_deps)
    if scout_turn.exit_code != 0:
        combined = scout_turn.raw_stdout + ("\n" + scout_turn.raw_stderr if scout_turn.raw_stderr else "")
        wake = parse_quota_reset(combined)
        if wake:
            db.mark_unit_waiting_quota(unit_key, wake, "scout_quota_window")
            raise QuotaExhaustedError("Scout hit quota window", wake_at_iso=wake, family=writer_family)
        raise AutopilotError(f"Scout failed: {sanitize_terminal_text(combined[-1200:], 800)}")
    scout_data = validate_scout_output(extract_json_object(scout_turn.raw_stdout))
    dod_cmd = cfg.verify_cmd or str(scout_data["dod_check"])
    target_area = str(scout_data["target_area"] or "general")

    defect_feedback = ""
    defect_trajectory: list[int] = []
    approved_gate: CandidateGateResult | None = None
    open_gates: list[CandidateGateResult] = []
    try:
        while True:
            urow_cur = db.get_unit(unit_key)
            used_so_far = int(urow_cur["review_rounds_used"]) if urow_cur else 0
            if used_so_far >= max_rounds:
                break
            attempt_num = used_so_far + 1

            writer_prompt = (
                f"{advisory_ctx}\n\n<scout_plan>\n{json.dumps(scout_data, ensure_ascii=False)}\n</scout_plan>\n"
                f"<issue>\n{issue_summary}\n</issue>\n{defect_feedback}\n"
                "Output JSON matching required_fill_in_schemas.writer (summary <= 300 chars)."
            )
            try:
                w_turn = model_runner.run_writer(
                    family=writer_family,
                    model=writer_model,
                    worktree=wt,
                    prompt=writer_prompt,
                    run_dir=run_dir,
                    managed_gitdir=managed_gitdir,
                    repo_main_objects=main_obj,
                    trusted_base_cache=trusted_base_cache,
                )
            finally:
                cleanup_workspace_node_modules_mountpoints(trusted_base_cache, wt, extra_rel_mounts=ro_ws_deps)
            if w_turn.exit_code != 0:
                combined = w_turn.raw_stdout + ("\n" + w_turn.raw_stderr if w_turn.raw_stderr else "")
                wake = parse_quota_reset(combined)
                if wake:
                    db.mark_unit_waiting_quota(unit_key, wake, "writer_quota_window")
                    raise QuotaExhaustedError("Writer hit quota window", wake_at_iso=wake, family=writer_family)
                raise AutopilotError(f"Writer failed: {sanitize_terminal_text(combined[-1200:], 800)}")
            writer_data = validate_writer_output(extract_json_object(w_turn.raw_stdout))

            try:
                gate = sample_and_gate_worktree(
                    managed_gitdir=managed_gitdir,
                    wt_gitdir=wt_gitdir,
                    worktree=wt,
                    repo_main=repo_main,
                    run_dir=run_dir / f"round-{attempt_num}",
                    base_sha=base_sha,
                    frozen_write_scope=frozen_scope,
                    dod_check=dod_cmd,
                    issue_summary=issue_summary,
                    commit_message=writer_data["summary_le_300_chars"],
                )
                open_gates.append(gate)
            except ScopeViolationError as exc:
                db.record_pitfall(
                    project_id=cfg.project_id,
                    target_area=target_area,
                    symptom=f"Scope gate rejected edit: {exc.violations[0] if exc.violations else exc}",
                    rule_text=f"Never modify hard-stop or out-of-scope paths ({', '.join(frozen_scope[:3])})",
                )
                sync_project_pitfalls_markdown(db, cfg.project_id, advisory_dir=advisory_dir)
                if exc.is_lockfile:
                    db.mark_unit_needs_human(unit_key, f"Lockfile change requires human approval: {exc.violations}", non_veto=True)
                    return {"status": "needs-human", "reason": "lockfile_escalation", "defect_trajectory": defect_trajectory}
                raise

            db.set_current_candidate(unit_key=unit_key, candidate_sha=gate.candidate_sha, claim_epoch=claim_epoch)

            verify_out_dir = run_dir / f"verify-out-{gate.candidate_sha[:12]}-r{attempt_num}"
            v_rc, ui_ok, v_out = run_verify_ring_command(
                clean_tree_dir=gate.clean_tree_dir,
                verify_out_dir=verify_out_dir,
                dod_cmd=dod_cmd,
                enable_ui_verify=bool(cfg.enable_ui_verify and scout_data["ui_verify_needed"]),
                ui_verify_url=cfg.ui_verify_url,
                use_bwrap=use_bwrap_verify,
                trusted_base_cache=trusted_base_cache,
                clean_tree_fd=gate.clean_tree_fd,
                trusted_base_cache_fd=trusted_base_cache_fd,
                touched_paths=gate.touched_paths,
                extra_verify_env=dict(cfg.extra.get("verify_env") or {}) if isinstance(cfg.extra.get("verify_env"), dict) else None,
                repo_main_dir=repo_main,
                ro_workspace_deps=ro_ws_deps,
            )
            db.record_verify_receipt(
                unit_key=unit_key,
                candidate_sha=gate.candidate_sha,
                dod_cmd=dod_cmd,
                exit_code=v_rc,
                ui_verified=ui_ok,
                artifact_dir=str(verify_out_dir),
                touched_paths=gate.touched_paths,
            )
            if v_rc != 0:
                db.record_pitfall(
                    project_id=cfg.project_id,
                    target_area=target_area,
                    symptom=f"verify_ring DoD exited {v_rc}",
                    rule_text=f"Ensure `{dod_cmd}` passes cleanly before submitting candidate",
                )
                sync_project_pitfalls_markdown(db, cfg.project_id, advisory_dir=advisory_dir)
                reserved_fail_round = db.reserve_review_round(unit_key)
                if reserved_fail_round is None or reserved_fail_round >= max_rounds:
                    db.mark_unit_needs_human(unit_key, f"DoD failed after {max_rounds} rounds: {v_out[:240]}", non_veto=True)
                    return {"status": "needs-human", "reason": "verify_exhausted", "defect_trajectory": defect_trajectory}
                defect_feedback = f"<verify_failure round='{reserved_fail_round}'>\n{v_out}\n</verify_failure>"
                continue

            # Reserve persistent review round BEFORE calling Referee model!
            reserved_round = db.reserve_review_round(unit_key)
            if reserved_round is None:
                break

            outbox_dir = ensure_secure_dir(run_dir / f"referee-outbox-r{reserved_round}", 0o700)
            ref_prompt = (
                f"Adversarially review /ap-review-bundle (round {reserved_round}). "
                "Output ONLY JSON matching required_fill_in_schemas.referee with 3-column defects (location, failure_case, minimal_fix)."
            )
            try:
                r_turn = model_runner.run_referee(
                    family=referee_family,
                    model=referee_model,
                    review_bundle_dir=gate.review_bundle_dir,
                    outbox_dir=outbox_dir,
                    prompt=ref_prompt,
                    run_dir=run_dir,
                )
                raw_verdict_file = run_dir / f"referee-r{reserved_round}.json"
                raw_verdict_file.write_text(
                    r_turn.outbox_verdict_json if (referee_family == "codex" and r_turn.outbox_verdict_json) else r_turn.raw_stdout,
                    encoding="utf-8",
                )
                ref_data = collect_referee_verdict(r_turn, referee_family=referee_family, expected_round=reserved_round)
            except QuotaExhaustedError as qexc:
                db.mark_unit_waiting_quota(
                    unit_key,
                    qexc.wake_at_iso,
                    "referee_quota_window",
                    refund_reserved_round=reserved_round,
                )
                raise

            defects = ref_data["three_col_defects"]
            defect_cnt = int(ref_data["defect_count"])
            defect_trajectory.append(defect_cnt)
            db.record_review_receipt(
                unit_key=unit_key,
                candidate_sha=gate.candidate_sha,
                writer_family=writer_family,
                referee_family=referee_family,
                referee_model=r_turn.model_used or referee_model,
                verdict=str(ref_data["verdict"]),
                defect_count=defect_cnt,
                defects=defects,
                raw_path=str(raw_verdict_file),
                reserved_round_index=reserved_round,
            )

            if ref_data["verdict"] == "APPROVE" and defect_cnt == 0:
                approved_gate = gate
                break

            if defects:
                d0 = defects[0]
                db.record_pitfall(
                    project_id=cfg.project_id,
                    target_area=target_area,
                    symptom=f"{d0['location']}: {d0['failure_case']}",
                    rule_text=f"In {d0['location']}, {d0['minimal_fix']}",
                )
                sync_project_pitfalls_markdown(db, cfg.project_id, advisory_dir=advisory_dir)
            defect_feedback = f"<referee_defects round='{reserved_round}'>\n{json.dumps(defects, ensure_ascii=False, indent=2)}\n</referee_defects>"
    finally:
        for _g in open_gates:
            _g.close_fds()

    if approved_gate is None:
        db.mark_unit_needs_human(
            unit_key,
            f"Exhausted max_review_rounds={max_rounds} without reaching 0 defects (trajectory={defect_trajectory})",
            non_veto=True,
        )
        return {
            "status": "needs-human",
            "reason": "review_rounds_exhausted",
            "defect_trajectory": defect_trajectory,
        }

    # 6. PUBLISH via single-mutation SendGrant, checking status & veto after EVERY step!
    urow_pre_pub = db.get_unit(unit_key)
    assert urow_pre_pub is not None
    push_payload: dict[str, Any] = {}
    if urow_pre_pub.get("last_confirmed_head_oid"):
        push_payload["expected_old_oid"] = urow_pre_pub["last_confirmed_head_oid"]

    push_op = db.prepare_op(
        unit_key=unit_key,
        op_type="push_branch",
        claim_epoch=claim_epoch,
        candidate_sha=approved_gate.candidate_sha,
        payload=push_payload,
    )
    push_grant = db.promote_op_to_in_flight(push_op, caller_owner_kind="worker", caller_epoch=claim_epoch)
    push_res = execute_granted_op(
        grant=push_grant,
        db=db,
        transport=gh_transport,
        repo=repo,
        managed_gitdir=managed_gitdir,
    )
    urow_after_push = db.get_unit(unit_key)
    if push_res.get("status") != "succeeded_verified" or (urow_after_push and int(urow_after_push["veto_pending"])):
        return {
            "status": push_res.get("status", "paused"),
            "candidate_sha": approved_gate.candidate_sha,
            "defect_trajectory": defect_trajectory,
        }

    pr_id_out = urow_after_push["pr_id"] if urow_after_push else None
    if not pr_id_out:
        ref_hmac = compute_ref_id_hmac(hmac_secret, unit_key, "create_draft_pr", approved_gate.candidate_sha)
        repo_node_id = cfg.extra.get("repository_id") or gh_transport.get_repository_node_id(repo)
        pr_body = (
            f"Automated fix for `{unit_key}`.\n\n"
            f"- Verified DoD: `{dod_cmd}`\n"
            f"- Cross-family Referee (`{referee_family}`): `APPROVE` (defect trajectory `{defect_trajectory}`)\n"
            f"- Ref-ID: {ref_hmac}\n"
        )
        pr_op = db.prepare_op(
            unit_key=unit_key,
            op_type="create_draft_pr",
            claim_epoch=claim_epoch,
            candidate_sha=approved_gate.candidate_sha,
            ref_id_hmac=ref_hmac,
            payload={
                "repositoryId": repo_node_id,
                "title": f"fix({cfg.project_id}): {unit_key}",
                "body": pr_body,
            },
        )
        pr_grant = db.promote_op_to_in_flight(pr_op, caller_owner_kind="worker", caller_epoch=claim_epoch)
        pr_res = execute_granted_op(grant=pr_grant, db=db, transport=gh_transport, repo=repo)
        urow_after_pr = db.get_unit(unit_key)
        if pr_res.get("status") != "succeeded_verified" or (urow_after_pr and int(urow_after_pr["veto_pending"])):
            return {
                "status": pr_res.get("status", "paused"),
                "candidate_sha": approved_gate.candidate_sha,
                "pr_id": pr_res.get("pr_id"),
                "defect_trajectory": defect_trajectory,
            }
        pr_id_out = pr_res.get("pr_id")

    if claim["effective_tier"] in ("T2", "T3", "T4"):
        ready_op = db.prepare_op(
            unit_key=unit_key,
            op_type="mark_pr_ready",
            claim_epoch=claim_epoch,
            candidate_sha=approved_gate.candidate_sha,
        )
        ready_grant = db.promote_op_to_in_flight(ready_op, caller_owner_kind="worker", caller_epoch=claim_epoch)
        ready_res = execute_granted_op(grant=ready_grant, db=db, transport=gh_transport, repo=repo)
        urow_after_ready = db.get_unit(unit_key)
        if ready_res.get("status") != "succeeded_verified" or (urow_after_ready and int(urow_after_ready["veto_pending"])):
            return {
                "status": ready_res.get("status", "paused"),
                "candidate_sha": approved_gate.candidate_sha,
                "pr_id": pr_id_out,
                "defect_trajectory": defect_trajectory,
            }

    dur_ms = int((time.monotonic() - t_start) * 1000)
    db.mark_unit_published(unit_key, duration_ms=dur_ms)
    return {
        "status": "published",
        "candidate_sha": approved_gate.candidate_sha,
        "pr_id": pr_id_out,
        "defect_trajectory": defect_trajectory,
    }
