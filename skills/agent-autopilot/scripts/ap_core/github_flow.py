"""Single-mutation GitHub transport, ephemeral push bare repo, branch-protection cap, and 10-action reconciler."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .db import AutopilotDB
from .models import (
    POLICY_MANIFEST,
    AutopilotError,
    PrSnapshot,
    ScopeConflictError,
    SendGrant,
    ensure_secure_dir,
)

_LITERAL_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_DETERMINISTIC_GQL_ERROR_TYPES = frozenset({"UNPROCESSABLE", "FORBIDDEN", "NOT_FOUND", "BAD_USER_INPUT"})


class GraphQLServerRejectedError(AutopilotError):
    """Raised ONLY when GitHub's GraphQL endpoint returned an explicit structured JSON error response."""

    def __init__(self, errors: list[dict[str, Any]], *, data: dict[str, Any] | None = None) -> None:
        self.errors = errors
        self.data = data or {}
        super().__init__(f"GraphQL server rejected mutation: {errors}")


@dataclass(frozen=True)
class TransportResult:
    ok: bool
    remote_receipt_id: str | None = None
    pr_id: str | None = None
    pr_number: int | None = None
    unsent_proof: str | None = None
    error_detail: str | None = None


class GitHubTransport(Protocol):
    """Abstract single-mutation GitHub transport for live gh/git and deterministic fault-injection tests."""

    @property
    def bot_login(self) -> str | None: ...

    def get_repository_node_id(self, repo: str) -> str: ...

    def get_remote_branch_oid(self, repo: str, branch_name: str) -> str | None: ...

    def push_branch_ephemeral(
        self,
        *,
        repo: str,
        managed_gitdir: Path,
        candidate_sha: str,
        authorized_head_ref: str,
        authorized_base_ref: str,
        expected_old_oid: str | None,
    ) -> TransportResult: ...

    def fetch_pr_snapshot(self, repo: str, pr_id: str, *, snapshot_seq: int = 0) -> PrSnapshot | None: ...

    def find_pr_for_head_or_ref_id(
        self,
        repo: str,
        *,
        authorized_head_ref: str,
        ref_id_hmac: str | None,
        snapshot_seq: int = 0,
    ) -> PrSnapshot | None: ...

    def has_comment_with_ref_id(self, repo: str, subject_id: str, ref_id_hmac: str) -> bool | None: ...

    def has_label_on_subject(self, repo: str, subject_id: str, label_name: str) -> bool | None: ...

    def inspect_branch_protection(
        self,
        repo: str,
        authorized_base_ref: str,
        *,
        for_merge_pr: bool,
        has_separate_merge_token: bool,
    ) -> tuple[bool, str]: ...

    def send_single_mutation(
        self,
        *,
        repo: str,
        op_type: str,
        payload: dict[str, Any],
        use_merge_token: bool = False,
    ) -> TransportResult: ...


def has_exact_ref_id_line(text: str, ref_id_hmac: str) -> bool:
    """Line-by-line match allowing ONLY horizontal whitespace [ \\t] (NEVER matching across newlines!)."""
    if not ref_id_hmac or "\n" in ref_id_hmac or "\r" in ref_id_hmac:
        return False
    pat = re.compile(rf"^[ \t]*(?:-[ \t]*)?Ref-ID:[ \t]*{re.escape(ref_id_hmac)}[ \t]*$")
    return any(bool(pat.fullmatch(line)) for line in (text or "").splitlines())


def evaluate_classic_protection_for_enqueue(
    *,
    authorized_base_ref: str,
    rules: list[dict[str, Any]],
    has_incomplete_pagination: bool,
    merge_queue_branches: dict[str, bool],
    active_ruleset_mq_includes: list[list[str]] | None = None,
) -> tuple[bool, str]:
    """Enforce policy_manifest server_target_branch_constraint across rulesets + classic rules -> cap at T2 when unprovable."""
    if has_incomplete_pagination:
        return False, "rulesets or classic branchProtectionRules pagination incomplete -> cap T2"
    for inc_list in (active_ruleset_mq_includes or []):
        # Missing/null/empty refName.include on an ACTIVE MERGE_QUEUE ruleset cannot prove single target -> cap T2!
        if not inc_list:
            return False, "active MERGE_QUEUE ruleset has empty/unprovable refName.include -> cap T2"
        for rpat in inc_list:
            if rpat.startswith("~") or any(ch in rpat for ch in "*?["):
                return False, f"active MERGE_QUEUE ruleset uses symbolic/wildcard target {rpat!r} -> cap T2"
            norm = rpat[len("refs/heads/") :] if rpat.startswith("refs/heads/") else rpat
            if norm != authorized_base_ref:
                return False, f"active ruleset enables Merge Queue on non-authorized pattern {rpat!r} -> cap T2"
    mq_enabled_branches = [b for b, enabled in merge_queue_branches.items() if enabled]
    for b in mq_enabled_branches:
        if b != authorized_base_ref:
            return False, f"second Merge Queue enabled on non-authorized branch {b!r} -> cap T2"
    for rule in rules:
        pat = str(rule.get("pattern") or "").strip()
        if not pat or pat == authorized_base_ref:
            continue
        is_exact_literal = bool(_LITERAL_BRANCH_RE.fullmatch(pat)) and not any(ch in pat for ch in "*?[")
        if not is_exact_literal:
            return False, f"classic wildcard BranchProtectionRule {pat!r} cannot prove Merge Queue disabled -> cap T2"
        if pat not in merge_queue_branches or merge_queue_branches[pat] is not False:
            return False, f"literal classic rule {pat!r} missing mergeQueue==null proof -> cap T2"
    return True, "ok"


def _parse_iso_utc(raw: str) -> dt.datetime | None:
    if not raw:
        return None
    try:
        d = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return d if d.tzinfo is not None else d.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def is_enqueue_attributable_to_op(op_row: dict[str, Any], pr: PrSnapshot, *, bot_login: str | None) -> bool:
    """Check whether PR enqueue is strictly attributable to `op_row` per AUTOPILOT_PLAN.md §4.2.2."""
    receipt = op_row.get("remote_receipt_id")
    if receipt:
        if pr.state == "OPEN":
            return pr.merge_queue_entry_id == receipt
        if pr.state == "MERGED":
            return True
        return False

    if not bot_login or pr.state != "OPEN" or pr.merge_queue_entry_id is None:
        return False
    prep_dt = _parse_iso_utc(str(op_row.get("prepared_at") or ""))
    enq_dt = _parse_iso_utc(str(pr.merge_queue_enqueued_at or ""))
    if prep_dt is None or enq_dt is None:
        return False
    # GitHub timestamps are truncated to whole seconds; without an explicit receipt, same-second events are ambiguous -> retain unknown_paused!
    prep_sec = int(prep_dt.timestamp())
    if int(enq_dt.timestamp()) <= prep_sec:
        return False
    # Without a persisted remote_receipt_id, COMPLETE timeline pagination is REQUIRED to prove a single enqueue!
    if pr.enqueue_event_timestamps is None:
        return False
    parsed_evs = [_parse_iso_utc(ts) for ts in pr.enqueue_event_timestamps]
    if any(ed is None for ed in parsed_evs):
        return False
    # Any event in the SAME second as prepared_at OR after prepared_at counts toward ambiguity; must be exactly 1 AND strictly > prep_sec!
    events_from_prep_sec = [ed for ed in parsed_evs if ed is not None and int(ed.timestamp()) >= prep_sec]
    if len(events_from_prep_sec) != 1 or int(events_from_prep_sec[0].timestamp()) <= prep_sec:
        return False
    if (
        pr.merge_queue_enqueuer == bot_login
        and pr.head_ref_oid == op_row.get("candidate_sha")
        and pr.base_ref_name == op_row.get("authorized_base_ref")
    ):
        return True
    return False


def _expected_enqueuer_for_op(db: AutopilotDB, op_row: dict[str, Any]) -> str | None:
    """Require originating claim's persisted bound_gh_login for receipt-less enqueue attribution; return None if unrecorded!"""
    ce = op_row.get("claim_epoch")
    if ce is not None:
        cl = db.get_claim(int(ce))
        if cl is not None and cl.get("bound_gh_login"):
            return str(cl["bound_gh_login"])
    return None


def has_positive_enqueue_evidence(pr: PrSnapshot) -> bool:
    return pr.state == "OPEN" and pr.merge_queue_entry_id is not None


def fetch_pr_unveto_snapshot(
    transport: GitHubTransport,
    db: AutopilotDB,
    repo: str,
    eff_pr_id: str,
) -> PrSnapshot:
    seq_at_read = db.current_op_seq()
    snap = transport.fetch_pr_snapshot(repo, eff_pr_id, snapshot_seq=seq_at_read)
    if snap is None:
        raise AutopilotError(f"Failed to fetch live unveto PR snapshot for {eff_pr_id}")
    return snap


def verify_pre_send_pr_state(
    *,
    transport: GitHubTransport,
    db: AutopilotDB,
    repo: str,
    unit_key: str,
    eff_pr_id: str,
    op_type: str,
    expected_oid: str,
    authorized_base_ref: str,
    expected_is_draft: bool,
) -> PrSnapshot:
    """Mandatory live pre-send PR snapshot check: aborts with 0 remote writes + needs-human on ANY conflict."""
    snap = transport.fetch_pr_snapshot(repo, eff_pr_id, snapshot_seq=db.current_op_seq())
    if snap is None:
        raise AutopilotError(f"Pre-send live PR re-read failed for {eff_pr_id}; refusing to send {op_type}")

    conflict_reasons: list[str] = []
    if snap.state != "OPEN":
        conflict_reasons.append(f"state={snap.state!r}!=OPEN")
    if snap.is_draft != expected_is_draft:
        conflict_reasons.append(f"isDraft={snap.is_draft}!=expected({expected_is_draft})")
    if snap.merge_queue_entry_id is not None:
        conflict_reasons.append(f"mergeQueueEntry={snap.merge_queue_entry_id!r}!=None")
    if snap.auto_merge_enabled:
        conflict_reasons.append("autoMergeRequest!=None")
    if expected_oid and snap.head_ref_oid != expected_oid:
        conflict_reasons.append(f"headRefOid={snap.head_ref_oid!r}!=expected({expected_oid!r})")
    if authorized_base_ref and snap.base_ref_name != authorized_base_ref:
        conflict_reasons.append(f"baseRefName={snap.base_ref_name!r}!=authorized({authorized_base_ref!r})")

    if conflict_reasons:
        reason = f"pre_send_pr_conflict({op_type}): " + ", ".join(conflict_reasons)
        db.mark_unit_needs_human(unit_key, reason, non_veto=True)
        raise AutopilotError(reason)
    return snap


def _apply_bound_pr_postcheck_or_revoke(
    *,
    db: AutopilotDB,
    dispatcher_epoch: int,
    unit_key: str,
    op_id: str,
    op_type: str,
    candidate_sha: str,
    authorized_base_ref: str,
    pr: PrSnapshot,
    remote_receipt_id: str | None = None,
) -> dict[str, Any]:
    post_ok = (
        pr.state == "OPEN"
        and pr.is_draft is True
        and pr.merge_queue_entry_id is None
        and pr.auto_merge_enabled is False
        and pr.base_ref_name == authorized_base_ref
        and (op_type == "push_branch" or pr.head_ref_oid == candidate_sha)
    )
    with db.immediate_tx():
        if post_ok:
            return db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status="succeeded_verified",
                remote_receipt_id=remote_receipt_id or pr.pr_id,
                pr_id=pr.pr_id,
                confirmed_head_oid=candidate_sha or None,
            )

        if pr.state == "MERGED":
            new_st = (
                "merged_before_revoke"
                if (pr.head_ref_oid == candidate_sha and pr.base_ref_name == authorized_base_ref)
                else "diverged_needs_human"
            )
            res = db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status=new_st,
                remote_receipt_id=remote_receipt_id or pr.pr_id,
                pr_id=pr.pr_id,
                error_detail="PR merged before/during draft quiescence check",
            )
            if res.get("_scope_quarantined"):
                return res
            db.register_admin_revoke(
                unit_key=unit_key,
                dispatcher_epoch=dispatcher_epoch,
                pr_id=pr.pr_id,
                need_dequeue=False,
                need_disable_automerge=False,
                need_draft=False,
                terminal_state="needs-human",
                reason=f"{op_type} observed MERGED PR",
            )
            return res

        if pr.state == "OPEN":
            if op_type == "push_branch":
                settled_status = "succeeded_verified"
            else:
                settled_status = (
                    "succeeded_verified"
                    if (pr.head_ref_oid == candidate_sha and pr.base_ref_name == authorized_base_ref)
                    else "diverged_needs_human"
                )
            res = db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status=settled_status,
                remote_receipt_id=remote_receipt_id or pr.pr_id,
                pr_id=pr.pr_id,
                confirmed_head_oid=candidate_sha if settled_status == "succeeded_verified" else None,
                error_detail="bound PR violated draft quiescence post-condition",
            )
            if res.get("_scope_quarantined"):
                return res
            db.register_admin_revoke(
                unit_key=unit_key,
                dispatcher_epoch=dispatcher_epoch,
                pr_id=pr.pr_id,
                need_dequeue=(pr.merge_queue_entry_id is not None),
                need_disable_automerge=bool(pr.auto_merge_enabled),
                need_draft=(not pr.is_draft),
                terminal_state="needs-human",
                reason=f"{op_type} post-condition violation on PR {pr.pr_id}",
            )
            return res

        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="unknown_paused",
            pr_id=pr.pr_id,
            error_detail="PR is CLOSED (unmerged)",
        )


def _validate_authoritative_payload_alignment(
    *,
    payload: dict[str, Any],
    eff_pr_id: str | None,
    confirmed_head_oid: str | None,
    grant: SendGrant,
) -> dict[str, Any]:
    """Reject ANY payload field conflicting with frozen DB authority, and stamp authoritative targets."""
    out = dict(payload)
    if grant.op_type in (
        "mark_pr_ready",
        "enqueue_pr",
        "merge_pr",
        "convert_pr_to_draft",
        "dequeue_pr",
        "disable_pr_automerge",
    ) and eff_pr_id is None:
        raise AutopilotError(f"{grant.op_type} requires an authoritative bound eff_pr_id; refusing unbound payload")
    if eff_pr_id is None and out.get("pullRequestId") is not None:
        raise AutopilotError("Payload pullRequestId rejected because unit scope has no bound eff_pr_id")
    checks: list[tuple[str, Any]] = [
        ("pullRequestId", eff_pr_id),
        ("subjectId", eff_pr_id),
        ("labelableId", eff_pr_id),
        ("expectedHeadOid", grant.candidate_sha),
        ("baseRefName", grant.authorized_base_ref),
        ("headRefName", grant.authorized_head_ref),
        ("refIdHmac", grant.ref_id_hmac),
        ("expected_old_oid", confirmed_head_oid),
    ]
    for key, auth_val in checks:
        if auth_val is not None:
            if key in out and out[key] is not None and str(out[key]) != str(auth_val):
                raise AutopilotError(
                    f"Payload field {key}={out[key]!r} conflicts with frozen authoritative value {auth_val!r}"
                )
            out[key] = auth_val
    return out


def execute_granted_op(
    *,
    grant: SendGrant,
    db: AutopilotDB,
    transport: GitHubTransport,
    repo: str,
    managed_gitdir: Path | None = None,
    has_separate_merge_token: bool = False,
    simulate_crash_after_send: bool = False,
) -> dict[str, Any]:
    """Atomically consume one-shot SendGrant FIRST, validate pre-send invariants, and execute SINGLE mutation."""
    if not grant.granted:
        raise AutopilotError(f"Refusing to transmit {grant.op_id}: SendGrant(granted=False)")

    # ATOMIC ONE-TIME CONSUMPTION AT ENTRY: guarantees a duplicate caller NEVER races pre-send checks or mutates DB!
    if not db.consume_send_grant(grant):
        raise AutopilotError(f"SendGrant for {grant.op_id} was already consumed or invalidated; refusing duplicate entry")

    row = db.get_op(grant.op_id)
    if row is None or row["status"] != "in_flight":
        raise AutopilotError(f"Op {grant.op_id} is not in_flight")

    def _abort_before_network(unsent_tag: str, detail: str) -> dict[str, Any]:
        # Worker pre-send abort settles to not_executed; supervisor_admin stays unknown_paused WITH unsent_proof so recovery retries!
        target_st = "not_executed" if grant.owner_kind == "worker" else "unknown_paused"
        return db.complete_op_status(
            grant.op_id,
            expected_current_statuses=("in_flight",),
            new_status=target_st,
            unsent_proof=unsent_tag,
            error_detail=detail,
        )

    urow = db.get_unit(grant.unit_key)
    if urow is None:
        _abort_before_network("missing_unit", f"Unknown unit {grant.unit_key}")
        raise AutopilotError(f"Unknown unit {grant.unit_key}")
    if urow["repo"] and urow["repo"] != repo:
        _abort_before_network("repo_mismatch", f"repo {repo!r} != {urow['repo']!r}")
        raise AutopilotError(f"Target repo {repo!r} mismatches unit's frozen repo {urow['repo']!r}")

    if grant.owner_kind == "worker":
        if row.get("claim_epoch") is None:
            _abort_before_network("missing_worker_claim", "worker op missing claim_epoch")
            raise AutopilotError("Worker op missing claim_epoch; refusing remote write")
        cl_chk = db.get_claim(int(row["claim_epoch"]))
        bound_login = str((cl_chk or {}).get("bound_gh_login") or "").strip()
        ephem_tf = str((cl_chk or {}).get("ephemeral_token_file") or "").strip()
        if not cl_chk or not bound_login or not ephem_tf:
            _abort_before_network(
                "legacy_unbound_claim",
                "pre-upgrade claim missing bound_gh_login or ephemeral_token_file",
            )
            raise AutopilotError(
                "Legacy worker claim missing bound_gh_login or ephemeral_token_file; refusing new remote write"
            )
        if isinstance(transport, LiveGitHubCliTransport) and not Path(ephem_tf).is_file():
            _abort_before_network("missing_sealed_token_file", f"sealed token missing: {ephem_tf}")
            raise AutopilotError(f"Sealed token file {ephem_tf} missing; refusing remote write")
        cur_login = transport.bot_login
        if not cur_login or cur_login != bound_login:
            _abort_before_network(
                "gh_identity_drift",
                f"current gh login {cur_login!r} != bound_gh_login {bound_login!r}",
            )
            raise AutopilotError(
                f"GitHub identity drifted ({cur_login!r} != {bound_login!r}); refusing remote write"
            )

    op_type = grant.op_type
    if op_type in POLICY_MANIFEST["forbidden_graphql_mutations"]:
        _abort_before_network("forbidden_mutation", op_type)
        raise AutopilotError(f"Forbidden GraphQL mutation: {op_type}")

    raw_payload = json.loads(row["payload_json"] or "{}")
    scope = db.resolve_unit_scope_and_pending(grant.unit_key, pr_id=grant.pr_id)
    eff_pr_id = scope.eff_pr_id
    disp_epoch = db.get_dispatcher_epoch()

    try:
        call_payload = _validate_authoritative_payload_alignment(
            payload=raw_payload,
            eff_pr_id=eff_pr_id,
            confirmed_head_oid=urow.get("last_confirmed_head_oid"),
            grant=grant,
        )
    except AutopilotError as exc:
        _abort_before_network("payload_conflict", str(exc))
        raise

    # Pre-dequeue attribution check BEFORE sending dequeue_pr so queue evidence is never destroyed!
    if op_type == "dequeue_pr" and eff_pr_id:
        snap_dq = transport.fetch_pr_snapshot(repo, eff_pr_id, snapshot_seq=db.current_op_seq())
        if snap_dq is None:
            return _abort_before_network("pre_dequeue_unreadable", "pre-dequeue PR snapshot unreadable")
        if snap_dq.state == "OPEN" and snap_dq.merge_queue_entry_id is not None:
            scope_ops = db.list_ops_for_scope(grant.unit_key)
            pending_enqs = [
                sop for sop in scope_ops
                if sop["op_type"] == "enqueue_pr" and sop["status"] in ("in_flight", "unknown_paused")
            ]
            for sop in pending_enqs:
                exp_login = _expected_enqueuer_for_op(db, sop)
                if is_enqueue_attributable_to_op(sop, snap_dq, bot_login=exp_login):
                    db.complete_op_status(
                        sop["op_id"],
                        expected_current_statuses=("in_flight", "unknown_paused"),
                        new_status="succeeded_verified",
                        remote_receipt_id=snap_dq.merge_queue_entry_id,
                    )
                else:
                    return _abort_before_network(
                        "ambiguous_enqueue_ownership_pre_dequeue",
                        "ambiguous mergeQueueEntry ownership before dequeue_pr",
                    )

    if op_type in ("enqueue_pr", "merge_pr"):
        if op_type == "merge_pr" and not has_separate_merge_token:
            _abort_before_network("pre_send_missing_separate_merge_token_cap_T2", "missing separate merge_token")
            raise AutopilotError("merge_pr requires separate merge_token; capped at T2")
        ok_prot, prot_reason = transport.inspect_branch_protection(
            repo,
            str(grant.authorized_base_ref or ""),
            for_merge_pr=(op_type == "merge_pr"),
            has_separate_merge_token=has_separate_merge_token,
        )
        if not ok_prot:
            _abort_before_network(f"pre_send_protection_cap_T2:{prot_reason}", prot_reason)
            raise AutopilotError(prot_reason)

    expected_old_oid: str | None = urow.get("last_confirmed_head_oid") or call_payload.get("expected_old_oid")
    if grant.owner_kind == "worker" and eff_pr_id is not None and op_type in (
        "push_branch",
        "mark_pr_ready",
        "enqueue_pr",
        "merge_pr",
        "post_comment",
        "add_label",
    ):
        has_ready_for_cand = any(
            sop["op_type"] == "mark_pr_ready"
            and sop["status"] == "succeeded_verified"
            and sop["candidate_sha"] == grant.candidate_sha
            and sop["pr_id"] == eff_pr_id
            for sop in db.list_ops_for_scope(grant.unit_key)
        )
        exp_draft = False if (op_type in ("enqueue_pr", "merge_pr") or has_ready_for_cand) else True
        if op_type == "push_branch":
            exp_draft = True
            exp_oid = str(expected_old_oid or "")
        else:
            exp_oid = str(grant.candidate_sha or urow.get("last_confirmed_head_oid") or "")
        try:
            snap_pre = verify_pre_send_pr_state(
                transport=transport,
                db=db,
                repo=repo,
                unit_key=grant.unit_key,
                eff_pr_id=eff_pr_id,
                op_type=op_type,
                expected_oid=exp_oid,
                authorized_base_ref=str(grant.authorized_base_ref or ""),
                expected_is_draft=exp_draft,
            )
            if op_type == "push_branch" and not expected_old_oid:
                expected_old_oid = snap_pre.head_ref_oid
        except AutopilotError as exc:
            _abort_before_network(f"pre_send_aborted:{exc}", str(exc))
            raise

    # Always resolve & verify authoritative repositoryId against frozen `repo`!
    if op_type == "create_draft_pr":
        try:
            auth_repo_id = transport.get_repository_node_id(repo)
        except AutopilotError as exc:
            _abort_before_network("repo_id_lookup_failed", str(exc))
            raise
        provided_rid = call_payload.get("repositoryId")
        if provided_rid and provided_rid != "REPO_ID" and str(provided_rid) != str(auth_repo_id):
            _abort_before_network("repository_id_mismatch", f"{provided_rid!r} != {auth_repo_id!r}")
            raise AutopilotError(f"repositoryId {provided_rid!r} mismatches frozen repo {repo} ({auth_repo_id!r})")
        call_payload["repositoryId"] = auth_repo_id

    # Final millisecond scope-integrity gate right before network write (catches any conflict injected after consume_send_grant!)
    ok_fin_int, conn_fin_units, fin_int_reason = db.inspect_scope_integrity(grant.unit_key, pr_id=eff_pr_id)
    if not ok_fin_int:
        for uk_q in conn_fin_units or (grant.unit_key,):
            db.mark_unit_needs_human(uk_q, f"pre-network scope conflict: {fin_int_reason}", non_veto=False)
        _abort_before_network("scope_integrity_conflict_pre_network", fin_int_reason)
        raise ScopeConflictError(f"Refusing network send due to scope conflict: {fin_int_reason}")

    if op_type == "push_branch":
        if managed_gitdir is None:
            _abort_before_network("missing_managed_gitdir", "push_branch requires managed_gitdir")
            raise AutopilotError("push_branch requires managed_gitdir")
        if grant.authorized_head_ref == grant.authorized_base_ref:
            _abort_before_network("refused_push_to_base_ref", "head==base")
            raise AutopilotError("Refusing to push to authorized_base_ref")
        tr = transport.push_branch_ephemeral(
            repo=repo,
            managed_gitdir=managed_gitdir,
            candidate_sha=str(grant.candidate_sha),
            authorized_head_ref=str(grant.authorized_head_ref),
            authorized_base_ref=str(grant.authorized_base_ref),
            expected_old_oid=expected_old_oid,
        )
    else:
        tr = transport.send_single_mutation(
            repo=repo,
            op_type=op_type,
            payload=call_payload,
            use_merge_token=(op_type == "merge_pr"),
        )

    if simulate_crash_after_send:
        raise RuntimeError(f"Simulated crash right after transmitting {op_type} ({grant.op_id})")

    if not tr.ok:
        if tr.unsent_proof:
            if grant.owner_kind == "worker":
                if "lease" in tr.unsent_proof.lower() or "expectedheadoid" in tr.unsent_proof.lower():
                    db.mark_unit_needs_human(grant.unit_key, f"{op_type} server lease/OID rejected: {tr.error_detail}", non_veto=True)
                return db.complete_op_status(
                    grant.op_id,
                    expected_current_statuses=("in_flight",),
                    new_status="not_executed",
                    unsent_proof=tr.unsent_proof,
                    error_detail=tr.error_detail,
                )
            # Admin op with unsent_proof: keep unknown_paused WITH unsent_proof so lock stays held until reconcile/retry!
            db.record_op_receipt(grant.op_id, unsent_proof=tr.unsent_proof, error_detail=tr.error_detail)
            return reconcile_op(
                db=db,
                transport=transport,
                repo=repo,
                op_id=grant.op_id,
                sender_confirmed_terminated=True,
                dispatcher_epoch=disp_epoch,
            )
        return db.complete_op_status(
            grant.op_id,
            expected_current_statuses=("in_flight",),
            new_status="unknown_paused",
            error_detail=tr.error_detail or "transport outcome unknown",
        )

    db.record_op_receipt(
        grant.op_id,
        remote_receipt_id=tr.remote_receipt_id or "ack",
        pr_id=tr.pr_id,
        pr_number=tr.pr_number,
        confirmed_head_oid=str(grant.candidate_sha) if op_type in ("push_branch", "create_draft_pr") and grant.candidate_sha else None,
    )

    return reconcile_op(
        db=db,
        transport=transport,
        repo=repo,
        op_id=grant.op_id,
        sender_confirmed_terminated=True,
        dispatcher_epoch=disp_epoch,
    )


def reconcile_op(
    *,
    db: AutopilotDB,
    transport: GitHubTransport,
    repo: str,
    op_id: str,
    sender_confirmed_terminated: bool,
    dispatcher_epoch: int,
) -> dict[str, Any]:
    """Reconcile any in_flight / unknown_paused op strictly per AUTOPILOT_PLAN.md v7.8 §4.2.4."""
    row = db.get_op(op_id)
    if row is None:
        raise AutopilotError(f"Unknown op_id: {op_id}")
    if row["status"] not in ("in_flight", "unknown_paused"):
        return row
    if not sender_confirmed_terminated:
        return row
    if row["owner_kind"] == "supervisor_admin" and dispatcher_epoch < int(row["owner_epoch"]):
        return row

    op_type = str(row["op_type"])
    unit_key = str(row["unit_key"])
    cand = str(row["candidate_sha"] or "")
    base_ref = str(row["authorized_base_ref"] or "")
    head_ref = str(row["authorized_head_ref"] or "")
    has_receipt = bool(row["remote_receipt_id"])
    # If sender is confirmed terminated while send_consumed == 0, it NEVER transmitted a single byte!
    unsent_proof = row["unsent_proof"] or ("send_grant_never_consumed" if int(row["send_consumed"]) == 0 else None)
    payload = json.loads(row["payload_json"] or "{}")
    scope = db.resolve_unit_scope_and_pending(unit_key, pr_id=row["pr_id"])
    eff_pr_id = scope.eff_pr_id

    if row["owner_kind"] == "worker" and unsent_proof:
        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="not_executed",
            unsent_proof=unsent_proof,
        )

    if op_type == "push_branch":
        remote_oid = transport.get_remote_branch_oid(repo, head_ref)
        if remote_oid is None or remote_oid != cand:
            return db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status="unknown_paused",
            )
        if eff_pr_id is None:
            return db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status="succeeded_verified",
                remote_receipt_id=row["remote_receipt_id"] or f"ref:{cand}",
                confirmed_head_oid=cand,
            )
        pr = transport.fetch_pr_snapshot(repo, eff_pr_id, snapshot_seq=db.current_op_seq())
        if pr is None:
            return db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status="unknown_paused",
            )
        return _apply_bound_pr_postcheck_or_revoke(
            db=db,
            dispatcher_epoch=dispatcher_epoch,
            unit_key=unit_key,
            op_id=op_id,
            op_type="push_branch",
            candidate_sha=cand,
            authorized_base_ref=base_ref,
            pr=pr,
            remote_receipt_id=row["remote_receipt_id"] or f"ref:{cand}",
        )

    if op_type == "create_draft_pr":
        pr: PrSnapshot | None = None
        lookup_id = eff_pr_id or row["remote_receipt_id"]
        if lookup_id and not str(lookup_id).startswith("ack"):
            pr = transport.fetch_pr_snapshot(repo, str(lookup_id), snapshot_seq=db.current_op_seq())
        if pr is None:
            pr = transport.find_pr_for_head_or_ref_id(
                repo,
                authorized_head_ref=head_ref,
                ref_id_hmac=row["ref_id_hmac"],
                snapshot_seq=db.current_op_seq(),
            )
        if pr is None:
            return db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status="unknown_paused",
            )
        return _apply_bound_pr_postcheck_or_revoke(
            db=db,
            dispatcher_epoch=dispatcher_epoch,
            unit_key=unit_key,
            op_id=op_id,
            op_type="create_draft_pr",
            candidate_sha=cand,
            authorized_base_ref=base_ref,
            pr=pr,
            remote_receipt_id=pr.pr_id,
        )

    if op_type == "post_comment":
        subj = str(eff_pr_id or payload.get("subjectId") or "")
        found = transport.has_comment_with_ref_id(repo, subj, str(row["ref_id_hmac"] or "")) if subj else None
        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="succeeded_verified" if found else "unknown_paused",
        )

    if op_type == "add_label":
        subj = str(eff_pr_id or payload.get("labelableId") or "")
        lbl = str(payload.get("labelName") or "")
        found = transport.has_label_on_subject(repo, subj, lbl) if (subj and lbl) else None
        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="succeeded_verified" if found else "unknown_paused",
        )

    if not eff_pr_id:
        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="unknown_paused",
            unsent_proof=unsent_proof,
        )
    pr = transport.fetch_pr_snapshot(repo, eff_pr_id, snapshot_seq=db.current_op_seq())
    if pr is None:
        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="unknown_paused",
            unsent_proof=unsent_proof,
        )

    if op_type == "mark_pr_ready":
        if pr.state == "MERGED":
            if pr.head_ref_oid == cand and pr.base_ref_name == base_ref:
                return db.complete_op_status(
                    op_id,
                    expected_current_statuses=("in_flight", "unknown_paused"),
                    new_status="succeeded_verified" if has_receipt else "superseded_by_pr_merge",
                )
            db.mark_unit_needs_human(unit_key, "mark_pr_ready observed MERGED PR with head/base mismatch", non_veto=True)
            return db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status="diverged_needs_human",
            )
        if pr.state == "OPEN":
            if not has_receipt:
                if pr.head_ref_oid != cand or pr.base_ref_name != base_ref:
                    db.mark_unit_needs_human(
                        unit_key,
                        "OPEN mark_pr_ready without receipt observed head/base drift; retaining unknown_paused write lock",
                        non_veto=True,
                    )
                return db.complete_op_status(
                    op_id,
                    expected_current_statuses=("in_flight", "unknown_paused"),
                    new_status="unknown_paused",
                )
            if pr.head_ref_oid != cand or pr.base_ref_name != base_ref:
                with db.immediate_tx():
                    res = db.complete_op_status(
                        op_id,
                        expected_current_statuses=("in_flight", "unknown_paused"),
                        new_status="diverged_needs_human",
                    )
                    db.register_admin_revoke(
                        unit_key=unit_key,
                        dispatcher_epoch=dispatcher_epoch,
                        pr_id=eff_pr_id,
                        need_dequeue=(pr.merge_queue_entry_id is not None),
                        need_disable_automerge=bool(pr.auto_merge_enabled),
                        need_draft=(not pr.is_draft),
                        terminal_state="needs-human",
                        reason="mark_pr_ready head/base drifted",
                    )
                    return res
            if pr.is_draft:
                return db.complete_op_status(
                    op_id,
                    expected_current_statuses=("in_flight", "unknown_paused"),
                    new_status="rolled_back_to_draft",
                )
            return db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status="succeeded_verified",
            )
        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="unknown_paused",
        )

    if op_type == "merge_pr":
        if pr.state == "MERGED":
            if pr.head_ref_oid == cand and pr.base_ref_name == base_ref:
                return db.complete_op_status(
                    op_id,
                    expected_current_statuses=("in_flight", "unknown_paused"),
                    new_status="succeeded_verified",
                )
            db.mark_unit_needs_human(unit_key, "merge_pr observed MERGED PR with head/base mismatch", non_veto=True)
            return db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status="diverged_needs_human",
            )
        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="unknown_paused",
        )

    if op_type == "enqueue_pr":
        exp_enq_login = _expected_enqueuer_for_op(db, row)
        attr = is_enqueue_attributable_to_op(row, pr, bot_login=exp_enq_login)
        if attr and (
            has_positive_enqueue_evidence(pr)
            or (pr.state == "MERGED" and pr.head_ref_oid == cand and pr.base_ref_name == base_ref)
        ):
            return db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status="succeeded_verified",
                remote_receipt_id=row["remote_receipt_id"] or pr.merge_queue_entry_id,
            )
        if pr.state == "MERGED":
            if pr.head_ref_oid == cand and pr.base_ref_name == base_ref and not has_receipt:
                return db.complete_op_status(
                    op_id,
                    expected_current_statuses=("in_flight", "unknown_paused"),
                    new_status="superseded_by_pr_merge",
                )
            db.mark_unit_needs_human(unit_key, "enqueue_pr observed MERGED PR with head/base mismatch", non_veto=True)
            return db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status="diverged_needs_human",
            )
        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="unknown_paused",
        )

    # Supervisor Admin Actions
    if pr.state == "MERGED":
        db.mark_unit_needs_human(unit_key, f"{op_type} observed MERGED PR before revoke completed", non_veto=False)
        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="merged_before_revoke",
        )

    scope_ops = db.list_ops_for_scope(unit_key)
    conflicting_types = (
        {"mark_pr_ready"} if op_type == "convert_pr_to_draft" else {"enqueue_pr", "merge_pr"}
    )
    if op_type == "dequeue_pr" and pr.state == "OPEN" and pr.merge_queue_entry_id is not None:
        for sop in scope_ops:
            if sop["op_type"] == "enqueue_pr" and sop["status"] in ("in_flight", "unknown_paused"):
                exp_sop_login = _expected_enqueuer_for_op(db, sop)
                if is_enqueue_attributable_to_op(sop, pr, bot_login=exp_sop_login):
                    db.complete_op_status(
                        sop["op_id"],
                        expected_current_statuses=("in_flight", "unknown_paused"),
                        new_status="succeeded_verified",
                        remote_receipt_id=pr.merge_queue_entry_id,
                    )
        scope_ops = db.list_ops_for_scope(unit_key)

    has_unresolved_conflicting = any(
        sop["op_id"] != op_id
        and sop["op_type"] in conflicting_types
        and sop["status"] in ("prepared_local", "in_flight", "unknown_paused")
        for sop in scope_ops
    )

    target_achieved = (
        (op_type == "convert_pr_to_draft" and pr.state == "OPEN" and pr.is_draft is True)
        or (op_type == "dequeue_pr" and pr.state == "OPEN" and pr.merge_queue_entry_id is None)
        or (op_type == "disable_pr_automerge" and pr.state == "OPEN" and pr.auto_merge_enabled is False)
    )

    if target_achieved and has_receipt and not has_unresolved_conflicting:
        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="succeeded_verified",
        )
    if target_achieved and bool(unsent_proof) and not has_unresolved_conflicting:
        return db.complete_op_status(
            op_id,
            expected_current_statuses=("in_flight", "unknown_paused"),
            new_status="not_executed",
            unsent_proof=unsent_proof,
        )
    # If this admin op ALREADY executed (has_receipt) and a late conflicting mutation flipped PR state back (!target_achieved),
    # atomically retire this spent op_id to superseded_by_retry AND register a fresh compensation in the SAME transaction!
    if has_receipt and not target_achieved and pr.state == "OPEN":
        with db.immediate_tx():
            retired = db.complete_op_status(
                op_id,
                expected_current_statuses=("in_flight", "unknown_paused"),
                new_status="superseded_by_retry",
                error_detail="prior compensation receipt superseded by late remote flip; issuing fresh compensation",
            )
            db.register_admin_revoke(
                unit_key=unit_key,
                dispatcher_epoch=dispatcher_epoch,
                pr_id=eff_pr_id,
                need_dequeue=(op_type == "dequeue_pr" and pr.merge_queue_entry_id is not None),
                need_disable_automerge=(op_type == "disable_pr_automerge" and pr.auto_merge_enabled),
                need_draft=(op_type == "convert_pr_to_draft" and not pr.is_draft),
                remote_sync_pending=has_unresolved_conflicting,
                reason="re_compensate_after_late_flip",
            )
            return retired
    # Persist unsent_proof (e.g. send_grant_never_consumed) while keeping unknown_paused so supervisor recovery replaces & retries!
    return db.complete_op_status(
        op_id,
        expected_current_statuses=("in_flight", "unknown_paused"),
        new_status="unknown_paused",
        unsent_proof=unsent_proof,
    )


def _classify_graphql_rejection(gexc: GraphQLServerRejectedError) -> str | None:
    """Return deterministic unsent_proof ONLY when data has zero partial results and error type is deterministic."""
    if any(v is not None for v in (gexc.data or {}).values()):
        return None
    if not gexc.errors:
        return None
    for err in gexc.errors:
        etype = str(err.get("type") or "").upper()
        if etype not in _DETERMINISTIC_GQL_ERROR_TYPES:
            return None
    joined_msgs = " | ".join(str(e.get("message") or "") for e in gexc.errors).lower()
    if "head sha didn't match" in joined_msgs or "base branch was modified" in joined_msgs:
        return "expectedHeadOid_mismatch"
    if "pull request is in draft" in joined_msgs or "is still a draft" in joined_msgs:
        return "server_rejected_draft_state"
    return None


class LiveGitHubCliTransport:
    """Production GitHub transport using `gh api graphql` and ephemeral `0700` bare push repos."""

    def __init__(
        self,
        *,
        token: str | None = None,
        merge_token: str | None = None,
        cache_dir: Path | None = None,
        require_explicit_token: bool = False,
    ) -> None:
        self._token = token
        self._merge_token = merge_token
        self._cache_dir = cache_dir or (Path.home() / ".cache" / "agent-work" / "autopilot")
        self._require_explicit_token = require_explicit_token
        self._bot_login_cached: str | None = None

    def _gh_env(self, *, use_merge_token: bool = False) -> dict[str, str]:
        env = dict(os.environ)
        env["GH_PROMPT_DISABLED"] = "1"
        tok = (self._merge_token if use_merge_token else self._token) or ""
        tok = tok.strip()
        if self._require_explicit_token and not tok:
            raise AutopilotError("Dedicated project token required; refusing fallback to ambient GH_TOKEN or gh auth")
        if tok:
            env.pop("GITHUB_TOKEN", None)
            env["GH_TOKEN"] = tok
        return env

    @property
    def bot_login(self) -> str | None:
        """Always query live credential identity (never returning stale cached login if ambient gh auth switched)."""
        try:
            proc = subprocess.run(
                ["gh", "api", "user", "--jq", ".login"],
                env=self._gh_env(),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except Exception:
            return None
        login = proc.stdout.strip() if proc.returncode == 0 else ""
        return login or None

    def _graphql(self, query: str, variables: dict[str, Any], *, use_merge_token: bool = False) -> dict[str, Any]:
        cmd = ["gh", "api", "graphql", "-f", f"query={query}"]
        for k, v in variables.items():
            if isinstance(v, bool):
                cmd.extend(["-F", f"{k}={'true' if v else 'false'}"])
            elif isinstance(v, int):
                cmd.extend(["-F", f"{k}={v}"])
            elif v is not None:
                cmd.extend(["-f", f"{k}={v}"])
        proc = subprocess.run(
            cmd,
            env=self._gh_env(use_merge_token=use_merge_token),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        try:
            data = json.loads(proc.stdout) if proc.stdout.strip() else None
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict) and data.get("errors") and isinstance(data["errors"], list):
            raise GraphQLServerRejectedError(data["errors"], data=data.get("data"))
        if proc.returncode != 0 or not isinstance(data, dict):
            raise AutopilotError(f"gh graphql transport failed: {proc.stderr.strip() or proc.stdout.strip()}")
        return data.get("data") or {}

    def get_repository_node_id(self, repo: str) -> str:
        owner, name = repo.split("/", 1)
        d = self._graphql(
            "query($owner:String!,$name:String!){repository(owner:$owner,name:$name){id}}",
            {"owner": owner, "name": name},
        )
        rid = ((d.get("repository") or {}).get("id")) or ""
        if not rid:
            raise AutopilotError(f"Unable to resolve GitHub repository node ID for {repo}")
        return str(rid)

    def get_remote_branch_oid(self, repo: str, branch_name: str) -> str | None:
        owner, name = repo.split("/", 1)
        q = "query($owner:String!,$name:String!,$qualified:String!){repository(owner:$owner,name:$name){ref(qualifiedName:$qualified){target{oid}}}}"
        try:
            d = self._graphql(q, {"owner": owner, "name": name, "qualified": f"refs/heads/{branch_name}"})
            ref = (d.get("repository") or {}).get("ref")
            return ((ref or {}).get("target") or {}).get("oid")
        except Exception:
            return None

    def push_branch_ephemeral(
        self,
        *,
        repo: str,
        managed_gitdir: Path,
        candidate_sha: str,
        authorized_head_ref: str,
        authorized_base_ref: str,
        expected_old_oid: str | None,
    ) -> TransportResult:
        if authorized_head_ref == authorized_base_ref:
            return TransportResult(False, unsent_proof="refused_push_to_base_ref", error_detail="head==base")
        ensure_secure_dir(self._cache_dir, 0o700)
        eph_dir = Path(tempfile.mkdtemp(prefix="ephemeral-push-", dir=str(self._cache_dir)))
        os.chmod(eph_dir, 0o700)
        try:
            subprocess.run(["git", "init", "--bare", "-q", str(eph_dir)], check=True, timeout=15)
            info_dir = ensure_secure_dir(eph_dir / "objects" / "info", 0o700)
            (info_dir / "alternates").write_text(f"{managed_gitdir.resolve() / 'objects'}\n", encoding="utf-8")
            lease_arg = (
                f"--force-with-lease=refs/heads/{authorized_head_ref}:{expected_old_oid}"
                if expected_old_oid is not None
                else f"--force-with-lease=refs/heads/{authorized_head_ref}:"
            )
            url = f"https://github.com/{repo}.git"
            env = self._gh_env()
            env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"})
            proc = subprocess.run(
                [
                    "git",
                    f"--git-dir={eph_dir}",
                    "-c",
                    "credential.helper=!gh auth git-credential",
                    "push",
                    "--porcelain",
                    lease_arg,
                    url,
                    f"{candidate_sha}:refs/heads/{authorized_head_ref}",
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if proc.returncode == 0:
                return TransportResult(True, remote_receipt_id=f"push:{candidate_sha}")
            combined = f"{proc.stdout.strip()}\n{proc.stderr.strip()}".strip()
            low = combined.lower()
            porcelain_rejected = any(
                line.startswith("!")
                and any(r in line.lower() for r in ("stale info", "fetch first", "non-fast-forward", "[rejected]"))
                for line in proc.stdout.splitlines()
            )
            if porcelain_rejected or "stale info" in low:
                return TransportResult(False, unsent_proof="force_with_lease_rejected", error_detail=combined)
            return TransportResult(False, error_detail=combined)
        except subprocess.TimeoutExpired as exc:
            return TransportResult(False, error_detail=f"push timeout after {exc.timeout}s")
        finally:
            shutil.rmtree(eph_dir, ignore_errors=True)

    def fetch_pr_snapshot(self, repo: str, pr_id: str, *, snapshot_seq: int = 0) -> PrSnapshot | None:
        try:
            q = """
            query($id:ID!){
              node(id:$id){
                ... on PullRequest {
                  id number state isDraft headRefOid headRefName baseRefName body
                  autoMergeRequest { enabledAt }
                  mergeQueueEntry { id enqueuedAt enqueuer { login } }
                }
              }
            }
            """
            d = self._graphql(q, {"id": pr_id})
            n = d.get("node")
            if not n:
                return None
            # Paginate ADDED_TO_MERGE_QUEUE_EVENT timestamps so historical events before prepared_at never block!
            tl_timestamps: list[str] = []
            tl_cursor: str | None = None
            tl_complete = True
            while True:
                q_tl = """
                query($id:ID!,$after:String){
                  node(id:$id){
                    ... on PullRequest {
                      timelineItems(itemTypes:[ADDED_TO_MERGE_QUEUE_EVENT], first:100, after:$after){
                        pageInfo { hasNextPage endCursor }
                        nodes { ... on AddedToMergeQueueEvent { createdAt } }
                      }
                    }
                  }
                }
                """
                dtl = self._graphql(q_tl, {"id": pr_id, "after": tl_cursor})
                tconn = (((dtl.get("node") or {}).get("timelineItems")) or {})
                for ev in tconn.get("nodes") or []:
                    if ev and ev.get("createdAt"):
                        tl_timestamps.append(str(ev["createdAt"]))
                pi = tconn.get("pageInfo") or {}
                if not pi.get("hasNextPage"):
                    break
                tl_cursor = pi.get("endCursor")
                if not tl_cursor:
                    tl_complete = False
                    break

            mq = n.get("mergeQueueEntry") or {}
            return PrSnapshot(
                pr_id=n["id"],
                number=n.get("number"),
                state=n["state"],
                is_draft=bool(n["isDraft"]),
                head_ref_oid=n["headRefOid"],
                head_ref_name=n["headRefName"],
                base_ref_name=n["baseRefName"],
                merge_queue_entry_id=mq.get("id"),
                merge_queue_enqueuer=(mq.get("enqueuer") or {}).get("login"),
                merge_queue_enqueued_at=mq.get("enqueuedAt"),
                enqueue_event_timestamps=tuple(tl_timestamps) if tl_complete else None,
                auto_merge_enabled=bool(n.get("autoMergeRequest")),
                snapshot_seq=snapshot_seq,
                body=n.get("body") or "",
            )
        except Exception:
            return None

    def find_pr_for_head_or_ref_id(
        self,
        repo: str,
        *,
        authorized_head_ref: str,
        ref_id_hmac: str | None,
        snapshot_seq: int = 0,
    ) -> PrSnapshot | None:
        """Fully paginated lookup requiring NON-EMPTY exact single-line Ref-ID match and strict uniqueness."""
        if not ref_id_hmac:
            return None
        owner, name = repo.split("/", 1)
        cursor: str | None = None
        matches: list[PrSnapshot] = []
        try:
            while True:
                q = """
                query($owner:String!,$name:String!,$head:String!,$after:String){
                  repository(owner:$owner,name:$name){
                    pullRequests(headRefName:$head, first:50, after:$after, orderBy:{field:CREATED_AT, direction:DESC}){
                      pageInfo { hasNextPage endCursor }
                      nodes {
                        id number state isDraft headRefOid headRefName baseRefName body
                        autoMergeRequest { enabledAt }
                        mergeQueueEntry { id enqueuedAt enqueuer { login } }
                      }
                    }
                  }
                }
                """
                d = self._graphql(q, {"owner": owner, "name": name, "head": authorized_head_ref, "after": cursor})
                prs_conn = ((d.get("repository") or {}).get("pullRequests")) or {}
                for n in prs_conn.get("nodes") or []:
                    body = n.get("body") or ""
                    if not has_exact_ref_id_line(body, ref_id_hmac):
                        continue
                    mq = n.get("mergeQueueEntry") or {}
                    matches.append(
                        PrSnapshot(
                            pr_id=n["id"],
                            number=n.get("number"),
                            state=n["state"],
                            is_draft=bool(n["isDraft"]),
                            head_ref_oid=n["headRefOid"],
                            head_ref_name=n["headRefName"],
                            base_ref_name=n["baseRefName"],
                            merge_queue_entry_id=mq.get("id"),
                            merge_queue_enqueuer=(mq.get("enqueuer") or {}).get("login"),
                            merge_queue_enqueued_at=mq.get("enqueuedAt"),
                            auto_merge_enabled=bool(n.get("autoMergeRequest")),
                            snapshot_seq=snapshot_seq,
                            body=body,
                        )
                    )
                pi = prs_conn.get("pageInfo") or {}
                if not pi.get("hasNextPage"):
                    break
                cursor = pi.get("endCursor")
                if not cursor:
                    return None
            return matches[0] if len(matches) == 1 else None
        except Exception:
            return None

    def has_comment_with_ref_id(self, repo: str, subject_id: str, ref_id_hmac: str) -> bool | None:
        if not ref_id_hmac:
            return False
        cursor: str | None = None
        try:
            while True:
                q = """
                query($id:ID!,$after:String){
                  node(id:$id){
                    ... on Issue{comments(first:100, after:$after){pageInfo{hasNextPage endCursor} nodes{body}}}
                    ... on PullRequest{comments(first:100, after:$after){pageInfo{hasNextPage endCursor} nodes{body}}}
                  }
                }
                """
                d = self._graphql(q, {"id": subject_id, "after": cursor})
                conn = ((d.get("node") or {}).get("comments")) or {}
                if any(has_exact_ref_id_line(c.get("body") or "", ref_id_hmac) for c in (conn.get("nodes") or [])):
                    return True
                pi = conn.get("pageInfo") or {}
                if not pi.get("hasNextPage"):
                    return False
                cursor = pi.get("endCursor")
                if not cursor:
                    return None
        except Exception:
            return None

    def has_label_on_subject(self, repo: str, subject_id: str, label_name: str) -> bool | None:
        cursor: str | None = None
        try:
            while True:
                q = """
                query($id:ID!,$after:String){
                  node(id:$id){
                    ... on Labelable{labels(first:100, after:$after){pageInfo{hasNextPage endCursor} nodes{name}}}
                  }
                }
                """
                d = self._graphql(q, {"id": subject_id, "after": cursor})
                conn = ((d.get("node") or {}).get("labels")) or {}
                if any((l.get("name") or "") == label_name for l in (conn.get("nodes") or [])):
                    return True
                pi = conn.get("pageInfo") or {}
                if not pi.get("hasNextPage"):
                    return False
                cursor = pi.get("endCursor")
                if not cursor:
                    return None
        except Exception:
            return None

    def inspect_branch_protection(
        self,
        repo: str,
        authorized_base_ref: str,
        *,
        for_merge_pr: bool,
        has_separate_merge_token: bool,
    ) -> tuple[bool, str]:
        if for_merge_pr and not has_separate_merge_token:
            return False, "missing separate merge_token"
        owner, name = repo.split("/", 1)
        rules: list[dict[str, Any]] = []
        ruleset_mq_includes: list[list[str]] = []
        try:
            rs_cursor: str | None = None
            while True:
                q_rs = """
                query($owner:String!,$name:String!,$after:String){
                  repository(owner:$owner,name:$name){
                    rulesets(first:100, after:$after, includeParents:true){
                      pageInfo { hasNextPage endCursor }
                      nodes {
                        enforcement
                        conditions { refName { include } }
                        rules(first:100) { pageInfo { hasNextPage } nodes { type } }
                      }
                    }
                  }
                }
                """
                drs = self._graphql(q_rs, {"owner": owner, "name": name, "after": rs_cursor})
                rconn = ((drs.get("repository") or {}).get("rulesets")) or {}
                for rs_node in rconn.get("nodes") or []:
                    if str(rs_node.get("enforcement") or "").upper() != "ACTIVE":
                        continue
                    r_rules = rs_node.get("rules") or {}
                    if (r_rules.get("pageInfo") or {}).get("hasNextPage"):
                        return False, "incomplete ruleset rules pagination -> cap T2"
                    has_mq_rule = any(str(rn.get("type") or "").upper() == "MERGE_QUEUE" for rn in (r_rules.get("nodes") or []))
                    if has_mq_rule:
                        inc = (((rs_node.get("conditions") or {}).get("refName")) or {}).get("include")
                        ruleset_mq_includes.append([str(x) for x in inc] if isinstance(inc, list) else [])
                pi_rs = rconn.get("pageInfo") or {}
                if not pi_rs.get("hasNextPage"):
                    break
                rs_cursor = pi_rs.get("endCursor")
                if not rs_cursor:
                    return False, "incomplete rulesets pagination -> cap T2"

            cursor: str | None = None
            while True:
                q = """
                query($owner:String!,$name:String!,$after:String){
                  repository(owner:$owner,name:$name){
                    branchProtectionRules(first:50, after:$after){
                      pageInfo { hasNextPage endCursor }
                      nodes { pattern isAdminEnforced }
                    }
                  }
                }
                """
                d = self._graphql(q, {"owner": owner, "name": name, "after": cursor})
                bpr = ((d.get("repository") or {}).get("branchProtectionRules")) or {}
                rules.extend(bpr.get("nodes") or [])
                pi = bpr.get("pageInfo") or {}
                if not pi.get("hasNextPage"):
                    break
                cursor = pi.get("endCursor")
                if not cursor:
                    return False, "incomplete classic rule pagination"

            mq_map: dict[str, bool] = {}
            for r in rules:
                pat = str(r.get("pattern") or "")
                if pat and _LITERAL_BRANCH_RE.fullmatch(pat) and not any(c in pat for c in "*?["):
                    q_mq = "query($owner:String!,$name:String!,$b:String!){repository(owner:$owner,name:$name){mergeQueue(branch:$b){id}}}"
                    dmq = self._graphql(q_mq, {"owner": owner, "name": name, "b": pat})
                    mq_map[pat] = bool((dmq.get("repository") or {}).get("mergeQueue"))
            if for_merge_pr:
                return False, "live merge_pr requires explicit ruleset target exclusion proof -> cap T2"
            return evaluate_classic_protection_for_enqueue(
                authorized_base_ref=authorized_base_ref,
                rules=rules,
                has_incomplete_pagination=False,
                merge_queue_branches=mq_map,
                active_ruleset_mq_includes=ruleset_mq_includes,
            )
        except Exception as exc:
            return False, f"branch protection unreadable ({exc}) -> cap T2"

    def send_single_mutation(
        self,
        *,
        repo: str,
        op_type: str,
        payload: dict[str, Any],
        use_merge_token: bool = False,
    ) -> TransportResult:
        try:
            if op_type == "create_draft_pr":
                q = """
                mutation($repoId:ID!,$base:String!,$head:String!,$title:String!,$body:String!){
                  createPullRequest(input:{repositoryId:$repoId,baseRefName:$base,headRefName:$head,title:$title,body:$body,draft:true}){
                    pullRequest { id number }
                  }
                }
                """
                d = self._graphql(
                    q,
                    {
                        "repoId": payload["repositoryId"],
                        "base": payload["baseRefName"],
                        "head": payload["headRefName"],
                        "title": payload["title"],
                        "body": payload["body"],
                    },
                )
                pr = (d.get("createPullRequest") or {}).get("pullRequest") or {}
                return TransportResult(True, remote_receipt_id=pr["id"], pr_id=pr["id"], pr_number=pr.get("number"))
            if op_type == "mark_pr_ready":
                q = "mutation($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id}){pullRequest{id}}}"
                d = self._graphql(q, {"id": payload["pullRequestId"]})
                pr = (d.get("markPullRequestReadyForReview") or {}).get("pullRequest") or {}
                return TransportResult(True, remote_receipt_id=f"ready:{pr.get('id')}")
            if op_type == "post_comment":
                q = "mutation($id:ID!,$body:String!){addComment(input:{subjectId:$id,body:$body}){commentEdge{node{id}}}}"
                d = self._graphql(q, {"id": payload["subjectId"], "body": payload["body"]})
                cid = (((d.get("addComment") or {}).get("commentEdge") or {}).get("node") or {}).get("id")
                return TransportResult(True, remote_receipt_id=cid or "comment-ack")
            if op_type == "add_label":
                q = "mutation($id:ID!,$lids:[ID!]!){addLabelsToLabelable(input:{labelableId:$id,labelIds:$lids}){clientMutationId}}"
                proc = subprocess.run(
                    [
                        "gh",
                        "api",
                        "graphql",
                        "-f",
                        f"query={q}",
                        "-f",
                        f"id={payload['labelableId']}",
                        *[arg for lid in payload["labelIds"] for arg in ("-f", f"lids[]={lid}")],
                    ],
                    env=self._gh_env(),
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if proc.returncode != 0:
                    return TransportResult(False, error_detail=proc.stderr.strip() or proc.stdout.strip())
                return TransportResult(True, remote_receipt_id="label-ack")
            if op_type == "enqueue_pr":
                q = "mutation($id:ID!,$oid:GitObjectID!){enqueuePullRequest(input:{pullRequestId:$id,expectedHeadOid:$oid}){mergeQueueEntry{id}}}"
                d = self._graphql(q, {"id": payload["pullRequestId"], "oid": payload["expectedHeadOid"]})
                mqid = ((d.get("enqueuePullRequest") or {}).get("mergeQueueEntry") or {}).get("id")
                return TransportResult(True, remote_receipt_id=mqid or "mq-ack")
            if op_type == "merge_pr":
                q = "mutation($id:ID!,$oid:GitObjectID!,$m:PullRequestMergeMethod!){mergePullRequest(input:{pullRequestId:$id,expectedHeadOid:$oid,mergeMethod:$m}){pullRequest{id}}}"
                d = self._graphql(
                    q,
                    {
                        "id": payload["pullRequestId"],
                        "oid": payload["expectedHeadOid"],
                        "m": payload.get("mergeMethod", "SQUASH"),
                    },
                    use_merge_token=use_merge_token,
                )
                pr = (d.get("mergePullRequest") or {}).get("pullRequest") or {}
                return TransportResult(True, remote_receipt_id=f"merged:{pr.get('id')}")
            if op_type == "convert_pr_to_draft":
                q = "mutation($id:ID!){convertPullRequestToDraft(input:{pullRequestId:$id}){pullRequest{id}}}"
                d = self._graphql(q, {"id": payload["pullRequestId"]})
                pr = (d.get("convertPullRequestToDraft") or {}).get("pullRequest") or {}
                return TransportResult(True, remote_receipt_id=f"draft:{pr.get('id')}")
            if op_type == "dequeue_pr":
                q = "mutation($id:ID!){dequeuePullRequest(input:{id:$id}){mergeQueueEntry{id}}}"
                d = self._graphql(q, {"id": payload["pullRequestId"]})
                mq = (d.get("dequeuePullRequest") or {}).get("mergeQueueEntry") or {}
                return TransportResult(True, remote_receipt_id=f"deq:{mq.get('id') or payload['pullRequestId']}")
            if op_type == "disable_pr_automerge":
                q = "mutation($id:ID!){disablePullRequestAutoMerge(input:{pullRequestId:$id}){pullRequest{id}}}"
                d = self._graphql(q, {"id": payload["pullRequestId"]})
                pr = (d.get("disablePullRequestAutoMerge") or {}).get("pullRequest") or {}
                return TransportResult(True, remote_receipt_id=f"noam:{pr.get('id')}")
            raise AutopilotError(f"Unsupported single mutation op_type: {op_type}")
        except GraphQLServerRejectedError as gexc:
            proof = _classify_graphql_rejection(gexc)
            return TransportResult(False, unsent_proof=proof, error_detail=str(gexc))
        except subprocess.TimeoutExpired as texc:
            return TransportResult(False, unsent_proof=None, error_detail=f"gh mutation timed out after {texc.timeout}s")
        except Exception as exc:
            return TransportResult(False, unsent_proof=None, error_detail=str(exc))


@dataclass
class FakeGitHubTransport:
    """Deterministic in-memory GitHub transport with hooks for every race/fault-injection test."""

    bot_login: str | None = "autopilot-bot"
    branches: dict[tuple[str, str], str] = field(default_factory=dict)
    prs: dict[str, PrSnapshot] = field(default_factory=dict)
    comments: dict[str, list[str]] = field(default_factory=dict)
    labels: dict[str, set[str]] = field(default_factory=dict)
    classic_rules: list[dict[str, Any]] = field(default_factory=list)
    active_ruleset_mq_includes: list[list[str]] = field(default_factory=list)
    merge_queue_branches: dict[str, bool] = field(default_factory=dict)
    incomplete_pagination: bool = False
    merge_protection_ok: bool = False
    sent_ops_log: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    on_before_push: Any = None
    on_after_push_before_reconcile: Any = None
    fail_op_types_unknown: set[str] = field(default_factory=set)
    fail_op_types_unsent: dict[str, str] = field(default_factory=dict)
    _pr_counter: int = 0

    def get_repository_node_id(self, repo: str) -> str:
        return f"R_{repo.replace('/', '_')}"

    def get_remote_branch_oid(self, repo: str, branch_name: str) -> str | None:
        return self.branches.get((repo, branch_name))

    def push_branch_ephemeral(
        self,
        *,
        repo: str,
        managed_gitdir: Path,
        candidate_sha: str,
        authorized_head_ref: str,
        authorized_base_ref: str,
        expected_old_oid: str | None,
    ) -> TransportResult:
        if authorized_head_ref == authorized_base_ref:
            return TransportResult(False, unsent_proof="refused_push_to_base_ref", error_detail="head==base")
        if callable(self.on_before_push):
            self.on_before_push(self)
        cur_oid = self.branches.get((repo, authorized_head_ref))
        if expected_old_oid is not None and cur_oid != expected_old_oid:
            return TransportResult(
                False,
                unsent_proof="force_with_lease_rejected",
                error_detail=f"remote={cur_oid!r} != expected={expected_old_oid!r}",
            )
        self.sent_ops_log.append(("push_branch", {"branch": authorized_head_ref, "sha": candidate_sha}))
        if "push_branch" in self.fail_op_types_unknown:
            return TransportResult(False, error_detail="simulated network drop")
        self.branches[(repo, authorized_head_ref)] = candidate_sha
        for pid, snap in list(self.prs.items()):
            if snap.head_ref_name == authorized_head_ref and snap.state == "OPEN":
                self.prs[pid] = PrSnapshot(**{**snap.__dict__, "head_ref_oid": candidate_sha})
        if callable(self.on_after_push_before_reconcile):
            self.on_after_push_before_reconcile(self)
        return TransportResult(True, remote_receipt_id=f"push:{candidate_sha}")

    def fetch_pr_snapshot(self, repo: str, pr_id: str, *, snapshot_seq: int = 0) -> PrSnapshot | None:
        snap = self.prs.get(pr_id)
        if snap is None:
            return None
        return PrSnapshot(**{**snap.__dict__, "snapshot_seq": snapshot_seq})

    def find_pr_for_head_or_ref_id(
        self,
        repo: str,
        *,
        authorized_head_ref: str,
        ref_id_hmac: str | None,
        snapshot_seq: int = 0,
    ) -> PrSnapshot | None:
        if not ref_id_hmac:
            return None
        matches: list[PrSnapshot] = []
        for snap in self.prs.values():
            if snap.head_ref_name == authorized_head_ref:
                if not has_exact_ref_id_line(snap.body, ref_id_hmac):
                    continue
                matches.append(PrSnapshot(**{**snap.__dict__, "snapshot_seq": snapshot_seq}))
        return matches[0] if len(matches) == 1 else None

    def has_comment_with_ref_id(self, repo: str, subject_id: str, ref_id_hmac: str) -> bool | None:
        return any(has_exact_ref_id_line(b, ref_id_hmac) for b in self.comments.get(subject_id, []))

    def has_label_on_subject(self, repo: str, subject_id: str, label_name: str) -> bool | None:
        return label_name in self.labels.get(subject_id, set())

    def inspect_branch_protection(
        self,
        repo: str,
        authorized_base_ref: str,
        *,
        for_merge_pr: bool,
        has_separate_merge_token: bool,
    ) -> tuple[bool, str]:
        if for_merge_pr:
            if not has_separate_merge_token or not self.merge_protection_ok:
                return False, "merge_pr protection not satisfied -> cap T2"
            return True, "ok"
        return evaluate_classic_protection_for_enqueue(
            authorized_base_ref=authorized_base_ref,
            rules=self.classic_rules,
            has_incomplete_pagination=self.incomplete_pagination,
            merge_queue_branches=self.merge_queue_branches,
            active_ruleset_mq_includes=self.active_ruleset_mq_includes,
        )

    def send_single_mutation(
        self,
        *,
        repo: str,
        op_type: str,
        payload: dict[str, Any],
        use_merge_token: bool = False,
    ) -> TransportResult:
        if op_type in self.fail_op_types_unsent:
            return TransportResult(
                False,
                unsent_proof=self.fail_op_types_unsent[op_type],
                error_detail=self.fail_op_types_unsent[op_type],
            )
        self.sent_ops_log.append((op_type, dict(payload)))
        if op_type in self.fail_op_types_unknown:
            return TransportResult(False, error_detail=f"simulated timeout on {op_type}")

        if op_type == "create_draft_pr":
            if not payload.get("repositoryId") or payload.get("repositoryId") == "REPO_ID":
                return TransportResult(False, unsent_proof="invalid_repository_id", error_detail="missing repositoryId")
            self._pr_counter += 1
            pid = f"PR_{self._pr_counter}"
            head = payload["headRefName"]
            oid = self.branches.get((repo, head), payload.get("expectedHeadOid", ""))
            self.prs[pid] = PrSnapshot(
                pr_id=pid,
                number=self._pr_counter,
                state="OPEN",
                is_draft=True,
                head_ref_oid=oid,
                head_ref_name=head,
                base_ref_name=payload["baseRefName"],
                body=payload.get("body", ""),
            )
            return TransportResult(True, remote_receipt_id=pid, pr_id=pid, pr_number=self._pr_counter)

        pid = str(payload.get("pullRequestId") or payload.get("subjectId") or payload.get("labelableId") or "")
        if op_type == "post_comment":
            self.comments.setdefault(pid, []).append(str(payload.get("body") or ""))
            return TransportResult(True, remote_receipt_id=f"cmt-{len(self.comments[pid])}")
        if op_type == "add_label":
            self.labels.setdefault(pid, set()).add(str(payload.get("labelName") or "agent"))
            return TransportResult(True, remote_receipt_id="lbl-ack")

        snap = self.prs[pid]
        if op_type in ("enqueue_pr", "merge_pr") and payload.get("expectedHeadOid") != snap.head_ref_oid:
            return TransportResult(False, unsent_proof="expectedHeadOid_mismatch", error_detail="head OID changed")
        if op_type == "mark_pr_ready":
            self.prs[pid] = PrSnapshot(**{**snap.__dict__, "is_draft": False})
            return TransportResult(True, remote_receipt_id=f"rcpt-ready-{pid}")
        if op_type == "convert_pr_to_draft":
            self.prs[pid] = PrSnapshot(**{**snap.__dict__, "is_draft": True})
            return TransportResult(True, remote_receipt_id=f"rcpt-draft-{pid}")
        if op_type == "enqueue_pr":
            if snap.is_draft:
                return TransportResult(False, unsent_proof="cannot_enqueue_draft_pr", error_detail="PR is draft")
            mqid = f"MQE_{pid}"
            prev_ts = tuple(snap.enqueue_event_timestamps or ())
            self.prs[pid] = PrSnapshot(
                **{
                    **snap.__dict__,
                    "merge_queue_entry_id": mqid,
                    "merge_queue_enqueuer": self.bot_login,
                    "merge_queue_enqueued_at": "9999-12-31T00:00:00+00:00",
                    "enqueue_event_timestamps": (*prev_ts, "9999-12-31T00:00:00+00:00"),
                }
            )
            return TransportResult(True, remote_receipt_id=mqid)
        if op_type == "dequeue_pr":
            self.prs[pid] = PrSnapshot(
                **{**snap.__dict__, "merge_queue_entry_id": None, "merge_queue_enqueuer": None}
            )
            return TransportResult(True, remote_receipt_id=f"rcpt-deq-{pid}")
        if op_type == "disable_pr_automerge":
            self.prs[pid] = PrSnapshot(**{**snap.__dict__, "auto_merge_enabled": False})
            return TransportResult(True, remote_receipt_id=f"rcpt-noam-{pid}")
        if op_type == "merge_pr":
            self.prs[pid] = PrSnapshot(**{**snap.__dict__, "state": "MERGED", "merge_queue_entry_id": None})
            return TransportResult(True, remote_receipt_id=f"rcpt-merge-{pid}")
        raise AutopilotError(f"Unknown op_type in FakeGitHubTransport: {op_type}")
