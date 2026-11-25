#!/usr/bin/env python3
"""Comprehensive unit, fault-injection, and live Linux sandbox/systemd tests for agent-autopilot (v7.8)."""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
AP_SCRIPTS = REPO_ROOT / "skills" / "agent-autopilot" / "scripts"
if str(AP_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(AP_SCRIPTS))

from ap_core.chef_loop import ModelTurnResult, execute_chef_issue_pipeline  # noqa: E402
from ap_core.db import AutopilotDB  # noqa: E402
from ap_core.dream import run_dream_consolidation  # noqa: E402
from ap_core.git_gate import (  # noqa: E402
    check_autopilot_scope,
    ensure_managed_bare_repo,
    prepare_isolated_worktree,
    resolve_commit_oid,
    sample_and_gate_worktree,
    scrub_worktree_to_base,
    validate_raw_git_path,
    verify_worktree_clean,
)
from ap_core.github_flow import (  # noqa: E402
    FakeGitHubTransport,
    evaluate_classic_protection_for_enqueue,
    execute_granted_op,
    fetch_pr_unveto_snapshot,
    reconcile_op,
)
from ap_core.models import (  # noqa: E402
    POLICY_MANIFEST,
    AutopilotError,
    PrSnapshot,
    ScopeConflictError,
    ScopeViolationError,
    WorkflowConfig,
    parse_quota_reset,
)
from ap_core.onboard import onboard_project  # noqa: E402
from ap_core.sandbox import (  # noqa: E402
    AllowlistConnectProxyServer,
    ToolExecServer,
    build_execution_ring_bwrap,
    build_model_ring_bwrap,
    expected_transient_cgroup_dir,
    spawn_transient_unit_under_flock,
    verify_native_binaries,
    verify_unit_terminated,
)


def _ensure_compiled_test_binaries() -> tuple[Path, Path]:
    bin_dir = Path.home() / ".cache" / "agent-work" / "auto-issue-fix" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    b_init = bin_dir / "ap-sandbox-init"
    b_sh = bin_dir / "ap-safe-sh"
    if not b_init.is_file() or not b_sh.is_file():
        subprocess.run(
            ["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic", "-std=c11",
             str(REPO_ROOT / "skills/agent-autopilot/native/ap_sandbox_init.c"), "-o", str(b_init)],
            check=True,
        )
        subprocess.run(
            ["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic", "-std=c11",
             str(REPO_ROOT / "skills/agent-autopilot/native/ap_safe_sh.c"), "-o", str(b_sh)],
            check=True,
        )
    return b_init, b_sh


def _init_git_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@local.invalid"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
    (repo_dir / "src").mkdir()
    (repo_dir / "src" / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (repo_dir / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo_dir, check=True)
    return resolve_commit_oid(repo_dir, "HEAD")


class TestPolicyManifestAndGitGates(unittest.TestCase):
    def test_policy_manifest_samples_and_backslash_in_real_git_tree(self) -> None:
        m = POLICY_MANIFEST
        self.assertEqual(m["schema_version"], 16)
        self.assertTrue(m["one_mutation_per_op_id"])
        self.assertEqual(len(m["global_hard_stop_anchored"]), 69)
        self.assertEqual(len(m["global_hard_stop_basenames"]), 36)
        self.assertEqual(len(m["action_transport_map"]), 10)
        self.assertEqual(len(m["external_op_statuses"]), 11)

        # 4/4 invalid raw paths rejected BEFORE check_scope()
        for bad_raw in m["expected_raw_invalid_path_samples"]:
            with self.assertRaises(ScopeViolationError) as ctx:
                validate_raw_git_path(bad_raw)
            self.assertTrue(ctx.exception.violations)

        # 21/21 hard-stop samples blocked (case-insensitive basenames preserve original case in diagnostic!)
        for hs in m["expected_hard_stop_samples"]:
            with self.assertRaises(ScopeViolationError) as ctx:
                check_autopilot_scope([hs], ["**"])
            self.assertIn(hs, ctx.exception.violations[0])

        # 3/3 allow samples pass
        check_autopilot_scope(list(m["expected_allow_samples"]), ["src/**", "apps/server/src/**", "packages/ui/src/**"])

        # Dependency lockfile escalates with is_lockfile=True
        with self.assertRaises(ScopeViolationError) as lock_ctx:
            check_autopilot_scope(["apps/web/package.json"], ["apps/**"])
        self.assertTrue(lock_ctx.exception.is_lockfile)

        # Real Git tree containing literal backslash filename `src\evil.py`, 120000 symlink, and poisoned REPO_MAIN config
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo_main = base / "repo_main"
            base_sha = _init_git_repo(repo_main)

            # Poison REPO_MAIN/.git/config with malicious fsmonitor + smudge filter + pushInsteadOf
            marker = base / "poison_ran"
            with (repo_main / ".git" / "config").open("a", encoding="utf-8") as fh:
                fh.write(
                    f"\n[core]\n\tfsmonitor = touch {marker}\n"
                    f"[filter \"evil\"]\n\tsmudge = touch {marker}\n"
                    "[url \"https://attacker.invalid/\"]\n\tpushInsteadOf = https://github.com/\n"
                )

            mg = ensure_managed_bare_repo(repo_main, base / "managed.git")
            wt, wt_gd = prepare_isolated_worktree(
                managed_gitdir=mg, worktree_dir=base / "wt", wt_name="wt1", base_sha=base_sha
            )

            # Write a literal backslash filename on Linux ext4/tmpfs: `wt / "src\\evil.py"`
            (wt / "src\\evil.py").write_text("print('evil')\n", encoding="utf-8")
            with self.assertRaises(ScopeViolationError) as bs_ctx:
                sample_and_gate_worktree(
                    managed_gitdir=mg,
                    wt_gitdir=wt_gd,
                    worktree=wt,
                    repo_main=repo_main,
                    run_dir=base / "run_bs",
                    base_sha=base_sha,
                    frozen_write_scope=["src/**"],
                )
            self.assertIn("src\\evil.py", bs_ctx.exception.violations[0])
            self.assertFalse(marker.exists(), "Malicious REPO_MAIN/.git/config must NEVER execute!")

            # Clean backslash file, add valid edit + 120000 symlink inside src/, verify CLEAN_TREE OID parity
            (wt / "src\\evil.py").unlink()
            (wt / "src" / "calc.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
            (wt / "src" / "alias.py").symlink_to("calc.py")
            gate = sample_and_gate_worktree(
                managed_gitdir=mg,
                wt_gitdir=wt_gd,
                worktree=wt,
                repo_main=repo_main,
                run_dir=base / "run_ok",
                base_sha=base_sha,
                frozen_write_scope=["src/**"],
            )
            self.assertTrue((gate.clean_tree_dir / "src" / "alias.py").is_symlink())
            self.assertFalse(marker.exists())

            # Tamper with worktree/.git -> caught immediately
            (wt / ".git").write_text("gitdir: /etc\n", encoding="utf-8")
            with self.assertRaises(ScopeViolationError):
                sample_and_gate_worktree(
                    managed_gitdir=mg,
                    wt_gitdir=wt_gd,
                    worktree=wt,
                    repo_main=repo_main,
                    run_dir=base / "run_tamper",
                    base_sha=base_sha,
                    frozen_write_scope=["src/**"],
                )


class TestNativeBinariesBwrapAndSystemdLive(unittest.TestCase):
    def test_c_binaries_bwrap_rings_and_systemd_transient_lifecycle(self) -> None:
        b_init, b_sh = _ensure_compiled_test_binaries()
        verify_native_binaries(b_init, b_sh)

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            wt = base / "wt"
            wt.mkdir()
            (wt / ".git").write_text("gitdir: /nonexistent\n", encoding="utf-8")
            tool_sock = base / "tool.sock"
            srv = ToolExecServer(tool_sock, wt)
            srv.start()
            try:
                env = dict(os.environ)
                env["AP_TOOL_SOCK"] = str(tool_sock)

                # 1. Early child exit (exit 0) with 512 KiB unread stdin -> returns 0 cleanly
                big_stdin = b"x" * (512 * 1024)
                p_early = subprocess.run(
                    [str(b_sh), "-c", "exit 0"],
                    input=big_stdin,
                    cwd=str(wt),
                    env=env,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(p_early.returncode, 0)

                # 2. Silent broken pipe (stdout reader closes while child sleeps silently) -> exits 141 + killpg!
                r_fd, w_fd = os.pipe()
                proc_pipe = subprocess.Popen(
                    [str(b_sh), "-c", "sleep 30"],
                    cwd=str(wt),
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=w_fd,
                    stderr=subprocess.DEVNULL,
                )
                os.close(w_fd)
                time.sleep(0.15)
                os.close(r_fd)  # Break pipe while child produces ZERO output!
                rc_pipe = proc_pipe.wait(timeout=5)
                self.assertEqual(rc_pipe, 141)
                time.sleep(0.1)
                self.assertGreaterEqual(len(srv.killed_pgids), 1)

                # 3. Live bwrap model_ring + Landlock exec enforcement + CONNECT domain allowlist proxy
                proxy_sock = base / "proxy.sock"
                proxy = AllowlistConnectProxyServer(proxy_sock, allowed_domains={"api.openai.com"})
                proxy.start()
                try:
                    # Test proxy directly: evil.example.com:443 -> 403 Forbidden
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as cs:
                        cs.connect(str(proxy_sock))
                        cs.sendall(b"CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
                        resp = cs.recv(1024)
                    self.assertIn(b"403 Forbidden", resp)

                    # Build codex:issue_model bwrap using `/bin/echo` or static `b_sh` as fake codex_cli
                    # Verify `/usr/bin/bash` inside model_ring is `ap-safe-sh`, `.git` is read-only, and Landlock blocks rogue binary!
                    rogue = wt / "rogue_bin"
                    shutil.copyfile(b_sh, rogue)
                    os.chmod(rogue, 0o755)
                    argv = build_model_ring_bwrap(
                        role_key="codex:issue_model",
                        host_binaries={
                            "ap_sandbox_init": b_init,
                            "ap_safe_sh": b_sh,
                            "codex_cli": b_sh,  # Static binary acting as codex_cli to execute shell test inside model_ring
                        },
                        sandbox_home=base / "sb_home",
                        outbox_dir=base / "outbox",
                        proxy_sock=proxy_sock,
                        inner_cmd=["/usr/local/bin/codex", "-c", "echo HELLO_FROM_SAFE_SH"],
                        worktree=wt,
                        shared_tmp=base / "shared_tmp",
                        shell_snapshots=base / "snaps",
                        tool_sock=tool_sock,
                    )
                    res_ring = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
                    self.assertEqual(res_ring.returncode, 0, msg=res_ring.stderr)
                    self.assertIn("HELLO_FROM_SAFE_SH", res_ring.stdout)
                finally:
                    proxy.close()

                # 4. verify_ring isolation: ephemeral_tool_cache is NOT mounted in verify_ring
                clean_tree = base / "clean_tree"
                clean_tree.mkdir()
                (clean_tree / "ok.txt").write_text("clean\n", encoding="utf-8")
                verify_out = base / "verify_out"
                v_argv = build_execution_ring_bwrap(
                    ring_kind="verify_ring",
                    inner_cmd=["/bin/bash", "-c", "test ! -e /ap-tool-cache && test -f ok.txt"],
                    cwd=verify_out,
                    clean_tree=clean_tree,
                    verify_out_dir=verify_out,
                )
                v_res = subprocess.run(v_argv, capture_output=True, text=True, timeout=15, check=False)
                self.assertEqual(v_res.returncode, 0, msg=v_res.stderr)
            finally:
                srv.close()

            # 5. Live systemd transient unit + pass_fds lock non-leak + 4-phase gitignored __pycache__ lease retention
            repo_main = base / "repo_sd"
            base_sha = _init_git_repo(repo_main)
            mg = ensure_managed_bare_repo(repo_main, base / "mg_sd.git")
            wt_sd, wt_gd_sd = prepare_isolated_worktree(
                managed_gitdir=mg, worktree_dir=base / "wt_sd", wt_name="wt_sd", base_sha=base_sha
            )
            db = AutopilotDB(base / "sd.db")
            try:
                cfg = WorkflowConfig(
                    project_id="proj-sd",
                    kind="issue",
                    enabled=True,
                    repos=("org/repo",),
                    workspace_path=str(repo_main),
                    write_scope=("src/**",),
                )
                db.upsert_project(cfg)
                db.ensure_work_unit(unit_key="org/repo#1", project_id="proj-sd", repo="org/repo", issue_number=1)
                db.ensure_lease_slots("proj-sd", ["proj-sd:slot-1"], base / "locks")

                flock_p = base / "locks" / "proj-sd_slot-1.flock"
                lfd = os.open(str(flock_p), os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(lfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                uname = f"ap-test-unit-{os.getpid()}.service"
                exp_cg = expected_transient_cgroup_dir(uname)
                try:
                    ce = db.claim_and_reserve(
                        unit_key="org/repo#1",
                        cfg=cfg,
                        slot_keys=["proj-sd:slot-1"],
                        worker_unit_name=uname,
                        expected_cgroup_dir=str(exp_cg),
                        base_sha=base_sha,
                        authorized_head_ref="agent/issue-1",
                    )
                    sd_proc = spawn_transient_unit_under_flock(
                        unit_name=uname,
                        cmd=["/bin/sh", "-c", "exit 7"],
                        flock_fd=lfd,
                        wait=True,
                    )
                    self.assertEqual(sd_proc.returncode, 7)
                    self.assertTrue(verify_unit_terminated(uname, exp_cg))
                finally:
                    fcntl.flock(lfd, fcntl.LOCK_UN)
                    os.close(lfd)

                # Plant gitignored __pycache__/dirty.pyc -> verify_worktree_clean is False, lease MUST stay 'reclaiming'!
                pycache = wt_sd / "__pycache__"
                pycache.mkdir()
                (pycache / "dirty.pyc").write_bytes(b"\x00\x01")
                self.assertFalse(verify_worktree_clean(managed_gitdir=mg, wt_gitdir=wt_gd_sd, worktree=wt_sd))
                db.begin_reclaim_claim(ce)
                freed = db.finish_reclaim_leases_free(
                    ce, cleanup_rc=0, unit_terminated=True, worktree_clean=False
                )
                self.assertFalse(freed)
                lstate = db._conn.execute("SELECT state FROM leases WHERE slot_key = 'proj-sd:slot-1'").fetchone()["state"]
                self.assertEqual(lstate, "reclaiming")

                # Scrub worktree -> cleans __pycache__, lease transitions to 'free'
                rc_scrub = scrub_worktree_to_base(managed_gitdir=mg, wt_gitdir=wt_gd_sd, worktree=wt_sd, base_sha=base_sha)
                self.assertEqual(rc_scrub, 0)
                self.assertTrue(db.finish_reclaim_leases_free(ce, cleanup_rc=0, unit_terminated=True, worktree_clean=True))
                lstate2 = db._conn.execute("SELECT state FROM leases WHERE slot_key = 'proj-sd:slot-1'").fetchone()["state"]
                self.assertEqual(lstate2, "free")
            finally:
                db.close()


class TestTransactionalStateMachineAndReconciliation(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.db = AutopilotDB(self.base / "state.db")
        self.cfg = WorkflowConfig(
            project_id="p1",
            kind="issue",
            enabled=True,
            repos=("org/app",),
            workspace_path=str(self.base),
            authorized_base_ref="main",
            branch_prefix="agent/",
            trust_tier="T3",
            max_in_progress=2,
            write_scope=("src/**",),
            merge_paths=("src/**",),
        )
        self.db.upsert_project(self.cfg)
        with self.db.immediate_tx():
            self.db._conn.execute("UPDATE projects SET max_in_progress = 2 WHERE project_id = 'p1'")
        self.db.ensure_lease_slots("p1", ["s1", "s2"], self.base / "locks")

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def _seed_receipts(self, unit_key: str, cand: str, *, touched: tuple[str, ...] = ("src/calc.py",), pr_id: str | None = None, seed_ready: bool = False) -> None:
        self.db.record_verify_receipt(
            unit_key=unit_key, candidate_sha=cand, dod_cmd="pytest", exit_code=0,
            ui_verified=False, artifact_dir="/tmp", touched_paths=touched,
        )
        self.db.record_review_receipt(
            unit_key=unit_key,
            candidate_sha=cand,
            writer_family="codex",
            referee_family="claude",
            referee_model="claude-fable-5-2",
            verdict="APPROVE",
            defect_count=0,
            defects=[],
            raw_path="/tmp/r.json",
        )
        if seed_ready and pr_id:
            with self.db.immediate_tx():
                seq = self.db._next_counter_in_tx("op_seq")
                self.db._conn.execute(
                    """
                    INSERT INTO external_ops(op_id, op_seq, unit_key, pr_id, op_type, owner_kind, owner_epoch, candidate_sha, status, remote_receipt_id, prepared_at, updated_at)
                    VALUES (?, ?, ?, ?, 'mark_pr_ready', 'worker', 1, ?, 'succeeded_verified', 'rcpt-seed', '2026-01-01', '2026-01-01')
                    """,
                    (f"seed-ready-{unit_key}-{cand[:6]}-{seq}", seq, unit_key, pr_id, cand),
                )

    def test_five_entrypoints_shared_pr_scope_and_pr_conflict_and_single_sendgrant(self) -> None:
        self.db.ensure_work_unit(unit_key="A", project_id="p1", repo="org/app", issue_number=1, pr_id="PR_SHARED")
        self.db.ensure_work_unit(unit_key="B", project_id="p1", repo="org/app", issue_number=2, pr_id="PR_SHARED")

        # Conflicting non-null pr_id -> ScopeConflictError immediately!
        with self.assertRaises(ScopeConflictError):
            self.db.resolve_unit_scope_and_pending("A", pr_id="PR_OTHER")

        # Claim both A and B while clean
        ce_b = self.db.claim_and_reserve(
            unit_key="B",
            cfg=self.cfg,
            slot_keys=["s2"],
            worker_unit_name="u-b.service",
            expected_cgroup_dir="/cg/b",
            base_sha="1111111",
            authorized_head_ref="agent/b",
            bound_gh_login="autopilot-bot",
            ephemeral_token_file="/tmp/ap-test.tok",
        )
        ce_a = self.db.claim_and_reserve(
            unit_key="A",
            cfg=self.cfg,
            slot_keys=["s1"],
            worker_unit_name="u-a.service",
            expected_cgroup_dir="/cg/a",
            base_sha="1111111",
            authorized_head_ref="agent/a",
            bound_gh_login="autopilot-bot",
            ephemeral_token_file="/tmp/ap-test.tok",
        )
        self.db.set_current_candidate(unit_key="A", candidate_sha="aaaaaaa111", claim_epoch=ce_a)
        self._seed_receipts("A", "aaaaaaa111")

        # When ONLY A has its own worker prepared_local, set_current_candidate(A) aborts it and switches cleanly!
        op_a_self = self.db.prepare_op(unit_key="A", op_type="post_comment", claim_epoch=ce_a)
        self.db.set_current_candidate(unit_key="A", candidate_sha="aaaaaaa222", claim_epoch=ce_a)
        self.assertEqual(self.db.get_op(op_a_self)["status"], "aborted_pre_send")
        self._seed_receipts("A", "aaaaaaa222")

        # Prepare an op on A so we can test promote_op_to_in_flight(A) once B adds a pending op
        op_a_ready = self.db.prepare_op(unit_key="A", op_type="post_comment", claim_epoch=ce_a)

        # Concurrent promote_op_to_in_flight on op_a_ready -> EXACTLY ONE caller gets SendGrant(granted=True)!
        grants = []
        bar = threading.Barrier(2)

        def _try_promote() -> None:
            bar.wait()
            grants.append(self.db.promote_op_to_in_flight(op_a_ready, caller_owner_kind="worker", caller_epoch=ce_a))

        t1 = threading.Thread(target=_try_promote)
        t2 = threading.Thread(target=_try_promote)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        self.assertEqual(sum(1 for g in grants if g.granted), 1)
        self.db.complete_op_status(op_a_ready, expected_current_statuses=("in_flight",), new_status="succeeded_verified")

        # Now insert a `pr_id IS NULL` worker `prepared_local` on sibling B!
        op_a_next = self.db.prepare_op(unit_key="A", op_type="post_comment", claim_epoch=ce_a)
        with self.db.immediate_tx():
            seq = self.db._next_counter_in_tx("op_seq")
            self.db._conn.execute(
                """
                INSERT INTO external_ops(op_id, op_seq, unit_key, pr_id, op_type, owner_kind, owner_epoch, claim_epoch, status, prepared_at, updated_at)
                VALUES ('op-b-nullpr', ?, 'B', NULL, 'post_comment', 'worker', ?, ?, 'prepared_local', '2026-01-01', '2026-01-01')
                """,
                (seq, ce_b, ce_b),
            )

        # Verify ALL 5 entrypoints on A are blocked by B's `pr_id IS NULL` pending op (under both veto=0 and veto=1)!
        for veto_flag in (0, 1):
            with self.db.immediate_tx():
                self.db._conn.execute("UPDATE work_units SET veto_pending = ? WHERE unit_key IN ('A', 'B')", (veto_flag,))
            # 1) set_current_candidate(A)
            with self.assertRaises(AutopilotError):
                self.db.set_current_candidate(unit_key="A", candidate_sha="aaaaaaa333", claim_epoch=ce_a)
            # 2) prepare_op(A)
            with self.assertRaises(AutopilotError):
                self.db.prepare_op(unit_key="A", op_type="add_label", claim_epoch=ce_a)
            # 3) promote_op_to_in_flight(A)
            g_blocked = self.db.promote_op_to_in_flight(op_a_next, caller_owner_kind="worker", caller_epoch=ce_a)
            self.assertFalse(g_blocked.granted)
            # 4) clear_veto_and_resume(A)
            snap_ok = PrSnapshot(
                pr_id="PR_SHARED", state="OPEN", is_draft=True, head_ref_oid="aaaaaaa222",
                head_ref_name="agent/a", base_ref_name="main", snapshot_seq=999999,
            )
            with self.assertRaises(AutopilotError):
                self.db.clear_veto_and_resume("A", pr_snapshot=snap_ok)
            # 5) claim_and_reserve(C sharing PR_SHARED)
            self.db.ensure_work_unit(unit_key="C", project_id="p1", repo="org/app", issue_number=3, pr_id="PR_SHARED")
            self.db.ensure_lease_slots("p1", ["s3"], self.base / "locks")
            with self.assertRaises(AutopilotError):
                self.db.claim_and_reserve(
                    unit_key="C", cfg=self.cfg, slot_keys=["s3"], worker_unit_name="u-c.service",
                    expected_cgroup_dir="/cg/c", base_sha="1111111", authorized_head_ref="agent/c",
                )

    def test_mark_pr_ready_third_party_race_and_drift_retains_unknown_paused_lock(self) -> None:
        tr = FakeGitHubTransport()
        tr.prs["PR_1"] = PrSnapshot(
            pr_id="PR_1", state="OPEN", is_draft=False, head_ref_oid="cand111",
            head_ref_name="agent/1", base_ref_name="main",
        )
        self.db.ensure_work_unit(unit_key="U1", project_id="p1", repo="org/app", issue_number=1, pr_id="PR_1")
        ce = self.db.claim_and_reserve(
            unit_key="U1", cfg=self.cfg, slot_keys=["s1"], worker_unit_name="u1.service",
            expected_cgroup_dir="/cg/1", base_sha="0000000", authorized_head_ref="agent/1",
            bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
        )
        self.db.set_current_candidate(unit_key="U1", candidate_sha="cand111", claim_epoch=ce)
        self._seed_receipts("U1", "cand111")
        op_r = self.db.prepare_op(unit_key="U1", op_type="mark_pr_ready", claim_epoch=ce, candidate_sha="cand111")
        g = self.db.promote_op_to_in_flight(op_r, caller_owner_kind="worker", caller_epoch=ce)
        self.assertTrue(g.granted)
        # Simulate sender entered execute_granted_op (consumed grant before socket write) and crashed mid-flight:
        self.assertTrue(self.db.consume_send_grant(g))

        # Sender NOT terminated -> reconciler must keep in_flight
        r_alive = reconcile_op(db=self.db, transport=tr, repo="org/app", op_id=op_r, sender_confirmed_terminated=False, dispatcher_epoch=1)
        self.assertEqual(r_alive["status"], "in_flight")

        # Case 1: Sender terminated WITHOUT receipt, maintainer already marked PR Ready -> MUST stay unknown_paused!
        r_no_rcpt = reconcile_op(db=self.db, transport=tr, repo="org/app", op_id=op_r, sender_confirmed_terminated=True, dispatcher_epoch=1)
        self.assertEqual(r_no_rcpt["status"], "unknown_paused")

        # Case 2: Maintainer ALSO pushes new commit (`headRefOid != cand111`) while still OPEN without receipt ->
        # MUST escalate unit to needs-human AND STILL retain `unknown_paused` (never exiting 3-state lock!)
        tr.prs["PR_1"] = PrSnapshot(**{**tr.prs["PR_1"].__dict__, "head_ref_oid": "drifted999"})
        r_drift = reconcile_op(db=self.db, transport=tr, repo="org/app", op_id=op_r, sender_confirmed_terminated=True, dispatcher_epoch=1)
        self.assertEqual(r_drift["status"], "unknown_paused")
        self.assertEqual(self.db.get_unit("U1")["terminal_state"], "needs-human")
        self.assertEqual(self.db.resolve_unit_scope_and_pending("U1").pending_cnt, 1)

        # Supervisor registers convert_pr_to_draft -> pulls PR back to Draft, yet scope lock REMAINS held because mark_pr_ready is unknown_paused!
        ep = self.db.bump_dispatcher_epoch()
        adm_ids = self.db.register_admin_revoke(unit_key="U1", dispatcher_epoch=ep, pr_id="PR_1", need_draft=True)
        g_adm = self.db.promote_op_to_in_flight(
            adm_ids[0], caller_owner_kind="supervisor_admin", caller_epoch=ep,
            dispatcher_lock_held=True, all_scope_workers_terminated=True,
        )
        self.assertTrue(g_adm.granted)
        adm_res = execute_granted_op(grant=g_adm, db=self.db, transport=tr, repo="org/app")
        self.assertEqual(adm_res["status"], "unknown_paused")
        with self.assertRaises(AutopilotError):
            self.db.clear_veto_and_resume("U1", pr_snapshot=fetch_pr_unveto_snapshot(tr, self.db, "org/app", "PR_1"))

    def test_admin_epoch_takeover_partial_success_and_all_presend_postsend_races(self) -> None:
        tr = FakeGitHubTransport()
        repo_main = self.base / "repo_race"
        base_sha = _init_git_repo(repo_main)
        mg = ensure_managed_bare_repo(repo_main, self.base / "mg_race.git")
        wt, wt_gd = prepare_isolated_worktree(
            managed_gitdir=mg, worktree_dir=self.base / "wt_race", wt_name="wt_r", base_sha=base_sha
        )
        (wt / "src" / "calc.py").write_text("def add(a, b):\n    return int(a) + int(b)\n", encoding="utf-8")
        gate = sample_and_gate_worktree(
            managed_gitdir=mg, wt_gitdir=wt_gd, worktree=wt, repo_main=repo_main,
            run_dir=self.base / "run_r1", base_sha=base_sha, frozen_write_scope=["src/**"],
        )
        cand = gate.candidate_sha
        tr.branches[("org/app", "agent/2")] = base_sha
        tr.prs["PR_2"] = PrSnapshot(
            pr_id="PR_2", state="OPEN", is_draft=False, head_ref_oid=base_sha,
            head_ref_name="agent/2", base_ref_name="main",
            merge_queue_entry_id="MQ_1", auto_merge_enabled=True,
        )
        self.db.ensure_work_unit(unit_key="U2", project_id="p1", repo="org/app", issue_number=2, pr_id="PR_2")

        # 1. Epoch 1 supervisor registers all 3 single-mutation admin ops, then crashes BEFORE promoting!
        ep1 = self.db.bump_dispatcher_epoch()
        adm_e1 = self.db.register_admin_revoke(
            unit_key="U2", dispatcher_epoch=ep1, pr_id="PR_2",
            need_dequeue=True, need_disable_automerge=True, need_draft=True,
        )
        self.assertEqual(len(adm_e1), 3)

        # Epoch 2 supervisor takes over -> retires all 3 `prepared_local` rows to `superseded_by_retry` (0 sends!)
        ep2 = self.db.bump_dispatcher_epoch()
        adm_e2 = [
            self.db.replace_admin_op_for_retry(old_op_id=oid, new_dispatcher_epoch=ep2, dispatcher_lock_held=True)
            for oid in adm_e1
        ]
        for old_id in adm_e1:
            self.assertEqual(self.db.get_op(old_id)["status"], "superseded_by_retry")
        self.assertEqual(len(tr.sent_ops_log), 0)

        # 2. Simulate PARTIAL SUCCESS: dequeue_pr succeeds, disable_pr_automerge fails unknown -> lock retained!
        tr.fail_op_types_unknown.add("disable_pr_automerge")
        g_deq = self.db.promote_op_to_in_flight(
            adm_e2[0], caller_owner_kind="supervisor_admin", caller_epoch=ep2,
            dispatcher_lock_held=True, all_scope_workers_terminated=True,
        )
        res_deq = execute_granted_op(grant=g_deq, db=self.db, transport=tr, repo="org/app")
        self.assertEqual(res_deq["status"], "succeeded_verified")

        g_noam = self.db.promote_op_to_in_flight(
            adm_e2[1], caller_owner_kind="supervisor_admin", caller_epoch=ep2,
            dispatcher_lock_held=True, all_scope_workers_terminated=True,
        )
        res_noam = execute_granted_op(grant=g_noam, db=self.db, transport=tr, repo="org/app")
        self.assertEqual(res_noam["status"], "unknown_paused")
        self.assertGreaterEqual(self.db.resolve_unit_scope_and_pending("U2").pending_cnt, 1)
        with self.assertRaises(AutopilotError):
            self.db.clear_veto_and_resume("U2", pr_snapshot=fetch_pr_unveto_snapshot(tr, self.db, "org/app", "PR_2"))

        # Resolve unknown_paused via operator unsent_proof + retry, and finish convert_pr_to_draft
        tr.fail_op_types_unknown.clear()
        ep3 = self.db.bump_dispatcher_epoch()
        self.db.record_op_receipt(adm_e2[1], unsent_proof="operator_verified_dropped_before_tls")
        retry_noam = self.db.replace_admin_op_for_retry(old_op_id=adm_e2[1], new_dispatcher_epoch=ep3, dispatcher_lock_held=True)
        retry_draft = self.db.replace_admin_op_for_retry(old_op_id=adm_e2[2], new_dispatcher_epoch=ep3, dispatcher_lock_held=True)
        for oid in (retry_noam, retry_draft):
            g_x = self.db.promote_op_to_in_flight(
                oid, caller_owner_kind="supervisor_admin", caller_epoch=ep3,
                dispatcher_lock_held=True, all_scope_workers_terminated=True,
            )
            self.assertEqual(execute_granted_op(grant=g_x, db=self.db, transport=tr, repo="org/app")["status"], "succeeded_verified")

        # 3. Third party re-enqueues BEFORE unveto snapshot (local pending_cnt == 0, but remote mergeQueueEntry != None) -> REJECTED!
        self.assertEqual(self.db.resolve_unit_scope_and_pending("U2").pending_cnt, 0)
        tr.prs["PR_2"] = PrSnapshot(**{**tr.prs["PR_2"].__dict__, "is_draft": False, "merge_queue_entry_id": "MQ_RE"})
        with self.assertRaises(AutopilotError):
            self.db.clear_veto_and_resume("U2", pr_snapshot=fetch_pr_unveto_snapshot(tr, self.db, "org/app", "PR_2"))
        self.assertEqual(self.db.get_unit("U2")["veto_pending"], 1)

        # Restore quiescence -> clear_veto_and_resume succeeds!
        tr.prs["PR_2"] = PrSnapshot(**{**tr.prs["PR_2"].__dict__, "is_draft": True, "merge_queue_entry_id": None})
        self.db.clear_veto_and_resume("U2", pr_snapshot=fetch_pr_unveto_snapshot(tr, self.db, "org/app", "PR_2"))
        self.assertEqual(self.db.get_unit("U2")["veto_pending"], 0)

        # 4. Standalone Ready-only flip AFTER unveto (not queued, no automerge, head unchanged) ->
        # next worker pre-send re-read catches `isDraft != True`, aborts with 0 remote writes + needs-human!
        ce2 = self.db.claim_and_reserve(
            unit_key="U2", cfg=self.cfg, slot_keys=["s1"], worker_unit_name="u2.service",
            expected_cgroup_dir="/cg/2", base_sha=base_sha, authorized_head_ref="agent/2",
            bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
        )
        self.db.set_current_candidate(unit_key="U2", candidate_sha=cand, claim_epoch=ce2)
        self._seed_receipts("U2", cand)
        tr.sent_ops_log.clear()
        tr.prs["PR_2"] = PrSnapshot(**{**tr.prs["PR_2"].__dict__, "is_draft": False})
        op_p1 = self.db.prepare_op(unit_key="U2", op_type="push_branch", claim_epoch=ce2, candidate_sha=cand, payload={"expected_old_oid": base_sha})
        g_p1 = self.db.promote_op_to_in_flight(op_p1, caller_owner_kind="worker", caller_epoch=ce2)
        with self.assertRaises(AutopilotError):
            execute_granted_op(grant=g_p1, db=self.db, transport=tr, repo="org/app", managed_gitdir=mg)
        self.assertEqual(len(tr.sent_ops_log), 0, "Pre-send Ready-only conflict MUST perform 0 remote writes!")
        self.assertEqual(self.db.get_unit("U2")["terminal_state"], "needs-human")

        # 5. Post-re-read OID drift rejected by `--force-with-lease`!
        tr.prs["PR_2"] = PrSnapshot(**{**tr.prs["PR_2"].__dict__, "is_draft": True})
        with self.db.immediate_tx():
            self.db._conn.execute("UPDATE work_units SET terminal_state = NULL, status = 'running' WHERE unit_key = 'U2'")
        tr.on_before_push = lambda t: t.branches.__setitem__(("org/app", "agent/2"), "other_remote_sha")
        op_p2 = self.db.prepare_op(unit_key="U2", op_type="push_branch", claim_epoch=ce2, candidate_sha=cand, payload={"expected_old_oid": base_sha})
        g_p2 = self.db.promote_op_to_in_flight(op_p2, caller_owner_kind="worker", caller_epoch=ce2)
        res_lease = execute_granted_op(grant=g_p2, db=self.db, transport=tr, repo="org/app", managed_gitdir=mg)
        self.assertEqual(res_lease["status"], "not_executed")
        self.assertEqual(tr.branches[("org/app", "agent/2")], "other_remote_sha")
        self.assertEqual(self.db.get_unit("U2")["terminal_state"], "needs-human")

        # 6. Post-re-read Ready-only race during push_branch: BOTH normal return AND crash-before-postcheck!
        for crash_mode in (False, True):
            tr.branches[("org/app", "agent/2")] = base_sha
            tr.prs["PR_2"] = PrSnapshot(
                pr_id="PR_2", state="OPEN", is_draft=True, head_ref_oid=base_sha,
                head_ref_name="agent/2", base_ref_name="main",
            )
            with self.db.immediate_tx():
                self.db._conn.execute("DELETE FROM external_ops WHERE unit_key = 'U2'")
                self.db._conn.execute("UPDATE work_units SET veto_pending = 0, terminal_state = NULL, status = 'running', last_confirmed_head_oid = NULL WHERE unit_key = 'U2'")
            tr.on_before_push = lambda t: t.prs.__setitem__(
                "PR_2", PrSnapshot(**{**t.prs["PR_2"].__dict__, "is_draft": False})
            )
            op_px = self.db.prepare_op(unit_key="U2", op_type="push_branch", claim_epoch=ce2, candidate_sha=cand, payload={"expected_old_oid": base_sha})
            g_px = self.db.promote_op_to_in_flight(op_px, caller_owner_kind="worker", caller_epoch=ce2)
            if not crash_mode:
                r_px = execute_granted_op(grant=g_px, db=self.db, transport=tr, repo="org/app", managed_gitdir=mg)
            else:
                with self.assertRaises(RuntimeError):
                    execute_granted_op(
                        grant=g_px, db=self.db, transport=tr, repo="org/app",
                        managed_gitdir=mg, simulate_crash_after_send=True,
                    )
                r_px = reconcile_op(
                    db=self.db, transport=tr, repo="org/app", op_id=op_px,
                    sender_confirmed_terminated=True, dispatcher_epoch=self.db.get_dispatcher_epoch(),
                )
            self.assertEqual(r_px["status"], "succeeded_verified")
            self.assertEqual(self.db.get_unit("U2")["veto_pending"], 1)
            self.assertEqual(self.db.get_unit("U2")["terminal_state"], "needs-human")
            adm_ops = [o for o in self.db.list_ops_for_scope("U2") if o["owner_kind"] == "supervisor_admin"]
            self.assertEqual([o["op_type"] for o in adm_ops], ["convert_pr_to_draft"])
        tr.on_before_push = None

        # 7. push_branch baseRefName-only drift while still Draft -> settles push_branch, sets veto+needs-human, 0 convert_pr_to_draft!
        with self.db.immediate_tx():
            self.db._conn.execute("DELETE FROM external_ops WHERE unit_key = 'U2'")
            self.db._conn.execute("UPDATE work_units SET veto_pending = 0, terminal_state = NULL, status = 'running', last_confirmed_head_oid = NULL WHERE unit_key = 'U2'")
        tr.branches[("org/app", "agent/2")] = cand
        tr.prs["PR_2"] = PrSnapshot(
            pr_id="PR_2", state="OPEN", is_draft=True, head_ref_oid=cand,
            head_ref_name="agent/2", base_ref_name="develop",
        )
        op_pb = self.db.prepare_op(unit_key="U2", op_type="push_branch", claim_epoch=ce2, candidate_sha=cand)
        g_pb = self.db.promote_op_to_in_flight(op_pb, caller_owner_kind="worker", caller_epoch=ce2)
        self.db.consume_send_grant(g_pb)
        r_pb = reconcile_op(
            db=self.db, transport=tr, repo="org/app", op_id=op_pb,
            sender_confirmed_terminated=True, dispatcher_epoch=self.db.get_dispatcher_epoch(),
        )
        self.assertEqual(r_pb["status"], "succeeded_verified")
        self.assertEqual(self.db.get_unit("U2")["veto_pending"], 1)
        self.assertEqual([o for o in self.db.list_ops_for_scope("U2") if o["owner_kind"] == "supervisor_admin"], [])

        # 8. create_draft_pr baseRefName drift (found without baseRefName filter -> diverged_needs_human + veto=1)
        # AND create_draft_pr Ready + queued + automerge -> 3 independent single-mutation op_ids!
        self.db.ensure_work_unit(unit_key="U3", project_id="p1", repo="org/app", issue_number=3)
        ce3 = self.db.claim_and_reserve(
            unit_key="U3", cfg=self.cfg, slot_keys=["s2"], worker_unit_name="u3.service",
            expected_cgroup_dir="/cg/3", base_sha=base_sha, authorized_head_ref="agent/3",
            bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
        )
        self.db.set_current_candidate(unit_key="U3", candidate_sha=cand, claim_epoch=ce3)
        self._seed_receipts("U3", cand)
        op_cd1 = self.db.prepare_op(unit_key="U3", op_type="create_draft_pr", claim_epoch=ce3, candidate_sha=cand, ref_id_hmac="ap-ref3")
        g_cd1 = self.db.promote_op_to_in_flight(op_cd1, caller_owner_kind="worker", caller_epoch=ce3)
        self.db.consume_send_grant(g_cd1)
        tr.prs["PR_3"] = PrSnapshot(
            pr_id="PR_3", state="OPEN", is_draft=True, head_ref_oid=cand,
            head_ref_name="agent/3", base_ref_name="wrong-base", body="Ref-ID: ap-ref3",
        )
        r_cd1 = reconcile_op(
            db=self.db, transport=tr, repo="org/app", op_id=op_cd1,
            sender_confirmed_terminated=True, dispatcher_epoch=self.db.get_dispatcher_epoch(),
        )
        self.assertEqual(r_cd1["status"], "diverged_needs_human")
        self.assertEqual(self.db.get_unit("U3")["pr_id"], "PR_3")
        self.assertEqual(self.db.get_unit("U3")["veto_pending"], 1)

        with self.db.immediate_tx():
            self.db._conn.execute("DELETE FROM external_ops WHERE unit_key = 'U3'")
            self.db._conn.execute("UPDATE work_units SET veto_pending = 0, terminal_state = NULL, status = 'running' WHERE unit_key = 'U3'")
        op_cd2 = self.db.prepare_op(unit_key="U3", op_type="create_draft_pr", claim_epoch=ce3, candidate_sha=cand, ref_id_hmac="ap-ref3")
        g_cd2 = self.db.promote_op_to_in_flight(op_cd2, caller_owner_kind="worker", caller_epoch=ce3)
        self.db.consume_send_grant(g_cd2)
        tr.prs["PR_3"] = PrSnapshot(
            pr_id="PR_3", state="OPEN", is_draft=False, head_ref_oid=cand,
            head_ref_name="agent/3", base_ref_name="main",
            merge_queue_entry_id="MQ_3", auto_merge_enabled=True, body="Ref-ID: ap-ref3",
        )
        r_cd2 = reconcile_op(
            db=self.db, transport=tr, repo="org/app", op_id=op_cd2,
            sender_confirmed_terminated=True, dispatcher_epoch=self.db.get_dispatcher_epoch(),
        )
        self.assertEqual(r_cd2["status"], "succeeded_verified")
        adm3 = [o["op_type"] for o in self.db.list_ops_for_scope("U3") if o["owner_kind"] == "supervisor_admin"]
        self.assertEqual(adm3, ["dequeue_pr", "disable_pr_automerge", "convert_pr_to_draft"])

    def test_enqueue_attribution_and_classic_protection_wildcard_t2_cap(self) -> None:
        # Classic wildcard BranchProtectionRule -> immediately caps at T2!
        ok_wild, _ = evaluate_classic_protection_for_enqueue(
            authorized_base_ref="main",
            rules=[{"pattern": "release/*"}],
            has_incomplete_pagination=False,
            merge_queue_branches={"main": True},
        )
        self.assertFalse(ok_wild)

        ok_lit, _ = evaluate_classic_protection_for_enqueue(
            authorized_base_ref="main",
            rules=[{"pattern": "main"}, {"pattern": "staging"}],
            has_incomplete_pagination=False,
            merge_queue_branches={"main": True, "staging": False},
        )
        self.assertTrue(ok_lit)

        # MERGED PR without persisted remote_receipt_id -> superseded_by_pr_merge (never succeeded_verified!)
        tr = FakeGitHubTransport()
        tr.prs["PR_M"] = PrSnapshot(
            pr_id="PR_M", state="MERGED", is_draft=False, head_ref_oid="candM1234567",
            head_ref_name="agent/m", base_ref_name="main",
        )
        self.db.ensure_work_unit(unit_key="UM", project_id="p1", repo="org/app", issue_number=9, pr_id="PR_M")
        ce = self.db.claim_and_reserve(
            unit_key="UM", cfg=self.cfg, slot_keys=["s1"], worker_unit_name="um.service",
            expected_cgroup_dir="/cg/m", base_sha="0000000", authorized_head_ref="agent/m",
            bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
        )
        self.db.set_current_candidate(unit_key="UM", candidate_sha="candM1234567", claim_epoch=ce)
        self._seed_receipts("UM", "candM1234567", pr_id="PR_M", seed_ready=True)
        op_eq1 = self.db.prepare_op(unit_key="UM", op_type="enqueue_pr", claim_epoch=ce, candidate_sha="candM1234567")
        g_eq1 = self.db.promote_op_to_in_flight(op_eq1, caller_owner_kind="worker", caller_epoch=ce)
        self.db.consume_send_grant(g_eq1)
        r_no_rcpt = reconcile_op(db=self.db, transport=tr, repo="org/app", op_id=op_eq1, sender_confirmed_terminated=True, dispatcher_epoch=1)
        self.assertEqual(r_no_rcpt["status"], "superseded_by_pr_merge")

        # With persisted remote_receipt_id BEFORE merge -> succeeded_verified!
        op_eq2 = self.db.prepare_op(unit_key="UM", op_type="enqueue_pr", claim_epoch=ce, candidate_sha="candM1234567")
        g_eq2 = self.db.promote_op_to_in_flight(op_eq2, caller_owner_kind="worker", caller_epoch=ce)
        self.db.consume_send_grant(g_eq2)
        self.db.record_op_receipt(op_eq2, remote_receipt_id="MQE_PERSISTED")
        r_with_rcpt = reconcile_op(db=self.db, transport=tr, repo="org/app", op_id=op_eq2, sender_confirmed_terminated=True, dispatcher_epoch=1)
        self.assertEqual(r_with_rcpt["status"], "succeeded_verified")


class _ScriptedChefRunner:
    """Fake ModelRunner testing both Claude stdout JSON referee and Codex outbox/verdict.json referee."""

    def __init__(self, defect_schedule: list[int], *, use_outbox: bool) -> None:
        self.defect_schedule = list(defect_schedule)
        self.use_outbox = use_outbox
        self.referee_prompts: list[str] = []
        self.bundle_files_seen: list[list[str]] = []
        self._round = 0

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
        return ModelTurnResult(
            raw_stdout=json.dumps(
                {
                    "root_cause": "add() missing int coercion",
                    "target_area": "src/calc.py",
                    "exemplar_files": ["src/calc.py"],
                    "dod_check": "python3 -c 'import sys; sys.path.insert(0, \"src\"); import calc; assert calc.add(2, 3) == 5'",
                    "ui_verify_needed": False,
                    "uncertainties": [],
                }
            )
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
        self._round += 1
        (worktree / "src" / "calc.py").write_text(
            f"# round {self._round}\ndef add(a, b):\n    return int(a) + int(b)\n",
            encoding="utf-8",
        )
        return ModelTurnResult(
            raw_stdout=json.dumps(
                {
                    "summary_le_300_chars": f"Coerce add() args in round {self._round}",
                    "changed_files": ["src/calc.py"],
                    "executed_checks": ["python3 -c ..."],
                    "uncertainties": [],
                }
            )
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
        self.referee_prompts.append(prompt)
        self.bundle_files_seen.append([str(p.relative_to(review_bundle_dir)) for p in review_bundle_dir.rglob("*") if p.is_file()])
        dcnt = self.defect_schedule[self._round - 1]
        defects = [
            {
                "location": f"src/calc.py:{i + 1}",
                "failure_case": f"edge case #{i + 1}",
                "minimal_fix": "tighten input validation",
            }
            for i in range(dcnt)
        ]
        verdict_obj = {
            "verdict": "APPROVE" if dcnt == 0 else "REVISE",
            "round_index": self._round,
            "defect_count": dcnt,
            "three_col_defects": defects,
            "uncertainties": [],
        }
        txt = json.dumps(verdict_obj)
        if self.use_outbox:
            (outbox_dir / "verdict.json").write_text(txt, encoding="utf-8")
            return ModelTurnResult(raw_stdout="done", outbox_verdict_json=txt, model_used=model)
        # claude:readonly_model has Read/Glob/Grep only -> returns JSON via controlled stdout!
        return ModelTurnResult(raw_stdout=f"Review complete:\n```json\n{txt}\n```", outbox_verdict_json=None, model_used=model)


class TestChefPipelineDreamAndQuota(unittest.TestCase):
    def test_bidirectional_referee_convergence_exhaustion_dream_and_quota(self) -> None:
        # Quota parser test (Claude 5-hour window format)
        now_ref = dt.datetime(2026, 11, 24, 17, 12, 0, tzinfo=dt.timezone.utc)  # 09:12 PST
        wake = parse_quota_reset("You've hit your 5-hour limit · resets 10:50am (America/Los_Angeles)", now=now_ref)
        self.assertIsNotNone(wake)
        self.assertGreater(wake, now_ref.isoformat())

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo_main = base / "repo"
            base_sha = _init_git_repo(repo_main)
            croot = base / "cfg"
            sroot = base / "state"
            onboard_project(
                project_id="demo",
                kind="issue",
                workspace_path=repo_main,
                repos=["org/demo"],
                trust_tier="T2",
                writer_family="codex",
                config_root=croot,
                state_root=sroot,
            )
            # Populate secret marker in advisory PITFALLS.md to prove it NEVER leaks into Referee!
            (sroot / "advisory" / "demo" / "PITFALLS.md").write_text("ADVISORY_PITFALL_SECRET_TOKEN\n", encoding="utf-8")

            db = AutopilotDB(sroot / "autopilot.db")
            try:
                cfg_codex = WorkflowConfig(
                    project_id="demo",
                    kind="issue",
                    enabled=True,
                    repos=("org/demo",),
                    workspace_path=str(repo_main),
                    trust_tier="T2",
                    writer_family="codex",
                    write_scope=("src/**",),
                )
                db.upsert_project(cfg_codex)
                db.ensure_lease_slots("demo", ["s1"], sroot / "locks")
                mg = ensure_managed_bare_repo(repo_main, base / "mg.git")

                # 1. Codex writer -> Claude referee (via stdout JSON!) converging 2 -> 1 -> 0
                db.ensure_work_unit(unit_key="org/demo#10", project_id="demo", repo="org/demo", issue_number=10)
                ce1 = db.claim_and_reserve(
                    unit_key="org/demo#10", cfg=cfg_codex, slot_keys=["s1"],
                    worker_unit_name="w10.service", expected_cgroup_dir="/cg/10",
                    base_sha=base_sha, authorized_head_ref="agent/issue-10",
                    bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                )
                runner1 = _ScriptedChefRunner([2, 1, 0], use_outbox=False)
                gh1 = FakeGitHubTransport()
                res1 = execute_chef_issue_pipeline(
                    db=db,
                    cfg=cfg_codex,
                    unit_key="org/demo#10",
                    repo="org/demo",
                    issue_summary="#10 Fix calc.add",
                    claim_epoch=ce1,
                    managed_gitdir=mg,
                    worktree_dir=base / "wt10",
                    repo_main=repo_main,
                    run_dir=base / "run10",
                    advisory_dir=sroot / "advisory" / "demo",
                    model_runner=runner1,
                    gh_transport=gh1,
                    hmac_secret=b"test-secret",
                )
                self.assertEqual(res1["status"], "published")
                self.assertEqual(res1["defect_trajectory"], [2, 1, 0])
                self.assertEqual([op for op, _ in gh1.sent_ops_log], ["push_branch", "create_draft_pr", "mark_pr_ready"])
                for rp in runner1.referee_prompts:
                    self.assertNotIn("ADVISORY_PITFALL_SECRET_TOKEN", rp)
                for bfiles in runner1.bundle_files_seen:
                    self.assertNotIn("PITFALLS.md", bfiles)
                db.begin_reclaim_claim(ce1)
                db.finish_reclaim_leases_free(ce1, cleanup_rc=0, unit_terminated=True, worktree_clean=True)

                # 2. Claude writer -> Codex referee (via outbox/verdict.json) exhausting 3 rounds [3, 2, 1] -> ZERO remote sends!
                cfg_claude = WorkflowConfig(**{**cfg_codex.__dict__, "writer_family": "claude"})
                db.ensure_work_unit(unit_key="org/demo#11", project_id="demo", repo="org/demo", issue_number=11)
                ce2 = db.claim_and_reserve(
                    unit_key="org/demo#11", cfg=cfg_claude, slot_keys=["s1"],
                    worker_unit_name="w11.service", expected_cgroup_dir="/cg/11",
                    base_sha=base_sha, authorized_head_ref="agent/issue-11",
                    bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                )
                runner2 = _ScriptedChefRunner([3, 2, 1], use_outbox=True)
                gh2 = FakeGitHubTransport()
                res2 = execute_chef_issue_pipeline(
                    db=db,
                    cfg=cfg_claude,
                    unit_key="org/demo#11",
                    repo="org/demo",
                    issue_summary="#11 Unconverged fix",
                    claim_epoch=ce2,
                    managed_gitdir=mg,
                    worktree_dir=base / "wt11",
                    repo_main=repo_main,
                    run_dir=base / "run11",
                    advisory_dir=sroot / "advisory" / "demo",
                    model_runner=runner2,
                    gh_transport=gh2,
                    hmac_secret=b"test-secret",
                )
                self.assertEqual(res2["status"], "needs-human")
                self.assertEqual(res2["defect_trajectory"], [3, 2, 1])
                self.assertEqual(len(gh2.sent_ops_log), 0, "Exhausted 3-round review MUST execute 0 remote sends!")
                self.assertEqual(db.get_unit("org/demo#11")["terminal_state"], "needs-human")

                # 3. Dream consolidation: pitfalls with hits >= 2 generate human-gated gate_patch.json + 48h maturation!
                dream_res = run_dream_consolidation(db, state_root=sroot)
                self.assertTrue(dream_res["gate_proposals"])
                self.assertTrue(Path(dream_res["gate_proposals"][0]).is_file())
            finally:
                db.close()


class TestCodeReviewHardeningInvariants(unittest.TestCase):
    def test_multithread_tx_isolation_oneshot_grant_timeout_safety_t3_paths_and_claude_elf(self) -> None:
        from unittest import mock
        from ap_core.git_gate import resolve_repo_common_objects_dir
        from ap_core.github_flow import LiveGitHubCliTransport
        from ap_core.models import SandboxError
        from ap_core.sandbox import prepare_sandbox_home, safe_read_outbox_file

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            db = AutopilotDB(base / "hard.db")
            try:
                # 1. Multi-thread SQLite RLock isolation: thread 1 rollback NEVER rolls back thread 2's committed row!
                t1_entered = threading.Event()
                t1_rollback = threading.Event()
                t2_done = threading.Event()

                def _t1() -> None:
                    with self.assertRaises(RuntimeError):
                        with db.immediate_tx():
                            db.ensure_work_unit(unit_key="T1_ROLLED_BACK", project_id="p", repo="o/r", issue_number=1)
                            t1_entered.set()
                            t1_rollback.wait(timeout=5)
                            raise RuntimeError("abort t1")

                def _t2() -> None:
                    t1_entered.wait(timeout=5)
                    t1_rollback.set()
                    db.ensure_work_unit(unit_key="T2_COMMITTED", project_id="p", repo="o/r", issue_number=2)
                    t2_done.set()

                th1 = threading.Thread(target=_t1)
                th2 = threading.Thread(target=_t2)
                th1.start()
                th2.start()
                th1.join()
                th2.join()
                self.assertTrue(t2_done.is_set())
                self.assertIsNone(db.get_unit("T1_ROLLED_BACK"))
                self.assertIsNotNone(db.get_unit("T2_COMMITTED"))

                # 2. One-shot SendGrant consumption: duplicate execute_granted_op with SAME grant sends ONLY ONCE!
                cfg = WorkflowConfig(
                    project_id="p", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base),
                    trust_tier="T3", write_scope=("src/**", "docs/**"), merge_paths=("docs/**",),
                )
                db.upsert_project(cfg)
                db.ensure_lease_slots("p", ["s1"], base / "locks")
                db.ensure_work_unit(unit_key="U_ONCE", project_id="p", repo="o/r", issue_number=5)
                ce = db.claim_and_reserve(
                    unit_key="U_ONCE", cfg=cfg, slot_keys=["s1"], worker_unit_name="u.service",
                    expected_cgroup_dir="/cg/u", base_sha="0000000", authorized_head_ref="agent/5",
                    bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                )
                db.set_current_candidate(unit_key="U_ONCE", candidate_sha="cand5555555", claim_epoch=ce)
                db.record_verify_receipt(
                    unit_key="U_ONCE", candidate_sha="cand5555555", dod_cmd="true", exit_code=0,
                    ui_verified=False, artifact_dir="/tmp", touched_paths=("src/calc.py",),
                )
                db.record_review_receipt(
                    unit_key="U_ONCE", candidate_sha="cand5555555", writer_family="codex",
                    referee_family="claude", referee_model="claude-fable-5-2", verdict="APPROVE",
                    defect_count=0, defects=[], raw_path="/tmp/r.json",
                )
                tr = FakeGitHubTransport()
                tr.fail_op_types_unknown.add("create_draft_pr")
                op_pr = db.prepare_op(
                    unit_key="U_ONCE", op_type="create_draft_pr", claim_epoch=ce, candidate_sha="cand5555555",
                    payload={"title": "t", "body": "b"},
                )
                grant = db.promote_op_to_in_flight(op_pr, caller_owner_kind="worker", caller_epoch=ce)
                res_first = execute_granted_op(grant=grant, db=db, transport=tr, repo="o/r")
                self.assertEqual(res_first["status"], "unknown_paused")
                self.assertEqual(len(tr.sent_ops_log), 1)
                with self.assertRaises(AutopilotError):
                    execute_granted_op(grant=grant, db=db, transport=tr, repo="o/r")
                self.assertEqual(len(tr.sent_ops_log), 1, "Same SendGrant MUST NEVER transmit twice!")

                # operator_resolve_op rejects prepared_local, missing evidence, or unconfirmed sender termination
                with self.assertRaises(AutopilotError):
                    db.operator_resolve_op(op_pr, new_status="prepared_local", sender_confirmed_terminated=True)
                with self.assertRaises(AutopilotError):
                    db.operator_resolve_op(op_pr, new_status="succeeded_verified", sender_confirmed_terminated=True)
                with self.assertRaises(AutopilotError):
                    db.operator_resolve_op(op_pr, new_status="not_executed", unsent_proof="verified_no_pr", sender_confirmed_terminated=False)
                db.operator_resolve_op(op_pr, new_status="not_executed", unsent_proof="verified_no_pr", sender_confirmed_terminated=True)

                # 3. Authoritative payload conflict rejected upfront in prepare_op & T3 merge_paths + mark_pr_ready enforced!
                tr.fail_op_types_unknown.clear()
                with self.assertRaises(AutopilotError):
                    db.prepare_op(
                        unit_key="U_ONCE", op_type="create_draft_pr", claim_epoch=ce, candidate_sha="cand5555555",
                        payload={"title": "t", "body": "b", "baseRefName": "hijack-branch"},
                    )

                # Create real draft PR, then attempt enqueue_pr WITHOUT mark_pr_ready -> rejected!
                op_pr3 = db.prepare_op(unit_key="U_ONCE", op_type="create_draft_pr", claim_epoch=ce, candidate_sha="cand5555555", payload={"title": "t", "body": "b"})
                g_pr3 = db.promote_op_to_in_flight(op_pr3, caller_owner_kind="worker", caller_epoch=ce)
                execute_granted_op(grant=g_pr3, db=db, transport=tr, repo="o/r")
                with self.assertRaises(AutopilotError):
                    db.prepare_op(unit_key="U_ONCE", op_type="enqueue_pr", claim_epoch=ce, candidate_sha="cand5555555")

                # Even after mark_pr_ready succeeds, touched_paths=('src/calc.py',) is outside T3 merge_paths=('docs/**',) -> rejected!
                op_rdy = db.prepare_op(unit_key="U_ONCE", op_type="mark_pr_ready", claim_epoch=ce, candidate_sha="cand5555555")
                g_rdy = db.promote_op_to_in_flight(op_rdy, caller_owner_kind="worker", caller_epoch=ce)
                execute_granted_op(grant=g_rdy, db=db, transport=tr, repo="o/r")
                with self.assertRaises(AutopilotError):
                    db.prepare_op(unit_key="U_ONCE", op_type="enqueue_pr", claim_epoch=ce, candidate_sha="cand5555555")

                # 4. TimeoutExpired or GraphQL TIMEOUT error MUST NOT set unsent_proof; structured UNPROCESSABLE DOES!
                live_tr = LiveGitHubCliTransport(cache_dir=base)
                with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["gh", "expectedHeadOid"], timeout=30)):
                    t_res = live_tr.send_single_mutation(
                        repo="o/r", op_type="enqueue_pr",
                        payload={"pullRequestId": "PR1", "expectedHeadOid": "abc"},
                    )
                self.assertFalse(t_res.ok)
                self.assertIsNone(t_res.unsent_proof, "Timeout MUST leave unsent_proof=None (unknown_paused)!")

                gql_timeout_proc = subprocess.CompletedProcess(
                    args=["gh"], returncode=1,
                    stdout=json.dumps({"data": {"enqueuePullRequest": None}, "errors": [{"type": "TIMEOUT", "message": "upstream timeout"}]}),
                    stderr="",
                )
                with mock.patch("subprocess.run", return_value=gql_timeout_proc):
                    t_res2 = live_tr.send_single_mutation(
                        repo="o/r", op_type="enqueue_pr",
                        payload={"pullRequestId": "PR1", "expectedHeadOid": "abc"},
                    )
                self.assertIsNone(t_res2.unsent_proof)

                gql_unproc_proc = subprocess.CompletedProcess(
                    args=["gh"], returncode=1,
                    stdout=json.dumps({"data": {"enqueuePullRequest": None}, "errors": [{"type": "UNPROCESSABLE", "message": "Base branch was modified"}]}),
                    stderr="",
                )
                with mock.patch("subprocess.run", return_value=gql_unproc_proc):
                    t_res3 = live_tr.send_single_mutation(
                        repo="o/r", op_type="enqueue_pr",
                        payload={"pullRequestId": "PR1", "expectedHeadOid": "abc"},
                    )
                self.assertIsNotNone(t_res3.unsent_proof)

                # 4b. Cross-line Ref-ID:\nap-... and missing ref_id_hmac rejected by has_exact_ref_id_line / find_pr_for_head_or_ref_id
                from ap_core.github_flow import has_exact_ref_id_line
                self.assertTrue(has_exact_ref_id_line("Ref-ID: ap-123456\nother", "ap-123456"))
                self.assertFalse(has_exact_ref_id_line("Ref-ID:\nap-123456", "ap-123456"))
                self.assertFalse(has_exact_ref_id_line("Ref-ID: ap-123456", ""))
                self.assertIsNone(tr.find_pr_for_head_or_ref_id("o/r", authorized_head_ref="agent/5", ref_id_hmac=None))

                # 5. Active ruleset enabling Merge Queue on 2nd branch or empty includes -> caps at T2
                ok_rs, _ = evaluate_classic_protection_for_enqueue(
                    authorized_base_ref="main",
                    rules=[],
                    has_incomplete_pagination=False,
                    merge_queue_branches={},
                    active_ruleset_mq_includes=[["refs/heads/main", "refs/heads/release"]],
                )
                self.assertFalse(ok_rs)
                ok_rs_empty, _ = evaluate_classic_protection_for_enqueue(
                    authorized_base_ref="main",
                    rules=[],
                    has_incomplete_pagination=False,
                    merge_queue_branches={},
                    active_ruleset_mq_includes=[[]],
                )
                self.assertFalse(ok_rs_empty)

                # 5b. Readonly AutopilotDB on nonexistent path creates ZERO files/dirs on disk and rejects writes!
                missing_db_path = base / "no_such_dir" / "missing.db"
                ro_db = AutopilotDB(missing_db_path, readonly=True)
                try:
                    self.assertFalse(missing_db_path.exists())
                    self.assertFalse(missing_db_path.parent.exists())
                    with self.assertRaises(AutopilotError):
                        with ro_db.immediate_tx():
                            pass
                finally:
                    ro_db.close()

                # 6. clear_veto_and_resume requires any_veto == 1 and preserves lockfile non-veto needs-human!
                db.ensure_work_unit(unit_key="U_LOCK", project_id="p", repo="o/r", issue_number=6)
                db.mark_unit_needs_human("U_LOCK", "lockfile touched", non_veto=True)
                with self.assertRaises(AutopilotError):
                    db.clear_veto_and_resume("U_LOCK")
                db.register_admin_revoke(unit_key="U_LOCK", dispatcher_epoch=db.bump_dispatcher_epoch(), reason="veto_on_top")
                db.clear_veto_and_resume("U_LOCK")
                self.assertEqual(db.get_unit("U_LOCK")["terminal_state"], "needs-human")
            finally:
                db.close()

            # 7. Combined hard-stop + lockfile preserves is_lockfile=True
            with self.assertRaises(ScopeViolationError) as combo_ctx:
                check_autopilot_scope([".env", "pnpm-lock.yaml"], ["**"])
            self.assertTrue(combo_ctx.exception.is_lockfile)

            # 8. O_NOFOLLOW|O_NONBLOCK outbox reader rejects symlinks & FIFOs, and Codex auth projection strips refresh_token
            obox = base / "obox"
            obox.mkdir()
            (obox / "verdict.json").symlink_to("/etc/passwd")
            with self.assertRaises(SandboxError):
                safe_read_outbox_file(obox, "verdict.json")
            os.mkfifo(obox / "fifo.json")
            with self.assertRaises(SandboxError):
                safe_read_outbox_file(obox, "fifo.json")

            fake_home = base / "fake_home"
            (fake_home / ".codex").mkdir(parents=True)
            (fake_home / ".codex" / "auth.json").write_text(
                json.dumps({"tokens": {"access_token": "short-tok", "refresh_token": "SECRET_REFRESH", "account_id": "acc1"}}),
                encoding="utf-8",
            )
            sbh = prepare_sandbox_home(base / "run_cred", "codex", host_home=fake_home)
            proj_txt = (sbh / ".codex" / "auth.json").read_text(encoding="utf-8")
            self.assertIn("short-tok", proj_txt)
            self.assertNotIn("SECRET_REFRESH", proj_txt)

            # 9. Linked worktree common objects dir & tracked-yet-gitignored CLEAN_TREE OID parity
            repo_m = base / "repo_wt_main"
            b_sha = _init_git_repo(repo_m)
            # Track a file that ALSO matches .gitignore (`*.pyc`)
            (repo_m / "src" / "tracked_ignored.pyc").write_bytes(b"tracked-bytes")
            subprocess.run(["git", "add", "-f", "src/tracked_ignored.pyc"], cwd=repo_m, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "add tracked ignored"], cwd=repo_m, check=True)
            b_sha2 = resolve_commit_oid(repo_m, "HEAD")

            linked_wt = base / "linked_wt"
            subprocess.run(["git", "-C", str(repo_m), "worktree", "add", "--detach", str(linked_wt), b_sha2], check=True, capture_output=True)
            self.assertIsNotNone(resolve_repo_common_objects_dir(linked_wt))

            mg_l = ensure_managed_bare_repo(linked_wt, base / "mg_linked.git")
            wt_l, wt_gd_l = prepare_isolated_worktree(managed_gitdir=mg_l, worktree_dir=base / "wt_l", base_sha=b_sha2)
            (wt_l / "src" / "calc.py").write_text("def add(a, b):\n    return a + b + 0\n", encoding="utf-8")
            gate_l = sample_and_gate_worktree(
                managed_gitdir=mg_l, wt_gitdir=wt_gd_l, worktree=wt_l, repo_main=linked_wt,
                run_dir=base / "run_linked", base_sha=b_sha2, frozen_write_scope=["src/**"],
            )
            self.assertTrue((gate_l.clean_tree_dir / "src" / "tracked_ignored.pyc").is_file())

            # 10. Live Claude ELF dynamic loader (/lib64 -> /usr/lib64) + Landlock inside model_ring!
            claude_bin = shutil.which("claude")
            if claude_bin:
                b_init, b_sh = _ensure_compiled_test_binaries()
                bundle_d = base / "claude_bundle"
                bundle_d.mkdir()
                argv_claude = build_model_ring_bwrap(
                    role_key="claude:readonly_model",
                    host_binaries={
                        "ap_sandbox_init": b_init,
                        "ap_safe_sh": b_sh,
                        "claude_cli": Path(claude_bin).resolve(),
                    },
                    sandbox_home=base / "claude_sb",
                    outbox_dir=base / "claude_obox",
                    proxy_sock=None,
                    inner_cmd=["/usr/local/bin/claude", "--version"],
                    review_bundle_dir=bundle_d,
                )
                c_proc = subprocess.run(argv_claude, capture_output=True, text=True, timeout=20, check=False)
                self.assertEqual(c_proc.returncode, 0, msg=c_proc.stderr + c_proc.stdout)
                self.assertTrue(c_proc.stdout.strip())

    def test_round3_adversarial_review_closures(self) -> None:
        """Regression suite covering all 13 Codex Astra + 4 Claude Fable Round-3 findings."""
        import sqlite3
        import agent_autopilot as ap_cli
        from ap_core.git_gate import _promote_scratch_objects
        from ap_core.github_flow import LiveGitHubCliTransport, is_enqueue_attributable_to_op
        from ap_core.sandbox import prepare_sandbox_home

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            # 1. Pre-migration unknown_paused row without grant_token MUST migrate to send_consumed=1 (retaining lock!)
            legacy_db_path = base / "legacy_upg.db"
            raw_c = sqlite3.connect(str(legacy_db_path))
            raw_c.execute(
                "CREATE TABLE external_ops (op_id TEXT PRIMARY KEY, op_seq INTEGER NOT NULL, unit_key TEXT NOT NULL, "
                "pr_id TEXT, op_type TEXT NOT NULL, owner_kind TEXT NOT NULL, owner_epoch INTEGER NOT NULL, claim_epoch INTEGER, "
                "candidate_sha TEXT, authorized_base_ref TEXT, authorized_head_ref TEXT, ref_id_hmac TEXT, payload_json TEXT NOT NULL DEFAULT '{}', "
                "status TEXT NOT NULL, remote_receipt_id TEXT, unsent_proof TEXT, error_detail TEXT, superseded_by_op_id TEXT, "
                "prepared_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )
            raw_c.execute(
                "INSERT INTO external_ops(op_id, op_seq, unit_key, pr_id, op_type, owner_kind, owner_epoch, status, prepared_at, updated_at) "
                "VALUES ('op-old-unk', 1, 'U_OLD', 'PR_OLD', 'mark_pr_ready', 'worker', 1, 'unknown_paused', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')"
            )
            raw_c.commit()
            raw_c.close()

            upg_db = AutopilotDB(legacy_db_path)
            try:
                migrated_op = upg_db.get_op("op-old-unk")
                self.assertEqual(int(migrated_op["send_consumed"]), 1, "Legacy unknown_paused MUST migrate to send_consumed=1!")
                upg_db.ensure_work_unit(unit_key="U_OLD", project_id="p_old", repo="o/r", issue_number=1, pr_id="PR_OLD")
                tr_old = FakeGitHubTransport()
                tr_old.prs["PR_OLD"] = PrSnapshot(
                    pr_id="PR_OLD", state="OPEN", is_draft=False, head_ref_oid="abc",
                    head_ref_name="agent/1", base_ref_name="main",
                )
                r_old = reconcile_op(db=upg_db, transport=tr_old, repo="o/r", op_id="op-old-unk", sender_confirmed_terminated=True, dispatcher_epoch=2)
                self.assertEqual(r_old["status"], "unknown_paused", "Migrated unknown_paused MUST NOT release write lock!")

                # 2. max_per_day enforced atomically in claim_and_reserve + upsert_project preserves kind & dedicated token fail-closed
                cfg_cap = WorkflowConfig(
                    project_id="p_cap", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base),
                    trust_tier="T2", write_scope=("src/**",), max_per_day=1, token_file=str(base / "missing.tok"),
                )
                upg_db.upsert_project(cfg_cap)
                self.assertEqual(upg_db.get_project_row("p_cap")["kind"], "issue")
                # Dedicated token_file missing -> _resolve_strict_project_gh_transport refuses fallback even if WORKFLOW.md absent!
                with self.assertRaises(AutopilotError):
                    ap_cli._resolve_strict_project_gh_transport(upg_db, "p_cap", {})

                upg_db.ensure_lease_slots("p_cap", ["sc1"], base / "locks_cap")
                upg_db.ensure_work_unit(unit_key="UC1", project_id="p_cap", repo="o/r", issue_number=10)
                upg_db.ensure_work_unit(unit_key="UC2", project_id="p_cap", repo="o/r", issue_number=11)
                ce_c1 = upg_db.claim_and_reserve(
                    unit_key="UC1", cfg=cfg_cap, slot_keys=["sc1"], worker_unit_name="uc1.service",
                    expected_cgroup_dir="/cg/nonexistent_uc1", base_sha="0000000", authorized_head_ref="agent/10",
                    bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                )

                # 3. Unbound mark_pr_ready with caller-supplied pullRequestId MUST be rejected!
                upg_db.set_current_candidate(unit_key="UC1", candidate_sha="cand1010", claim_epoch=ce_c1)
                upg_db.record_verify_receipt(unit_key="UC1", candidate_sha="cand1010", dod_cmd="true", exit_code=0, ui_verified=False, artifact_dir="/tmp", touched_paths=("src/a.py",))
                upg_db.record_review_receipt(unit_key="UC1", candidate_sha="cand1010", writer_family="codex", referee_family="claude", referee_model="claude-fable-5-2", verdict="APPROVE", defect_count=0, defects=[], raw_path="/tmp/r.json")
                with self.assertRaises(AutopilotError):
                    upg_db.prepare_op(unit_key="UC1", op_type="mark_pr_ready", claim_epoch=ce_c1, candidate_sha="cand1010", payload={"pullRequestId": "OTHER_PR"})

                # Release first claim -> second claim on same day rejected by max_per_day=1!
                upg_db.begin_reclaim_claim(ce_c1)
                upg_db.finish_reclaim_leases_free(ce_c1, cleanup_rc=0, unit_terminated=True, worktree_clean=True)
                with self.assertRaises(AutopilotError):
                    upg_db.claim_and_reserve(
                        unit_key="UC2", cfg=cfg_cap, slot_keys=["sc1"], worker_unit_name="uc2.service",
                        expected_cgroup_dir="/cg/nonexistent_uc2", base_sha="0000000", authorized_head_ref="agent/11",
                    )

                # 4. Incomplete timeline (enqueue_event_timestamps=None) refuses receipt-less attribution, AND
                # pre-dequeue abort persists unsent_proof so subsequent supervisor epoch CAN replace & retry!
                snap_incomp = PrSnapshot(
                    pr_id="PR_INC", state="OPEN", is_draft=False, head_ref_oid="cand_inc",
                    head_ref_name="agent/inc", base_ref_name="main",
                    merge_queue_entry_id="MQ_INC", merge_queue_enqueuer="autopilot-bot",
                    merge_queue_enqueued_at="9999-12-31T00:00:00+00:00",
                    enqueue_event_timestamps=None,
                )
                self.assertFalse(
                    is_enqueue_attributable_to_op(
                        {"remote_receipt_id": None, "prepared_at": "2026-01-01T00:00:00+00:00", "candidate_sha": "cand_inc", "authorized_base_ref": "main"},
                        snap_incomp,
                        bot_login="autopilot-bot",
                    )
                )

                # 5. Delayed Ready landing AFTER initial veto snapshot is caught by supervisor_recover_and_reconcile!
                cfg_v = WorkflowConfig(project_id="pv", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                upg_db.upsert_project(cfg_v)
                upg_db.ensure_lease_slots("pv", ["sv1"], base / "locks_v")
                upg_db.ensure_work_unit(unit_key="UV", project_id="pv", repo="o/r", issue_number=20, pr_id="PR_V")
                ce_v = upg_db.claim_and_reserve(
                    unit_key="UV", cfg=cfg_v, slot_keys=["sv1"], worker_unit_name="ap-nonexistent-uv.service",
                    expected_cgroup_dir="/sys/fs/cgroup/nonexistent_uv", base_sha="0000000", authorized_head_ref="agent/20",
                    bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                )
                upg_db.set_current_candidate(unit_key="UV", candidate_sha="candV20", claim_epoch=ce_v)
                upg_db.record_verify_receipt(unit_key="UV", candidate_sha="candV20", dod_cmd="true", exit_code=0, ui_verified=False, artifact_dir="/tmp", touched_paths=("src/a.py",))
                upg_db.record_review_receipt(unit_key="UV", candidate_sha="candV20", writer_family="codex", referee_family="claude", referee_model="claude-fable-5-2", verdict="APPROVE", defect_count=0, defects=[], raw_path="/tmp/r.json")
                op_vr = upg_db.prepare_op(unit_key="UV", op_type="mark_pr_ready", claim_epoch=ce_v, candidate_sha="candV20")
                g_vr = upg_db.promote_op_to_in_flight(op_vr, caller_owner_kind="worker", caller_epoch=ce_v)
                upg_db.consume_send_grant(g_vr)
                upg_db.begin_reclaim_claim(ce_v)
                upg_db.finish_reclaim_leases_free(ce_v, cleanup_rc=0, unit_terminated=True, worktree_clean=True)

                # Operator vetoes while PR is still Draft (delayed Ready hasn't landed yet -> 0 admin ops initially)
                ep_v1 = upg_db.bump_dispatcher_epoch()
                upg_db.register_admin_revoke(unit_key="UV", dispatcher_epoch=ep_v1, pr_id="PR_V", remote_sync_pending=False, reason="veto_early")
                # Now delayed Ready lands on GitHub (`is_draft=False`) while `op_vr` is unresolved!
                tr_v = FakeGitHubTransport()
                tr_v.prs["PR_V"] = PrSnapshot(
                    pr_id="PR_V", state="OPEN", is_draft=False, head_ref_oid="candV20",
                    head_ref_name="agent/20", base_ref_name="main",
                )
                ep_v2 = upg_db.bump_dispatcher_epoch()
                ap_cli.supervisor_recover_and_reconcile(upg_db, ep_v2, {"pv": cfg_v}, transport_override=tr_v)
                adm_v = [o["op_type"] for o in upg_db.list_ops_for_scope("UV") if o["owner_kind"] == "supervisor_admin"]
                self.assertIn("convert_pr_to_draft", adm_v, "Supervisor MUST catch delayed Ready and register convert_pr_to_draft!")
            finally:
                upg_db.close()

            # 6. ToolExecServer kills child process group via POLLHUP even when stdin_tx is backpressured + unread bytes!
            wt_bp = base / "wt_bp"
            wt_bp.mkdir()
            sdir = ap_cli._create_short_socket_dir()
            try:
                self.assertLess(len(str(sdir / "t.sock").encode("utf-8")), 104, "Socket path MUST fit sun_path[108]!")
                srv_bp = ToolExecServer(sdir / "t.sock", wt_bp)
                srv_bp.start()
                try:
                    cwd_b = str(wt_bp).encode("utf-8")
                    hdr_bp = (
                        f"CWD:{len(cwd_b)}\nARGC:2\n".encode("ascii")
                        + cwd_b + b"\n"
                        + b"A:2\n-c\nA:8\nsleep 30\n"
                    )
                    chunk = b"A" * 65536
                    frame = f"I:{len(chunk)}\n".encode("ascii") + chunk
                    # Send header + non-blocking flood of stdin frames until kernel socket buffer ALSO has unread bytes while stdin_tx >= 262144, then close!
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as cli:
                        cli.connect(str(sdir / "t.sock"))
                        cli.sendall(hdr_bp)
                        cli.setblocking(False)
                        payload_flood = bytearray(frame * 10)
                        for _ in range(40):
                            try:
                                sent_n = cli.send(payload_flood)
                                del payload_flood[:sent_n]
                                if not payload_flood:
                                    break
                            except BlockingIOError:
                                break
                            time.sleep(0.01)
                        time.sleep(0.05)
                    deadline = time.monotonic() + 3.0
                    while time.monotonic() < deadline and not srv_bp.killed_pgids:
                        time.sleep(0.05)
                    self.assertTrue(srv_bp.killed_pgids, "ToolExecServer MUST killpg on POLLHUP even while stdin_tx is backpressured!")
                finally:
                    srv_bp.close()
            finally:
                shutil.rmtree(sdir, ignore_errors=True)

            # 7. Real `git push --porcelain --force-with-lease` stdout rejection & atomic loose object replacement!
            bare_rem = base / "rem.git"
            subprocess.run(["git", "init", "--bare", "-q", str(bare_rem)], check=True)
            loc_repo = base / "loc_repo"
            sha1 = _init_git_repo(loc_repo)
            subprocess.run(["git", "-C", str(loc_repo), "push", "-q", str(bare_rem), f"{sha1}:refs/heads/feat"], check=True)
            (loc_repo / "src" / "calc.py").write_text("x = 2\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(loc_repo), "commit", "-am", "two", "-q"], check=True)
            sha2 = resolve_commit_oid(loc_repo, "HEAD")
            porc = subprocess.run(
                [
                    "git", "-C", str(loc_repo), "push", "--porcelain",
                    "--force-with-lease=refs/heads/feat:0000000000000000000000000000000000000001",
                    str(bare_rem), f"{sha2}:refs/heads/feat",
                ],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(porc.returncode, 0)
            live_t = LiveGitHubCliTransport(cache_dir=base)
            with unittest.mock.patch("subprocess.run", side_effect=[
                subprocess.CompletedProcess(["git", "init"], 0, "", ""),
                porc,
            ]):
                p_res = live_t.push_branch_ephemeral(
                    repo="o/r", managed_gitdir=loc_repo / ".git", candidate_sha=sha2,
                    authorized_head_ref="feat", authorized_base_ref="main",
                    expected_old_oid="0000000000000000000000000000000000000001",
                )
            self.assertEqual(p_res.unsent_proof, "force_with_lease_rejected")

            # Corrupt/truncated loose object in managed_objects is atomically repaired by _promote_scratch_objects
            scratch_objs = base / "scratch_o"
            managed_objs = base / "managed_o"
            raw_content = b"blob 5\x00hello"
            import hashlib, zlib
            oid_h = hashlib.sha1(raw_content).hexdigest()
            (scratch_objs / oid_h[:2]).mkdir(parents=True)
            (scratch_objs / oid_h[:2] / oid_h[2:]).write_bytes(zlib.compress(raw_content))
            (managed_objs / oid_h[:2]).mkdir(parents=True)
            (managed_objs / oid_h[:2] / oid_h[2:]).write_bytes(b"truncated-corrupt")
            _promote_scratch_objects(scratch_objs, managed_objs)
            self.assertEqual(zlib.decompress((managed_objs / oid_h[:2] / oid_h[2:]).read_bytes()), raw_content)

            # 8. claude:issue_model includes --permission-mode bypassPermissions & allow list in projected settings.json
            sbh_c = prepare_sandbox_home(base / "sb_claude_w", "claude", role_key="claude:issue_model", host_home=base / "empty_h")
            c_settings = json.loads((sbh_c / ".claude" / "settings.json").read_text(encoding="utf-8"))
            self.assertIn("Edit", c_settings["permissions"]["allow"])
            self.assertIn("Bash", c_settings["permissions"]["allow"])
            self.assertIn("bypassPermissions", POLICY_MANIFEST["role_matrix"]["claude:issue_model"]["claude_cli_flags"])

    def test_round4_adversarial_review_closures(self) -> None:
        """Regression suite covering Round-4 monorepo deps, cargo isolation, re-compensation, sub-second enqueue, short-write, and token_mode."""
        import hashlib
        import zlib
        import agent_autopilot as ap_cli
        from ap_core.git_gate import _promote_scratch_objects
        from ap_core.github_flow import is_enqueue_attributable_to_op
        from ap_core.models import SandboxError, build_pnpm_exec_cmd, read_nonempty_token_file
        from ap_core.sandbox import cleanup_workspace_node_modules_mountpoints, prepare_workspace_node_modules_bind_args

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            # 1. Live bwrap VFS bind mount resolves pnpm relative workspace symlink (`../../../packages/shared`) to CANDIDATE source!
            tbc = base / "tbc"
            (tbc / "node_modules" / ".bin").mkdir(parents=True)
            (tbc / "apps" / "web" / "node_modules" / "@repo").mkdir(parents=True)
            (tbc / "apps" / "web" / "node_modules" / "@repo" / "shared").symlink_to("../../../../packages/shared")
            (tbc / "packages" / "shared" / "node_modules").mkdir(parents=True)
            # Notice cache has NO `packages/shared/index.txt`, ONLY candidate `target_ws` has it!
            target_ws = base / "ws"
            (target_ws / "apps" / "web").mkdir(parents=True)
            (target_ws / "packages" / "shared").mkdir(parents=True)
            (target_ws / "packages" / "shared" / "index.txt").write_text("CANDIDATE_V2", encoding="utf-8")

            v_argv = build_execution_ring_bwrap(
                ring_kind="verify_ring",
                inner_cmd=["/bin/cat", "apps/web/node_modules/@repo/shared/index.txt"],
                cwd=base / "vo",
                clean_tree=target_ws,
                verify_out_dir=base / "vo",
                trusted_base_cache=tbc,
            )
            vfs_proc = subprocess.run(v_argv, capture_output=True, text=True, timeout=15, check=False)
            self.assertEqual(vfs_proc.returncode, 0, msg=vfs_proc.stderr)
            self.assertEqual(vfs_proc.stdout.strip(), "CANDIDATE_V2", "bwrap bind mount MUST resolve `..` into candidate tree!")

            # O_NOFOLLOW rejects symlinked workspace package dir (zero writes outside target_tree!)
            outside_dir = base / "outside"
            outside_dir.mkdir()
            bad_ws = base / "bad_ws"
            (bad_ws / "apps").mkdir(parents=True)
            (bad_ws / "apps" / "web").symlink_to(outside_dir)
            with self.assertRaises(SandboxError):
                prepare_workspace_node_modules_bind_args(tbc, bad_ws)
            self.assertFalse((outside_dir / "node_modules").exists())

            # Empty mountpoint cleanup leaves zero residue in worktree
            wt_mp = base / "wt_mp"
            (wt_mp / "apps" / "web").mkdir(parents=True)
            prepare_workspace_node_modules_bind_args(tbc, wt_mp)
            cleanup_workspace_node_modules_mountpoints(tbc, wt_mp)
            self.assertFalse((wt_mp / "apps" / "web" / "node_modules").exists())

            # ELF vs shebang-less pnpm detection
            elf_fake = base / "pnpm-elf"
            elf_fake.write_bytes(b"\x7fELF\x02\x01\x01\x00")
            sh_fake = base / "pnpm-shim"
            sh_fake.write_text("# Shebang-less sh script\nexit 0\n", encoding="utf-8")
            self.assertEqual(build_pnpm_exec_cmd(elf_fake), [str(elf_fake.resolve())])
            self.assertEqual(build_pnpm_exec_cmd(sh_fake), ["/bin/sh", str(sh_fake.resolve())])

            # 2. tool_ring / verify_ring NEVER mount ~/.cargo wholesale OR shared ~/.cargo/registry / ~/.local/share/pnpm
            forbidden_shared = {
                str((Path.home() / ".cargo").resolve()),
                str((Path.home() / ".cargo" / "registry").resolve()),
                str((Path.home() / ".local" / "share" / "pnpm").resolve()),
            }
            for i, tok in enumerate(v_argv[:-2]):
                if tok == "--ro-bind":
                    self.assertNotIn(v_argv[i + 1], forbidden_shared)

            # 3. Whitespace-only & 0000-permission token files rejected as AutopilotError & cross-project unit claim rejected
            ws_tok = base / "ws.tok"
            ws_tok.write_text("  \n\t\n", encoding="utf-8")
            with self.assertRaises(AutopilotError):
                read_nonempty_token_file(ws_tok)
            unread_tok = base / "unread.tok"
            unread_tok.write_text("ghp_secret", encoding="utf-8")
            os.chmod(unread_tok, 0o000)
            try:
                if os.geteuid() != 0:
                    with self.assertRaises(AutopilotError):
                        read_nonempty_token_file(unread_tok)
            finally:
                os.chmod(unread_tok, 0o600)

            db4 = AutopilotDB(base / "r4.db")
            try:
                db4.ensure_work_unit(unit_key="SHARED_REPO#1", project_id="proj_A", repo="o/shared", issue_number=1)
                with self.assertRaises(ScopeConflictError):
                    db4.ensure_work_unit(unit_key="SHARED_REPO#1", project_id="proj_B", repo="o/shared", issue_number=1)
                with db4.immediate_tx():
                    db4._conn.execute(
                        "INSERT INTO projects(project_id, kind, enabled, max_in_progress, current_step_idx, clean_matured_runs, token_file, token_mode, updated_at) "
                        "VALUES ('legacy_p', 'issue', 1, 1, 0, 0, '', NULL, '2026-01-01T00:00:00+00:00')"
                    )
                with self.assertRaises(AutopilotError):
                    ap_cli._resolve_strict_project_gh_transport(db4, "legacy_p", {})

                # 4. Same-second enqueue event WITHOUT receipt MUST retain unknown_paused (return False)
                same_sec_snap = PrSnapshot(
                    pr_id="PR_SS", state="OPEN", is_draft=False, head_ref_oid="c_ss",
                    head_ref_name="agent/ss", base_ref_name="main",
                    merge_queue_entry_id="MQ_SS", merge_queue_enqueuer="autopilot-bot",
                    merge_queue_enqueued_at="2026-11-24T12:00:00Z",
                    enqueue_event_timestamps=("2026-11-24T12:00:00Z",),
                )
                self.assertFalse(
                    is_enqueue_attributable_to_op(
                        {"remote_receipt_id": None, "prepared_at": "2026-11-24T12:00:00.900000+00:00", "candidate_sha": "c_ss", "authorized_base_ref": "main"},
                        same_sec_snap,
                        bot_login="autopilot-bot",
                    )
                )

                # 5. First convert_pr_to_draft gets receipt & observes Draft, THEN late worker Ready flips PR back to Ready ->
                # supervisor retires spent admin op to superseded_by_retry AND executes a 2nd convert_pr_to_draft!
                cfg4 = WorkflowConfig(project_id="p4", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                db4.upsert_project(cfg4)
                db4.ensure_lease_slots("p4", ["s4"], base / "locks4")
                db4.ensure_work_unit(unit_key="U4", project_id="p4", repo="o/r", issue_number=40, pr_id="PR_40")
                ce4 = db4.claim_and_reserve(
                    unit_key="U4", cfg=cfg4, slot_keys=["s4"], worker_unit_name="ap-nonexist-40.service",
                    expected_cgroup_dir="/sys/fs/cgroup/nonexist_40", base_sha="000", authorized_head_ref="agent/40",
                    bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                )
                db4.set_current_candidate(unit_key="U4", candidate_sha="cand4000", claim_epoch=ce4)
                db4.record_verify_receipt(unit_key="U4", candidate_sha="cand4000", dod_cmd="true", exit_code=0, ui_verified=False, artifact_dir="/tmp", touched_paths=("src/a.py",))
                db4.record_review_receipt(unit_key="U4", candidate_sha="cand4000", writer_family="codex", referee_family="claude", referee_model="claude-fable-5-2", verdict="APPROVE", defect_count=0, defects=[], raw_path="/tmp/r.json")
                op_w_ready = db4.prepare_op(unit_key="U4", op_type="mark_pr_ready", claim_epoch=ce4, candidate_sha="cand4000")
                g_wr = db4.promote_op_to_in_flight(op_w_ready, caller_owner_kind="worker", caller_epoch=ce4)
                db4.consume_send_grant(g_wr)
                db4.begin_reclaim_claim(ce4)
                db4.finish_reclaim_leases_free(ce4, cleanup_rc=0, unit_terminated=True, worktree_clean=True)

                tr4 = FakeGitHubTransport()
                tr4.prs["PR_40"] = PrSnapshot(pr_id="PR_40", state="OPEN", is_draft=False, head_ref_oid="cand4000", head_ref_name="agent/40", base_ref_name="main")
                ep4_1 = db4.bump_dispatcher_epoch()
                db4.register_admin_revoke(unit_key="U4", dispatcher_epoch=ep4_1, pr_id="PR_40", need_draft=True, remote_sync_pending=True, reason="veto1")
                ap_cli.supervisor_recover_and_reconcile(db4, ep4_1, {"p4": cfg4}, transport_override=tr4)
                self.assertTrue(tr4.prs["PR_40"].is_draft)

                # Late in-flight Ready arrives AFTER first convert_pr_to_draft succeeded -> flips PR back to Ready!
                tr4.prs["PR_40"] = PrSnapshot(pr_id="PR_40", state="OPEN", is_draft=False, head_ref_oid="cand4000", head_ref_name="agent/40", base_ref_name="main")
                ep4_2 = db4.bump_dispatcher_epoch()
                ap_cli.supervisor_recover_and_reconcile(db4, ep4_2, {"p4": cfg4}, transport_override=tr4)
                self.assertTrue(tr4.prs["PR_40"].is_draft, "Second convert_pr_to_draft MUST pull PR back to Draft!")
                draft_sends = [s for s in tr4.sent_ops_log if s[0] == "convert_pr_to_draft"]
                self.assertEqual(len(draft_sends), 2)
                self.assertGreaterEqual(db4.resolve_unit_scope_and_pending("U4").pending_cnt, 1, "Write lock MUST stay held!")
            finally:
                db4.close()

            # 6. Short-write fault injection (writing 3 bytes then 0) on _promote_scratch_objects MUST NOT install corrupt object
            sc2 = base / "sc2"
            mg2 = base / "mg2"
            raw_b = b"blob 12\x00hello world!"
            oid2 = hashlib.sha1(raw_b).hexdigest()
            (sc2 / oid2[:2]).mkdir(parents=True)
            (sc2 / oid2[:2] / oid2[2:]).write_bytes(zlib.compress(raw_b))
            calls = {"n": 0}
            real_write = os.write

            def _short_zero_write(fd: int, buf: bytes) -> int:
                calls["n"] += 1
                return real_write(fd, bytes(buf)[:3]) if calls["n"] == 1 else 0

            with unittest.mock.patch("os.write", side_effect=_short_zero_write):
                with self.assertRaises(AutopilotError):
                    _promote_scratch_objects(sc2, mg2)
            self.assertFalse((mg2 / oid2[:2] / oid2[2:]).exists(), "Corrupt short-written object MUST NOT be installed!")

    def test_round7_cargo_offline_cache_and_identity_quarantine(self) -> None:
        """Regression suite covering Round-7 Cargo base_sha^{tree} + RUSTUP_HOME, cross-project scope quarantine, bound_gh_login, token-after-claim, and multi-repo probe isolation."""
        import agent_autopilot as ap_cli
        from ap_core.git_gate import prepare_trusted_base_cache
        from ap_core.github_flow import LiveGitHubCliTransport
        from ap_core.routine_flow import probe_github_issues_zero_token

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            # 1. Real Git commit with Cargo.toml + Cargo.lock -> prepare_trusted_base_cache resolves base_sha^{tree}
            #    and live `cargo check --locked --offline` succeeds inside verify_ring bwrap with RUSTUP_HOME!
            cargo_bin = shutil.which("cargo") or (str(Path.home() / ".cargo" / "bin" / "cargo") if (Path.home() / ".cargo" / "bin" / "cargo").is_file() else None)
            if cargo_bin:
                rust_repo = base / "rust_repo"
                rust_repo.mkdir()
                subprocess.run(["git", "init", "-q", "-b", "main"], cwd=rust_repo, check=True)
                subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=rust_repo, check=True)
                subprocess.run(["git", "config", "user.name", "Tester"], cwd=rust_repo, check=True)
                (rust_repo / "src").mkdir()
                (rust_repo / "Cargo.toml").write_text(
                    '[package]\nname = "ap_smoke"\nversion = "0.1.0"\nedition = "2021"\n',
                    encoding="utf-8",
                )
                (rust_repo / "src" / "lib.rs").write_text("pub fn add(a: i32, b: i32) -> i32 { a + b }\n", encoding="utf-8")
                c_env = dict(os.environ, PATH=f"{Path.home() / '.cargo' / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}")
                subprocess.run([cargo_bin, "generate-lockfile"], cwd=rust_repo, env=c_env, check=True, capture_output=True)
                subprocess.run(["git", "add", "Cargo.toml", "Cargo.lock", "src/lib.rs"], cwd=rust_repo, check=True)
                subprocess.run(["git", "commit", "-q", "-m", "init cargo crate"], cwd=rust_repo, check=True)
                rust_commit_sha = resolve_commit_oid(rust_repo, "HEAD")

                mg_rust = ensure_managed_bare_repo(rust_repo, base / "mg_rust.git")
                tbc_rust = prepare_trusted_base_cache(
                    managed_gitdir=mg_rust, base_sha=rust_commit_sha, cache_root=base / "rust_cache"
                )
                self.assertIsNotNone(tbc_rust)
                assert tbc_rust is not None
                self.assertTrue((tbc_rust / "cargo_home").is_dir())

                v_rust_argv = build_execution_ring_bwrap(
                    ring_kind="verify_ring",
                    inner_cmd=["/bin/bash", "-lc", "cargo check --locked --offline"],
                    cwd=base / "rust_vo",
                    clean_tree=rust_repo,
                    verify_out_dir=base / "rust_vo",
                    trusted_base_cache=tbc_rust,
                )
                self.assertIn("CARGO_HOME", v_rust_argv)
                if (Path.home() / ".rustup").is_dir():
                    self.assertIn("RUSTUP_HOME", v_rust_argv)
                rust_chk = subprocess.run(v_rust_argv, capture_output=True, text=True, timeout=60, check=False)
                self.assertEqual(rust_chk.returncode, 0, msg=rust_chk.stderr + rust_chk.stdout)

            db7 = AutopilotDB(base / "r7.db")
            try:
                cfg_a = WorkflowConfig(project_id="proj_a", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T3", write_scope=("src/**",), merge_paths=("src/**",))
                cfg_b = WorkflowConfig(project_id="proj_b", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T3", write_scope=("src/**",))
                db7.upsert_project(cfg_a)
                db7.upsert_project(cfg_b)
                db7.ensure_lease_slots("proj_a", ["proj_a:slot-1"], base / "locks7")

                # 2. Cross-project ownership conflict across shared PR scope quarantines ALL compensation (0 convert_pr_to_draft!)
                db7.ensure_work_unit(unit_key="UA_CONF", project_id="proj_a", repo="o/r", issue_number=70, pr_id="PR_CONF")
                with db7.immediate_tx():
                    db7._conn.execute(
                        "INSERT INTO external_ops(op_id, op_seq, unit_key, project_id, pr_id, op_type, owner_kind, owner_epoch, status, send_consumed, prepared_at, updated_at) "
                        "VALUES ('op-proj-b', 1, 'UA_CONF', 'proj_b', 'PR_CONF', 'mark_pr_ready', 'worker', 1, 'unknown_paused', 1, '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')"
                    )
                    db7._conn.execute("UPDATE work_units SET veto_pending = 1, veto_remote_sync_pending = 1 WHERE unit_key = 'UA_CONF'")
                tr_conf = FakeGitHubTransport()
                tr_conf.prs["PR_CONF"] = PrSnapshot(pr_id="PR_CONF", state="OPEN", is_draft=False, head_ref_oid="c70", head_ref_name="agent/70", base_ref_name="main")
                ep7 = db7.bump_dispatcher_epoch()
                ap_cli.supervisor_recover_and_reconcile(db7, ep7, {"proj_a": cfg_a, "proj_b": cfg_b}, transport_override=tr_conf)
                self.assertEqual(len(tr_conf.sent_ops_log), 0, "Cross-project PR scope conflict MUST quarantine all automatic compensation!")
                self.assertEqual(db7.get_unit("UA_CONF")["terminal_state"], "needs-human")

                # 3. Worker bound to `bot-a` crashes after consuming grant; `bot-b` enqueues candidate 2s later; supervisor running as `bot-b` MUST keep unknown_paused!
                db7.ensure_work_unit(unit_key="U_ENQ_A", project_id="proj_a", repo="o/r", issue_number=71, pr_id="PR_71")
                ce_a = db7.claim_and_reserve(
                    unit_key="U_ENQ_A", cfg=cfg_a, slot_keys=["proj_a:slot-1"], worker_unit_name="ap-nonexist-71.service",
                    expected_cgroup_dir="/sys/fs/cgroup/nonexist_71", base_sha="0000000", authorized_head_ref="agent/71",
                    bound_gh_login="bot-a", ephemeral_token_file="/tmp/ap-test.tok",
                )
                db7.set_current_candidate(unit_key="U_ENQ_A", candidate_sha="cand7100", claim_epoch=ce_a)
                db7.record_verify_receipt(unit_key="U_ENQ_A", candidate_sha="cand7100", dod_cmd="true", exit_code=0, ui_verified=False, artifact_dir="/tmp", touched_paths=("src/a.py",))
                db7.record_review_receipt(unit_key="U_ENQ_A", candidate_sha="cand7100", writer_family="codex", referee_family="claude", referee_model="claude-fable-5-2", verdict="APPROVE", defect_count=0, defects=[], raw_path="/tmp/r.json")
                op_rdy71 = db7.prepare_op(unit_key="U_ENQ_A", op_type="mark_pr_ready", claim_epoch=ce_a, candidate_sha="cand7100")
                g_rdy71 = db7.promote_op_to_in_flight(op_rdy71, caller_owner_kind="worker", caller_epoch=ce_a)
                tr_a = FakeGitHubTransport()
                tr_a.bot_login = "bot-a"
                tr_a.prs["PR_71"] = PrSnapshot(pr_id="PR_71", state="OPEN", is_draft=True, head_ref_oid="cand7100", head_ref_name="agent/71", base_ref_name="main")
                execute_granted_op(grant=g_rdy71, db=db7, transport=tr_a, repo="o/r")
                tr_b = FakeGitHubTransport()
                tr_b.bot_login = "bot-b"
                # Force mark_pr_ready succeeded_verified so we can prepare enqueue_pr:
                with db7.immediate_tx():
                    db7._conn.execute("UPDATE external_ops SET status = 'succeeded_verified', remote_receipt_id = 'rdy-ok' WHERE op_id = ?", (op_rdy71,))
                    db7._conn.execute("UPDATE external_ops SET prepared_at = '2026-11-24T10:00:00+00:00' WHERE op_id = ?", (op_rdy71,))
                op_enq_a = db7.prepare_op(unit_key="U_ENQ_A", op_type="enqueue_pr", claim_epoch=ce_a, candidate_sha="cand7100")
                with db7.immediate_tx():
                    db7._conn.execute("UPDATE external_ops SET prepared_at = '2026-11-24T10:00:01+00:00' WHERE op_id = ?", (op_enq_a,))
                g_enq_a = db7.promote_op_to_in_flight(op_enq_a, caller_owner_kind="worker", caller_epoch=ce_a)
                db7.consume_send_grant(g_enq_a)
                db7.begin_reclaim_claim(ce_a)
                db7.finish_reclaim_leases_free(ce_a, cleanup_rc=0, unit_terminated=True, worktree_clean=True)

                tr_b.prs["PR_71"] = PrSnapshot(
                    pr_id="PR_71", state="OPEN", is_draft=False, head_ref_oid="cand7100",
                    head_ref_name="agent/71", base_ref_name="main",
                    merge_queue_entry_id="MQ_BY_B", merge_queue_enqueuer="bot-b",
                    merge_queue_enqueued_at="2026-11-24T10:00:05Z",
                    enqueue_event_timestamps=("2026-11-24T10:00:05Z",),
                )
                r_enq_b = reconcile_op(db=db7, transport=tr_b, repo="o/r", op_id=op_enq_a, sender_confirmed_terminated=True, dispatcher_epoch=db7.bump_dispatcher_epoch())
                self.assertEqual(r_enq_b["status"], "unknown_paused", "Account B enqueue MUST NEVER satisfy worker A's receipt-less enqueue_pr!")

                # 4. Rejected claim_and_reserve writes ZERO `.bound_gh_token` files to disk!
                db7.ensure_work_unit(unit_key="o/r#72", project_id="proj_a", repo="o/r", issue_number=72)
                with db7.immediate_tx():
                    db7._conn.execute("UPDATE work_units SET status = 'published' WHERE unit_key = 'o/r#72'")
                cache_override = base / "cache72"
                with unittest.mock.patch.dict(os.environ, {"AGENT_AUTOPILOT_CACHE_DIR": str(cache_override)}):
                    with self.assertRaises(AutopilotError):
                        ap_cli._submit_issue_worker_nonblocking(
                            cfg=cfg_a,
                            db=db7,
                            state_root=base / "state72",
                            cand={"unit_key": "o/r#72", "repo": "o/r", "number": 72, "title": "Already published"},
                            prefetched_bases={"o/r": (base / "mg.git", "0000000")},
                            pre_resolved_gh=("ghp_never_leak", "bot-a"),
                        )
                leaked_toks = list(cache_override.rglob(".bound_gh_token"))
                self.assertEqual(leaked_toks, [], "Rejected reservation MUST write ZERO token files to disk!")

                # 5. LiveGitHubCliTransport.bot_login is uncached (queries every call) & multi-repo probe isolates per-repo errors!
                live_id_tr = LiveGitHubCliTransport(token="ghp_test", require_explicit_token=True)
                with unittest.mock.patch(
                    "subprocess.run",
                    side_effect=[
                        subprocess.CompletedProcess(["gh"], 0, "bot-a\n", ""),
                        subprocess.CompletedProcess(["gh"], 0, "bot-b\n", ""),
                    ],
                ) as m_run:
                    self.assertEqual(live_id_tr.bot_login, "bot-a")
                    self.assertEqual(live_id_tr.bot_login, "bot-b")
                    self.assertEqual(m_run.call_count, 2)

                cfg_multi = WorkflowConfig(project_id="pm", kind="issue", enabled=True, repos=("o/good", "o/denied"), workspace_path=str(base), write_scope=("src/**",))
                db7.upsert_project(cfg_multi)
                with unittest.mock.patch(
                    "subprocess.run",
                    side_effect=[
                        subprocess.CompletedProcess(["gh"], 0, json.dumps([{"number": 5, "title": "Fix bug", "labels": []}]), ""),
                        subprocess.CompletedProcess(["gh"], 1, "", "HTTP 403 Resource not accessible"),
                    ],
                ):
                    m_prb = probe_github_issues_zero_token(cfg_multi, db7)
                self.assertTrue(m_prb["actionable"])
                self.assertEqual([c["unit_key"] for c in m_prb["candidates"]], ["o/good#5"])
                self.assertIn("o/denied", m_prb["repo_errors"])
            finally:
                db7.close()

    def test_round8_all_codex_closures(self) -> None:
        """Regression suite covering all 8 Round-8 Codex Astra findings."""
        import argparse
        import io
        import agent_autopilot as ap_cli
        from ap_core.git_gate import prepare_trusted_base_cache
        from ap_core.models import QuotaExhaustedError, parse_workflow_file
        from ap_core.routine_flow import probe_github_issues_zero_token

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            # 1. Cargo cold-cache bwrap isolation: `.cargo/config.toml` `rustc-wrapper` CANNOT read outside host files!
            cargo_bin = shutil.which("cargo") or (str(Path.home() / ".cargo" / "bin" / "cargo") if (Path.home() / ".cargo" / "bin" / "cargo").is_file() else None)
            if cargo_bin:
                secret_other = base / "other_project_secret.txt"
                secret_other.write_text("TOP_SECRET_OTHER_PROJ", encoding="utf-8")
                mal_repo = base / "mal_rust"
                mal_repo.mkdir()
                subprocess.run(["git", "init", "-q", "-b", "main"], cwd=mal_repo, check=True)
                subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=mal_repo, check=True)
                subprocess.run(["git", "config", "user.name", "Tester"], cwd=mal_repo, check=True)
                (mal_repo / "src").mkdir()
                (mal_repo / ".cargo").mkdir()
                (mal_repo / "Cargo.toml").write_text('[package]\nname = "mal_smoke"\nversion = "0.1.0"\nedition = "2021"\n', encoding="utf-8")
                (mal_repo / "src" / "lib.rs").write_text("pub fn x() -> i32 { 1 }\n", encoding="utf-8")
                # Plant a wrapper script inside the repo that FAILS (exit 99) if it can read `secret_other`!
                wrap_sh = mal_repo / "wrapper.sh"
                wrap_sh.write_text(
                    f"#!/bin/sh\nif [ -f '{secret_other}' ]; then echo LEAKED >&2; exit 99; fi\nexec \"$@\"\n",
                    encoding="utf-8",
                )
                os.chmod(wrap_sh, 0o755)
                (mal_repo / ".cargo" / "config.toml").write_text('[build]\nrustc-wrapper = "./wrapper.sh"\n', encoding="utf-8")
                c_env = dict(os.environ, PATH=f"{Path.home() / '.cargo' / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}")
                subprocess.run([cargo_bin, "generate-lockfile"], cwd=mal_repo, env=c_env, check=True, capture_output=True)
                subprocess.run(["git", "add", "."], cwd=mal_repo, check=True)
                subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=mal_repo, check=True)
                mal_sha = resolve_commit_oid(mal_repo, "HEAD")
                mg_mal = ensure_managed_bare_repo(mal_repo, base / "mg_mal.git")
                tbc_mal = prepare_trusted_base_cache(managed_gitdir=mg_mal, base_sha=mal_sha, cache_root=base / "mal_cache")
                self.assertIsNotNone(tbc_mal)

            # 8. Nested Rust workspace (`expert-trajectory/Cargo.toml` without root `Cargo.toml`) gets `--manifest-path`!
            nested_ws = base / "nested_rust_ws"
            (nested_ws / "expert-trajectory").mkdir(parents=True)
            (nested_ws / "expert-trajectory" / "Cargo.toml").write_text('[package]\nname="et"\nversion="0.1.0"\n', encoding="utf-8")
            ob_nested = onboard_project(
                project_id="nested-rs",
                kind="issue",
                workspace_path=nested_ws,
                repos=["o/nested"],
                config_root=base / "cfg_n",
                state_root=base / "st_n",
            )
            wf_nested = parse_workflow_file(Path(ob_nested["workflow_path"]))
            self.assertEqual(wf_nested.verify_cmd, "cargo check --manifest-path expert-trajectory/Cargo.toml")

            db8 = AutopilotDB(base / "r8.db")
            try:
                cfg_p1 = WorkflowConfig(project_id="p1", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                cfg_p2 = WorkflowConfig(project_id="p2", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                db8.upsert_project(cfg_p1)
                db8.upsert_project(cfg_p2)
                db8.ensure_lease_slots("p1", ["p1:slot-1"], base / "locks8")

                # 2a. Released historical claim from project p2 with ZERO ops still quarantines p1 unit!
                db8.ensure_work_unit(unit_key="U_REL_CLAIM", project_id="p1", repo="o/r", issue_number=80, pr_id="PR_80")
                with db8.immediate_tx():
                    db8._conn.execute(
                        "INSERT INTO run_claims(claim_epoch, unit_key, project_id, repo, slot_vector_json, worker_unit_name, expected_cgroup_dir, base_sha, authorized_base_ref, authorized_head_ref, policy_version, effective_tier, frozen_write_scope_json, frozen_merge_paths_json, merge_method, state, created_at) "
                        "VALUES (500, 'U_REL_CLAIM', 'p2', 'o/r', '[]', 'old.service', '/cg/old', '000', 'main', 'agent/80', 'v1', 'T2', '[\"src/**\"]', '[]', 'SQUASH', 'released', '2026-01-01T00:00:00+00:00')"
                    )
                    db8._conn.execute("UPDATE work_units SET veto_pending = 1, veto_remote_sync_pending = 1 WHERE unit_key = 'U_REL_CLAIM'")
                tr8 = FakeGitHubTransport()
                tr8.prs["PR_80"] = PrSnapshot(pr_id="PR_80", state="OPEN", is_draft=False, head_ref_oid="c80", head_ref_name="agent/80", base_ref_name="main")
                ap_cli.supervisor_recover_and_reconcile(db8, db8.bump_dispatcher_epoch(), {"p1": cfg_p1, "p2": cfg_p2}, transport_override=tr8)
                self.assertEqual(len(tr8.sent_ops_log), 0)

                # 2b. Two-sided PR conflict: U_LEFT binds PR_B with historical op on PR_A; U_RIGHT binds PR_A with pending convert_pr_to_draft -> BOTH quarantined!
                db8.ensure_work_unit(unit_key="U_LEFT", project_id="p1", repo="o/r", issue_number=81, pr_id="PR_B")
                db8.ensure_work_unit(unit_key="U_RIGHT", project_id="p1", repo="o/r", issue_number=82, pr_id="PR_A")
                ep_old = db8.bump_dispatcher_epoch()
                adm_right = db8.register_admin_revoke(unit_key="U_RIGHT", dispatcher_epoch=ep_old, pr_id="PR_A", need_draft=True, reason="veto_r")
                with db8.immediate_tx():
                    db8._conn.execute(
                        "INSERT INTO external_ops(op_id, op_seq, unit_key, project_id, pr_id, op_type, owner_kind, owner_epoch, status, send_consumed, prepared_at, updated_at) "
                        "VALUES ('op-pr-conflict', 999, 'U_LEFT', 'p1', 'PR_A', 'post_comment', 'worker', 1, 'succeeded_verified', 1, '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')"
                    )
                tr8.prs["PR_A"] = PrSnapshot(pr_id="PR_A", state="OPEN", is_draft=False, head_ref_oid="ca", head_ref_name="agent/82", base_ref_name="main")
                ep_new = db8.bump_dispatcher_epoch()
                ap_cli.supervisor_recover_and_reconcile(db8, ep_new, {"p1": cfg_p1}, transport_override=tr8)
                self.assertEqual(len(tr8.sent_ops_log), 0, "Two-sided PR conflict MUST block replacement and promotion on U_RIGHT!")
                self.assertFalse(
                    db8.promote_op_to_in_flight(adm_right[0], caller_owner_kind="supervisor_admin", caller_epoch=ep_old, dispatcher_lock_held=True, all_scope_workers_terminated=True).granted
                )

                # 3. Manual `cmd_veto` on cross-project shared PR freezes locally WITHOUT sending convert_pr_to_draft!
                sroot_v = base / "st_veto"
                db_v = AutopilotDB(sroot_v / "autopilot.db")
                try:
                    db_v.upsert_project(cfg_p1)
                    db_v.upsert_project(cfg_p2)
                    db_v.ensure_work_unit(unit_key="VA", project_id="p1", repo="o/r", issue_number=1, pr_id="PR_SHARED_V")
                    # Normal API blocks cross-project binding; plant legacy conflicted row via SQL to test cmd_veto quarantine!
                    with self.assertRaises(ScopeConflictError):
                        db_v.ensure_work_unit(unit_key="VB", project_id="p2", repo="o/r", issue_number=2, pr_id="PR_SHARED_V")
                    with db_v.immediate_tx():
                        db_v._conn.execute(
                            "INSERT INTO work_units(unit_key, project_id, repo, issue_number, status, pr_id, created_at, updated_at) "
                            "VALUES ('VB', 'p2', 'o/r', 2, 'queued', 'PR_SHARED_V', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')"
                        )
                finally:
                    db_v.close()
                buf_v = io.StringIO()
                with unittest.mock.patch.dict(os.environ, {"AGENT_AUTOPILOT_STATE_DIR": str(sroot_v)}), unittest.mock.patch("sys.stdout", buf_v):
                    rc_v = ap_cli.cmd_veto(argparse.Namespace(unit_key="VA", reason="test_conflict_veto"))
                self.assertEqual(rc_v, 0)
                v_payload = json.loads(buf_v.getvalue())
                self.assertTrue(v_payload["quarantined_scope_conflict"])
                self.assertEqual(v_payload["admin_ops"], [])

                # 4. Pre-upgrade active claim lacking `bound_gh_login` or `ephemeral_token_file` CANNOT prepare/promote/execute new writes,
                #    while already-sent `in_flight` ops STILL reconcile!
                db8.ensure_work_unit(unit_key="U_LEG_ACT", project_id="p1", repo="o/r", issue_number=84, pr_id="PR_84")
                ce_leg = db8.claim_and_reserve(
                    unit_key="U_LEG_ACT", cfg=cfg_p1, slot_keys=["p1:slot-1"], worker_unit_name="ap-nonexist-84.service",
                    expected_cgroup_dir="/sys/fs/cgroup/nonexist_84", base_sha="000", authorized_head_ref="agent/84",
                    bound_gh_login="", ephemeral_token_file="",
                )
                with self.assertRaises(AutopilotError):
                    db8.prepare_op(unit_key="U_LEG_ACT", op_type="post_comment", claim_epoch=ce_leg)
                with db8.immediate_tx():
                    db8._conn.execute(
                        "INSERT INTO external_ops(op_id, op_seq, unit_key, project_id, pr_id, op_type, owner_kind, owner_epoch, claim_epoch, status, send_consumed, grant_token, prepared_at, updated_at) "
                        "VALUES ('op-leg-prep', 1001, 'U_LEG_ACT', 'p1', 'PR_84', 'post_comment', 'worker', ?, ?, 'prepared_local', 0, '', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                        (ce_leg, ce_leg),
                    )
                    db8._conn.execute(
                        "INSERT INTO external_ops(op_id, op_seq, unit_key, project_id, pr_id, op_type, owner_kind, owner_epoch, claim_epoch, ref_id_hmac, payload_json, status, send_consumed, prepared_at, updated_at) "
                        "VALUES ('op-leg-sent', 1002, 'U_LEG_ACT', 'p1', 'PR_84', 'post_comment', 'worker', ?, ?, 'ap-leg84', '{\"subjectId\":\"PR_84\"}', 'in_flight', 1, '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                        (ce_leg, ce_leg),
                    )
                self.assertFalse(db8.promote_op_to_in_flight("op-leg-prep", caller_owner_kind="worker", caller_epoch=ce_leg).granted)
                tr_leg = FakeGitHubTransport()
                tr_leg.comments.setdefault("PR_84", []).append("hello\nRef-ID: ap-leg84")
                rec_sent = reconcile_op(db=db8, transport=tr_leg, repo="o/r", op_id="op-leg-sent", sender_confirmed_terminated=True, dispatcher_epoch=db8.bump_dispatcher_epoch())
                self.assertEqual(rec_sent["status"], "succeeded_verified")
                db8.begin_reclaim_claim(ce_leg)
                db8.finish_reclaim_leases_free(ce_leg, cleanup_rc=0, unit_terminated=True, worktree_clean=True)

                # 5. Stale in-memory WorkflowConfig rejected when DB token_file was rotated from tokA -> tokB!
                tok_a = base / "tokA"
                tok_b = base / "tokB"
                tok_a.write_text("ghp_old_A\n", encoding="utf-8")
                tok_b.write_text("ghp_new_B\n", encoding="utf-8")
                stale_cfg = WorkflowConfig(project_id="p_rot", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), token_file=str(tok_a), write_scope=("src/**",))
                fresh_cfg = WorkflowConfig(project_id="p_rot", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), token_file=str(tok_b), write_scope=("src/**",))
                db8.upsert_project(fresh_cfg)
                with self.assertRaises(AutopilotError):
                    ap_cli._resolve_strict_project_gh_transport(db8, "p_rot", {"p_rot": stale_cfg})

                # 6. Per-repo `TimeoutExpired` in `probe_github_issues_zero_token` preserves healthy repo's issues!
                cfg_to = WorkflowConfig(project_id="p_to", kind="issue", enabled=True, repos=("o/healthy", "o/slow"), workspace_path=str(base), write_scope=("src/**",))
                db8.upsert_project(cfg_to)
                with unittest.mock.patch(
                    "subprocess.run",
                    side_effect=[
                        subprocess.CompletedProcess(["gh"], 0, json.dumps([{"number": 9, "title": "Healthy issue", "labels": []}]), ""),
                        subprocess.TimeoutExpired(cmd=["gh", "issue", "list"], timeout=25),
                    ],
                ):
                    to_prb = probe_github_issues_zero_token(cfg_to, db8)
                self.assertTrue(to_prb["actionable"])
                self.assertEqual([c["unit_key"] for c in to_prb["candidates"]], ["o/healthy#9"])
                self.assertIn("o/slow", to_prb["repo_errors"])

                # 7. Referee QuotaExhaustedError across 3 consecutive quota hits refunds review_rounds_used (stays 0) and NEVER escalates to needs-human!
                repo_q = base / "repo_q"
                sha_q = _init_git_repo(repo_q)
                mg_q = ensure_managed_bare_repo(repo_q, base / "mg_q.git")
                cfg_q = WorkflowConfig(project_id="p1", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(repo_q), trust_tier="T2", write_scope=("src/**",))
                db8.ensure_work_unit(unit_key="o/r#88", project_id="p1", repo="o/r", issue_number=88)

                class _QuotaRefereeRunner(_ScriptedChefRunner):
                    def run_referee(self, **kwargs):
                        return ModelTurnResult(
                            raw_stdout="You've hit your 5-hour limit · resets 11:59pm (America/Los_Angeles)",
                            raw_stderr="",
                            exit_code=1,
                            model_used="claude-fable-5-2",
                        )

                for _ in range(3):
                    with db8.immediate_tx():
                        db8._conn.execute("UPDATE work_units SET waiting_until = NULL, status = 'queued' WHERE unit_key = 'o/r#88'")
                    ce_q = db8.claim_and_reserve(
                        unit_key="o/r#88", cfg=cfg_q, slot_keys=["p1:slot-1"], worker_unit_name="wq.service",
                        expected_cgroup_dir="/cg/wq", base_sha=sha_q, authorized_head_ref="agent/88",
                        bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                    )
                    with self.assertRaises(QuotaExhaustedError):
                        execute_chef_issue_pipeline(
                            db=db8, cfg=cfg_q, unit_key="o/r#88", repo="o/r", issue_summary="#88 Quota test",
                            claim_epoch=ce_q, managed_gitdir=mg_q, worktree_dir=base / f"wt_q_{ce_q}",
                            repo_main=repo_q, run_dir=base / f"run_q_{ce_q}", advisory_dir=base / "adv_q",
                            model_runner=_QuotaRefereeRunner([0], use_outbox=False),
                            gh_transport=FakeGitHubTransport(), hmac_secret=b"sec",
                        )
                    db8.begin_reclaim_claim(ce_q)
                    db8.finish_reclaim_leases_free(ce_q, cleanup_rc=0, unit_terminated=True, worktree_clean=True)
                    uq = db8.get_unit("o/r#88")
                    self.assertEqual(uq["status"], "waiting_quota")
                    self.assertIsNone(uq["terminal_state"])
                    self.assertEqual(int(uq["review_rounds_used"]), 0, "Referee quota MUST refund reserved review round!")
                    self.assertEqual(int(uq["failure_streak"]), 0, "Quota wait MUST NOT increment failure_streak!")
            finally:
                db8.close()

    def test_round9_all_codex_closures(self) -> None:
        """Regression suite covering all 6 Round-9 Codex Astra findings."""
        import agent_autopilot as ap_cli
        from ap_core.models import SandboxError, parse_workflow_file, render_workflow_markdown
        from ap_core.sandbox import (
            prepare_workspace_node_modules_bind_args,
            run_isolated_deps_prefetch,
            verify_trusted_base_cache_integrity,
        )

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            # 1 & 2. Symlinked `.ready`, `node_modules`, `cargo_home`, or escaping symlink inside cache MUST raise SandboxError!
            outside_victim = base / "victim.txt"
            outside_victim.write_text("DO_NOT_OVERWRITE", encoding="utf-8")
            outside_dir = base / "outside_dir"
            outside_dir.mkdir()
            (outside_dir / "secret.txt").write_text("SECRET", encoding="utf-8")

            bad_cache1 = base / "bad_cache_ready"
            bad_cache1.mkdir()
            (bad_cache1 / ".ready").symlink_to(outside_victim)
            with self.assertRaises(SandboxError):
                verify_trusted_base_cache_integrity(bad_cache1)
            self.assertEqual(outside_victim.read_text(encoding="utf-8"), "DO_NOT_OVERWRITE")

            bad_cache2 = base / "bad_cache_nm"
            bad_cache2.mkdir()
            (bad_cache2 / "node_modules").symlink_to(outside_dir)
            tgt_ws = base / "tgt_ws"
            tgt_ws.mkdir()
            with self.assertRaises(SandboxError):
                prepare_workspace_node_modules_bind_args(bad_cache2, tgt_ws)

            bad_cache3 = base / "bad_cache_escape"
            (bad_cache3 / "node_modules" / ".bin").mkdir(parents=True)
            (bad_cache3 / "node_modules" / ".bin" / "evil").symlink_to("../../../victim.txt")
            with self.assertRaises(SandboxError):
                verify_trusted_base_cache_integrity(bad_cache3)

            # 3. `run_isolated_deps_prefetch` runs inside `--unshare-net`: host loopback service is 100% UNREACHABLE,
            #    and CONNECT proxy blocks non-registry domains (403 Forbidden)!
            host_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host_listener.bind(("127.0.0.1", 0))
            host_port = host_listener.getsockname()[1]
            host_listener.listen(4)
            try:
                pf_stage = base / "pf_stage"
                pf_stage.mkdir()
                probe_py = (
                    "import os, socket, sys\n"
                    # Attempt 1: connect directly to host loopback -> MUST fail in isolated --unshare-net!
                    "s = socket.socket()\ns.settimeout(1.5)\n"
                    f"try:\n  s.connect(('127.0.0.1', {host_port}))\n  sys.exit(91)\nexcept OSError:\n  pass\n"
                    # Attempt 2: ask HTTPS_PROXY to CONNECT to evil.example:443 -> MUST get 403 Forbidden!
                    "hp = os.environ['HTTPS_PROXY'].replace('http://', '')\n"
                    "h, p = hp.split(':')\n"
                    "ps = socket.create_connection((h, int(p)), timeout=2.0)\n"
                    "ps.sendall(b'CONNECT evil.example:443 HTTP/1.1\\r\\nHost: evil.example:443\\r\\n\\r\\n')\n"
                    "resp = ps.recv(256)\n"
                    "sys.exit(0 if b'403' in resp else 92)\n"
                )
                pf_res = run_isolated_deps_prefetch(
                    inner_cmd=["/usr/bin/python3", "-c", probe_py],
                    cwd=pf_stage,
                    stage_dir=pf_stage,
                    timeout=20,
                )
                self.assertEqual(pf_res.returncode, 0, msg=pf_res.stderr + pf_res.stdout)
            finally:
                host_listener.close()

            # 4. Late cross-project conflict emerging AFTER `promote_op_to_in_flight` is caught atomically inside `consume_send_grant`!
            db9 = AutopilotDB(base / "r9.db")
            try:
                cfg_a = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                cfg_b = WorkflowConfig(project_id="pb", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                db9.upsert_project(cfg_a)
                db9.upsert_project(cfg_b)
                db9.ensure_lease_slots("pa", ["pa:s1"], base / "locks9")
                db9.ensure_work_unit(unit_key="UA9", project_id="pa", repo="o/r", issue_number=91, pr_id="PR_91")
                ce9 = db9.claim_and_reserve(
                    unit_key="UA9", cfg=cfg_a, slot_keys=["pa:s1"], worker_unit_name="ua9.service",
                    expected_cgroup_dir="/cg/ua9", base_sha="000", authorized_head_ref="agent/91",
                    bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                )
                db9.set_current_candidate(unit_key="UA9", candidate_sha="cand9100", claim_epoch=ce9)
                db9.record_verify_receipt(unit_key="UA9", candidate_sha="cand9100", dod_cmd="true", exit_code=0, ui_verified=False, artifact_dir="/tmp", touched_paths=("src/a.py",))
                db9.record_review_receipt(unit_key="UA9", candidate_sha="cand9100", writer_family="codex", referee_family="claude", referee_model="claude-fable-5-2", verdict="APPROVE", defect_count=0, defects=[], raw_path="/tmp/r.json")
                op_r9 = db9.prepare_op(unit_key="UA9", op_type="mark_pr_ready", claim_epoch=ce9, candidate_sha="cand9100")
                g_r9 = db9.promote_op_to_in_flight(op_r9, caller_owner_kind="worker", caller_epoch=ce9)
                self.assertTrue(g_r9.granted)
                # Normal API blocks cross-project binding; plant conflicted row via SQL to test consume_send_grant defense-in-depth!
                with self.assertRaises(ScopeConflictError):
                    db9.ensure_work_unit(unit_key="UB9", project_id="pb", repo="o/r", issue_number=92, pr_id="PR_91")
                with db9.immediate_tx():
                    db9._conn.execute(
                        "INSERT INTO work_units(unit_key, project_id, repo, issue_number, status, pr_id, created_at, updated_at) "
                        "VALUES ('UB9', 'pb', 'o/r', 92, 'queued', 'PR_91', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')"
                    )
                tr9 = FakeGitHubTransport()
                tr9.prs["PR_91"] = PrSnapshot(pr_id="PR_91", state="OPEN", is_draft=True, head_ref_oid="cand9100", head_ref_name="agent/91", base_ref_name="main")
                with self.assertRaises(ScopeConflictError):
                    execute_granted_op(grant=g_r9, db=db9, transport=tr9, repo="o/r")
                self.assertEqual(len(tr9.sent_ops_log), 0, "Late scope conflict MUST block transmission inside consume_send_grant!")
                op_after = db9.get_op(op_r9)
                self.assertEqual(op_after["status"], "not_executed")
                self.assertEqual(int(op_after["send_consumed"]), 0)
                self.assertEqual(db9.get_unit("UA9")["veto_pending"], 1)
                self.assertEqual(db9.get_unit("UB9")["veto_pending"], 1)

                # 5. Reloaded WORKFLOW.md with mismatched `project_id` rejected, AND switching disk WORKFLOW.md from dedicated -> ambient drops old DB token!
                wf_path_a = base / "WORKFLOW_A.md"
                old_tok_f = base / "old_ded.tok"
                old_tok_f.write_text("ghp_OLD_DEDICATED\n", encoding="utf-8")
                wf_ded = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), token_file=str(old_tok_f), write_scope=("src/**",))
                db9.upsert_project(wf_ded)
                # Write valid ambient WORKFLOW.md for `pa` (token_file="") -> must NOT resurrect `old_ded.tok` from DB!
                wf_amb_disk = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), token_file="", write_scope=("src/**",))
                wf_path_a.write_text(render_workflow_markdown(wf_amb_disk), encoding="utf-8")
                parsed_amb = parse_workflow_file(wf_path_a)
                resolved_tr = ap_cli._resolve_strict_project_gh_transport(db9, "pa", {"pa": parsed_amb})
                self.assertIsNone(resolved_tr._token)
                self.assertFalse(resolved_tr._require_explicit_token)
                # Now tamper `wf_path_a` on disk to declare `project_id: pb` -> resolving for `pa` MUST raise AutopilotError!
                wf_wrong_id = WorkflowConfig(project_id="pb", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), token_file=str(old_tok_f), write_scope=("src/**",))
                wf_path_a.write_text(render_workflow_markdown(wf_wrong_id), encoding="utf-8")
                with self.assertRaises(AutopilotError):
                    ap_cli._resolve_strict_project_gh_transport(db9, "pa", {"pa": parsed_amb})
            finally:
                db9.close()

            # 6. Root Cargo workspace with `expert-trajectory/` member preserves `expert-trajectory/**` in `write_scope`!
            ws_cargo_root = base / "ws_cargo_root"
            (ws_cargo_root / "expert-trajectory" / "src").mkdir(parents=True)
            (ws_cargo_root / "Cargo.toml").write_text('[workspace]\nmembers = ["expert-trajectory"]\n', encoding="utf-8")
            (ws_cargo_root / "expert-trajectory" / "Cargo.toml").write_text('[package]\nname="et"\nversion="0.1.0"\n', encoding="utf-8")
            ob_ws_rs = onboard_project(
                project_id="ws-rs",
                kind="issue",
                workspace_path=ws_cargo_root,
                repos=["o/ws-rs"],
                config_root=base / "cfg_ws_rs",
                state_root=base / "st_ws_rs",
            )
            wf_ws_rs = parse_workflow_file(Path(ob_ws_rs["workflow_path"]))
            self.assertEqual(wf_ws_rs.verify_cmd, "cargo check")
            self.assertIn("expert-trajectory/**", wf_ws_rs.write_scope)
            check_autopilot_scope(["expert-trajectory/src/lib.rs"], wf_ws_rs.write_scope)

    def test_round10_all_codex_closures(self) -> None:
        """Regression suite covering all 5 Round-10 Codex Astra findings."""
        import argparse
        import agent_autopilot as ap_cli
        from ap_core.git_gate import prepare_trusted_base_cache

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            # 1. `scrub_worktree_to_base` refuses standalone repo (preserving its `.git`!) & `cmd_scrub_worktree` accepts ONLY `--claim-epoch`!
            standalone = base / "standalone_repo"
            s_sha = _init_git_repo(standalone)
            mg_other = ensure_managed_bare_repo(standalone, base / "mg_other.git")
            wt_other, wt_gd_other = prepare_isolated_worktree(managed_gitdir=mg_other, worktree_dir=base / "wt_other", base_sha=s_sha)
            with self.assertRaises(AutopilotError):
                scrub_worktree_to_base(managed_gitdir=mg_other, wt_gitdir=wt_gd_other, worktree=standalone, base_sha=s_sha)
            self.assertTrue((standalone / ".git" / "HEAD").is_file(), "Standalone repository .git MUST remain untouched!")
            parser = ap_cli.build_parser()
            with self.assertRaises(SystemExit):
                parser.parse_args(["scrub-worktree", "--worktree", str(standalone)])

            # 2. Cross-project PR binding blocked in `ensure_work_unit` / `resolve_unit_scope_and_pending`,
            #    AND even a raw-SQL conflict injected AFTER `consume_send_grant` aborts before network send!
            db10 = AutopilotDB(base / "r10.db")
            try:
                cfg_a = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                cfg_b = WorkflowConfig(project_id="pb", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                db10.upsert_project(cfg_a)
                db10.upsert_project(cfg_b)
                db10.ensure_lease_slots("pa", ["pa:s1"], base / "locks10")
                db10.ensure_work_unit(unit_key="UA10", project_id="pa", repo="o/r", issue_number=101, pr_id="PR_101")
                with self.assertRaises(ScopeConflictError):
                    db10.ensure_work_unit(unit_key="UB10", project_id="pb", repo="o/r", issue_number=102, pr_id="PR_101")

                # Conflict receipt returned by remote create_draft_pr onto a PR already owned by pb is isolated without binding!
                db10.ensure_work_unit(unit_key="UB_OWN", project_id="pb", repo="o/r", issue_number=103, pr_id="PR_OWNED_BY_B")
                db10.ensure_work_unit(unit_key="UA_NEW", project_id="pa", repo="o/r", issue_number=104)
                ce10 = db10.claim_and_reserve(
                    unit_key="UA_NEW", cfg=cfg_a, slot_keys=["pa:s1"], worker_unit_name="ua10.service",
                    expected_cgroup_dir="/cg/ua10", base_sha="000", authorized_head_ref="agent/104",
                    bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                )
                db10.set_current_candidate(unit_key="UA_NEW", candidate_sha="cand1040", claim_epoch=ce10)
                db10.record_verify_receipt(unit_key="UA_NEW", candidate_sha="cand1040", dod_cmd="true", exit_code=0, ui_verified=False, artifact_dir="/tmp", touched_paths=("src/a.py",))
                db10.record_review_receipt(unit_key="UA_NEW", candidate_sha="cand1040", writer_family="codex", referee_family="claude", referee_model="claude-fable-5-2", verdict="APPROVE", defect_count=0, defects=[], raw_path="/tmp/r.json")
                op_cd10 = db10.prepare_op(unit_key="UA_NEW", op_type="create_draft_pr", claim_epoch=ce10, candidate_sha="cand1040", payload={"title": "t", "body": "b"})
                g_cd10 = db10.promote_op_to_in_flight(op_cd10, caller_owner_kind="worker", caller_epoch=ce10)
                db10.consume_send_grant(g_cd10)
                q_rcpt = db10.record_op_receipt(op_cd10, remote_receipt_id="PR_OWNED_BY_B", pr_id="PR_OWNED_BY_B")
                self.assertEqual(q_rcpt["status"], "diverged_needs_human")
                self.assertIsNone(db10.get_unit("UA_NEW")["pr_id"], "Conflict receipt MUST NOT bind UA_NEW onto PB's PR!")
                self.assertEqual(db10.get_unit("UB_OWN")["veto_pending"], 1)
            finally:
                db10.close()

            # 4 & 5. Stale/incomplete `final_dir` is atomically replaced AND tracked `.cargo/vendor/helper` path dependency survives `.cargo/config.toml` stripping!
            cargo_bin = shutil.which("cargo") or (str(Path.home() / ".cargo" / "bin" / "cargo") if (Path.home() / ".cargo" / "bin" / "cargo").is_file() else None)
            if cargo_bin:
                vend_repo = base / "vend_rust"
                (vend_repo / "src").mkdir(parents=True)
                (vend_repo / ".cargo" / "vendor" / "helper" / "src").mkdir(parents=True)
                subprocess.run(["git", "init", "-q", "-b", "main"], cwd=vend_repo, check=True)
                subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=vend_repo, check=True)
                subprocess.run(["git", "config", "user.name", "Tester"], cwd=vend_repo, check=True)
                (vend_repo / ".cargo" / "config.toml").write_text('[build]\nrustc-wrapper = "/nonexistent/evil"\n', encoding="utf-8")
                (vend_repo / ".cargo" / "vendor" / "helper" / "Cargo.toml").write_text(
                    '[package]\nname = "helper"\nversion = "0.1.0"\nedition = "2021"\n', encoding="utf-8"
                )
                (vend_repo / ".cargo" / "vendor" / "helper" / "src" / "lib.rs").write_text("pub fn h() -> i32 { 42 }\n", encoding="utf-8")
                (vend_repo / "Cargo.toml").write_text(
                    '[package]\nname = "vend_app"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\nhelper = { path = ".cargo/vendor/helper" }\n',
                    encoding="utf-8",
                )
                (vend_repo / "src" / "lib.rs").write_text("pub fn v() -> i32 { helper::h() }\n", encoding="utf-8")
                c_env = dict(os.environ, PATH=f"{Path.home() / '.cargo' / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}")
                subprocess.run([cargo_bin, "generate-lockfile"], cwd=vend_repo, env=c_env, check=True, capture_output=True)
                subprocess.run(["git", "add", "."], cwd=vend_repo, check=True)
                subprocess.run(["git", "commit", "-q", "-m", "vendored helper"], cwd=vend_repo, check=True)
                vend_sha = resolve_commit_oid(vend_repo, "HEAD")
                mg_vend = ensure_managed_bare_repo(vend_repo, base / "mg_vend.git")

                croot_v = base / "vend_cache"
                # First materialize cleanly to learn final_dir path, then corrupt final_dir into an empty directory and re-run!
                tbc_v1 = prepare_trusted_base_cache(managed_gitdir=mg_vend, base_sha=vend_sha, cache_root=croot_v)
                assert tbc_v1 is not None
                shutil.rmtree(tbc_v1)
                tbc_v1.mkdir(parents=True)  # Incomplete empty directory at exact `final_dir`!
                tbc_v2 = prepare_trusted_base_cache(managed_gitdir=mg_vend, base_sha=vend_sha, cache_root=croot_v)
                assert tbc_v2 is not None
                self.assertTrue((tbc_v2 / "cargo_home").is_dir(), "Incomplete stale final_dir MUST be atomically replaced!")
                self.assertTrue((tbc_v2 / ".ready").is_file())

    def test_round11_all_codex_closures(self) -> None:
        """Regression suite covering all 4 Round-11 Codex Astra findings."""
        import argparse
        import agent_autopilot as ap_cli

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            # 1 & 2. Cross-project conflict receipt (BOTH immediate AND post-crash `reconcile_op` on Ready/MERGED PR!)
            #        commits `scope_quarantined=1` cleanly and NEVER triggers `convert_pr_to_draft` on project B's Ready PR!
            db11 = AutopilotDB(base / "r11.db")
            try:
                cfg_a = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                cfg_b = WorkflowConfig(project_id="pb", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                db11.upsert_project(cfg_a)
                db11.upsert_project(cfg_b)
                db11.ensure_lease_slots("pa", ["pa:s1"], base / "locks11")
                db11.ensure_work_unit(unit_key="UB_READY", project_id="pb", repo="o/r", issue_number=110, pr_id="PR_READY_B")
                db11.ensure_work_unit(unit_key="UA_CRASH", project_id="pa", repo="o/r", issue_number=111)
                ce11 = db11.claim_and_reserve(
                    unit_key="UA_CRASH", cfg=cfg_a, slot_keys=["pa:s1"], worker_unit_name="ap-nonexist-111.service",
                    expected_cgroup_dir="/sys/fs/cgroup/nonexist_111", base_sha="000", authorized_head_ref="agent/111",
                    bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                )
                db11.set_current_candidate(unit_key="UA_CRASH", candidate_sha="cand1110", claim_epoch=ce11)
                db11.record_verify_receipt(unit_key="UA_CRASH", candidate_sha="cand1110", dod_cmd="true", exit_code=0, ui_verified=False, artifact_dir="/tmp", touched_paths=("src/a.py",))
                db11.record_review_receipt(unit_key="UA_CRASH", candidate_sha="cand1110", writer_family="codex", referee_family="claude", referee_model="claude-fable-5-2", verdict="APPROVE", defect_count=0, defects=[], raw_path="/tmp/r.json")
                op_cd11 = db11.prepare_op(
                    unit_key="UA_CRASH", op_type="create_draft_pr", claim_epoch=ce11,
                    candidate_sha="cand1110", ref_id_hmac="ap-ref111", payload={"title": "t", "body": "b"},
                )
                g_cd11 = db11.promote_op_to_in_flight(op_cd11, caller_owner_kind="worker", caller_epoch=ce11)
                db11.consume_send_grant(g_cd11)
                db11.begin_reclaim_claim(ce11)
                db11.finish_reclaim_leases_free(ce11, cleanup_rc=0, unit_terminated=True, worktree_clean=True)

                # Simulate lost receipt: remote GitHub has PR_READY_B (is_draft=False!) matching `Ref-ID: ap-ref111`, already owned by `pb`!
                tr11 = FakeGitHubTransport()
                tr11.prs["PR_READY_B"] = PrSnapshot(
                    pr_id="PR_READY_B", state="OPEN", is_draft=False, head_ref_oid="cand1110",
                    head_ref_name="agent/111", base_ref_name="main", body="Ref-ID: ap-ref111",
                )
                # Run TWO consecutive supervisor recovery ticks: NEITHER raises ScopeConflictError, AND ZERO `convert_pr_to_draft` sent!
                ap_cli.supervisor_recover_and_reconcile(db11, db11.bump_dispatcher_epoch(), {"pa": cfg_a, "pb": cfg_b}, transport_override=tr11)
                ap_cli.supervisor_recover_and_reconcile(db11, db11.bump_dispatcher_epoch(), {"pa": cfg_a, "pb": cfg_b}, transport_override=tr11)
                self.assertEqual(db11.get_op(op_cd11)["status"], "diverged_needs_human")
                self.assertEqual(int(db11.get_unit("UA_CRASH")["scope_quarantined"]), 1)
                self.assertEqual(int(db11.get_unit("UB_READY")["scope_quarantined"]), 1)
                self.assertEqual(len(tr11.sent_ops_log), 0, "Conflict quarantine MUST NEVER send convert_pr_to_draft on project B's PR!")
            finally:
                db11.close()

            # 3. Registered worktree path replaced by a standalone repo with real `.git/` directory -> `scrub_worktree_to_base` REFUSES to delete `.git/`!
            src_repo = base / "src_r"
            b_sha = _init_git_repo(src_repo)
            old_cache_root = base / "old_cache" / "pa" / "o__r"
            mg11 = ensure_managed_bare_repo(src_repo, old_cache_root / "managed.git")
            wt11, wt_gd11 = prepare_isolated_worktree(
                managed_gitdir=mg11, worktree_dir=old_cache_root / "worktrees" / "wt-11", base_sha=b_sha
            )
            # Replace `wt11` at the EXACT registered path with a standalone repo having a real `.git/` directory + unpushed commit!
            shutil.rmtree(wt11)
            _init_git_repo(wt11)
            (wt11 / "unpushed.txt").write_text("precious_unpushed_work", encoding="utf-8")
            subprocess.run(["git", "add", "unpushed.txt"], cwd=wt11, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "precious"], cwd=wt11, check=True)
            with self.assertRaises(AutopilotError):
                scrub_worktree_to_base(managed_gitdir=mg11, wt_gitdir=wt_gd11, worktree=wt11, base_sha=b_sha)
            self.assertTrue((wt11 / ".git" / "objects").is_dir(), "Standalone `.git/` directory at reused path MUST NOT be deleted!")
            self.assertEqual((wt11 / "unpushed.txt").read_text(encoding="utf-8"), "precious_unpushed_work")

            # 4. `AGENT_AUTOPILOT_CACHE_DIR` rotated AFTER claim creation -> `cmd_scrub_worktree` uses `frozen_cache_dir` and succeeds!
            wt11_real, _ = prepare_isolated_worktree(
                managed_gitdir=mg11, worktree_dir=old_cache_root / "worktrees" / "wt-11-rot", base_sha=b_sha
            )
            (wt11_real / "dirty.tmp").write_text("dirty", encoding="utf-8")
            sroot_c = base / "state_rot_cache"
            db_c = AutopilotDB(sroot_c / "autopilot.db")
            try:
                cfg_c = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_repo), write_scope=("src/**",))
                db_c.upsert_project(cfg_c)
                db_c.ensure_lease_slots("pa", ["pa:slot-1"], sroot_c / "locks")
                db_c.ensure_work_unit(unit_key="o/r#115", project_id="pa", repo="o/r", issue_number=115)
                ce_rot = db_c.claim_and_reserve(
                    unit_key="o/r#115", cfg=cfg_c, slot_keys=["pa:slot-1"], worker_unit_name="ap-w115.service",
                    expected_cgroup_dir="/cg/w115", base_sha=b_sha, authorized_head_ref="agent/115",
                    worktree_path=str(wt11_real), managed_gitdir=str(mg11), frozen_cache_dir=str(old_cache_root.resolve()),
                    bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                )
                db_c.begin_reclaim_claim(ce_rot)
                db_c.record_cleanup_unit(ce_rot, "ap-cu115.service", "/cg/cu115")
            finally:
                db_c.close()

            new_cache_env = base / "completely_new_cache_dir"
            with (
                unittest.mock.patch.dict(os.environ, {"AGENT_AUTOPILOT_STATE_DIR": str(sroot_c), "AGENT_AUTOPILOT_CACHE_DIR": str(new_cache_env)}),
                unittest.mock.patch.object(ap_cli, "verify_self_in_expected_cgroup", return_value=True),
            ):
                rc_sc = ap_cli.cmd_scrub_worktree(argparse.Namespace(claim_epoch=str(ce_rot)))
            self.assertEqual(rc_sc, 0, "cmd_scrub_worktree MUST honor frozen_cache_dir even after AGENT_AUTOPILOT_CACHE_DIR changes!")
            self.assertFalse((wt11_real / "dirty.tmp").exists())

    def test_round12_all_codex_closures(self) -> None:
        """Regression suite covering all 4 Round-12 Codex Astra findings."""
        import argparse
        import sqlite3
        import agent_autopilot as ap_cli
        from ap_core.models import ensure_secure_dir

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            # 1. Pre-upgrade DB with legacy `error_detail='conflicting_pr_id=PR_B:...'` and `veto_remote_sync_pending=1` on project B
            #    is migrated atomically on open (`conflicting_pr_id` backfilled, `scope_quarantined=1`, `veto_remote_sync_pending=0`),
            #    sending ZERO `convert_pr_to_draft` across recovery ticks!
            mig_db_p = base / "mig12.db"
            db_init = AutopilotDB(mig_db_p)
            db_init.close()
            raw_c = sqlite3.connect(str(mig_db_p))
            raw_c.execute(
                "INSERT INTO projects(project_id, kind, enabled, max_in_progress, current_step_idx, clean_matured_runs, token_file, token_mode, updated_at) "
                "VALUES ('pa', 'issue', 1, 1, 0, 0, '', 'ambient', '2026-01-01'), ('pb', 'issue', 1, 1, 0, 0, '', 'ambient', '2026-01-01')"
            )
            raw_c.execute(
                "INSERT INTO work_units(unit_key, project_id, repo, issue_number, status, terminal_state, pr_id, veto_pending, veto_remote_sync_pending, scope_quarantined, last_error, created_at, updated_at) "
                "VALUES ('UB_OLD', 'pb', 'o/r', 1, 'paused', 'needs-human', 'PR_B_OLD', 1, 1, 0, 'conflicting_pr_id=PR_B_OLD: conflict', '2026-01-01', '2026-01-01'), "
                "       ('UA_OLD', 'pa', 'o/r', 2, 'paused', 'needs-human', NULL, 1, 0, 0, 'conflicting_pr_id=PR_B_OLD: conflict', '2026-01-01', '2026-01-01')"
            )
            raw_c.execute(
                "INSERT INTO external_ops(op_id, op_seq, unit_key, project_id, pr_id, op_type, owner_kind, owner_epoch, status, send_consumed, remote_receipt_id, conflicting_pr_id, error_detail, prepared_at, updated_at) "
                "VALUES ('op-old-conf', 1, 'UA_OLD', 'pa', NULL, 'create_draft_pr', 'worker', 1, 'diverged_needs_human', 1, 'PR_B_OLD', NULL, 'conflicting_pr_id=PR_B_OLD: conflict', '2026-01-01', '2026-01-01')"
            )
            raw_c.commit()
            raw_c.close()

            db12 = AutopilotDB(mig_db_p)
            try:
                self.assertEqual(db12.get_op("op-old-conf")["conflicting_pr_id"], "PR_B_OLD")
                self.assertEqual(int(db12.get_unit("UB_OLD")["scope_quarantined"]), 1)
                self.assertEqual(int(db12.get_unit("UB_OLD")["veto_remote_sync_pending"]), 0)
                tr12 = FakeGitHubTransport()
                tr12.prs["PR_B_OLD"] = PrSnapshot(pr_id="PR_B_OLD", state="OPEN", is_draft=False, head_ref_oid="cb", head_ref_name="agent/1", base_ref_name="main")
                cfg_a = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                cfg_b = WorkflowConfig(project_id="pb", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(base), trust_tier="T2", write_scope=("src/**",))
                ap_cli.supervisor_recover_and_reconcile(db12, db12.bump_dispatcher_epoch(), {"pa": cfg_a, "pb": cfg_b}, transport_override=tr12)
                ap_cli.supervisor_recover_and_reconcile(db12, db12.bump_dispatcher_epoch(), {"pa": cfg_a, "pb": cfg_b}, transport_override=tr12)
                self.assertEqual(len(tr12.sent_ops_log), 0, "Migrated conflict receipt MUST send 0 convert_pr_to_draft!")
            finally:
                db12.close()

            # 2, 3 & 4. Symlink `wt-A -> wt-B` refused BEFORE `.resolve()`; foreign linked worktree `.git` gitfile refused;
            #           and offline/unmounted `frozen_cache_dir` (or mismatched inode) retains `'reclaiming'`!
            src_r = base / "src12"
            sha12 = _init_git_repo(src_r)
            rc12 = ensure_secure_dir(base / "cache12" / "pa" / "o__r", 0o700)
            st_rc12 = os.lstat(rc12)
            mg12 = ensure_managed_bare_repo(src_r, rc12 / "managed.git")
            wt_a, wt_gd_a = prepare_isolated_worktree(managed_gitdir=mg12, worktree_dir=rc12 / "worktrees" / "wt-A", base_sha=sha12)
            wt_b, _ = prepare_isolated_worktree(managed_gitdir=mg12, worktree_dir=rc12 / "worktrees" / "wt-B", base_sha=sha12)
            (wt_b / "keep_b.txt").write_text("SIBLING_WORK", encoding="utf-8")

            # 2) Replace `wt-A` with symlink -> `wt-B`: `cmd_scrub_worktree` for claim A MUST fail without touching `wt-B`!
            shutil.rmtree(wt_a)
            wt_a.symlink_to(wt_b)
            sroot12 = base / "state12"
            db_s12 = AutopilotDB(sroot12 / "autopilot.db")
            try:
                cfg_s = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db_s12.upsert_project(cfg_s)
                db_s12.ensure_lease_slots("pa", ["pa:slot-1"], sroot12 / "locks")
                db_s12.ensure_work_unit(unit_key="o/r#120", project_id="pa", repo="o/r", issue_number=120)
                ce_sym = db_s12.claim_and_reserve(
                    unit_key="o/r#120", cfg=cfg_s, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-120.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-120.service")), base_sha=sha12, authorized_head_ref="agent/120",
                    worktree_path=str(wt_a), managed_gitdir=str(mg12),
                    frozen_cache_dir=str(rc12.resolve()), frozen_cache_dev=int(st_rc12.st_dev), frozen_cache_ino=int(st_rc12.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file="/tmp/ap-test.tok",
                )
                db_s12.begin_reclaim_claim(ce_sym)
                db_s12.record_cleanup_unit(ce_sym, "ap-cu120.service", str(expected_transient_cgroup_dir("ap-cu120.service")))
            finally:
                db_s12.close()

            with (
                unittest.mock.patch.dict(os.environ, {"AGENT_AUTOPILOT_STATE_DIR": str(sroot12)}),
                unittest.mock.patch.object(ap_cli, "verify_self_in_expected_cgroup", return_value=True),
            ):
                with self.assertRaises(AutopilotError):
                    ap_cli.cmd_scrub_worktree(argparse.Namespace(claim_epoch=str(ce_sym)))
            self.assertEqual((wt_b / "keep_b.txt").read_text(encoding="utf-8"), "SIBLING_WORK", "Sibling wt-B MUST remain untouched!")

            # 3) Foreign linked worktree from ANOTHER repo placed at `wt-A`: `.git` is a regular file pointing to `other_repo/.git/worktrees/...` -> REFUSED!
            wt_a.unlink()
            other_repo = base / "foreign_repo"
            _init_git_repo(other_repo)
            subprocess.run(["git", "-C", str(other_repo), "worktree", "add", "--detach", str(wt_a), "HEAD"], check=True, capture_output=True)
            (wt_a / "foreign_uncommitted.txt").write_text("FOREIGN_DIRTY", encoding="utf-8")
            with self.assertRaises(AutopilotError):
                scrub_worktree_to_base(managed_gitdir=mg12, wt_gitdir=wt_gd_a, worktree=wt_a, base_sha=sha12)
            self.assertEqual((wt_a / "foreign_uncommitted.txt").read_text(encoding="utf-8"), "FOREIGN_DIRTY")

            # 4) Simulate cache volume unmounted/replaced (replace `rc12` with a brand-new empty mountpoint directory with DIFFERENT inode!):
            #    `_reclaim_single_claim_via_bounded_unit` MUST return False and retain `state='reclaiming'`!
            moved_vol = base / "offline_vol_backup"
            os.replace(rc12, moved_vol)
            rc12.mkdir(parents=True)  # Empty mountpoint directory with different inode (`st_ino != frozen_cache_ino`)!
            db_vol = AutopilotDB(sroot12 / "autopilot.db")
            try:
                cl_vol = db_vol.get_claim(ce_sym)
                assert cl_vol is not None
                freed_offline = ap_cli._reclaim_single_claim_via_bounded_unit(db_vol, cl_vol, cfg_s)
                self.assertFalse(freed_offline, "Unmounted/inode-drifted cache volume MUST NOT release claim or lease!")
                self.assertEqual(db_vol.get_claim(ce_sym)["state"], "reclaiming")
            finally:
                db_vol.close()

    def test_round13_all_codex_closures(self) -> None:
        """Regression suite covering all 4 Round-13 Codex Astra findings."""
        import sqlite3
        import agent_autopilot as ap_cli
        from ap_core.models import ensure_secure_dir

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src13"
            sha13 = _init_git_repo(src_r)
            rc13 = ensure_secure_dir(base / "cache13" / "pa" / "o__r", 0o700)
            mg13 = ensure_managed_bare_repo(src_r, rc13 / "managed.git")
            wt_b, _ = prepare_isolated_worktree(managed_gitdir=mg13, worktree_dir=rc13 / "worktrees" / "wt-B", base_sha=sha13)
            (wt_b / "keep_b13.txt").write_text("SIBLING_SAFE", encoding="utf-8")

            # 1a. `prepare_isolated_worktree` refuses `wt-A -> wt-B` symlink BEFORE `.resolve()` (leaving `wt-B` untouched!)
            wt_a_sym = rc13 / "worktrees" / "wt-A"
            wt_a_sym.symlink_to(wt_b)
            with self.assertRaises(AutopilotError):
                prepare_isolated_worktree(managed_gitdir=mg13, worktree_dir=wt_a_sym, base_sha=sha13)
            self.assertEqual((wt_b / "keep_b13.txt").read_text(encoding="utf-8"), "SIBLING_SAFE")
            wt_a_sym.unlink()

            # 1b. `prepare_isolated_worktree` refuses non-empty unowned directory lacking registered metadata (never rmtrees it!)
            unowned = rc13 / "worktrees" / "wt-unowned"
            unowned.mkdir(parents=True)
            (unowned / "user_notes.txt").write_text("DO_NOT_DELETE", encoding="utf-8")
            with self.assertRaises(AutopilotError):
                prepare_isolated_worktree(managed_gitdir=mg13, worktree_dir=unowned, base_sha=sha13)
            self.assertEqual((unowned / "user_notes.txt").read_text(encoding="utf-8"), "DO_NOT_DELETE")

            # 2. `scrub_worktree_to_base` refuses non-empty ordinary directory missing `.git` at a registered path!
            wt_c, wt_gd_c = prepare_isolated_worktree(managed_gitdir=mg13, worktree_dir=rc13 / "worktrees" / "wt-C", base_sha=sha13)
            shutil.rmtree(wt_c)
            wt_c.mkdir()
            (wt_c / "plain_file.txt").write_text("PLAIN_DIR_DATA", encoding="utf-8")
            with self.assertRaises(AutopilotError):
                scrub_worktree_to_base(managed_gitdir=mg13, wt_gitdir=wt_gd_c, worktree=wt_c, base_sha=sha13)
            self.assertEqual((wt_c / "plain_file.txt").read_text(encoding="utf-8"), "PLAIN_DIR_DATA")

            # 3. Pre-upgrade `path_recorded=1` claim with `frozen_cache_dev=NULL, frozen_cache_ino=NULL` on an empty replaced cache dir
            #    MUST retain `reclaiming` (never releasing the slot without positive ownership proof)!
            empty_replaced_rc = ensure_secure_dir(base / "empty_replaced_rc", 0o700)
            sroot13 = base / "state13"
            db13 = AutopilotDB(sroot13 / "autopilot.db")
            try:
                # 4. Brand-new state_root ALREADY has `sealed_tokens/` created upfront on DB init so crash after claim_and_reserve
                #    before writing `.gh_token` STILL reclaims cleanly!
                self.assertTrue((sroot13 / "sealed_tokens").is_dir())
                cfg13 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db13.upsert_project(cfg13)
                db13.ensure_lease_slots("pa", ["pa:slot-1"], sroot13 / "locks")
                db13.ensure_work_unit(unit_key="o/r#130", project_id="pa", repo="o/r", issue_number=130)
                ce_null_dev = db13.claim_and_reserve(
                    unit_key="o/r#130", cfg=cfg13, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-130.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-130.service")), base_sha=sha13, authorized_head_ref="agent/130",
                    run_dir=str(empty_replaced_rc / "runs" / "claim-130"),
                    worktree_path=str(empty_replaced_rc / "worktrees" / "wt-130"),
                    managed_gitdir=str(empty_replaced_rc / "managed.git"),
                    frozen_cache_dir=str(empty_replaced_rc),
                    frozen_cache_dev=None,
                    frozen_cache_ino=None,
                    bound_gh_login="autopilot-bot",
                    ephemeral_token_file=str(sroot13 / "sealed_tokens" / "claim-pa-130.gh_token"),
                )
                cl_nd = db13.get_claim(ce_null_dev)
                assert cl_nd is not None
                self.assertFalse(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db13, cl_nd, cfg13),
                    "Legacy claim with NULL dev/ino on empty replaced cache root MUST retain 'reclaiming'!",
                )
                self.assertEqual(db13.get_claim(ce_null_dev)["state"], "reclaiming")

                # 4b. Fresh claim WITH `(frozen_cache_dev, frozen_cache_ino)` that crashed right after `claim_and_reserve`
                #     (before writing `.gh_token` or `wt`) in a brand-new `state_root` reclaims cleanly to `released`/`free`!
                st_rc13 = os.lstat(rc13)
                sroot_fresh = base / "brand_new_state"
                db_fr = AutopilotDB(sroot_fresh / "autopilot.db")
                try:
                    db_fr.upsert_project(cfg13)
                    db_fr.ensure_lease_slots("pa", ["pa:slot-1"], sroot_fresh / "locks")
                    db_fr.ensure_work_unit(unit_key="o/r#131", project_id="pa", repo="o/r", issue_number=131)
                    ce_fr = db_fr.claim_and_reserve(
                        unit_key="o/r#131", cfg=cfg13, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-131.service",
                        expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-131.service")), base_sha=sha13, authorized_head_ref="agent/131",
                        run_dir=str(rc13 / "runs" / "claim-131"),
                        worktree_path=str(rc13 / "worktrees" / "wt-131"),
                        managed_gitdir=str(mg13),
                        frozen_cache_dir=str(rc13),
                        frozen_cache_dev=int(st_rc13.st_dev),
                        frozen_cache_ino=int(st_rc13.st_ino),
                        bound_gh_login="autopilot-bot",
                        ephemeral_token_file=str(sroot_fresh / "sealed_tokens" / "claim-pa-131.gh_token"),
                    )
                    cl_fr = db_fr.get_claim(ce_fr)
                    assert cl_fr is not None
                    self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db_fr, cl_fr, cfg13))
                    self.assertEqual(db_fr.get_claim(ce_fr)["state"], "released")
                finally:
                    db_fr.close()
            finally:
                db13.close()

    def test_round14_all_codex_closures(self) -> None:
        """Regression suite covering all 3 Round-14 Codex Astra findings."""
        import subprocess as _sp
        import agent_autopilot as ap_cli
        from ap_core.models import ensure_sealed_tokens_dir, ensure_secure_dir

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo14"
            sha14 = _init_git_repo(src_r)

            # 1. Relocated worktree (`git worktree move wt-A wt-moved`):
            #    - `prepare_isolated_worktree(wt-A)` refuses to delete `managed.git/worktrees/wt-A`!
            #    - `_reclaim_single_claim_via_bounded_unit` retains `reclaiming` and marks `needs-human` (never releasing slot)!
            rc14 = ensure_secure_dir(base / "cache" / "pa" / "o__r", 0o700)
            mg14 = ensure_managed_bare_repo(src_r, rc14 / "managed.git")
            wt_a, wt_gd_a = prepare_isolated_worktree(managed_gitdir=mg14, worktree_dir=rc14 / "worktrees" / "wt-A", base_sha=sha14)
            wt_moved = rc14 / "worktrees" / "wt-moved"
            _sp.run(
                ["git", "--git-dir", str(mg14), "worktree", "move", str(wt_a), str(wt_moved)],
                check=True,
                capture_output=True,
            )
            self.assertFalse(wt_a.exists())
            self.assertTrue((wt_gd_a / "HEAD").is_file())
            with self.assertRaises(AutopilotError):
                prepare_isolated_worktree(managed_gitdir=mg14, worktree_dir=wt_a, base_sha=sha14)
            self.assertTrue((wt_gd_a / "HEAD").is_file(), "Relocated worktree metadata MUST NOT be deleted!")

            sroot14 = base / "state14"
            db14 = AutopilotDB(sroot14 / "autopilot.db")
            try:
                cfg14 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db14.upsert_project(cfg14)
                db14.ensure_lease_slots("pa", ["pa:slot-1"], sroot14 / "locks")
                db14.ensure_work_unit(unit_key="o/r#140", project_id="pa", repo="o/r", issue_number=140)
                st_rc14 = os.lstat(rc14)
                ce_mv = db14.claim_and_reserve(
                    unit_key="o/r#140", cfg=cfg14, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-140.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-140.service")), base_sha=sha14, authorized_head_ref="agent/140",
                    run_dir=str(rc14 / "runs" / "claim-140"),
                    worktree_path=str(wt_a),
                    managed_gitdir=str(mg14),
                    frozen_cache_dir=str(rc14),
                    frozen_cache_dev=int(st_rc14.st_dev),
                    frozen_cache_ino=int(st_rc14.st_ino),
                    bound_gh_login="autopilot-bot",
                    ephemeral_token_file=str(sroot14 / "sealed_tokens" / "claim-pa-140.gh_token"),
                )
                cl_mv = db14.get_claim(ce_mv)
                assert cl_mv is not None
                self.assertFalse(ap_cli._reclaim_single_claim_via_bounded_unit(db14, cl_mv, cfg14))
                self.assertEqual(db14.get_claim(ce_mv)["state"], "reclaiming")
                self.assertEqual(db14.get_unit("o/r#140")["terminal_state"], "needs-human")
                self.assertTrue((wt_gd_a / "HEAD").is_file())
            finally:
                db14.close()

            # 2. Higher-level ancestor symlink swap (`cache/pb -> other_cache/pb` where `o__r/worktrees` are real directories):
            other_rc = ensure_secure_dir(base / "other_cache" / "pb" / "o__r", 0o700)
            ensure_managed_bare_repo(src_r, other_rc / "managed.git")
            sym_proj = base / "cache" / "pb"
            sym_proj.symlink_to(base / "other_cache" / "pb")
            sym_rc = sym_proj / "o__r"
            with self.assertRaises(AutopilotError):
                prepare_isolated_worktree(managed_gitdir=sym_rc / "managed.git", worktree_dir=sym_rc / "worktrees" / "wt-sym", base_sha=sha14)
            self.assertFalse((other_rc / "worktrees" / "wt-sym").exists())
            self.assertFalse(
                ap_cli._verify_frozen_cache_storage_mounted(
                    {"frozen_cache_dev": os.stat(other_rc).st_dev, "frozen_cache_ino": os.stat(other_rc).st_ino},
                    sym_rc,
                ),
                "Higher-level ancestor symlink MUST fail _verify_frozen_cache_storage_mounted even if target dev/ino match!",
            )

            # 3. Symlinked `sealed_tokens -> shared_service_dir` (`0755`) MUST fail closed WITHOUT chmodding target to `0700`!
            shared_svc = base / "shared_service_dir"
            shared_svc.mkdir()
            os.chmod(shared_svc, 0o755)
            bad_sroot = base / "bad_state_root"
            bad_sroot.mkdir()
            (bad_sroot / "sealed_tokens").symlink_to(shared_svc)
            with self.assertRaises(AutopilotError):
                ensure_sealed_tokens_dir(bad_sroot)
            self.assertEqual(os.stat(shared_svc).st_mode & 0o777, 0o755)
            with self.assertRaises(AutopilotError):
                AutopilotDB(bad_sroot / "autopilot.db")
            self.assertEqual(os.stat(shared_svc).st_mode & 0o777, 0o755, "AutopilotDB init MUST NOT chmod symlink target!")

    def test_round15_all_codex_closures(self) -> None:
        """Regression suite covering all 4 Round-15 Codex Astra findings."""
        import subprocess as _sp
        import agent_autopilot as ap_cli
        from ap_core.models import ensure_secure_dir

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo15"
            sha15 = _init_git_repo(src_r)
            rc15 = ensure_secure_dir(base / "cache15" / "pa" / "o__r", 0o700)
            mg15 = ensure_managed_bare_repo(src_r, rc15 / "managed.git")

            # 1. `git worktree lock` offline worktree: startup refuses `rmtree(wt_gitdir)` AND reclaim retains lease!
            wt_lck, wt_gd_lck = prepare_isolated_worktree(managed_gitdir=mg15, worktree_dir=rc15 / "worktrees" / "wt-lck", base_sha=sha15)
            _sp.run(["git", "--git-dir", str(mg15), "worktree", "lock", str(wt_lck)], check=True, capture_output=True)
            self.assertTrue((wt_gd_lck / "locked").is_file())
            shutil.rmtree(wt_lck)  # simulate offline/unmounted removable worktree while locked metadata remains
            with self.assertRaises(AutopilotError):
                prepare_isolated_worktree(managed_gitdir=mg15, worktree_dir=wt_lck, base_sha=sha15)
            self.assertTrue((wt_gd_lck / "HEAD").is_file(), "Locked worktree metadata MUST NOT be deleted!")

            sroot15 = base / "state15"
            db15 = AutopilotDB(sroot15 / "autopilot.db")
            try:
                cfg_a = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                cfg_b = WorkflowConfig(project_id="pb", kind="issue", enabled=True, repos=("o/r2",), workspace_path=str(src_r), write_scope=("src/**",))
                db15.upsert_project(cfg_a)
                db15.upsert_project(cfg_b)
                db15.ensure_lease_slots("pa", ["pa:slot-1"], sroot15 / "locks")
                db15.ensure_lease_slots("pb", ["pb:slot-1"], sroot15 / "locks")
                db15.ensure_work_unit(unit_key="o/r#150", project_id="pa", repo="o/r", issue_number=150)
                st_rc15 = os.lstat(rc15)
                ce_lck = db15.claim_and_reserve(
                    unit_key="o/r#150", cfg=cfg_a, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-150.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-150.service")), base_sha=sha15, authorized_head_ref="agent/150",
                    run_dir=str(rc15 / "runs" / "claim-150"), worktree_path=str(wt_lck), managed_gitdir=str(mg15),
                    frozen_cache_dir=str(rc15), frozen_cache_dev=int(st_rc15.st_dev), frozen_cache_ino=int(st_rc15.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot15 / "sealed_tokens" / "claim-pa-150.gh_token"),
                )
                self.assertFalse(ap_cli._reclaim_single_claim_via_bounded_unit(db15, db15.get_claim(ce_lck), cfg_a))
                self.assertEqual(db15.get_claim(ce_lck)["state"], "reclaiming")
                self.assertTrue((wt_gd_lck / "HEAD").is_file())

                # 2. Unreadable `gitdir` (`PermissionError`) on project A MUST NOT abort `supervisor_recover_and_reconcile` for project B!
                wt_unr, wt_gd_unr = prepare_isolated_worktree(managed_gitdir=mg15, worktree_dir=rc15 / "worktrees" / "wt-unr", base_sha=sha15)
                shutil.rmtree(wt_unr)
                os.chmod(wt_gd_unr / "gitdir", 0o000)
                rc_b = ensure_secure_dir(base / "cache15" / "pb" / "o__r2", 0o700)
                mg_b = ensure_managed_bare_repo(src_r, rc_b / "managed.git")
                st_rcb = os.lstat(rc_b)
                try:
                    cfg_unr = WorkflowConfig(project_id="pa_unr", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                    db15.upsert_project(cfg_unr)
                    db15.ensure_lease_slots("pa_unr", ["pa_unr:slot-1"], sroot15 / "locks")
                    db15.ensure_work_unit(unit_key="o/r#151", project_id="pa_unr", repo="o/r", issue_number=151)
                    ce_unr = db15.claim_and_reserve(
                        unit_key="o/r#151", cfg=cfg_unr, slot_keys=["pa_unr:slot-1"], worker_unit_name="ap-nonexist-151.service",
                        expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-151.service")), base_sha=sha15, authorized_head_ref="agent/151",
                        run_dir=str(rc15 / "runs" / "claim-151"), worktree_path=str(wt_unr), managed_gitdir=str(mg15),
                        frozen_cache_dir=str(rc15), frozen_cache_dev=int(st_rc15.st_dev), frozen_cache_ino=int(st_rc15.st_ino),
                        bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot15 / "sealed_tokens" / "claim-pa-151.gh_token"),
                    )
                    db15.ensure_work_unit(unit_key="o/r2#201", project_id="pb", repo="o/r2", issue_number=201)
                    ce_pb = db15.claim_and_reserve(
                        unit_key="o/r2#201", cfg=cfg_b, slot_keys=["pb:slot-1"], worker_unit_name="ap-nonexist-201.service",
                        expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-201.service")), base_sha=sha15, authorized_head_ref="agent/201",
                        run_dir=str(rc_b / "runs" / "claim-201"), worktree_path=str(rc_b / "worktrees" / "wt-201"), managed_gitdir=str(mg_b),
                        frozen_cache_dir=str(rc_b), frozen_cache_dev=int(st_rcb.st_dev), frozen_cache_ino=int(st_rcb.st_ino),
                        bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot15 / "sealed_tokens" / "claim-pb-201.gh_token"),
                    )
                    rec_out = ap_cli.supervisor_recover_and_reconcile(
                        db15, db15.bump_dispatcher_epoch(), {"pa": cfg_a, "pa_unr": cfg_unr, "pb": cfg_b}
                    )
                    self.assertIn(ce_pb, rec_out["reclaimed_claims"], "Project B MUST still reclaim even when Project A has PermissionError!")
                    self.assertEqual(db15.get_claim(ce_unr)["state"], "reclaiming")
                    self.assertEqual(db15.get_claim(ce_pb)["state"], "released")
                finally:
                    os.chmod(wt_gd_unr / "gitdir", 0o600)

                # 3. Retained `rcache_fd` prevents TOCTOU volume swap after `(dev, ino)` verification:
                #    Even if `rc_swap` is replaced by another real directory containing `managed.git`, `_prepare_worker_pinned_paths`
                #    and `prepare_isolated_worktree` write ONLY to the pinned original storage object (`rc_swap_moved`), ZERO to replacement!
                rc_swap = ensure_secure_dir(base / "cache15" / "pswap" / "o__r", 0o700)
                ensure_managed_bare_repo(src_r, rc_swap / "managed.git")
                st_sw = os.lstat(rc_swap)
                cl_sw = {
                    "frozen_cache_dev": int(st_sw.st_dev),
                    "frozen_cache_ino": int(st_sw.st_ino),
                    "managed_gitdir": str(rc_swap / "managed.git"),
                    "run_dir": str(rc_swap / "runs" / "claim-sw"),
                    "worktree_path": str(rc_swap / "worktrees" / "wt-sw"),
                }
                pinned_fd = ap_cli._open_verified_claim_cache_fd(cl_sw, rc_swap)
                assert pinned_fd is not None
                try:
                    rc_swap_moved = base / "cache15" / "pswap" / "o__r_orig_moved"
                    os.rename(rc_swap, rc_swap_moved)
                    ensure_secure_dir(rc_swap, 0o700)
                    ensure_managed_bare_repo(src_r, rc_swap / "managed.git")
                    _, mg_p, run_p, wt_p, rfd_sw = ap_cli._prepare_worker_pinned_paths(cl_sw, 999, rc_swap, pinned_fd)
                    os.close(rfd_sw)
                    prepare_isolated_worktree(managed_gitdir=mg_p, worktree_dir=wt_p, base_sha=sha15)
                    self.assertFalse((rc_swap / "runs").exists(), "Replacement volume MUST receive ZERO run_dir writes!")
                    self.assertFalse((rc_swap / "worktrees").exists(), "Replacement volume MUST receive ZERO git worktree writes!")
                    self.assertTrue((rc_swap_moved / "runs" / "claim-sw").is_dir())
                    self.assertTrue((rc_swap_moved / "worktrees" / "wt-sw" / "src").exists() or (rc_swap_moved / "worktrees" / "wt-sw" / ".git").is_file())
                finally:
                    os.close(pinned_fd)

                # 4. Redirected `runs -> empty_dir` symlink after worker crash MUST retain `reclaiming` (`sb_cleanup_ok = False`)!
                rc_rdir = ensure_secure_dir(base / "cache15" / "prdir" / "o__r", 0o700)
                mg_rdir = ensure_managed_bare_repo(src_r, rc_rdir / "managed.git")
                st_rd = os.lstat(rc_rdir)
                orig_run = ensure_secure_dir(rc_rdir / "runs" / "claim-154", 0o700)
                (orig_run / ".bound_gh_token").write_text("SECRET_TOK\n", encoding="utf-8")
                os.rename(rc_rdir / "runs", rc_rdir / "runs_moved")
                empty_runs_target = ensure_secure_dir(base / "empty_runs_target", 0o700)
                (rc_rdir / "runs").symlink_to(empty_runs_target)
                cfg_rd = WorkflowConfig(project_id="prdir", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db15.upsert_project(cfg_rd)
                db15.ensure_lease_slots("prdir", ["prdir:slot-1"], sroot15 / "locks")
                db15.ensure_work_unit(unit_key="o/r#154", project_id="prdir", repo="o/r", issue_number=154)
                ce_rd = db15.claim_and_reserve(
                    unit_key="o/r#154", cfg=cfg_rd, slot_keys=["prdir:slot-1"], worker_unit_name="ap-nonexist-154.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-154.service")), base_sha=sha15, authorized_head_ref="agent/154",
                    run_dir=str(rc_rdir / "runs" / "claim-154"), worktree_path=str(rc_rdir / "worktrees" / "wt-154"), managed_gitdir=str(mg_rdir),
                    frozen_cache_dir=str(rc_rdir), frozen_cache_dev=int(st_rd.st_dev), frozen_cache_ino=int(st_rd.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot15 / "sealed_tokens" / "claim-prdir-154.gh_token"),
                )
                self.assertFalse(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db15, db15.get_claim(ce_rd), cfg_rd),
                    "Redirected `runs/` parent symlink MUST block reclaim and retain lease!",
                )
                self.assertEqual(db15.get_claim(ce_rd)["state"], "reclaiming")
            finally:
                db15.close()

    def test_round16_all_codex_closures(self) -> None:
        """Regression suite covering all 3 Round-16 Codex Astra findings."""
        import agent_autopilot as ap_cli
        from ap_core.models import ensure_secure_dir, open_dir_nofollow, pinned_proc_fd_path
        from ap_core.sandbox import SandboxError, build_execution_ring_bwrap

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo16"
            sha16 = _init_git_repo(src_r)
            rc16 = ensure_secure_dir(base / "cache16" / "pa" / "o__r", 0o700)
            mg16 = ensure_managed_bare_repo(src_r, rc16 / "managed.git")

            # 1. `prepare_isolated_worktree` NEVER deletes existing `wt_gitdir` when `wt` is absent or empty
            #    (eliminating the TOCTOU window where `git worktree lock` is set right before `rmtree`)!
            wt_abs, wt_gd_abs = prepare_isolated_worktree(managed_gitdir=mg16, worktree_dir=rc16 / "worktrees" / "wt-abs", base_sha=sha16)
            shutil.rmtree(wt_abs)
            with self.assertRaises(AutopilotError):
                prepare_isolated_worktree(managed_gitdir=mg16, worktree_dir=wt_abs, base_sha=sha16)
            self.assertTrue((wt_gd_abs / "HEAD").is_file(), "Existing metadata MUST be preserved when worktree is absent!")
            wt_abs.mkdir()
            with self.assertRaises(AutopilotError):
                prepare_isolated_worktree(managed_gitdir=mg16, worktree_dir=wt_abs, base_sha=sha16)
            self.assertTrue((wt_gd_abs / "HEAD").is_file(), "Existing metadata MUST be preserved when worktree is empty!")

            # 2. `verify_ring` / `copy_clean_tree_no_hardlinks` uses retained directory fds (NEVER `rmtree`s replacement volume!):
            rc_ver = ensure_secure_dir(base / "cache16" / "pver" / "o__r", 0o700)
            ct_dir = ensure_secure_dir(rc_ver / "runs" / "claim-v" / "clean-tree-abc", 0o700)
            (ct_dir / "hello.txt").write_text("clean_payload\n", encoding="utf-8")
            p_fd = open_dir_nofollow(rc_ver, create=False)
            try:
                pin_v = pinned_proc_fd_path(p_fd)
                pinned_ct = pin_v / "runs" / "claim-v" / "clean-tree-abc"
                pinned_vo = pin_v / "runs" / "claim-v" / "verify-out-abc-r1"
                # Swap `rc_ver` path to a replacement volume that ALREADY has a populated `verify-out-abc-r1`!
                rc_ver_moved = base / "cache16" / "pver" / "o__r_orig_moved"
                os.rename(rc_ver, rc_ver_moved)
                victim_vo = ensure_secure_dir(rc_ver / "runs" / "claim-v" / "verify-out-abc-r1", 0o700)
                (victim_vo / "precious.txt").write_text("DO_NOT_DELETE", encoding="utf-8")

                argv_v = build_execution_ring_bwrap(
                    ring_kind="verify_ring",
                    inner_cmd=["/bin/true"],
                    cwd=pinned_vo,
                    clean_tree=pinned_ct,
                    verify_out_dir=pinned_vo,
                )
                self.assertTrue(argv_v)
                self.assertEqual((victim_vo / "precious.txt").read_text(encoding="utf-8"), "DO_NOT_DELETE")
                self.assertEqual((rc_ver_moved / "runs" / "claim-v" / "verify-out-abc-r1" / "hello.txt").read_text(encoding="utf-8"), "clean_payload\n")
                # Also non-empty verify_out_dir refuses overwrite instead of rmtree!
                with self.assertRaises(SandboxError):
                    build_execution_ring_bwrap(
                        ring_kind="verify_ring",
                        inner_cmd=["/bin/true"],
                        cwd=pinned_vo,
                        clean_tree=pinned_ct,
                        verify_out_dir=pinned_vo,
                    )
            finally:
                os.close(p_fd)

            # 3. Replacing `run_dir` (containing `sandbox_home_*` OAuth credentials) with a same-named empty real directory
            #    is caught by persisted `(run_dir_dev, run_dir_ino)` -> retains `reclaiming` (NEVER releases slot)!
            sroot16 = base / "state16"
            db16 = AutopilotDB(sroot16 / "autopilot.db")
            try:
                cfg16 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db16.upsert_project(cfg16)
                db16.ensure_lease_slots("pa", ["pa:slot-1"], sroot16 / "locks")
                db16.ensure_work_unit(unit_key="o/r#160", project_id="pa", repo="o/r", issue_number=160)
                st_rc16 = os.lstat(rc16)
                rdir16 = rc16 / "runs" / "claim-160"
                ce16 = db16.claim_and_reserve(
                    unit_key="o/r#160", cfg=cfg16, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-160.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-160.service")), base_sha=sha16, authorized_head_ref="agent/160",
                    run_dir=str(rdir16), worktree_path=str(rc16 / "worktrees" / "wt-160"), managed_gitdir=str(mg16),
                    frozen_cache_dir=str(rc16), frozen_cache_dev=int(st_rc16.st_dev), frozen_cache_ino=int(st_rc16.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot16 / "sealed_tokens" / "claim-pa-160.gh_token"),
                )
                # Worker startup records `(run_dir_dev, run_dir_ino)` BEFORE writing `sandbox_home_*` credentials:
                fd16 = ap_cli._open_verified_claim_cache_fd(db16.get_claim(ce16), rc16)
                assert fd16 is not None
                try:
                    *_, rfd16 = ap_cli._prepare_worker_pinned_paths(db16.get_claim(ce16), ce16, rc16, fd16, db=db16)
                    os.close(rfd16)
                finally:
                    os.close(fd16)
                sbh16 = ensure_secure_dir(rdir16 / "sandbox_home_codex_1", 0o700)
                st_sbh16 = os.lstat(sbh16)
                db16.register_claim_credential_dir(ce16, int(st_sbh16.st_dev), int(st_sbh16.st_ino), "sandbox_home_codex_1")
                (sbh16 / "auth.json").write_text('{"token":"secret"}', encoding="utf-8")

                # Move original `rdir16` away and create a brand-new empty real directory at `rdir16`:
                os.rename(rdir16, rc16 / "runs" / "claim-160-moved")
                ensure_secure_dir(rdir16, 0o700)
                self.assertFalse(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db16, db16.get_claim(ce16), cfg16),
                    "Same-named empty replacement `run_dir` MUST fail `(run_dir_dev, run_dir_ino)` check and retain lease!",
                )
                self.assertEqual(db16.get_claim(ce16)["state"], "reclaiming")

                # Restoring original `rdir16` allows dir_fd-pinned credential purge + clean release!
                os.rmdir(rdir16)
                os.rename(rc16 / "runs" / "claim-160-moved", rdir16)
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db16, db16.get_claim(ce16), cfg16))
                self.assertFalse((rdir16 / "sandbox_home_codex_1").exists())
                self.assertEqual(db16.get_claim(ce16)["state"], "released")
            finally:
                db16.close()

    def test_round17_all_codex_closures(self) -> None:
        """Regression suite covering all 4 Round-17 Codex Astra findings."""
        import sqlite3
        import agent_autopilot as ap_cli
        from ap_core.chef_loop import run_verify_ring_command
        from ap_core.models import ensure_secure_dir
        from ap_core.sandbox import SandboxError, cleanup_sandbox_home_at_dirfd, prepare_sandbox_home

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo17"
            sha17 = _init_git_repo(src_r)
            rc17 = ensure_secure_dir(base / "cache17" / "pa" / "o__r", 0o700)
            mg17 = ensure_managed_bare_repo(src_r, rc17 / "managed.git")

            # 1. `run_verify_ring_command` holds `ct_fd` and `vo_fd` open through `pass_fds` + `--ro-bind-fd` / `--bind-fd`:
            ct17 = ensure_secure_dir(rc17 / "runs" / "claim-v17" / "clean-tree-17", 0o700)
            (ct17 / "verdict.txt").write_text("EXACT_CANDIDATE_17\n", encoding="utf-8")
            vo17 = rc17 / "runs" / "claim-v17" / "verify-out-17-r1"
            v_rc, _, v_out = run_verify_ring_command(
                clean_tree_dir=ct17,
                verify_out_dir=vo17,
                dod_cmd="cat verdict.txt",
                use_bwrap=True,
            )
            self.assertEqual(v_rc, 0)
            self.assertIn("EXACT_CANDIDATE_17", v_out)

            # 2. Worker retains `run_dir_fd` open: even if `runs/claim-w17` is swapped to directory B right after
            #    `_prepare_worker_pinned_paths` records A's `(dev, ino)`, `prepare_sandbox_home` writes OAuth credentials ONLY to A (ZERO to B)!
            fake_home = ensure_secure_dir(base / "fake_home", 0o700)
            ensure_secure_dir(fake_home / ".codex", 0o700)
            (fake_home / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"tok_17"}}', encoding="utf-8")
            sroot17 = base / "state17"
            db17 = AutopilotDB(sroot17 / "autopilot.db")
            try:
                cfg17 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db17.upsert_project(cfg17)
                db17.ensure_lease_slots("pa", ["pa:slot-1"], sroot17 / "locks")
                db17.ensure_work_unit(unit_key="o/r#170", project_id="pa", repo="o/r", issue_number=170)
                st_rc17 = os.lstat(rc17)
                rdir_a = rc17 / "runs" / "claim-w17"
                ce17 = db17.claim_and_reserve(
                    unit_key="o/r#170", cfg=cfg17, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-170.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-170.service")), base_sha=sha17, authorized_head_ref="agent/170",
                    run_dir=str(rdir_a), worktree_path=str(rc17 / "worktrees" / "wt-170"), managed_gitdir=str(mg17),
                    frozen_cache_dir=str(rc17), frozen_cache_dev=int(st_rc17.st_dev), frozen_cache_ino=int(st_rc17.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot17 / "sealed_tokens" / "claim-pa-170.gh_token"),
                )
                rc_fd17 = ap_cli._open_verified_claim_cache_fd(db17.get_claim(ce17), rc17)
                assert rc_fd17 is not None
                try:
                    _, _, pinned_rdir, _, retained_rfd = ap_cli._prepare_worker_pinned_paths(
                        db17.get_claim(ce17), ce17, rc17, rc_fd17, db=db17
                    )
                    try:
                        # Swap `rdir_a` path on disk to replacement directory B BEFORE `prepare_sandbox_home` writes credentials!
                        rdir_a_moved = rc17 / "runs" / "claim-w17-orig-A"
                        os.rename(rdir_a, rdir_a_moved)
                        rdir_b = ensure_secure_dir(rdir_a, 0o700)
                        sbh_p = prepare_sandbox_home(
                            pinned_rdir, "codex", host_home=fake_home, run_dir_fd=retained_rfd, db=db17, claim_epoch=ce17
                        )
                        self.assertEqual(list(rdir_b.iterdir()), [], "Unregistered replacement dir B MUST receive ZERO credentials!")
                        self.assertTrue((rdir_a_moved / sbh_p.name / ".codex" / "auth.json").is_file())
                    finally:
                        os.close(retained_rfd)
                finally:
                    os.close(rc_fd17)

                # Restore A to `rdir_a` and verify reclaim cleans A and releases slot:
                os.rmdir(rdir_a)
                os.rename(rdir_a_moved, rdir_a)
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db17, db17.get_claim(ce17), cfg17))
                self.assertEqual(db17.get_claim(ce17)["state"], "released")

                # 3. Pre-upgrade active claim (`run_dir_state = 'legacy_untracked'`, `run_dir_dev/ino = NULL`) MUST NOT accept
                #    a same-named empty directory as proof of credential cleanup -> retains `reclaiming`!
                db17.ensure_work_unit(unit_key="o/r#171", project_id="pa", repo="o/r", issue_number=171)
                rdir_leg = ensure_secure_dir(rc17 / "runs" / "claim-leg171", 0o700)
                ce_leg = db17.claim_and_reserve(
                    unit_key="o/r#171", cfg=cfg17, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-171.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-171.service")), base_sha=sha17, authorized_head_ref="agent/171",
                    run_dir=str(rdir_leg), worktree_path=str(rc17 / "worktrees" / "wt-171"), managed_gitdir=str(mg17),
                    frozen_cache_dir=str(rc17), frozen_cache_dev=int(st_rc17.st_dev), frozen_cache_ino=int(st_rc17.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot17 / "sealed_tokens" / "claim-pa-171.gh_token"),
                )
                # Simulate pre-upgrade row where `run_dir_dev=NULL, run_dir_ino=NULL, run_dir_state='legacy_untracked'`:
                raw_c = sqlite3.connect(str(sroot17 / "autopilot.db"))
                raw_c.execute("UPDATE run_claims SET run_dir_dev = NULL, run_dir_ino = NULL, run_dir_state = 'legacy_untracked' WHERE claim_epoch = ?", (ce_leg,))
                raw_c.commit()
                raw_c.close()
                self.assertFalse(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db17, db17.get_claim(ce_leg), cfg17),
                    "Pre-upgrade active claim lacking run_dir_dev/ino MUST retain 'reclaiming' even on empty same-named dir!",
                )
                self.assertEqual(db17.get_claim(ce_leg)["state"], "reclaiming")

                # 4. Renamed `sandbox_home_a -> sandbox_home_b` after enumeration raises `SandboxError` (never silently succeeding)
                #    AND post-purge rescan catches any remaining `sandbox_home_*`!
                rdir_ren = ensure_secure_dir(base / "rdir_ren", 0o700)
                sbh_a = ensure_secure_dir(rdir_ren / "sandbox_home_codex_a", 0o700)
                (sbh_a / "tok").write_text("sec", encoding="utf-8")
                ino_a = os.lstat(sbh_a).st_ino
                os.rename(sbh_a, rdir_ren / "sandbox_home_codex_b")
                ren_fd = os.open(str(rdir_ren), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    with self.assertRaises(SandboxError):
                        cleanup_sandbox_home_at_dirfd(ren_fd, "sandbox_home_codex_a", expected_ino=ino_a)
                finally:
                    os.close(ren_fd)
            finally:
                db17.close()

    def test_round18_all_codex_closures(self) -> None:
        """Regression suite covering all 5 Round-18 Codex Astra findings."""
        import agent_autopilot as ap_cli
        from ap_core.chef_loop import run_verify_ring_command
        from ap_core.git_gate import export_verified_clean_tree
        from ap_core.models import ensure_secure_dir
        from ap_core.sandbox import build_execution_ring_bwrap, build_model_ring_bwrap, prepare_sandbox_home_fd

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo18"
            sha18 = _init_git_repo(src_r)
            rc18 = ensure_secure_dir(base / "cache18" / "pa" / "o__r", 0o700)
            mg18 = ensure_managed_bare_repo(src_r, rc18 / "managed.git")
            tree_oid = subprocess.check_output(
                ["git", "--git-dir", str(mg18), "rev-parse", f"{sha18}^{{tree}}"], text=True
            ).strip()

            # 1 & 2. `export_verified_clean_tree(..., retain_fd=True)` retains `ct_fd` from Git OID check into `verify_ring`:
            #        Even if `clean_tree` path on disk is swapped to tree B BEFORE `run_verify_ring_command`, `verify_ring` runs tree C (`ct_fd`)!
            ct_path, ct_fd = export_verified_clean_tree(
                managed_gitdir=mg18,
                tree_oid=tree_oid,
                clean_tree_dir=rc18 / "runs" / "claim-18" / "clean-tree-C",
                retain_fd=True,
            )
            try:
                ct_disk = rc18 / "runs" / "claim-18" / "clean-tree-C"
                os.rename(ct_disk, rc18 / "runs" / "claim-18" / "clean-tree-C-moved")
                evil_b = ensure_secure_dir(ct_disk, 0o700)
                (evil_b / "src").mkdir()
                (evil_b / "src" / "calc.py").write_text("EVIL_REPLACEMENT_TREE\n", encoding="utf-8")
                v_rc, _, v_out = run_verify_ring_command(
                    clean_tree_dir=ct_path,
                    verify_out_dir=rc18 / "runs" / "claim-18" / "verify-out-C-r1",
                    dod_cmd="cat src/calc.py",
                    use_bwrap=True,
                    clean_tree_fd=ct_fd,
                )
                self.assertEqual(v_rc, 0)
                self.assertIn("def add", v_out)
                self.assertNotIn("EVIL_REPLACEMENT_TREE", v_out)
            finally:
                os.close(ct_fd)

            # 3. Single `tbc_fd` used for integrity check, enumeration, AND `node_modules` `--ro-bind-fd` mounts:
            tbc_a = ensure_secure_dir(base / "tbc_A", 0o700)
            (tbc_a / ".ready").write_text("ok\n", encoding="utf-8")
            ensure_secure_dir(tbc_a / "node_modules" / "pkg-a", 0o755)
            (tbc_a / "node_modules" / "pkg-a" / "ver.txt").write_text("FROM_CACHE_A\n", encoding="utf-8")
            ct_nm = ensure_secure_dir(base / "ct_nm", 0o700)
            vo_nm = base / "vo_nm"
            rfds3: list[int] = []
            try:
                argv3 = build_execution_ring_bwrap(
                    ring_kind="verify_ring",
                    inner_cmd=["/bin/cat", "node_modules/pkg-a/ver.txt"],
                    cwd=vo_nm,
                    clean_tree=ct_nm,
                    verify_out_dir=vo_nm,
                    trusted_base_cache=tbc_a,
                    retain_fds=rfds3,
                )
                self.assertIn("--ro-bind-fd", argv3)
                p3 = subprocess.run(argv3, capture_output=True, text=True, pass_fds=tuple(rfds3), timeout=20, check=False)
                self.assertEqual(p3.returncode, 0)
                self.assertEqual(p3.stdout.strip(), "FROM_CACHE_A")
            finally:
                for _f in rfds3:
                    os.close(_f)

            # 4. `prepare_sandbox_home_fd` + `build_model_ring_bwrap(..., sandbox_home_fd=sbh_fd, retain_fds=...)` mounts `/home/sandbox` via `--bind-fd`!
            fake_h = ensure_secure_dir(base / "fake_h18", 0o700)
            ensure_secure_dir(fake_h / ".codex", 0o700)
            (fake_h / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"TOK_A_ONLY"}}', encoding="utf-8")
            sroot18 = base / "state18"
            db18 = AutopilotDB(sroot18 / "autopilot.db")
            try:
                cfg18 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db18.upsert_project(cfg18)
                db18.ensure_lease_slots("pa", ["pa:slot-1"], sroot18 / "locks")
                db18.ensure_work_unit(unit_key="o/r#180", project_id="pa", repo="o/r", issue_number=180)
                st_rc18 = os.lstat(rc18)
                rdir18 = ensure_secure_dir(rc18 / "runs" / "claim-180", 0o700)
                ce18 = db18.claim_and_reserve(
                    unit_key="o/r#180", cfg=cfg18, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-180.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-180.service")), base_sha=sha18, authorized_head_ref="agent/180",
                    run_dir=str(rdir18), worktree_path=str(rc18 / "worktrees" / "wt-180"), managed_gitdir=str(mg18),
                    frozen_cache_dir=str(rc18), frozen_cache_dev=int(st_rc18.st_dev), frozen_cache_ino=int(st_rc18.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot18 / "sealed_tokens" / "claim-pa-180.gh_token"),
                )
                rfd18 = os.open(str(rdir18), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    sb_p, sbh_fd, sbh_nm, _ = prepare_sandbox_home_fd(
                        rdir18, "codex", host_home=fake_h, run_dir_fd=rfd18, db=db18, claim_epoch=ce18
                    )
                    try:
                        # Swap `rdir18 / sbh_nm` to evil sandbox B BEFORE `build_model_ring_bwrap`!
                        os.rename(rdir18 / sbh_nm, rdir18 / "archived_creds")
                        ensure_secure_dir(rdir18 / sbh_nm, 0o700)
                        mfds: list[int] = []
                        try:
                            m_argv = build_model_ring_bwrap(
                                role_key="codex:readonly_model",
                                host_binaries=ap_cli.resolve_host_binaries(),
                                sandbox_home=sb_p,
                                outbox_dir=ensure_secure_dir(rdir18 / "obox", 0o700),
                                proxy_sock=None,
                                inner_cmd=["/usr/local/bin/codex", "--version"],
                                review_bundle_dir=ensure_secure_dir(rdir18 / "rb", 0o700),
                                sandbox_home_fd=sbh_fd,
                                retain_fds=mfds,
                            )
                            self.assertIn("--bind-fd", m_argv)
                        finally:
                            for _mf in mfds:
                                os.close(_mf)
                    finally:
                        os.close(sbh_fd)
                finally:
                    os.close(rfd18)

                # 5. Credential directory moved OUTSIDE `rdir18` (`archived_outside`) after registration in `claim_credential_dirs`:
                #    BOTH Round 1 AND Round 2 of reclaim MUST refuse to release (`state == 'reclaiming'`) until purged!
                os.rename(rdir18 / "archived_creds", base / "stolen_outside_creds")
                self.assertFalse(ap_cli._reclaim_single_claim_via_bounded_unit(db18, db18.get_claim(ce18), cfg18))
                self.assertFalse(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db18, db18.get_claim(ce18), cfg18),
                    "Second reclaim round MUST STILL retain 'reclaiming' while registered credential inode is unpurged!",
                )
                self.assertEqual(db18.get_claim(ce18)["state"], "reclaiming")

                # Moving it back into `rdir18` under ANY name (`archived`) lets reclaim match by `(dev, ino)`, purge it, and release!
                os.rename(base / "stolen_outside_creds", rdir18 / "archived")
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db18, db18.get_claim(ce18), cfg18))
                self.assertFalse((rdir18 / "archived").exists())
                self.assertEqual(db18.get_claim(ce18)["state"], "released")
            finally:
                db18.close()

    def test_round19_all_codex_closures(self) -> None:
        """Regression suite covering all 6 Round-19 Codex Astra findings."""
        import contextlib
        import sqlite3
        import agent_autopilot as ap_cli
        from ap_core.models import empty_and_fsync_dirfd, ensure_secure_dir
        from ap_core.sandbox import cleanup_sandbox_home_at_dirfd, safe_read_outbox_file_fd

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo19"
            sha19 = _init_git_repo(src_r)
            rc19 = ensure_secure_dir(base / "cache19" / "pa" / "o__r", 0o700)
            mg19 = ensure_managed_bare_repo(src_r, rc19 / "managed.git")

            # 1. Outbox `verdict.json` read via retained `obox_fd` (`safe_read_outbox_file_fd`), immune to path swap to B (`APPROVE`)!
            obox_a = ensure_secure_dir(base / "outbox_A", 0o700)
            obox_fd = os.open(str(obox_a), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                (obox_a / "verdict.json").write_text('{"verdict":"REVISE","defect_count":1}', encoding="utf-8")
                os.rename(obox_a, base / "outbox_A_moved")
                obox_b = ensure_secure_dir(base / "outbox_A", 0o700)
                (obox_b / "verdict.json").write_text('{"verdict":"APPROVE","defect_count":0}', encoding="utf-8")
                read_v = safe_read_outbox_file_fd(obox_fd, "verdict.json")
                self.assertIsNotNone(read_v)
                self.assertIn('"REVISE"', read_v)
                self.assertNotIn('"APPROVE"', read_v)
            finally:
                os.close(obox_fd)

            # 2 & 3. `cleanup_sandbox_home_at_dirfd` empties A via `sbh_fd`, commits ledger BEFORE `os.rmdir`, and NEVER deletes non-empty replacement B!
            pdir = ensure_secure_dir(base / "pdir19", 0o700)
            sbh_a = ensure_secure_dir(pdir / "sandbox_home_codex_1", 0o700)
            (sbh_a / "auth.json").write_text("SECRET", encoding="utf-8")
            st_a = os.lstat(sbh_a)
            committed_ledger: list[tuple[int, int]] = []

            def _simulate_swap_after_empty(d: int, i: int) -> None:
                committed_ledger.append((d, i))
                # Simulate A being moved away and non-empty B taking `sandbox_home_codex_1` right before `os.rmdir`!
                os.rename(pdir / "sandbox_home_codex_1", pdir / "emptied_A_moved")
                rep_b = ensure_secure_dir(pdir / "sandbox_home_codex_1", 0o700)
                (rep_b / "victim.txt").write_text("DO_NOT_DELETE_B", encoding="utf-8")

            pfd = os.open(str(pdir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                cleanup_sandbox_home_at_dirfd(
                    pfd,
                    "sandbox_home_codex_1",
                    expected_dev=int(st_a.st_dev),
                    expected_ino=int(st_a.st_ino),
                    on_emptied_before_rmdir=_simulate_swap_after_empty,
                )
            finally:
                os.close(pfd)
            self.assertEqual(committed_ledger, [(int(st_a.st_dev), int(st_a.st_ino))])
            self.assertEqual(list((pdir / "emptied_A_moved").iterdir()), [], "Original A MUST be 100% emptied of credentials!")
            self.assertEqual((pdir / "sandbox_home_codex_1" / "victim.txt").read_text(encoding="utf-8"), "DO_NOT_DELETE_B")

            # 4. Pre-ledger bound claim (`run_dir_state='bound'`, `cred_ledger_tracked=0`) with renamed `archived` dir retains `reclaiming`!
            sroot19 = base / "state19"
            db19 = AutopilotDB(sroot19 / "autopilot.db")
            try:
                cfg19 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db19.upsert_project(cfg19)
                db19.ensure_lease_slots("pa", ["pa:slot-1"], sroot19 / "locks")
                db19.ensure_work_unit(unit_key="o/r#190", project_id="pa", repo="o/r", issue_number=190)
                st_rc19 = os.lstat(rc19)
                rdir19 = ensure_secure_dir(rc19 / "runs" / "claim-190", 0o700)
                arch19 = ensure_secure_dir(rdir19 / "archived", 0o700)
                (arch19 / "auth.json").write_text("LEGACY_TOKEN", encoding="utf-8")
                ce19 = db19.claim_and_reserve(
                    unit_key="o/r#190", cfg=cfg19, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-190.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-190.service")), base_sha=sha19, authorized_head_ref="agent/190",
                    run_dir=str(rdir19), worktree_path=str(rc19 / "worktrees" / "wt-190"), managed_gitdir=str(mg19),
                    frozen_cache_dir=str(rc19), frozen_cache_dev=int(st_rc19.st_dev), frozen_cache_ino=int(st_rc19.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot19 / "sealed_tokens" / "claim-pa-190.gh_token"),
                )
                raw19 = sqlite3.connect(str(sroot19 / "autopilot.db"))
                raw19.execute("UPDATE run_claims SET cred_ledger_tracked = 0 WHERE claim_epoch = ?", (ce19,))
                raw19.commit()
                raw19.close()
                self.assertFalse(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db19, db19.get_claim(ce19), cfg19),
                    "Pre-ledger bound claim (`cred_ledger_tracked=0`) MUST retain 'reclaiming' so renamed `archived` tokens never leak!",
                )
                self.assertEqual(db19.get_claim(ce19)["state"], "reclaiming")
            finally:
                db19.close()

            # 5 & 6. `empty_and_fsync_dirfd` + `os.rmdir` preserves any non-empty replacement directory at the same name!
            smk_parent = ensure_secure_dir(base / "smk_parent", 0o700)
            p_smk_fd = os.open(str(smk_parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.mkdir(".smoke-vo", 0o700, dir_fd=p_smk_fd)
                vo_fd = os.open(".smoke-vo", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=p_smk_fd)
                try:
                    (smk_parent / ".smoke-vo" / "tmp.txt").write_text("temp", encoding="utf-8")
                    os.rename(smk_parent / ".smoke-vo", smk_parent / ".smoke-vo-orig")
                    rep_smk = ensure_secure_dir(smk_parent / ".smoke-vo", 0o700)
                    (rep_smk / "keep.txt").write_text("KEEP_REPLACEMENT", encoding="utf-8")
                    empty_and_fsync_dirfd(vo_fd)
                finally:
                    os.close(vo_fd)
                with contextlib.suppress(OSError):
                    os.rmdir(".smoke-vo", dir_fd=p_smk_fd)
            finally:
                os.close(p_smk_fd)
            self.assertEqual(list((smk_parent / ".smoke-vo-orig").iterdir()), [])
            self.assertEqual((smk_parent / ".smoke-vo" / "keep.txt").read_text(encoding="utf-8"), "KEEP_REPLACEMENT")

    def test_round20_all_codex_closures(self) -> None:
        """Regression suite covering all 7 Round-20 Codex Astra findings."""
        import errno
        import sqlite3
        from unittest import mock
        import agent_autopilot as ap_cli
        from ap_core.git_gate import prepare_trusted_base_cache_fd
        from ap_core.models import AutopilotError, empty_and_fsync_dirfd, ensure_secure_dir, pinned_proc_fd_path
        from ap_core.sandbox import SandboxError, build_execution_ring_bwrap, cleanup_sandbox_home_at_dirfd, prepare_sandbox_home_fd

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo20"
            sha20 = _init_git_repo(src_r)
            rc20 = ensure_secure_dir(base / "cache20" / "pa" / "o__r", 0o700)
            mg20 = ensure_managed_bare_repo(src_r, rc20 / "managed.git")

            # 1. Cargo pre-model smoke check (`skip_clean_tree_copy=True`, `clean_tree_fd`, `verify_out_fd`, `trusted_base_cache_fd`):
            #    Executes `cargo --version` inside `verify_ring` using two `/proc/<pid>/fd/<n>` directories with ZERO ENOTDIR!
            tbc_cargo = ensure_secure_dir(base / "tbc_cargo20", 0o700)
            (tbc_cargo / ".ready").write_text("ok\n", encoding="utf-8")
            ensure_secure_dir(tbc_cargo / "cargo_home", 0o700)
            tbc_c_fd = os.open(str(tbc_cargo), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            rdir_smk = ensure_secure_dir(base / "rdir_smk20", 0o700)
            rdir_smk_fd = os.open(str(rdir_smk), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.mkdir(".cargo-smoke-ct", 0o700, dir_fd=rdir_smk_fd)
                ct_smk_fd = os.open(".cargo-smoke-ct", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rdir_smk_fd)
                os.mkdir(".cargo-smoke-vo", 0o700, dir_fd=rdir_smk_fd)
                vo_smk_fd = os.open(".cargo-smoke-vo", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rdir_smk_fd)
                smk_fds: list[int] = []
                try:
                    c_argv = build_execution_ring_bwrap(
                        ring_kind="verify_ring",
                        inner_cmd=["/bin/bash", "-lc", "cargo --version"],
                        cwd=pinned_proc_fd_path(vo_smk_fd),
                        clean_tree=pinned_proc_fd_path(ct_smk_fd),
                        verify_out_dir=pinned_proc_fd_path(vo_smk_fd),
                        trusted_base_cache=tbc_cargo,
                        skip_clean_tree_copy=True,
                        retain_fds=smk_fds,
                        clean_tree_fd=ct_smk_fd,
                        verify_out_fd=vo_smk_fd,
                        trusted_base_cache_fd=tbc_c_fd,
                    )
                    c_proc = subprocess.run(c_argv, capture_output=True, text=True, pass_fds=tuple(smk_fds), timeout=20, check=False)
                    self.assertEqual(c_proc.returncode, 0, c_proc.stderr)
                    self.assertIn("cargo", c_proc.stdout.lower())
                finally:
                    for _f in smk_fds:
                        os.close(_f)
                    os.close(vo_smk_fd)
                    os.close(ct_smk_fd)
            finally:
                os.close(rdir_smk_fd)
                os.close(tbc_c_fd)

            # 2, 3, 7. Reclaim ledger invariants:
            #   (2) Stranger non-empty replacement B at `sandbox_home_*` is NEVER emptied even on Round 2 & Round 3 of reclaim!
            #   (3) Crash after `empty_and_fsync_dirfd` and BEFORE `mark_claim_credential_dir_purged` (`purged=0` on 0-entry shell)
            #       commits `purged=1` and releases cleanly on retry!
            #   (7) Pre-upgrade `routine` claim (`unit_kind='routine'`, `run_dir_state='bound'`, `cred_ledger_tracked=0`) releases cleanly!
            fake_h20 = ensure_secure_dir(base / "fake_h20", 0o700)
            ensure_secure_dir(fake_h20 / ".codex", 0o700)
            (fake_h20 / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"TOK20"}}', encoding="utf-8")
            sroot20 = base / "state20"
            db20 = AutopilotDB(sroot20 / "autopilot.db")
            try:
                cfg20 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db20.upsert_project(cfg20)
                db20.ensure_lease_slots("pa", ["pa:slot-1"], sroot20 / "locks")

                # (2) Stranger non-empty replacement directory B at `sandbox_home_*` survives multiple reclaim rounds:
                db20.ensure_work_unit(unit_key="o/r#200", project_id="pa", repo="o/r", issue_number=200)
                st_rc20 = os.lstat(rc20)
                rdir200 = ensure_secure_dir(rc20 / "runs" / "claim-200", 0o700)
                ce200 = db20.claim_and_reserve(
                    unit_key="o/r#200", cfg=cfg20, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-200.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-200.service")), base_sha=sha20, authorized_head_ref="agent/200",
                    run_dir=str(rdir200), worktree_path=str(rc20 / "worktrees" / "wt-200"), managed_gitdir=str(mg20),
                    frozen_cache_dir=str(rc20), frozen_cache_dev=int(st_rc20.st_dev), frozen_cache_ino=int(st_rc20.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot20 / "sealed_tokens" / "claim-pa-200.gh_token"),
                )
                rfd200 = os.open(str(rdir200), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _, sbh_fd200, sbh_nm200, sbh_ino200 = prepare_sandbox_home_fd(
                        rdir200, "codex", host_home=fake_h20, run_dir_fd=rfd200, db=db20, claim_epoch=ce200
                    )
                    sbh_dev200 = int(os.fstat(sbh_fd200).st_dev)
                    empty_and_fsync_dirfd(sbh_fd200, on_dir_emptied=lambda d, i: db20.mark_claim_credential_dir_purged(ce200, d, i))
                    db20.mark_claim_credential_dir_purged(ce200, sbh_dev200, sbh_ino200)
                    os.close(sbh_fd200)
                    os.rmdir(sbh_nm200, dir_fd=rfd200)
                    # Stranger non-empty B (even if ext4 reuses freed inode OR allocates a brand-new inode!) occupies `sbh_nm200`:
                    (rdir200 / ".hold_freed_ino").write_text("hold", encoding="utf-8")
                    rep_b200 = ensure_secure_dir(rdir200 / sbh_nm200, 0o700)
                    (rdir200 / ".hold_freed_ino").unlink()
                    (rep_b200 / "precious.txt").write_text("KEEP_B_ACROSS_ROUNDS", encoding="utf-8")
                finally:
                    os.close(rfd200)
                self.assertFalse(ap_cli._reclaim_single_claim_via_bounded_unit(db20, db20.get_claim(ce200), cfg20))
                self.assertFalse(ap_cli._reclaim_single_claim_via_bounded_unit(db20, db20.get_claim(ce200), cfg20))
                self.assertEqual(
                    (rdir200 / sbh_nm200 / "precious.txt").read_text(encoding="utf-8"),
                    "KEEP_B_ACROSS_ROUNDS",
                    "Stranger replacement B MUST NEVER be emptied on Round 1 or Round 2 of reclaim!",
                )
                # Removing stranger B manually allows reclaim to finish cleanly:
                (rdir200 / sbh_nm200 / "precious.txt").unlink()
                (rdir200 / sbh_nm200).rmdir()
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db20, db20.get_claim(ce200), cfg20))
                self.assertEqual(db20.get_claim(ce200)["state"], "released")

                # (3) Crash AFTER `empty_and_fsync_dirfd(A)` and BEFORE `mark_claim_credential_dir_purged` (`purged=0` on 0-entry shell):
                db20.ensure_work_unit(unit_key="o/r#201", project_id="pa", repo="o/r", issue_number=201)
                rdir201 = ensure_secure_dir(rc20 / "runs" / "claim-201", 0o700)
                ce201 = db20.claim_and_reserve(
                    unit_key="o/r#201", cfg=cfg20, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-201.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-201.service")), base_sha=sha20, authorized_head_ref="agent/201",
                    run_dir=str(rdir201), worktree_path=str(rc20 / "worktrees" / "wt-201"), managed_gitdir=str(mg20),
                    frozen_cache_dir=str(rc20), frozen_cache_dev=int(st_rc20.st_dev), frozen_cache_ino=int(st_rc20.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot20 / "sealed_tokens" / "claim-pa-201.gh_token"),
                )
                rfd201 = os.open(str(rdir201), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _, sbh_fd201, _, _ = prepare_sandbox_home_fd(
                        rdir201, "codex", host_home=fake_h20, run_dir_fd=rfd201, db=db20, claim_epoch=ce201
                    )
                    # Empty A (including `.codex`), then simulate SIGKILL BEFORE top-level `mark_claim_credential_dir_purged`:
                    empty_and_fsync_dirfd(sbh_fd201, on_dir_emptied=lambda d, i: db20.mark_claim_credential_dir_purged(ce201, d, i))
                    os.close(sbh_fd201)
                finally:
                    os.close(rfd201)
                self.assertEqual(len(db20.list_unpurged_claim_credential_dirs(ce201)), 1)
                self.assertTrue(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db20, db20.get_claim(ce201), cfg20),
                    "0-entry registered shell with purged=0 MUST commit purged=1 + rmdir and release cleanly!",
                )
                self.assertEqual(db20.list_unpurged_claim_credential_dirs(ce201), [])
                self.assertEqual(db20.get_claim(ce201)["state"], "released")

                # (7) Pre-upgrade `routine` claim (`unit_kind='routine'`, `run_dir_state='bound'`, `cred_ledger_tracked=0`) releases cleanly:
                cfg_rt = WorkflowConfig(project_id="pay_rt", kind="routine", repos=(), routine_driver="lark_payments", enabled=True, workspace_path=str(base))
                db20.upsert_project(cfg_rt)
                db20.ensure_lease_slots("pay_rt", ["pay_rt:slot-1"], sroot20 / "locks")
                db20.ensure_work_unit(unit_key="pay_rt:routine", project_id="pay_rt", repo="")
                rt_parent = ensure_secure_dir(base / "rt_cache", 0o700)
                st_rtp = os.lstat(rt_parent)
                rt_rdir = ensure_secure_dir(rt_parent / "claim-rt1", 0o700)
                ce_rt = db20.claim_and_reserve(
                    unit_key="pay_rt:routine", cfg=cfg_rt, slot_keys=["pay_rt:slot-1"], worker_unit_name="ap-nonexist-rt1.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-rt1.service")), base_sha="routine", authorized_head_ref="agent/routine",
                    run_dir=str(rt_rdir), frozen_cache_dir=str(rt_parent), frozen_cache_dev=int(st_rtp.st_dev), frozen_cache_ino=int(st_rtp.st_ino),
                )
                raw20 = sqlite3.connect(str(sroot20 / "autopilot.db"))
                raw20.execute("UPDATE run_claims SET cred_ledger_tracked = 0 WHERE claim_epoch = ?", (ce_rt,))
                raw20.commit()
                raw20.close()
                self.assertTrue(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db20, db20.get_claim(ce_rt), cfg_rt),
                    "Pre-upgrade routine bound claim (`cred_ledger_tracked=0`) MUST reclaim cleanly!",
                )
                self.assertEqual(db20.get_claim(ce_rt)["state"], "released")
            finally:
                db20.close()

            # 4 & 6. `empty_and_fsync_dirfd` propagates `os.fsync` EIO BEFORE `on_emptied_before_rmdir`, AND leaks 0 FDs across deep trees!
            eio_parent = ensure_secure_dir(base / "eio_p", 0o700)
            sbh_eio = ensure_secure_dir(eio_parent / "sandbox_home_eio", 0o700)
            (sbh_eio / "tok").write_text("x", encoding="utf-8")
            eio_pfd = os.open(str(eio_parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            ledger_called = False
            try:
                with mock.patch("os.fsync", side_effect=OSError(errno.EIO, "simulated EIO")):
                    with self.assertRaises(SandboxError):
                        cleanup_sandbox_home_at_dirfd(
                            eio_pfd,
                            "sandbox_home_eio",
                            on_emptied_before_rmdir=lambda _d, _i: globals().update(),
                        )
                # Verify callback is NOT invoked on EIO:
                cb_hits: list[int] = []
                (sbh_eio / "tok2").write_text("y", encoding="utf-8")
                with mock.patch("os.fsync", side_effect=OSError(errno.EIO, "simulated EIO")):
                    with self.assertRaises(SandboxError):
                        cleanup_sandbox_home_at_dirfd(
                            eio_pfd,
                            "sandbox_home_eio",
                            on_emptied_before_rmdir=lambda _d, iv: cb_hits.append(iv),
                        )
                self.assertEqual(cb_hits, [], "on_emptied_before_rmdir MUST NOT run when os.fsync raises EIO!")
            finally:
                os.close(eio_pfd)
            _ = ledger_called

            deep_root = ensure_secure_dir(base / "deep_fd_test", 0o700)
            for idx in range(40):
                d = ensure_secure_dir(deep_root / f"sub_{idx}" / "nested", 0o700)
                (d / "f.txt").write_text("hi", encoding="utf-8")
            dfd_deep = os.open(str(deep_root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fds_before = len(os.listdir("/proc/self/fd"))
                empty_and_fsync_dirfd(dfd_deep)
                fds_after = len(os.listdir("/proc/self/fd"))
                self.assertEqual(fds_after, fds_before, f"FD leak detected in empty_and_fsync_dirfd: {fds_before} -> {fds_after}")
            finally:
                os.close(dfd_deep)

            # 5. Cold `prepare_trusted_base_cache_fd` verifies published `deps-<key>` `(dev, ino) == fstat(stage_fd)` inside `key_lock_fd`!
            pnpm_repo = base / "pnpm_swap_repo"
            _init_git_repo(pnpm_repo)
            (pnpm_repo / "package.json").write_text('{"name":"t","version":"1.0.0"}\n', encoding="utf-8")
            (pnpm_repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(pnpm_repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(pnpm_repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "lock"], check=True, capture_output=True)
            psha = subprocess.check_output(["git", "-C", str(pnpm_repo), "rev-parse", "HEAD"], text=True).strip()
            pmg = ensure_managed_bare_repo(pnpm_repo, base / "pmg.git")
            pcache = ensure_secure_dir(base / "pcache", 0o700)

            real_replace = os.replace

            def _tampering_replace(src: Any, dst: Any, *, src_dir_fd: int | None = None, dst_dir_fd: int | None = None) -> None:
                if isinstance(src, str) and src.startswith(".stage-deps-") and isinstance(dst, str) and dst.startswith("deps-") and src_dir_fd is not None:
                    # Swap `stage_name` to an unverified directory B right before publish `os.replace`!
                    real_replace(src, f"{src}-orig-A", src_dir_fd=src_dir_fd, dst_dir_fd=src_dir_fd)
                    os.mkdir(src, 0o700, dir_fd=src_dir_fd)
                    bfd = os.open(src, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=src_dir_fd)
                    try:
                        rfd_evil = os.open(".ready", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=bfd)
                        os.write(rfd_evil, b"evil\n")
                        os.close(rfd_evil)
                        os.mkdir("node_modules", 0o755, dir_fd=bfd)
                        pfd_evil = os.open("evil.txt", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=bfd)
                        os.write(pfd_evil, b"KEEP_B_UNTOUCHED")
                        os.close(pfd_evil)
                    finally:
                        os.close(bfd)
                real_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

            def _fake_prefetch(*, inner_cmd: list[str], cwd: Path, stage_dir: Path, **kwargs: Any) -> subprocess.CompletedProcess[str]:
                (stage_dir / "node_modules").mkdir(parents=True, exist_ok=True)
                return subprocess.CompletedProcess(inner_cmd, 0, "ok", "")

            with mock.patch("ap_core.sandbox.run_isolated_deps_prefetch", side_effect=_fake_prefetch):
                with mock.patch("os.replace", side_effect=_tampering_replace):
                    with self.assertRaises(AutopilotError):
                        prepare_trusted_base_cache_fd(managed_gitdir=pmg, base_sha=psha, cache_root=pcache)
            # Verify `deps-<key>` is NOT left published as a warm cache, AND replacement B's contents were preserved in `.unverified-*`!
            bdeps = pcache / "base-deps"
            self.assertEqual([p.name for p in bdeps.glob("deps-*")], [], "Unverified replacement B MUST NOT remain published at deps-<key>!")
            unver = list(bdeps.glob(".unverified-deps-*"))
            self.assertEqual(len(unver), 1)
            self.assertEqual((unver[0] / "evil.txt").read_text(encoding="utf-8"), "KEEP_B_UNTOUCHED")

    def test_round21_all_codex_closures(self) -> None:
        """Regression suite covering all 6 Round-21 Codex Astra findings."""
        import errno
        from unittest import mock
        import agent_autopilot as ap_cli
        from ap_core.git_gate import prepare_trusted_base_cache_fd
        from ap_core.models import empty_and_fsync_dirfd, ensure_secure_dir
        from ap_core.sandbox import build_deps_prefetch_bwrap, build_execution_ring_bwrap, prepare_sandbox_home_fd

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo21"
            sha21 = _init_git_repo(src_r)
            rc21 = ensure_secure_dir(base / "cache21" / "pa" / "o__r", 0o700)
            mg21 = ensure_managed_bare_repo(src_r, rc21 / "managed.git")

            # 1 & 5 & 6. Warm cache hit via `_is_valid_complete_cache_fd` (`0` rebuilds on 2nd call!),
            #            `--bind-fd` on `build_deps_prefetch_bwrap`, AND pinned stale-dir fd during stale replacement!
            pnpm_repo = base / "pnpm_warm_repo"
            _init_git_repo(pnpm_repo)
            (pnpm_repo / "package.json").write_text('{"name":"w","version":"1.0.0"}\n', encoding="utf-8")
            (pnpm_repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(pnpm_repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(pnpm_repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "lock"], check=True, capture_output=True)
            psha = subprocess.check_output(["git", "-C", str(pnpm_repo), "rev-parse", "HEAD"], text=True).strip()
            pmg = ensure_managed_bare_repo(pnpm_repo, base / "pmg21.git")
            pcache = ensure_secure_dir(base / "pcache21", 0o700)

            prefetch_calls: list[int] = []

            def _counting_prefetch(*, inner_cmd: list[str], cwd: Path, stage_dir: Path, stage_fd: int | None = None, **kwargs: Any) -> subprocess.CompletedProcess[str]:
                self.assertIsNotNone(stage_fd, "Prefetch MUST pass open stage_fd!")
                pf_ret: list[int] = []
                try:
                    pf_argv = build_deps_prefetch_bwrap(
                        inner_cmd=inner_cmd,
                        cwd=cwd,
                        stage_dir=stage_dir,
                        proxy_sock=base / "dummy.sock",
                        stage_fd=stage_fd,
                        retain_fds=pf_ret,
                    )
                    self.assertIn("--bind-fd", pf_argv)
                finally:
                    for _f in pf_ret:
                        os.close(_f)
                prefetch_calls.append(1)
                (stage_dir / "node_modules").mkdir(parents=True, exist_ok=True)
                return subprocess.CompletedProcess(inner_cmd, 0, "ok", "")

            with mock.patch("ap_core.sandbox.run_isolated_deps_prefetch", side_effect=_counting_prefetch):
                p1, fd1 = prepare_trusted_base_cache_fd(managed_gitdir=pmg, base_sha=psha, cache_root=pcache)
                assert p1 is not None and fd1 is not None
                os.close(fd1)
                # Second call MUST hit warm cache WITHOUT calling `run_isolated_deps_prefetch`!
                p2, fd2 = prepare_trusted_base_cache_fd(managed_gitdir=pmg, base_sha=psha, cache_root=pcache)
                assert p2 is not None and fd2 is not None
                os.close(fd2)
            self.assertEqual(len(prefetch_calls), 1, "Warm cache hit MUST NOT trigger cold rebuild!")

            # (6) Corrupt `.ready` to force stale replacement, and swap `.stale-deps-*` to stranger B right after quarantine rename:
            (p1 / ".ready").unlink()
            (p1 / "stale_file.txt").write_text("OLD_STALE", encoding="utf-8")
            from ap_core.models import quarantine_noreplace_at_dirfd as _real_qnr21

            def _stale_swap_quarantine(dfd: int, sname: str, pfx: str) -> str:
                dst = _real_qnr21(dfd, sname, pfx)
                if dst.startswith(".stale-deps-"):
                    os.replace(dst, f"{dst}-orig-A", src_dir_fd=dfd, dst_dir_fd=dfd)
                    os.mkdir(dst, 0o700, dir_fd=dfd)
                    sbfd = os.open(dst, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
                    try:
                        vf = os.open("keep_b.txt", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=sbfd)
                        os.write(vf, b"DO_NOT_DELETE_STALE_B")
                        os.close(vf)
                    finally:
                        os.close(sbfd)
                return dst

            with mock.patch("ap_core.sandbox.run_isolated_deps_prefetch", side_effect=_counting_prefetch):
                with mock.patch("ap_core.git_gate.quarantine_noreplace_at_dirfd", side_effect=_stale_swap_quarantine):
                    p3, fd3 = prepare_trusted_base_cache_fd(managed_gitdir=pmg, base_sha=psha, cache_root=pcache)
                    assert p3 is not None and fd3 is not None
                    os.close(fd3)
            stale_bs = [p for p in (pcache / "base-deps").glob(".stale-deps-*") if not p.name.endswith("-orig-A")]
            self.assertEqual(len(stale_bs), 1)
            self.assertEqual((stale_bs[0] / "keep_b.txt").read_text(encoding="utf-8"), "DO_NOT_DELETE_STALE_B")

            # 2 & 3. (2) Normal `round-1` reusing a freed `purged=1` inode MUST NOT block reclaim!
            #        (3) `prepare_sandbox_home_fd` rollback on `.codex` error + `fsync` EIO MUST NOT `rmdir` unpurged shell!
            fake_h21 = ensure_secure_dir(base / "fake_h21", 0o700)
            ensure_secure_dir(fake_h21 / ".codex", 0o700)
            (fake_h21 / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"TOK21"}}', encoding="utf-8")
            sroot21 = base / "state21"
            db21 = AutopilotDB(sroot21 / "autopilot.db")
            try:
                cfg21 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db21.upsert_project(cfg21)
                db21.ensure_lease_slots("pa", ["pa:slot-1"], sroot21 / "locks")
                db21.ensure_work_unit(unit_key="o/r#210", project_id="pa", repo="o/r", issue_number=210)
                st_rc21 = os.lstat(rc21)
                rdir210 = ensure_secure_dir(rc21 / "runs" / "claim-210", 0o700)
                ce210 = db21.claim_and_reserve(
                    unit_key="o/r#210", cfg=cfg21, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-210.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-210.service")), base_sha=sha21, authorized_head_ref="agent/210",
                    run_dir=str(rdir210), worktree_path=str(rc21 / "worktrees" / "wt-210"), managed_gitdir=str(mg21),
                    frozen_cache_dir=str(rc21), frozen_cache_dev=int(st_rc21.st_dev), frozen_cache_ino=int(st_rc21.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot21 / "sealed_tokens" / "claim-pa-210.gh_token"),
                )
                rfd210 = os.open(str(rdir210), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _, sbh_fd210, sbh_nm210, sbh_ino210 = prepare_sandbox_home_fd(
                        rdir210, "codex", host_home=fake_h21, run_dir_fd=rfd210, db=db21, claim_epoch=ce210
                    )
                    sbh_dev210 = int(os.fstat(sbh_fd210).st_dev)
                    empty_and_fsync_dirfd(sbh_fd210, on_dir_emptied=lambda d, i: db21.mark_claim_credential_dir_purged(ce210, d, i))
                    db21.mark_claim_credential_dir_purged(ce210, sbh_dev210, sbh_ino210)
                    os.close(sbh_fd210)
                    os.rmdir(sbh_nm210, dir_fd=rfd210)
                    # Immediately create normal artifact dir `round-1` (ext4 reuses freed `sbh_ino210`!) and populate it:
                    rnd1 = ensure_secure_dir(rdir210 / "round-1", 0o700)
                    (rnd1 / "bundle.txt").write_text("normal artifact", encoding="utf-8")
                finally:
                    os.close(rfd210)
                self.assertTrue(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db21, db21.get_claim(ce210), cfg21),
                    "Normal `round-1` reusing a freed `purged=1` inode MUST NOT block reclaim!",
                )
                self.assertEqual(db21.get_claim(ce210)["state"], "released")

                # (3) `prepare_sandbox_home_fd` rollback when `.claude` creation raises ENOSPC AND rollback `fsync` raises EIO:
                #     MUST keep directory shell on disk so later reclaim can settle `purged=0` -> `purged=1`!
                db21.ensure_work_unit(unit_key="o/r#211", project_id="pa", repo="o/r", issue_number=211)
                rdir211 = ensure_secure_dir(rc21 / "runs" / "claim-211", 0o700)
                ce211 = db21.claim_and_reserve(
                    unit_key="o/r#211", cfg=cfg21, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-211.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-211.service")), base_sha=sha21, authorized_head_ref="agent/211",
                    run_dir=str(rdir211), worktree_path=str(rc21 / "worktrees" / "wt-211"), managed_gitdir=str(mg21),
                    frozen_cache_dir=str(rc21), frozen_cache_dev=int(st_rc21.st_dev), frozen_cache_ino=int(st_rc21.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot21 / "sealed_tokens" / "claim-pa-211.gh_token"),
                )
                rfd211 = os.open(str(rdir211), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    real_mkdir = os.mkdir
                    real_fsync = os.fsync
                    fsync_cnt = [0]

                    def _fail_dot_claude(p: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
                        if p == ".claude":
                            raise OSError(errno.ENOSPC, "disk full")
                        real_mkdir(p, mode, dir_fd=dir_fd)

                    def _fail_rollback_fsync(fd_arg: int) -> None:
                        fsync_cnt[0] += 1
                        if fsync_cnt[0] >= 3:
                            raise OSError(errno.EIO, "rollback fsync EIO")
                        real_fsync(fd_arg)

                    with mock.patch("os.mkdir", side_effect=_fail_dot_claude):
                        with mock.patch("os.fsync", side_effect=_fail_rollback_fsync):
                            with self.assertRaises(OSError):
                                prepare_sandbox_home_fd(
                                    rdir211, "claude", host_home=fake_h21, run_dir_fd=rfd211, db=db21, claim_epoch=ce211
                                )
                finally:
                    os.close(rfd211)
                self.assertEqual(len(db21.list_unpurged_claim_credential_dirs(ce211)), 1)
                self.assertEqual(
                    len(list(rdir211.glob("sandbox_home_*"))),
                    1,
                    "Rollback MUST NOT rmdir shell when rollback fsync/ledger commit failed!",
                )
                # Subsequent healthy reclaim settles `purged=1` and releases slot!
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db21, db21.get_claim(ce211), cfg21))
                self.assertEqual(db21.list_unpurged_claim_credential_dirs(ce211), [])
                self.assertEqual(db21.get_claim(ce211)["state"], "released")
            finally:
                db21.close()

            # 4. `tool_ring` with `retain_fds` + `trusted_base_cache_fd` uses `--ro-bind-fd` for EVERY `node_modules` mount (zero `--ro-bind` mixup)!
            wt_t = ensure_secure_dir(base / "wt_tool21", 0o700)
            (wt_t / ".git").write_text("gitdir: /nonexistent\n", encoding="utf-8")
            tfds: list[int] = []
            tbc_t_fd = os.open(str(p3), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                t_argv = build_execution_ring_bwrap(
                    ring_kind="tool_ring",
                    inner_cmd=["/bin/true"],
                    cwd=wt_t,
                    worktree=wt_t,
                    ephemeral_tool_cache=ensure_secure_dir(base / "eph21", 0o700),
                    shared_tmp=ensure_secure_dir(base / "stmp21", 0o700),
                    retain_fds=tfds,
                    trusted_base_cache_fd=tbc_t_fd,
                )
                nm_idx = [i for i, tok in enumerate(t_argv) if tok.endswith("/node_modules")]
                self.assertTrue(len(nm_idx) >= 1)
                for i in nm_idx:
                    self.assertEqual(t_argv[i - 2], "--ro-bind-fd", f"Expected --ro-bind-fd before {t_argv[i]}, got {t_argv[i-2:i+1]}")
            finally:
                for _f in tfds:
                    os.close(_f)
                os.close(tbc_t_fd)

    def test_round22_all_codex_closures(self) -> None:
        """Regression suite covering all 5 Round-22 Codex Astra [P1] findings."""
        import errno
        from unittest import mock
        import agent_autopilot as ap_cli
        from ap_core.git_gate import prepare_trusted_base_cache_fd
        from ap_core.models import ensure_secure_dir
        from ap_core.sandbox import SandboxError, build_execution_ring_bwrap, prepare_sandbox_home_fd

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo22"
            sha22 = _init_git_repo(src_r)
            rc22 = ensure_secure_dir(base / "cache22" / "pa" / "o__r", 0o700)
            mg22 = ensure_managed_bare_repo(src_r, rc22 / "managed.git")

            # 1 & 2. (2) Unverified directory B placed at `deps-<key>` with `.ready` + `node_modules/` (simulating crash right after swapped `os.replace`)
            #            lacks matching `.deps-<key>.published.json` AND lacks `.ap-stage-owner`, so next call REJECTS B on warm check AND
            #            quarantines B to `.stale-deps-*` WITHOUT recursively deleting B's files!
            pnpm_repo = base / "pnpm_r22"
            _init_git_repo(pnpm_repo)
            (pnpm_repo / "package.json").write_text('{"name":"r22","version":"1.0.0"}\n', encoding="utf-8")
            (pnpm_repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(pnpm_repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(pnpm_repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "lock"], check=True, capture_output=True)
            psha = subprocess.check_output(["git", "-C", str(pnpm_repo), "rev-parse", "HEAD"], text=True).strip()
            pmg = ensure_managed_bare_repo(pnpm_repo, base / "pmg22.git")
            pcache = ensure_secure_dir(base / "pcache22", 0o700)

            def _fake_pf(*, inner_cmd: list[str], cwd: Path, stage_dir: Path, **kwargs: Any) -> subprocess.CompletedProcess[str]:
                (stage_dir / "node_modules").mkdir(parents=True, exist_ok=True)
                (stage_dir / "node_modules" / "good.txt").write_text("VERIFIED_CACHE", encoding="utf-8")
                return subprocess.CompletedProcess(inner_cmd, 0, "ok", "")

            with mock.patch("ap_core.sandbox.run_isolated_deps_prefetch", side_effect=_fake_pf):
                p_good, fd_good = prepare_trusted_base_cache_fd(managed_gitdir=pmg, base_sha=psha, cache_root=pcache)
                assert p_good is not None and fd_good is not None
                os.close(fd_good)

            # Simulate crash right after an attacker's B (with `.ready` + `node_modules/`, different inode!) replaced `deps-<key>`:
            os.rename(p_good, p_good.parent / "orig_good_moved")
            evil_b = ensure_secure_dir(p_good, 0o700)
            (evil_b / ".ready").write_text(f"{psha}\n", encoding="utf-8")
            ensure_secure_dir(evil_b / "node_modules", 0o755)
            (evil_b / "node_modules" / "evil.txt").write_text("UNVERIFIED_B_KEEP_INTACT", encoding="utf-8")

            with mock.patch("ap_core.sandbox.run_isolated_deps_prefetch", side_effect=_fake_pf):
                p_rebuilt, fd_rebuilt = prepare_trusted_base_cache_fd(managed_gitdir=pmg, base_sha=psha, cache_root=pcache)
                assert p_rebuilt is not None and fd_rebuilt is not None
                try:
                    self.assertTrue((Path(f"/proc/{os.getpid()}/fd/{fd_rebuilt}") / "node_modules" / "good.txt").is_file())
                    self.assertFalse((Path(f"/proc/{os.getpid()}/fd/{fd_rebuilt}") / "node_modules" / "evil.txt").exists())
                finally:
                    os.close(fd_rebuilt)
            # And stranger B was quarantined to `.stale-deps-*` WITHOUT deleting its files:
            quarantined_b = list((pcache / "base-deps").glob(".stale-deps-*"))
            self.assertEqual(len(quarantined_b), 1)
            self.assertEqual((quarantined_b[0] / "node_modules" / "evil.txt").read_text(encoding="utf-8"), "UNVERIFIED_B_KEEP_INTACT")

            # 3. `prepare_sandbox_home_fd`: if `sbh_name` is swapped between `os.mkdir` and `os.open` to B already containing `.codex/`,
            #    it refuses BEFORE ledger registration and does NOT wipe B's `.codex/`!
            rdir_sbh = ensure_secure_dir(base / "rdir_sbh22", 0o700)
            rfd_sbh = os.open(str(rdir_sbh), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            sroot22 = base / "state22"
            db22 = AutopilotDB(sroot22 / "autopilot.db")
            try:
                cfg22 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db22.upsert_project(cfg22)
                db22.ensure_lease_slots("pa", ["pa:slot-1"], sroot22 / "locks")
                db22.ensure_work_unit(unit_key="o/r#220", project_id="pa", repo="o/r", issue_number=220)
                st_rc22 = os.lstat(rc22)
                ce220 = db22.claim_and_reserve(
                    unit_key="o/r#220", cfg=cfg22, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-220.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-220.service")), base_sha=sha22, authorized_head_ref="agent/220",
                    run_dir=str(rc22 / "runs" / "claim-220"), worktree_path=str(rc22 / "worktrees" / "wt-220"), managed_gitdir=str(mg22),
                    frozen_cache_dir=str(rc22), frozen_cache_dev=int(st_rc22.st_dev), frozen_cache_ino=int(st_rc22.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot22 / "sealed_tokens" / "claim-pa-220.gh_token"),
                )
                real_mkdir22 = os.mkdir
                swapped_name: list[str] = []

                def _swap_after_sbh_mkdir(p: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
                    real_mkdir22(p, mode, dir_fd=dir_fd)
                    if isinstance(p, str) and p.startswith("sandbox_home_") and not swapped_name:
                        swapped_name.append(p)
                        os.rename(rdir_sbh / p, rdir_sbh / f"{p}-orig")
                        b_dir = ensure_secure_dir(rdir_sbh / p, 0o700)
                        ensure_secure_dir(b_dir / ".codex", 0o700)
                        (b_dir / ".codex" / "precious.json").write_text("DO_NOT_WIPE_B_CODEX", encoding="utf-8")

                with mock.patch("os.mkdir", side_effect=_swap_after_sbh_mkdir):
                    with self.assertRaises(SandboxError):
                        prepare_sandbox_home_fd(rdir_sbh, "codex", run_dir_fd=rfd_sbh, db=db22, claim_epoch=ce220)
                self.assertEqual(db22.list_all_claim_credential_dirs(ce220), [], "Replaced B MUST NOT be registered in ledger!")
                self.assertEqual(
                    (rdir_sbh / swapped_name[0] / ".codex" / "precious.json").read_text(encoding="utf-8"),
                    "DO_NOT_WIPE_B_CODEX",
                )

                # 5. `_prepare_worker_pinned_paths` calls `fsync` on parent `runs/` & `claim-220/` BEFORE recording `bound` in SQLite!
                rc_fd22 = ap_cli._open_verified_claim_cache_fd(db22.get_claim(ce220), rc22)
                assert rc_fd22 is not None
                try:
                    with mock.patch("os.fsync", side_effect=OSError(errno.EIO, "parent fsync failed")):
                        with self.assertRaises(OSError):
                            ap_cli._prepare_worker_pinned_paths(db22.get_claim(ce220), ce220, rc22, rc_fd22, db=db22)
                    self.assertEqual(db22.get_claim(ce220)["run_dir_state"], "uncreated", "Must NOT commit 'bound' when parent fsync fails!")
                finally:
                    os.close(rc_fd22)
            finally:
                os.close(rfd_sbh)
                db22.close()

            # 4. `tool_ring` mounts `<wt>/.git` read-only via `--ro-bind-fd` relative to `wt_fd_tool`, and fails closed if `.git` is missing!
            wt_ok = ensure_secure_dir(base / "wt_ok22", 0o700)
            (wt_ok / ".git").write_text("gitdir: /tmp/fake\n", encoding="utf-8")
            tfds22: list[int] = []
            try:
                argv_ok = build_execution_ring_bwrap(
                    ring_kind="tool_ring",
                    inner_cmd=["/bin/sh", "-c", "if echo x > .git 2>/dev/null; then exit 9; else exit 0; fi"],
                    cwd=wt_ok,
                    worktree=wt_ok,
                    ephemeral_tool_cache=ensure_secure_dir(base / "eph22", 0o700),
                    shared_tmp=ensure_secure_dir(base / "stmp22", 0o700),
                    retain_fds=tfds22,
                )
                dg_idx = argv_ok.index(f"{wt_ok.resolve()}/.git")
                self.assertEqual(argv_ok[dg_idx - 2], "--ro-bind-fd")
                p_ro = subprocess.run(argv_ok, capture_output=True, text=True, pass_fds=tuple(tfds22), timeout=20, check=False)
                self.assertEqual(p_ro.returncode, 0, "Worktree .git MUST be read-only inside tool_ring!")
            finally:
                for _f in tfds22:
                    os.close(_f)

            wt_no_git = ensure_secure_dir(base / "wt_no_git22", 0o700)
            tfds_bad: list[int] = []
            try:
                with self.assertRaises(SandboxError):
                    build_execution_ring_bwrap(
                        ring_kind="tool_ring",
                        inner_cmd=["/bin/true"],
                        cwd=wt_no_git,
                        worktree=wt_no_git,
                        ephemeral_tool_cache=ensure_secure_dir(base / "eph22b", 0o700),
                        shared_tmp=ensure_secure_dir(base / "stmp22b", 0o700),
                        retain_fds=tfds_bad,
                    )
            finally:
                for _f in tfds_bad:
                    os.close(_f)

    def test_round23_all_codex_closures(self) -> None:
        """Regression suite covering all 4 Round-23 Codex Astra [P1] findings."""
        import shutil as _shutil
        from unittest import mock
        import agent_autopilot as ap_cli
        from ap_core.git_gate import prepare_trusted_base_cache_fd
        from ap_core.models import AutopilotError, ensure_secure_dir
        from ap_core.sandbox import cleanup_sandbox_home_at_dirfd, prepare_sandbox_home_fd

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo23"
            sha23 = _init_git_repo(src_r)
            rc23 = ensure_secure_dir(base / "cache23" / "pa" / "o__r", 0o700)
            mg23 = ensure_managed_bare_repo(src_r, rc23 / "managed.git")

            pnpm_repo = base / "pnpm_r23"
            _init_git_repo(pnpm_repo)
            (pnpm_repo / "package.json").write_text('{"name":"r23","version":"1.0.0"}\n', encoding="utf-8")
            (pnpm_repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(pnpm_repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(pnpm_repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "lock"], check=True, capture_output=True)
            psha = subprocess.check_output(["git", "-C", str(pnpm_repo), "rev-parse", "HEAD"], text=True).strip()
            pmg = ensure_managed_bare_repo(pnpm_repo, base / "pmg23.git")
            pcache = ensure_secure_dir(base / "pcache23", 0o700)

            def _pf23(*, inner_cmd: list[str], cwd: Path, stage_dir: Path, **kwargs: Any) -> subprocess.CompletedProcess[str]:
                (stage_dir / "node_modules").mkdir(parents=True, exist_ok=True)
                (stage_dir / "node_modules" / "real.txt").write_text("GENUINE_PREFETCH", encoding="utf-8")
                return subprocess.CompletedProcess(inner_cmd, 0, "ok", "")

            with mock.patch("ap_core.sandbox.run_isolated_deps_prefetch", side_effect=_pf23):
                p_orig, fd_orig = prepare_trusted_base_cache_fd(managed_gitdir=pmg, base_sha=psha, cache_root=pcache)
                assert p_orig is not None and fd_orig is not None
                orig_ino = os.fstat(fd_orig).st_ino
                os.close(fd_orig)

            # 2. Delete `p_orig` (leaving `.published.json` behind!) so ext4 REUSES `orig_ino` for a brand-new unverified dir B
            #    containing `.ready` + `node_modules/`: `publish_id` check MUST reject B on warm check AND preserve B in `.stale-deps-*`!
            _shutil.rmtree(p_orig)
            reused_b = ensure_secure_dir(p_orig, 0o700)
            _ = orig_ino
            (reused_b / ".ready").write_text(f"{psha}\n", encoding="utf-8")
            ensure_secure_dir(reused_b / "node_modules", 0o755)
            (reused_b / "node_modules" / "spoof.txt").write_text("REUSED_INODE_SPOOF_KEEP", encoding="utf-8")

            with mock.patch("ap_core.sandbox.run_isolated_deps_prefetch", side_effect=_pf23):
                p_reb, fd_reb = prepare_trusted_base_cache_fd(managed_gitdir=pmg, base_sha=psha, cache_root=pcache)
                assert p_reb is not None and fd_reb is not None
                try:
                    self.assertTrue((Path(f"/proc/{os.getpid()}/fd/{fd_reb}") / "node_modules" / "real.txt").is_file())
                    self.assertFalse((Path(f"/proc/{os.getpid()}/fd/{fd_reb}") / "node_modules" / "spoof.txt").exists())
                finally:
                    os.close(fd_reb)

            # 1. Replace `deps-<key>` with a regular backup file: rebuild quarantines it to `.stale-deps-*` WITHOUT unlinking it!
            _shutil.rmtree(p_reb)
            p_reb.write_text("REGULAR_BACKUP_FILE_DO_NOT_UNLINK", encoding="utf-8")
            with mock.patch("ap_core.sandbox.run_isolated_deps_prefetch", side_effect=_pf23):
                p_reb2, fd_reb2 = prepare_trusted_base_cache_fd(managed_gitdir=pmg, base_sha=psha, cache_root=pcache)
                assert p_reb2 is not None and fd_reb2 is not None
                os.close(fd_reb2)
            stale_files = [p for p in (pcache / "base-deps").glob(".stale-deps-*") if p.is_file()]
            self.assertEqual(len(stale_files), 1, "Regular backup file MUST be preserved in .stale-deps-*, never unlinked!")
            self.assertEqual(stale_files[0].read_text(encoding="utf-8"), "REGULAR_BACKUP_FILE_DO_NOT_UNLINK")

            # 3. Cold stage init swap between `os.mkdir` and `os.open` to non-empty B already containing `.ap-stage-owner`:
            #    `_create_exclusive_subdir_fd` rejects BEFORE `stage_fd` is assigned, leaving B 100% intact!
            pcache_sw = ensure_secure_dir(base / "pcache_sw23", 0o700)
            real_mkdir23 = os.mkdir
            swapped_stage_names: list[str] = []

            def _swap_stage_mkdir(p: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
                real_mkdir23(p, mode, dir_fd=dir_fd)
                if isinstance(p, str) and p.startswith(".stage-deps-") and not swapped_stage_names and dir_fd is not None:
                    swapped_stage_names.append(p)
                    bdeps_sw = pcache_sw / "base-deps"
                    os.rename(bdeps_sw / p, bdeps_sw / f"{p}-orig")
                    b_st = ensure_secure_dir(bdeps_sw / p, 0o700)
                    (b_st / ".ap-stage-owner").write_text("foreign-owner\n", encoding="utf-8")
                    (b_st / "keep_me.txt").write_text("DO_NOT_EMPTY_STAGE_B", encoding="utf-8")

            with mock.patch("os.mkdir", side_effect=_swap_stage_mkdir):
                with self.assertRaises(AutopilotError):
                    prepare_trusted_base_cache_fd(managed_gitdir=pmg, base_sha=psha, cache_root=pcache_sw)
            self.assertEqual(
                (pcache_sw / "base-deps" / swapped_stage_names[0] / "keep_me.txt").read_text(encoding="utf-8"),
                "DO_NOT_EMPTY_STAGE_B",
            )

            # 4. Credential `.codex` subdir relocated out of `sandbox_home_*` BEFORE cleanup:
            #    - Moving `.codex` outside `run_dir` keeps `(dev_sub, ino_sub)` `purged=0` and BLOCKS lease release!
            #    - Moving `.codex` to `run_dir/archived` lets reclaim match `(dev_sub, ino_sub)`, purge `auth.json`, and release!
            fake_h23 = ensure_secure_dir(base / "fake_h23", 0o700)
            ensure_secure_dir(fake_h23 / ".codex", 0o700)
            (fake_h23 / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"TOK23_SECRET"}}', encoding="utf-8")
            sroot23 = base / "state23"
            db23 = AutopilotDB(sroot23 / "autopilot.db")
            try:
                cfg23 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db23.upsert_project(cfg23)
                db23.ensure_lease_slots("pa", ["pa:slot-1"], sroot23 / "locks")
                db23.ensure_work_unit(unit_key="o/r#230", project_id="pa", repo="o/r", issue_number=230)
                st_rc23 = os.lstat(rc23)
                rdir230 = ensure_secure_dir(rc23 / "runs" / "claim-230", 0o700)
                ce230 = db23.claim_and_reserve(
                    unit_key="o/r#230", cfg=cfg23, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-230.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-230.service")), base_sha=sha23, authorized_head_ref="agent/230",
                    run_dir=str(rdir230), worktree_path=str(rc23 / "worktrees" / "wt-230"), managed_gitdir=str(mg23),
                    frozen_cache_dir=str(rc23), frozen_cache_dev=int(st_rc23.st_dev), frozen_cache_ino=int(st_rc23.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot23 / "sealed_tokens" / "claim-pa-230.gh_token"),
                )
                rfd230 = os.open(str(rdir230), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _, sbh_fd230, sbh_nm230, sbh_ino230 = prepare_sandbox_home_fd(
                        rdir230, "codex", host_home=fake_h23, run_dir_fd=rfd230, db=db23, claim_epoch=ce230
                    )
                    sbh_dev230 = int(os.fstat(sbh_fd230).st_dev)
                    os.close(sbh_fd230)
                    # Relocate `.codex` (containing `auth.json`!) to `rdir230 / "archived"` BEFORE `cleanup_sandbox_home_at_dirfd`!
                    os.rename(rdir230 / sbh_nm230 / ".codex", rdir230 / "archived")
                    cleanup_sandbox_home_at_dirfd(
                        rfd230,
                        sbh_nm230,
                        expected_dev=sbh_dev230,
                        expected_ino=sbh_ino230,
                        on_emptied_before_rmdir=lambda d, i: db23.mark_claim_credential_dir_purged(ce230, d, i),
                    )
                finally:
                    os.close(rfd230)
                # `.codex` (`archived`) AND `auth.json` inside it are BOTH STILL `purged=0` in `claim_credential_dirs`!
                self.assertEqual(len(db23.list_unpurged_claim_credential_dirs(ce230)), 2)
                # If `archived` is moved outside `rdir230`, reclaim MUST refuse to release the lease!
                os.rename(rdir230 / "archived", base / "stolen_dot_codex")
                self.assertFalse(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db23, db23.get_claim(ce230), cfg23),
                    "Relocated .codex subdir MUST block lease release while unpurged!",
                )
                self.assertEqual(db23.get_claim(ce230)["state"], "reclaiming")
                # Moving it into `rdir230 / "archived"` lets reclaim match `(dev_sub, ino_sub)`, purge `auth.json`, and release!
                os.rename(base / "stolen_dot_codex", rdir230 / "archived")
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db23, db23.get_claim(ce230), cfg23))
                self.assertFalse((rdir230 / "archived").exists())
                self.assertEqual(db23.list_unpurged_claim_credential_dirs(ce230), [])
                self.assertEqual(db23.get_claim(ce230)["state"], "released")
            finally:
                db23.close()

    def test_round24_all_codex_closures(self) -> None:
        """Regression suite covering all 5 Round-24 Codex Astra [P1] findings."""
        import shutil as _shutil
        import sqlite3
        from unittest import mock
        import agent_autopilot as ap_cli
        from ap_core.models import ensure_secure_dir, quarantine_noreplace_at_dirfd
        from ap_core.sandbox import SandboxError, cleanup_sandbox_home_at_dirfd, prepare_sandbox_home_fd

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo24"
            sha24 = _init_git_repo(src_r)
            rc24 = ensure_secure_dir(base / "cache24" / "pa" / "o__r", 0o700)
            mg24 = ensure_managed_bare_repo(src_r, rc24 / "managed.git")
            fake_h24 = ensure_secure_dir(base / "fake_h24", 0o700)
            ensure_secure_dir(fake_h24 / ".codex", 0o700)
            (fake_h24 / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"TOK24_SECRET"}}', encoding="utf-8")

            sroot24 = base / "state24"
            db24 = AutopilotDB(sroot24 / "autopilot.db")
            try:
                cfg24 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db24.upsert_project(cfg24)
                db24.ensure_lease_slots("pa", ["pa:slot-1"], sroot24 / "locks")

                # 1. Replaced `.codex` subdir (between `os.mkdir(".codex")` and `os.open(".codex")`) inside registered `sandbox_home_*`:
                #    `prepare_sandbox_home_fd` refuses B, AND subsequent supervisor reclaim MUST NOT recurse into unregistered B!
                db24.ensure_work_unit(unit_key="o/r#240", project_id="pa", repo="o/r", issue_number=240)
                st_rc24 = os.lstat(rc24)
                rdir240 = ensure_secure_dir(rc24 / "runs" / "claim-240", 0o700)
                ce240 = db24.claim_and_reserve(
                    unit_key="o/r#240", cfg=cfg24, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-240.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-240.service")), base_sha=sha24, authorized_head_ref="agent/240",
                    run_dir=str(rdir240), worktree_path=str(rc24 / "worktrees" / "wt-240"), managed_gitdir=str(mg24),
                    frozen_cache_dir=str(rc24), frozen_cache_dev=int(st_rc24.st_dev), frozen_cache_ino=int(st_rc24.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot24 / "sealed_tokens" / "claim-pa-240.gh_token"),
                )
                rfd240 = os.open(str(rdir240), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                real_mkdir24 = os.mkdir
                swapped_codex = [False]
                try:
                    def _swap_dot_codex(p: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
                        real_mkdir24(p, mode, dir_fd=dir_fd)
                        if p == ".codex" and dir_fd is not None and not swapped_codex[0]:
                            swapped_codex[0] = True
                            sbh_real = Path(os.readlink(f"/proc/self/fd/{dir_fd}"))
                            os.rename(sbh_real / ".codex", sbh_real / ".codex-orig")
                            os.rmdir(sbh_real / ".codex-orig")
                            real_mkdir24(sbh_real / ".codex", 0o700)
                            (sbh_real / ".codex" / "keep_sub_b.txt").write_text("DO_NOT_DELETE_SUB_B", encoding="utf-8")

                    with mock.patch("os.mkdir", side_effect=_swap_dot_codex):
                        with self.assertRaises(SandboxError):
                            prepare_sandbox_home_fd(rdir240, "codex", host_home=fake_h24, run_dir_fd=rfd240, db=db24, claim_epoch=ce240)
                finally:
                    os.close(rfd240)
                self.assertFalse(ap_cli._reclaim_single_claim_via_bounded_unit(db24, db24.get_claim(ce240), cfg24))
                sbh_dirs240 = list(rdir240.glob("sandbox_home_*"))
                self.assertEqual(len(sbh_dirs240), 1)
                self.assertEqual(
                    (sbh_dirs240[0] / ".codex" / "keep_sub_b.txt").read_text(encoding="utf-8"),
                    "DO_NOT_DELETE_SUB_B",
                    "Reclaim MUST NOT wipe unregistered replaced .codex subdir B!",
                )
                # Remove foreign B manually so `ce240` settles cleanly for next subtests:
                (sbh_dirs240[0] / ".codex" / "keep_sub_b.txt").unlink()
                (sbh_dirs240[0] / ".codex").rmdir()
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db24, db24.get_claim(ce240), cfg24))

                # 2. Standalone `auth.json` moved out of `.codex` to `rdir241/archived-auth.json` (and outside `rdir241`):
                db24.ensure_work_unit(unit_key="o/r#241", project_id="pa", repo="o/r", issue_number=241)
                rdir241 = ensure_secure_dir(rc24 / "runs" / "claim-241", 0o700)
                ce241 = db24.claim_and_reserve(
                    unit_key="o/r#241", cfg=cfg24, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-241.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-241.service")), base_sha=sha24, authorized_head_ref="agent/241",
                    run_dir=str(rdir241), worktree_path=str(rc24 / "worktrees" / "wt-241"), managed_gitdir=str(mg24),
                    frozen_cache_dir=str(rc24), frozen_cache_dev=int(st_rc24.st_dev), frozen_cache_ino=int(st_rc24.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot24 / "sealed_tokens" / "claim-pa-241.gh_token"),
                )
                rfd241 = os.open(str(rdir241), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _, sbh_fd241, sbh_nm241, sbh_ino241 = prepare_sandbox_home_fd(
                        rdir241, "codex", host_home=fake_h24, run_dir_fd=rfd241, db=db24, claim_epoch=ce241
                    )
                    sbh_dev241 = int(os.fstat(sbh_fd241).st_dev)
                    os.close(sbh_fd241)
                    # Move ONLY `auth.json` out to `base / "stolen-auth.json"` before normal `cleanup_sandbox_home_at_dirfd`!
                    os.rename(rdir241 / sbh_nm241 / ".codex" / "auth.json", base / "stolen-auth.json")
                    cleanup_sandbox_home_at_dirfd(
                        rfd241,
                        sbh_nm241,
                        expected_dev=sbh_dev241,
                        expected_ino=sbh_ino241,
                        on_emptied_before_rmdir=lambda d, i: db24.mark_claim_credential_dir_purged(ce241, d, i),
                    )
                finally:
                    os.close(rfd241)
                self.assertFalse(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db24, db24.get_claim(ce241), cfg24),
                    "Moved standalone `auth.json` MUST keep `'file'` row `purged=0` and block lease release!",
                )
                # Moving `stolen-auth.json` into `rdir241 / "archived-auth.json"` lets reclaim zero-truncate, unlink, and release!
                os.rename(base / "stolen-auth.json", rdir241 / "archived-auth.json")
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db24, db24.get_claim(ce241), cfg24))
                self.assertFalse((rdir241 / "archived-auth.json").exists())
                self.assertEqual(db24.get_claim(ce241)["state"], "released")

                # 3. Pre-v2 active issue claim (`cred_ledger_tracked = 1`) retains `reclaiming`!
                db24.ensure_work_unit(unit_key="o/r#242", project_id="pa", repo="o/r", issue_number=242)
                rdir242 = ensure_secure_dir(rc24 / "runs" / "claim-242", 0o700)
                ce242 = db24.claim_and_reserve(
                    unit_key="o/r#242", cfg=cfg24, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-242.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-242.service")), base_sha=sha24, authorized_head_ref="agent/242",
                    run_dir=str(rdir242), worktree_path=str(rc24 / "worktrees" / "wt-242"), managed_gitdir=str(mg24),
                    frozen_cache_dir=str(rc24), frozen_cache_dev=int(st_rc24.st_dev), frozen_cache_ino=int(st_rc24.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot24 / "sealed_tokens" / "claim-pa-242.gh_token"),
                )
                raw24 = sqlite3.connect(str(sroot24 / "autopilot.db"))
                raw24.execute("UPDATE run_claims SET cred_ledger_tracked = 1 WHERE claim_epoch = ?", (ce242,))
                raw24.commit()
                raw24.close()
                self.assertFalse(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db24, db24.get_claim(ce242), cfg24),
                    "Pre-v2 issue claim (`cred_ledger_tracked = 1`) MUST retain lease!",
                )
                # Mark `ce242` released directly so we can test #4 on `pa:slot-1`:
                raw24b = sqlite3.connect(str(sroot24 / "autopilot.db"))
                raw24b.execute("UPDATE run_claims SET state = 'released' WHERE claim_epoch = ?", (ce242,))
                raw24b.execute("UPDATE leases SET state = 'free', claim_epoch = NULL WHERE slot_key = 'pa:slot-1'")
                raw24b.commit()
                raw24b.close()

                # 4. Deleted `purged=0` `.codex` whose freed inode is reused by `rdir243/round-1`:
                #    `owner_token` (`user.ap_cred_id`) mismatch MUST preserve `round-1` untouched AND retain lease!
                db24.ensure_work_unit(unit_key="o/r#243", project_id="pa", repo="o/r", issue_number=243)
                rdir243 = ensure_secure_dir(rc24 / "runs" / "claim-243", 0o700)
                ce243 = db24.claim_and_reserve(
                    unit_key="o/r#243", cfg=cfg24, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-243.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-243.service")), base_sha=sha24, authorized_head_ref="agent/243",
                    run_dir=str(rdir243), worktree_path=str(rc24 / "worktrees" / "wt-243"), managed_gitdir=str(mg24),
                    frozen_cache_dir=str(rc24), frozen_cache_dev=int(st_rc24.st_dev), frozen_cache_ino=int(st_rc24.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot24 / "sealed_tokens" / "claim-pa-243.gh_token"),
                )
                rfd243 = os.open(str(rdir243), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _, sbh_fd243, sbh_nm243, _ = prepare_sandbox_home_fd(
                        rdir243, "codex", host_home=fake_h24, run_dir_fd=rfd243, db=db24, claim_epoch=ce243
                    )
                    os.close(sbh_fd243)
                    _shutil.rmtree(rdir243 / sbh_nm243)
                    # `round-1` reuses one of the freed inodes (`purged=0` in DB!), lacking `user.ap_cred_id`:
                    rnd243 = ensure_secure_dir(rdir243 / "round-1", 0o700)
                    (rnd243 / "keep_artifact.txt").write_text("DO_NOT_DELETE_ROUND1", encoding="utf-8")
                finally:
                    os.close(rfd243)
                self.assertFalse(ap_cli._reclaim_single_claim_via_bounded_unit(db24, db24.get_claim(ce243), cfg24))
                self.assertEqual((rdir243 / "round-1" / "keep_artifact.txt").read_text(encoding="utf-8"), "DO_NOT_DELETE_ROUND1")
            finally:
                db24.close()

            # 5. `quarantine_noreplace_at_dirfd` (`renameat2` `RENAME_NOREPLACE`) retries on `EEXIST` and NEVER overwrites an existing backup!
            qdir = ensure_secure_dir(base / "qdir24", 0o700)
            (qdir / ".stale-deps-k-000000000001").write_text("OLD_BACKUP_1", encoding="utf-8")
            (qdir / "deps-k").write_text("NEW_BACKUP_2", encoding="utf-8")
            qfd = os.open(str(qdir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                seq_hex = iter(["000000000001", "000000000002"])
                with mock.patch("uuid.UUID.hex", new_callable=mock.PropertyMock, side_effect=lambda: next(seq_hex) + "0" * 20):
                    chosen = quarantine_noreplace_at_dirfd(qfd, "deps-k", ".stale-deps-k")
                self.assertEqual(chosen, ".stale-deps-k-000000000002")
                self.assertEqual((qdir / ".stale-deps-k-000000000001").read_text(encoding="utf-8"), "OLD_BACKUP_1")
                self.assertEqual((qdir / ".stale-deps-k-000000000002").read_text(encoding="utf-8"), "NEW_BACKUP_2")
            finally:
                os.close(qfd)

    def test_round25_all_codex_closures(self) -> None:
        """Regression suite covering all 5 Round-25 Codex Astra [P1] findings."""
        import errno
        from unittest import mock
        import agent_autopilot as ap_cli
        from ap_core.models import ensure_secure_dir
        from ap_core.sandbox import build_model_ring_bwrap, cleanup_sandbox_home_at_dirfd, prepare_sandbox_home_fd

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo25"
            sha25 = _init_git_repo(src_r)
            rc25 = ensure_secure_dir(base / "cache25" / "pa" / "o__r", 0o700)
            mg25 = ensure_managed_bare_repo(src_r, rc25 / "managed.git")
            fake_h25 = ensure_secure_dir(base / "fake_h25", 0o700)
            ensure_secure_dir(fake_h25 / ".codex", 0o700)
            (fake_h25 / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"TOK25_SECRET"}}', encoding="utf-8")

            sroot25 = base / "state25"
            db25 = AutopilotDB(sroot25 / "autopilot.db")
            try:
                cfg25 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db25.upsert_project(cfg25)
                db25.ensure_lease_slots("pa", ["pa:slot-1"], sroot25 / "locks")

                # 1. Init rollback when `auth.json` A is moved to `rdir/archived-auth.json`, foreign file B occupies `.codex/auth.json`,
                #    and `config.toml` creation raises ENOSPC: B MUST NOT be deleted, and A MUST stay `purged=0` (blocking lease release)!
                db25.ensure_work_unit(unit_key="o/r#250", project_id="pa", repo="o/r", issue_number=250)
                st_rc25 = os.lstat(rc25)
                rdir250 = ensure_secure_dir(rc25 / "runs" / "claim-250", 0o700)
                ce250 = db25.claim_and_reserve(
                    unit_key="o/r#250", cfg=cfg25, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-250.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-250.service")), base_sha=sha25, authorized_head_ref="agent/250",
                    run_dir=str(rdir250), worktree_path=str(rc25 / "worktrees" / "wt-250"), managed_gitdir=str(mg25),
                    frozen_cache_dir=str(rc25), frozen_cache_dev=int(st_rc25.st_dev), frozen_cache_ino=int(st_rc25.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot25 / "sealed_tokens" / "claim-pa-250.gh_token"),
                )
                rfd250 = os.open(str(rdir250), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                real_wf = ap_cli.sys.modules["ap_core.sandbox"]._write_file_at_dirfd
                try:
                    def _swap_auth_then_fail_cfg(dfd: int, fname: str, content: bytes, mode: int, **kw: Any) -> None:
                        if fname == "config.toml":
                            sub_real = Path(os.readlink(f"/proc/self/fd/{dfd}"))
                            os.rename(sub_real / "auth.json", base / "stolen-auth-250.json")
                            (sub_real / "auth.json").write_text("INNOCENT_BACKUP_B", encoding="utf-8")
                            raise OSError(errno.ENOSPC, "config.toml disk full")
                        real_wf(dfd, fname, content, mode, **kw)

                    with mock.patch("ap_core.sandbox._write_file_at_dirfd", side_effect=_swap_auth_then_fail_cfg):
                        with self.assertRaises(OSError):
                            prepare_sandbox_home_fd(rdir250, "codex", host_home=fake_h25, run_dir_fd=rfd250, db=db25, claim_epoch=ce250)
                finally:
                    os.close(rfd250)
                sbh250 = list(rdir250.glob("sandbox_home_*"))[0]
                self.assertEqual((sbh250 / ".codex" / "auth.json").read_text(encoding="utf-8"), "INNOCENT_BACKUP_B")
                self.assertFalse(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db25, db25.get_claim(ce250), cfg25),
                    "Reclaim MUST NOT delete foreign B at `.codex/auth.json` AND MUST NOT release while `stolen-auth-250.json` is unpurged!",
                )
                self.assertEqual((sbh250 / ".codex" / "auth.json").read_text(encoding="utf-8"), "INNOCENT_BACKUP_B")
                # Remove foreign B and move `stolen-auth-250.json` back into `rdir250 / "archived-auth.json"` -> clean purge & release!
                (sbh250 / ".codex" / "auth.json").unlink()
                os.rename(base / "stolen-auth-250.json", rdir250 / "archived-auth.json")
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db25, db25.get_claim(ce250), cfg25))
                self.assertEqual(db25.get_claim(ce250)["state"], "released")

                # 2 & 5. (2) Crash right after `purged=1` commit and BEFORE `os.unlink(staged_sec)` does NOT wedge reclaim!
                #        (5) Next turn's `config.toml` reusing freed `purged=1` `auth.json` inode cleans up cleanly!
                db25.ensure_work_unit(unit_key="o/r#251", project_id="pa", repo="o/r", issue_number=251)
                rdir251 = ensure_secure_dir(rc25 / "runs" / "claim-251", 0o700)
                ce251 = db25.claim_and_reserve(
                    unit_key="o/r#251", cfg=cfg25, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-251.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-251.service")), base_sha=sha25, authorized_head_ref="agent/251",
                    run_dir=str(rdir251), worktree_path=str(rc25 / "worktrees" / "wt-251"), managed_gitdir=str(mg25),
                    frozen_cache_dir=str(rc25), frozen_cache_dev=int(st_rc25.st_dev), frozen_cache_ino=int(st_rc25.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot25 / "sealed_tokens" / "claim-pa-251.gh_token"),
                )
                rfd251 = os.open(str(rdir251), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    # Turn 1: create & purge normally so `auth.json` inode becomes `purged=1` and freed!
                    _, sbh_fd_t1, sbh_nm_t1, sbh_ino_t1 = prepare_sandbox_home_fd(
                        rdir251, "codex", host_home=fake_h25, run_dir_fd=rfd251, db=db25, claim_epoch=ce251
                    )
                    sbh_dev_t1 = int(os.fstat(sbh_fd_t1).st_dev)
                    os.close(sbh_fd_t1)
                    unp_t1 = db25.list_unpurged_claim_credential_dirs(ce251)
                    dt_t1 = {(int(r["dir_dev"]), int(r["dir_ino"])): str(r["owner_token"]) for r in unp_t1 if r["entry_kind"] == "dir"}
                    ft_t1 = {(int(r["dir_dev"]), int(r["dir_ino"])): str(r["owner_token"]) for r in unp_t1 if r["entry_kind"] == "file"}
                    cleanup_sandbox_home_at_dirfd(
                        rfd251, sbh_nm_t1, expected_dev=sbh_dev_t1, expected_ino=sbh_ino_t1,
                        expected_owner_token=dt_t1[(sbh_dev_t1, sbh_ino_t1)],
                        allowed_child_dirs=dt_t1, tracked_files=ft_t1,
                        on_emptied_before_rmdir=lambda d, i: db25.mark_claim_credential_dir_purged(ce251, d, i),
                    )
                    # Turn 2 on SAME claim (`empty_h` so `config.toml` reuses freed Turn-1 inode!):
                    _, sbh_fd_t2, sbh_nm_t2, _ = prepare_sandbox_home_fd(
                        rdir251, "codex", host_home=ensure_secure_dir(base / "empty_h25", 0o700),
                        run_dir_fd=rfd251, db=db25, claim_epoch=ce251,
                    )
                    os.close(sbh_fd_t2)
                    # Also simulate crash right before `os.unlink(".ap-purge-sec-*")` on a relocated secret file:
                    _, sbh_fd_t3, sbh_nm_t3, _ = prepare_sandbox_home_fd(
                        rdir251, "codex", host_home=fake_h25, run_dir_fd=rfd251, db=db25, claim_epoch=ce251
                    )
                    os.close(sbh_fd_t3)
                    os.rename(rdir251 / sbh_nm_t3 / ".codex" / "auth.json", rdir251 / "reloc-auth.json")
                finally:
                    os.close(rfd251)

                # Also simulate crash right before `os.unlink("item", dir_fd=qfd)` inside private `.ap-qbox-*`:
                real_unlink25 = os.unlink
                crashed_once = [False]

                def _crash_on_first_sec_unlink(p: Any, *, dir_fd: int | None = None) -> None:
                    if p == "item" and not crashed_once[0]:
                        crashed_once[0] = True
                        raise OSError(errno.EIO, "simulated crash right before unlink after purged=1")
                    real_unlink25(p, dir_fd=dir_fd)

                with mock.patch("os.unlink", side_effect=_crash_on_first_sec_unlink):
                    self.assertFalse(ap_cli._reclaim_single_claim_via_bounded_unit(db25, db25.get_claim(ce251), cfg25))
                # Next reclaim round recovers from the `.ap-purge-sec-*` crash AND cleans Turn 2 (`config.toml` reusing Turn-1 inode)!
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db25, db25.get_claim(ce251), cfg25))
                self.assertEqual(db25.get_claim(ce251)["state"], "released")

                # 3. `build_model_ring_bwrap` mounts `/home/sandbox` as ephemeral `--tmpfs` with `--ro-bind-fd` files,
                #    so CLI creating `/home/sandbox/.codex/sessions/s1` inside `bwrap` leaves ZERO `sessions/` on host disk!
                rdir_cli = ensure_secure_dir(base / "rdir_cli25", 0o700)
                rfd_cli = os.open(str(rdir_cli), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    sb_cli, sbh_fd_cli, sbh_nm_cli, _ = prepare_sandbox_home_fd(
                        rdir_cli, "codex", host_home=fake_h25, run_dir_fd=rfd_cli
                    )
                    mfds25: list[int] = []
                    try:
                        m_argv25 = build_model_ring_bwrap(
                            role_key="codex:readonly_model",
                            host_binaries=ap_cli.resolve_host_binaries(),
                            sandbox_home=sb_cli,
                            outbox_dir=ensure_secure_dir(rdir_cli / "obox", 0o700),
                            proxy_sock=None,
                            inner_cmd=[
                                "/usr/bin/python3",
                                "-c",
                                "import os, pathlib; os.makedirs('/home/sandbox/.codex/sessions', exist_ok=True); "
                                "pathlib.Path('/home/sandbox/.codex/sessions/run1.jsonl').write_text('ok'); "
                                "assert 'TOK25_SECRET' in pathlib.Path('/home/sandbox/.codex/auth.json').read_text()",
                            ],
                            review_bundle_dir=ensure_secure_dir(rdir_cli / "rb", 0o700),
                            sandbox_home_fd=sbh_fd_cli,
                            retain_fds=mfds25,
                        )
                        # Swap `/usr/local/bin/ap-sandbox-init` not needed — Wait: `codex:readonly_model` only mounts codex_cli, not python3;
                        # verify `--tmpfs /home/sandbox` + `--ro-bind-fd` directly on `m_argv25`!
                        t_idx = m_argv25.index("/home/sandbox")
                        self.assertEqual(m_argv25[t_idx - 1], "--tmpfs")
                        auth_idx = m_argv25.index("/home/sandbox/.codex/auth.json")
                        self.assertEqual(m_argv25[auth_idx - 2], "--ro-bind-fd")
                    finally:
                        for _f in mfds25:
                            os.close(_f)
                        os.close(sbh_fd_cli)
                finally:
                    os.close(rfd_cli)
            finally:
                db25.close()

    def test_round26_all_codex_and_claude_closures(self) -> None:
        """Regression suite covering all 5 Round-26 Codex Astra + Claude Sonnet findings (including live bwrap execution!)."""
        import errno
        from unittest import mock
        import agent_autopilot as ap_cli
        from ap_core.models import AutopilotError, ensure_secure_dir
        from ap_core.sandbox import (
            SandboxError,
            build_model_ring_bwrap,
            prepare_sandbox_home_fd,
            prepare_sandbox_home_memfds,
        )

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo26"
            sha26 = _init_git_repo(src_r)
            rc26 = ensure_secure_dir(base / "cache26" / "pa" / "o__r", 0o700)
            mg26 = ensure_managed_bare_repo(src_r, rc26 / "managed.git")
            fake_h26 = ensure_secure_dir(base / "fake_h26", 0o700)
            ensure_secure_dir(fake_h26 / ".codex", 0o700)
            (fake_h26 / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"TOK26_GENUINE"}}', encoding="utf-8")

            # 1. (a) Live `bwrap` execution with `prepare_sandbox_home_memfds` (`--ro-bind-data`, ZERO host disk files!),
            #        AND (b) replacing `.codex` inside `sbh_fd` with another account's `.codex` raises `SandboxError`!
            memfds = prepare_sandbox_home_memfds("codex", role_key="codex:readonly_model", host_home=fake_h26)
            rfds_live: list[int] = []
            try:
                argv_live = build_model_ring_bwrap(
                    role_key="codex:readonly_model",
                    host_binaries=ap_cli.resolve_host_binaries(),
                    sandbox_home=base / "unused_memfd_home",
                    outbox_dir=ensure_secure_dir(base / "obox26", 0o700),
                    proxy_sock=None,
                    inner_cmd=["/usr/local/bin/codex", "--version"],
                    review_bundle_dir=ensure_secure_dir(base / "rb26", 0o700),
                    elf_lib_stage_dir=ensure_secure_dir(base / "elf26", 0o700),
                    sandbox_file_fds=memfds,
                    retain_fds=rfds_live,
                )
                self.assertIn("--ro-bind-data", argv_live)
                p_live = subprocess.run(argv_live, capture_output=True, text=True, pass_fds=tuple(rfds_live), timeout=20, check=False)
                self.assertEqual(p_live.returncode, 0, p_live.stderr)
                self.assertIn("codex", p_live.stdout.lower())
            finally:
                for _f in rfds_live:
                    os.close(_f)
                for _m in memfds.values():
                    os.close(_m)

            rdir_sw = ensure_secure_dir(base / "rdir_sw26", 0o700)
            rfd_sw = os.open(str(rdir_sw), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                sb_sw, sbh_fd_sw, sbh_nm_sw, _ = prepare_sandbox_home_fd(rdir_sw, "codex", host_home=fake_h26, run_dir_fd=rfd_sw)
                try:
                    # Replace `.codex` inside `sbh_fd_sw` with another account's `.codex` directory!
                    os.rename(rdir_sw / sbh_nm_sw / ".codex", rdir_sw / "orig_dot_codex")
                    other_codex = ensure_secure_dir(rdir_sw / sbh_nm_sw / ".codex", 0o700)
                    (other_codex / "auth.json").write_text('{"tokens":{"access_token":"OTHER_ACCOUNT_TOK"}}', encoding="utf-8")
                    rfds_bad: list[int] = []
                    try:
                        with self.assertRaises(SandboxError):
                            build_model_ring_bwrap(
                                role_key="codex:readonly_model",
                                host_binaries=ap_cli.resolve_host_binaries(),
                                sandbox_home=sb_sw,
                                outbox_dir=ensure_secure_dir(base / "obox26b", 0o700),
                                proxy_sock=None,
                                inner_cmd=["/usr/local/bin/codex", "--version"],
                                review_bundle_dir=ensure_secure_dir(base / "rb26b", 0o700),
                                sandbox_home_fd=sbh_fd_sw,
                                retain_fds=rfds_bad,
                            )
                    finally:
                        for _f in rfds_bad:
                            os.close(_f)
                finally:
                    os.close(sbh_fd_sw)
            finally:
                os.close(rfd_sw)

            sroot26 = base / "state26"
            db26 = AutopilotDB(sroot26 / "autopilot.db")
            try:
                cfg26 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db26.upsert_project(cfg26)
                db26.ensure_lease_slots("pa", ["pa:slot-1"], sroot26 / "locks")

                # 2. (Claude + Codex #2) Crash AFTER child `.codex` `purged=1` commit and BEFORE `os.rmdir(".codex", dir_fd=sbh_fd)`:
                #    Next reclaim MUST recognize empty `purged=1` `.codex` via `purged_child_dirs` + `owner_token`, `rmdir` it, and release!
                db26.ensure_work_unit(unit_key="o/r#260", project_id="pa", repo="o/r", issue_number=260)
                st_rc26 = os.lstat(rc26)
                rdir260 = ensure_secure_dir(rc26 / "runs" / "claim-260", 0o700)
                ce260 = db26.claim_and_reserve(
                    unit_key="o/r#260", cfg=cfg26, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-260.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-260.service")), base_sha=sha26, authorized_head_ref="agent/260",
                    run_dir=str(rdir260), worktree_path=str(rc26 / "worktrees" / "wt-260"), managed_gitdir=str(mg26),
                    frozen_cache_dir=str(rc26), frozen_cache_dev=int(st_rc26.st_dev), frozen_cache_ino=int(st_rc26.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot26 / "sealed_tokens" / "claim-pa-260.gh_token"),
                )
                rfd260 = os.open(str(rdir260), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _, sbh_fd260, _, _ = prepare_sandbox_home_fd(
                        rdir260, "codex", host_home=fake_h26, run_dir_fd=rfd260, db=db26, claim_epoch=ce260
                    )
                    os.close(sbh_fd260)
                finally:
                    os.close(rfd260)
                real_rmdir26 = os.rmdir
                failed_child_rmdir = [False]

                def _fail_dot_codex_rmdir(p: Any, *, dir_fd: int | None = None) -> None:
                    if p == ".codex" and not failed_child_rmdir[0]:
                        failed_child_rmdir[0] = True
                        raise OSError(errno.EIO, "simulated crash right after .codex purged=1 before rmdir")
                    real_rmdir26(p, dir_fd=dir_fd)

                with mock.patch("os.rmdir", side_effect=_fail_dot_codex_rmdir):
                    self.assertFalse(ap_cli._reclaim_single_claim_via_bounded_unit(db26, db26.get_claim(ce260), cfg26))
                # `.codex` is now empty AND `purged=1` in DB, while parent `sandbox_home_*` is still `purged=0`:
                self.assertTrue(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db26, db26.get_claim(ce260), cfg26),
                    "Reclaim MUST finish rmdir on empty `purged=1` `.codex` child without wedging!",
                )
                self.assertEqual(db26.get_claim(ce260)["state"], "released")

                # 3. Interrupted `prepare_sandbox_home_fd` AFTER `.codex` fsync and BEFORE SQLite subdir registration:
                #    `sbh_fd` carries `user.ap_sub_id == sub_tok`, so reclaim verifies 0-entry `.codex` intent token and releases!
                db26.ensure_work_unit(unit_key="o/r#261", project_id="pa", repo="o/r", issue_number=261)
                rdir261 = ensure_secure_dir(rc26 / "runs" / "claim-261", 0o700)
                ce261 = db26.claim_and_reserve(
                    unit_key="o/r#261", cfg=cfg26, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-261.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-261.service")), base_sha=sha26, authorized_head_ref="agent/261",
                    run_dir=str(rdir261), worktree_path=str(rc26 / "worktrees" / "wt-261"), managed_gitdir=str(mg26),
                    frozen_cache_dir=str(rc26), frozen_cache_dev=int(st_rc26.st_dev), frozen_cache_ino=int(st_rc26.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot26 / "sealed_tokens" / "claim-pa-261.gh_token"),
                )
                rfd261 = os.open(str(rdir261), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                real_reg26 = db26.register_claim_credential_dir
                reg_calls = [0]
                try:
                    def _crash_before_sub_sql(*a: Any, **kw: Any) -> None:
                        reg_calls[0] += 1
                        if reg_calls[0] == 2:
                            # Simulate SIGKILL right before SQLite commit for `.codex` (also block rollback rmdir via EIO):
                            raise AutopilotError("simulated crash before .codex SQLite registration")
                        real_reg26(*a, **kw)

                    real_fsync26 = os.fsync
                    with mock.patch.object(db26, "register_claim_credential_dir", side_effect=_crash_before_sub_sql):
                        with mock.patch("os.rmdir", side_effect=OSError(errno.EIO, "block rollback rmdir")):
                            with self.assertRaises(AutopilotError):
                                prepare_sandbox_home_fd(rdir261, "codex", host_home=fake_h26, run_dir_fd=rfd261, db=db26, claim_epoch=ce261)
                    _ = real_fsync26
                finally:
                    os.close(rfd261)
                self.assertEqual(len(db26.list_unpurged_claim_credential_dirs(ce261)), 1)  # Only `sbh_fd` registered, `.codex` unregistered on disk!
                self.assertTrue(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db26, db26.get_claim(ce261), cfg26),
                    "Pre-SQLite empty `.codex` matching `sbh_fd` `user.ap_sub_id` MUST reclaim cleanly!",
                )
                self.assertEqual(db26.get_claim(ce261)["state"], "released")

                # 4 & 5. Hardlink (`st_nlink > 1`) on `auth.json` MUST be detected BEFORE `ftruncate(0)`, preserving backup content & holding lease!
                db26.ensure_work_unit(unit_key="o/r#262", project_id="pa", repo="o/r", issue_number=262)
                rdir262 = ensure_secure_dir(rc26 / "runs" / "claim-262", 0o700)
                ce262 = db26.claim_and_reserve(
                    unit_key="o/r#262", cfg=cfg26, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-262.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-262.service")), base_sha=sha26, authorized_head_ref="agent/262",
                    run_dir=str(rdir262), worktree_path=str(rc26 / "worktrees" / "wt-262"), managed_gitdir=str(mg26),
                    frozen_cache_dir=str(rc26), frozen_cache_dev=int(st_rc26.st_dev), frozen_cache_ino=int(st_rc26.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot26 / "sealed_tokens" / "claim-pa-262.gh_token"),
                )
                rfd262 = os.open(str(rdir262), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _, sbh_fd262, sbh_nm262, _ = prepare_sandbox_home_fd(
                        rdir262, "codex", host_home=fake_h26, run_dir_fd=rfd262, db=db26, claim_epoch=ce262
                    )
                    os.close(sbh_fd262)
                    # Create an extra hardlink to `auth.json`:
                    os.link(rdir262 / sbh_nm262 / ".codex" / "auth.json", base / "hardlink-backup-auth.json")
                finally:
                    os.close(rfd262)
                self.assertFalse(
                    ap_cli._reclaim_single_claim_via_bounded_unit(db26, db26.get_claim(ce262), cfg26),
                    "Extra hardlink (`st_nlink == 2`) MUST block reclaim!",
                )
                self.assertIn(
                    "TOK26_GENUINE",
                    (base / "hardlink-backup-auth.json").read_text(encoding="utf-8"),
                    "Hardlink check MUST happen BEFORE `ftruncate(0)` so backup content is NOT destroyed!",
                )
                # Removing extra hardlink allows clean zero-truncation + purge + release; ALSO simulate crash inside `.ap-qbox-*`
                # AFTER `ftruncate(0)` and BEFORE `mark_claim_credential_dir_purged` SQLite commit:
                (base / "hardlink-backup-auth.json").unlink()
                real_mark26 = db26.mark_claim_credential_dir_purged
                crashed_mid_qbox = [False]

                def _crash_mid_qbox(ce_arg: int, d_arg: int, i_arg: int) -> None:
                    if not crashed_mid_qbox[0]:
                        crashed_mid_qbox[0] = True
                        raise AutopilotError("simulated crash after ftruncate(0) inside .ap-qbox-* before SQLite purged=1")
                    real_mark26(ce_arg, d_arg, i_arg)

                with mock.patch.object(db26, "mark_claim_credential_dir_purged", side_effect=_crash_mid_qbox):
                    self.assertFalse(ap_cli._reclaim_single_claim_via_bounded_unit(db26, db26.get_claim(ce262), cfg26))
                # Next reclaim MUST settle `.ap-qbox-*` `purged=1` in SQLite, unlink `"item"`, rmdir qbox, and release!
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db26, db26.get_claim(ce262), cfg26))
                self.assertEqual(db26.get_claim(ce262)["state"], "released")
            finally:
                db26.close()

    def test_round27_all_codex_closures(self) -> None:
        """Regression suite covering all 5 Round-27 Codex Astra [P1] findings."""
        import errno
        from unittest import mock
        import agent_autopilot as ap_cli
        from ap_core.models import empty_and_fsync_dirfd, ensure_secure_dir, renameat2_noreplace
        from ap_core.sandbox import SandboxError, build_model_ring_bwrap, prepare_sandbox_home_fd

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo27"
            sha27 = _init_git_repo(src_r)
            rc27 = ensure_secure_dir(base / "cache27" / "pa" / "o__r", 0o700)
            mg27 = ensure_managed_bare_repo(src_r, rc27 / "managed.git")
            fake_h27 = ensure_secure_dir(base / "fake_h27", 0o700)
            ensure_secure_dir(fake_h27 / ".codex", 0o700)
            (fake_h27 / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"TOK27_SECRET"}}', encoding="utf-8")

            # 1. Missing or `EIO` `user.ap_sub_id` on `sandbox_home_fd` MUST raise `SandboxError` (never skip ownership checks!):
            untagged_sb = ensure_secure_dir(base / "untagged_sb", 0o700)
            ensure_secure_dir(untagged_sb / ".codex", 0o700)
            (untagged_sb / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"OTHER_ACC"}}', encoding="utf-8")
            us_fd = os.open(str(untagged_sb), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                rfds27: list[int] = []
                try:
                    with self.assertRaises(SandboxError):
                        build_model_ring_bwrap(
                            role_key="codex:readonly_model",
                            host_binaries=ap_cli.resolve_host_binaries(),
                            sandbox_home=untagged_sb,
                            outbox_dir=ensure_secure_dir(base / "obox27", 0o700),
                            proxy_sock=None,
                            inner_cmd=["/usr/local/bin/codex", "--version"],
                            review_bundle_dir=ensure_secure_dir(base / "rb27", 0o700),
                            sandbox_home_fd=us_fd,
                            retain_fds=rfds27,
                        )
                finally:
                    for _f in rfds27:
                        os.close(_f)
            finally:
                os.close(us_fd)

            # 5. Generic `empty_and_fsync_dirfd(export_fd)` (Cargo cold-cache cleanup) MUST cleanly remove `.ap-qbox-fixtures/`!
            cargo_exp = ensure_secure_dir(base / "cargo_export_tree", 0o700)
            qfix = ensure_secure_dir(cargo_exp / ".ap-qbox-fixtures", 0o755)
            (qfix / "sample.rs").write_text("fn main() {}\n", encoding="utf-8")
            cexp_fd = os.open(str(cargo_exp), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                empty_and_fsync_dirfd(cexp_fd)
            finally:
                os.close(cexp_fd)
            self.assertEqual(list(cargo_exp.iterdir()), [], "Generic empty_and_fsync_dirfd MUST delete .ap-qbox-fixtures!")

            sroot27 = base / "state27"
            db27 = AutopilotDB(sroot27 / "autopilot.db")
            try:
                cfg27 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db27.upsert_project(cfg27)
                db27.ensure_lease_slots("pa", ["pa:slot-1"], sroot27 / "locks")
                st_rc27 = os.lstat(rc27)

                # 2. Crash between `mkdir` and `setxattr` on BOTH `.ap-qbox-*` AND `.codex` MUST NOT wedge slot!
                db27.ensure_work_unit(unit_key="o/r#270", project_id="pa", repo="o/r", issue_number=270)
                rdir270 = ensure_secure_dir(rc27 / "runs" / "claim-270", 0o700)
                ce270 = db27.claim_and_reserve(
                    unit_key="o/r#270", cfg=cfg27, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-270.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-270.service")), base_sha=sha27, authorized_head_ref="agent/270",
                    run_dir=str(rdir270), worktree_path=str(rc27 / "worktrees" / "wt-270"), managed_gitdir=str(mg27),
                    frozen_cache_dir=str(rc27), frozen_cache_dev=int(st_rc27.st_dev), frozen_cache_ino=int(st_rc27.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot27 / "sealed_tokens" / "claim-pa-270.gh_token"),
                )
                rfd270 = os.open(str(rdir270), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _, sbh_fd270, _, _ = prepare_sandbox_home_fd(rdir270, "codex", host_home=fake_h27, run_dir_fd=rfd270, db=db27, claim_epoch=ce270)
                    os.close(sbh_fd270)
                    ensure_secure_dir(rdir270 / ".ap-qbox-crashed00001", 0o700)
                    real_setx = os.setxattr
                    setx_cnt = [0]

                    def _crash_on_sub_xattr(fd_x: Any, k_x: bytes, v_x: bytes, *rest: Any) -> None:
                        setx_cnt[0] += 1
                        if setx_cnt[0] == 3:
                            raise OSError(errno.EIO, "simulated crash between mkdir(.codex) and setxattr")
                        real_setx(fd_x, k_x, v_x, *rest)

                    with mock.patch("os.setxattr", side_effect=_crash_on_sub_xattr):
                        with mock.patch("os.rmdir", side_effect=OSError(errno.EIO, "block rollback")):
                            with self.assertRaises(OSError):
                                prepare_sandbox_home_fd(rdir270, "codex", host_home=fake_h27, run_dir_fd=rfd270, db=db27, claim_epoch=ce270)
                finally:
                    os.close(rfd270)
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db27, db27.get_claim(ce270), cfg27))
                self.assertEqual(db27.get_claim(ce270)["state"], "released")

                # 3 & 4. (3) `config.toml` reusing a Turn-1 `purged=1` `auth.json` inode inside crashed `.ap-qbox-*` recovers cleanly,
                #        AND (4) swapping `aaa_first.toml` -> `auth.json` between `os.stat` and `renameat2_noreplace` still zero-truncates & settles `purged=1`!
                db27.ensure_work_unit(unit_key="o/r#271", project_id="pa", repo="o/r", issue_number=271)
                rdir271 = ensure_secure_dir(rc27 / "runs" / "claim-271", 0o700)
                ce271 = db27.claim_and_reserve(
                    unit_key="o/r#271", cfg=cfg27, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-271.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-271.service")), base_sha=sha27, authorized_head_ref="agent/271",
                    run_dir=str(rdir271), worktree_path=str(rc27 / "worktrees" / "wt-271"), managed_gitdir=str(mg27),
                    frozen_cache_dir=str(rc27), frozen_cache_dev=int(st_rc27.st_dev), frozen_cache_ino=int(st_rc27.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot27 / "sealed_tokens" / "claim-pa-271.gh_token"),
                )
                rfd271 = os.open(str(rdir271), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _, sbh_t1, nm_t1, _ = prepare_sandbox_home_fd(rdir271, "codex", host_home=fake_h27, run_dir_fd=rfd271, db=db27, claim_epoch=ce271)
                    os.close(sbh_t1)
                    from ap_core.sandbox import cleanup_sandbox_home_at_dirfd
                    st_t1 = os.lstat(rdir271 / nm_t1)
                    tok_t1 = os.getxattr(rdir271 / nm_t1, b"user.ap_cred_id").decode("ascii")
                    all_r1 = db27.list_all_claim_credential_dirs(ce271)
                    cleanup_sandbox_home_at_dirfd(
                        rfd271, nm_t1, expected_dev=int(st_t1.st_dev), expected_ino=int(st_t1.st_ino), expected_owner_token=tok_t1,
                        allowed_child_dirs={(int(r["dir_dev"]), int(r["dir_ino"])): str(r["owner_token"]) for r in all_r1 if r["entry_kind"] == "dir"},
                        tracked_files={(int(r["dir_dev"]), int(r["dir_ino"])): str(r["owner_token"]) for r in all_r1 if r["entry_kind"] == "file"},
                        on_emptied_before_rmdir=lambda d, i: db27.mark_claim_credential_dir_purged(ce271, d, i),
                    )
                    _, sbh_t2, nm_t2, _ = prepare_sandbox_home_fd(rdir271, "codex", host_home=fake_h27, run_dir_fd=rfd271, db=db27, claim_epoch=ce271)
                    os.close(sbh_t2)
                    cfg_p = rdir271 / nm_t2 / ".codex" / "config.toml"
                    st_cfg = os.lstat(cfg_p)
                    db27.register_claim_credential_dir(ce271, int(st_cfg.st_dev), int(st_cfg.st_ino), "old_turn_auth", entry_kind="file", owner_token="old_tok_turn1")
                    db27.mark_claim_credential_dir_purged(ce271, int(st_cfg.st_dev), int(st_cfg.st_ino))
                    qb_cfg = ensure_secure_dir(rdir271 / nm_t2 / ".codex" / ".ap-qbox-cfg00001", 0o700)
                    os.setxattr(qb_cfg, b"user.ap_qbox", b"1")
                    os.rename(cfg_p, qb_cfg / "item")
                    sub_tok2 = os.getxattr(rdir271 / nm_t2 / ".codex", b"user.ap_cred_id")
                    extra_p = rdir271 / nm_t2 / ".codex" / "aaa_first.toml"
                    extra_p.write_text("x=1\n", encoding="utf-8")
                    os.setxattr(extra_p, b"user.ap_owned_file", sub_tok2)
                    auth_p2 = rdir271 / nm_t2 / ".codex" / "auth.json"
                    hard_spy_fd = os.open(str(auth_p2), os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        real_ren2 = renameat2_noreplace
                        swapped_once = [False]

                        def _swap_cfg_to_auth_before_move(sfd: int, snm: str, dfd: int, dnm: str) -> None:
                            if snm == "aaa_first.toml" and not swapped_once[0]:
                                swapped_once[0] = True
                                os.replace(auth_p2, extra_p)
                            real_ren2(sfd, snm, dfd, dnm)

                        with mock.patch("ap_core.models.renameat2_noreplace", side_effect=_swap_cfg_to_auth_before_move):
                            self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db27, db27.get_claim(ce271), cfg27))
                        self.assertEqual(os.fstat(hard_spy_fd).st_size, 0, "Swapped auth.json MUST be zero-truncated!")
                    finally:
                        os.close(hard_spy_fd)
                finally:
                    os.close(rfd271)
                self.assertEqual(db27.get_claim(ce271)["state"], "released")
            finally:
                db27.close()

    def test_round28_all_codex_closures(self) -> None:
        """Regression suite covering all 3 Round-28 Codex Astra [P1] findings."""
        import errno
        from unittest import mock
        import agent_autopilot as ap_cli
        from ap_core.models import ensure_secure_dir
        from ap_core.sandbox import SandboxError, build_model_ring_bwrap, prepare_sandbox_home_fd

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fake_h28 = ensure_secure_dir(base / "fake_h28", 0o700)
            ensure_secure_dir(fake_h28 / ".codex", 0o700)
            (fake_h28 / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"TOK28_TURN_A"}}', encoding="utf-8")

            # 1. Passing `sandbox_home_fd` WITHOUT `retain_fds` MUST raise `SandboxError` before building mounts!
            rdir28 = ensure_secure_dir(base / "rdir28", 0o700)
            rfd28 = os.open(str(rdir28), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                sb_a, sbh_fd_a, sbh_nm_a, _ = prepare_sandbox_home_fd(rdir28, "codex", host_home=fake_h28, run_dir_fd=rfd28)
                try:
                    with self.assertRaises(SandboxError):
                        build_model_ring_bwrap(
                            role_key="codex:readonly_model",
                            host_binaries=ap_cli.resolve_host_binaries(),
                            sandbox_home=sb_a,
                            outbox_dir=ensure_secure_dir(base / "obox28", 0o700),
                            proxy_sock=None,
                            inner_cmd=["/usr/local/bin/codex", "--version"],
                            review_bundle_dir=ensure_secure_dir(base / "rb28", 0o700),
                            sandbox_home_fd=sbh_fd_a,
                            retain_fds=None,
                        )
                finally:
                    os.close(sbh_fd_a)

                # 2. DB-less `prepare_sandbox_home_fd(..., db=None)` rollback MUST NOT zero-truncate another turn's `auth.json`!
                other_auth_src = rdir28 / sbh_nm_a / ".codex" / "auth.json"
                self.assertIn("TOK28_TURN_A", other_auth_src.read_text(encoding="utf-8"))
                real_link = os.link
                link_calls = [0]

                def _swap_auth_and_fail_cfg_link(src_p: Any, dst_p: Any, **kw: Any) -> None:
                    link_calls[0] += 1
                    if dst_p == "config.toml":
                        # Move Turn-A's single-link `auth.json` into Turn-B's `.codex/auth.json` right before failing `config.toml`!
                        sub_b_path = Path(f"/proc/{os.getpid()}/fd/{kw['dst_dir_fd']}")
                        os.replace(other_auth_src, sub_b_path / "auth.json")
                        raise OSError(errno.EIO, "simulated config.toml link failure")
                    real_link(src_p, dst_p, **kw)

                with mock.patch("os.link", side_effect=_swap_auth_and_fail_cfg_link):
                    with self.assertRaises(OSError):
                        prepare_sandbox_home_fd(rdir28, "codex", host_home=fake_h28, run_dir_fd=rfd28, db=None)
                # Find Turn-B's preserved directory and confirm Turn-A's `auth.json` was NOT zero-truncated!
                found_preserved = False
                for child_d in rdir28.iterdir():
                    if child_d.name != sbh_nm_a and child_d.is_dir():
                        for sub_f in (child_d / ".codex").iterdir():
                            if "TOK28_TURN_A" in sub_f.read_text(encoding="utf-8"):
                                found_preserved = True
                self.assertTrue(found_preserved, "DB-less rollback MUST preserve another turn's auth.json without zero-truncating it!")

                # 3. Crash BEFORE `set_owned_file_token` in `_write_file_at_dirfd` (`O_TMPFILE` before `os.link`) leaves ZERO untagged file in `.codex`!
                rdir28c = ensure_secure_dir(base / "rdir28c", 0o700)
                rfd28c = os.open(str(rdir28c), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    real_setx28 = os.setxattr

                    def _crash_on_cfg_owned_xattr(fd_x: Any, k_x: bytes, v_x: bytes, *rest: Any) -> None:
                        if k_x == b"user.ap_owned_file":
                            # Second `user.ap_owned_file` is `config.toml` (`O_TMPFILE` not yet linked into `.codex`!)
                            st_x = os.fstat(fd_x)
                            if st_x.st_nlink == 0 and os.lseek(fd_x, 0, os.SEEK_END) == 0:
                                pass
                        real_setx28(fd_x, k_x, v_x, *rest)

                    owned_calls = [0]

                    def _crash_second_owned_xattr(fd_x: Any, k_x: bytes, v_x: bytes, *rest: Any) -> None:
                        if k_x == b"user.ap_owned_file":
                            owned_calls[0] += 1
                            if owned_calls[0] == 2:
                                raise OSError(errno.EIO, "simulated crash before setting user.ap_owned_file on config.toml")
                        real_setx28(fd_x, k_x, v_x, *rest)

                    _ = _crash_on_cfg_owned_xattr
                    with mock.patch("os.setxattr", side_effect=_crash_second_owned_xattr):
                        with self.assertRaises(OSError):
                            prepare_sandbox_home_fd(rdir28c, "codex", host_home=fake_h28, run_dir_fd=rfd28c, db=None)
                    self.assertEqual(list(rdir28c.iterdir()), [], "O_TMPFILE crash before setxattr/link MUST leave zero untagged files and rollback cleanly!")
                finally:
                    os.close(rfd28c)
            finally:
                os.close(rfd28)

    def test_round29_all_codex_closures(self) -> None:
        """Regression suite covering both Round-29 Codex Astra [P1] findings."""
        import errno
        import stat
        from unittest import mock
        import agent_autopilot as ap_cli
        from ap_core.models import AutopilotError, ensure_secure_dir
        from ap_core.sandbox import prepare_sandbox_home_fd

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_r = base / "src_repo29"
            sha29 = _init_git_repo(src_r)
            rc29 = ensure_secure_dir(base / "cache29" / "pa" / "o__r", 0o700)
            mg29 = ensure_managed_bare_repo(src_r, rc29 / "managed.git")
            fake_h29 = ensure_secure_dir(base / "fake_h29", 0o700)
            ensure_secure_dir(fake_h29 / ".codex", 0o700)
            (fake_h29 / ".codex" / "auth.json").write_text('{"tokens":{"access_token":"TOK29_OAUTH_SECRET"}}', encoding="utf-8")

            # 1. DB-less `prepare_sandbox_home_fd(..., db=None)` where final `fsync(tfd)` fails AFTER writing `auth.json` bytes:
            #    `local_secret_file_toks` registered BEFORE writing bytes MUST zero-truncate and unlink `auth.json` cleanly!
            rdir29a = ensure_secure_dir(base / "rdir29a", 0o700)
            rfd29a = os.open(str(rdir29a), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                real_fsync29 = os.fsync
                failed_after_secret_write = [False]

                def _fail_post_write_fsync(fd_s: int) -> None:
                    st_s = os.fstat(fd_s)
                    if not failed_after_secret_write[0] and stat.S_ISREG(st_s.st_mode) and st_s.st_size > 0:
                        failed_after_secret_write[0] = True
                        raise OSError(errno.EIO, "simulated EIO on final fsync(tfd) after writing auth.json bytes")
                    real_fsync29(fd_s)

                with mock.patch("os.fsync", side_effect=_fail_post_write_fsync):
                    with self.assertRaises(OSError):
                        prepare_sandbox_home_fd(rdir29a, "codex", host_home=fake_h29, run_dir_fd=rfd29a, db=None)
                self.assertEqual(list(rdir29a.iterdir()), [], "DB-less rollback MUST zero-truncate & remove auth.json when post-write fsync fails!")
            finally:
                os.close(rfd29a)

            # 2. 0-byte secret shell interrupted AFTER `os.link` and BEFORE SQLite registration, reusing a Turn-1 `purged=1` inode:
            #    Reclaim MUST distinguish `(dev, ino, owner_token)` and remove the 0-byte shell cleanly!
            sroot29 = base / "state29"
            db29 = AutopilotDB(sroot29 / "autopilot.db")
            try:
                cfg29 = WorkflowConfig(project_id="pa", kind="issue", enabled=True, repos=("o/r",), workspace_path=str(src_r), write_scope=("src/**",))
                db29.upsert_project(cfg29)
                db29.ensure_lease_slots("pa", ["pa:slot-1"], sroot29 / "locks")
                db29.ensure_work_unit(unit_key="o/r#290", project_id="pa", repo="o/r", issue_number=290)
                st_rc29 = os.lstat(rc29)
                rdir290 = ensure_secure_dir(rc29 / "runs" / "claim-290", 0o700)
                ce290 = db29.claim_and_reserve(
                    unit_key="o/r#290", cfg=cfg29, slot_keys=["pa:slot-1"], worker_unit_name="ap-nonexist-290.service",
                    expected_cgroup_dir=str(expected_transient_cgroup_dir("ap-nonexist-290.service")), base_sha=sha29, authorized_head_ref="agent/290",
                    run_dir=str(rdir290), worktree_path=str(rc29 / "worktrees" / "wt-290"), managed_gitdir=str(mg29),
                    frozen_cache_dir=str(rc29), frozen_cache_dev=int(st_rc29.st_dev), frozen_cache_ino=int(st_rc29.st_ino),
                    bound_gh_login="autopilot-bot", ephemeral_token_file=str(sroot29 / "sealed_tokens" / "claim-pa-290.gh_token"),
                )
                rfd290 = os.open(str(rdir290), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    real_reg29 = db29.register_claim_credential_dir
                    file_reg_hit = [False]

                    def _crash_before_file_sql(ce_r: int, d_r: int, i_r: int, nm_r: str, *, entry_kind: str = "dir", owner_token: str = "") -> None:
                        if entry_kind == "file" and not file_reg_hit[0]:
                            file_reg_hit[0] = True
                            # Seed a historical Turn-1 `purged=1` row on this exact `(d_r, i_r)` with a different token!
                            real_reg29(ce_r, d_r, i_r, "turn1_auth", entry_kind="file", owner_token="turn1_distinct_tok")
                            db29.mark_claim_credential_dir_purged(ce_r, d_r, i_r)
                            raise AutopilotError("simulated crash after os.link before Turn-2 SQLite file registration")
                        real_reg29(ce_r, d_r, i_r, nm_r, entry_kind=entry_kind, owner_token=owner_token)

                    with mock.patch.object(db29, "register_claim_credential_dir", side_effect=_crash_before_file_sql):
                        with mock.patch("os.rmdir", side_effect=OSError(errno.EIO, "block rollback")):
                            with self.assertRaises(AutopilotError):
                                prepare_sandbox_home_fd(rdir290, "codex", host_home=fake_h29, run_dir_fd=rfd290, db=db29, claim_epoch=ce290)
                finally:
                    os.close(rfd290)
                self.assertTrue(ap_cli._reclaim_single_claim_via_bounded_unit(db29, db29.get_claim(ce290), cfg29))
                self.assertEqual(db29.get_claim(ce290)["state"], "released")
            finally:
                db29.close()


if __name__ == "__main__":
    unittest.main()
