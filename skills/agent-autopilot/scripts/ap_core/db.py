"""SQLite state store exclusively owning leases, shared-PR unit scope checks, one-shot SendGrant, and op reconciliation."""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import sqlite3
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Iterator

from .host_guard import HEAVY_UNIT_KINDS, count_global_heavy_claims, load_global_limits
from .models import (
    ACTION_TYPES,
    CANDIDATE_BOUND_WORKER_ACTIONS,
    EXTERNAL_OP_STATUSES,
    PENDING_OP_STATUSES,
    POLICY_MANIFEST,
    SUPERVISOR_ADMIN_ACTIONS,
    AutopilotError,
    PrSnapshot,
    ScopeConflictError,
    ScopeResolution,
    SendGrant,
    WorkflowConfig,
    ensure_sealed_tokens_dir,
    ensure_secure_dir,
    now_iso,
    now_utc,
    open_dir_nofollow,
    resolve_cross_family_referee,
)

_CODEX_DISPATCH_SCRIPTS = Path(__file__).resolve().parents[3] / "codex-dispatch" / "scripts"
if str(_CODEX_DISPATCH_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_CODEX_DISPATCH_SCRIPTS))
import codex_dispatch as _cd  # type: ignore[import-not-found]  # noqa: E402

OPERATOR_RESOLVABLE_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {
        "succeeded_verified",
        "not_executed",
        "merged_before_revoke",
        "diverged_needs_human",
    }
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta_counters (
    name TEXT PRIMARY KEY,
    val INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    max_in_progress INTEGER NOT NULL DEFAULT 1,
    current_step_idx INTEGER NOT NULL DEFAULT 0,
    clean_matured_runs INTEGER NOT NULL DEFAULT 0,
    token_file TEXT NOT NULL DEFAULT '',
    token_mode TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS leases (
    slot_key TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('free', 'active', 'reclaiming')),
    claim_epoch INTEGER,
    unit_key TEXT,
    worker_unit_name TEXT,
    expected_cgroup_dir TEXT,
    flock_path TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS work_units (
    unit_key TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    repo TEXT NOT NULL DEFAULT '',
    issue_number INTEGER,
    status TEXT NOT NULL DEFAULT 'queued',
    terminal_state TEXT,
    pause_reason_kind TEXT,
    current_candidate_sha TEXT,
    last_confirmed_head_oid TEXT,
    pr_id TEXT,
    pr_number INTEGER,
    veto_pending INTEGER NOT NULL DEFAULT 0,
    veto_remote_sync_pending INTEGER NOT NULL DEFAULT 0,
    scope_quarantined INTEGER NOT NULL DEFAULT 0,
    review_rounds_used INTEGER NOT NULL DEFAULT 0,
    waiting_until TEXT,
    failure_streak INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    approved_protected_paths_json TEXT NOT NULL DEFAULT '[]',
    blocked_protected_paths_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_work_units_pr_id ON work_units(pr_id) WHERE pr_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_work_units_project ON work_units(project_id, status);

CREATE TABLE IF NOT EXISTS run_claims (
    claim_epoch INTEGER PRIMARY KEY,
    unit_key TEXT NOT NULL,
    project_id TEXT NOT NULL,
    repo TEXT NOT NULL DEFAULT '',
    slot_vector_json TEXT NOT NULL,
    worker_unit_name TEXT NOT NULL,
    expected_cgroup_dir TEXT NOT NULL,
    cleanup_unit_name TEXT,
    cleanup_cgroup_dir TEXT,
    base_sha TEXT NOT NULL,
    authorized_base_ref TEXT NOT NULL,
    authorized_head_ref TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    effective_tier TEXT NOT NULL,
    frozen_write_scope_json TEXT NOT NULL,
    frozen_merge_paths_json TEXT NOT NULL,
    frozen_approved_protected_paths_json TEXT NOT NULL DEFAULT '[]',
    merge_method TEXT NOT NULL,
    unit_kind TEXT NOT NULL DEFAULT 'issue',
    run_dir TEXT NOT NULL DEFAULT '',
    run_dir_dev INTEGER,
    run_dir_ino INTEGER,
    run_dir_state TEXT NOT NULL DEFAULT 'legacy_untracked',
    cred_ledger_tracked INTEGER NOT NULL DEFAULT 0,
    worktree_path TEXT NOT NULL DEFAULT '',
    managed_gitdir TEXT NOT NULL DEFAULT '',
    frozen_cache_dir TEXT NOT NULL DEFAULT '',
    frozen_cache_dev INTEGER,
    frozen_cache_ino INTEGER,
    path_recorded INTEGER NOT NULL DEFAULT 0,
    bound_gh_login TEXT NOT NULL DEFAULT '',
    ephemeral_token_file TEXT NOT NULL DEFAULT '',
    outcome TEXT,
    state TEXT NOT NULL CHECK(state IN ('active', 'reclaiming', 'released')),
    created_at TEXT NOT NULL,
    released_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_run_claims_unit ON run_claims(unit_key, state);

CREATE TABLE IF NOT EXISTS external_ops (
    op_id TEXT PRIMARY KEY,
    op_seq INTEGER NOT NULL,
    unit_key TEXT NOT NULL,
    project_id TEXT NOT NULL DEFAULT '',
    pr_id TEXT,
    op_type TEXT NOT NULL,
    owner_kind TEXT NOT NULL CHECK(owner_kind IN ('worker', 'supervisor_admin')),
    owner_epoch INTEGER NOT NULL,
    claim_epoch INTEGER,
    candidate_sha TEXT,
    authorized_base_ref TEXT,
    authorized_head_ref TEXT,
    ref_id_hmac TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL,
    grant_token TEXT,
    send_consumed INTEGER NOT NULL DEFAULT 0,
    remote_receipt_id TEXT,
    unsent_proof TEXT,
    conflicting_pr_id TEXT,
    error_detail TEXT,
    superseded_by_op_id TEXT,
    prepared_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_external_ops_unit ON external_ops(unit_key, status);
CREATE INDEX IF NOT EXISTS idx_external_ops_pr ON external_ops(pr_id, status) WHERE pr_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS verify_receipts (
    unit_key TEXT NOT NULL,
    candidate_sha TEXT NOT NULL,
    dod_cmd TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    ui_verified INTEGER NOT NULL DEFAULT 0,
    touched_paths_json TEXT NOT NULL DEFAULT '[]',
    artifact_dir TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(unit_key, candidate_sha)
);

CREATE TABLE IF NOT EXISTS review_receipts (
    unit_key TEXT NOT NULL,
    candidate_sha TEXT NOT NULL,
    round_index INTEGER NOT NULL,
    writer_family TEXT NOT NULL,
    referee_family TEXT NOT NULL,
    referee_model TEXT NOT NULL,
    verdict TEXT NOT NULL,
    defect_count INTEGER NOT NULL,
    defects_json TEXT NOT NULL,
    raw_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(unit_key, candidate_sha, round_index)
);

CREATE TABLE IF NOT EXISTS run_history (
    run_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    unit_key TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0.0,
    completed_at TEXT NOT NULL,
    matured_clean INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pitfalls (
    sig TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    target_area TEXT NOT NULL,
    symptom TEXT NOT NULL,
    rule_text TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'advisory',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routine_cursors (
    project_id TEXT PRIMARY KEY,
    last_full_run_ts REAL,
    processed_ids_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS claim_credential_dirs (
    claim_epoch INTEGER NOT NULL,
    dir_dev INTEGER NOT NULL,
    dir_ino INTEGER NOT NULL,
    initial_name TEXT NOT NULL,
    entry_kind TEXT NOT NULL DEFAULT 'dir',
    owner_token TEXT NOT NULL DEFAULT '',
    purged INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    purged_at TEXT,
    PRIMARY KEY(claim_epoch, dir_dev, dir_ino)
);
"""

_COLUMN_MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("projects", "token_file", "TEXT NOT NULL DEFAULT ''"),
    ("projects", "token_mode", "TEXT"),
    ("work_units", "pause_reason_kind", "TEXT"),
    ("work_units", "last_confirmed_head_oid", "TEXT"),
    ("work_units", "veto_remote_sync_pending", "INTEGER NOT NULL DEFAULT 0"),
    ("work_units", "scope_quarantined", "INTEGER NOT NULL DEFAULT 0"),
    ("work_units", "approved_protected_paths_json", "TEXT NOT NULL DEFAULT '[]'"),
    ("work_units", "blocked_protected_paths_json", "TEXT"),
    ("run_claims", "frozen_approved_protected_paths_json", "TEXT NOT NULL DEFAULT '[]'"),
    ("run_claims", "repo", "TEXT NOT NULL DEFAULT ''"),
    ("run_claims", "cleanup_unit_name", "TEXT"),
    ("run_claims", "cleanup_cgroup_dir", "TEXT"),
    ("run_claims", "unit_kind", "TEXT NOT NULL DEFAULT 'issue'"),
    ("run_claims", "run_dir", "TEXT NOT NULL DEFAULT ''"),
    ("run_claims", "run_dir_dev", "INTEGER"),
    ("run_claims", "run_dir_ino", "INTEGER"),
    ("run_claims", "run_dir_state", "TEXT NOT NULL DEFAULT 'legacy_untracked'"),
    ("run_claims", "cred_ledger_tracked", "INTEGER NOT NULL DEFAULT 0"),
    ("claim_credential_dirs", "entry_kind", "TEXT NOT NULL DEFAULT 'dir'"),
    ("claim_credential_dirs", "owner_token", "TEXT NOT NULL DEFAULT ''"),
    ("run_claims", "worktree_path", "TEXT NOT NULL DEFAULT ''"),
    ("run_claims", "managed_gitdir", "TEXT NOT NULL DEFAULT ''"),
    ("run_claims", "frozen_cache_dir", "TEXT NOT NULL DEFAULT ''"),
    ("run_claims", "frozen_cache_dev", "INTEGER"),
    ("run_claims", "frozen_cache_ino", "INTEGER"),
    ("run_claims", "path_recorded", "INTEGER NOT NULL DEFAULT 0"),
    ("run_claims", "bound_gh_login", "TEXT NOT NULL DEFAULT ''"),
    ("run_claims", "ephemeral_token_file", "TEXT NOT NULL DEFAULT ''"),
    ("run_claims", "outcome", "TEXT"),
    ("external_ops", "project_id", "TEXT NOT NULL DEFAULT ''"),
    ("external_ops", "grant_token", "TEXT"),
    ("external_ops", "send_consumed", "INTEGER NOT NULL DEFAULT 0"),
    ("external_ops", "conflicting_pr_id", "TEXT"),
    ("verify_receipts", "touched_paths_json", "TEXT NOT NULL DEFAULT '[]'"),
)


class AutopilotDB:
    """Exclusive thread-safe transactional manager for agent-autopilot SQLite state."""

    def __init__(self, db_path: Path, *, readonly: bool = False) -> None:
        self.db_path = db_path
        self.readonly = readonly
        self._lock = threading.RLock()
        self._tx_depth = 0
        if readonly:
            if db_path.is_file():
                self._conn = sqlite3.connect(
                    f"file:{db_path}?mode=ro",
                    uri=True,
                    timeout=5.0,
                    isolation_level=None,
                    check_same_thread=False,
                )
                self._conn.row_factory = sqlite3.Row
            else:
                # Pure in-memory empty schema so --dry-run / --probe-only creates ZERO files/dirs on disk!
                self._conn = sqlite3.connect(
                    ":memory:",
                    isolation_level=None,
                    check_same_thread=False,
                )
                self._conn.row_factory = sqlite3.Row
                for stmt in SCHEMA_SQL.strip().split(";"):
                    s = stmt.strip()
                    if s:
                        self._conn.execute(s)
            return

        ensure_secure_dir(db_path.parent, 0o700)
        ensure_sealed_tokens_dir(db_path.parent)
        self._conn = sqlite3.connect(
            str(db_path),
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._init_pragmas_and_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _init_pragmas_and_schema(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=DELETE")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            with self.immediate_tx():
                for stmt in SCHEMA_SQL.strip().split(";"):
                    s = stmt.strip()
                    if s:
                        self._conn.execute(s)
                for cname in ("dispatcher_epoch", "op_seq", "claim_epoch"):
                    self._conn.execute(
                        "INSERT OR IGNORE INTO meta_counters(name, val) VALUES (?, 0)",
                        (cname,),
                    )
                # Transactional schema migrations for upgraded DBs
                for tbl, col, col_def in _COLUMN_MIGRATIONS:
                    existing_cols = {
                        str(r["name"])
                        for r in self._conn.execute(f"PRAGMA table_info({tbl})").fetchall()
                    }
                    if col not in existing_cols:
                        self._conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {col_def}")
                # Conservatively mark ANY pre-migration in_flight OR unknown_paused row lacking grant_token as send_consumed=1
                self._conn.execute(
                    "UPDATE external_ops SET send_consumed = 1 WHERE status IN ('in_flight', 'unknown_paused') AND grant_token IS NULL AND send_consumed = 0"
                )
                self._conn.execute(
                    "UPDATE run_claims SET run_dir_state = 'bound' WHERE run_dir_dev IS NOT NULL AND run_dir_ino IS NOT NULL AND run_dir_state = 'legacy_untracked'"
                )
                # Backfill external_ops.project_id from originating run_claims for pre-migration rows
                self._conn.execute(
                    """
                    UPDATE external_ops
                    SET project_id = COALESCE(
                        (SELECT rc.project_id FROM run_claims rc WHERE rc.claim_epoch = external_ops.claim_epoch),
                        ''
                    )
                    WHERE project_id = '' AND claim_epoch IS NOT NULL
                    """
                )
                # Fast `EXISTS`-gated backfill: O(1) on clean/already-migrated DBs, yet ALWAYS migrates any unmigrated conflict rows!
                need_conf_mig = bool(
                    self._conn.execute(
                        """
                        SELECT 1 FROM external_ops eo
                        WHERE eo.conflicting_pr_id IS NULL
                          AND (
                              eo.error_detail LIKE 'conflicting_pr_id=%'
                              OR eo.remote_receipt_id LIKE 'conflict:%'
                              OR (
                                  eo.status = 'diverged_needs_human'
                                  AND eo.remote_receipt_id IS NOT NULL
                                  AND EXISTS (
                                      SELECT 1 FROM work_units wu_op
                                      JOIN work_units wu_pr ON wu_pr.pr_id = eo.remote_receipt_id
                                      WHERE wu_op.unit_key = eo.unit_key
                                        AND wu_op.project_id != ''
                                        AND wu_pr.project_id != ''
                                        AND wu_op.project_id != wu_pr.project_id
                                  )
                              )
                          )
                        UNION ALL
                        SELECT 1 FROM work_units
                        WHERE scope_quarantined = 0
                          AND (last_error LIKE 'conflicting_pr_id=%' OR last_error LIKE 'quarantined_on_send_consume:%' OR last_error LIKE 'manual_veto_quarantined:%')
                        LIMIT 1
                        """
                    ).fetchone()
                )
                if need_conf_mig:
                    for crow_mig in self._conn.execute(
                        "SELECT op_id, remote_receipt_id, error_detail FROM external_ops WHERE conflicting_pr_id IS NULL AND (error_detail LIKE 'conflicting_pr_id=%' OR remote_receipt_id LIKE 'conflict:%')"
                    ).fetchall():
                        ed = str(crow_mig["error_detail"] or "")
                        rr = str(crow_mig["remote_receipt_id"] or "")
                        c_pr = ""
                        if ed.startswith("conflicting_pr_id=") and ":" in ed:
                            c_pr = ed.split(":", 1)[0].split("=", 1)[1].strip()
                        elif rr.startswith("conflict:"):
                            c_pr = rr.split(":", 1)[1].strip()
                        if c_pr:
                            self._conn.execute("UPDATE external_ops SET conflicting_pr_id = ? WHERE op_id = ?", (c_pr, crow_mig["op_id"]))
                    for drow_mig in self._conn.execute(
                        """
                        SELECT eo.op_id, eo.remote_receipt_id
                        FROM external_ops eo
                        JOIN work_units wu_op ON wu_op.unit_key = eo.unit_key
                        JOIN work_units wu_pr ON wu_pr.pr_id = eo.remote_receipt_id
                        WHERE eo.conflicting_pr_id IS NULL
                          AND eo.status = 'diverged_needs_human'
                          AND eo.remote_receipt_id IS NOT NULL
                          AND wu_op.project_id != ''
                          AND wu_pr.project_id != ''
                          AND wu_op.project_id != wu_pr.project_id
                        """
                    ).fetchall():
                        self._conn.execute(
                            "UPDATE external_ops SET conflicting_pr_id = ? WHERE op_id = ?",
                            (drow_mig["remote_receipt_id"], drow_mig["op_id"]),
                        )
                    all_uks = [str(r["unit_key"]) for r in self._conn.execute("SELECT unit_key FROM work_units").fetchall()]
                    seen_q: set[str] = set()
                    for uk_m in all_uks:
                        if uk_m in seen_q:
                            continue
                        ur_m = self._conn.execute("SELECT last_error FROM work_units WHERE unit_key = ?", (uk_m,)).fetchone()
                        le_m = str(ur_m["last_error"] or "") if ur_m else ""
                        ok_m, conn_m, _ = self._inspect_scope_integrity_in_tx(uk_m)
                        has_legacy_marker = any(
                            le_m.startswith(pfx)
                            for pfx in ("conflicting_pr_id=", "quarantined_on_send_consume:", "manual_veto_quarantined:")
                        )
                        if not ok_m or has_legacy_marker:
                            targets_m = conn_m or (uk_m,)
                            seen_q.update(targets_m)
                            um_m = ",".join("?" for _ in targets_m)
                            self._conn.execute(
                                f"""
                                UPDATE work_units
                                SET scope_quarantined = 1,
                                    veto_pending = 1,
                                    veto_remote_sync_pending = 0,
                                    status = 'paused',
                                    terminal_state = 'needs-human'
                                WHERE unit_key IN ({um_m})
                                """,
                                targets_m,
                            )

    @contextlib.contextmanager
    def immediate_tx(self) -> Iterator[sqlite3.Connection]:
        """Thread-serialized BEGIN IMMEDIATE transaction (nested calls on same thread share outer tx)."""
        if self.readonly:
            raise AutopilotError("Refusing write transaction on readonly AutopilotDB")
        with self._lock:
            if self._tx_depth > 0:
                self._tx_depth += 1
                try:
                    yield self._conn
                finally:
                    self._tx_depth -= 1
                return

            self._conn.execute("BEGIN IMMEDIATE")
            self._tx_depth = 1
            try:
                yield self._conn
            except BaseException:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise
            else:
                if self._conn.in_transaction:
                    self._conn.execute("COMMIT")
            finally:
                self._tx_depth = 0

    def _next_counter_in_tx(self, name: str) -> int:
        assert self._tx_depth > 0 and self._conn.in_transaction, "_next_counter_in_tx requires active IMMEDIATE tx"
        self._conn.execute("UPDATE meta_counters SET val = val + 1 WHERE name = ?", (name,))
        row = self._conn.execute("SELECT val FROM meta_counters WHERE name = ?", (name,)).fetchone()
        assert row is not None
        return int(row["val"])

    def current_op_seq(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT val FROM meta_counters WHERE name = 'op_seq'").fetchone()
            return int(row["val"]) if row else 0

    def bump_dispatcher_epoch(self) -> int:
        with self.immediate_tx():
            return self._next_counter_in_tx("dispatcher_epoch")

    def get_dispatcher_epoch(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT val FROM meta_counters WHERE name = 'dispatcher_epoch'").fetchone()
            return int(row["val"]) if row else 0

    def upsert_project(self, cfg: WorkflowConfig) -> None:
        with self.immediate_tx():
            steps = POLICY_MANIFEST["chef_pipeline"]["staircase_concurrency_steps"]
            row = self._conn.execute(
                "SELECT max_in_progress, current_step_idx FROM projects WHERE project_id = ?",
                (cfg.project_id,),
            ).fetchone()
            tmode = "dedicated" if (cfg.token_file and cfg.token_file.strip()) else "ambient"
            if row is None:
                init_cap = min(cfg.max_in_progress, int(POLICY_MANIFEST["chef_pipeline"]["initial_max_in_progress"]))
                step_idx = steps.index(init_cap) if init_cap in steps else 0
                self._conn.execute(
                    "INSERT INTO projects(project_id, kind, enabled, max_in_progress, current_step_idx, clean_matured_runs, token_file, token_mode, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)",
                    (cfg.project_id, cfg.kind, int(cfg.enabled), init_cap, step_idx, (cfg.token_file or "").strip(), tmode, now_iso()),
                )
            else:
                # Preserve human staircase promotions when current_step_idx > 0 unless config explicitly caps higher/lower
                promoted_cap = int(row["max_in_progress"])
                eff_cap = promoted_cap if int(row["current_step_idx"]) > 0 else min(cfg.max_in_progress, promoted_cap)
                self._conn.execute(
                    "UPDATE projects SET kind = ?, enabled = ?, max_in_progress = ?, token_file = ?, token_mode = ?, updated_at = ? WHERE project_id = ?",
                    (cfg.kind, int(cfg.enabled), eff_cap, (cfg.token_file or "").strip(), tmode, now_iso(), cfg.project_id),
                )

    def _assert_pr_project_compatible_in_tx(self, pr_id: str, project_id: str) -> None:
        """Forbid binding `pr_id` to `project_id` if any existing unit, op, or claim on `pr_id` belongs to another project."""
        if not pr_id or not project_id:
            return
        other_pids: set[str] = set()
        for r in self._conn.execute(
            "SELECT DISTINCT project_id, unit_key FROM work_units WHERE pr_id = ?",
            (pr_id,),
        ).fetchall():
            if r["project_id"] and str(r["project_id"]) != project_id:
                other_pids.add(str(r["project_id"]))
            for cr in self._conn.execute(
                "SELECT DISTINCT project_id FROM run_claims WHERE unit_key = ? AND project_id != ''",
                (r["unit_key"],),
            ).fetchall():
                if cr["project_id"] and str(cr["project_id"]) != project_id:
                    other_pids.add(str(cr["project_id"]))
        for r in self._conn.execute(
            "SELECT DISTINCT project_id, claim_epoch FROM external_ops WHERE pr_id = ?",
            (pr_id,),
        ).fetchall():
            if r["project_id"] and str(r["project_id"]) != project_id:
                other_pids.add(str(r["project_id"]))
            if r["claim_epoch"] is not None:
                cr = self._conn.execute(
                    "SELECT project_id FROM run_claims WHERE claim_epoch = ?",
                    (int(r["claim_epoch"]),),
                ).fetchone()
                if cr and cr["project_id"] and str(cr["project_id"]) != project_id:
                    other_pids.add(str(cr["project_id"]))
        if other_pids:
            raise ScopeConflictError(
                f"Cannot bind PR {pr_id!r} to project {project_id!r}: already bound to project(s) {sorted(other_pids)}"
            )

    def ensure_work_unit(
        self,
        *,
        unit_key: str,
        project_id: str,
        repo: str = "",
        issue_number: int | None = None,
        pr_id: str | None = None,
        pr_number: int | None = None,
    ) -> dict[str, Any]:
        with self.immediate_tx():
            ts = now_iso()
            row = self._conn.execute("SELECT * FROM work_units WHERE unit_key = ?", (unit_key,)).fetchone()
            eff_pid = str(row["project_id"]) if (row is not None and row["project_id"]) else project_id
            if pr_id is not None:
                self._assert_pr_project_compatible_in_tx(str(pr_id), str(eff_pid))
            if row is None:
                self._conn.execute(
                    "INSERT INTO work_units(unit_key, project_id, repo, issue_number, status, pr_id, pr_number, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?)",
                    (unit_key, project_id, repo, issue_number, pr_id, pr_number, ts, ts),
                )
            else:
                if row["project_id"] and project_id and str(row["project_id"]) != str(project_id):
                    raise ScopeConflictError(
                        f"Unit {unit_key} already belongs to project {row['project_id']!r}, cannot rebind to {project_id!r}"
                    )
                if pr_id is not None and row["pr_id"] is not None and row["pr_id"] != pr_id:
                    raise ScopeConflictError(
                        f"Unit {unit_key} already bound to pr_id={row['pr_id']!r}, cannot rebind to {pr_id!r}"
                    )
                if pr_id is not None and row["pr_id"] is None:
                    self._conn.execute(
                        "UPDATE work_units SET pr_id = ?, pr_number = COALESCE(?, pr_number), updated_at = ? WHERE unit_key = ?",
                        (pr_id, pr_number, ts, unit_key),
                    )
            out = self._conn.execute("SELECT * FROM work_units WHERE unit_key = ?", (unit_key,)).fetchone()
            assert out is not None
            return dict(out)

    def ensure_lease_slots(self, project_id: str, slot_keys: list[str], flock_dir: Path) -> None:
        ensure_secure_dir(flock_dir, 0o700)
        with self.immediate_tx():
            ts = now_iso()
            for sk in slot_keys:
                safe_name = sk.replace("/", "__").replace(":", "_")
                f_path = str(flock_dir / f"{safe_name}.flock")
                self._conn.execute(
                    "INSERT OR IGNORE INTO leases(slot_key, project_id, state, flock_path, updated_at) "
                    "VALUES (?, ?, 'free', ?, ?)",
                    (sk, project_id, f_path, ts),
                )

    def resolve_unit_scope_and_pending(
        self,
        unit_key: str,
        pr_id: str | None = None,
        statuses: tuple[str, ...] = PENDING_OP_STATUSES,
        *,
        exclude_op_id: str | None = None,
        exclude_self_worker_prepared: bool = False,
        bind_pr_if_unset: bool = False,
    ) -> ScopeResolution:
        """Single unified scope expansion & pending-op query shared by all 5 write entrypoints."""
        with self._lock:
            if not self.readonly and self._tx_depth == 0:
                with self.immediate_tx():
                    return self.resolve_unit_scope_and_pending(
                        unit_key,
                        pr_id=pr_id,
                        statuses=statuses,
                        exclude_op_id=exclude_op_id,
                        exclude_self_worker_prepared=exclude_self_worker_prepared,
                        bind_pr_if_unset=bind_pr_if_unset,
                    )

            urow = self._conn.execute(
                "SELECT unit_key, project_id, pr_id FROM work_units WHERE unit_key = ?",
                (unit_key,),
            ).fetchone()
            if urow is None:
                raise AutopilotError(f"Unknown work_unit: {unit_key!r}")

            bound_pr = urow["pr_id"]
            hist_prs = {
                r["pr_id"]
                for r in self._conn.execute(
                    "SELECT DISTINCT pr_id FROM external_ops WHERE unit_key = ? AND pr_id IS NOT NULL",
                    (unit_key,),
                )
            }
            distinct_prs: set[str] = set()
            if bound_pr is not None:
                distinct_prs.add(str(bound_pr))
            distinct_prs.update(str(p) for p in hist_prs if p)
            if pr_id is not None:
                distinct_prs.add(str(pr_id))
            if len(distinct_prs) > 1:
                raise ScopeConflictError(
                    f"Conflicting non-null PR identities on {unit_key!r}: bound={bound_pr!r}, hist={sorted(hist_prs)}, arg={pr_id!r}"
                )

            eff_pr_id = next(iter(distinct_prs), None)
            if bind_pr_if_unset and not self.readonly and eff_pr_id is not None and bound_pr is None:
                self._assert_pr_project_compatible_in_tx(eff_pr_id, str(urow["project_id"] or ""))
                self._conn.execute(
                    "UPDATE work_units SET pr_id = ?, updated_at = ? WHERE unit_key = ?",
                    (eff_pr_id, now_iso(), unit_key),
                )

            scope_rows = self._conn.execute(
                """
                SELECT unit_key FROM work_units
                WHERE unit_key = ? OR (? IS NOT NULL AND pr_id = ?)
                UNION
                SELECT DISTINCT unit_key FROM external_ops
                WHERE ? IS NOT NULL AND pr_id = ?
                """,
                (unit_key, eff_pr_id, eff_pr_id, eff_pr_id, eff_pr_id),
            ).fetchall()
            scope_units = tuple(sorted({str(r["unit_key"]) for r in scope_rows} | {unit_key}))

            u_marks = ",".join("?" for _ in scope_units)
            any_veto_row = self._conn.execute(
                f"SELECT COALESCE(MAX(veto_pending), 0) AS v FROM work_units WHERE unit_key IN ({u_marks})",
                scope_units,
            ).fetchone()
            any_veto = int(any_veto_row["v"]) if any_veto_row else 0

            max_seq_row = self._conn.execute(
                f"""
                SELECT COALESCE(MAX(op_seq), 0) AS m FROM external_ops
                WHERE unit_key IN ({u_marks}) OR (? IS NOT NULL AND pr_id = ?)
                """,
                (*scope_units, eff_pr_id, eff_pr_id),
            ).fetchone()
            max_op_seq = int(max_seq_row["m"]) if max_seq_row else 0

            if not statuses:
                pending_cnt = 0
            else:
                s_marks = ",".join("?" for _ in statuses)
                cnt_row = self._conn.execute(
                    f"""
                    SELECT COUNT(*) AS c FROM external_ops
                    WHERE (? IS NULL OR op_id != ?)
                      AND NOT (? = 1 AND unit_key = ? AND owner_kind = 'worker' AND status = 'prepared_local')
                      AND (unit_key IN ({u_marks}) OR (? IS NOT NULL AND pr_id = ?))
                      AND status IN ({s_marks})
                    """,
                    (
                        exclude_op_id,
                        exclude_op_id,
                        1 if exclude_self_worker_prepared else 0,
                        unit_key,
                        *scope_units,
                        eff_pr_id,
                        eff_pr_id,
                        *statuses,
                    ),
                ).fetchone()
                pending_cnt = int(cnt_row["c"]) if cnt_row else 0

            return ScopeResolution(
                eff_pr_id=eff_pr_id,
                scope_units=scope_units,
                pending_cnt=pending_cnt,
                any_veto=any_veto,
                max_op_seq=max_op_seq,
            )

    def _inspect_scope_integrity_in_tx(
        self,
        unit_key: str,
        pr_id: str | None = None,
    ) -> tuple[bool, tuple[str, ...], str]:
        """Fixpoint connected-component check across work_units, external_ops, AND run_claims (catching >1 PR or >1 project_id)."""
        conn_units: set[str] = {unit_key}
        conn_prs: set[str] = {str(pr_id)} if pr_id else set()

        while True:
            prev_u = len(conn_units)
            prev_p = len(conn_prs)
            if conn_units:
                um = ",".join("?" for _ in conn_units)
                u_seq = tuple(sorted(conn_units))
                for r in self._conn.execute(
                    f"SELECT pr_id FROM work_units WHERE unit_key IN ({um}) AND pr_id IS NOT NULL",
                    u_seq,
                ).fetchall():
                    if r["pr_id"]:
                        conn_prs.add(str(r["pr_id"]))
                for r in self._conn.execute(
                    f"SELECT DISTINCT pr_id, conflicting_pr_id FROM external_ops WHERE unit_key IN ({um})",
                    u_seq,
                ).fetchall():
                    if r["pr_id"]:
                        conn_prs.add(str(r["pr_id"]))
                    if r["conflicting_pr_id"]:
                        conn_prs.add(str(r["conflicting_pr_id"]))
            if conn_prs:
                pm = ",".join("?" for _ in conn_prs)
                p_seq = tuple(sorted(conn_prs))
                for r in self._conn.execute(
                    f"SELECT unit_key FROM work_units WHERE pr_id IN ({pm})",
                    p_seq,
                ).fetchall():
                    if r["unit_key"]:
                        conn_units.add(str(r["unit_key"]))
                for r in self._conn.execute(
                    f"SELECT DISTINCT unit_key FROM external_ops WHERE pr_id IN ({pm}) OR conflicting_pr_id IN ({pm})",
                    (*p_seq, *p_seq),
                ).fetchall():
                    if r["unit_key"]:
                        conn_units.add(str(r["unit_key"]))
            if len(conn_units) == prev_u and len(conn_prs) == prev_p:
                break

        existing_units = tuple(
            r["unit_key"]
            for r in self._conn.execute(
                f"SELECT unit_key FROM work_units WHERE unit_key IN ({','.join('?' for _ in conn_units)}) ORDER BY unit_key",
                tuple(sorted(conn_units)),
            ).fetchall()
        )
        if existing_units:
            em = ",".join("?" for _ in existing_units)
            q_cnt = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM work_units WHERE unit_key IN ({em}) AND scope_quarantined != 0",
                existing_units,
            ).fetchone()["c"]
            if int(q_cnt) > 0:
                return (
                    False,
                    existing_units,
                    f"Persisted scope_quarantined=1 across connected units {list(existing_units)}",
                )
        if len(conn_prs) > 1:
            return (
                False,
                existing_units,
                f"Conflicting PR identities {sorted(conn_prs)} across connected units {list(existing_units)}",
            )

        pids: set[str] = set()
        if conn_units:
            um = ",".join("?" for _ in conn_units)
            u_seq = tuple(sorted(conn_units))
            for r in self._conn.execute(
                f"SELECT DISTINCT project_id FROM work_units WHERE unit_key IN ({um}) AND project_id != ''",
                u_seq,
            ).fetchall():
                if r["project_id"]:
                    pids.add(str(r["project_id"]))
            for r in self._conn.execute(
                f"SELECT DISTINCT project_id FROM run_claims WHERE unit_key IN ({um}) AND project_id != ''",
                u_seq,
            ).fetchall():
                if r["project_id"]:
                    pids.add(str(r["project_id"]))
            for r in self._conn.execute(
                f"SELECT DISTINCT project_id, claim_epoch FROM external_ops WHERE unit_key IN ({um})",
                u_seq,
            ).fetchall():
                if r["project_id"]:
                    pids.add(str(r["project_id"]))
                if r["claim_epoch"] is not None:
                    cr = self._conn.execute(
                        "SELECT project_id FROM run_claims WHERE claim_epoch = ?",
                        (int(r["claim_epoch"]),),
                    ).fetchone()
                    if cr and cr["project_id"]:
                        pids.add(str(cr["project_id"]))
        if conn_prs:
            pm = ",".join("?" for _ in conn_prs)
            p_seq = tuple(sorted(conn_prs))
            for r in self._conn.execute(
                f"SELECT DISTINCT project_id FROM external_ops WHERE pr_id IN ({pm}) AND project_id != ''",
                p_seq,
            ).fetchall():
                if r["project_id"]:
                    pids.add(str(r["project_id"]))

        if len(pids) > 1:
            return (
                False,
                existing_units,
                f"Cross-project ownership conflict {sorted(pids)} across connected units {list(existing_units)}",
            )
        return True, existing_units, ""

    def inspect_scope_integrity(
        self,
        unit_key: str,
        pr_id: str | None = None,
    ) -> tuple[bool, tuple[str, ...], str]:
        with self._lock:
            if not self.readonly and self._tx_depth == 0:
                with self.immediate_tx():
                    return self._inspect_scope_integrity_in_tx(unit_key, pr_id=pr_id)
            return self._inspect_scope_integrity_in_tx(unit_key, pr_id=pr_id)

    def register_claim_credential_dir(
        self,
        claim_epoch: int,
        dir_dev: int,
        dir_ino: int,
        initial_name: str,
        *,
        entry_kind: str = "dir",
        owner_token: str = "",
    ) -> None:
        """Persist an active credential dir/file `(dev, ino, entry_kind, owner_token)` BEFORE writing tokens!"""
        with self.immediate_tx():
            self._conn.execute(
                """
                INSERT INTO claim_credential_dirs(claim_epoch, dir_dev, dir_ino, initial_name, entry_kind, owner_token, purged, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(claim_epoch, dir_dev, dir_ino) DO UPDATE SET
                    entry_kind = excluded.entry_kind,
                    owner_token = CASE WHEN excluded.owner_token != '' THEN excluded.owner_token ELSE claim_credential_dirs.owner_token END,
                    purged = 0,
                    purged_at = NULL
                """,
                (int(claim_epoch), int(dir_dev), int(dir_ino), str(initial_name), str(entry_kind), str(owner_token), now_iso()),
            )

    def mark_claim_credential_dir_purged(self, claim_epoch: int, dir_dev: int, dir_ino: int) -> None:
        with self.immediate_tx():
            self._conn.execute(
                "UPDATE claim_credential_dirs SET purged = 1, purged_at = ? WHERE claim_epoch = ? AND dir_dev = ? AND dir_ino = ?",
                (now_iso(), int(claim_epoch), int(dir_dev), int(dir_ino)),
            )

    def list_unpurged_claim_credential_dirs(self, claim_epoch: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT claim_epoch, dir_dev, dir_ino, initial_name, entry_kind, owner_token FROM claim_credential_dirs WHERE claim_epoch = ? AND purged = 0",
            (int(claim_epoch),),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_all_claim_credential_dirs(self, claim_epoch: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT claim_epoch, dir_dev, dir_ino, initial_name, entry_kind, owner_token, purged FROM claim_credential_dirs WHERE claim_epoch = ?",
            (int(claim_epoch),),
        ).fetchall()
        return [dict(r) for r in rows]

    def record_claim_run_dir_identity(self, claim_epoch: int, run_dir_dev: int, run_dir_ino: int) -> None:
        """Persist `run_dir` `(st_dev, st_ino)` BEFORE writing credentials; reject if already bound to a different inode."""
        with self.immediate_tx():
            row = self._conn.execute(
                "SELECT run_dir_dev, run_dir_ino FROM run_claims WHERE claim_epoch = ?",
                (claim_epoch,),
            ).fetchone()
            if row is None:
                raise AutopilotError(f"Unknown claim_epoch={claim_epoch}")
            if row["run_dir_dev"] is not None and row["run_dir_ino"] is not None:
                if int(row["run_dir_dev"]) != int(run_dir_dev) or int(row["run_dir_ino"]) != int(run_dir_ino):
                    raise AutopilotError(
                        f"run_dir identity drifted for claim_epoch={claim_epoch}: ({run_dir_dev}, {run_dir_ino}) != ({row['run_dir_dev']}, {row['run_dir_ino']})"
                    )
                self._conn.execute(
                    "UPDATE run_claims SET run_dir_state = 'bound' WHERE claim_epoch = ? AND run_dir_state != 'bound'",
                    (claim_epoch,),
                )
                return
            self._conn.execute(
                "UPDATE run_claims SET run_dir_dev = ?, run_dir_ino = ?, run_dir_state = 'bound' WHERE claim_epoch = ?",
                (int(run_dir_dev), int(run_dir_ino), claim_epoch),
            )

    # --- Entrypoint 1: claim_and_reserve ---
    def claim_and_reserve(
        self,
        *,
        unit_key: str,
        cfg: WorkflowConfig,
        slot_keys: list[str],
        worker_unit_name: str,
        expected_cgroup_dir: str,
        base_sha: str,
        authorized_head_ref: str,
        run_dir: str = "",
        run_dir_dev: int | None = None,
        run_dir_ino: int | None = None,
        worktree_path: str = "",
        managed_gitdir: str = "",
        frozen_cache_dir: str = "",
        frozen_cache_dev: int | None = None,
        frozen_cache_ino: int | None = None,
        bound_gh_login: str = "",
        ephemeral_token_file: str = "",
    ) -> int:
        if not slot_keys:
            raise AutopilotError("claim_and_reserve requires non-empty physical lease vector V")
        if cfg.kind == "issue" and authorized_head_ref == cfg.authorized_base_ref:
            raise AutopilotError("authorized_head_ref MUST NOT equal authorized_base_ref")
        if cfg.kind == "issue" and not cfg.write_scope:
            raise AutopilotError("frozen_write_scope MUST be non-empty for issue units")

        with self.immediate_tx():
            ok_int, _, int_reason = self._inspect_scope_integrity_in_tx(unit_key)
            if not ok_int:
                raise ScopeConflictError(int_reason)
            scope = self.resolve_unit_scope_and_pending(unit_key, statuses=PENDING_OP_STATUSES)
            if scope.any_veto != 0:
                raise AutopilotError(f"Cannot claim {unit_key}: veto_pending=1 in scope {scope.scope_units}")
            if scope.pending_cnt != 0:
                raise AutopilotError(
                    f"Cannot claim {unit_key}: {scope.pending_cnt} pending external_ops in scope {scope.scope_units}"
                )

            urow = self._conn.execute("SELECT * FROM work_units WHERE unit_key = ?", (unit_key,)).fetchone()
            if urow is None:
                raise AutopilotError(f"Unknown unit_key: {unit_key}")
            if urow["project_id"] and str(urow["project_id"]) != str(cfg.project_id):
                raise ScopeConflictError(
                    f"Unit {unit_key} belongs to project {urow['project_id']!r}, cannot claim under {cfg.project_id!r}"
                )
            if urow["terminal_state"] in ("done", "needs-human"):
                raise AutopilotError(f"Cannot claim terminal unit {unit_key} ({urow['terminal_state']})")
            if urow["status"] == "running" or (cfg.kind == "issue" and urow["status"] == "published"):
                raise AutopilotError(f"Cannot claim unit {unit_key} already in status={urow['status']!r}")
            if urow["waiting_until"] and str(urow["waiting_until"]) > now_iso():
                raise AutopilotError(f"Unit {unit_key} is waiting_quota/resource until {urow['waiting_until']}")

            prow = self._conn.execute(
                "SELECT max_in_progress, current_step_idx, enabled FROM projects WHERE project_id = ?",
                (cfg.project_id,),
            ).fetchone()
            if prow is not None and not int(prow["enabled"]):
                raise AutopilotError(f"Project {cfg.project_id} is disabled")
            if prow is not None:
                cap = int(prow["max_in_progress"]) if int(prow["current_step_idx"]) > 0 else min(cfg.max_in_progress, int(prow["max_in_progress"]))
            else:
                cap = cfg.max_in_progress
            active_claims = self._conn.execute(
                "SELECT COUNT(*) AS c FROM run_claims WHERE project_id = ? AND state IN ('active', 'reclaiming')",
                (cfg.project_id,),
            ).fetchone()["c"]
            if int(active_claims) >= cap:
                raise AutopilotError(f"WIP limit reached for {cfg.project_id}: {active_claims}/{cap}")
            if cfg.kind in HEAVY_UNIT_KINDS:
                g_cap = load_global_limits().max_global_in_progress
                g_active = count_global_heavy_claims(self._conn)
                if g_active >= g_cap:
                    raise AutopilotError(f"Global WIP limit reached across projects: {g_active}/{g_cap}")

            if cfg.max_per_day > 0:
                day_start_iso = now_utc().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
                today_claims = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM run_claims WHERE project_id = ? AND created_at >= ?",
                    (cfg.project_id, day_start_iso),
                ).fetchone()["c"]
                if int(today_claims) >= cfg.max_per_day:
                    raise AutopilotError(f"Daily run cap reached for {cfg.project_id}: {today_claims}/{cfg.max_per_day}")

            ordered_slots = sorted(set(slot_keys))
            s_marks = ",".join("?" for _ in ordered_slots)
            lrows = self._conn.execute(
                f"SELECT slot_key, state FROM leases WHERE slot_key IN ({s_marks})",
                ordered_slots,
            ).fetchall()
            if len(lrows) != len(ordered_slots):
                raise AutopilotError(f"Missing lease slot definition among {ordered_slots}")
            busy = [r["slot_key"] for r in lrows if r["state"] != "free"]
            if busy:
                raise AutopilotError(f"Physical lease vector busy on slots: {busy}")

            if run_dir_dev is None and run_dir_ino is None and run_dir:
                import os as _os
                with contextlib.suppress(OSError, AutopilotError):
                    _rfd = open_dir_nofollow(Path(run_dir), create=False)
                    try:
                        _rst = _os.fstat(_rfd)
                        run_dir_dev = int(_rst.st_dev)
                        run_dir_ino = int(_rst.st_ino)
                    finally:
                        _os.close(_rfd)

            rd_state = "bound" if (run_dir_dev is not None and run_dir_ino is not None) else "uncreated"
            claim_epoch = self._next_counter_in_tx("claim_epoch")
            ts = now_iso()
            self._conn.execute(
                """
                INSERT INTO run_claims(
                    claim_epoch, unit_key, project_id, repo, slot_vector_json, worker_unit_name,
                    expected_cgroup_dir, base_sha, authorized_base_ref, authorized_head_ref,
                    policy_version, effective_tier, frozen_write_scope_json, frozen_merge_paths_json,
                    frozen_approved_protected_paths_json,
                    merge_method, unit_kind, run_dir, run_dir_dev, run_dir_ino, run_dir_state, cred_ledger_tracked, worktree_path, managed_gitdir,
                    frozen_cache_dir, frozen_cache_dev, frozen_cache_ino, path_recorded,
                    bound_gh_login, ephemeral_token_file, state, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, ?, ?, ?, ?, ?, 1, ?, ?, 'active', ?)
                """,
                (
                    claim_epoch,
                    unit_key,
                    cfg.project_id,
                    str(urow["repo"] or ""),
                    json.dumps(ordered_slots),
                    worker_unit_name,
                    expected_cgroup_dir,
                    base_sha,
                    cfg.authorized_base_ref,
                    authorized_head_ref,
                    cfg.policy_version or "inline",
                    cfg.trust_tier,
                    json.dumps(list(cfg.write_scope)),
                    json.dumps(list(cfg.merge_paths)),
                    str(urow["approved_protected_paths_json"] or "[]"),
                    cfg.merge_method,
                    cfg.kind,
                    run_dir,
                    run_dir_dev,
                    run_dir_ino,
                    rd_state,
                    worktree_path,
                    managed_gitdir,
                    frozen_cache_dir,
                    frozen_cache_dev,
                    frozen_cache_ino,
                    bound_gh_login,
                    ephemeral_token_file,
                    ts,
                ),
            )
            self._conn.execute(
                f"""
                UPDATE leases
                SET state = 'active', claim_epoch = ?, unit_key = ?, worker_unit_name = ?,
                    expected_cgroup_dir = ?, updated_at = ?
                WHERE slot_key IN ({s_marks}) AND state = 'free'
                """,
                (claim_epoch, unit_key, worker_unit_name, expected_cgroup_dir, ts, *ordered_slots),
            )
            self._conn.execute(
                "UPDATE work_units SET status = 'running', waiting_until = NULL, updated_at = ? WHERE unit_key = ?",
                (ts, unit_key),
            )
            return claim_epoch

    def record_claim_outcome(self, claim_epoch: int, outcome: str) -> None:
        with self.immediate_tx():
            self._conn.execute(
                "UPDATE run_claims SET outcome = ? WHERE claim_epoch = ?",
                (outcome, claim_epoch),
            )

    def get_project_row(self, project_id: str) -> dict[str, Any] | None:
        with self._lock:
            r = self._conn.execute("SELECT * FROM projects WHERE project_id = ?", (project_id,)).fetchone()
            return dict(r) if r else None

    # --- Entrypoint 4: set_current_candidate ---
    def set_current_candidate(self, *, unit_key: str, candidate_sha: str, claim_epoch: int) -> None:
        if not candidate_sha or len(candidate_sha) < 7:
            raise AutopilotError(f"Invalid candidate_sha: {candidate_sha!r}")
        with self.immediate_tx():
            crow = self._conn.execute(
                "SELECT state, unit_key FROM run_claims WHERE claim_epoch = ?",
                (claim_epoch,),
            ).fetchone()
            if crow is None or crow["state"] != "active" or crow["unit_key"] != unit_key:
                raise AutopilotError(f"Inactive or mismatched claim_epoch={claim_epoch} for {unit_key}")

            scope = self.resolve_unit_scope_and_pending(
                unit_key,
                pr_id=None,
                statuses=PENDING_OP_STATUSES,
                exclude_self_worker_prepared=True,
            )
            if scope.any_veto != 0:
                raise AutopilotError(f"Cannot switch candidate on {unit_key}: veto_pending=1")
            if scope.pending_cnt != 0:
                raise AutopilotError(
                    f"Cannot switch candidate on {unit_key}: {scope.pending_cnt} blocking ops in scope {scope.scope_units}"
                )

            ts = now_iso()
            op_seq = self._next_counter_in_tx("op_seq")
            self._conn.execute(
                """
                UPDATE external_ops
                SET status = 'aborted_pre_send', op_seq = ?, updated_at = ?
                WHERE unit_key = ? AND owner_kind = 'worker' AND status = 'prepared_local'
                """,
                (op_seq, ts, unit_key),
            )
            self._conn.execute(
                "UPDATE work_units SET current_candidate_sha = ?, updated_at = ? WHERE unit_key = ?",
                (candidate_sha, ts, unit_key),
            )

    def _check_t3_and_ready_prereqs_in_tx(
        self,
        *,
        unit_key: str,
        eff_pr_id: str | None,
        candidate_sha: str,
        effective_tier: str,
        frozen_merge_paths_json: str,
    ) -> None:
        if not eff_pr_id:
            raise AutopilotError("enqueue_pr/merge_pr requires bound eff_pr_id")
        ready_row = self._conn.execute(
            """
            SELECT op_id FROM external_ops
            WHERE unit_key = ? AND pr_id = ? AND candidate_sha = ?
              AND op_type = 'mark_pr_ready' AND status = 'succeeded_verified'
            LIMIT 1
            """,
            (unit_key, eff_pr_id, candidate_sha),
        ).fetchone()
        if ready_row is None:
            raise AutopilotError(
                f"enqueue_pr/merge_pr requires succeeded_verified mark_pr_ready for ({unit_key}, {eff_pr_id}, {candidate_sha})"
            )
        if effective_tier == "T3":
            merge_paths = json.loads(frozen_merge_paths_json or "[]")
            if not merge_paths:
                raise AutopilotError("T3 enqueue_pr/merge_pr requires non-empty frozen merge_paths")
            vrow = self._conn.execute(
                "SELECT touched_paths_json FROM verify_receipts WHERE unit_key = ? AND candidate_sha = ?",
                (unit_key, candidate_sha),
            ).fetchone()
            touched = json.loads(vrow["touched_paths_json"] or "[]") if vrow else []
            if not touched:
                raise AutopilotError("T3 enqueue_pr/merge_pr requires non-empty verified touched_paths")
            ok_m, viol_m = _cd.check_scope(list(touched), list(merge_paths), [])
            if not ok_m:
                raise AutopilotError(f"T3 merge_paths gate rejected files: {viol_m}")

    # --- Entrypoint 2: prepare_op (worker) ---
    def prepare_op(
        self,
        *,
        unit_key: str,
        op_type: str,
        claim_epoch: int,
        pr_id: str | None = None,
        candidate_sha: str | None = None,
        ref_id_hmac: str | None = None,
        payload: dict[str, Any] | None = None,
        op_id: str | None = None,
    ) -> str:
        if op_type not in ACTION_TYPES or op_type in SUPERVISOR_ADMIN_ACTIONS:
            raise AutopilotError(f"Invalid worker op_type: {op_type!r}")

        with self.immediate_tx():
            crow = self._conn.execute(
                "SELECT * FROM run_claims WHERE claim_epoch = ? AND unit_key = ? AND state = 'active'",
                (claim_epoch, unit_key),
            ).fetchone()
            if crow is None:
                raise AutopilotError(f"No active run_claim(claim_epoch={claim_epoch}) for {unit_key}")
            if not str(crow["bound_gh_login"] or "").strip() or not str(crow["ephemeral_token_file"] or "").strip():
                raise AutopilotError(
                    f"Legacy active claim_epoch={claim_epoch} missing bound_gh_login or ephemeral_token_file; refusing new worker write"
                )
            ok_int, _, int_reason = self._inspect_scope_integrity_in_tx(unit_key, pr_id=pr_id)
            if not ok_int:
                raise ScopeConflictError(int_reason)

            allowed_tier_actions = POLICY_MANIFEST["trust_tier_actions"][crow["effective_tier"]]
            if op_type not in allowed_tier_actions:
                raise AutopilotError(
                    f"Action {op_type!r} forbidden under frozen effective_tier={crow['effective_tier']!r}"
                )

            scope = self.resolve_unit_scope_and_pending(
                unit_key,
                pr_id=pr_id,
                statuses=PENDING_OP_STATUSES,
                bind_pr_if_unset=True,
            )
            if scope.any_veto != 0:
                raise AutopilotError(f"Cannot prepare {op_type}: veto_pending=1 in scope {scope.scope_units}")
            if scope.pending_cnt != 0:
                raise AutopilotError(
                    f"Cannot prepare {op_type}: {scope.pending_cnt} pending ops in scope {scope.scope_units}"
                )

            urow = self._conn.execute("SELECT * FROM work_units WHERE unit_key = ?", (unit_key,)).fetchone()
            assert urow is not None
            eff_cand = candidate_sha if candidate_sha is not None else urow["current_candidate_sha"]

            # Require authoritative bound PR on PR-targeting worker actions; NEVER accept unbound payload pullRequestId!
            pl = dict(payload or {})
            if op_type in ("mark_pr_ready", "enqueue_pr", "merge_pr") and scope.eff_pr_id is None:
                raise AutopilotError(f"{op_type} requires an authoritative bound pr_id on scope")
            if scope.eff_pr_id is None and pl.get("pullRequestId") is not None:
                raise AutopilotError("prepare_op rejected caller-supplied pullRequestId without bound pr_id")
            for pkey, auth_v in (
                ("pullRequestId", scope.eff_pr_id),
                ("subjectId", scope.eff_pr_id),
                ("labelableId", scope.eff_pr_id),
                ("baseRefName", crow["authorized_base_ref"]),
                ("headRefName", crow["authorized_head_ref"]),
                ("expectedHeadOid", eff_cand),
                ("expected_old_oid", urow["last_confirmed_head_oid"]),
            ):
                if auth_v is not None and pkey in pl and pl[pkey] is not None and str(pl[pkey]) != str(auth_v):
                    raise AutopilotError(
                        f"prepare_op rejected conflicting payload[{pkey!r}]={pl[pkey]!r} != {auth_v!r}"
                    )

            if op_type in CANDIDATE_BOUND_WORKER_ACTIONS:
                if not eff_cand or eff_cand != urow["current_candidate_sha"]:
                    raise AutopilotError(
                        f"{op_type} requires candidate_sha matching current_candidate_sha={urow['current_candidate_sha']!r}"
                    )
                self._verify_publish_receipts_in_tx(unit_key, str(eff_cand))
                if op_type in ("enqueue_pr", "merge_pr"):
                    self._check_t3_and_ready_prereqs_in_tx(
                        unit_key=unit_key,
                        eff_pr_id=scope.eff_pr_id,
                        candidate_sha=str(eff_cand),
                        effective_tier=str(crow["effective_tier"]),
                        frozen_merge_paths_json=str(crow["frozen_merge_paths_json"]),
                    )

            new_id = op_id or f"op-{uuid.uuid4().hex[:16]}"
            seq = self._next_counter_in_tx("op_seq")
            ts = now_iso()
            self._conn.execute(
                """
                INSERT INTO external_ops(
                    op_id, op_seq, unit_key, project_id, pr_id, op_type, owner_kind, owner_epoch, claim_epoch,
                    candidate_sha, authorized_base_ref, authorized_head_ref, ref_id_hmac, payload_json,
                    status, send_consumed, prepared_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'worker', ?, ?, ?, ?, ?, ?, ?, 'prepared_local', 0, ?, ?)
                """,
                (
                    new_id,
                    seq,
                    unit_key,
                    str(crow["project_id"] or ""),
                    scope.eff_pr_id,
                    op_type,
                    claim_epoch,
                    claim_epoch,
                    eff_cand,
                    crow["authorized_base_ref"],
                    crow["authorized_head_ref"],
                    ref_id_hmac,
                    json.dumps(pl, ensure_ascii=False),
                    ts,
                    ts,
                ),
            )
            return new_id

    # --- Entrypoint 3: promote_op_to_in_flight ---
    def promote_op_to_in_flight(
        self,
        op_id: str,
        *,
        caller_owner_kind: str,
        caller_epoch: int,
        dispatcher_lock_held: bool = False,
        all_scope_workers_terminated: bool = False,
    ) -> SendGrant:
        if caller_owner_kind not in ("worker", "supervisor_admin"):
            raise AutopilotError(f"Invalid caller_owner_kind: {caller_owner_kind!r}")

        with self.immediate_tx():
            row = self._conn.execute("SELECT * FROM external_ops WHERE op_id = ?", (op_id,)).fetchone()
            if row is None:
                return SendGrant(False, op_id, "", caller_owner_kind, caller_epoch)
            if row["status"] != "prepared_local" or row["owner_kind"] != caller_owner_kind:
                return SendGrant(
                    False,
                    op_id,
                    str(row["op_type"]),
                    str(row["owner_kind"]),
                    int(row["owner_epoch"]),
                    unit_key=str(row["unit_key"]),
                    pr_id=row["pr_id"],
                )

            unit_key = str(row["unit_key"])
            op_type = str(row["op_type"])
            ok_int, _, _ = self._inspect_scope_integrity_in_tx(unit_key, pr_id=row["pr_id"])
            if not ok_int:
                return SendGrant(False, op_id, op_type, caller_owner_kind, caller_epoch, unit_key=unit_key, pr_id=row["pr_id"])
            scope = self.resolve_unit_scope_and_pending(
                unit_key,
                pr_id=row["pr_id"],
                statuses=PENDING_OP_STATUSES,
                exclude_op_id=op_id,
            )

            if caller_owner_kind == "worker":
                crow = self._conn.execute(
                    "SELECT state, effective_tier, frozen_merge_paths_json, bound_gh_login, ephemeral_token_file FROM run_claims WHERE claim_epoch = ? AND unit_key = ?",
                    (caller_epoch, unit_key),
                ).fetchone()
                urow = self._conn.execute(
                    "SELECT current_candidate_sha FROM work_units WHERE unit_key = ?",
                    (unit_key,),
                ).fetchone()
                if (
                    crow is None
                    or crow["state"] != "active"
                    or int(row["claim_epoch"] or -1) != caller_epoch
                    or not str(crow["bound_gh_login"] or "").strip()
                    or not str(crow["ephemeral_token_file"] or "").strip()
                    or scope.any_veto != 0
                    or scope.pending_cnt != 0
                ):
                    return SendGrant(False, op_id, op_type, caller_owner_kind, caller_epoch, unit_key=unit_key)
                if op_type in CANDIDATE_BOUND_WORKER_ACTIONS:
                    if not urow or urow["current_candidate_sha"] != row["candidate_sha"]:
                        return SendGrant(False, op_id, op_type, caller_owner_kind, caller_epoch, unit_key=unit_key)
                    if op_type in ("enqueue_pr", "merge_pr"):
                        try:
                            self._check_t3_and_ready_prereqs_in_tx(
                                unit_key=unit_key,
                                eff_pr_id=scope.eff_pr_id,
                                candidate_sha=str(row["candidate_sha"]),
                                effective_tier=str(crow["effective_tier"]),
                                frozen_merge_paths_json=str(crow["frozen_merge_paths_json"]),
                            )
                        except AutopilotError:
                            return SendGrant(False, op_id, op_type, caller_owner_kind, caller_epoch, unit_key=unit_key)
            else:
                cur_disp = self.get_dispatcher_epoch()
                if (
                    not dispatcher_lock_held
                    or caller_epoch != cur_disp
                    or int(row["owner_epoch"]) != cur_disp
                    or scope.any_veto != 1
                    or not all_scope_workers_terminated
                ):
                    return SendGrant(False, op_id, op_type, caller_owner_kind, caller_epoch, unit_key=unit_key)
                u_marks = ",".join("?" for _ in scope.scope_units)
                inflight_cnt = self._conn.execute(
                    f"""
                    SELECT COUNT(*) AS c FROM external_ops
                    WHERE op_id != ?
                      AND (unit_key IN ({u_marks}) OR (? IS NOT NULL AND pr_id = ?))
                      AND status = 'in_flight'
                    """,
                    (op_id, *scope.scope_units, scope.eff_pr_id, scope.eff_pr_id),
                ).fetchone()["c"]
                same_type_unknown = self._conn.execute(
                    f"""
                    SELECT COUNT(*) AS c FROM external_ops
                    WHERE op_id != ?
                      AND op_type = ?
                      AND (unit_key IN ({u_marks}) OR (? IS NOT NULL AND pr_id = ?))
                      AND status = 'unknown_paused'
                    """,
                    (op_id, op_type, *scope.scope_units, scope.eff_pr_id, scope.eff_pr_id),
                ).fetchone()["c"]
                if int(inflight_cnt) != 0 or int(same_type_unknown) != 0:
                    return SendGrant(False, op_id, op_type, caller_owner_kind, caller_epoch, unit_key=unit_key)

            seq = self._next_counter_in_tx("op_seq")
            ts = now_iso()
            gtok = uuid.uuid4().hex
            cur = self._conn.execute(
                """
                UPDATE external_ops
                SET status = 'in_flight', grant_token = ?, send_consumed = 0, op_seq = ?, updated_at = ?
                WHERE op_id = ? AND status = 'prepared_local' AND owner_kind = ? AND owner_epoch = ?
                """,
                (gtok, seq, ts, op_id, caller_owner_kind, caller_epoch),
            )
            granted = cur.rowcount == 1
            return SendGrant(
                granted=granted,
                op_id=op_id,
                op_type=op_type,
                owner_kind=caller_owner_kind,
                owner_epoch=caller_epoch,
                grant_token=gtok if granted else "",
                unit_key=unit_key,
                pr_id=scope.eff_pr_id or row["pr_id"],
                candidate_sha=row["candidate_sha"],
                authorized_base_ref=row["authorized_base_ref"],
                authorized_head_ref=row["authorized_head_ref"],
                ref_id_hmac=row["ref_id_hmac"],
                op_seq=seq if granted else int(row["op_seq"]),
            )

    def consume_send_grant(self, grant: SendGrant) -> bool:
        """Atomically re-verify scope integrity & consume one-shot SendGrant BEFORE pre-send checks or network transmission."""
        if not grant.granted or not grant.grant_token:
            return False
        conflict_reason: str | None = None
        consumed_ok = False
        with self.immediate_tx():
            row = self._conn.execute(
                "SELECT * FROM external_ops WHERE op_id = ? AND status = 'in_flight' AND send_consumed = 0 AND grant_token = ?",
                (grant.op_id, grant.grant_token),
            ).fetchone()
            if row is None:
                return False
            ok_int, conn_units, int_reason = self._inspect_scope_integrity_in_tx(
                str(row["unit_key"]), pr_id=row["pr_id"]
            )
            if not ok_int:
                # Commit the unsent settlement (`send_consumed=0`) & quarantine BEFORE raising ScopeConflictError outside `immediate_tx`!
                ts = now_iso()
                seq = self._next_counter_in_tx("op_seq")
                settled_st = "not_executed" if row["owner_kind"] == "worker" else "unknown_paused"
                self._conn.execute(
                    """
                    UPDATE external_ops
                    SET status = ?, unsent_proof = 'scope_integrity_conflict_pre_send',
                        error_detail = ?, grant_token = '', op_seq = ?, updated_at = ?
                    WHERE op_id = ? AND status = 'in_flight' AND send_consumed = 0
                    """,
                    (settled_st, int_reason, seq, ts, grant.op_id),
                )
                targets = conn_units or (str(row["unit_key"]),)
                um = ",".join("?" for _ in targets)
                self._conn.execute(
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
                    (f"quarantined_on_send_consume: {int_reason}", ts, *targets),
                )
                conflict_reason = int_reason
            else:
                seq = self._next_counter_in_tx("op_seq")
                cur = self._conn.execute(
                    """
                    UPDATE external_ops
                    SET send_consumed = 1, op_seq = ?, updated_at = ?
                    WHERE op_id = ? AND status = 'in_flight' AND send_consumed = 0 AND grant_token = ?
                    """,
                    (seq, now_iso(), grant.op_id, grant.grant_token),
                )
                consumed_ok = cur.rowcount == 1
        if conflict_reason is not None:
            raise ScopeConflictError(f"Aborted send grant consumption due to scope conflict: {conflict_reason}")
        return consumed_ok

    def register_admin_revoke(
        self,
        *,
        unit_key: str,
        dispatcher_epoch: int,
        pr_id: str | None = None,
        need_dequeue: bool = False,
        need_disable_automerge: bool = False,
        need_draft: bool = False,
        remote_sync_pending: bool = False,
        terminal_state: str | None = "needs-human",
        reason: str = "admin_revoke",
    ) -> list[str]:
        """Atomically set veto_pending=1 across scope, abort worker prepared_local, and register per-flag single-mutation ops."""
        with self.immediate_tx():
            scope = self.resolve_unit_scope_and_pending(
                unit_key,
                pr_id=pr_id,
                statuses=PENDING_OP_STATUSES,
                bind_pr_if_unset=True,
            )
            u_marks = ",".join("?" for _ in scope.scope_units)
            ts = now_iso()
            sync_val = 1 if remote_sync_pending else 0
            if terminal_state:
                self._conn.execute(
                    f"""
                    UPDATE work_units
                    SET veto_pending = 1,
                        veto_remote_sync_pending = CASE WHEN ? = 1 THEN 1 ELSE veto_remote_sync_pending END,
                        status = 'paused',
                        terminal_state = ?,
                        pause_reason_kind = COALESCE(pause_reason_kind, 'veto'),
                        last_error = ?,
                        updated_at = ?
                    WHERE unit_key IN ({u_marks})
                    """,
                    (sync_val, terminal_state, reason, ts, *scope.scope_units),
                )
            else:
                self._conn.execute(
                    f"""
                    UPDATE work_units
                    SET veto_pending = 1,
                        veto_remote_sync_pending = CASE WHEN ? = 1 THEN 1 ELSE veto_remote_sync_pending END,
                        status = 'paused',
                        pause_reason_kind = COALESCE(pause_reason_kind, 'veto'),
                        last_error = ?,
                        updated_at = ?
                    WHERE unit_key IN ({u_marks})
                    """,
                    (sync_val, reason, ts, *scope.scope_units),
                )

            seq_abort = self._next_counter_in_tx("op_seq")
            self._conn.execute(
                f"""
                UPDATE external_ops
                SET status = 'aborted_pre_send', op_seq = ?, updated_at = ?
                WHERE owner_kind = 'worker'
                  AND status = 'prepared_local'
                  AND (unit_key IN ({u_marks}) OR (? IS NOT NULL AND pr_id = ?))
                """,
                (seq_abort, ts, *scope.scope_units, scope.eff_pr_id, scope.eff_pr_id),
            )

            requested_actions: list[str] = []
            if need_dequeue:
                requested_actions.append("dequeue_pr")
            if need_disable_automerge:
                requested_actions.append("disable_pr_automerge")
            if need_draft:
                requested_actions.append("convert_pr_to_draft")

            urow_adm = self._conn.execute("SELECT project_id FROM work_units WHERE unit_key = ?", (unit_key,)).fetchone()
            adm_pid = str(urow_adm["project_id"] or "") if urow_adm else ""
            created_ids: list[str] = []
            for act in requested_actions:
                if not scope.eff_pr_id:
                    raise AutopilotError(f"Admin action {act} requires non-null eff_pr_id")
                existing = self._conn.execute(
                    f"""
                    SELECT op_id FROM external_ops
                    WHERE op_type = ?
                      AND owner_kind = 'supervisor_admin'
                      AND status IN ('prepared_local', 'in_flight', 'unknown_paused')
                      AND (unit_key IN ({u_marks}) OR pr_id = ?)
                    """,
                    (act, *scope.scope_units, scope.eff_pr_id),
                ).fetchone()
                if existing is not None:
                    continue
                new_id = f"op-adm-{uuid.uuid4().hex[:14]}"
                seq = self._next_counter_in_tx("op_seq")
                self._conn.execute(
                    """
                    INSERT INTO external_ops(
                        op_id, op_seq, unit_key, project_id, pr_id, op_type, owner_kind, owner_epoch,
                        payload_json, status, send_consumed, prepared_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'supervisor_admin', ?, ?, 'prepared_local', 0, ?, ?)
                    """,
                    (new_id, seq, unit_key, adm_pid, scope.eff_pr_id, act, dispatcher_epoch, json.dumps({"reason": reason}), ts, ts),
                )
                created_ids.append(new_id)
            return created_ids

    def mark_veto_remote_synced(self, unit_key: str) -> None:
        with self.immediate_tx():
            scope = self.resolve_unit_scope_and_pending(unit_key)
            u_marks = ",".join("?" for _ in scope.scope_units)
            self._conn.execute(
                f"UPDATE work_units SET veto_remote_sync_pending = 0, updated_at = ? WHERE unit_key IN ({u_marks})",
                (now_iso(), *scope.scope_units),
            )

    def replace_admin_op_for_retry(
        self,
        *,
        old_op_id: str,
        new_dispatcher_epoch: int,
        dispatcher_lock_held: bool,
    ) -> str:
        """Retire an old-epoch prepared_local (or proven-unsent / unconsumed in_flight/unknown_paused) and create a new prepared_local."""
        if not dispatcher_lock_held:
            raise AutopilotError("replace_admin_op_for_retry requires holding dispatcher.lock")
        with self.immediate_tx():
            cur_disp = self.get_dispatcher_epoch()
            if new_dispatcher_epoch != cur_disp:
                raise AutopilotError(
                    f"new_dispatcher_epoch={new_dispatcher_epoch} != current_dispatcher_epoch={cur_disp}"
                )
            row = self._conn.execute("SELECT * FROM external_ops WHERE op_id = ?", (old_op_id,)).fetchone()
            if row is None or row["owner_kind"] != "supervisor_admin":
                raise AutopilotError(f"Admin op not found: {old_op_id!r}")
            ok_int, _, int_reason = self._inspect_scope_integrity_in_tx(str(row["unit_key"]), pr_id=row["pr_id"])
            if not ok_int:
                raise ScopeConflictError(int_reason)
            old_epoch = int(row["owner_epoch"])
            if new_dispatcher_epoch <= old_epoch:
                raise AutopilotError(
                    f"replace_admin_op_for_retry requires new_dispatcher_epoch ({new_dispatcher_epoch}) > row.owner_epoch ({old_epoch})"
                )
            old_status = str(row["status"])
            if old_status == "prepared_local":
                pass
            elif old_status in ("in_flight", "unknown_paused"):
                if not row["unsent_proof"] and int(row["send_consumed"]) != 0:
                    raise AutopilotError(
                        f"Cannot retry {old_op_id} ({old_status}) without persisted unsent_proof or send_consumed==0"
                    )
            else:
                raise AutopilotError(f"Cannot replace terminal admin op {old_op_id} in status={old_status!r}")

            new_id = f"op-adm-{uuid.uuid4().hex[:14]}"
            seq1 = self._next_counter_in_tx("op_seq")
            ts = now_iso()
            cur = self._conn.execute(
                """
                UPDATE external_ops
                SET status = 'superseded_by_retry', superseded_by_op_id = ?, op_seq = ?, updated_at = ?
                WHERE op_id = ? AND status = ? AND owner_epoch = ?
                """,
                (new_id, seq1, ts, old_op_id, old_status, old_epoch),
            )
            if cur.rowcount != 1:
                raise AutopilotError(f"Concurrent state change while retiring {old_op_id}")
            seq2 = self._next_counter_in_tx("op_seq")
            self._conn.execute(
                """
                INSERT INTO external_ops(
                    op_id, op_seq, unit_key, project_id, pr_id, op_type, owner_kind, owner_epoch,
                    payload_json, status, send_consumed, prepared_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'supervisor_admin', ?, ?, 'prepared_local', 0, ?, ?)
                """,
                (
                    new_id,
                    seq2,
                    row["unit_key"],
                    str(row["project_id"] or ""),
                    row["pr_id"],
                    row["op_type"],
                    new_dispatcher_epoch,
                    row["payload_json"],
                    ts,
                    ts,
                ),
            )
            return new_id

    # --- Entrypoint 5: clear_veto_and_resume ---
    def clear_veto_and_resume(
        self,
        unit_key: str,
        *,
        pr_snapshot: PrSnapshot | None = None,
    ) -> tuple[str, ...]:
        with self.immediate_tx():
            ok_int, _, int_reason = self._inspect_scope_integrity_in_tx(unit_key)
            if not ok_int:
                raise ScopeConflictError(f"Cannot clear veto while scope ownership/PR conflict remains: {int_reason}")
            scope = self.resolve_unit_scope_and_pending(unit_key, pr_id=None, statuses=PENDING_OP_STATUSES)
            if scope.any_veto != 1:
                raise AutopilotError(f"Cannot clear veto on {unit_key}: no active veto_pending in {scope.scope_units}")
            if scope.pending_cnt != 0:
                raise AutopilotError(
                    f"Cannot clear veto on {unit_key}: {scope.pending_cnt} pending ops remain in {scope.scope_units}"
                )
            u_marks = ",".join("?" for _ in scope.scope_units)
            sync_pend = self._conn.execute(
                f"SELECT COALESCE(MAX(veto_remote_sync_pending), 0) AS s FROM work_units WHERE unit_key IN ({u_marks})",
                scope.scope_units,
            ).fetchone()["s"]
            if int(sync_pend) != 0:
                raise AutopilotError(
                    f"Cannot clear veto on {unit_key}: initial remote PR revoke inspection still pending"
                )
            if scope.eff_pr_id is not None:
                if pr_snapshot is None:
                    raise AutopilotError(
                        f"clear_veto_and_resume on PR-bound unit {unit_key} ({scope.eff_pr_id}) requires live PrSnapshot"
                    )
                if pr_snapshot.pr_id != scope.eff_pr_id:
                    raise ScopeConflictError(
                        f"Snapshot pr_id={pr_snapshot.pr_id!r} != scope eff_pr_id={scope.eff_pr_id!r}"
                    )
                if pr_snapshot.snapshot_seq < scope.max_op_seq:
                    raise AutopilotError(
                        f"Stale unveto snapshot: snapshot_seq={pr_snapshot.snapshot_seq} < max_op_seq={scope.max_op_seq}"
                    )
                if (
                    pr_snapshot.state != "OPEN"
                    or pr_snapshot.is_draft is not True
                    or pr_snapshot.merge_queue_entry_id is not None
                    or pr_snapshot.auto_merge_enabled is not False
                ):
                    raise AutopilotError(
                        "Remote PR violated unveto quiescence invariant (require OPEN & isDraft=True & mergeQueueEntry=None & autoMerge=False)"
                    )

            ts = now_iso()
            self._conn.execute(
                f"""
                UPDATE work_units
                SET veto_pending = 0,
                    veto_remote_sync_pending = 0,
                    status = CASE
                        WHEN terminal_state = 'done' THEN status
                        WHEN pause_reason_kind = 'non_veto_escalation' THEN 'paused'
                        ELSE 'queued'
                    END,
                    terminal_state = CASE
                        WHEN terminal_state = 'needs-human' AND COALESCE(pause_reason_kind, 'veto') = 'veto' THEN NULL
                        ELSE terminal_state
                    END,
                    pause_reason_kind = CASE
                        WHEN COALESCE(pause_reason_kind, 'veto') = 'veto' THEN NULL
                        ELSE pause_reason_kind
                    END,
                    updated_at = ?
                WHERE unit_key IN ({u_marks})
                """,
                (ts, *scope.scope_units),
            )
            return scope.scope_units

    def approve_unit_protected_paths(
        self,
        unit_key: str,
        patterns: list[str] | tuple[str, ...],
    ) -> dict[str, Any]:
        """Grant operator-approved schema/migration path globs to one unit and resume only matching protected-path pauses."""
        import ast
        from .git_gate import is_path_covered_by_approved_protected, validate_approvable_protected_glob

        if not patterns:
            raise AutopilotError("approve-paths requires at least one --allow glob")
        validated = [validate_approvable_protected_glob(p) for p in patterns]
        with self.immediate_tx():
            ok_int, _, int_reason = self._inspect_scope_integrity_in_tx(unit_key)
            if not ok_int:
                raise ScopeConflictError(int_reason)
            scope = self.resolve_unit_scope_and_pending(unit_key, pr_id=None, statuses=PENDING_OP_STATUSES)
            if scope.any_veto != 0:
                raise AutopilotError(f"Cannot approve-paths on {unit_key}: veto_pending=1 in scope {scope.scope_units}")
            if scope.pending_cnt != 0:
                raise AutopilotError(
                    f"Cannot approve-paths on {unit_key}: {scope.pending_cnt} pending external_ops in scope {scope.scope_units}"
                )
            urow = self._conn.execute(
                "SELECT * FROM work_units WHERE unit_key = ?",
                (unit_key,),
            ).fetchone()
            if not urow:
                raise AutopilotError(f"Unknown unit_key: {unit_key}")
            if int(urow["scope_quarantined"]) != 0:
                raise ScopeConflictError(f"Cannot approve-paths on quarantined unit {unit_key}")
            if urow["terminal_state"] == "done":
                raise AutopilotError(f"Cannot approve-paths on completed unit {unit_key}")
            u_marks = ",".join("?" for _ in scope.scope_units)
            busy_claim = self._conn.execute(
                f"SELECT unit_key, claim_epoch, state FROM run_claims WHERE unit_key IN ({u_marks}) AND state IN ('active', 'reclaiming') LIMIT 1",
                scope.scope_units,
            ).fetchone()
            if busy_claim:
                raise AutopilotError(
                    f"Cannot approve-paths on {unit_key} while {busy_claim['unit_key']} claim_epoch={busy_claim['claim_epoch']} is {busy_claim['state']}"
                )

            existing = json.loads(str(urow["approved_protected_paths_json"] or "[]"))
            merged: list[str] = []
            for p in [*existing, *validated]:
                if p not in merged:
                    merged.append(p)

            raw_blocked = urow["blocked_protected_paths_json"]
            blocked_paths: list[str] = []
            if raw_blocked is not None:
                blocked_paths = [str(x) for x in json.loads(str(raw_blocked or "[]")) if str(x)]
            else:
                # Backward-compatible parse ONLY for pre-upgrade rows (blocked_protected_paths_json IS NULL).
                # Legacy errors truncated at 5 entries (`[:5]`), so fail closed if len(parsed) >= 5.
                prefix = "Change needs protected paths (human approval): "
                err_txt = str(urow["last_error"] or "")
                if err_txt.startswith(prefix):
                    with contextlib.suppress(SyntaxError, ValueError):
                        parsed = ast.literal_eval(err_txt[len(prefix):].strip())
                        if isinstance(parsed, list) and 0 < len(parsed) < 5:
                            suffix = " (matches global_hard_stop_anchored)"
                            for item in parsed:
                                s = str(item)
                                if s.endswith(suffix):
                                    blocked_paths.append(s[: -len(suffix)])
                                else:
                                    blocked_paths = []
                                    break

            resumed = (
                urow["status"] == "paused"
                and urow["terminal_state"] == "needs-human"
                and urow["pause_reason_kind"] == "non_veto_escalation"
                and bool(blocked_paths)
                and all(is_path_covered_by_approved_protected(bp, merged) for bp in blocked_paths)
            )
            ts = now_iso()
            if resumed:
                self._conn.execute(
                    """
                    UPDATE work_units
                    SET approved_protected_paths_json = ?,
                        blocked_protected_paths_json = '[]',
                        status = 'queued',
                        terminal_state = NULL,
                        pause_reason_kind = NULL,
                        waiting_until = NULL,
                        failure_streak = 0,
                        review_rounds_used = 0,
                        last_error = NULL,
                        updated_at = ?
                    WHERE unit_key = ?
                    """,
                    (json.dumps(merged), ts, unit_key),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE work_units
                    SET approved_protected_paths_json = ?,
                        updated_at = ?
                    WHERE unit_key = ?
                    """,
                    (json.dumps(merged), ts, unit_key),
                )
            return {
                "unit_key": unit_key,
                "approved_protected_paths": merged,
                "resumed": resumed,
            }

    def operator_resolve_op(
        self,
        op_id: str,
        *,
        new_status: str,
        sender_confirmed_terminated: bool,
        receipt_id: str | None = None,
        unsent_proof: str | None = None,
    ) -> dict[str, Any]:
        """Operator resolution requiring confirmed sender termination + evidence-backed terminal status."""
        if not sender_confirmed_terminated:
            raise AutopilotError(f"Refusing resolve-op on {op_id}: original sender is not confirmed terminated")
        if new_status not in OPERATOR_RESOLVABLE_TERMINAL_STATUSES:
            raise AutopilotError(
                f"resolve-op only permits terminal statuses {sorted(OPERATOR_RESOLVABLE_TERMINAL_STATUSES)}, got {new_status!r}"
            )
        if new_status in ("succeeded_verified", "merged_before_revoke", "diverged_needs_human") and not receipt_id:
            raise AutopilotError(f"resolve-op to {new_status} requires --receipt-id")
        if new_status == "not_executed" and not unsent_proof:
            raise AutopilotError("resolve-op to not_executed requires --unsent-proof")
        return self.complete_op_status(
            op_id,
            expected_current_statuses=("unknown_paused", "in_flight"),
            new_status=new_status,
            remote_receipt_id=receipt_id,
            unsent_proof=unsent_proof,
            error_detail="operator_resolved",
        )

    def _quarantine_pr_receipt_conflict_in_tx(
        self,
        *,
        op_id: str,
        unit_key: str,
        conflicting_pr_id: str,
        remote_receipt_id: str | None,
        reason: str,
    ) -> dict[str, Any]:
        """Persist conflict receipt on `op_id` WITHOUT creating a cross-project PR binding, and quarantine both sides!"""
        ts = now_iso()
        seq = self._next_counter_in_tx("op_seq")
        detail = f"conflicting_pr_id={conflicting_pr_id}: {reason}"
        self._conn.execute(
            """
            UPDATE external_ops
            SET status = 'diverged_needs_human',
                remote_receipt_id = COALESCE(?, remote_receipt_id),
                conflicting_pr_id = ?,
                error_detail = ?,
                op_seq = ?,
                updated_at = ?
            WHERE op_id = ?
            """,
            (remote_receipt_id or f"conflict:{conflicting_pr_id}", conflicting_pr_id, detail, seq, ts, op_id),
        )
        quarantined = {unit_key}
        for r in self._conn.execute("SELECT unit_key FROM work_units WHERE pr_id = ?", (conflicting_pr_id,)).fetchall():
            quarantined.add(str(r["unit_key"]))
        for r in self._conn.execute("SELECT DISTINCT unit_key FROM external_ops WHERE pr_id = ? OR conflicting_pr_id = ?", (conflicting_pr_id, conflicting_pr_id)).fetchall():
            quarantined.add(str(r["unit_key"]))
        um = ",".join("?" for _ in quarantined)
        self._conn.execute(
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
            (detail, ts, *sorted(quarantined)),
        )
        out = self._conn.execute("SELECT * FROM external_ops WHERE op_id = ?", (op_id,)).fetchone()
        assert out is not None
        res = dict(out)
        res["_updated"] = True
        res["_scope_quarantined"] = True
        return res

    def record_op_receipt(
        self,
        op_id: str,
        *,
        remote_receipt_id: str | None = None,
        unsent_proof: str | None = None,
        pr_id: str | None = None,
        pr_number: int | None = None,
        confirmed_head_oid: str | None = None,
        error_detail: str | None = None,
    ) -> dict[str, Any]:
        with self.immediate_tx():
            row = self._conn.execute("SELECT * FROM external_ops WHERE op_id = ?", (op_id,)).fetchone()
            if row is None:
                raise AutopilotError(f"Unknown op_id: {op_id}")
            if pr_id is not None:
                try:
                    self.resolve_unit_scope_and_pending(str(row["unit_key"]), pr_id=pr_id, bind_pr_if_unset=True)
                except ScopeConflictError as exc:
                    return self._quarantine_pr_receipt_conflict_in_tx(
                        op_id=op_id,
                        unit_key=str(row["unit_key"]),
                        conflicting_pr_id=pr_id,
                        remote_receipt_id=remote_receipt_id,
                        reason=str(exc),
                    )
                if pr_number is not None:
                    self._conn.execute(
                        "UPDATE work_units SET pr_number = COALESCE(?, pr_number) WHERE unit_key = ?",
                        (pr_number, row["unit_key"]),
                    )
            if confirmed_head_oid:
                self._conn.execute(
                    "UPDATE work_units SET last_confirmed_head_oid = ?, updated_at = ? WHERE unit_key = ?",
                    (confirmed_head_oid, now_iso(), row["unit_key"]),
                )
            seq = self._next_counter_in_tx("op_seq")
            ts = now_iso()
            self._conn.execute(
                """
                UPDATE external_ops
                SET remote_receipt_id = COALESCE(?, remote_receipt_id),
                    unsent_proof = COALESCE(?, unsent_proof),
                    pr_id = COALESCE(?, pr_id),
                    error_detail = COALESCE(?, error_detail),
                    op_seq = ?,
                    updated_at = ?
                WHERE op_id = ?
                """,
                (remote_receipt_id, unsent_proof, pr_id, error_detail, seq, ts, op_id),
            )
            out = self._conn.execute("SELECT * FROM external_ops WHERE op_id = ?", (op_id,)).fetchone()
            assert out is not None
            return dict(out)

    def complete_op_status(
        self,
        op_id: str,
        *,
        expected_current_statuses: tuple[str, ...],
        new_status: str,
        remote_receipt_id: str | None = None,
        unsent_proof: str | None = None,
        error_detail: str | None = None,
        pr_id: str | None = None,
        confirmed_head_oid: str | None = None,
    ) -> dict[str, Any]:
        if new_status not in EXTERNAL_OP_STATUSES:
            raise AutopilotError(f"Invalid external_op status: {new_status!r}")
        with self.immediate_tx():
            row = self._conn.execute("SELECT * FROM external_ops WHERE op_id = ?", (op_id,)).fetchone()
            if row is None:
                raise AutopilotError(f"Unknown op_id: {op_id}")
            if pr_id is not None:
                try:
                    self.resolve_unit_scope_and_pending(str(row["unit_key"]), pr_id=pr_id, bind_pr_if_unset=True)
                except ScopeConflictError as exc:
                    return self._quarantine_pr_receipt_conflict_in_tx(
                        op_id=op_id,
                        unit_key=str(row["unit_key"]),
                        conflicting_pr_id=pr_id,
                        remote_receipt_id=remote_receipt_id,
                        reason=str(exc),
                    )
            if confirmed_head_oid and new_status == "succeeded_verified":
                self._conn.execute(
                    "UPDATE work_units SET last_confirmed_head_oid = ?, updated_at = ? WHERE unit_key = ?",
                    (confirmed_head_oid, now_iso(), row["unit_key"]),
                )
            s_marks = ",".join("?" for _ in expected_current_statuses)
            seq = self._next_counter_in_tx("op_seq")
            ts = now_iso()
            cur = self._conn.execute(
                f"""
                UPDATE external_ops
                SET status = ?,
                    remote_receipt_id = COALESCE(?, remote_receipt_id),
                    unsent_proof = COALESCE(?, unsent_proof),
                    pr_id = COALESCE(?, pr_id),
                    error_detail = COALESCE(?, error_detail),
                    op_seq = ?,
                    updated_at = ?
                WHERE op_id = ? AND status IN ({s_marks})
                """,
                (new_status, remote_receipt_id, unsent_proof, pr_id, error_detail, seq, ts, op_id, *expected_current_statuses),
            )
            latest = self._conn.execute("SELECT * FROM external_ops WHERE op_id = ?", (op_id,)).fetchone()
            assert latest is not None
            res = dict(latest)
            res["_updated"] = cur.rowcount == 1
            return res

    def mark_unit_needs_human(
        self,
        unit_key: str,
        reason: str,
        *,
        non_veto: bool = True,
        blocked_protected_paths: list[str] | tuple[str, ...] = (),
    ) -> None:
        with self.immediate_tx():
            kind = "non_veto_escalation" if non_veto else "veto"
            self._conn.execute(
                """
                UPDATE work_units
                SET status = 'paused',
                    terminal_state = 'needs-human',
                    pause_reason_kind = ?,
                    last_error = ?,
                    blocked_protected_paths_json = ?,
                    updated_at = ?
                WHERE unit_key = ?
                """,
                (kind, reason, json.dumps(list(blocked_protected_paths)), now_iso(), unit_key),
            )

    def mark_unit_waiting_quota(
        self,
        unit_key: str,
        wake_at_iso: str,
        reason: str,
        *,
        refund_reserved_round: int | None = None,
    ) -> None:
        with self.immediate_tx():
            if refund_reserved_round is not None:
                self._conn.execute(
                    """
                    UPDATE work_units
                    SET status = 'waiting_quota',
                        waiting_until = ?,
                        last_error = ?,
                        review_rounds_used = CASE WHEN review_rounds_used = ? THEN MAX(0, review_rounds_used - 1) ELSE review_rounds_used END,
                        updated_at = ?
                    WHERE unit_key = ?
                    """,
                    (wake_at_iso, reason, int(refund_reserved_round), now_iso(), unit_key),
                )
            else:
                self._conn.execute(
                    "UPDATE work_units SET status = 'waiting_quota', waiting_until = ?, last_error = ?, updated_at = ? WHERE unit_key = ?",
                    (wake_at_iso, reason, now_iso(), unit_key),
                )

    def mark_unit_published(self, unit_key: str, *, duration_ms: int = 0) -> None:
        with self.immediate_tx():
            urow = self._conn.execute("SELECT project_id FROM work_units WHERE unit_key = ?", (unit_key,)).fetchone()
            if urow is None:
                return
            ts = now_iso()
            self._conn.execute(
                "UPDATE work_units SET status = 'published', failure_streak = 0, updated_at = ? WHERE unit_key = ?",
                (ts, unit_key),
            )
            self._conn.execute(
                "INSERT INTO run_history(run_id, project_id, unit_key, status, duration_ms, completed_at, matured_clean) VALUES (?, ?, ?, 'published', ?, ?, 0)",
                (f"run-{uuid.uuid4().hex[:14]}", urow["project_id"], unit_key, int(duration_ms), ts),
            )

    def mark_unit_done(self, unit_key: str) -> None:
        with self.immediate_tx():
            self._conn.execute(
                "UPDATE work_units SET status = 'done', terminal_state = 'done', failure_streak = 0, updated_at = ? WHERE unit_key = ?",
                (now_iso(), unit_key),
            )

    # --- 4-Phase Physical Lease Reclamation ---
    def begin_reclaim_claim(self, claim_epoch: int) -> dict[str, Any]:
        with self.immediate_tx():
            crow = self._conn.execute("SELECT * FROM run_claims WHERE claim_epoch = ?", (claim_epoch,)).fetchone()
            if crow is None:
                raise AutopilotError(f"Unknown claim_epoch={claim_epoch}")
            ts = now_iso()
            if crow["state"] == "active":
                self._conn.execute(
                    "UPDATE run_claims SET state = 'reclaiming' WHERE claim_epoch = ?",
                    (claim_epoch,),
                )
                self._conn.execute(
                    "UPDATE leases SET state = 'reclaiming', updated_at = ? WHERE claim_epoch = ?",
                    (ts, claim_epoch),
                )
            out = self._conn.execute("SELECT * FROM run_claims WHERE claim_epoch = ?", (claim_epoch,)).fetchone()
            assert out is not None
            return dict(out)

    def record_cleanup_unit(self, claim_epoch: int, cleanup_unit_name: str, cleanup_cgroup_dir: str) -> None:
        with self.immediate_tx():
            self._conn.execute(
                "UPDATE run_claims SET cleanup_unit_name = ?, cleanup_cgroup_dir = ? WHERE claim_epoch = ?",
                (cleanup_unit_name, cleanup_cgroup_dir, claim_epoch),
            )

    def finish_reclaim_leases_free(
        self,
        claim_epoch: int,
        *,
        cleanup_rc: int,
        unit_terminated: bool,
        worktree_clean: bool,
    ) -> bool:
        """Phase 4: Release physical leases to 'free' ONLY if cleanup_rc==0, unit_terminated, and worktree_clean."""
        if cleanup_rc != 0 or not unit_terminated or not worktree_clean:
            with self.immediate_tx():
                self.begin_reclaim_claim(claim_epoch)
            return False
        with self.immediate_tx():
            unpurged_cred = self._conn.execute(
                "SELECT 1 FROM claim_credential_dirs WHERE claim_epoch = ? AND purged = 0 LIMIT 1",
                (claim_epoch,),
            ).fetchone()
            if unpurged_cred is not None:
                self.begin_reclaim_claim(claim_epoch)
                return False
            crow = self._conn.execute("SELECT * FROM run_claims WHERE claim_epoch = ?", (claim_epoch,)).fetchone()
            if crow is None:
                return False
            ts = now_iso()
            seq = self._next_counter_in_tx("op_seq")
            self._conn.execute(
                """
                UPDATE external_ops
                SET status = 'aborted_pre_send', op_seq = ?, updated_at = ?
                WHERE claim_epoch = ? AND owner_kind = 'worker' AND status = 'prepared_local'
                """,
                (seq, ts, claim_epoch),
            )
            self._conn.execute(
                "UPDATE run_claims SET state = 'released', released_at = ? WHERE claim_epoch = ?",
                (ts, claim_epoch),
            )
            self._conn.execute(
                """
                UPDATE leases
                SET state = 'free', claim_epoch = NULL, unit_key = NULL,
                    worker_unit_name = NULL, expected_cgroup_dir = NULL, updated_at = ?
                WHERE claim_epoch = ?
                """,
                (ts, claim_epoch),
            )
            urow = self._conn.execute("SELECT * FROM work_units WHERE unit_key = ?", (crow["unit_key"],)).fetchone()
            if urow is not None and urow["status"] == "running":
                streak = int(urow["failure_streak"]) + 1
                if streak >= 3:
                    self._conn.execute(
                        "UPDATE work_units SET status = 'paused', terminal_state = 'needs-human', pause_reason_kind = 'non_veto_escalation', failure_streak = ?, last_error = COALESCE(last_error, 'max_retries_exceeded'), updated_at = ? WHERE unit_key = ?",
                        (streak, ts, crow["unit_key"]),
                    )
                else:
                    backoff_until = (now_utc() + dt.timedelta(seconds=30 * streak)).replace(microsecond=0).isoformat()
                    self._conn.execute(
                        "UPDATE work_units SET status = 'queued', failure_streak = ?, waiting_until = ?, updated_at = ? WHERE unit_key = ?",
                        (streak, backoff_until, ts, crow["unit_key"]),
                    )
            return True

    def record_verify_receipt(
        self,
        *,
        unit_key: str,
        candidate_sha: str,
        dod_cmd: str,
        exit_code: int,
        ui_verified: bool,
        artifact_dir: str,
        touched_paths: list[str] | tuple[str, ...] = (),
    ) -> None:
        with self.immediate_tx():
            self._conn.execute(
                """
                INSERT OR REPLACE INTO verify_receipts(
                    unit_key, candidate_sha, dod_cmd, exit_code, ui_verified, touched_paths_json, artifact_dir, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    unit_key,
                    candidate_sha,
                    dod_cmd,
                    int(exit_code),
                    int(ui_verified),
                    json.dumps(list(touched_paths)),
                    artifact_dir,
                    now_iso(),
                ),
            )

    def reserve_review_round(self, unit_key: str) -> int | None:
        max_rounds = int(POLICY_MANIFEST["chef_pipeline"]["max_review_rounds"])
        with self.immediate_tx():
            urow = self._conn.execute(
                "SELECT review_rounds_used FROM work_units WHERE unit_key = ?",
                (unit_key,),
            ).fetchone()
            if urow is None:
                raise AutopilotError(f"Unknown unit_key: {unit_key}")
            used = int(urow["review_rounds_used"])
            if used >= max_rounds:
                return None
            nxt = used + 1
            self._conn.execute(
                "UPDATE work_units SET review_rounds_used = ?, updated_at = ? WHERE unit_key = ?",
                (nxt, now_iso(), unit_key),
            )
            return nxt

    def record_review_receipt(
        self,
        *,
        unit_key: str,
        candidate_sha: str,
        writer_family: str,
        referee_family: str,
        referee_model: str,
        verdict: str,
        defect_count: int,
        defects: list[dict[str, str]],
        raw_path: str,
        reserved_round_index: int | None = None,
    ) -> int:
        expected_ref = resolve_cross_family_referee(writer_family)
        if referee_family != expected_ref:
            raise AutopilotError(
                f"Cross-family referee violation: writer={writer_family!r} requires referee={expected_ref!r}, got {referee_family!r}"
            )
        with self.immediate_tx():
            max_rounds = int(POLICY_MANIFEST["chef_pipeline"]["max_review_rounds"])
            if reserved_round_index is not None:
                round_idx = int(reserved_round_index)
            else:
                r = self.reserve_review_round(unit_key)
                if r is None:
                    raise AutopilotError(f"Exceeded max_review_rounds={max_rounds} on {unit_key}")
                round_idx = r
            if round_idx < 1 or round_idx > max_rounds:
                raise AutopilotError(f"Invalid review round_idx={round_idx} (max {max_rounds})")
            ts = now_iso()
            self._conn.execute(
                """
                INSERT INTO review_receipts(
                    unit_key, candidate_sha, round_index, writer_family, referee_family,
                    referee_model, verdict, defect_count, defects_json, raw_path, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    unit_key,
                    candidate_sha,
                    round_idx,
                    writer_family,
                    referee_family,
                    referee_model,
                    verdict,
                    int(defect_count),
                    json.dumps(defects, ensure_ascii=False),
                    raw_path,
                    ts,
                ),
            )
            return round_idx

    def _verify_publish_receipts_in_tx(self, unit_key: str, candidate_sha: str) -> None:
        if not POLICY_MANIFEST["chef_pipeline"]["publish_requires_current_candidate_verify_and_review_receipts"]:
            return
        vrow = self._conn.execute(
            "SELECT exit_code FROM verify_receipts WHERE unit_key = ? AND candidate_sha = ?",
            (unit_key, candidate_sha),
        ).fetchone()
        if vrow is None or int(vrow["exit_code"]) != 0:
            raise AutopilotError(
                f"Missing passing verify_receipts for ({unit_key}, {candidate_sha})"
            )
        rrow = self._conn.execute(
            """
            SELECT writer_family, referee_family, verdict, defect_count
            FROM review_receipts
            WHERE unit_key = ? AND candidate_sha = ? AND verdict = 'APPROVE' AND defect_count = 0
            ORDER BY round_index DESC LIMIT 1
            """,
            (unit_key, candidate_sha),
        ).fetchone()
        if rrow is None or rrow["writer_family"] == rrow["referee_family"]:
            raise AutopilotError(
                f"Missing cross-family APPROVE review_receipts for ({unit_key}, {candidate_sha})"
            )

    def get_op(self, op_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM external_ops WHERE op_id = ?", (op_id,)).fetchone()
            return dict(row) if row else None

    def get_unit(self, unit_key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM work_units WHERE unit_key = ?", (unit_key,)).fetchone()
            return dict(row) if row else None

    def get_claim(self, claim_epoch: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM run_claims WHERE claim_epoch = ?", (claim_epoch,)).fetchone()
            return dict(row) if row else None

    def list_ops_for_scope(self, unit_key: str) -> list[dict[str, Any]]:
        with self._lock:
            scope = self.resolve_unit_scope_and_pending(unit_key)
            u_marks = ",".join("?" for _ in scope.scope_units)
            rows = self._conn.execute(
                f"""
                SELECT * FROM external_ops
                WHERE unit_key IN ({u_marks}) OR (? IS NOT NULL AND pr_id = ?)
                ORDER BY op_seq ASC
                """,
                (*scope.scope_units, scope.eff_pr_id, scope.eff_pr_id),
            ).fetchall()
            return [dict(r) for r in rows]

    def record_pitfall(self, *, project_id: str, target_area: str, symptom: str, rule_text: str) -> dict[str, Any]:
        import hashlib as _hl

        max_len = int(POLICY_MANIFEST["chef_pipeline"]["max_pitfall_rule_chars"])
        clean_rule = " ".join(rule_text.split())[:max_len]
        clean_symptom = " ".join(symptom.split())[:max_len]
        sig = _hl.sha256(f"{target_area}|{clean_rule}".encode("utf-8")).hexdigest()[:16]
        with self.immediate_tx():
            ts = now_iso()
            row = self._conn.execute("SELECT hits FROM pitfalls WHERE sig = ?", (sig,)).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO pitfalls(sig, project_id, target_area, symptom, rule_text, hits, status, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 1, 'advisory', ?, ?)",
                    (sig, project_id, target_area, clean_symptom, clean_rule, ts, ts),
                )
            else:
                self._conn.execute(
                    "UPDATE pitfalls SET hits = hits + 1, updated_at = ? WHERE sig = ?",
                    (ts, sig),
                )
            out = self._conn.execute("SELECT * FROM pitfalls WHERE sig = ?", (sig,)).fetchone()
            assert out is not None
            return dict(out)

    def approve_concurrency_promotion(
        self,
        project_id: str,
        *,
        force: bool = False,
        target_cap: int | None = None,
    ) -> int:
        steps = POLICY_MANIFEST["chef_pipeline"]["staircase_concurrency_steps"]
        min_clean = int(POLICY_MANIFEST["chef_pipeline"]["staircase_min_clean_runs"])
        with self.immediate_tx():
            row = self._conn.execute("SELECT * FROM projects WHERE project_id = ?", (project_id,)).fetchone()
            if row is None:
                raise AutopilotError(f"Unknown project_id: {project_id}")
            if target_cap is not None and not force:
                raise AutopilotError("Explicit target concurrency override requires --force")
            if not force and int(row["clean_matured_runs"]) < min_clean:
                raise AutopilotError(
                    f"Project {project_id} has {row['clean_matured_runs']}/{min_clean} 48h-matured clean runs"
                )
            if target_cap is not None:
                if int(target_cap) not in steps:
                    raise AutopilotError(f"Invalid target concurrency {target_cap}; allowed steps: {steps}")
                next_idx = steps.index(int(target_cap))
                new_cap = int(target_cap)
            else:
                next_idx = min(int(row["current_step_idx"]) + 1, len(steps) - 1)
                new_cap = int(steps[next_idx])
            self._conn.execute(
                "UPDATE projects SET current_step_idx = ?, max_in_progress = ?, clean_matured_runs = 0, updated_at = ? WHERE project_id = ?",
                (next_idx, new_cap, now_iso(), project_id),
            )
            return new_cap
