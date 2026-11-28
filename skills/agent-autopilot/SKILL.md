---
name: agent-autopilot
description: >-
  Universal 24x7 self-evolving autonomous issue-fixing and scheduled routine engine (`agent-autopilot`)
  with zero-token precheck probes, multi-ring bwrap + Landlock sandboxes, cross-family Claude <-> Codex
  referee loops, executable DoD gates, and single-mutation transactional GitHub reconciliation.
license: MIT
metadata:
  version: "0.1.0"
---

# agent-autopilot (24x7 Self-Evolving Issue & Routine Engine)

`agent-autopilot` turns any repository or recurring operational workflow into a safe, token-efficient, self-improving autonomous loop built on the 6 Chef Principles:

1. **Look at What AI Did (`01 看它做的`)**: `Scout` produces an executable `dod_check` BEFORE coding; `verify_ring` executes it offline on an immutable `$CLEAN_TREE` copy (plus optional headless Chrome UI check) with mandatory `uncertainties` slots.
2. **Give AI a 5-Second Map (`02 给张地图`)**: Human-authoritative `~/.config/agent-autopilot/projects/<id>/WORKFLOW.md` (`0600`) is physically separated from non-authoritative `~/.local/state/agent-autopilot/advisory/<id>/{PROJECT_MAP.md,feature-map.json}`.
3. **Turn Mistakes into Rules (`03 写进规矩`)**: `dream` distills defects into `PITFALLS.md` (never shown to Referees), cross-project `proposals/<sig>/LESSONS_LEARNED.patch`, and `hits >= 2` executable gate proposals.
4. **Cross-Family Referee Loop (`04 换 AI 当裁判`)**: Codex writers are judged by Claude (`claude-opus-5-5`) and/or AGY, and Claude writers by Codex (`gpt-6.2-astra`) and/or AGY, on symmetric read-only `/ap-review-bundle` up to 3 rounds (`N -> M -> 0`), halting at `needs-human` with zero remote writes if unresolved.
5. **Shortcut = Right Answer (`05 捷径即答案`)**: Per-module `exemplar_files` + strict fill-in JSON schemas (`<= 300` char summary, 3-column defect table).
6. **Specialized Roles & Staircase Rollout (`06 分工干活，阶梯铺开`)**: `Scout -> Writer -> Referee`, starting at `max_in_progress = 1` (`T1`/`T2`) and stepping `[1, 2, 3]` only after `>= 10` 48h-matured clean runs + human `approve-promotion`.

## Common CLI Commands

```bash
# 1. Verify sandbox, linger, native C binaries, and onboarded projects
agent-autopilot doctor
agent-autopilot selftest --live

# 2. Onboard any GitHub repository or recurring routine
agent-autopilot onboard --project-id my-app --kind issue \
  --workspace /path/to/repo --repos org/my-app --base-ref main --tier T1

agent-autopilot onboard --project-id my-cron --kind routine \
  --workspace /path/to/repo --interval-sec 1800 \
  --precheck-cmd "python3 scripts/has_todo.py" \
  --routine-prompt "Process pending items and update STATUS.md"

# 3. Zero-LLM-token precheck probe across all projects
agent-autopilot probe

# 4. Run a single deterministic cycle manually before enabling timer
agent-autopilot run-once --project my-app

# 5. Inspect live systemd/cgroup & SQLite status (incl. active evolution experiments), run audit/dream, or apply/dismiss experiments
agent-autopilot top
agent-autopilot audit --readonly
agent-autopilot evolution list
agent-autopilot evolution apply <exp_id>
agent-autopilot dream
agent-autopilot veto org/my-app#42 --reason "hold for schema review"
agent-autopilot clear-veto org/my-app#42
```

## Operator Recovery & Dedicated Token Paths

- **Dedicated GitHub Tokens (Never in Repo or Chat)**: Write project-scoped tokens locally with `0600` permissions under `~/.config/agent-autopilot/tokens/<project_id>.gh_token` (e.g., `~/.config/agent-autopilot/tokens/my-app.gh_token`). Until present, zero-token precheck records `waiting_dedicated_token` without waking any model.
- **Ambiguous Remote Mutation (`unknown_paused`)**: Inspect `agent-autopilot top` (`pending_external_ops`), verify the original sender process has exited and inspect GitHub PR/branch state, then settle via `agent-autopilot resolve-op <op_id> --status succeeded_verified --receipt-id <id>` or `--status not_executed --unsent-proof <reason>`.
- **Stuck `reclaiming` Lease (`cred_ledger_tracked=2`)**: Indicates frozen cache storage is unmounted or a foreign backup entry was placed inside `runs/claim-<epoch>`. Check `last_error` in `agent-autopilot top`, inspect `~/.cache/agent-work/agent-autopilot/<project>/`, and re-run `agent-autopilot dispatch` once resolved.

## Universal Execution & Throughput Rules (Cross-Project Lessons)

These rules apply to every onboarded repository regardless of stack:

1. **Decouple Parallel Work from Exclusive Resources (Batch-Train Verification)**: Within approved project (`max_in_progress`) and host (`max_global_in_progress`) concurrency limits (preserving shared-PR write locks), run coding, local tests, independent review, and cloud CI in parallel across isolated worktrees; serialize ONLY truly exclusive physical resources (e.g., a single interactive desktop testbed). Batch heavy post-merge regression suites into unified train runs instead of running full regression after every small merge.
2. **Never Hold a Concurrency Slot Waiting on Cloud CI**: Complete branch push **and** PR creation/update first, then release the slot immediately. Native `issue` units finish upon reaching `published`; for `delegated` runners that implement multi-step resume prechecks, record project-local `wake_after` and let CI-aware zero-token precheck resume the unit once checks finish and schedule/cooldown gates allow.
3. **Front-Load Quick Review Before Expensive External E2E**: Keep mandatory local DoD / configured UI checks ahead of the formal referee unchanged; run an extra fast code review before expensive **external / real-machine / slow cloud-build** E2E outside local DoD so logic and boundary defects are fixed in minutes instead of forcing a second full E2E cycle.
4. **Probe Unverified Platform or External Behavior First**: Before implementing against OS internals, UI/accessibility events, or external services, run a fast read-only diagnostic probe to confirm the expected events/paths actually occur.
5. **Safe Process Waiting & Timeout-Gated Hang Recovery**: Wait on same-shell children with `wait "$pid"` (preserving exit status). For cross-shell tasks, prefer explicit PID/receipt checks; never use `pgrep -f <cmd>` self-matching loops, brittle line-start `^rc=`/`done=` polling, or bare `tail --pid` without `-f` (note: `tail --pid=<pid> -f /dev/null` requires GNU `tail`, is unsupported on macOS, does not propagate exit codes, and hangs on unreaped zombies — always pair with a timeout and inspect the task receipt separately). Do NOT kill a worker solely because it is idle in `ep_poll` after a `Stop` hook (hooks may trigger continued turns awaiting network I/O); terminate only after supervisor timeout confirmation and worker-identity verification, releasing the slot through normal cgroup exit/reclaim.
6. **Diff-Aware Issue Closing & Transactional 5xx Reconciliation**: Inspect actual PR diff and scope before closing linked issues (keep parent/multi-phase issues open on partial Phase-1 PRs). On HTTP 5xx (e.g., GitHub `502 Bad Gateway`) during remote merge, reconcile by the original `op_id`: keep `OPEN` in `unknown_paused` rather than blindly resending, verify candidate SHA and target branch if `MERGED`, and re-issue only with confirmed unsent or deterministic rejection proof.
7. **Closed-Loop Zero-Token Self-Evolution Experiments (`evolution_experiments`)**: `agent-autopilot audit` (and `autopilot-dream`, running outside `dispatcher.lock` with full fault isolation) evaluates ratio + own-7d-baseline metrics (`null_outcome_rate`, `<3m` `short_spin_rate`, `needs_human_or_failure_rate`, healthy-only `slot_underutilization`, `delegated_telemetry_missing`, `cost_or_turns_regression`, `high_review_rework`, `cross_family_gap`, and deep stale cache) without polluting code `pitfalls`. Active experiments surface directly in `agent-autopilot top` and can be executed via `agent-autopilot evolution apply <exp_id>` (or dismissed). After `review_after`, the next audit re-measures the metric against its baseline and either marks `verified_better` or automatically executes `rollback_payload` (`rolled_back`). Delegated runners report token/cost telemetry to `AUTOPILOT_TELEMETRY_OUT` so `delegated-exec` ingests them into `turn_usage_ledger`.
