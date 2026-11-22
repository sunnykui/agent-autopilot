---
name: codex-dispatch
description: >-
  Automatically offload codebase exploration, pre-coding architecture critique, contract-based
  implementation, test fixing, and independent adversarial review from Claude Code to local
  OpenAI Codex CLI while conserving Claude tokens. Use silently by default for non-trivial coding,
  refactoring, debugging, review, or repository research tasks without requiring the user to ask.
license: MIT
metadata:
  version: "0.2.0"
---

# codex-dispatch (Claude Architects Contracts, Codex Executes)

`SKILL_DIR` is the directory containing this `SKILL.md`.
Use `codex-dispatch` directly if available on `PATH`, or invoke `python3 "$SKILL_DIR/scripts/codex_dispatch.py"`.
Always pass prompts via `stdin` heredoc (`<<'EOF' ... EOF`) to prevent shell quoting issues.

Models are **auto-discovered** from the user's local Codex installation (`~/.codex/config.toml` & `~/.codex/models_cache.json`) into three adaptive slots (`workhorse`, `flagship`, `visual`). Run `codex-dispatch doctor` only if diagnosing environment setup.

## Autonomous End-to-End Pipeline (Zero User Babysitting)

Execute the required stages back-to-back without stopping for routine intermediate confirmation:

1. **Explore (`explore`)** — Map unfamiliar call chains, reusable helpers, and fast test commands (`workhorse` read-only):
   ```bash
   codex-dispatch explore -C "<workspace>" -f "src/entry.ts" <<'EOF'
   Trace the order callback flow, list reusable lock/retry utilities, and report fast unit test commands.
   EOF
   ```
2. **Architecture Critique (`critique`)** — Before coding cross-module changes, refactors, new abstractions, or tricky bug fixes, challenge your draft design in a fresh `flagship` read-only session:
   ```bash
   codex-dispatch critique -C "<workspace>" -f "src/order,src/common" <<'EOF'
   Draft plan: introduce OrderIdempotencyGuard with checkAndLock(key, ttl) -> Result.
   Check against actual repo code: can existing primitives be reused? Are there coupling or rollback flaws? Is there a cleaner design?
   EOF
   ```
3. **Contract Implementation (`implement`)** — Specify **goal, reusable modules, public signatures/invariants, edge cases**, plus `--allow` and `--verify`. Let Codex craft idiomatic internal code:
   ```bash
   codex-dispatch implement -C "<workspace>" \
     --tier std \
     --allow "src/order/**,tests/order/**" \
     --forbid "vendor/**,migrations/**" \
     --verify "pytest tests/order -q" <<'EOF'
   Goal: implement idempotent callback handling and concurrent duplicate unit tests.
   Reuse: use existing lock primitives in `src/common/locks.py`; do not create duplicate helpers.
   Contract: `process_callback(event_id: str, payload: Mapping[str, Any]) -> CallbackOutcome`; duplicate completed events return `DUPLICATE_IGNORED`; downstream failure must release lock for retry.
   Edge cases: empty `event_id` raises `ValueError`; concurrent identical `event_id` executes side effects once.
   EOF
   ```
   - `--tier`: `fast` (`workhorse` low) | `std` (`workhorse` medium, default) | `high` (`workhorse` high, cross-file) | `hard` (`flagship` high, complex) | `xhigh` (`flagship` xhigh, extreme concurrency/security).
   - Parallel independent modules: add `--worktree` to execute inside an isolated Git worktree with full scope & verify gates.
4. **Independent Adversarial Review (`review`)** — Run a fresh `flagship` read-only skeptical check before delivery:
   ```bash
   codex-dispatch review -C "<workspace>" --base main <<'EOF'
   Focus on lock-release failure paths, partial rollback safety, and scope boundaries.
   EOF
   ```
5. **Rework (`resume <task_id>`)** — If `scope_gate`, `verify_gate`, or `review` flags material issues, send delta fix instructions to the same `implement` `task_id` (automatically restores sandbox/allowlist and upgrades rework to `flagship` + `high`):
   ```bash
   codex-dispatch resume <task_id> <<'EOF'
   Fix: 1) release lock on exception at `src/order/handler.py:84`; 2) revert out-of-scope file edits.
   EOF
   ```

## Hard Operating Rules

- **Background without polling**: For runs likely exceeding ~90s (`implement --tier high/hard`, `critique`, `review`), set Claude Bash tool `run_in_background: true`. NEVER append `&`/`nohup` or poll with `sleep`.
- **Read compact receipts only**: Rely on stdout receipt + targeted `git diff` hunks. Read `<run_dir>/stderr.log` or `events.jsonl` ONLY when status is `FAILED`.
- **Two-rework cap**: After 2 failed `resume` attempts on the same task, take over directly and finish cleanly.
