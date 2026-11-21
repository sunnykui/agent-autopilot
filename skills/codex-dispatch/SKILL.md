---
name: codex-dispatch
description: >-
  Automatically offload codebase exploration, pre-coding architecture critique, contract-based
  implementation, test fixing, and independent adversarial review from Claude Code to local
  OpenAI Codex CLI (`gpt-6.2-sol`, `gpt-6.2-astra`, `gpt-6.1-terra`) while conserving Claude Pro
  tokens. Use silently by default for any non-trivial coding, refactoring, debugging, review,
  or repo research task without requiring the user to ask for Codex.
---

# codex-dispatch (Claude 统筹契约，Codex 自动执行)

Executable wrapper: `codex-dispatch` (installed at `~/.local/bin/codex-dispatch`, backed by `~/.claude/skills/codex-dispatch/scripts/codex_dispatch.py`).
All prompts MUST be passed via `stdin` heredoc (`<<'EOF' ... EOF`) to eliminate shell escaping errors.

## Automatic End-to-End Pipeline (No User Babysitting)

Run the needed stages back-to-back automatically; do NOT pause between stages to ask routine permission:

1. **Explore (`explore`)** — When repo structure, call chains, or test commands are not already in context:
   ```bash
   codex-dispatch explore -C "<workspace>" -f "src/entry.ts" <<'EOF'
   查清订单状态流转的调用链、现有可复用的重试/幂等工具与快速单测命令。
   EOF
   ```
2. **Architecture Critique (`critique`)** — Before coding cross-module features, refactors, schema/API changes, or thorny bug fixes, challenge your draft design with `gpt-6.2-astra` in a fresh read-only session:
   ```bash
   codex-dispatch critique -C "<workspace>" -f "src/order,src/common" <<'EOF'
   拟定方案：新增 OrderIdempotencyGuard 中间件，接口为 checkAndLock(key, ttl) -> Result。
   请对照现有代码挑刺：是否已有同类组件可复用？分层与异常回滚是否有漏洞？有无更简方案？
   EOF
   ```
3. **Contract Implementation (`implement`)** — State **goal, reusable modules, public signatures/invariants, edge cases**, and enforce `--allow` + `--verify`. Let Codex craft clean internal code:
   ```bash
   codex-dispatch implement -C "<workspace>" \
     --tier std \
     --allow "src/order/**,tests/order/**" \
     --forbid "vendor/**,migrations/**" \
     --verify "pytest tests/order -q" <<'EOF'
   目标：实现订单回调幂等保护并补齐并发重复回调单测。
   复用：直接使用 `src/common/locks.py` 的现有锁原语，不新建重复工具类。
   接口契约：`process_callback(event_id: str, payload: Mapping[str, Any]) -> CallbackOutcome`；重复已成功事件返回 `DUPLICATE_IGNORED`；下游失败必须释放锁允许重试。
   边界情况：空 `event_id` 抛 `ValueError`；同一 `event_id` 并发到达只有一个执行副作用。
   EOF
   ```
   - `--tier`: `std` (`gpt-6.2-sol` medium, default) | `high` (`gpt-6.2-sol` high, cross-file) | `hard` (`gpt-6.2-astra` high, complex/tricky) | `xhigh` (`gpt-6.2-astra` xhigh, extreme concurrency/security).
   - Parallel independent modules: add `--worktree` to isolate Git worktrees.
4. **Independent Adversarial Review (`review`)** — For non-trivial changes, run a fresh read-only `gpt-6.2-astra` adversarial check:
   ```bash
   codex-dispatch review -C "<workspace>" --base main <<'EOF'
   重点挑刺幂等锁释放路径、部分失败回滚与越界副作用。
   EOF
   ```
5. **Rework (`resume <task_id>`)** — If `scope_gate`, `verify_gate`, or `review` flags issues, send concise delta instructions back to the SAME `implement` `task_id` (script automatically restores `sandbox_mode`, allowlist, and upgrades rework to `gpt-6.2-astra` + `high`):
   ```bash
   codex-dispatch resume <task_id> <<'EOF'
   修复两处问题：1) `src/order/handler.py:84` 异常分支未释放锁；2) 还原越界修改的文件。
   EOF
   ```

## Hard Operating Rules

- **Background without polling**: For runs expected to exceed ~90s (`implement --tier high/hard`, `critique`, `review`), set Claude Bash tool `run_in_background: true`. NEVER append `&`/`nohup` or loop with `sleep`.
- **Read compact receipts only**: Rely on stdout receipt + targeted `git diff` hunks. Read `<run_dir>/stderr.log` or `events.jsonl` ONLY when status is `FAILED`.
- **Two-rework cap**: If the same task still fails acceptance after 2 `resume` rounds, take over directly and finish cleanly.
