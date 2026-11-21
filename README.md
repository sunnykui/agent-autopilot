# claude-codex (`codex-dispatch`)

面向 **$20 Claude Pro + OpenAI Codex (`gpt-6.2-sol` / `gpt-6.2-astra` / `gpt-6.1-terra`)** 的无感自动编排工具与全局记忆套件。

## 设计目标

1. **全程无感自动闭环**：在 Claude Code 中只需正常说业务需求，无需手动敲插件命令或逐步确认；Claude 自动在后台串联「摸底 (`explore`) → 架构挑刺 (`critique`) → 契约实现 (`implement`) → 白名单与单测门禁 → 独立对抗性审查 (`review`) → 自动升档返工 (`resume`)」。
2. **保护 $20 Claude Pro 额度**：用确定性 Python 包装器承接基线对比、JSONL 解析、文件越界校验与单测运行，Claude 只写紧凑接口契约、只读 30 行以内的验收回执。
3. **代码与架构更优雅**：废除束手束脚的“函数级微步骤说明书”，改为“动手前由 `gpt-6.2-astra` 挑刺架构与复用点 + 明确公开契约与文件白名单 + 放权 Codex 写地道内聚代码”。
4. **严格遵守安全与配额底线**：写任务锁定 `workspace-write` 沙箱（并行加 `--worktree`），绝不使用 `danger-full-access`；运行产物统一存放在 `~/.cache/agent-work/codex-dispatch/`（不占 `/tmp` 内存盘）。

## 安装与回归测试

```bash
# 运行离线回归测试
python3 -m unittest discover -s tests -p "test_*.py" -v

# 安装到 ~/.claude/skills/codex-dispatch 与 ~/.local/bin/codex-dispatch
bash ./install.sh
```

## 常用命令（供 Claude 自动调用）

```bash
codex-dispatch explore   -C <repo> -f "src/entry.py" <<'EOF' ... EOF
codex-dispatch critique  -C <repo> -f "src/core"     <<'EOF' ... EOF
codex-dispatch implement -C <repo> --allow "src/**,tests/**" --verify "pytest -q" <<'EOF' ... EOF
codex-dispatch review    -C <repo> --base main       <<'EOF' ... EOF
codex-dispatch resume    <task_id>                   <<'EOF' ... EOF
codex-dispatch status
codex-dispatch clean --days 7
```
