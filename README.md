# codex-dispatch

**Claude 管架构契约与验收，Codex 扛执行与对抗审查 —— 零打扰、省 Claude Token、防越界的双模型自动编程套件。**

专为 **Claude Pro ($20) + OpenAI Codex CLI** 用户打造：当你在 Claude Code 中像平时一样提业务或开发需求时，Claude 会在后台自动调度本机 Codex 完成「代码库摸底 → 动手前架构挑刺 → 契约式实现 → 文件白名单与单测门禁 → 独立对抗性审查 → 自动升档返工」，全程无需手动敲命令，大幅节省 Claude 额度并提升代码架构优雅度。

---

## 核心特性

- **自适应全系 Codex 模型（零硬编码）**：自动读取本机 `~/.codex/config.toml` 与 `~/.codex/models_cache.json`，将账号可用模型映射为 `workhorse`（日常主力编码/检索，如 `gpt-6.2-sol` / `gpt-5.4-mini`）、`flagship`（架构挑刺/疑难根因/对抗审查，如 `gpt-6.2-astra` / `gpt-5.4`）与 `visual`（截图视觉走查，如 `gpt-6.1-terra`），同时兼容 macOS `ChatGPT.app` 内置 CLI 与独立安装的 `codex`。
- **契约式委派 + 动手前架构挑刺**：内置角色专属 XML 提示词契约（融合 OpenAI 官方提示词块与防中途反问策略），复杂改动在写代码前先用旗舰模型对照真实仓库挑刺设计，杜绝重复造轮子与打补丁式烂代码。
- **可执行安全门禁（零 Token 校验）**：
  - 写任务强制运行在 `workspace-write` 沙箱（支持 `--worktree` 托管独立 Git 工作树并行开发），**绝不开启 `danger-full-access`**；
  - 自动拍下任务前 Git 基线（精准忽略原有未提交文件），拦截越界修改（根锚定逐段通配符 `--allow` / `--forbid`）与擅自 `git commit`；
  - 范围合规后才运行 `--verify` 快速单测，并在测试后二次核查文件状态，只向 Claude 返回 30 行以内的精简验收回执。
- **稳健会话续接与自动升档**：`resume <task_id>` 自动恢复原会话沙箱、文件白名单，并在返工时自动升档至 `flagship + high` 推理强度，解决 `codex exec resume` 默认丢失参数的问题。

---

## 快速安装（支持三种标准方式）

前置要求：Python 3.10+，且本机已安装并登录 OpenAI `codex` CLI（`codex login`）。

### 方式一：克隆并一键安装（推荐，包含全局 CLI 包装器与免审批配置）

```bash
git clone https://github.com/sunnykui/codex-dispatch.git
cd codex-dispatch
bash ./install.sh --allow-claude-permissions
```

确保 `~/.local/bin` 在 `PATH` 中，然后把仓库内的通用规则模板按需合入全局记忆即可实现**全程无感自动触发**：
- [templates/CLAUDE.snippet.md](templates/CLAUDE.snippet.md) → 合入 `~/.claude/CLAUDE.md`
- [templates/AGENTS.snippet.md](templates/AGENTS.snippet.md) → 追加至 `~/.codex/AGENTS.md`

### 方式二：Claude Code 插件市场安装

在 Claude Code 中依次执行：

```text
/plugin marketplace add sunnykui/codex-dispatch
/plugin install codex-dispatch@codex-dispatch
```

### 方式三：`skills` CLI 安装

```bash
npx skills add sunnykui/codex-dispatch
```

---

## 环境自检与自定义模型

安装后可随时运行只读自检（零模型调用开销）：

```bash
codex-dispatch doctor
```

如需手动固定三个槽位的模型，可设置环境变量或创建 `~/.config/codex-dispatch/config.json`：

```json
{
  "workhorse_model": "gpt-6.2-sol",
  "flagship_model": "gpt-6.2-astra",
  "visual_model": "gpt-6.1-terra"
}
```

---

## 命令速览（通常由 Claude 在后台自动调用）

```bash
# 1. 只读摸底：查调用链、可复用模块与单测命令
codex-dispatch explore -C <repo> -f "src/entry.py" <<'EOF'
查清回调状态机调用链与现有锁工具。
EOF

# 2. 动手前架构挑刺（全新旗舰只读会话）
codex-dispatch critique -C <repo> -f "src/core" <<'EOF'
拟定方案：…… 请对照仓库源码挑刺是否有重复抽象或异常回滚漏洞。
EOF

# 3. 契约式实现 + 白名单门禁 + 自动跑单测（加 --worktree 可隔离并行写）
codex-dispatch implement -C <repo> \
  --tier std \
  --allow "src/order/**,tests/order/**" \
  --forbid "migrations/**" \
  --verify "pytest tests/order -q" <<'EOF'
目标与公开接口契约：……
EOF

# 4. 独立对抗性代码审查
codex-dispatch review -C <repo> --base main <<'EOF'
重点检查并发竞争与异常释放路径。
EOF

# 5. 原会话续接返工（自动恢复沙箱/白名单并升档旗舰模型）
codex-dispatch resume <task_id> <<'EOF'
修复审查指出的锁释放遗漏。
EOF

# 6. 查看最近任务与清理过期缓存
codex-dispatch status
codex-dispatch clean --days 7
```

---

## 运行离线测试

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

## License

[MIT](LICENSE)
