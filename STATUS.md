# `agent-autopilot` 交接状态与通用运维手册（`STATUS.md`）

更新时间：2026-11-25（`America/Los_Angeles`）
仓库：`sunnykui/agent-autopilot`

---

## 1. 工程交付与验证状态

1. **双模型对抗性审查全部 `APPROVE`**：
   - 架构规范（[`docs/AUTOPILOT_PLAN.md`](docs/AUTOPILOT_PLAN.md) v7.8）：Claude Fable 5.2 + Codex GPT-6.2 Astra 双 `APPROVE`。
   - 全量代码实现审查（30+ 轮增量对抗挑刺）：Claude Fable 5.2 / Sonnet 5.5 + Codex GPT-6.2 Astra 双 `APPROVE`（0 个 P0/P1 阻塞项）。
   - 通用试点增强（2026-11-25）：新增全项目通用的 `--require-labels` 标签准入过滤、多槽位并行调度（`slot-1..slot-N` 并发派发 + `managed.git` 工作树互斥锁 + `approve-promotion --force --target <N>` 并发调控）、无状态多语言 SDK 自动发现（Node / Go / Rust / Terraform / uv，零版本号硬编码）、`go.sum` 离线 `GOMODCACHE` 预取、`ro_workspace_deps` 受控只读依赖挂载、`AP_TOUCHED_FILES` 干净树改动集注入，以及 `delegated` 模式只读断网 `bwrap` 续做预检。
   - 自动化验证：`python3 -B -m unittest discover -s tests -p "test_*.py"` **54/54 全部通过**，`agent-autopilot selftest --live` **通过**（`schema_version = 16`）。
   - 试点首夜修复（2026-11-26）：①“基线已红”识别——验收失败时用同一命令在未改动的授权基线上复跑，候选的每条失败都已出现在基线上才判为环境问题，挂起等待（不扣改代码轮次），醒来先零 token 复查基线，连续 6 次仍红转人工；②`delegated` 项目仅因续做预检触发时遵守 `schedule_interval_sec`（在调度锁内复核），新 issue 不受影响；③`delegated-exec --cmd` 与子命令名冲突、大仓库索引采样超时、清理单元时限过短等修复。
2. **零个人/业务敏感硬编码**：
   - 仓库内源码与文档已彻底剥离个人邮箱、内部仓库名、宿主机用户路径及任何凭据；
   - 各业务仓库、邮箱地址、忽略发件人列表与专用 Token 路径全部隔离在宿主机本机目录 `~/.config/agent-autopilot/`（`0600`）与 `~/.local/state/agent-autopilot/`（`0700`，本机实例台账见 `~/.local/state/agent-autopilot/HOST_STATUS.md`）。

---

## 2. 支持的三类工作流模式

| 模式 (`kind`) | 适用场景 | 零 Token 预检机制 | 安全与执行边界 |
| :--- | :--- | :--- | :--- |
| `issue` | GitHub Issue 自动修复与开 Draft PR | `gh issue list --state open --assignee <assignee>` | 四环 `bwrap` + 匿名 `memfd` 凭据 + 跨家族 AI 裁判最多 3 轮 + 干净树离线验收 |
| `routine` | 定时例行巡检（如飞书邮箱巡检、每日 `dream` 复盘） | 先检时间窗口与未读增量，无新事项 `0` Token 秒退 | 外部邮件仅允许创建草稿；仅在有新草稿/新待办时通知指定本人邮箱 |
| `delegated` | 托管既有仓库内自带的自治脚本 | 先检专用 Token 文件与开关，缺失时记为等待资源 | 独立瞬态 `systemd` `cgroup` 隔离与物理 `.flock` 槽位互斥 |

---

## 3. 日常运维常用命令

```bash
# 1. 查看全局实时健康度、物理槽位锁、在途任务与定时器状态
agent-autopilot top

# 2. 手动触发一次全项目零 Token 预检（不消耗大模型额度）
agent-autopilot probe

# 3. 立即对单个已接入项目手动执行一轮
agent-autopilot run-once --project <project_id>

# 4. 紧急叫停某个单据（自动停止对应 Worker，并将关联 PR 退回 Draft / 取消自动合并）
agent-autopilot veto <org/repo#number> --reason "manual review"
agent-autopilot clear-veto <org/repo#number>

# 5. 10 秒将任意新仓库或任意自定义定时任务接入自治体系
agent-autopilot onboard --project-id <project_id> --kind issue \
  --workspace /path/to/repo --repos <org/repo> --base-ref main --tier T1

agent-autopilot onboard --project-id <routine_id> --kind routine \
  --workspace /path/to/repo --interval-sec 1800 \
  --precheck-cmd "test -s queue.txt" --routine-prompt "处理队列并更新状态"

# 6. 满 10 单 48 小时零回滚后，批准并发阶梯从 1 升到 2（最高 3）；或管理员显式设定并发上限
agent-autopilot approve-promotion <project_id>
agent-autopilot approve-promotion <project_id> --force --target 3
```

---

## 4. 开新会话可直接粘贴的开场提示词

```text
请先读取仓库内的 STATUS.md（若在运行宿主机上请同时查看 ~/.local/state/agent-autopilot/HOST_STATUS.md），并运行 `agent-autopilot top` 与 `systemctl --user list-timers agent-autopilot-dispatch.timer --no-pager` 核实真实运行状态后继续协作。
```
