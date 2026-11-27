# `agent-autopilot` 交接状态与通用运维手册（`STATUS.md`）

更新时间：2026-11-27（`America/Los_Angeles`）
仓库：`sunnykui/agent-autopilot`

---

## 1. 工程交付与验证状态

1. **双模型对抗性审查全部 `APPROVE`**：
   - 架构规范（[`docs/AUTOPILOT_PLAN.md`](docs/AUTOPILOT_PLAN.md) v7.8）：Claude Fable 5.2 + Codex GPT-6.2 Astra 双 `APPROVE`。
   - 全量代码实现审查（30+ 轮增量对抗挑刺）：Claude Fable 5.2 / Sonnet 5.5 + Codex GPT-6.2 Astra 双 `APPROVE`（0 个 P0/P1 阻塞项）。
   - 通用试点增强（2026-11-25）：新增全项目通用的 `--require-labels` 标签准入过滤、多槽位并行调度（`slot-1..slot-N` 并发派发 + `managed.git` 工作树互斥锁 + `approve-promotion --force --target <N>` 并发调控）、无状态多语言 SDK 自动发现（Node / Go / Rust / Terraform / uv，零版本号硬编码）、`go.sum` 离线 `GOMODCACHE` 预取、`ro_workspace_deps` 受控只读依赖挂载、`AP_TOUCHED_FILES` 干净树改动集注入，以及 `delegated` 模式只读断网 `bwrap` 续做预检。
   - 自动化验证：`python3 -B -m unittest discover -s tests -p "test_*.py"` **45/46 通过**（`test_round22_all_codex_closures` 为基点 `32cb6e1` 起即存在的旧失败），`agent-autopilot selftest --live` **通过**（`schema_version = 16`）。
   - 试点首夜修复（2026-11-26）：①“基线已红”识别——验收失败时用同一命令在未改动的授权基线上复跑，候选的每条失败都已出现在基线上才判为环境问题，挂起等待（不扣改代码轮次），醒来先零 token 复查基线，连续 6 次仍红转人工；②`delegated` 项目仅因续做预检触发时遵守 `schedule_interval_sec`（在调度锁内复核），新 issue 不受影响；③`delegated-exec --cmd` 与子命令名冲突、大仓库索引采样超时、清理单元时限过短等修复。
2. **零个人/业务敏感硬编码**：
   - 仓库内源码与文档已彻底剥离个人邮箱、内部仓库名、宿主机用户路径及任何凭据；
   - 各业务仓库、邮箱地址、忽略发件人列表与专用 Token 路径全部隔离在宿主机本机目录 `~/.config/agent-autopilot/`（`0600`）与 `~/.local/state/agent-autopilot/`（`0700`，本机实例台账见 `~/.local/state/agent-autopilot/HOST_STATUS.md`）。

3. **主机算力护栏（2026-11-26，分支 `sunnykui/fix-cpu`；起因：4 vCPU 突发型主机 CPU 积分耗尽、Steal 约 60%）**：
   - 全机重型 Worker（`issue` / `delegated`）并发上限 `max_global_in_progress`（默认 `1`），在 `claim_and_reserve` 事务内强制；只计 `active` 认领（卡在 `reclaiming` 的不占槽位，避免一个清理失败的单元把所有项目饿死）。`routine` 不受限。
   - 派发前零 Token 闸门：全局槽位已满则直接跳过；否则采样 1 秒 `/proc/stat` steal 占比与 `/proc/loadavg`，steal > 15% 或 1 分钟负载 > 4.0 时本轮记为普通等待（`waiting_host_capacity:*`），下个定时 tick 自动重试；最近一次判定写入 `~/.local/state/agent-autopilot/host_gate.json`。
   - 可调项（可选）：`~/.config/agent-autopilot/global.json` 的 `max_global_in_progress` / `host_max_steal_pct` / `host_max_load1` / `host_sample_sec`，或同名 `AGENT_AUTOPILOT_*` 环境变量。
   - `templates/app-autopilot.slice`（`CPUWeight=10`、`CPUQuota=110%`、`IOWeight=20`、`MemoryHigh=6G`、`MemoryMax=8G`）由 `install.sh --install-systemd-units` 安装；不安装时 `systemd-run --slice` 会生成无配额的空 slice。瞬态单元追加 `Nice=15`；tool/verify 沙箱默认注入 `GOMAXPROCS=2`、`RAYON_NUM_THREADS=2`、`UV_THREADPOOL_SIZE=2`、`PLAYWRIGHT_WORKERS=1`（WORKFLOW `verify_env` 显式值优先）。
   - 已知旧失败：`test_round22_all_codex_closures`（tool_ring 内 `.git` 只读断言）在本分支基点 `32cb6e1` 上同样失败，与本改动无关。
4. **单任务受保护迁移路径人工批准（2026-11-26）**：
   - 新增 `agent-autopilot approve-paths <unit_key> --allow <glob>`：仅允许对 `policy_manifest.json` 的 `approvable_hard_stop_anchored` 子集（`prisma/**`、`migrations/**`、`**/migrations/**`）按单任务授权并自动恢复非否决 `needs-human` 暂停；认领时冻结到 `run_claims.frozen_approved_protected_paths_json`，密钥、控制文件、CI 与锁文件仍无条件阻断。
5. **跨项目通用执行与吞吐准则沉淀（2026-11-27）**：
   - 将多仓库实战沉淀的 6 条通用准则写入 [`skills/agent-autopilot/SKILL.md`](skills/agent-autopilot/SKILL.md) 与 [`skills/codex-dispatch/SKILL.md`](skills/codex-dispatch/SKILL.md)（严格脱敏、零业务硬编码），并修正既有 `resolve-op` 文档示例为有效状态名（`succeeded_verified` / `not_executed`）：在已批准两级并发上限内将可并发阶段与独占物理资源解耦及批量合测列车、推分支建 PR 后即释槽（原生 `issue` 发布后结束，已实现续做预检的 `delegated` 项目在 CI 完且冷却期与调度条件满足后恢复）、独立快审前置到 DoD 之外的昂贵外部/真机 E2E 之前、平台/外部行为先探针证实、安全进程等待（同 shell 用 `wait "$pid"`，跨 shell 读任务回执，禁 `pgrep -f` 自匹配并按主管超时与身份核验回收僵死进程）、合前审 diff 区分阶段性 PR 及远端 5xx 按原 `op_id` 事务对账。

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
