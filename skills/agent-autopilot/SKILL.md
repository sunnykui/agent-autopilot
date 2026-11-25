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
4. **Cross-Family Referee Loop (`04 换 AI 当裁判`)**: Codex writers are judged by Claude (`claude-fable-5-2`) and Claude writers by Codex (`gpt-6.2-astra`) on symmetric read-only `/ap-review-bundle` up to 3 rounds (`N -> M -> 0`), halting at `needs-human` with zero remote writes if unresolved.
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

# 3. Zero-LLM-token precheck probe across all projects
agent-autopilot probe

# 4. Run a single deterministic cycle manually before enabling timer
agent-autopilot run-once --project my-app

# 5. Inspect live systemd/cgroup & SQLite status, consolidate pitfalls, or veto/unveto
agent-autopilot top
agent-autopilot dream
agent-autopilot veto org/my-app#42 --reason "hold for schema review"
agent-autopilot clear-veto org/my-app#42
```

## Operator Recovery & Dedicated Token Paths

- **Dedicated GitHub Tokens (Never in Repo or Chat)**: Write project-scoped tokens locally with `0600` permissions under `~/.config/agent-autopilot/tokens/<project_id>.gh_token` (e.g., `~/.config/agent-autopilot/tokens/my-app.gh_token`). Until present, zero-token precheck records `waiting_dedicated_token` without waking any model.
- **Ambiguous Remote Mutation (`unknown_paused`)**: Inspect `agent-autopilot top` (`pending_external_ops`), verify GitHub PR/branch state, then settle via `agent-autopilot resolve-op <op_id> --status confirmed_remote --receipt-id <id>` or `--status confirmed_unsent --unsent-proof <reason>`.
- **Stuck `reclaiming` Lease (`cred_ledger_tracked=2`)**: Indicates frozen cache storage is unmounted or a foreign backup entry was placed inside `runs/claim-<epoch>`. Check `last_error` in `agent-autopilot top`, inspect `~/.cache/agent-work/agent-autopilot/<project>/`, and re-run `agent-autopilot dispatch` once resolved.
