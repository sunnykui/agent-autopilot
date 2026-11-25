#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash ./install.sh [OPTIONS]

Options:
  --allow-claude-permissions  Pre-allow `codex-dispatch` and `agent-autopilot` in ~/.claude/settings.json
  --install-systemd-units     Install `agent-autopilot-dispatch.{service,timer}` into ~/.config/systemd/user/ (does NOT start timer)
  -h, --help                  Show this help message
EOF
}

ALLOW_PERMS=0
INSTALL_SYSTEMD=0
for arg in "$@"; do
  case "$arg" in
    --allow-claude-permissions) ALLOW_PERMS=1 ;;
    --install-systemd-units) INSTALL_SYSTEMD=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_PARENT="${HOME}/.claude/skills"
BIN_DIR="${HOME}/.local/bin"
AP_SHARE_BIN="${HOME}/.local/share/agent-autopilot/bin"
CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/agent-work/codex-dispatch"

mkdir -p "${SKILLS_PARENT}" "${BIN_DIR}" "${AP_SHARE_BIN}" "${CACHE_DIR}"
chmod 0700 "${HOME}/.local/share/agent-autopilot" "${AP_SHARE_BIN}" 2>/dev/null || true

# 1. Install both codex-dispatch (100% portable across macOS/Linux) and agent-autopilot Python skills FIRST
install_one_skill() {
  local skill_name="$1"
  local main_script="$2"
  local cli_name="$3"
  local src_dir="${REPO_DIR}/skills/${skill_name}"
  local dst_dir="${SKILLS_PARENT}/${skill_name}"
  local stage_dir="${SKILLS_PARENT}/.${skill_name}.staging.$$"
  local backup_dir="${SKILLS_PARENT}/.${skill_name}.prev.$$"

  cp -R "${src_dir}" "${stage_dir}"
  find "${stage_dir}" -name "__pycache__" -type d -prune -exec rm -rf {} +
  chmod +x "${stage_dir}/scripts/${main_script}"
  python3 -B "${stage_dir}/scripts/${main_script}" --help >/dev/null

  if [ -e "${dst_dir}" ]; then
    mv "${dst_dir}" "${backup_dir}"
  fi
  if mv "${stage_dir}" "${dst_dir}"; then
    rm -rf "${backup_dir}"
  else
    if [ -e "${backup_dir}" ]; then
      mv "${backup_dir}" "${dst_dir}"
    fi
    rm -rf "${stage_dir}"
    exit 1
  fi
  ln -sfn "${dst_dir}/scripts/${main_script}" "${BIN_DIR}/${cli_name}"
  echo "Installed skill to ${dst_dir} -> ${BIN_DIR}/${cli_name}"
}

install_one_skill "codex-dispatch" "codex_dispatch.py" "codex-dispatch"
install_one_skill "agent-autopilot" "agent_autopilot.py" "agent-autopilot"

# 2. On Linux with static C toolchain, compile Landlock/bwrap static sandbox binaries (distinct inodes)
if [ "$(uname -s)" = "Linux" ]; then
  CC_BIN="${CC:-gcc}"
  if command -v "${CC_BIN}" >/dev/null 2>&1; then
    if "${CC_BIN}" -static -O2 -Wall -Wextra -Werror -pedantic -std=c11 \
      "${REPO_DIR}/skills/agent-autopilot/native/ap_sandbox_init.c" \
      -o "${AP_SHARE_BIN}/ap-sandbox-init.tmp.$$" && \
       "${CC_BIN}" -static -O2 -Wall -Wextra -Werror -pedantic -std=c11 \
      "${REPO_DIR}/skills/agent-autopilot/native/ap_safe_sh.c" \
      -o "${AP_SHARE_BIN}/ap-safe-sh.tmp.$$"; then
      mv "${AP_SHARE_BIN}/ap-sandbox-init.tmp.$$" "${AP_SHARE_BIN}/ap-sandbox-init"
      mv "${AP_SHARE_BIN}/ap-safe-sh.tmp.$$" "${AP_SHARE_BIN}/ap-safe-sh"
      chmod 0755 "${AP_SHARE_BIN}/ap-sandbox-init" "${AP_SHARE_BIN}/ap-safe-sh"
      echo "Compiled native static binaries in ${AP_SHARE_BIN}"
    else
      rm -f "${AP_SHARE_BIN}/ap-sandbox-init.tmp.$$" "${AP_SHARE_BIN}/ap-safe-sh.tmp.$$"
      echo "Warning: static C compilation skipped/unavailable; codex-dispatch remains fully functional." >&2
    fi
  fi
else
  echo "Note: non-Linux host ($(uname -s)); skipping Linux Landlock static binaries (codex-dispatch installed cleanly)."
fi

if [ "${INSTALL_SYSTEMD}" -eq 1 ]; then
  SD_USER_DIR="${HOME}/.config/systemd/user"
  mkdir -p "${SD_USER_DIR}"
  cp "${REPO_DIR}/skills/agent-autopilot/templates/agent-autopilot-dispatch.service" "${SD_USER_DIR}/"
  cp "${REPO_DIR}/skills/agent-autopilot/templates/agent-autopilot-dispatch.timer" "${SD_USER_DIR}/"
  systemctl --user daemon-reload
  echo "Installed systemd units into ${SD_USER_DIR}"
fi

if [ "${ALLOW_PERMS}" -eq 1 ]; then
  SETTINGS_PATH="${HOME}/.claude/settings.json"
  python3 - "${SETTINGS_PATH}" <<'PY'
import json, os, pathlib, sys
settings_path = pathlib.Path(sys.argv[1])
settings_path.parent.mkdir(parents=True, exist_ok=True)
data = {}
if settings_path.is_file():
    data = json.loads(settings_path.read_text(encoding="utf-8"))
perms = data.setdefault("permissions", {})
if not isinstance(perms, dict):
    perms = {}
    data["permissions"] = perms
allow = list(perms.get("allow") or [])
for rule in (
    "Bash(codex-dispatch *)",
    "Bash(codex-dispatch:*)",
    "Read(~/.cache/agent-work/codex-dispatch/**)",
    "Bash(agent-autopilot *)",
    "Bash(agent-autopilot:*)",
):
    if rule not in allow:
        allow.append(rule)
perms["allow"] = allow
tmp = settings_path.with_name(f".settings.json.{os.getpid()}.tmp")
tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
os.replace(tmp, settings_path)
print(f"Updated permissions.allow in {settings_path}")
PY
fi

python3 -B "${SKILLS_PARENT}/codex-dispatch/scripts/codex_dispatch.py" doctor || true
python3 -B "${SKILLS_PARENT}/agent-autopilot/scripts/agent_autopilot.py" doctor || true
