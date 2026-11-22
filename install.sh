#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash ./install.sh [OPTIONS]

Options:
  --allow-claude-permissions  Pre-allow `codex-dispatch` in ~/.claude/settings.json so Claude Code runs without approval prompts
  -h, --help                  Show this help message
EOF
}

ALLOW_PERMS=0
for arg in "$@"; do
  case "$arg" in
    --allow-claude-permissions) ALLOW_PERMS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_SRC="${REPO_DIR}/skills/codex-dispatch"
SKILLS_PARENT="${HOME}/.claude/skills"
SKILL_DST="${SKILLS_PARENT}/codex-dispatch"
BIN_DIR="${HOME}/.local/bin"
CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/agent-work/codex-dispatch"

mkdir -p "${SKILLS_PARENT}" "${BIN_DIR}" "${CACHE_DIR}"

STAGE_DIR="${SKILLS_PARENT}/.codex-dispatch.staging.$$"
BACKUP_DIR="${SKILLS_PARENT}/.codex-dispatch.prev.$$"
cleanup_stage() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup_stage EXIT

cp -R "${SKILL_SRC}" "${STAGE_DIR}"
rm -rf "${STAGE_DIR}/scripts/__pycache__"
chmod +x "${STAGE_DIR}/scripts/codex_dispatch.py"
python3 "${STAGE_DIR}/scripts/codex_dispatch.py" --help >/dev/null

if [ -e "${SKILL_DST}" ]; then
  mv "${SKILL_DST}" "${BACKUP_DIR}"
fi
if mv "${STAGE_DIR}" "${SKILL_DST}"; then
  rm -rf "${BACKUP_DIR}"
else
  if [ -e "${BACKUP_DIR}" ]; then
    mv "${BACKUP_DIR}" "${SKILL_DST}"
  fi
  exit 1
fi

ln -sfn "${SKILL_DST}/scripts/codex_dispatch.py" "${BIN_DIR}/codex-dispatch"

if [ "${ALLOW_PERMS}" -eq 1 ]; then
  SETTINGS_PATH="${HOME}/.claude/settings.json"
  python3 - "${SETTINGS_PATH}" "${CACHE_DIR}" <<'PY'
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

echo "Installed skill to ${SKILL_DST}"
echo "Linked CLI wrapper at ${BIN_DIR}/codex-dispatch"
python3 "${SKILL_DST}/scripts/codex_dispatch.py" doctor || true
