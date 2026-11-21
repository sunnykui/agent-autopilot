#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_SRC="${REPO_DIR}/skills/codex-dispatch"
SKILLS_PARENT="${HOME}/.claude/skills"
SKILL_DST="${SKILLS_PARENT}/codex-dispatch"
BIN_DIR="${HOME}/.local/bin"
CACHE_DIR="${HOME}/.cache/agent-work/codex-dispatch"

mkdir -p "${SKILLS_PARENT}" "${BIN_DIR}" "${CACHE_DIR}"

STAGE_DIR="${SKILLS_PARENT}/.codex-dispatch.staging.$$"
BACKUP_DIR="${SKILLS_PARENT}/.codex-dispatch.prev.$$"
cleanup_stage() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup_stage EXIT

cp -R "${SKILL_SRC}" "${STAGE_DIR}"
chmod +x "${STAGE_DIR}/scripts/codex_dispatch.py"
# Smoke-check staged script before replacing live installation
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

echo "Installed skill to ${SKILL_DST}"
echo "Linked CLI wrapper at ${BIN_DIR}/codex-dispatch"
