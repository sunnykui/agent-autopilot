"""Universal project onboarding: generates authoritative WORKFLOW.md + isolated advisory PROJECT_MAP & exemplars."""
from __future__ import annotations

import contextlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

from .db import AutopilotDB
from .models import (
    WorkflowConfig,
    default_config_root,
    default_state_root,
    ensure_secure_dir,
    now_iso,
    render_workflow_markdown,
)


def _discover_exemplar_files(repo_dir: Path, max_files: int = 8) -> dict[str, list[str]]:
    """Auto-discover clean, representative source files per top-level module for Principle 05 (Shortcut = Answer)."""
    buckets: dict[str, list[str]] = {}
    if not repo_dir.is_dir():
        return buckets
    candidates_roots = ["apps", "packages", "src", "skills", "expert-trajectory"]
    for root_name in candidates_roots:
        rpath = repo_dir / root_name
        if not rpath.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(rpath):
            dirnames[:] = [
                d
                for d in dirnames
                if d not in ("node_modules", "dist", "build", ".git", "__pycache__", "migrations", "target")
            ]
            dp = Path(dirpath)
            for fn in sorted(filenames):
                if not fn.endswith((".ts", ".tsx", ".py", ".rs", ".mjs")):
                    continue
                if ".test." in fn or ".spec." in fn or fn.startswith("test_"):
                    continue
                rel = str((dp / fn).relative_to(repo_dir))
                top_mod = "/".join(rel.split("/")[:2])
                lst = buckets.setdefault(top_mod, [])
                if len(lst) < 2:
                    lst.append(rel)
            if sum(len(v) for v in buckets.values()) >= max_files:
                return buckets
    return buckets


def _infer_repo_defaults(repo_dir: Path) -> tuple[str, list[str], str]:
    """Infer (verify_cmd, write_scope, repo_notes) from actual repo manifests and AGENTS.md."""
    agents_txt = (repo_dir / "AGENTS.md").read_text(encoding="utf-8", errors="replace") if (repo_dir / "AGENTS.md").is_file() else ""
    pkg_json = repo_dir / "package.json"
    if pkg_json.is_file():
        pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
        scripts = pkg.get("scripts") or {}
        if "本项目不要测试" in agents_txt:
            # Strict repo no-test policy declared in AGENTS.md: rely on typecheck + lint + format:check
            parts = [
                "pnpm run typecheck" if "typecheck" in scripts else "",
                "pnpm run lint" if "lint" in scripts else "",
                "pnpm run format:check" if "format:check" in scripts else "",
            ]
            vcmd = " && ".join(p for p in parts if p)
            return (
                vcmd or "pnpm -r --parallel typecheck",
                ["apps/**", "packages/**", "dashboard/**", "docs/**"],
                "IRON LAW from AGENTS.md: NO tests allowed; NO hand-written migrations; NO foreign keys.",
            )
        if "test" in scripts and "typecheck" in scripts:
            return ("pnpm run typecheck && pnpm test", ["apps/**", "packages/**", "src/**"], "Node/TS workspace.")
        if "typecheck" in scripts:
            return ("pnpm run typecheck", ["apps/**", "packages/**", "src/**"], "Node/TS workspace.")
    if (repo_dir / "Cargo.toml").is_file():
        rust_scopes = ["src/**", "crates/**"]
        if (repo_dir / "expert-trajectory").is_dir():
            rust_scopes.insert(0, "expert-trajectory/**")
        return ("cargo check", rust_scopes, "Rust workspace.")
    if (repo_dir / "expert-trajectory" / "Cargo.toml").is_file():
        return (
            "cargo check --manifest-path expert-trajectory/Cargo.toml",
            ["expert-trajectory/**", "src/**"],
            "Nested Rust workspace (expert-trajectory/Cargo.toml).",
        )
    return ("python3 -B -m unittest discover -s tests -p 'test_*.py'", ["src/**", "skills/**", "tests/**"], "Python workspace.")


def onboard_project(
    *,
    project_id: str,
    kind: str,
    workspace_path: Path,
    repos: list[str] | None = None,
    authorized_base_ref: str = "main",
    branch_prefix: str = "agent/",
    trust_tier: str = "T1",
    writer_family: str = "codex",
    verify_cmd: str | None = None,
    write_scope: list[str] | None = None,
    routine_driver: str = "",
    delegated_cmd: str = "",
    token_file: str = "",
    schedule_interval_sec: int = 300,
    enabled: bool = True,
    extra: dict[str, Any] | None = None,
    prompt_body: str = "",
    config_root: Path | None = None,
    state_root: Path | None = None,
    overwrite: bool = False,
) -> dict[str, str]:
    """Create authoritative WORKFLOW.md (0600) + isolated non-authoritative PROJECT_MAP.md / PITFALLS.md / feature-map.json."""
    croot = config_root or default_config_root()
    sroot = state_root or default_state_root()
    ws_resolved = workspace_path.expanduser().resolve()

    inferred_verify, inferred_scope, repo_notes = _infer_repo_defaults(ws_resolved)
    eff_verify = verify_cmd if verify_cmd is not None else (inferred_verify if kind == "issue" else "")
    eff_scope = tuple(write_scope if write_scope is not None else (inferred_scope if kind == "issue" else []))

    proj_cfg_dir = ensure_secure_dir(croot / "projects" / project_id, 0o700)
    workflow_path = proj_cfg_dir / "WORKFLOW.md"

    default_body = prompt_body or (
        f"# {project_id} Autopilot Authoritative Contract\n\n"
        f"- Kind: `{kind}` | Workspace: `{ws_resolved}`\n"
        f"- Base Branch: `{authorized_base_ref}` | Branch Prefix: `{branch_prefix}` | Tier: `{trust_tier}`\n"
        f"- Notes: {repo_notes}\n"
    )
    cfg = WorkflowConfig(
        project_id=project_id,
        kind=kind,
        enabled=enabled,
        repos=tuple(repos or []),
        workspace_path=str(ws_resolved),
        authorized_base_ref=authorized_base_ref,
        branch_prefix=branch_prefix,
        trust_tier=trust_tier,
        max_in_progress=1,
        max_per_day=24 if kind == "routine" else 5,
        write_scope=eff_scope,
        verify_cmd=eff_verify,
        writer_family=writer_family,
        schedule_interval_sec=schedule_interval_sec,
        routine_driver=routine_driver,
        delegated_cmd=delegated_cmd,
        token_file=token_file,
        extra=dict(extra or {}),
        prompt_body=default_body,
    )

    if overwrite or not workflow_path.exists():
        workflow_path.write_text(render_workflow_markdown(cfg), encoding="utf-8")
        os.chmod(workflow_path, 0o600)

    # Non-authoritative advisory files (Principle 02 + 03 + 05)
    adv_dir = ensure_secure_dir(sroot / "advisory" / project_id, 0o700)
    exemplars = _discover_exemplar_files(ws_resolved) if kind in ("issue", "delegated") else {}

    fmap_path = adv_dir / "feature-map.json"
    fmap_path.write_text(
        json.dumps(
            {
                "project_id": project_id,
                "generated_at": now_iso(),
                "authoritative": False,
                "exemplar_files_by_module": exemplars,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    pmap_path = adv_dir / "PROJECT_MAP.md"
    if overwrite or not pmap_path.exists():
        exemplar_lines = "\n".join(
            f"- `{mod}`: " + ", ".join(f"`{f}`" for f in files)
            for mod, files in exemplars.items()
        ) or "- (Routine / non-code workspace)"
        pmap_path.write_text(
            f"# 5-Second Genius Map: `{project_id}` (Advisory Only)\n\n"
            f"- **Workspace**: `{ws_resolved}`\n"
            f"- **Repos**: {', '.join(repos or ['(local routine)'])}\n"
            f"- **Executable DoD Gate**: `{eff_verify or '(routine probe)'}`\n"
            f"- **Repo Rules**: {repo_notes}\n\n"
            f"## Golden Exemplar Files (Copy Idioms From Here)\n{exemplar_lines}\n",
            encoding="utf-8",
        )

    pit_path = adv_dir / "PITFALLS.md"
    if not pit_path.exists():
        pit_path.write_text(
            f"# {project_id} Pitfall Rules (Advisory — Excluded from Referee & Visual)\n\n",
            encoding="utf-8",
        )

    return {
        "project_id": project_id,
        "workflow_path": str(workflow_path),
        "advisory_dir": str(adv_dir),
        "project_map": str(pmap_path),
        "feature_map": str(fmap_path),
        "pitfalls": str(pit_path),
    }


def import_legacy_autopilot_state(
    *,
    db: AutopilotDB,
    legacy_state_dir: Path,
    backup_dir: Path,
    project_id: str = "default",
) -> dict[str, Any]:
    """Backup legacy autopilot state non-destructively (preserving mtimes), import terminal issues, and write tombstone."""
    import uuid as _uuid
    from .models import AutopilotError

    src = legacy_state_dir.resolve()
    dst = backup_dir.resolve()
    if src == dst or src in dst.parents or dst in src.parents:
        raise AutopilotError(f"Refusing overlapping legacy_state_dir={src} and backup_dir={dst}")

    ensure_secure_dir(dst.parent, 0o700)
    final_backup = dst
    if src.is_dir():
        stage_dst = dst.parent / f".{dst.name}.staging-{_uuid.uuid4().hex[:8]}"
        shutil.copytree(src, stage_dst, copy_function=shutil.copy2)
        src_files = sum(1 for p in src.rglob("*") if p.is_file())
        dst_files = sum(1 for p in stage_dst.rglob("*") if p.is_file())
        if src_files != dst_files:
            shutil.rmtree(stage_dst, ignore_errors=True)
            raise AutopilotError(f"Backup verification failed: {dst_files} != {src_files} files")
        if dst.exists():
            prev_dst = dst.parent / f"{dst.name}.prev-{_uuid.uuid4().hex[:8]}"
            os.replace(dst, prev_dst)
            os.replace(stage_dst, dst)
            shutil.rmtree(prev_dst, ignore_errors=True)
        else:
            os.replace(stage_dst, dst)

    imported: list[str] = []
    repo_to_pid: dict[str, str] = {}
    cfg_projects = default_config_root() / "projects"
    if cfg_projects.is_dir():
        from .models import parse_workflow_file
        for wf_p in sorted(cfg_projects.glob("*/WORKFLOW.md")):
            with contextlib.suppress(Exception):
                wfc = parse_workflow_file(wf_p)
                for rp in wfc.repos:
                    repo_to_pid[rp] = wfc.project_id
    state_sub = legacy_state_dir / "state"
    if state_sub.is_dir():
        for jf in sorted(state_sub.glob("*.json")):
            data = json.loads(jf.read_text(encoding="utf-8"))
            repo = str(data.get("repo") or "")
            num = data.get("issueNumber") or data.get("number")
            term = str(data.get("terminal") or "")
            if repo and num:
                ukey = f"{repo}#{int(num)}"
                eff_pid = repo_to_pid.get(repo, project_id)
                db.ensure_work_unit(unit_key=ukey, project_id=eff_pid, repo=repo, issue_number=int(num))
                if term == "done":
                    db.mark_unit_done(ukey)
                elif term:
                    db.mark_unit_needs_human(ukey, f"imported_legacy_terminal:{term}")
                imported.append(ukey)

    tombstone: Path | None = None
    if legacy_state_dir.is_dir():
        tombstone = legacy_state_dir / "runner.disabled"
        tombstone.write_text(
            json.dumps({"migrated_to": "agent-autopilot", "migrated_at": now_iso()}, indent=2) + "\n",
            encoding="utf-8",
        )
    return {
        "imported_units": imported,
        "backup_dir": str(backup_dir),
        "tombstone": str(tombstone) if tombstone else None,
    }
