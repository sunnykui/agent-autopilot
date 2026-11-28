"""Universal project onboarding: generates authoritative WORKFLOW.md + isolated advisory PROJECT_MAP & exemplars."""
from __future__ import annotations

import contextlib
import json
import os
import shlex
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
    candidates_roots = ["apps", "packages", "services", "crates", "src", "skills", "lib"]
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
        if "no tests allowed" in agents_txt.lower():
            # Repo policy explicitly forbids unit tests in AGENTS.md: rely on static typecheck + lint + format:check
            parts = [
                "pnpm run typecheck" if "typecheck" in scripts else "",
                "pnpm run lint" if "lint" in scripts else "",
                "pnpm run format:check" if "format:check" in scripts else "",
            ]
            vcmd = " && ".join(p for p in parts if p)
            scopes = [d + "/**" for d in ("apps", "packages", "dashboard", "src", "docs") if (repo_dir / d).is_dir()]
            return (
                vcmd or "pnpm -r --parallel typecheck",
                scopes or ["src/**"],
                "AGENTS.md declares no-test policy; static typecheck/lint gates enforced.",
            )
        if "test" in scripts and "typecheck" in scripts:
            scopes = [d + "/**" for d in ("apps", "packages", "services", "src", "skills") if (repo_dir / d).is_dir()]
            return ("pnpm run typecheck && pnpm test", scopes or ["apps/**", "packages/**", "src/**"], "Node/TS workspace.")
        if "typecheck" in scripts:
            scopes = [d + "/**" for d in ("apps", "packages", "services", "src", "skills") if (repo_dir / d).is_dir()]
            return ("pnpm run typecheck", scopes or ["apps/**", "packages/**", "src/**"], "Node/TS workspace.")
    nested_cargos = sorted(p for p in repo_dir.glob("*/Cargo.toml") if not p.parent.name.startswith("."))
    if (repo_dir / "Cargo.toml").is_file():
        member_scopes = [f"{p.parent.name}/**" for p in nested_cargos if p.parent.name not in ("src", "crates", "target")]
        base_rs = [d + "/**" for d in ("src", "crates") if (repo_dir / d).is_dir()] or ["src/**", "crates/**"]
        return ("cargo check", [*member_scopes, *base_rs], "Rust workspace.")
    if nested_cargos:
        first_rel = nested_cargos[0].relative_to(repo_dir)
        sub_name = first_rel.parts[0]
        return (
            f"cargo check --manifest-path {shlex.quote(first_rel.as_posix())}",
            [f"{sub_name}/**", "src/**"],
            f"Nested Rust workspace ({first_rel.as_posix()}).",
        )
    if (repo_dir / "scripts" / "check.sh").is_file():
        scopes = [d + "/**" for d in ("apps", "clusters", "scripts", "tests", "docs") if (repo_dir / d).is_dir()]
        return ("bash scripts/check.sh", scopes or ["scripts/**", "tests/**"], "Repo gate via scripts/check.sh.")
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
    referee_families: list[str] | tuple[str, ...] | None = None,
    verify_cmd: str | None = None,
    write_scope: list[str] | None = None,
    routine_driver: str = "",
    delegated_cmd: str = "",
    token_file: str = "",
    assignee: str = "@me",
    require_labels: list[str] | None = None,
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
        referee_families=tuple(str(x).strip() for x in (referee_families or []) if str(x).strip()),
        schedule_interval_sec=schedule_interval_sec,
        routine_driver=routine_driver or ("custom" if kind == "routine" else ""),
        delegated_cmd=delegated_cmd,
        token_file=token_file,
        assignee=assignee,
        require_labels=tuple(str(x).strip() for x in (require_labels or []) if str(x).strip()),
        extra=dict(extra or {}),
        prompt_body=default_body,
    )

    if overwrite or not workflow_path.exists():
        import uuid as _uuid
        from .models import parse_workflow_file

        rendered = render_workflow_markdown(cfg)
        tmp_wf = proj_cfg_dir / f".WORKFLOW.md.{_uuid.uuid4().hex[:8]}.tmp"
        try:
            tmp_wf.write_text(rendered, encoding="utf-8")
            os.chmod(tmp_wf, 0o600)
            # Validate candidate WORKFLOW.md with the authoritative parser BEFORE publishing!
            parse_workflow_file(tmp_wf)
            if overwrite:
                os.replace(tmp_wf, workflow_path)
            else:
                try:
                    # Atomic non-overwriting publish so concurrent first-time onboard cannot clobber!
                    os.link(tmp_wf, workflow_path)
                except FileExistsError:
                    pass
        finally:
            with contextlib.suppress(OSError):
                if tmp_wf.exists():
                    tmp_wf.unlink()

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
