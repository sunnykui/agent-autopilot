#!/usr/bin/env python3
"""codex-dispatch: Deterministic, token-saving Claude -> Codex CLI orchestrator.

Combines the strongest patterns from:
- oil-delegate: deterministic CLI wrapper, stdin prompt passing, JSONL session tracking
- openai/codex-plugin-cc: XML prompt contracts & grounded adversarial review
- cathrynlavery/codex-build: pre/post git baseline snapshot & executable file allowlist gate
- alexzh3/codex-orchestrator: fresh-session review isolation & stateful resume escalation

Zero external dependencies (Python 3.10+ stdlib only). Never uses danger-full-access.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

SCHEMA_VERSION = 1
DEFAULT_TIMEOUT = 1800  # 30 minutes max per CLAUDE.md bottom line
OUTSIDE_WS_PREFIX = "<OUTSIDE_WORKSPACE>:"

ROLE_DEFAULTS: dict[str, dict[str, str]] = {
    "explore": {"model": "gpt-6.2-sol", "effort": "low", "sandbox": "read-only"},
    "critique": {"model": "gpt-6.2-astra", "effort": "high", "sandbox": "read-only"},
    "implement": {"model": "gpt-6.2-sol", "effort": "medium", "sandbox": "workspace-write"},
    "review": {"model": "gpt-6.2-astra", "effort": "high", "sandbox": "read-only"},
    "visual": {"model": "gpt-6.1-terra", "effort": "medium", "sandbox": "read-only"},
}

TIER_PRESETS: dict[str, tuple[str, str]] = {
    "fast": ("gpt-6.2-sol", "low"),
    "std": ("gpt-6.2-sol", "medium"),
    "high": ("gpt-6.2-sol", "high"),
    "hard": ("gpt-6.2-astra", "high"),
    "xhigh": ("gpt-6.2-astra", "xhigh"),
    "visual": ("gpt-6.1-terra", "medium"),
}

FRESH_ONLY_ROLES = {"critique", "review"}
VALID_SANDBOXES = {"read-only", "workspace-write"}
TRANSIENT_CACHE_GLOBS = (
    "**/__pycache__/**",
    ".pytest_cache/**",
    "**/.pytest_cache/**",
    ".mypy_cache/**",
    "**/.mypy_cache/**",
    ".ruff_cache/**",
    "**/.ruff_cache/**",
)
TASK_ID_RE = re.compile(
    r"^\d{8}-\d{6}-(explore|critique|implement|review|visual)-[0-9a-f]{6}$"
)


class DispatchError(Exception):
    """Deterministic setup or validation error before/during dispatch."""


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def now_iso() -> str:
    return now_utc().replace(microsecond=0).isoformat()


def resolve_cache_root(explicit: str | None = None) -> Path:
    raw = explicit or os.environ.get("CODEX_DISPATCH_HOME")
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".cache" / "agent-work" / "codex-dispatch").resolve()


def validate_task_dir(cache_root: Path, task_id: str) -> Path:
    if not TASK_ID_RE.match(task_id):
        raise DispatchError(f"Invalid task_id format: {task_id!r}")
    candidate = cache_root / task_id
    if candidate.is_symlink():
        raise DispatchError(f"Refusing symlinked task directory: {candidate}")
    resolved = candidate.resolve()
    if resolved.parent != cache_root.resolve():
        raise DispatchError(f"Task directory escapes cache root: {task_id!r}")
    return resolved


@contextlib.contextmanager
def task_lock(run_dir: Path, *, blocking: bool = False) -> Iterator[None]:
    lock_path = run_dir / ".lock"
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        try:
            fcntl.flock(fd, flags)
        except BlockingIOError as exc:
            raise DispatchError(f"Task '{run_dir.name}' is currently locked by another active process.") from exc
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def resolve_codex_bin() -> str:
    override = os.environ.get("CODEX_DISPATCH_BIN")
    if override:
        path = Path(override).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve())
        raise DispatchError(f"CODEX_DISPATCH_BIN is not executable: {override}")
    found = shutil.which("codex")
    if found:
        return found
    for candidate in ("/usr/local/bin/codex", str(Path.home() / ".local/bin/codex")):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise DispatchError("Cannot find `codex` binary in PATH or standard locations.")


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def split_patterns(raw_items: list[str] | None) -> list[str]:
    patterns: list[str] = []
    for item in raw_items or []:
        for part in item.split(","):
            cleaned = part.strip()
            if cleaned and cleaned not in patterns:
                patterns.append(cleaned)
    return patterns


def normalize_rel_path(rel_path: str) -> str:
    """Normalize slash separators and leading `./` WITHOUT stripping significant whitespace in filenames."""
    norm = rel_path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    while len(norm) > 1 and norm.endswith("/"):
        norm = norm[:-1]
    return norm


def _segment_to_regex(seg: str) -> str:
    out: list[str] = []
    i = 0
    n = len(seg)
    while i < n:
        ch = seg[i]
        if ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[":
            j = i + 1
            if j < n and seg[j] in ("!", "^"):
                j += 1
            if j < n and seg[j] == "]":
                j += 1
            while j < n and seg[j] != "]":
                j += 1
            if j < n:
                inner = seg[i + 1 : j].replace("\\", "\\\\")
                if inner.startswith("!"):
                    inner = "^" + inner[1:]
                out.append(f"[{inner}]")
                i = j + 1
            else:
                out.append(re.escape(ch))
                i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    return "".join(out)


def compile_anchored_pattern(pattern: str) -> re.Pattern[str]:
    """Compile a workspace-root-anchored glob where `*` NEVER crosses `/` and `**` matches 0+ segments."""
    pat = normalize_rel_path(pattern.strip())
    if pat in ("*", "**"):
        return re.compile(r"^.+$")
    has_glob = any(c in pat for c in ("*", "?", "["))
    if not has_glob:
        esc = re.escape(pat)
        return re.compile(rf"^{esc}(?:/.*)?$")

    parts = pat.split("/")
    regex_parts: list[str] = ["^"]
    idx = 0
    total = len(parts)
    while idx < total:
        seg = parts[idx]
        if seg == "**":
            while idx + 1 < total and parts[idx + 1] == "**":
                idx += 1
            if idx == total - 1:
                # Trailing `/**`: matches directory itself (if prefix exists) or anything underneath
                if regex_parts[-1] == "/":
                    regex_parts.pop()
                    regex_parts.append(r"(?:/.*)?")
                else:
                    regex_parts.append(r".*")
            else:
                # Leading or middle `**/`: zero or more path segments
                regex_parts.append(r"(?:.+/)?")
            idx += 1
            continue

        regex_parts.append(_segment_to_regex(seg))
        if idx < total - 1 and parts[idx + 1] != "**":
            regex_parts.append("/")
        elif idx < total - 1 and parts[idx + 1] == "**":
            regex_parts.append("/")
        idx += 1

    regex_parts.append("$")
    return re.compile("".join(regex_parts))


def matches_pattern(rel_path: str, pattern: str) -> bool:
    """Match workspace-relative POSIX path against root-anchored glob or directory prefix."""
    if rel_path.startswith(OUTSIDE_WS_PREFIX):
        return False
    path_str = normalize_rel_path(rel_path)
    pat = normalize_rel_path(pattern.strip())
    if not pat or not path_str:
        return False
    return bool(compile_anchored_pattern(pat).match(path_str))


def check_scope(
    touched_files: list[str],
    allow_patterns: list[str],
    forbid_patterns: list[str],
) -> tuple[bool, list[str]]:
    """Verify touched files stay inside workspace and obey forbidlist + allowlist."""
    violations: list[str] = []
    for rel in touched_files:
        if rel.startswith(OUTSIDE_WS_PREFIX):
            violations.append(f"{rel} (modified outside workspace subdirectory)")
            continue
        if any(matches_pattern(rel, pat) for pat in forbid_patterns):
            violations.append(f"{rel} (matches forbidden path)")
            continue
        if allow_patterns and not any(matches_pattern(rel, pat) for pat in allow_patterns):
            violations.append(f"{rel} (outside allowed scope)")
    return (len(violations) == 0), violations


def run_git(workspace: Path, args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(workspace),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def detect_git_repo(workspace: Path) -> Path | None:
    proc = run_git(workspace, ["rev-parse", "--show-toplevel"])
    if proc.returncode != 0:
        return None
    top = proc.stdout.rstrip("\r\n")
    return Path(top).resolve() if top else None


def entry_fingerprint(path: Path) -> str:
    """Capture type, mode bits, and content/target digest WITHOUT following leaf symlinks."""
    try:
        st = path.lstat()
    except OSError:
        return "missing"
    mode = st.st_mode
    if os.path.islink(path):
        try:
            return f"link:{mode:o}:{os.readlink(path)}"
        except OSError:
            return f"link:{mode:o}:unreadable"
    if not os.path.isfile(path):
        return f"other:{mode:o}:{st.st_size}:{st.st_mtime_ns}"
    if st.st_size > 20 * 1024 * 1024:
        return f"large:{mode:o}:{st.st_size}:{st.st_mtime_ns}"
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return f"unreadable:{mode:o}"
    return f"file:{mode:o}:{h.hexdigest()}"


def parse_porcelain_entries(output: str) -> dict[str, str]:
    """Parse `git status --porcelain=v1 -z` into {repo_rel_path: xy_code} preserving exact names."""
    tokens = output.split("\0")
    entries: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if not tok or len(tok) < 4:
            i += 1
            continue
        xy = tok[:2]
        path_part = normalize_rel_path(tok[3:])
        if path_part:
            entries[path_part] = xy
        if "R" in xy or "C" in xy:
            if i + 1 < len(tokens) and tokens[i + 1]:
                orig = normalize_rel_path(tokens[i + 1])
                if orig:
                    entries[orig] = f"{xy}:orig"
            i += 2
            continue
        i += 1
    return entries


def _repo_rel_to_workspace_rel(git_root: Path, workspace: Path, repo_rel: str) -> str:
    """Lexically map repo-relative path to workspace-relative path WITHOUT following symlinks."""
    ws_rel_prefix = ""
    if workspace != git_root:
        try:
            ws_rel_prefix = normalize_rel_path(str(workspace.relative_to(git_root)))
        except ValueError:
            return f"{OUTSIDE_WS_PREFIX}{repo_rel}"
    if not ws_rel_prefix or ws_rel_prefix == ".":
        return repo_rel
    if repo_rel == ws_rel_prefix:
        return "."
    prefix_slash = ws_rel_prefix + "/"
    if repo_rel.startswith(prefix_slash):
        return repo_rel[len(prefix_slash) :]
    return f"{OUTSIDE_WS_PREFIX}{repo_rel}"


def capture_baseline(workspace: Path, *, include_ignored: bool = False) -> dict[str, Any]:
    git_root = detect_git_repo(workspace)
    if git_root is not None:
        head_proc = run_git(git_root, ["rev-parse", "--verify", "HEAD"])
        head_sha = head_proc.stdout.strip() if head_proc.returncode == 0 else None
        status_args = ["status", "--porcelain=v1", "-z", "-uall"]
        if include_ignored:
            status_args.append("--ignored=matching")
        status_proc = run_git(git_root, status_args)
        if status_proc.returncode != 0:
            raise DispatchError(f"`git status` failed while capturing baseline: {status_proc.stderr.strip()}")
        porcelain = parse_porcelain_entries(status_proc.stdout)
        index_proc = run_git(git_root, ["diff", "--cached", "--raw", "--no-abbrev", "-z"])
        index_sig = hashlib.sha256(index_proc.stdout.encode("utf-8", errors="surrogateescape")).hexdigest()
        states: dict[str, str] = {}
        for rel, xy in porcelain.items():
            states[rel] = f"{xy}|{entry_fingerprint(git_root / rel)}"
        return {
            "is_git": True,
            "include_ignored": include_ignored,
            "root": str(git_root),
            "head": head_sha,
            "index_sig": index_sig,
            "entry_states": states,
        }

    file_states: dict[str, str] = {}
    for root, dirs, files in os.walk(workspace, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git"]
        root_path = Path(root)
        # Also record symlinked directories themselves
        for dname in list(dirs):
            dpath = root_path / dname
            if dpath.is_symlink():
                rel_d = normalize_rel_path(str(dpath.relative_to(workspace)))
                file_states[rel_d] = entry_fingerprint(dpath)
        for fname in files:
            fpath = root_path / fname
            rel = normalize_rel_path(str(fpath.relative_to(workspace)))
            file_states[rel] = entry_fingerprint(fpath)
    return {
        "is_git": False,
        "include_ignored": include_ignored,
        "root": str(workspace),
        "head": None,
        "file_states": file_states,
    }


def compute_post_delta(workspace: Path, baseline: dict[str, Any]) -> dict[str, Any]:
    include_ignored = bool(baseline.get("include_ignored", False))
    if baseline.get("is_git"):
        git_root = Path(baseline["root"])
        head_proc = run_git(git_root, ["rev-parse", "--verify", "HEAD"])
        post_head = head_proc.stdout.strip() if head_proc.returncode == 0 else None
        head_changed = baseline.get("head") != post_head

        status_args = ["status", "--porcelain=v1", "-z", "-uall"]
        if include_ignored:
            status_args.append("--ignored=matching")
        status_proc = run_git(git_root, status_args)
        if status_proc.returncode != 0:
            raise DispatchError(f"`git status` failed during post-run verification: {status_proc.stderr.strip()}")
        post_porcelain = parse_porcelain_entries(status_proc.stdout)
        pre_states: dict[str, str] = baseline.get("entry_states", {})

        post_states: dict[str, str] = {}
        for rel, xy in post_porcelain.items():
            post_states[rel] = f"{xy}|{entry_fingerprint(git_root / rel)}"

        touched_repo_rel: set[str] = set()
        for rel, cur_state in post_states.items():
            if pre_states.get(rel) != cur_state:
                touched_repo_rel.add(rel)
        for rel, old_state in pre_states.items():
            if rel not in post_states:
                # Reverted, staged-and-committed, or deleted dirty file
                old_fp = old_state.split("|", 1)[1] if "|" in old_state else ""
                cur_fp = entry_fingerprint(git_root / rel)
                if cur_fp != old_fp or old_state[:2].strip():
                    touched_repo_rel.add(rel)

        if head_changed and baseline.get("head") and post_head:
            diff_names = run_git(git_root, ["diff", "--name-only", "-z", baseline["head"], post_head])
            if diff_names.returncode == 0:
                for tok in diff_names.stdout.split("\0"):
                    if tok:
                        touched_repo_rel.add(normalize_rel_path(tok))

        touched_ws_rel = sorted(
            _repo_rel_to_workspace_rel(git_root, workspace, rel) for rel in touched_repo_rel
        )

        diff_stat = ""
        if touched_repo_rel and post_head:
            stat_proc = run_git(git_root, ["diff", "--stat", "HEAD", "--", *sorted(touched_repo_rel)])
            diff_stat = stat_proc.stdout.strip() if stat_proc.returncode == 0 else ""

        return {
            "head_changed": head_changed,
            "pre_head": baseline.get("head"),
            "post_head": post_head,
            "touched_files": touched_ws_rel,
            "diff_stat": diff_stat,
        }

    post_snap = capture_baseline(workspace, include_ignored=include_ignored)
    pre_files: dict[str, str] = baseline.get("file_states", {})
    post_files: dict[str, str] = post_snap.get("file_states", {})
    touched_non_git = sorted(
        {k for k, v in post_files.items() if pre_files.get(k) != v}
        | {k for k in pre_files if k not in post_files}
    )
    return {
        "head_changed": False,
        "pre_head": None,
        "post_head": None,
        "touched_files": touched_non_git,
        "diff_stat": "",
    }


def create_managed_worktree(workspace: Path, run_dir: Path) -> Path:
    git_root = detect_git_repo(workspace)
    if git_root is None:
        raise DispatchError("--worktree requires a Git repository.")
    wt_root = run_dir / "worktree"
    proc = run_git(git_root, ["worktree", "add", "--detach", str(wt_root), "HEAD"], timeout=60)
    if proc.returncode != 0:
        raise DispatchError(f"Failed to create isolated git worktree: {proc.stderr.strip()}")
    if workspace != git_root:
        sub_rel = workspace.relative_to(git_root)
        return (wt_root / sub_rel).resolve()
    return wt_root.resolve()


def validate_entry_files(workspace: Path, raw_files: list[str] | None) -> list[str]:
    validated: list[str] = []
    for item in split_patterns(raw_files):
        p = Path(item).expanduser()
        candidate = p if p.is_absolute() else (workspace / p)
        if not candidate.exists() and not candidate.is_symlink():
            raise DispatchError(f"Entry file/path does not exist: {item} (checked: {candidate})")
        try:
            validated.append(str(candidate.resolve().relative_to(workspace.resolve())))
        except ValueError:
            validated.append(str(candidate))
    return validated


def compose_prompt(
    *,
    role: str,
    user_prompt: str,
    workspace: Path,
    entry_files: list[str],
    allow_patterns: list[str],
    forbid_patterns: list[str],
    verify_cmd: str | None,
    base_ref: str | None = None,
    commit_sha: str | None = None,
    uncommitted: bool = False,
) -> str:
    blocks: list[str] = []

    default_task = user_prompt.strip()
    if not default_task and role == "review":
        default_task = "Perform a thorough adversarial review of the specified repository changes."
    task_lines = [default_task]
    if role == "review":
        if base_ref:
            task_lines.append(f"\nReview target: git diff `{base_ref}...HEAD` plus any uncommitted/untracked changes.")
        elif commit_sha:
            task_lines.append(f"\nReview target: commit `{commit_sha}` (`git show {commit_sha}`).")
        elif uncommitted:
            task_lines.append("\nReview target: all staged, unstaged, and untracked changes in workspace.")
    if entry_files:
        task_lines.append("\nEntry paths to inspect first:\n" + "\n".join(f"- `{p}`" for p in entry_files))
    blocks.append("<task>\n" + "\n".join(task_lines) + "\n</task>")

    if role == "explore":
        blocks.extend(
            [
                "<grounding_rules>\n"
                "- Read-only investigation: do NOT create, edit, or delete any files.\n"
                "- Cite exact `file:line` locations for every architectural claim, call chain, and interface.\n"
                "- Explicitly list existing reusable modules, helpers, types, and test commands so the caller will not duplicate code.\n"
                "- Distinguish verified code facts from hypotheses.\n"
                "</grounding_rules>",
                "<compact_output_contract>\n"
                "Return a dense, high-signal Markdown brief (aim <= 45 lines):\n"
                "1. Key entrypoints & call flow (`file:line`)\n"
                "2. Existing abstractions/utilities to reuse\n"
                "3. Constraints, invariants, or pitfalls discovered\n"
                "4. Exact fast test/typecheck commands available in this repo\n"
                "</compact_output_contract>",
            ]
        )
    elif role == "critique":
        blocks.extend(
            [
                "<operating_stance>\n"
                "You are performing a pre-implementation architectural critique in read-only mode.\n"
                "Inspect the actual repository code first. Challenge over-engineering, duplicate abstractions, leaky boundaries, hidden coupling, state/concurrency hazards, and missing edge cases.\n"
                "</operating_stance>",
                "<grounding_rules>\n"
                "- Read-only mode: do NOT modify any files.\n"
                "- Anchor every critique to concrete existing files, types, and patterns in this repository.\n"
                "- Prefer simpler, more cohesive designs that reuse existing codebase primitives.\n"
                "</grounding_rules>",
                "<structured_output_contract>\n"
                "Return a concise architectural verdict:\n"
                "1. Verdict (`sound` | `revise-before-coding`) & core reasoning\n"
                "2. Existing modules/patterns in the repo that MUST be reused\n"
                "3. Material design flaws, coupling risks, or edge cases to fix in the plan\n"
                "4. Recommended clean public interface / file boundary contract\n"
                "</structured_output_contract>",
            ]
        )
    elif role == "implement":
        scope_lines = [
            f"- Workspace root: `{workspace}`",
            "- Forbidden git actions: NEVER run `git commit`, `git push`, `git reset --hard`, `git checkout --`, or modify files outside workspace.",
            "- Avoid unrelated refactors, drive-by formatting, or adding unrequested dependencies.",
        ]
        if allow_patterns:
            scope_lines.append("- Allowed write paths ONLY (root-anchored): " + ", ".join(f"`{p}`" for p in allow_patterns))
        if forbid_patterns:
            scope_lines.append("- Strictly forbidden paths: " + ", ".join(f"`{p}`" for p in forbid_patterns))

        verify_lines = [
            "- Prefer fast, targeted compile/typecheck/unit checks while iterating instead of running slow full suites repeatedly."
        ]
        if verify_cmd:
            verify_lines.append(f"- Required verification command before finishing: `{verify_cmd}`")
        verify_lines.append("- Verify edge cases, error paths, and type coherence before stopping.")

        blocks.extend(
            [
                "<default_follow_through_policy>\n"
                "Act autonomously as a senior software engineer in a non-interactive run. Do NOT pause to ask clarifying questions on local implementation details: inspect surrounding code, follow idiomatic repository conventions, make clean cohesive engineering choices within the contract, and carry the implementation all the way to verified completion.\n"
                "Stop early ONLY if fulfilling the request requires violating the file scope, breaking an explicit public contract, or performing a destructive action.\n"
                "</default_follow_through_policy>",
                "<code_elegance_and_action_safety>\n"
                + "\n".join(scope_lines)
                + "\n- Write clean, modular, idiomatic code with clear single-responsibility boundaries; reuse existing helpers and types rather than duplicating logic.\n"
                "</code_elegance_and_action_safety>",
                "<verification_loop>\n" + "\n".join(verify_lines) + "\n</verification_loop>",
                "<structured_output_contract>\n"
                "Output ONLY a concise engineering handoff (<= 30 lines):\n"
                "1. Touched files & key design choices made\n"
                "2. Exact verification commands executed and pass/fail results\n"
                "3. Any remaining risks, blockers, or unverified edge cases\n"
                "</structured_output_contract>",
            ]
        )
    elif role == "review":
        blocks.extend(
            [
                "<operating_stance>\n"
                "You are performing an independent adversarial code & architecture review in read-only mode.\n"
                "Default to skepticism: actively try to disprove correctness, find race conditions, broken invariants, partial-failure bugs, auth/trust leaks, compatibility regressions, scope creep, or architectural bloat.\n"
                "Report ONLY material findings backed by code evidence. Zero style nitpicks or filler.\n"
                "</operating_stance>",
                "<grounding_rules>\n"
                "- Read-only mode: do NOT modify any files or git state.\n"
                "- Inspect both tracked diffs (`git status`, `git diff`) AND any untracked new files, plus surrounding callers.\n"
                "- Every finding MUST include exact `file:line_start-line_end`, concrete failure scenario, and minimal fix.\n"
                "</grounding_rules>",
                "<structured_output_contract>\n"
                "Return a terse review:\n"
                "1. Verdict: `APPROVE` or `NEEDS_REWORK`\n"
                "2. Material findings ordered by severity (`[HIGH|MED] file:lines — bug/failure mode -> concrete fix`), or `None` if clean\n"
                "3. Critical edge case(s) verified or still unverified\n"
                "</structured_output_contract>",
            ]
        )
    else:  # visual
        blocks.extend(
            [
                "<grounding_rules>\n"
                "Read-only visual & code inspection: do NOT modify files. Cross-check attached visual image(s) against actual layout/component code and report concrete visual/UI defects with exact file paths.\n"
                "</grounding_rules>"
            ]
        )

    return "\n\n".join(blocks) + "\n"


def compose_resume_prompt(
    *,
    delta_prompt: str,
    allow_patterns: list[str],
    forbid_patterns: list[str],
    verify_cmd: str | None,
) -> str:
    lines = [
        "<rework_delta>",
        delta_prompt.strip(),
        "</rework_delta>",
        "",
        "<rework_constraints>",
        "- Fix the exact issues above completely without introducing regressions or touching out-of-scope files.",
        "- Do NOT run `git commit` or `git push`.",
    ]
    if allow_patterns:
        lines.append("- Allowed write paths ONLY: " + ", ".join(f"`{p}`" for p in allow_patterns))
    if forbid_patterns:
        lines.append("- Forbidden paths: " + ", ".join(f"`{p}`" for p in forbid_patterns))
    if verify_cmd:
        lines.append(f"- Re-run and pass verification command before finishing: `{verify_cmd}`")
    lines.extend(
        [
            "- End with a brief summary (<= 20 lines): what changed, verification results, any remaining blocker.",
            "</rework_constraints>",
        ]
    )
    return "\n".join(lines) + "\n"


def build_codex_command(
    *,
    codex_bin: str,
    model: str,
    effort: str,
    sandbox: str,
    summary_path: Path,
    is_git: bool,
    session_id: str | None = None,
    allow_network: bool = False,
    images: list[str] | None = None,
    native_review: bool = False,
    base_ref: str | None = None,
    uncommitted: bool = False,
    commit_sha: str | None = None,
    has_prompt: bool = True,
) -> list[str]:
    if session_id:
        cmd = [
            codex_bin,
            "exec",
            "resume",
            "--json",
            "-m",
            model,
            "-c",
            f'model_reasoning_effort="{effort}"',
            "-c",
            f'sandbox_mode="{sandbox}"',
            "-o",
            str(summary_path),
        ]
        if allow_network and sandbox == "workspace-write":
            cmd.extend(["-c", "sandbox_workspace_write.network_access=true"])
        if not is_git:
            cmd.append("--skip-git-repo-check")
        for img in images or []:
            cmd.extend(["-i", img])
        cmd.append(session_id)
        cmd.append("-")
        return cmd

    if native_review:
        if has_prompt and (base_ref or commit_sha or uncommitted):
            raise DispatchError(
                "Native `codex exec review` cannot combine `--base`/`--commit`/`--uncommitted` with custom focus text. "
                "Omit `--native` to run steerable adversarial review with both target flags and custom focus."
            )
        cmd = [
            codex_bin,
            "exec",
            "review",
            "--json",
            "-m",
            model,
            "-c",
            f'model_reasoning_effort="{effort}"',
            "-o",
            str(summary_path),
        ]
        if base_ref:
            cmd.extend(["--base", base_ref])
        elif commit_sha:
            cmd.extend(["--commit", commit_sha])
        elif uncommitted or not has_prompt:
            cmd.append("--uncommitted")
        else:
            cmd.append("-")
        return cmd

    cmd = [
        codex_bin,
        "exec",
        "--json",
        "-s",
        sandbox,
        "-m",
        model,
        "-c",
        f'model_reasoning_effort="{effort}"',
        "-o",
        str(summary_path),
    ]
    if not is_git:
        cmd.append("--skip-git-repo-check")
    if allow_network and sandbox == "workspace-write":
        cmd.extend(["-c", "sandbox_workspace_write.network_access=true"])
    for img in images or []:
        cmd.extend(["-i", img])
    cmd.append("-")
    return cmd


def _find_session_id_in_obj(obj: Any) -> str | None:
    if not isinstance(obj, dict):
        return None
    for key in ("thread_id", "session_id", "conversation_id"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    if obj.get("type") in ("session_meta", "thread.started"):
        payload = obj.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("id"), str):
            return payload["id"].strip()
    for nested_key in ("payload", "thread", "session"):
        nested = _find_session_id_in_obj(obj.get(nested_key))
        if nested:
            return nested
    return None


def parse_codex_execution(
    *,
    raw_stdout: str,
    raw_stderr: str,
    exit_code: int,
    summary_path: Path,
    prior_session_id: str | None = None,
) -> dict[str, Any]:
    session_id = prior_session_id
    agent_messages: list[str] = []
    errors: list[str] = []
    turn_completed = False

    # Split strictly on LF so U+2028/U+2029 inside JSON strings never corrupt JSONL parsing
    for line in raw_stdout.split("\n"):
        stripped = line.rstrip("\r").strip()
        if not stripped.startswith("{"):
            continue
        try:
            ev = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(ev, dict):
            continue
        if not session_id:
            session_id = _find_session_id_in_obj(ev)
        ev_type = ev.get("type")
        if ev_type == "turn.completed":
            turn_completed = True
        elif ev_type == "item.completed":
            item = ev.get("item")
            if isinstance(item, dict) and item.get("type") in ("agent_message", "message"):
                txt = item.get("text")
                if isinstance(txt, str) and txt.strip():
                    agent_messages.append(txt.strip())
        elif ev_type in ("turn.failed", "error"):
            err_obj = ev.get("error") or ev.get("message") or ev
            if isinstance(err_obj, dict):
                errors.append(str(err_obj.get("message") or err_obj))
            else:
                errors.append(str(err_obj))

    summary_text = ""
    if summary_path.is_file():
        try:
            summary_text = summary_path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            summary_text = ""
    # Only fall back to JSONL agent_message when the turn genuinely completed
    if not summary_text and turn_completed and agent_messages:
        summary_text = agent_messages[-1]

    ok = (exit_code == 0) and bool(summary_text) and not errors
    err_detail = "; ".join(errors)
    if not ok and not err_detail:
        stderr_tail = "\n".join(raw_stderr.strip().split("\n")[-12:]).strip()
        if exit_code != 0:
            err_detail = f"codex exited with code {exit_code}" + (f": {stderr_tail}" if stderr_tail else "")
        elif not summary_text:
            err_detail = "codex produced an empty or incomplete summary output" + (
                f" ({stderr_tail})" if stderr_tail else ""
            )

    return {
        "ok": ok,
        "session_id": session_id,
        "summary": summary_text,
        "error": err_detail or None,
    }


def _terminate_process_group(proc: subprocess.Popen[str]) -> tuple[str, str]:
    pgid = proc.pid
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGTERM)
    try:
        out, err = proc.communicate(timeout=4)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(pgid, signal.SIGKILL)
        try:
            out, err = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            # Close pipes so detached grandchildren holding fds cannot block forever
            if proc.stdout:
                with contextlib.suppress(OSError):
                    proc.stdout.close()
            if proc.stderr:
                with contextlib.suppress(OSError):
                    proc.stderr.close()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=2)
            out, err = "", ""
    # Ensure no lingering survivor in the process group
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)
    return out or "", err or ""


def execute_process(
    cmd: list[str],
    *,
    cwd: Path,
    stdin_text: str | None,
    timeout: int,
) -> tuple[int, str, str, bool]:
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    timed_out = False
    try:
        out, err = proc.communicate(input=stdin_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        out, err = _terminate_process_group(proc)
    return (proc.returncode if proc.returncode is not None else -1), out or "", err or "", timed_out


def run_verify_command(workspace: Path, verify_cmd: str, timeout: int = 300) -> dict[str, Any]:
    t0 = time.monotonic()
    proc = subprocess.Popen(
        ["bash", "--noprofile", "--norc", "-c", verify_cmd],
        cwd=str(workspace),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    timed_out = False
    try:
        output, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        output, _ = _terminate_process_group(proc)
    elapsed = round(time.monotonic() - t0, 1)
    code = proc.returncode if not timed_out else 124
    lines = (output or "").strip().split("\n")
    tail = "\n".join(lines[-25:]).strip() if lines else ""
    return {
        "command": verify_cmd,
        "passed": (code == 0 and not timed_out),
        "exit_code": code,
        "timed_out": timed_out,
        "elapsed_sec": elapsed,
        "output_tail": tail,
    }


def filter_transient_caches(paths: list[str], forbid_patterns: list[str]) -> list[str]:
    """Ignore benign tool bytecode/linter caches in repos lacking .gitignore unless explicitly forbidden."""
    filtered: list[str] = []
    for p in paths:
        if any(matches_pattern(p, fp) for fp in forbid_patterns):
            filtered.append(p)
            continue
        if any(matches_pattern(p, cg) for cg in TRANSIENT_CACHE_GLOBS):
            continue
        filtered.append(p)
    return filtered


def evaluate_write_gates(
    *,
    exec_workspace: Path,
    baseline: dict[str, Any],
    allow_patterns: list[str],
    forbid_patterns: list[str],
    verify_cmd: str | None,
    codex_ok: bool,
) -> dict[str, Any]:
    """Run scope & HEAD check BEFORE verify command, then re-check delta AFTER verify command."""
    delta = compute_post_delta(exec_workspace, baseline)
    delta["touched_files"] = filter_transient_caches(delta["touched_files"], forbid_patterns)
    scope_checked = bool(allow_patterns or forbid_patterns) or any(
        f.startswith(OUTSIDE_WS_PREFIX) for f in delta["touched_files"]
    )
    scope_ok, scope_violations = check_scope(delta["touched_files"], allow_patterns, forbid_patterns)

    verify_result: dict[str, Any] | None = None
    # Security & integrity invariant: NEVER execute `--verify` if HEAD or file scope was violated!
    if codex_ok and not delta["head_changed"] and scope_ok and verify_cmd:
        verify_result = run_verify_command(exec_workspace, verify_cmd)
        # Re-snapshot after `--verify` to ensure the test command itself didn't mutate forbidden/out-of-scope state
        delta = compute_post_delta(exec_workspace, baseline)
        delta["touched_files"] = filter_transient_caches(delta["touched_files"], forbid_patterns)
        scope_checked = bool(allow_patterns or forbid_patterns) or any(
            f.startswith(OUTSIDE_WS_PREFIX) for f in delta["touched_files"]
        )
        scope_ok, scope_violations = check_scope(delta["touched_files"], allow_patterns, forbid_patterns)

    return {
        "delta": delta,
        "scope_checked": scope_checked,
        "scope_ok": scope_ok,
        "scope_violations": scope_violations,
        "verify": verify_result,
    }


def read_prompt_input(args: argparse.Namespace, *, optional: bool = False) -> str:
    if getattr(args, "prompt_file", None):
        p = Path(args.prompt_file).expanduser().resolve()
        if not p.is_file():
            raise DispatchError(f"Prompt file not found: {p}")
        text = p.read_text(encoding="utf-8")
    elif getattr(args, "prompt", None) and args.prompt != "-":
        text = args.prompt
    elif not sys.stdin.isatty() or getattr(args, "prompt", None) == "-":
        text = sys.stdin.read()
    else:
        text = ""

    cleaned = text.strip()
    if not cleaned and not optional:
        raise DispatchError("Prompt is empty. Pass via stdin (`<<'EOF'`), `--prompt`, or `--prompt-file`.")
    return cleaned


def resolve_model_and_effort(
    role: str,
    tier: str | None,
    explicit_model: str | None,
    explicit_effort: str | None,
) -> tuple[str, str, str]:
    defaults = ROLE_DEFAULTS[role]
    model = defaults["model"]
    effort = defaults["effort"]
    sandbox = defaults["sandbox"]
    if tier:
        if tier not in TIER_PRESETS:
            raise DispatchError(f"Unknown --tier '{tier}'. Valid: {', '.join(TIER_PRESETS)}")
        model, effort = TIER_PRESETS[tier]
    if explicit_model:
        model = explicit_model
    if explicit_effort:
        effort = explicit_effort
    return model, effort, sandbox


def format_receipt(result: dict[str, Any]) -> str:
    lines = [
        f"=== codex-dispatch [{result['status']}] ===",
        f"task_id    : {result['task_id']}",
        f"session_id : {result.get('session_id') or 'none'}",
        f"role/model : {result['role']} | {result['model']} (effort={result['effort']}, sandbox={result['sandbox']})",
        f"elapsed    : {result['elapsed_sec']}s | artifacts: {result['run_dir']}",
    ]
    if result.get("worktree_path"):
        lines.append(f"worktree   : {result['worktree_path']}")
    if result.get("escalated"):
        lines.append(f"escalated  : auto-upgraded for rework #{result['rework_count']}")

    if result["sandbox"] == "workspace-write":
        touched = result.get("touched_files") or []
        lines.append(
            f"touched({len(touched)}): {', '.join(touched[:15]) if touched else '(none)'}"
            + (f" ... +{len(touched) - 15} more" if len(touched) > 15 else "")
        )
        if result.get("head_changed"):
            lines.append("git_guard  : VIOLATION — HEAD changed (unauthorized git commit detected!)")
        if result.get("scope_checked"):
            if result.get("scope_ok"):
                lines.append("scope_gate : PASS (all touched files within allowlist)")
            else:
                lines.append("scope_gate : VIOLATION — " + "; ".join(result.get("scope_violations") or []))
        if result.get("diff_stat"):
            lines.append("--- diff --stat ---")
            lines.extend(result["diff_stat"].splitlines()[:15])

    verify = result.get("verify")
    if verify:
        v_state = "PASS" if verify["passed"] else f"FAIL (exit {verify['exit_code']})"
        lines.append(f"verify_gate: {v_state} (`{verify['command']}`, {verify['elapsed_sec']}s)")
        if not verify["passed"] and verify.get("output_tail"):
            lines.append("--- verify failure tail ---")
            lines.extend(verify["output_tail"].splitlines()[-15:])

    if result.get("error"):
        lines.append(f"error      : {result['error']}")

    summary = (result.get("summary") or "").strip()
    if summary:
        lines.append("--- codex summary ---")
        lines.append(summary)
    return "\n".join(lines) + "\n"


def make_task_id(role: str) -> str:
    stamp = now_utc().strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{role}-{uuid.uuid4().hex[:6]}"


def cmd_dispatch_new(args: argparse.Namespace) -> int:
    role = args.role
    workspace = Path(args.cd or os.getcwd()).expanduser().resolve()
    if not workspace.is_dir():
        raise DispatchError(f"Workspace directory does not exist: {workspace}")

    native_review = bool(role == "review" and getattr(args, "native", False))
    has_review_target = bool(
        role == "review" and (getattr(args, "base", None) or getattr(args, "commit", None) or getattr(args, "uncommitted", False))
    )
    user_prompt = read_prompt_input(args, optional=(native_review or has_review_target))

    allow_patterns = split_patterns(getattr(args, "allow", None))
    forbid_patterns = split_patterns(getattr(args, "forbid", None))
    entry_files = validate_entry_files(workspace, getattr(args, "file", None))
    images = [str(Path(i).expanduser().resolve()) for i in (getattr(args, "image", None) or [])]
    for img in images:
        if not os.path.isfile(img):
            raise DispatchError(f"Image file does not exist: {img}")
    if images and role == "explore" and not args.model and not args.tier:
        role = "visual"

    model, effort, sandbox = resolve_model_and_effort(role, args.tier, args.model, args.effort)
    use_worktree = bool(getattr(args, "worktree", False) and sandbox == "workspace-write")

    cache_root = resolve_cache_root(args.state_dir)
    task_id = make_task_id(role)
    run_dir = cache_root / task_id
    summary_path = run_dir / "summary.md"
    prompt_path = run_dir / "prompt.md"
    events_path = run_dir / "events.jsonl"
    stderr_path = run_dir / "stderr.log"
    meta_path = run_dir / "meta.json"
    baseline_path = run_dir / "baseline.json"

    is_git_probe = detect_git_repo(workspace) is not None
    if use_worktree and not is_git_probe:
        raise DispatchError("--worktree requires a Git repository.")

    preview_prompt = (
        user_prompt
        if native_review
        else compose_prompt(
            role=role,
            user_prompt=user_prompt,
            workspace=workspace,
            entry_files=entry_files,
            allow_patterns=allow_patterns,
            forbid_patterns=forbid_patterns,
            verify_cmd=getattr(args, "verify", None),
            base_ref=getattr(args, "base", None),
            commit_sha=getattr(args, "commit", None),
            uncommitted=bool(getattr(args, "uncommitted", False)),
        )
    )

    codex_bin = resolve_codex_bin()
    cmd = build_codex_command(
        codex_bin=codex_bin,
        model=model,
        effort=effort,
        sandbox=sandbox,
        summary_path=summary_path,
        is_git=is_git_probe,
        allow_network=bool(getattr(args, "allow_network", False)),
        images=images,
        native_review=native_review,
        base_ref=getattr(args, "base", None),
        uncommitted=bool(getattr(args, "uncommitted", False)),
        commit_sha=getattr(args, "commit", None),
        has_prompt=bool(preview_prompt),
    )

    if getattr(args, "dry_run", False):
        payload = {
            "status": "DRY_RUN",
            "task_id": task_id,
            "role": role,
            "model": model,
            "effort": effort,
            "sandbox": sandbox,
            "workspace": str(workspace),
            "worktree": use_worktree,
            "command": cmd,
            "run_dir": str(run_dir),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    run_dir.mkdir(parents=True, exist_ok=True)
    with task_lock(run_dir):
        exec_workspace = create_managed_worktree(workspace, run_dir) if use_worktree else workspace
        composed_prompt = (
            user_prompt
            if native_review
            else compose_prompt(
                role=role,
                user_prompt=user_prompt,
                workspace=exec_workspace,
                entry_files=entry_files,
                allow_patterns=allow_patterns,
                forbid_patterns=forbid_patterns,
                verify_cmd=getattr(args, "verify", None),
                base_ref=getattr(args, "base", None),
                commit_sha=getattr(args, "commit", None),
                uncommitted=bool(getattr(args, "uncommitted", False)),
            )
        )
        include_ignored = bool(forbid_patterns)
        baseline = capture_baseline(exec_workspace, include_ignored=include_ignored)
        atomic_write_json(baseline_path, baseline)
        prompt_path.write_text(composed_prompt, encoding="utf-8")

        stdin_payload = composed_prompt if cmd[-1] == "-" else None
        t0 = time.monotonic()
        exit_code, raw_out, raw_err, timed_out = execute_process(
            cmd,
            cwd=exec_workspace,
            stdin_text=stdin_payload,
            timeout=args.timeout,
        )
        elapsed = round(time.monotonic() - t0, 1)

        events_path.write_text(raw_out, encoding="utf-8")
        stderr_path.write_text(raw_err, encoding="utf-8")

        parsed = parse_codex_execution(
            raw_stdout=raw_out,
            raw_stderr=raw_err,
            exit_code=124 if timed_out else exit_code,
            summary_path=summary_path,
        )
        if timed_out:
            parsed["ok"] = False
            parsed["error"] = f"Timed out after {args.timeout}s"

        gate_info: dict[str, Any] = {
            "delta": {},
            "scope_checked": False,
            "scope_ok": True,
            "scope_violations": [],
            "verify": None,
        }
        if sandbox == "workspace-write":
            gate_info = evaluate_write_gates(
                exec_workspace=exec_workspace,
                baseline=baseline,
                allow_patterns=allow_patterns,
                forbid_patterns=forbid_patterns,
                verify_cmd=getattr(args, "verify", None),
                codex_ok=parsed["ok"],
            )

        delta = gate_info["delta"]
        verify_result = gate_info["verify"]
        gates_ok = (
            parsed["ok"]
            and not delta.get("head_changed", False)
            and gate_info["scope_ok"]
            and (verify_result is None or verify_result["passed"])
        )
        status = "OK" if gates_ok else ("GATE_FAILED" if parsed["ok"] else "FAILED")

        result_record: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "status": status,
            "task_id": task_id,
            "session_id": parsed["session_id"],
            "role": role,
            "model": model,
            "effort": effort,
            "sandbox": sandbox,
            "workspace": str(workspace),
            "exec_workspace": str(exec_workspace),
            "worktree": use_worktree,
            "worktree_path": str(exec_workspace) if use_worktree else None,
            "is_git": bool(baseline.get("is_git")),
            "allow_network": bool(getattr(args, "allow_network", False)),
            "allow_patterns": allow_patterns,
            "forbid_patterns": forbid_patterns,
            "verify_cmd": getattr(args, "verify", None),
            "rework_count": 0,
            "elapsed_sec": elapsed,
            "run_dir": str(run_dir),
            "touched_files": delta.get("touched_files", []),
            "head_changed": delta.get("head_changed", False),
            "diff_stat": delta.get("diff_stat", ""),
            "scope_checked": gate_info["scope_checked"],
            "scope_ok": gate_info["scope_ok"],
            "scope_violations": gate_info["scope_violations"],
            "verify": verify_result,
            "summary": parsed["summary"],
            "error": parsed["error"],
        }
        atomic_write_json(meta_path, result_record)

    if getattr(args, "json", False):
        print(json.dumps(result_record, ensure_ascii=False, indent=2))
    else:
        sys.stdout.write(format_receipt(result_record))
    return 0 if status == "OK" else 1


def cmd_resume(args: argparse.Namespace) -> int:
    cache_root = resolve_cache_root(args.state_dir)
    run_dir = validate_task_dir(cache_root, args.task_id)
    meta_path = run_dir / "meta.json"
    if not meta_path.is_file():
        raise DispatchError(f"Unknown task_id '{args.task_id}' (no metadata at {meta_path})")

    delta_text = read_prompt_input(args, optional=False)

    with task_lock(run_dir):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("task_id") != args.task_id:
            raise DispatchError(f"Metadata task_id mismatch inside {meta_path}")
        role = meta.get("role")
        sandbox = meta.get("sandbox")
        if role not in ROLE_DEFAULTS or sandbox not in VALID_SANDBOXES:
            raise DispatchError(f"Corrupted role/sandbox metadata in {meta_path}")
        if role in FRESH_ONLY_ROLES and getattr(args, "write", False):
            raise DispatchError(
                f"Task '{args.task_id}' has role '{role}' (fresh read-only only); start a new `implement` task instead."
            )
        session_id = meta.get("session_id")
        if not session_id or not isinstance(session_id, str):
            raise DispatchError(f"Task '{args.task_id}' recorded no session_id; cannot resume. Start a fresh run.")

        exec_workspace = Path(meta.get("exec_workspace") or meta["workspace"]).resolve()
        if not exec_workspace.is_dir():
            raise DispatchError(f"Execution workspace no longer exists: {exec_workspace}")

        baseline_path = run_dir / "baseline.json"
        if sandbox == "workspace-write":
            if not baseline_path.is_file():
                raise DispatchError(
                    f"Missing original baseline.json for write task '{args.task_id}'; refusing unsafe resume."
                )
            initial_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        else:
            initial_baseline = (
                json.loads(baseline_path.read_text(encoding="utf-8"))
                if baseline_path.is_file()
                else {"is_git": detect_git_repo(exec_workspace) is not None}
            )
        is_git = bool(initial_baseline.get("is_git"))

        rework_num = int(meta.get("rework_count", 0)) + 1
        model = args.model or meta["model"]
        effort = args.effort or meta["effort"]
        escalated = False

        if (
            role == "implement"
            and not args.no_escalate
            and not args.model
            and not args.effort
            and (model != "gpt-6.2-astra" or effort in ("low", "medium"))
        ):
            model = "gpt-6.2-astra"
            effort = "high"
            escalated = True

        allow_patterns = split_patterns(args.allow) if args.allow else list(meta.get("allow_patterns") or [])
        forbid_patterns = split_patterns(args.forbid) if args.forbid else list(meta.get("forbid_patterns") or [])
        verify_cmd = args.verify if args.verify is not None else meta.get("verify_cmd")
        allow_network = bool(args.allow_network or meta.get("allow_network", False))

        step_tag = f"rework-{rework_num:02d}"
        summary_path = run_dir / f"{step_tag}-summary.md"
        prompt_path = run_dir / f"{step_tag}-prompt.md"
        events_path = run_dir / f"{step_tag}-events.jsonl"
        stderr_path = run_dir / f"{step_tag}-stderr.log"

        composed = (
            compose_resume_prompt(
                delta_prompt=delta_text,
                allow_patterns=allow_patterns,
                forbid_patterns=forbid_patterns,
                verify_cmd=verify_cmd,
            )
            if sandbox == "workspace-write"
            else delta_text + "\n"
        )

        codex_bin = resolve_codex_bin()
        cmd = build_codex_command(
            codex_bin=codex_bin,
            model=model,
            effort=effort,
            sandbox=sandbox,
            summary_path=summary_path,
            is_git=is_git,
            session_id=session_id,
            allow_network=allow_network,
        )

        if getattr(args, "dry_run", False):
            print(
                json.dumps(
                    {
                        "status": "DRY_RUN",
                        "task_id": args.task_id,
                        "session_id": session_id,
                        "rework_count": rework_num,
                        "escalated": escalated,
                        "model": model,
                        "effort": effort,
                        "sandbox": sandbox,
                        "exec_workspace": str(exec_workspace),
                        "command": cmd,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0

        prompt_path.write_text(composed, encoding="utf-8")

        t0 = time.monotonic()
        exit_code, raw_out, raw_err, timed_out = execute_process(
            cmd,
            cwd=exec_workspace,
            stdin_text=composed,
            timeout=args.timeout,
        )
        elapsed = round(time.monotonic() - t0, 1)

        events_path.write_text(raw_out, encoding="utf-8")
        stderr_path.write_text(raw_err, encoding="utf-8")

        parsed = parse_codex_execution(
            raw_stdout=raw_out,
            raw_stderr=raw_err,
            exit_code=124 if timed_out else exit_code,
            summary_path=summary_path,
            prior_session_id=session_id,
        )
        if timed_out:
            parsed["ok"] = False
            parsed["error"] = f"Timed out after {args.timeout}s"

        gate_info: dict[str, Any] = {
            "delta": {},
            "scope_checked": False,
            "scope_ok": True,
            "scope_violations": [],
            "verify": None,
        }
        if sandbox == "workspace-write":
            gate_info = evaluate_write_gates(
                exec_workspace=exec_workspace,
                baseline=initial_baseline,
                allow_patterns=allow_patterns,
                forbid_patterns=forbid_patterns,
                verify_cmd=verify_cmd,
                codex_ok=parsed["ok"],
            )

        delta = gate_info["delta"]
        verify_result = gate_info["verify"]
        gates_ok = (
            parsed["ok"]
            and not delta.get("head_changed", False)
            and gate_info["scope_ok"]
            and (verify_result is None or verify_result["passed"])
        )
        status = "OK" if gates_ok else ("GATE_FAILED" if parsed["ok"] else "FAILED")

        meta.update(
            {
                "updated_at": now_iso(),
                "status": status,
                "session_id": parsed["session_id"] or session_id,
                "model": model,
                "effort": effort,
                "allow_patterns": allow_patterns,
                "forbid_patterns": forbid_patterns,
                "verify_cmd": verify_cmd,
                "rework_count": rework_num,
                "escalated": escalated,
                "elapsed_sec": elapsed,
                "touched_files": delta.get("touched_files", []),
                "head_changed": delta.get("head_changed", False),
                "diff_stat": delta.get("diff_stat", ""),
                "scope_checked": gate_info["scope_checked"],
                "scope_ok": gate_info["scope_ok"],
                "scope_violations": gate_info["scope_violations"],
                "verify": verify_result,
                "summary": parsed["summary"],
                "error": parsed["error"],
            }
        )
        atomic_write_json(meta_path, meta)

    if getattr(args, "json", False):
        print(json.dumps(meta, ensure_ascii=False, indent=2))
    else:
        sys.stdout.write(format_receipt(meta))
    return 0 if status == "OK" else 1


def cmd_status(args: argparse.Namespace) -> int:
    cache_root = resolve_cache_root(args.state_dir)
    if args.task_id:
        run_dir = validate_task_dir(cache_root, args.task_id)
        meta_path = run_dir / "meta.json"
        if not meta_path.is_file():
            raise DispatchError(f"Task not found: {args.task_id}")
        print(meta_path.read_text(encoding="utf-8"))
        return 0

    if not cache_root.is_dir():
        print("No codex-dispatch tasks recorded yet.")
        return 0
    metas = sorted(cache_root.glob("*/meta.json"), reverse=True)[: args.limit]
    if not metas:
        print("No codex-dispatch tasks recorded yet.")
        return 0
    for mp in metas:
        if not TASK_ID_RE.match(mp.parent.name):
            continue
        try:
            m = json.loads(mp.read_text(encoding="utf-8"))
            st = str(m.get("status") or "UNKNOWN")
            rl = str(m.get("role") or "unknown")
            print(
                f"{m.get('task_id') or mp.parent.name} | {st:11s} | {rl:9s} | "
                f"{m.get('model') or '?'} ({m.get('effort') or '?'}) | rework={m.get('rework_count', 0)} | {m.get('workspace') or ''}"
            )
        except (OSError, json.JSONDecodeError):
            continue
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    cache_root = resolve_cache_root(args.state_dir)
    if not cache_root.is_dir():
        print("Nothing to clean.")
        return 0
    cutoff = time.time() - (args.days * 86400)
    removed = 0
    for entry in cache_root.iterdir():
        if entry.is_symlink() or not entry.is_dir() or not TASK_ID_RE.match(entry.name):
            continue
        meta_path = entry / "meta.json"
        if not meta_path.is_file():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if not isinstance(meta, dict) or meta.get("task_id") != entry.name:
                continue
            if entry.stat().st_mtime >= cutoff:
                continue
            with task_lock(entry, blocking=False):
                wt_path = meta.get("worktree_path")
                ws_path = meta.get("workspace")
                if wt_path and ws_path and os.path.isdir(ws_path):
                    run_git(Path(ws_path), ["worktree", "remove", "--force", str(entry / "worktree")])
                shutil.rmtree(entry)
                removed += 1
        except (OSError, json.JSONDecodeError, DispatchError):
            continue
    print(f"Cleaned {removed} verified task directories older than {args.days} days from {cache_root}.")
    return 0


def add_common_dispatch_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("-C", "--cd", help="Workspace root directory (defaults to current directory)")
    p.add_argument("-f", "--file", action="append", help="Verified entry file/dir paths (comma-separated or repeatable)")
    p.add_argument("--tier", choices=list(TIER_PRESETS), help="Model/effort preset (fast|std|high|hard|xhigh|visual)")
    p.add_argument("-m", "--model", help="Explicit Codex model override (e.g. gpt-6.2-astra, gpt-6.2-sol)")
    p.add_argument("--effort", help="Explicit reasoning effort override (low|medium|high|xhigh|max|ultra)")
    p.add_argument("--allow", action="append", help="Allowed write path globs/prefixes (comma-separated or repeatable)")
    p.add_argument("--forbid", action="append", help="Forbidden write path globs/prefixes")
    p.add_argument("--verify", help="Fast deterministic verification shell command to run after write task")
    p.add_argument("--worktree", action="store_true", help="Run write task in an isolated managed Git worktree")
    p.add_argument("--allow-network", action="store_true", help="Enable network inside workspace-write sandbox (requires user approval)")
    p.add_argument("-i", "--image", action="append", help="Attach image file(s) (auto-selects gpt-6.1-terra for explore)")
    p.add_argument("--prompt-file", help="Read prompt from file instead of stdin")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Max runtime seconds (default: 1800)")
    p.add_argument("--state-dir", help="Override artifact cache directory")
    p.add_argument("--json", action="store_true", help="Print full JSON result instead of compact receipt")
    p.add_argument("--dry-run", action="store_true", help="Print resolved command and exit without running Codex")
    p.add_argument("prompt", nargs="?", help="Prompt text, or `-` / omit to read from stdin")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codex-dispatch",
        description="Deterministic token-saving Claude -> Codex orchestrator.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    for role_name, help_txt in (
        ("explore", "Read-only codebase exploration & reusable-module discovery (gpt-6.2-sol)"),
        ("critique", "Read-only pre-coding architecture critique or root-cause diagnosis (gpt-6.2-astra)"),
        ("implement", "Contract-driven coding with baseline diff, allowlist gate & verify hook"),
        ("review", "Independent read-only adversarial code review (gpt-6.2-astra)"),
        ("visual", "Read-only visual/UI screenshot inspection (gpt-6.1-terra)"),
    ):
        sp = sub.add_parser(role_name, help=help_txt)
        sp.set_defaults(role=role_name, handler=cmd_dispatch_new)
        if role_name == "review":
            sp.add_argument("--base", help="Git base branch/ref for review (e.g. main)")
            sp.add_argument("--uncommitted", action="store_true", help="Review uncommitted changes")
            sp.add_argument("--commit", help="Review specific commit SHA")
            sp.add_argument("--native", action="store_true", help="Use native `codex exec review` subcommand")
        add_common_dispatch_flags(sp)

    p_resume = sub.add_parser("resume", help="Resume an existing task_id for rework/follow-up (auto-restores sandbox/model)")
    p_resume.set_defaults(handler=cmd_resume)
    p_resume.add_argument("task_id", help="Task ID from previous codex-dispatch receipt")
    p_resume.add_argument("-m", "--model", help="Override model on resume")
    p_resume.add_argument("--effort", help="Override reasoning effort on resume")
    p_resume.add_argument("--no-escalate", action="store_true", help="Keep original model instead of auto-upgrading rework to astra+high")
    p_resume.add_argument("--allow", action="append", help="Override allowed write globs")
    p_resume.add_argument("--forbid", action="append", help="Override forbidden write globs")
    p_resume.add_argument("--verify", help="Override verification command")
    p_resume.add_argument("--allow-network", action="store_true", help="Enable sandbox network on resume")
    p_resume.add_argument("--write", action="store_true", help="Internal flag check")
    p_resume.add_argument("--prompt-file", help="Read rework prompt from file")
    p_resume.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p_resume.add_argument("--state-dir", help="Override artifact cache directory")
    p_resume.add_argument("--json", action="store_true", help="Print JSON result")
    p_resume.add_argument("--dry-run", action="store_true", help="Preview resume command without running")
    p_resume.add_argument("prompt", nargs="?", help="Delta rework instructions, or `-`/stdin")

    p_status = sub.add_parser("status", help="List recent dispatched tasks or inspect one task_id")
    p_status.set_defaults(handler=cmd_status)
    p_status.add_argument("task_id", nargs="?", help="Optional specific task_id")
    p_status.add_argument("-n", "--limit", type=int, default=15)
    p_status.add_argument("--state-dir", help="Override artifact cache directory")

    p_clean = sub.add_parser("clean", help="Remove old task directories from ~/.cache/agent-work/codex-dispatch")
    p_clean.set_defaults(handler=cmd_clean)
    p_clean.add_argument("--days", type=int, default=7, help="Delete runs older than N days (default: 7)")
    p_clean.add_argument("--state-dir", help="Override artifact cache directory")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except DispatchError as exc:
        sys.stderr.write(f"[codex-dispatch ERROR] {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
