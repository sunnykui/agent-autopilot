"""Controlled bare repo, literal backslash/gitlink raw path gate, git_ops_ring sampling, and CLEAN_TREE export."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .models import (
    POLICY_MANIFEST,
    AutopilotError,
    EmptyCandidateError,
    ScopeViolationError,
    build_pnpm_exec_cmd,
    empty_and_fsync_dirfd,
    ensure_secure_dir,
    open_dir_nofollow,
    pinned_proc_fd_path,
    quarantine_noreplace_at_dirfd,
)
from .sandbox import build_execution_ring_bwrap

_CODEX_DISPATCH_SCRIPTS = Path(__file__).resolve().parents[3] / "codex-dispatch" / "scripts"
if str(_CODEX_DISPATCH_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_CODEX_DISPATCH_SCRIPTS))
import codex_dispatch as _cd  # type: ignore[import-not-found]  # noqa: E402

_SECRET_BYTE_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("PEM private key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(rb"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|gho_[A-Za-z0-9]{30,})\b")),
    ("Anthropic API key", re.compile(rb"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI API key", re.compile(rb"\bsk-(?:proj|live)-[A-Za-z0-9_-]{20,}\b")),
    ("AWS Access Key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
)


@dataclass(frozen=True)
class CandidateGateResult:
    candidate_sha: str
    tree_oid: str
    touched_paths: tuple[str, ...]
    clean_tree_dir: Path
    review_bundle_dir: Path
    clean_tree_fd: int | None = None
    review_bundle_fd: int | None = None

    def close_fds(self) -> None:
        for fd in (self.clean_tree_fd, self.review_bundle_fd):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)


def _safe_git_env(
    *,
    git_dir: Path,
    work_tree: Path | None = None,
    git_common_dir: Path | None = None,
    index_file: Path | None = None,
    object_dir: Path | None = None,
    alt_object_dirs: list[Path] | None = None,
) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_DIR": str(git_dir),
    }
    if git_common_dir is not None:
        env["GIT_COMMON_DIR"] = str(git_common_dir)
    if work_tree is not None:
        env["GIT_WORK_TREE"] = str(work_tree)
    if index_file is not None:
        env["GIT_INDEX_FILE"] = str(index_file)
    if object_dir is not None:
        env["GIT_OBJECT_DIRECTORY"] = str(object_dir)
    if alt_object_dirs:
        env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = os.pathsep.join(str(p) for p in alt_object_dirs)
    return env


def resolve_repo_common_objects_dir(repo_main: Path) -> Path | None:
    """Resolve the shared Git objects directory safely for both standard clones and linked worktrees."""
    if not repo_main.exists():
        return None
    proc = subprocess.run(
        ["git", "-C", str(repo_main), "rev-parse", "--git-common-dir"],
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": "/tmp",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode != 0:
        return None
    raw = proc.stdout.strip()
    if not raw:
        return None
    p = Path(raw)
    common_dir = (p if p.is_absolute() else (repo_main / p)).resolve()
    obj_dir = common_dir / "objects"
    return obj_dir if obj_dir.is_dir() else None


def ensure_managed_bare_repo(repo_main: Path | None, managed_gitdir: Path) -> Path:
    """Create/refresh controlled bare MANAGED_GITDIR without inheriting $REPO_MAIN/.git/config."""
    ensure_secure_dir(managed_gitdir.parent, 0o700)
    if not (managed_gitdir / "HEAD").is_file():
        ensure_secure_dir(managed_gitdir, 0o700)
        subprocess.run(
            ["git", "init", "--bare", "-q", str(managed_gitdir)],
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": "/tmp",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
            },
            check=True,
            timeout=20,
        )
        (managed_gitdir / "config").write_text(
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n"
            "[gc]\n\tauto = 0\n",
            encoding="utf-8",
        )
        hooks_dir = managed_gitdir / "hooks"
        if hooks_dir.exists():
            shutil.rmtree(hooks_dir)
        hooks_dir.mkdir(mode=0o700)

    if repo_main is not None:
        main_objects = resolve_repo_common_objects_dir(repo_main)
        if main_objects is not None:
            info_dir = ensure_secure_dir(managed_gitdir / "objects" / "info", 0o700)
            (info_dir / "alternates").write_text(f"{main_objects}\n", encoding="utf-8")
    return managed_gitdir.resolve()


def fetch_authorized_base_into_managed(
    *,
    managed_gitdir: Path,
    repo_slug: str,
    authorized_base_ref: str,
    gh_token: str | None = None,
) -> str:
    """Fetch exact authorized_base_ref from GitHub into controlled MANAGED_GITDIR and return verified commit OID."""
    mg = managed_gitdir.resolve()
    url = f"https://github.com/{repo_slug}.git"
    target_ref = f"refs/remotes/origin/{authorized_base_ref}"
    env = _safe_git_env(git_dir=mg)
    env["GH_PROMPT_DISABLED"] = "1"
    if gh_token:
        env.pop("GITHUB_TOKEN", None)
        env["GH_TOKEN"] = gh_token
    else:
        # Explicit ambient mode: preserve host credential context so `gh auth git-credential` can access private repos!
        if os.environ.get("HOME"):
            env["HOME"] = os.environ["HOME"]
        if os.environ.get("XDG_CONFIG_HOME"):
            env["XDG_CONFIG_HOME"] = os.environ["XDG_CONFIG_HOME"]
        for amb_k in ("GH_TOKEN", "GITHUB_TOKEN", "GH_CONFIG_DIR"):
            if os.environ.get(amb_k):
                env[amb_k] = os.environ[amb_k]
    proc = subprocess.run(
        [
            "git",
            f"--git-dir={mg}",
            "-c",
            "credential.helper=!gh auth git-credential",
            "fetch",
            "--no-tags",
            url,
            f"+refs/heads/{authorized_base_ref}:{target_ref}",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        raise AutopilotError(
            f"Controlled fetch failed for {repo_slug}:{authorized_base_ref}: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    rev = subprocess.run(
        ["git", f"--git-dir={mg}", "rev-parse", "--verify", f"{target_ref}^{{commit}}"],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if rev.returncode != 0:
        raise AutopilotError(f"Failed to resolve fetched {target_ref} in {mg}: {rev.stderr.strip()}")
    return rev.stdout.strip()


def resolve_commit_oid(repo_main: Path, ref_or_sha: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_main), "rev-parse", "--verify", f"{ref_or_sha}^{{commit}}"],
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": "/tmp",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if proc.returncode != 0:
        raise AutopilotError(f"Failed to resolve commit {ref_or_sha!r} in {repo_main}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _assert_wt_gitdir_bound_to_exact_wt(wt_gitdir: Path, wt: Path) -> None:
    """Verify existing `wt_gitdir` is unlocked, non-symlink, and its `gitdir` backpointer points to `wt/.git` (not relocated!)."""
    try:
        if wt_gitdir.is_symlink() or (wt_gitdir.exists() and not wt_gitdir.is_dir()):
            raise AutopilotError(f"Refusing symlinked or non-directory wt_gitdir: {wt_gitdir}")
        if not wt_gitdir.exists():
            return
    except OSError as exc:
        raise AutopilotError(f"Unable to inspect wt_gitdir {wt_gitdir}: {exc}") from exc

    locked_marker = wt_gitdir / "locked"
    try:
        os.lstat(locked_marker)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise AutopilotError(f"Refusing to touch {wt_gitdir}: unable to inspect locked marker ({exc})") from exc
    else:
        raise AutopilotError(f"Refusing to delete/reuse locked worktree metadata {wt_gitdir} (git worktree lock active)")

    gitdir_ptr = wt_gitdir / "gitdir"
    try:
        if not gitdir_ptr.is_file() or gitdir_ptr.is_symlink():
            raise AutopilotError(f"Refusing to delete/reuse {wt_gitdir}: missing or symlinked gitdir backpointer")
        reg_ptr = Path(os.path.normpath(gitdir_ptr.read_text(encoding="utf-8", errors="replace").strip()))
    except OSError as exc:
        raise AutopilotError(f"Refusing to delete/reuse {wt_gitdir}: unreadable gitdir backpointer ({exc})") from exc

    proc_pfx = f"/proc/{os.getpid()}/fd/"
    canon_wt = wt.resolve() if str(wt).startswith(proc_pfx) else wt
    exp_ptr = Path(os.path.normpath(str(canon_wt / ".git")))
    if reg_ptr != exp_ptr:
        raise AutopilotError(
            f"Refusing to delete/reuse {wt_gitdir}: gitdir points to relocated worktree {reg_ptr} != {exp_ptr}"
        )


def prepare_isolated_worktree(
    *,
    managed_gitdir: Path,
    worktree_dir: Path,
    wt_name: str = "",
    base_sha: str,
) -> tuple[Path, Path]:
    """Create or reset a detached worktree under MANAGED_GITDIR, refusing symlinked ancestors, relocated metadata, or unowned dirs!"""
    _ = wt_name
    raw_mg = Path(os.path.normpath(str(managed_gitdir)))
    raw_wt = Path(os.path.normpath(str(worktree_dir)))
    if not raw_mg.is_absolute():
        raw_mg = Path(os.path.normpath(str(Path.cwd() / raw_mg)))
    if not raw_wt.is_absolute():
        raw_wt = Path(os.path.normpath(str(Path.cwd() / raw_wt)))

    # Walk EVERY ancestor of `raw_mg` and `raw_wt.parent` with `O_DIRECTORY|O_NOFOLLOW` so higher-level cache symlinks fail closed!
    os.close(open_dir_nofollow(raw_mg, create=False))
    os.close(open_dir_nofollow(raw_mg / "worktrees", create=True, mode=0o700))
    os.close(open_dir_nofollow(raw_wt.parent, create=True, mode=0o700))
    if raw_wt.is_symlink():
        raise AutopilotError(f"Refusing symlinked worktree target in prepare_isolated_worktree: {raw_wt}")

    registered_name = raw_wt.name
    mg = raw_mg
    wt = raw_wt
    wt_gitdir = mg / "worktrees" / registered_name
    wt_lock_fd = os.open(str(mg / ".autopilot-worktree.flock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(wt_lock_fd, fcntl.LOCK_EX)
        _assert_wt_gitdir_bound_to_exact_wt(wt_gitdir, wt)
        env = _safe_git_env(git_dir=mg)

        if not wt.exists():
            if wt_gitdir.exists() or wt_gitdir.is_symlink():
                raise AutopilotError(
                    f"Refusing to recreate absent worktree {wt} while metadata {wt_gitdir} already exists; preserving metadata"
                )
            subprocess.run(
                ["git", "worktree", "add", "--detach", str(wt), base_sha],
                env=env,
                pass_fds=(wt_lock_fd,),
                check=True,
                timeout=240,
                capture_output=True,
            )
        elif not wt.is_dir():
            raise AutopilotError(f"Refusing non-directory worktree path: {wt}")
        elif not any(wt.iterdir()):
            if wt_gitdir.exists() or wt_gitdir.is_symlink():
                raise AutopilotError(
                    f"Refusing to recreate empty worktree {wt} while metadata {wt_gitdir} already exists; preserving metadata"
                )
            wt.rmdir()
            subprocess.run(
                ["git", "worktree", "add", "--detach", str(wt), base_sha],
                env=env,
                pass_fds=(wt_lock_fd,),
                check=True,
                timeout=240,
                capture_output=True,
            )
        else:
            # Non-empty existing directory: REQUIRE bidirectional ownership proof BEFORE reset/clean (NEVER rmtree unowned dir!)
            if not wt_gitdir.is_dir():
                raise AutopilotError(f"Refusing to overwrite non-empty directory {wt} lacking registered metadata {wt_gitdir}")
            verify_dot_git_integrity(wt, wt_gitdir)
            wt_env = _safe_git_env(git_dir=wt_gitdir, git_common_dir=mg, work_tree=wt)
            subprocess.run(["git", "reset", "--hard", base_sha], env=wt_env, pass_fds=(wt_lock_fd,), check=True, timeout=240, capture_output=True)
            subprocess.run(["git", "clean", "-ffdx"], env=wt_env, pass_fds=(wt_lock_fd,), check=True, timeout=240, capture_output=True)
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(wt_lock_fd, fcntl.LOCK_UN)
        with contextlib.suppress(OSError):
            os.close(wt_lock_fd)

    verify_dot_git_integrity(wt, wt_gitdir)
    return wt, wt_gitdir


def verify_dot_git_integrity(worktree: Path, expected_wt_gitdir: Path) -> None:
    dot_git = worktree / ".git"
    if dot_git.is_symlink() or not dot_git.is_file():
        raise ScopeViolationError(
            f"Worktree .git tampered (must be regular file, not symlink/dir): {dot_git}",
            violations=[".git (tampered gitfile)"],
        )
    expected_bytes = f"gitdir: {expected_wt_gitdir.resolve()}\n".encode("utf-8")
    actual_bytes = dot_git.read_bytes()
    if actual_bytes != expected_bytes:
        raise ScopeViolationError(
            f"Worktree .git bytes mismatch: expected {expected_bytes!r}, got {actual_bytes!r}",
            violations=[".git (tampered gitdir pointer)"],
        )


def validate_raw_git_path(raw_path: str, *, old_mode: str = "000000", new_mode: str = "100644") -> None:
    """Reject literal backslashes, control chars, '.'/'..' segments, and 160000 gitlinks BEFORE check_scope()."""
    if old_mode == "160000" or new_mode == "160000":
        raise ScopeViolationError(
            f"Forbidden submodule/gitlink entry (mode 160000): {raw_path!r}",
            violations=[f"{raw_path} (forbidden 160000 gitlink)"],
        )
    if not raw_path:
        raise ScopeViolationError("Empty git path entry", violations=["<empty> (invalid raw path)"])
    if "\\" in raw_path:
        raise ScopeViolationError(
            f"Forbidden literal backslash in raw git path: {raw_path!r}",
            violations=[f"{raw_path} (contains literal backslash)"],
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_path):
        raise ScopeViolationError(
            f"Forbidden ASCII control character in raw git path: {raw_path!r}",
            violations=[f"{raw_path!r} (contains control character)"],
        )
    if raw_path.startswith("/") or raw_path.endswith("/"):
        raise ScopeViolationError(
            f"Forbidden leading/trailing slash in raw git path: {raw_path!r}",
            violations=[f"{raw_path} (leading/trailing slash)"],
        )
    segments = raw_path.split("/")
    for seg in segments:
        if seg in ("", ".", ".."):
            raise ScopeViolationError(
                f"Forbidden path traversal/empty segment in raw git path: {raw_path!r}",
                violations=[f"{raw_path} (invalid segment {seg!r})"],
            )


_APPROVED_GLOB_RE = re.compile(r"^[A-Za-z0-9._/*-]+$")


def validate_approvable_protected_glob(pattern: str) -> str:
    """Validate an operator-approved protected path glob against the narrow approvable subset."""
    pat = str(pattern or "").strip()
    if not pat:
        raise ScopeViolationError("Empty approved protected path pattern", violations=["<empty>"])
    if not _APPROVED_GLOB_RE.fullmatch(pat):
        raise ScopeViolationError(
            f"Disallowed characters in approved protected path pattern (only [A-Za-z0-9._/*-] allowed): {pat!r}",
            violations=[pat],
        )
    if pat.startswith("/") or pat.endswith("/"):
        raise ScopeViolationError(f"Leading/trailing slash forbidden in pattern: {pat!r}", violations=[pat])
    segs = pat.split("/")
    for seg in segs:
        if seg in ("", ".", ".."):
            raise ScopeViolationError(f"Invalid path segment in pattern: {pat!r}", violations=[pat])
        if "**" in seg and seg != "**":
            raise ScopeViolationError(f"Double-star must occupy an entire segment: {pat!r}", violations=[pat])

    approvable = list(POLICY_MANIFEST.get("approvable_hard_stop_anchored", ()))
    if not approvable:
        raise ScopeViolationError(
            "No approvable_hard_stop_anchored patterns configured; failing closed",
            violations=[f"{pat} (no approvable_hard_stop_anchored)"],
        )

    probe = "/".join("x" if s in ("*", "**") else s.replace("*", "x") for s in segs)
    try:
        ok_self, _ = _cd.check_scope([probe], [pat], [])
    except re.error as exc:
        raise ScopeViolationError(f"Uncompilable approved glob {pat!r}: {exc}", violations=[pat]) from exc
    if not ok_self:
        raise ScopeViolationError(f"Approved glob did not match its own probe path: {pat!r}", violations=[pat])

    approvable_set = set(approvable)
    anchored_forbid = list(POLICY_MANIFEST["global_hard_stop_anchored"])
    non_approvable = [p for p in anchored_forbid if p not in approvable_set]
    basenames_forbid_lower = [f"**/{b.lower()}" for b in POLICY_MANIFEST["global_hard_stop_basenames"]]
    lockfile_patterns = list(POLICY_MANIFEST["dependency_lock_paths"])

    ok_approvable, _ = _cd.check_scope([probe], approvable, [])
    ok_non_approvable, _ = _cd.check_scope([probe], [], non_approvable)
    ok_base, _ = _cd.check_scope([probe.lower()], [], basenames_forbid_lower)
    ok_lock, _ = _cd.check_scope([probe], [], lockfile_patterns)
    if not (ok_approvable and ok_non_approvable and ok_base and ok_lock):
        raise ScopeViolationError(
            f"Protected path pattern {pat!r} is not eligible for operator approval (only schema/migration patterns allowed)",
            violations=[f"{pat} (not in approvable_hard_stop_anchored)"],
        )
    return pat


def is_path_covered_by_approved_protected(
    raw_path: str,
    approved_protected_paths: list[str] | tuple[str, ...],
) -> bool:
    """Return True iff concrete raw_path is eligible for AND covered by operator-approved protected globs."""
    validate_raw_git_path(raw_path)
    approvable = list(POLICY_MANIFEST.get("approvable_hard_stop_anchored", ()))
    if not approvable or not approved_protected_paths:
        return False
    approved_list = [validate_approvable_protected_glob(p) for p in approved_protected_paths]
    anchored_forbid = list(POLICY_MANIFEST["global_hard_stop_anchored"])
    approvable_set = set(approvable)
    non_approvable_forbid = [p for p in anchored_forbid if p not in approvable_set]
    basenames_forbid_lower = [f"**/{b.lower()}" for b in POLICY_MANIFEST["global_hard_stop_basenames"]]
    lockfile_patterns = list(POLICY_MANIFEST["dependency_lock_paths"])

    ok_approvable, _ = _cd.check_scope([raw_path], approvable, [])
    ok_approved, _ = _cd.check_scope([raw_path], approved_list, [])
    ok_non_approvable, _ = _cd.check_scope([raw_path], [], non_approvable_forbid)
    ok_base, _ = _cd.check_scope([raw_path.lower()], [], basenames_forbid_lower)
    ok_lock, _ = _cd.check_scope([raw_path], [], lockfile_patterns)
    return bool(ok_approvable and ok_approved and ok_non_approvable and ok_base and ok_lock)


def check_autopilot_scope(
    raw_paths: list[str],
    frozen_write_scope: list[str] | tuple[str, ...],
    approved_protected_paths: list[str] | tuple[str, ...] = (),
) -> None:
    """Validate raw paths then apply two-step codex_dispatch.check_scope() + aggregated lockfile escalation."""
    if not frozen_write_scope:
        raise ScopeViolationError(
            "frozen_write_scope MUST be non-empty",
            violations=["<policy> (empty frozen_write_scope)"],
        )
    for rp in raw_paths:
        validate_raw_git_path(rp)

    anchored_forbid = list(POLICY_MANIFEST["global_hard_stop_anchored"])
    basenames_forbid_lower = [f"**/{b.lower()}" for b in POLICY_MANIFEST["global_hard_stop_basenames"]]
    lockfile_patterns = list(POLICY_MANIFEST["dependency_lock_paths"])
    approved_list = [validate_approvable_protected_glob(p) for p in approved_protected_paths]

    hard_violations: list[str] = []
    lock_hits: list[str] = []
    for rp in raw_paths:
        ok_lock, _ = _cd.check_scope([rp], [], lockfile_patterns)
        if not ok_lock:
            lock_hits.append(f"{rp} (dependency lockfile requires human approval)")

        ok_a, _ = _cd.check_scope([rp], [], anchored_forbid)
        if not ok_a:
            if not (approved_list and is_path_covered_by_approved_protected(rp, approved_list)):
                hard_violations.append(f"{rp} (matches global_hard_stop_anchored)")
                continue
        ok_b, _ = _cd.check_scope([rp.lower()], [], basenames_forbid_lower)
        if not ok_b:
            hard_violations.append(f"{rp} (matches case-insensitive global_hard_stop_basenames)")
            continue

    if hard_violations or lock_hits:
        # Preserve is_lockfile=True whenever ANY lockfile was touched, even alongside hard-stop violations!
        raise ScopeViolationError(
            "Hard-stop or dependency lockfile violation",
            violations=hard_violations + lock_hits,
            is_lockfile=bool(lock_hits),
        )

    ok_allow, allow_violations = _cd.check_scope(list(raw_paths), list(frozen_write_scope), [])
    if not ok_allow:
        raise ScopeViolationError("Path outside frozen_write_scope", violations=allow_violations, is_lockfile=False)


def parse_diff_tree_raw_z(raw_bytes: bytes) -> list[tuple[str, str, str, str, str, str]]:
    """Parse `git diff-tree --raw -r --no-renames -z base_sha tree_oid` into (old_mode, new_mode, old_oid, new_oid, status, raw_path)."""
    if not raw_bytes:
        return []
    parts = raw_bytes.split(b"\0")
    entries: list[tuple[str, str, str, str, str, str]] = []
    i = 0
    while i < len(parts):
        meta = parts[i]
        if not meta:
            i += 1
            continue
        if not meta.startswith(b":") or i + 1 >= len(parts):
            raise AutopilotError(f"Unexpected diff-tree record: {meta!r}")
        fields = meta[1:].decode("ascii", errors="replace").split(" ")
        if len(fields) < 5:
            raise AutopilotError(f"Malformed diff-tree metadata: {fields!r}")
        old_mode, new_mode, old_oid, new_oid, status = fields[:5]
        raw_path = parts[i + 1].decode("utf-8", errors="surrogateescape")
        entries.append((old_mode, new_mode, old_oid, new_oid, status, raw_path))
        i += 2
    return entries


_PEM_PRIVATE_KEY_BLOCK_RE = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)


def _secret_match_counts(label: str, pat: re.Pattern[bytes], blob: bytes) -> tuple[Counter[bytes], bool]:
    """Return `(match_counter, comparable_with_base)`. PEM blocks require full header-to-footer parity; unclosed headers fail closed."""
    headers = [m.group(0) for m in pat.finditer(blob)]
    if not headers:
        return Counter(), True
    if label == "PEM private key":
        blocks = [m.group(0) for m in _PEM_PRIVATE_KEY_BLOCK_RE.finditer(blob)]
        if len(blocks) != len(headers):
            return Counter(headers), False
        return Counter(blocks), True
    return Counter(headers), True


def _scan_blob_for_secrets(
    git_env: dict[str, str],
    blob_oid: str,
    raw_path: str,
    *,
    base_blob_oid: str = "",
) -> None:
    proc = subprocess.run(
        ["git", "cat-file", "blob", blob_oid],
        env=git_env,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if proc.returncode != 0:
        raise AutopilotError(f"Failed to inspect blob {blob_oid} for {raw_path}")
    blob = proc.stdout
    matched_patterns: list[tuple[str, re.Pattern[bytes], Counter[bytes], bool]] = []
    for label, pat in _SECRET_BYTE_PATTERNS:
        hits, comparable = _secret_match_counts(label, pat, blob)
        if hits:
            matched_patterns.append((label, pat, hits, comparable))
    if not matched_patterns:
        return
    base_blob: bytes | None = None
    if (
        len(base_blob_oid) in (40, 64)
        and all(ch in "0123456789abcdefABCDEF" for ch in base_blob_oid)
        and any(ch != "0" for ch in base_blob_oid)
    ):
        base_proc = subprocess.run(
            ["git", "cat-file", "blob", base_blob_oid],
            env=git_env,
            capture_output=True,
            timeout=15,
            check=False,
        )
        if base_proc.returncode != 0:
            raise AutopilotError(f"Failed to inspect base blob {base_blob_oid} for {raw_path}")
        base_blob = base_proc.stdout
    for label, pat, new_hits, comparable in matched_patterns:
        if base_blob is not None and comparable:
            old_hits, old_comparable = _secret_match_counts(label, pat, base_blob)
            if old_comparable and all(cnt <= old_hits[val] for val, cnt in new_hits.items()):
                continue
        raise ScopeViolationError(
            f"Secret material detected in {raw_path} ({label})",
            violations=[f"{raw_path} (contains {label})"],
        )


def _is_valid_loose_git_object(path: Path, expected_oid: str) -> bool:
    try:
        raw = path.read_bytes()
        decompressed = zlib.decompress(raw)
        return hashlib.sha1(decompressed).hexdigest() == expected_oid.lower()
    except Exception:
        return False


def _promote_scratch_objects(scratch_objects: Path, managed_objects: Path) -> None:
    """Crash-safe atomic promotion of loose Git objects (verifies zlib+SHA1 and replaces existing truncated files)."""
    for entry in scratch_objects.iterdir():
        if len(entry.name) == 2 and entry.is_dir():
            dst_fan = managed_objects / entry.name
            dst_fan.mkdir(parents=True, exist_ok=True)
            for obj_file in entry.iterdir():
                if obj_file.name.startswith(".tmp-"):
                    continue
                oid = f"{entry.name}{obj_file.name}"
                if not _is_valid_loose_git_object(obj_file, oid):
                    raise AutopilotError(f"Corrupt scratch Git loose object {oid} at {obj_file}")
                dst_obj = dst_fan / obj_file.name
                if dst_obj.exists() and _is_valid_loose_git_object(dst_obj, oid):
                    continue
                tmp_dst = dst_fan / f".tmp-{obj_file.name}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
                data = obj_file.read_bytes()
                fd = os.open(str(tmp_dst), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
                try:
                    mv = memoryview(data)
                    while mv:
                        written = os.write(fd, mv)
                        if written <= 0:
                            raise AutopilotError(f"Short/zero write promoting Git loose object {oid}")
                        mv = mv[written:]
                    os.fsync(fd)
                except BaseException:
                    with contextlib.suppress(OSError):
                        os.close(fd)
                    with contextlib.suppress(OSError):
                        tmp_dst.unlink()
                    raise
                else:
                    os.close(fd)
                if not _is_valid_loose_git_object(tmp_dst, oid):
                    tmp_dst.unlink(missing_ok=True)
                    raise AutopilotError(f"Post-write verification failed for Git loose object {oid}")
                if dst_obj.exists():
                    os.chmod(dst_obj, 0o644)
                os.replace(tmp_dst, dst_obj)
                dir_fd = os.open(str(dst_fan), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)


def prepare_trusted_base_cache(*, managed_gitdir: Path, base_sha: str, cache_root: Path) -> Path | None:
    """Materialize a self-contained workspace base dependency cache (pnpm + Cargo.lock); fail closed if required!"""
    p, fd = prepare_trusted_base_cache_fd(managed_gitdir=managed_gitdir, base_sha=base_sha, cache_root=cache_root)
    if fd is not None:
        with contextlib.suppress(OSError):
            os.close(fd)
    return p


def prepare_trusted_base_cache_fd(*, managed_gitdir: Path, base_sha: str, cache_root: Path) -> tuple[Path | None, int | None]:
    """Materialize/open verified workspace base dependency cache inside `key_lock_fd` and return `(cache_path, open_verified_fd)`!"""
    env = _safe_git_env(git_dir=managed_gitdir.resolve())
    try:
        ls_tree = subprocess.run(
            ["git", "ls-tree", "-r", "-z", "--name-only", base_sha],
            env=env,
            capture_output=True,
            timeout=20,
            check=True,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise AutopilotError(f"Failed to list tree {base_sha} for trusted_base_cache: {exc}") from exc
    all_paths = [p.decode("utf-8", errors="strict") for p in ls_tree.stdout.split(b"\x00") if p]
    all_paths_set = set(all_paths)
    has_pnpm = "pnpm-lock.yaml" in all_paths_set
    cargo_locks = sorted(p for p in all_paths if p == "Cargo.lock" or p.endswith("/Cargo.lock"))
    go_sums = sorted(
        p
        for p in all_paths
        if (p == "go.sum" or p.endswith("/go.sum"))
        and "/vendor/" not in f"/{p}"
        and (f"{p[:-6]}go.mod" in all_paths_set)
        and (f"{p[:-6]}vendor/modules.txt" not in all_paths_set)
    )
    if not has_pnpm and not cargo_locks and not go_sums:
        return None, None

    pnpm_prefix: list[str] = []
    if has_pnpm:
        pnpm_bin = shutil.which("pnpm") or str(Path.home() / ".local" / "bin" / "pnpm")
        if not Path(pnpm_bin).is_file():
            raise AutopilotError(f"Repository at {base_sha} requires pnpm-lock.yaml cache, but pnpm binary is missing")
        pnpm_prefix = build_pnpm_exec_cmd(pnpm_bin)

    cargo_bin = ""
    if cargo_locks:
        cargo_bin = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")
        if not Path(cargo_bin).is_file():
            raise AutopilotError(f"Repository at {base_sha} requires Cargo.lock cache, but cargo toolchain is missing")

    go_bin = ""
    go_in_ring_bin = ""
    if go_sums:
        from .sandbox import resolve_host_go_toolchain_root

        go_tc = resolve_host_go_toolchain_root()
        if go_tc is not None and (go_tc / "bin" / "go").is_file():
            go_bin = str(go_tc / "bin" / "go")
            go_in_ring_bin = "/ap-toolchain-bin/go"
        else:
            sys_go = shutil.which("go") or ""
            if sys_go and Path(sys_go).resolve().is_file() and str(Path(sys_go).resolve()).startswith("/usr/"):
                go_bin = str(Path(sys_go).resolve())
                go_in_ring_bin = go_bin
        if not go_bin or not go_in_ring_bin:
            raise AutopilotError(f"Repository at {base_sha} requires go.sum cache, but Go toolchain is missing")

    manifest_paths = sorted(
        p for p in all_paths
        if p in ("pnpm-lock.yaml", "pnpm-workspace.yaml")
        or p == "package.json"
        or p.endswith("/package.json")
        or p.startswith("patches/")
        or p == "Cargo.lock"
        or p.endswith("/Cargo.lock")
        or p == "Cargo.toml"
        or p.endswith("/Cargo.toml")
        or p == "go.sum"
        or p.endswith("/go.sum")
        or p == "go.mod"
        or p.endswith("/go.mod")
    )
    hasher = hashlib.sha256()
    blobs: list[tuple[str, bytes]] = []
    try:
        for mp in manifest_paths:
            b = subprocess.run(
                ["git", "cat-file", "blob", f"{base_sha}:{mp}"],
                env=env,
                capture_output=True,
                timeout=15,
                check=True,
            ).stdout
            hasher.update(mp.encode("utf-8") + b"\x00" + b + b"\x00")
            blobs.append((mp, b))
    except (subprocess.SubprocessError, OSError) as exc:
        raise AutopilotError(f"Failed to read manifest blob at {base_sha}: {exc}") from exc

    import fcntl
    import stat
    from .sandbox import open_verified_trusted_base_cache_fd, run_isolated_deps_prefetch, verify_trusted_base_cache_integrity

    def _is_valid_complete_cache_fd(cfd: int) -> bool:
        try:
            st_r = os.stat(".ready", dir_fd=cfd, follow_symlinks=False)
            if not stat.S_ISREG(st_r.st_mode) or stat.S_ISLNK(st_r.st_mode):
                return False
            if has_pnpm:
                st_nm = os.stat("node_modules", dir_fd=cfd, follow_symlinks=False)
                if not stat.S_ISDIR(st_nm.st_mode) or stat.S_ISLNK(st_nm.st_mode):
                    return False
            if cargo_locks:
                st_ch = os.stat("cargo_home", dir_fd=cfd, follow_symlinks=False)
                if not stat.S_ISDIR(st_ch.st_mode) or stat.S_ISLNK(st_ch.st_mode):
                    return False
            if go_sums:
                st_gm = os.stat("go_mod_cache", dir_fd=cfd, follow_symlinks=False)
                if not stat.S_ISDIR(st_gm.st_mode) or stat.S_ISLNK(st_gm.st_mode):
                    return False
            vfd, _ = open_verified_trusted_base_cache_fd(None, source_tbc_fd=cfd)
            os.close(vfd)
            return True
        except Exception:
            return False

    key = hasher.hexdigest()[:16]
    deps_root_fd = open_dir_nofollow(cache_root / "base-deps", create=True, mode=0o700)
    deps_root = pinned_proc_fd_path(deps_root_fd)
    key_lock_fd = os.open(f".deps-{key}.flock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=deps_root_fd)
    pub_meta_name = f".deps-{key}.published.json"
    publish_id = uuid.uuid4().hex
    stage_name = f".stage-deps-{key}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
    cargo_tree_name = f".cargo-tree-{key}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
    stage_dir = deps_root / stage_name
    cargo_tree_tmp = deps_root / cargo_tree_name
    stage_fd: int | None = None
    cargo_tree_fd: int | None = None
    stage_owner_claimed = False
    stage_promoted = False

    def _has_matching_publish_receipt_fd(cfd: int, dev_id: int, ino_id: int) -> bool:
        try:
            mfd = os.open(pub_meta_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=deps_root_fd)
        except OSError:
            return False
        try:
            st_m = os.fstat(mfd)
            if not stat.S_ISREG(st_m.st_mode) or st_m.st_size > 16384:
                return False
            meta = json.loads(os.read(mfd, 16384).decode("utf-8"))
        except Exception:
            return False
        finally:
            os.close(mfd)
        if not (
            isinstance(meta, dict)
            and meta.get("key") == key
            and int(meta.get("dev", -1)) == int(dev_id)
            and int(meta.get("ino", -1)) == int(ino_id)
            and isinstance(meta.get("publish_id"), str)
            and len(meta["publish_id"]) >= 16
        ):
            return False
        try:
            ofd = os.open(".ap-stage-owner", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=cfd)
        except OSError:
            return False
        try:
            st_o = os.fstat(ofd)
            if not stat.S_ISREG(st_o.st_mode) or st_o.st_size > 1024:
                return False
            owner_txt = os.read(ofd, 1024).decode("utf-8", errors="replace").strip()
            return owner_txt == f"{key}:{meta['publish_id']}"
        finally:
            os.close(ofd)

    def _write_publish_receipt(dev_id: int, ino_id: int, pub_id: str) -> None:
        tmp_meta = f".tmp-{pub_meta_name}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        tfd = os.open(tmp_meta, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=deps_root_fd)
        try:
            payload = (
                json.dumps({"key": key, "dev": int(dev_id), "ino": int(ino_id), "publish_id": pub_id, "base_sha": base_sha}) + "\n"
            ).encode("utf-8")
            os.write(tfd, payload)
            os.fsync(tfd)
        except BaseException:
            os.close(tfd)
            with contextlib.suppress(OSError):
                os.unlink(tmp_meta, dir_fd=deps_root_fd)
            raise
        os.close(tfd)
        os.replace(tmp_meta, pub_meta_name, src_dir_fd=deps_root_fd, dst_dir_fd=deps_root_fd)
        os.fsync(deps_root_fd)

    def _probe_existing_cache_fd() -> tuple[int | None, int | None, os.stat_result | None]:
        """Inspect `deps-{key}` once: return `(valid_cfd, rejected_dir_fd, rejected_nondir_stat)` retaining rejected fd open!"""
        try:
            st_cur = os.stat(f"deps-{key}", dir_fd=deps_root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None, None, None
        if not stat.S_ISDIR(st_cur.st_mode) or stat.S_ISLNK(st_cur.st_mode):
            return None, None, st_cur
        cfd = os.open(f"deps-{key}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=deps_root_fd)
        try:
            st_cfd = os.fstat(cfd)
            if _has_matching_publish_receipt_fd(cfd, int(st_cfd.st_dev), int(st_cfd.st_ino)) and _is_valid_complete_cache_fd(cfd):
                ret_valid = cfd
                cfd = -1
                return ret_valid, None, None
            ret_rej = cfd
            cfd = -1
            return None, ret_rej, None
        finally:
            if cfd >= 0:
                with contextlib.suppress(OSError):
                    os.close(cfd)

    try:
        fcntl.flock(key_lock_fd, fcntl.LOCK_EX)
        warm_fd, init_rej_fd, _ = _probe_existing_cache_fd()
        if init_rej_fd is not None:
            os.close(init_rej_fd)
        if warm_fd is not None:
            return Path(os.readlink(f"/proc/self/fd/{deps_root_fd}")) / f"deps-{key}", warm_fd

        stage_fd = _create_exclusive_subdir_fd(stage_dir, 0o700)
        st_stage = os.fstat(stage_fd)
        stage_pin = pinned_proc_fd_path(stage_fd)
        own_fd = os.open(".ap-stage-owner", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=stage_fd)
        try:
            os.write(own_fd, f"{key}:{publish_id}\n".encode("utf-8"))
            os.fsync(own_fd)
            stage_owner_claimed = True
        finally:
            os.close(own_fd)
        if has_pnpm:
            for rel_p, raw_b in blobs:
                if rel_p in ("pnpm-lock.yaml", "pnpm-workspace.yaml") or rel_p.endswith("package.json") or rel_p.startswith("patches/"):
                    dest = stage_pin / rel_p
                    ensure_secure_dir(dest.parent, 0o700)
                    dest.write_bytes(raw_b)
            try:
                iproc = run_isolated_deps_prefetch(
                    inner_cmd=[*pnpm_prefix, "install", "--frozen-lockfile", "--ignore-scripts", "--config.package-import-method=copy"],
                    cwd=stage_pin,
                    stage_dir=stage_pin,
                    stage_fd=stage_fd,
                    timeout=240,
                )
            except (subprocess.SubprocessError, OSError) as exc:
                raise AutopilotError(f"pnpm install execution failed: {exc}") from exc
            if iproc.returncode != 0 or not (stage_pin / "node_modules").is_dir() or (stage_pin / "node_modules").is_symlink():
                detail = (iproc.stderr or iproc.stdout or "")[-400:]
                raise AutopilotError(f"Failed to materialize pnpm trusted_base_cache (rc={iproc.returncode}): {detail}")

        if cargo_locks:
            try:
                os.mkdir("cargo_home", 0o700, dir_fd=stage_fd)
            except FileExistsError as exc:
                raise AutopilotError("Untrusted prior prefetch stage already created cargo_home in stage_dir") from exc
            ch_init_fd = os.open("cargo_home", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage_fd)
            try:
                os.fchmod(ch_init_fd, 0o700)
                cargo_home_dir = Path(os.readlink(f"/proc/self/fd/{ch_init_fd}"))
            finally:
                os.close(ch_init_fd)

            try:
                tree_rev = subprocess.run(
                    ["git", "rev-parse", "--verify", f"{base_sha}^{{tree}}"],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=True,
                )
            except (subprocess.SubprocessError, OSError) as exc:
                raise AutopilotError(f"Failed to resolve base tree OID for {base_sha}: {exc}") from exc
            base_tree_oid = tree_rev.stdout.strip()
            cargo_tree_pin, cargo_tree_fd = export_verified_clean_tree(
                managed_gitdir=managed_gitdir,
                tree_oid=base_tree_oid,
                clean_tree_dir=cargo_tree_tmp,
                retain_fd=True,
            )
            for c_root, c_dirs, c_files in os.walk(cargo_tree_pin, followlinks=False):
                crp = Path(c_root)
                if ".cargo" in c_files:
                    (crp / ".cargo").unlink()
                if ".cargo" in c_dirs:
                    dc = crp / ".cargo"
                    if dc.is_symlink():
                        c_dirs.remove(".cargo")
                        dc.unlink()
                    else:
                        dc_fd = os.open(str(dc), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                        try:
                            for cfg_entry in ("config", "config.toml", "credentials", "credentials.toml"):
                                try:
                                    st_cfg = os.stat(cfg_entry, dir_fd=dc_fd, follow_symlinks=False)
                                except FileNotFoundError:
                                    continue
                                if stat.S_ISDIR(st_cfg.st_mode) and not stat.S_ISLNK(st_cfg.st_mode):
                                    sub_c_fd = os.open(cfg_entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dc_fd)
                                    try:
                                        empty_and_fsync_dirfd(sub_c_fd)
                                    finally:
                                        os.close(sub_c_fd)
                                    os.rmdir(cfg_entry, dir_fd=dc_fd)
                                else:
                                    os.unlink(cfg_entry, dir_fd=dc_fd)
                        finally:
                            os.close(dc_fd)

            cargo_real = str(Path(cargo_bin).expanduser().absolute())
            cargo_tree_dest = Path(os.readlink(f"/proc/self/fd/{cargo_tree_fd}"))
            for lock_rel in cargo_locks:
                lock_parent = (cargo_tree_pin / lock_rel).parent
                manifest_toml = lock_parent / "Cargo.toml"
                if not manifest_toml.is_file():
                    continue
                container_manifest = str((cargo_tree_dest / lock_rel).parent / "Cargo.toml")
                try:
                    cproc = run_isolated_deps_prefetch(
                        inner_cmd=[
                            cargo_real,
                            "--config",
                            "registry.global-credential-providers=[]",
                            "fetch",
                            "--locked",
                            "--manifest-path",
                            container_manifest,
                        ],
                        cwd=lock_parent,
                        stage_dir=stage_pin,
                        ro_source_tree=cargo_tree_pin,
                        stage_fd=stage_fd,
                        ro_source_tree_fd=cargo_tree_fd,
                        extra_env={"CARGO_HOME": str(cargo_home_dir)},
                        timeout=300,
                    )
                    mproc = run_isolated_deps_prefetch(
                        inner_cmd=[
                            cargo_real,
                            "--config",
                            "registry.global-credential-providers=[]",
                            "metadata",
                            "--locked",
                            "--format-version",
                            "1",
                            "--manifest-path",
                            container_manifest,
                        ],
                        cwd=lock_parent,
                        stage_dir=stage_pin,
                        ro_source_tree=cargo_tree_pin,
                        stage_fd=stage_fd,
                        ro_source_tree_fd=cargo_tree_fd,
                        extra_env={"CARGO_HOME": str(cargo_home_dir)},
                        timeout=120,
                    )
                except (subprocess.SubprocessError, OSError) as exc:
                    raise AutopilotError(f"cargo fetch/metadata execution failed: {exc}") from exc
                if cproc.returncode != 0 or mproc.returncode != 0:
                    detail = (cproc.stderr or mproc.stderr or cproc.stdout or "")[-400:]
                    raise AutopilotError(f"Failed to materialize Cargo.lock cache for {lock_rel}: {detail}")
            try:
                ch_fd = os.open("cargo_home", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage_fd)
            except OSError as exc:
                raise AutopilotError(f"Refusing tampered/symlinked cargo_home inside stage_dir: {exc}") from exc
            try:
                for cred_name in ("credentials", "credentials.toml"):
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(cred_name, dir_fd=ch_fd)
            finally:
                os.close(ch_fd)

        if go_sums:
            try:
                os.mkdir("go_mod_cache", 0o700, dir_fd=stage_fd)
            except FileExistsError as exc:
                raise AutopilotError("Untrusted prior prefetch stage already created go_mod_cache in stage_dir") from exc
            gm_init_fd = os.open("go_mod_cache", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage_fd)
            try:
                os.fchmod(gm_init_fd, 0o700)
                go_mod_dir = Path(os.readlink(f"/proc/self/fd/{gm_init_fd}"))
            finally:
                os.close(gm_init_fd)

            if cargo_tree_fd is None:
                try:
                    tree_rev_g = subprocess.run(
                        ["git", "rev-parse", "--verify", f"{base_sha}^{{tree}}"],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=True,
                    )
                except (subprocess.SubprocessError, OSError) as exc:
                    raise AutopilotError(f"Failed to resolve base tree OID for {base_sha}: {exc}") from exc
                cargo_tree_pin, cargo_tree_fd = export_verified_clean_tree(
                    managed_gitdir=managed_gitdir,
                    tree_oid=tree_rev_g.stdout.strip(),
                    clean_tree_dir=cargo_tree_tmp,
                    retain_fd=True,
                )
            go_tree_dest = Path(os.readlink(f"/proc/self/fd/{cargo_tree_fd}"))
            import fnmatch as _fnmatch

            def _matches_go_prefix_pattern(mod_path: str, pat: str) -> bool:
                """Match Go `module.MatchPrefixPatterns` segment-by-segment (`*` never crosses `/`)."""
                p_segs = [seg for seg in pat.strip().strip("/").split("/") if seg]
                m_segs = [seg for seg in mod_path.strip().strip("/").split("/") if seg]
                if not p_segs or len(m_segs) < len(p_segs):
                    return False
                return all(_fnmatch.fnmatchcase(ms, ps) for ms, ps in zip(m_segs[: len(p_segs)], p_segs))

            goprivate_env = os.environ.get("GOPRIVATE", "").strip()
            gonoproxy_env = os.environ.get("GONOPROXY", "").strip()
            raw_goenv = os.environ.get("GOENV", "")
            if raw_goenv and raw_goenv != "off":
                try:
                    with open(raw_goenv, "rb"):
                        pass
                except OSError as exc:
                    raise AutopilotError(f"Explicit GOENV file {raw_goenv!r} is missing or unreadable: {exc}") from exc
            if not goprivate_env or not gonoproxy_env:
                try:
                    ge_proc = subprocess.run(
                        [go_bin, "env", "-json", "GOPRIVATE", "GONOPROXY"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if ge_proc.returncode != 0:
                        raise AutopilotError(f"go env -json failed (rc={ge_proc.returncode}): {ge_proc.stderr.strip()}")
                    ge_json = json.loads(ge_proc.stdout or "{}")
                    if not isinstance(ge_json, dict) or not isinstance(ge_json.get("GOPRIVATE"), str) or not isinstance(ge_json.get("GONOPROXY"), str):
                        raise AutopilotError("go env -json returned malformed GOPRIVATE/GONOPROXY payload")
                except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as exc:
                    raise AutopilotError(f"Failed to query Go GOPRIVATE/GONOPROXY policy before public proxy prefetch: {exc}") from exc
                if not goprivate_env and ge_json["GOPRIVATE"].strip():
                    goprivate_env = ge_json["GOPRIVATE"].strip()
                if not gonoproxy_env and ge_json["GONOPROXY"].strip():
                    gonoproxy_env = ge_json["GONOPROXY"].strip()
            private_pats = [pat.strip() for pat in (goprivate_env + "," + gonoproxy_env).split(",") if pat.strip()]
            for gsum_rel in go_sums:
                gmod_parent = (cargo_tree_pin / gsum_rel).parent
                gmod_file = gmod_parent / "go.mod"
                gsum_file = cargo_tree_pin / gsum_rel
                if not gmod_file.is_file() or (gmod_parent / "vendor" / "modules.txt").is_file():
                    continue
                if private_pats:
                    mod_candidates: set[str] = set()
                    # Use `go mod edit -json` offline to parse exact Go module syntax (including `go*` & slashless domains!):
                    edit_proc = subprocess.run(
                        [go_bin, "mod", "edit", "-json", str(gmod_file)],
                        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "GOPROXY": "off", "GOTOOLCHAIN": "local"},
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    if edit_proc.returncode == 0:
                        gmod_json = json.loads(edit_proc.stdout or "{}")
                        for req_item in gmod_json.get("Require") or []:
                            if isinstance(req_item, dict) and req_item.get("Path"):
                                mod_candidates.add(str(req_item["Path"]))
                        for rep_item in gmod_json.get("Replace") or []:
                            if isinstance(rep_item, dict):
                                new_t = rep_item.get("New") or {}
                                np = str(new_t.get("Path") or "").strip()
                                if np and not np.startswith((".", "/")):
                                    mod_candidates.add(np)
                    else:
                        for raw_ln in gmod_file.read_text(encoding="utf-8", errors="replace").splitlines():
                            ln = raw_ln.split("//", 1)[0].strip()
                            toks = ln.split()
                            if not toks or toks[0] in ("module", "go", "toolchain", "exclude", "retract", ")"):
                                continue
                            if "=>" in ln:
                                rhs = ln.split("=>", 1)[1].strip().split()
                                if rhs and not rhs[0].startswith((".", "/")):
                                    mod_candidates.add(rhs[0].strip('"'))
                            cand_t = toks[1] if (toks[0] in ("require", "replace") and len(toks) >= 2 and toks[1] != "(") else toks[0]
                            if cand_t not in ("(", "require", "replace") and not cand_t.startswith((".", "/")):
                                mod_candidates.add(cand_t.strip('"'))
                    if gsum_file.is_file():
                        for sln in gsum_file.read_text(encoding="utf-8", errors="replace").splitlines():
                            stoks = sln.strip().split()
                            if stoks:
                                mod_candidates.add(stoks[0])
                    for cand_mod in sorted(mod_candidates):
                        if any(_matches_go_prefix_pattern(cand_mod, pat) for pat in private_pats):
                            raise AutopilotError(
                                f"Refusing public proxy prefetch for private Go module {cand_mod!r} in {gsum_rel} (vendor modules or disable GOPRIVATE)"
                            )
                try:
                    go_dl_env = {
                        "GOMODCACHE": str(go_mod_dir),
                        "GOPROXY": "https://proxy.golang.org",
                        "GOSUMDB": "sum.golang.org",
                        "GOFLAGS": "-modcacherw",
                    }
                    if goprivate_env:
                        go_dl_env["GOPRIVATE"] = goprivate_env
                    if gonoproxy_env:
                        go_dl_env["GONOPROXY"] = gonoproxy_env
                    gproc = run_isolated_deps_prefetch(
                        inner_cmd=[go_in_ring_bin, "mod", "download", "-modcacherw"],
                        cwd=gmod_parent,
                        stage_dir=stage_pin,
                        ro_source_tree=cargo_tree_pin,
                        stage_fd=stage_fd,
                        ro_source_tree_fd=cargo_tree_fd,
                        extra_env=go_dl_env,
                        timeout=300,
                    )
                except (subprocess.SubprocessError, OSError) as exc:
                    raise AutopilotError(f"go mod download execution failed: {exc}") from exc
                if gproc.returncode != 0:
                    detail = (gproc.stderr or gproc.stdout or "")[-400:]
                    raise AutopilotError(f"Failed to materialize go.sum cache for {gsum_rel}: {detail}")

        verify_trusted_base_cache_integrity(stage_pin)
        try:
            rfd = os.open(".ready", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=stage_fd)
        except OSError as exc:
            raise AutopilotError(f"Refusing pre-existing or symlinked .ready inside stage_dir: {exc}") from exc
        try:
            os.write(rfd, (base_sha + "\n").encode("utf-8"))
            os.fsync(rfd)
        finally:
            os.close(rfd)

        deps_root_real = Path(os.readlink(f"/proc/self/fd/{deps_root_fd}"))
        warm_fd2, pinned_stale_fd, rej_nondir_st = _probe_existing_cache_fd()
        if warm_fd2 is not None:
            return deps_root_real / f"deps-{key}", warm_fd2
        if pinned_stale_fd is not None or rej_nondir_st is not None:
            st_pinned = os.fstat(pinned_stale_fd) if pinned_stale_fd is not None else None
            stale_proven_by_receipt = (
                pinned_stale_fd is not None
                and st_pinned is not None
                and _has_matching_publish_receipt_fd(pinned_stale_fd, int(st_pinned.st_dev), int(st_pinned.st_ino))
            )
            try:
                stale_name = quarantine_noreplace_at_dirfd(deps_root_fd, f"deps-{key}", f".stale-deps-{key}")
                stale_verified_same = False
                if st_pinned is not None:
                    with contextlib.suppress(OSError):
                        st_mv = os.stat(stale_name, dir_fd=deps_root_fd, follow_symlinks=False)
                        stale_verified_same = (
                            int(st_mv.st_dev) == int(st_pinned.st_dev) and int(st_mv.st_ino) == int(st_pinned.st_ino)
                        )
                try:
                    os.replace(stage_name, f"deps-{key}", src_dir_fd=deps_root_fd, dst_dir_fd=deps_root_fd)
                finally:
                    # ONLY empty quarantined items whose ownership is proven by THIS key's publish receipt;
                    # preserve ALL regular backup files and unproven/foreign directories intact in `.stale-deps-*`!
                    if pinned_stale_fd is not None and stale_verified_same and stale_proven_by_receipt:
                        with contextlib.suppress(Exception):
                            empty_and_fsync_dirfd(pinned_stale_fd)
                        with contextlib.suppress(OSError):
                            os.rmdir(stale_name, dir_fd=deps_root_fd)
            finally:
                if pinned_stale_fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(pinned_stale_fd)
        else:
            os.replace(stage_name, f"deps-{key}", src_dir_fd=deps_root_fd, dst_dir_fd=deps_root_fd)

        # CRITICAL: Inside `key_lock_fd`, reopen `deps-{key}` with `O_NOFOLLOW`, verify `(dev, ino) == fstat(stage_fd)`,
        # AND persist `.deps-{key}.published.json` bound to `(key, dev, ino, publish_id)`!
        try:
            pub_fd = os.open(f"deps-{key}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=deps_root_fd)
        except OSError as exc:
            with contextlib.suppress(OSError):
                quarantine_noreplace_at_dirfd(deps_root_fd, f"deps-{key}", f".unverified-deps-{key}")
            raise AutopilotError(f"Published trusted_base_cache deps-{key} is not a regular directory: {exc}") from exc
        try:
            st_pub = os.fstat(pub_fd)
            if int(st_pub.st_dev) != int(st_stage.st_dev) or int(st_pub.st_ino) != int(st_stage.st_ino):
                with contextlib.suppress(OSError):
                    quarantine_noreplace_at_dirfd(deps_root_fd, f"deps-{key}", f".unverified-deps-{key}")
                raise AutopilotError(
                    f"Trusted base cache publish identity mismatch: deps-{key} ({st_pub.st_dev}, {st_pub.st_ino}) != stage ({st_stage.st_dev}, {st_stage.st_ino})"
                )
            _write_publish_receipt(int(st_pub.st_dev), int(st_pub.st_ino), publish_id)
            stage_promoted = True
            ret_pub_fd = pub_fd
            pub_fd = -1
            return deps_root_real / f"deps-{key}", ret_pub_fd
        finally:
            if pub_fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(pub_fd)
    finally:
        if cargo_tree_fd is not None:
            with contextlib.suppress(Exception):
                empty_and_fsync_dirfd(cargo_tree_fd)
            with contextlib.suppress(OSError):
                os.close(cargo_tree_fd)
            with contextlib.suppress(OSError):
                os.rmdir(cargo_tree_name, dir_fd=deps_root_fd)
        if stage_fd is not None:
            if stage_owner_claimed and not stage_promoted:
                with contextlib.suppress(Exception):
                    empty_and_fsync_dirfd(stage_fd)
            with contextlib.suppress(OSError):
                os.close(stage_fd)
            if stage_owner_claimed and not stage_promoted:
                with contextlib.suppress(OSError):
                    os.rmdir(stage_name, dir_fd=deps_root_fd)
        with contextlib.suppress(OSError):
            fcntl.flock(key_lock_fd, fcntl.LOCK_UN)
        with contextlib.suppress(OSError):
            os.close(key_lock_fd)
        with contextlib.suppress(OSError):
            os.close(deps_root_fd)


def _create_exclusive_subdir_fd(target_dir: Path, mode: int = 0o700) -> int:
    """Exclusively create `target_dir.name` inside verified `target_dir.parent` (`O_NOFOLLOW`, 0-entry check, zero `shutil.rmtree`!) and return open fd."""
    pfd = open_dir_nofollow(target_dir.parent, create=True, mode=0o700)
    try:
        os.mkdir(target_dir.name, mode, dir_fd=pfd)
        sub_fd = os.open(target_dir.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
        try:
            with os.scandir(sub_fd) as chk_it:
                if any(True for _ in chk_it):
                    raise AutopilotError(f"Refusing non-empty replaced directory {target_dir} before ownership claim")
            os.fchmod(sub_fd, mode)
            ret_fd = sub_fd
            sub_fd = -1
            return ret_fd
        finally:
            if sub_fd >= 0:
                os.close(sub_fd)
    except FileExistsError as exc:
        raise AutopilotError(f"Refusing to overwrite or rmtree pre-existing directory {target_dir}") from exc
    finally:
        os.close(pfd)


def export_verified_clean_tree(
    *,
    managed_gitdir: Path,
    tree_oid: str,
    clean_tree_dir: Path,
    retain_fd: bool = False,
) -> Path | tuple[Path, int]:
    """Materialize immutable $CLEAN_TREE into an exclusively-created open `ct_fd` and verify exact 1:1 OID parity on `ct_fd`!"""
    os.close(open_dir_nofollow(managed_gitdir, create=False))
    ct_fd = _create_exclusive_subdir_fd(clean_tree_dir, 0o700)
    try:
        ct_pin = pinned_proc_fd_path(ct_fd)
        parent_fd = open_dir_nofollow(clean_tree_dir.parent, create=False)
        try:
            parent_pin = pinned_proc_fd_path(parent_fd)
            idx_tag = f"{tree_oid[:12]}-{uuid.uuid4().hex[:8]}"
            tmp_idx = parent_pin / f".export-{idx_tag}.idx"
            verify_idx = parent_pin / f".verify-{idx_tag}.idx"
            env = _safe_git_env(git_dir=managed_gitdir, work_tree=ct_pin, index_file=tmp_idx)
            try:
                subprocess.run(["git", "read-tree", tree_oid], env=env, check=True, timeout=30, capture_output=True)
                subprocess.run(["git", "checkout-index", "-a", "-f"], env=env, check=True, timeout=60, capture_output=True)
                venv = _safe_git_env(git_dir=managed_gitdir, work_tree=ct_pin, index_file=verify_idx)
                try:
                    subprocess.run(["git", "read-tree", tree_oid], env=venv, check=True, timeout=30, capture_output=True)
                    subprocess.run(["git", "update-index", "-q", "--refresh"], env=venv, check=False, timeout=30, capture_output=True)
                    df = subprocess.run(["git", "diff-files", "--quiet"], env=venv, check=False, timeout=30, capture_output=True)
                    others = subprocess.run(
                        ["git", "ls-files", "--others", "-z"],
                        env=venv,
                        check=True,
                        timeout=30,
                        capture_output=True,
                    )
                    wt_proc = subprocess.run(
                        ["git", "write-tree"],
                        env=venv,
                        check=True,
                        timeout=30,
                        capture_output=True,
                        text=True,
                    )
                    recomputed_oid = wt_proc.stdout.strip()
                    if df.returncode != 0 or others.stdout != b"" or recomputed_oid != tree_oid:
                        raise AutopilotError(
                            f"CLEAN_TREE OID/parity mismatch: expected {tree_oid}, recomputed {recomputed_oid}, df={df.returncode}, others={others.stdout!r}"
                        )
                finally:
                    with contextlib.suppress(OSError):
                        os.unlink(verify_idx.name, dir_fd=parent_fd)
            finally:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_idx.name, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)

        if retain_fd:
            ret_fd = ct_fd
            ct_fd = -1
            return ct_pin, ret_fd
        return Path(os.readlink(f"/proc/self/fd/{ct_fd}"))
    finally:
        if ct_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(ct_fd)


def export_base_clean_tree(*, managed_gitdir: Path, base_sha: str, clean_tree_dir: Path) -> tuple[Path, int]:
    """Materialize the authorized base commit's tree as an immutable CLEAN_TREE (used to tell baseline-red from candidate-red)."""
    mg = managed_gitdir.resolve()
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", f"{base_sha}^{{tree}}"],
        env=_safe_git_env(git_dir=mg),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise AutopilotError(f"Unable to resolve tree of base {base_sha}: {proc.stderr.strip()}")
    out = export_verified_clean_tree(managed_gitdir=mg, tree_oid=proc.stdout.strip(), clean_tree_dir=clean_tree_dir, retain_fd=True)
    assert isinstance(out, tuple)
    return out


def export_review_bundle(
    *,
    managed_gitdir: Path,
    base_sha: str,
    candidate_sha: str,
    entries: list[tuple[str, str, str, str, str, str]],
    dod_check: str,
    issue_summary: str,
    bundle_dir: Path,
    retain_fd: bool = False,
) -> Path | tuple[Path, int]:
    """Create immutable /ap-review-bundle directly from Git blob OIDs into an exclusively-created open `rb_fd`!"""
    os.close(open_dir_nofollow(managed_gitdir, create=False))
    rb_fd = _create_exclusive_subdir_fd(bundle_dir, 0o700)
    try:
        rb_pin = pinned_proc_fd_path(rb_fd)
        env = _safe_git_env(git_dir=managed_gitdir)
        diff_proc = subprocess.run(
            ["git", "diff", "--no-ext-diff", "--binary", base_sha, candidate_sha],
            env=env,
            capture_output=True,
            timeout=30,
            check=True,
        )
        touched_paths = [rp for _, _, _, _, _, rp in entries]
        symlinks_meta: dict[str, str] = {}
        ctx_dir = rb_pin / "files"

        for _old_mode, new_mode, _old_oid, new_oid, status, rp in entries:
            if status == "D":
                continue
            blob_proc = subprocess.run(
                ["git", "cat-file", "blob", new_oid],
                env=env,
                capture_output=True,
                timeout=15,
                check=True,
            )
            if new_mode == "120000":
                symlinks_meta[rp] = blob_proc.stdout.decode("utf-8", errors="replace")
            elif new_mode in ("100644", "100755"):
                dst = ctx_dir / rp
                ensure_secure_dir(dst.parent, 0o700)
                dst.write_bytes(blob_proc.stdout)

        (rb_pin / "diff.patch").write_bytes(diff_proc.stdout)
        (rb_pin / "changed_files.json").write_text(
            json.dumps(
                {
                    "base_sha": base_sha,
                    "candidate_sha": candidate_sha,
                    "touched_files": touched_paths,
                    "symlinks": symlinks_meta,
                    "dod_check": dod_check,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (rb_pin / "issue_context.md").write_text(issue_summary.strip() + "\n", encoding="utf-8")
        if retain_fd:
            ret_rb = rb_fd
            rb_fd = -1
            return rb_pin, ret_rb
        return Path(os.readlink(f"/proc/self/fd/{rb_fd}"))
    finally:
        if rb_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(rb_fd)


def sample_and_gate_worktree(
    *,
    managed_gitdir: Path,
    wt_gitdir: Path,
    worktree: Path,
    repo_main: Path | None,
    run_dir: Path,
    base_sha: str,
    frozen_write_scope: list[str] | tuple[str, ...],
    approved_protected_paths: list[str] | tuple[str, ...] = (),
    dod_check: str = "",
    issue_summary: str = "",
    commit_message: str = "autopilot candidate",
    use_bwrap_git_ops: bool | None = None,
) -> CandidateGateResult:
    """Sample worktree inside read-only git_ops_ring via non-existent stage.idx + scratch-objects, gate, and mint C."""
    verify_dot_git_integrity(worktree, wt_gitdir)
    ensure_secure_dir(run_dir, 0o700)
    scratch_objects = ensure_secure_dir(run_dir / "scratch-objects", 0o700)
    stage_dir = ensure_secure_dir(run_dir / "stage_dir", 0o700)
    stage_idx = stage_dir / "stage.idx"
    if stage_idx.exists():
        stage_idx.unlink()

    mg_real = managed_gitdir.resolve()
    wt_gd_real = wt_gitdir.resolve()
    wt_real = worktree.resolve()
    seeded_from_wt_index = False
    wt_idx_src = wt_gd_real / "index"
    if wt_idx_src.is_file() and not wt_idx_src.is_symlink():
        shutil.copyfile(wt_idx_src, stage_idx)
        seeded_from_wt_index = True

    alt_dirs = [mg_real / "objects"]
    main_obj = resolve_repo_common_objects_dir(repo_main) if repo_main is not None else None
    if main_obj is not None:
        alt_dirs.append(main_obj)

    sample_env = _safe_git_env(
        git_dir=wt_gd_real,
        git_common_dir=mg_real,
        work_tree=wt_real,
        index_file=stage_idx.resolve(),
        object_dir=scratch_objects.resolve(),
        alt_object_dirs=alt_dirs,
    )

    run_in_ring = (shutil.which("bwrap") is not None) if use_bwrap_git_ops is None else use_bwrap_git_ops
    tree_out_file = stage_dir.resolve() / "tree_oid.txt"
    diff_out_file = stage_dir.resolve() / "diff_raw.bin"
    if tree_out_file.exists():
        tree_out_file.unlink()
    if diff_out_file.exists():
        diff_out_file.unlink()

    if run_in_ring:
        read_tree_flag = "-m " if seeded_from_wt_index else ""
        ring_script = (
            "set -euo pipefail; "
            f'git read-tree {read_tree_flag}"{base_sha}" && '
            "git add -A && "
            f'tree_oid=$(git write-tree) && printf "%s" "$tree_oid" > "{tree_out_file}" && '
            f'git diff-tree --raw -r --no-renames -z "{base_sha}" "$tree_oid" > "{diff_out_file}"'
        )
        ring_argv = build_execution_ring_bwrap(
            ring_kind="git_ops_ring",
            inner_cmd=["/bin/bash", "-c", ring_script],
            cwd=wt_real,
            worktree=wt_real,
            managed_gitdir=mg_real,
            repo_main_objects=main_obj,
            scratch_objects=scratch_objects.resolve(),
            stage_dir=stage_dir.resolve(),
            git_cleanup_writable=False,
            extra_env={
                "GIT_DIR": str(wt_gd_real),
                "GIT_COMMON_DIR": str(mg_real),
                "GIT_WORK_TREE": str(wt_real),
                "GIT_INDEX_FILE": str(stage_idx.resolve()),
                "GIT_OBJECT_DIRECTORY": str(scratch_objects.resolve()),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": os.pathsep.join(str(p) for p in alt_dirs),
            },
        )
        r_proc = subprocess.run(ring_argv, capture_output=True, text=True, timeout=300, check=False)
        if r_proc.returncode != 0:
            raise AutopilotError(f"git_ops_ring sampling failed: {r_proc.stderr.strip() or r_proc.stdout.strip()}")
        tree_oid = tree_out_file.read_text(encoding="utf-8").strip()
        diff_raw_bytes = diff_out_file.read_bytes()
    else:
        rt_cmd = ["git", "read-tree", *(["-m"] if seeded_from_wt_index else []), base_sha]
        subprocess.run(rt_cmd, env=sample_env, check=True, timeout=60, capture_output=True)
        subprocess.run(["git", "add", "-A"], env=sample_env, check=True, timeout=180, capture_output=True)
        wt_res = subprocess.run(
            ["git", "write-tree"],
            env=sample_env,
            check=True,
            timeout=30,
            capture_output=True,
            text=True,
        )
        tree_oid = wt_res.stdout.strip()
        dt_res = subprocess.run(
            ["git", "diff-tree", "--raw", "-r", "--no-renames", "-z", base_sha, tree_oid],
            env=sample_env,
            check=True,
            timeout=30,
            capture_output=True,
        )
        diff_raw_bytes = dt_res.stdout

    entries = parse_diff_tree_raw_z(diff_raw_bytes)
    if not entries:
        raise EmptyCandidateError("Candidate produced empty diff against base_sha")

    raw_paths: list[str] = []
    for old_mode, new_mode, old_oid, new_oid, status, raw_path in entries:
        validate_raw_git_path(raw_path, old_mode=old_mode, new_mode=new_mode)
        raw_paths.append(raw_path)
        if status != "D" and new_mode in ("100644", "100755"):
            base_oid = old_oid if (status == "M" and old_mode in ("100644", "100755")) else ""
            _scan_blob_for_secrets(sample_env, new_oid, raw_path, base_blob_oid=base_oid)

    check_autopilot_scope(raw_paths, frozen_write_scope, approved_protected_paths=approved_protected_paths)

    _promote_scratch_objects(scratch_objects, mg_real / "objects")
    mg_env = _safe_git_env(git_dir=mg_real, alt_object_dirs=alt_dirs[1:])
    mg_env.update(
        {
            "GIT_AUTHOR_NAME": "agent-autopilot",
            "GIT_AUTHOR_EMAIL": "autopilot@local.invalid",
            "GIT_COMMITTER_NAME": "agent-autopilot",
            "GIT_COMMITTER_EMAIL": "autopilot@local.invalid",
        }
    )
    ct_res = subprocess.run(
        ["git", "commit-tree", tree_oid, "-p", base_sha, "-m", commit_message],
        env=mg_env,
        check=True,
        timeout=15,
        capture_output=True,
        text=True,
    )
    candidate_sha = ct_res.stdout.strip()

    exp_tag = f"{candidate_sha[:12]}-{uuid.uuid4().hex[:6]}"
    clean_tree_dir, ct_fd = export_verified_clean_tree(
        managed_gitdir=mg_real,
        tree_oid=tree_oid,
        clean_tree_dir=run_dir / f"clean-tree-{exp_tag}",
        retain_fd=True,
    )
    try:
        bundle_dir, rb_fd = export_review_bundle(
            managed_gitdir=mg_real,
            base_sha=base_sha,
            candidate_sha=candidate_sha,
            entries=entries,
            dod_check=dod_check,
            issue_summary=issue_summary,
            bundle_dir=run_dir / f"review-bundle-{exp_tag}",
            retain_fd=True,
        )
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(ct_fd)
        raise
    return CandidateGateResult(
        candidate_sha=candidate_sha,
        tree_oid=tree_oid,
        touched_paths=tuple(raw_paths),
        clean_tree_dir=clean_tree_dir,
        review_bundle_dir=bundle_dir,
        clean_tree_fd=ct_fd,
        review_bundle_fd=rb_fd,
    )


def verify_worktree_clean(*, managed_gitdir: Path, wt_gitdir: Path, worktree: Path) -> bool:
    """Verify worktree is 100% clean including gitignored files (__pycache__, etc.)."""
    try:
        verify_dot_git_integrity(worktree, wt_gitdir)
    except ScopeViolationError:
        return False
    env = _safe_git_env(
        git_dir=wt_gitdir.resolve(),
        git_common_dir=managed_gitdir.resolve(),
        work_tree=worktree.resolve(),
    )
    st = subprocess.run(
        ["git", "status", "--porcelain=v1", "--ignored=matching", "-z"],
        env=env,
        capture_output=True,
        timeout=20,
        check=False,
    )
    cl = subprocess.run(
        ["git", "clean", "-nffdx"],
        env=env,
        capture_output=True,
        timeout=20,
        check=False,
    )
    return st.returncode == 0 and cl.returncode == 0 and st.stdout == b"" and cl.stdout == b""


def scrub_worktree_to_base(*, managed_gitdir: Path, wt_gitdir: Path, worktree: Path, base_sha: str) -> int:
    """Verify exact `.git` backpointer AND refuse real `.git/` directories/symlinks BEFORE touching worktree!"""
    import stat

    if worktree.is_symlink() or managed_gitdir.is_symlink() or wt_gitdir.is_symlink():
        raise AutopilotError("Refusing symlinked worktree or gitdir in scrub_worktree_to_base")
    os.close(open_dir_nofollow(managed_gitdir, create=False))
    os.close(open_dir_nofollow(wt_gitdir, create=False))
    os.close(open_dir_nofollow(worktree, create=False))
    mg_real = Path(os.path.normpath(str(managed_gitdir)))
    wt_gd_real = Path(os.path.normpath(str(wt_gitdir)))
    wt_real = Path(os.path.normpath(str(worktree)))
    if wt_gd_real.parent != (mg_real / "worktrees") or not (mg_real / "HEAD").is_file():
        raise AutopilotError(f"Invalid managed worktree metadata path: {wt_gd_real} not under {mg_real / 'worktrees'}")
    try:
        os.lstat(wt_gd_real / "locked")
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise AutopilotError(f"Refusing to scrub {wt_real}: unable to inspect {wt_gd_real}/locked ({exc})") from exc
    else:
        raise AutopilotError(f"Refusing to scrub locked worktree {wt_real} ({wt_gd_real}/locked present)")

    proc_pfx = f"/proc/{os.getpid()}/fd/"
    canon_wt = wt_real.resolve() if str(wt_real).startswith(proc_pfx) else wt_real
    canon_wt_gd = wt_gd_real.resolve() if str(wt_gd_real).startswith(proc_pfx) else wt_gd_real

    gitdir_ptr = wt_gd_real / "gitdir"
    try:
        if not gitdir_ptr.is_file() or gitdir_ptr.is_symlink():
            raise AutopilotError(f"Missing registered gitdir backpointer in {wt_gd_real}; refusing to touch {wt_real}")
        raw_ptr = gitdir_ptr.read_text(encoding="utf-8", errors="replace").strip()
    except OSError as exc:
        raise AutopilotError(f"Unreadable gitdir backpointer in {wt_gd_real} ({exc}); refusing to touch {wt_real}") from exc
    registered_dot_git = Path(os.path.normpath(raw_ptr))
    expected_dot_git = Path(os.path.normpath(str(canon_wt / ".git")))
    if registered_dot_git != expected_dot_git:
        raise AutopilotError(
            f"Worktree ownership mismatch: {wt_gd_real}/gitdir points to {registered_dot_git}, not exact {expected_dot_git}; refusing to touch {wt_real}"
        )

    # CRITICAL: Inspect `<wt>/.git` via `os.lstat` BEFORE writing or running `git reset --hard`:
    # - Refuse directories or symlinks (e.g. standalone repo at reused path);
    # - If regular gitfile exists, verify its `gitdir:` target points to `canon_wt_gd` (refusing worktree of another repo!).
    dot_git = wt_real / ".git"
    try:
        st_dg = os.lstat(dot_git)
        if stat.S_ISDIR(st_dg.st_mode) or stat.S_ISLNK(st_dg.st_mode) or not stat.S_ISREG(st_dg.st_mode):
            raise AutopilotError(
                f"Refusing to scrub {wt_real}: {dot_git} is not a regular gitfile (possible standalone repository)"
            )
        existing_gf = dot_git.read_text(encoding="utf-8", errors="replace").strip()
        if not existing_gf.startswith("gitdir:"):
            raise AutopilotError(f"Refusing to scrub {wt_real}: malformed .git file header")
        gf_target_raw = existing_gf[len("gitdir:") :].strip()
        gf_target = Path(os.path.normpath(str((canon_wt / gf_target_raw) if not os.path.isabs(gf_target_raw) else gf_target_raw)))
        if gf_target != canon_wt_gd:
            raise AutopilotError(
                f"Refusing to scrub {wt_real}: existing .git gitfile points to {gf_target}, not {canon_wt_gd} (foreign worktree)"
            )
    except FileNotFoundError as exc:
        # In model_ring and tool_ring, `<wt>/.git` is read-only mounted; a non-empty directory missing `.git` has unproven ownership!
        if any(wt_real.iterdir()):
            raise AutopilotError(
                f"Refusing to scrub non-empty directory {wt_real} missing .git gitfile (unproven ownership)"
            ) from exc

    # Verify base_sha resolves inside managed_gitdir BEFORE modifying anything in worktree!
    chk_env = _safe_git_env(git_dir=mg_real)
    chk_base = subprocess.run(
        ["git", "rev-parse", "--verify", f"{base_sha}^{{commit}}"],
        env=chk_env,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if chk_base.returncode != 0:
        raise AutopilotError(f"base_sha {base_sha!r} not found in {mg_real}; refusing worktree scrub")

    dot_git.write_bytes(f"gitdir: {canon_wt_gd}\n".encode("utf-8"))
    with contextlib.suppress(OSError):
        idx_lock = wt_gd_real / "index.lock"
        if not idx_lock.is_symlink() and idx_lock.is_file():
            idx_lock.unlink()
    env = _safe_git_env(
        git_dir=wt_gd_real,
        git_common_dir=mg_real,
        work_tree=wt_real,
    )
    r1 = subprocess.run(["git", "reset", "--hard", base_sha], env=env, capture_output=True, timeout=240, check=False)
    r2 = subprocess.run(["git", "clean", "-ffdx"], env=env, capture_output=True, timeout=240, check=False)
    if r1.returncode != 0 or r2.returncode != 0:
        return 1
    return 0 if verify_worktree_clean(managed_gitdir=mg_real, wt_gitdir=wt_gd_real, worktree=wt_real) else 1
