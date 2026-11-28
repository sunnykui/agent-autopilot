"""Multi-ring bwrap/Landlock sandbox assembly, CONNECT allowlist proxy, tool-exec server, and systemd cgroup lifecycle."""
from __future__ import annotations

import contextlib
import datetime as dt
import errno
import fcntl
import json
import math
import os
import pwd
import re
import select
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from .host_guard import CPU_FANOUT_LIMIT_ENV
from .models import POLICY_MANIFEST, SandboxError, ensure_secure_dir, sanitize_terminal_text

# Background transient units yield CPU to interactive sessions inside their slice (slice-level CPUQuota is the hard cap).
BACKGROUND_UNIT_NICE = 15

_CONNECT_LINE_RE = re.compile(r"^CONNECT\s+([A-Za-z0-9._-]+):(\d+)\s+HTTP/1\.[01]$", re.IGNORECASE)
_IP_LITERAL_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^\[.*\]$")


def current_uid() -> int:
    return os.getuid()


def current_username() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def user_systemd_permanent_anchor(uid: int | None = None) -> Path:
    u = uid if uid is not None else current_uid()
    return Path(f"/sys/fs/cgroup/user.slice/user-{u}.slice/user@{u}.service")


def check_linger_enabled(username: str | None = None) -> bool:
    user = username or current_username()
    linger_file = Path("/var/lib/systemd/linger") / user
    if linger_file.exists():
        return True
    proc = subprocess.run(
        ["loginctl", "show-user", user, "-p", "Linger", "--value"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return proc.returncode == 0 and proc.stdout.strip().lower() == "yes"


def verify_native_binaries(ap_sandbox_init: Path, ap_safe_sh: Path) -> None:
    for label, p in (("ap_sandbox_init", ap_sandbox_init), ("ap_safe_sh", ap_safe_sh)):
        if not p.is_file() or p.is_symlink():
            raise SandboxError(f"{label} must be a regular non-symlink binary: {p}")
        if not os.access(p, os.X_OK):
            raise SandboxError(f"{label} is not executable: {p}")
    st_init = ap_sandbox_init.stat()
    st_sh = ap_safe_sh.stat()
    if st_init.st_dev == st_sh.st_dev and st_init.st_ino == st_sh.st_ino:
        raise SandboxError(
            f"ap_sandbox_init and ap_safe_sh MUST have distinct inodes (got inode {st_init.st_ino})"
        )


def _normalize_usr_merged_lib_path(path_str: str) -> str:
    if path_str.startswith("/lib64/"):
        return "/usr" + path_str
    if path_str.startswith("/lib/"):
        return "/usr" + path_str
    return path_str


def resolve_elf_runtime_mounts(elf_path: Path, stage_lib_dir: Path) -> list[tuple[str, str]]:
    """Discover dynamic loader + .so dependencies; normalize /lib64 -> /usr/lib64 and stage .so files 0644."""
    ensure_secure_dir(stage_lib_dir, 0o700)
    proc = subprocess.run(
        ["ldd", str(elf_path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode != 0 or "not a dynamic executable" in (proc.stdout + proc.stderr):
        return []

    mounts: list[tuple[str, str]] = []
    seen_targets: set[str] = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        host_p: Path | None = None
        target_p: str | None = None
        if "=>" in line:
            _left, right = line.split("=>", 1)
            right_tok = right.strip().split(" ", 1)[0].strip()
            if right_tok.startswith("/"):
                host_p = Path(right_tok)
                target_p = _normalize_usr_merged_lib_path(right_tok)
        elif line.startswith("/"):
            tok = line.split(" ", 1)[0].strip()
            host_p = Path(tok)
            target_p = _normalize_usr_merged_lib_path(tok)
        if host_p and target_p and target_p not in seen_targets and host_p.exists():
            seen_targets.add(target_p)
            resolved = host_p.resolve()
            if "ld-linux" in target_p:
                mounts.append((str(resolved), target_p))
            else:
                staged = stage_lib_dir / f"{len(mounts)}_{resolved.name}"
                if not staged.exists():
                    tmp_staged = stage_lib_dir / f".{staged.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                    try:
                        shutil.copyfile(resolved, tmp_staged)
                        os.chmod(tmp_staged, 0o644)
                        os.replace(tmp_staged, staged)
                    finally:
                        with contextlib.suppress(OSError):
                            if tmp_staged.exists():
                                tmp_staged.unlink()
                mounts.append((str(staged), target_p))
    return mounts


def _write_file_at_dirfd(dir_fd: int, filename: str, content: bytes, mode: int, *, dir_owner_token: str = "") -> None:
    """Create unnamed `O_TMPFILE`, stamp `user.ap_owned_file` & write content + `fsync`, THEN atomically `linkat` to `filename`!"""
    from .models import set_owned_file_token

    tfd = os.open(".", os.O_WRONLY | os.O_TMPFILE, mode, dir_fd=dir_fd)
    try:
        os.fchmod(tfd, mode)
        set_owned_file_token(tfd, dir_owner_token)
        mv = memoryview(content)
        off = 0
        while off < len(mv):
            off += os.write(tfd, mv[off:])
        os.fsync(tfd)
        os.link(f"/proc/{os.getpid()}/fd/{tfd}", filename, dst_dir_fd=dir_fd, follow_symlinks=True)
        os.fsync(dir_fd)
    finally:
        os.close(tfd)


def _write_registered_secret_file_at_dirfd(
    dir_fd: int,
    filename: str,
    content: bytes,
    mode: int,
    *,
    db: Any = None,
    claim_epoch: int | None = None,
    label: str = "",
    dir_owner_token: str = "",
    local_tracker: dict[tuple[int, int], str] | None = None,
) -> tuple[int, int, str]:
    """Create 0-byte `O_TMPFILE`, stamp `user.ap_cred_id` + `user.ap_owned_file` + `fsync`, `linkat` to `filename`, record rollback/SQLite BEFORE writing secret!"""
    from .models import set_cred_owner_token, set_owned_file_token

    ftok = uuid.uuid4().hex
    tfd = os.open(".", os.O_WRONLY | os.O_TMPFILE, mode, dir_fd=dir_fd)
    try:
        os.fchmod(tfd, mode)
        set_cred_owner_token(tfd, ftok)
        set_owned_file_token(tfd, dir_owner_token)
        os.fsync(tfd)
        os.link(f"/proc/{os.getpid()}/fd/{tfd}", filename, dst_dir_fd=dir_fd, follow_symlinks=True)
        os.fsync(dir_fd)
        st_f = os.fstat(tfd)
        if st_f.st_nlink != 1:
            raise SandboxError(f"Unexpected hardlink count ({st_f.st_nlink}) on newly created secret file {filename}")
        if local_tracker is not None:
            local_tracker[(int(st_f.st_dev), int(st_f.st_ino))] = ftok
        if db is not None and claim_epoch is not None:
            db.register_claim_credential_dir(
                int(claim_epoch),
                int(st_f.st_dev),
                int(st_f.st_ino),
                label or filename,
                entry_kind="file",
                owner_token=ftok,
            )
        mv = memoryview(content)
        off = 0
        while off < len(mv):
            off += os.write(tfd, mv[off:])
        os.fsync(tfd)
        return int(st_f.st_dev), int(st_f.st_ino), ftok
    finally:
        os.close(tfd)


def _make_memfd_with_bytes(name: str, data: bytes) -> int:
    mfd = os.memfd_create(name)
    try:
        mv = memoryview(data)
        off = 0
        while off < len(mv):
            off += os.write(mfd, mv[off:])
        os.lseek(mfd, 0, os.SEEK_SET)
        ret = mfd
        mfd = -1
        return ret
    finally:
        if mfd >= 0:
            os.close(mfd)


def _project_codex_auth_for_sandbox(raw_auth: Any) -> dict[str, Any]:
    """Project Codex CLI `auth.json` satisfying Rust `TokenData` serde schema while stripping real `refresh_token`."""
    from .models import now_iso

    if not isinstance(raw_auth, dict):
        return {}
    toks = raw_auth.get("tokens")
    if isinstance(toks, dict) and toks.get("access_token"):
        return {
            "auth_mode": raw_auth.get("auth_mode") or "chatgpt",
            "OPENAI_API_KEY": None,
            "tokens": {
                "id_token": str(toks.get("id_token") or ""),
                "access_token": toks["access_token"],
                "refresh_token": "sandbox-norefresh",
                **({"account_id": toks["account_id"]} if toks.get("account_id") else {}),
            },
            "last_refresh": now_iso().replace("+00:00", "Z"),
        }
    if isinstance(raw_auth.get("OPENAI_API_KEY"), str) and raw_auth["OPENAI_API_KEY"].strip():
        return {"auth_mode": "apikey", "OPENAI_API_KEY": raw_auth["OPENAI_API_KEY"].strip()}
    return {}


def _project_agy_auth_for_sandbox(raw_auth: Any, *, now: dt.datetime | None = None) -> dict[str, Any]:
    """Project AGY consumer OAuth token strictly stripping `refresh_token` and `id_token_email`."""
    if not isinstance(raw_auth, dict):
        return {}
    tok = raw_auth.get("token")
    if not isinstance(tok, dict):
        return {}
    access_token = tok.get("access_token")
    if not isinstance(access_token, str) or not access_token.strip():
        return {}
    expiry_raw = tok.get("expiry")
    if "expiry" in tok:
        if not isinstance(expiry_raw, str) or not expiry_raw.strip():
            raise SandboxError("AGY OAuth token has malformed non-string/null/empty expiry")
        try:
            exp_dt = dt.datetime.fromisoformat(expiry_raw.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise SandboxError(f"AGY OAuth token has unparseable expiry timestamp: {expiry_raw!r}") from exc
        if exp_dt.tzinfo is None:
            raise SandboxError(f"AGY OAuth token expiry must include explicit timezone offset: {expiry_raw!r}")
        ref_now = now or dt.datetime.now(dt.timezone.utc)
        # Reject tokens that are already expired OR within the 60s pre-expiry refresh window (sandbox has no refresh_token!)
        if exp_dt <= ref_now + dt.timedelta(seconds=60):
            raise SandboxError(
                f"AGY OAuth access_token expired or within 60s refresh window ({expiry_raw}); refresh on host before invoking sandbox"
            )
    projected_tok: dict[str, Any] = {
        "access_token": access_token.strip(),
        "token_type": str(tok.get("token_type") or "Bearer"),
    }
    if isinstance(expiry_raw, str) and expiry_raw.strip():
        projected_tok["expiry"] = expiry_raw.strip()
    expires_in = tok.get("expires_in")
    if isinstance(expires_in, int) and not isinstance(expires_in, bool) and expires_in >= 0:
        projected_tok["expires_in"] = expires_in
    return {
        "auth_method": str(raw_auth.get("auth_method") or "consumer"),
        "token": projected_tok,
    }


def _read_host_agy_oauth_nofollow(host_home: Path) -> dict[str, Any]:
    """Open `~/.gemini/antigravity-cli/antigravity-oauth-token` via O_NOFOLLOW with type/size checks."""
    from .models import AutopilotError, open_dir_nofollow

    tok_dir = host_home / ".gemini" / "antigravity-cli"
    try:
        dfd = open_dir_nofollow(tok_dir, create=False)
    except (AutopilotError, OSError) as exc:
        raise SandboxError(f"AGY OAuth directory unavailable or unsafe ({tok_dir}): {exc}") from exc
    try:
        try:
            ffd = os.open("antigravity-oauth-token", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except OSError as exc:
            raise SandboxError(f"AGY OAuth token file unavailable or symlinked in {tok_dir}: {exc}") from exc
        try:
            st = os.fstat(ffd)
            if not stat.S_ISREG(st.st_mode):
                raise SandboxError("AGY OAuth token entry is not a regular file")
            if st.st_size <= 0 or st.st_size > 65536:
                raise SandboxError(f"AGY OAuth token file has unexpected size: {st.st_size}")
            raw_bytes = os.read(ffd, 65537)
            if len(raw_bytes) > 65536:
                raise SandboxError("AGY OAuth token file exceeded 64 KiB cap")
            try:
                parsed = json.loads(raw_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SandboxError(f"AGY OAuth token file is not valid JSON: {exc}") from exc
            if not isinstance(parsed, dict):
                raise SandboxError("AGY OAuth token JSON must be an object")
            return parsed
        finally:
            os.close(ffd)
    finally:
        os.close(dfd)


def resolve_family_proxy_allowlist(family: str) -> set[str]:
    """Return strict per-family CONNECT proxy allowlist from policy_manifest.json (fail closed if missing)."""
    fam_map = POLICY_MANIFEST.get("family_llm_proxy_allowlist_domains")
    if not isinstance(fam_map, dict) or family not in fam_map:
        raise SandboxError(f"No proxy domain allowlist configured for model family: {family!r}")
    domains = {str(d).strip().lower() for d in fam_map[family] if str(d).strip()}
    if not domains:
        raise SandboxError(f"Empty proxy domain allowlist for model family: {family!r}")
    return domains


def _flock_shared_with_deadline(fd: int, *, timeout_sec: float = 10.0, label: str = "credential lock") -> None:
    """Acquire non-blocking LOCK_SH within a bounded deadline so a wedged lock can never stall worker/referee shutdown."""
    deadline = time.monotonic() + max(0.1, float(timeout_sec))
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return
        except BlockingIOError as exc:
            if time.monotonic() >= deadline:
                raise SandboxError(f"Timed out after {timeout_sec:.1f}s waiting for {label}") from exc
            time.sleep(0.05)


def prepare_sandbox_home_memfds(
    family: str,
    *,
    role_key: str = "",
    host_home: Path | None = None,
) -> dict[str, int]:
    """Project ONLY role-authorized OAuth/config files into anonymous in-RAM `memfd`s (ZERO host disk files or swaps!)."""
    hhome = host_home or Path.home()
    out: dict[str, int] = {}
    try:
        if family == "claude":
            cred_src = hhome / ".claude" / ".credentials.json"
            lock_path = hhome / ".claude" / ".credentials.lock"
            if cred_src.is_file():
                lock_path.parent.mkdir(parents=True, exist_ok=True)
                lfd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    _flock_shared_with_deadline(lfd, label="claude credentials lock")
                    raw = json.loads(cred_src.read_text(encoding="utf-8"))
                finally:
                    with contextlib.suppress(OSError):
                        fcntl.flock(lfd, fcntl.LOCK_UN)
                    os.close(lfd)
                oauth = raw.get("claudeAiOauth")
                if isinstance(oauth, dict) and oauth.get("accessToken"):
                    projected = {
                        "claudeAiOauth": {
                            "accessToken": oauth["accessToken"],
                            "expiresAt": oauth.get("expiresAt"),
                            "scopes": oauth.get("scopes", []),
                        }
                    }
                    out["/home/sandbox/.claude/.credentials.json"] = _make_memfd_with_bytes(
                        "ap_claude_cred", (json.dumps(projected, indent=2) + "\n").encode("utf-8")
                    )
            role_spec = POLICY_MANIFEST["role_matrix"].get(role_key or "claude:readonly_model", {})
            allowed_tools = list(role_spec.get("claude_tools") or ["Read", "Glob", "Grep"])
            settings = {
                "permissions": {
                    "allow": allowed_tools,
                    "deny": list(POLICY_MANIFEST["claude_permission_deny"]),
                }
            }
            out["/home/sandbox/.claude/settings.json"] = _make_memfd_with_bytes(
                "ap_claude_settings", (json.dumps(settings, indent=2) + "\n").encode("utf-8")
            )
        elif family == "codex":
            host_codex = hhome / ".codex"
            auth_src = host_codex / "auth.json"
            lock_path = host_codex / ".auth.lock"
            if auth_src.is_file():
                lock_path.parent.mkdir(parents=True, exist_ok=True)
                lfd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    _flock_shared_with_deadline(lfd, label="codex auth lock")
                    raw_auth = json.loads(auth_src.read_text(encoding="utf-8"))
                finally:
                    with contextlib.suppress(OSError):
                        fcntl.flock(lfd, fcntl.LOCK_UN)
                    os.close(lfd)
                projected_codex = _project_codex_auth_for_sandbox(raw_auth)
                if projected_codex:
                    out["/home/sandbox/.codex/auth.json"] = _make_memfd_with_bytes(
                        "ap_codex_auth", (json.dumps(projected_codex, indent=2) + "\n").encode("utf-8")
                    )
            mc_src = host_codex / "models_cache.json"
            if mc_src.is_file():
                out["/home/sandbox/.codex/models_cache.json"] = _make_memfd_with_bytes("ap_codex_mc", mc_src.read_bytes())
            out["/home/sandbox/.codex/config.toml"] = _make_memfd_with_bytes(
                "ap_codex_cfg", b"[features]\nmulti_agent = false\n"
            )
        elif family == "agy":
            raw_agy = _read_host_agy_oauth_nofollow(hhome)
            projected_agy = _project_agy_auth_for_sandbox(raw_agy)
            if not projected_agy:
                raise SandboxError("AGY OAuth token missing valid access_token for sandbox projection")
            out["/home/sandbox/.gemini/antigravity-cli/antigravity-oauth-token"] = _make_memfd_with_bytes(
                "ap_agy_oauth", (json.dumps(projected_agy, indent=2) + "\n").encode("utf-8")
            )
            role_spec = POLICY_MANIFEST["role_matrix"].get(role_key or "agy:readonly_model", {})
            deny_rules = [
                *list(POLICY_MANIFEST.get("agy_permission_deny") or []),
                *list(role_spec.get("agy_extra_permission_deny") or []),
            ]
            allow_rules = list(role_spec.get("agy_permission_allow") or [])
            agy_settings = {
                "permissions": {
                    "allow": allow_rules,
                    "deny": deny_rules,
                }
            }
            out["/home/sandbox/.gemini/antigravity-cli/settings.json"] = _make_memfd_with_bytes(
                "ap_agy_settings", (json.dumps(agy_settings, indent=2) + "\n").encode("utf-8")
            )
            # Mount empty MCP/hooks configs so no host MCP servers or hooks can load inside sandbox!
            out["/home/sandbox/.gemini/config/mcp_config.json"] = _make_memfd_with_bytes("ap_agy_mcp", b"{}\n")
            out["/home/sandbox/.gemini/config/hooks.json"] = _make_memfd_with_bytes("ap_agy_hooks", b"{}\n")
        else:
            raise SandboxError(f"Unsupported model family: {family!r}")
        ret_out = out
        out = {}
        return ret_out
    finally:
        for _fd in out.values():
            with contextlib.suppress(OSError):
                os.close(_fd)


def prepare_sandbox_home_fd(
    run_dir: Path,
    family: str,
    *,
    role_key: str = "",
    host_home: Path | None = None,
    run_dir_fd: int | None = None,
    db: Any = None,
    claim_epoch: int | None = None,
) -> tuple[Path, int, str, int]:
    """Create 0700 sandbox_home via `run_dir_fd`, register `(dev, ino)` in `db` BEFORE writing tokens, and return OPEN `sbh_fd`!"""
    from .models import AutopilotError, open_dir_nofollow, pinned_proc_fd_path, set_cred_owner_token

    hhome = host_home or Path.home()
    sbh_name = f"sandbox_home_{family}_{uuid.uuid4().hex[:8]}"
    try:
        rfd = os.dup(run_dir_fd) if run_dir_fd is not None else open_dir_nofollow(run_dir, create=True, mode=0o700)
    except (AutopilotError, OSError) as exc:
        raise SandboxError(f"Invalid run_dir for prepare_sandbox_home ({run_dir}): {exc}") from exc

    sbh_fd: int | None = None
    sub_fd: int | None = None
    sbh_verified_fresh = False
    sub_verified_fresh = False
    registered_in_ledger = False
    registered_sub_in_ledger = False
    st_sub: os.stat_result | None = None
    created_sub_name: str | None = None
    created_sub_files: list[str] = []
    registered_secret_files: list[tuple[str, int, int]] = []
    local_secret_file_toks: dict[tuple[int, int], str] = {}
    sbh_tok = uuid.uuid4().hex
    sub_tok = uuid.uuid4().hex
    try:
        os.mkdir(sbh_name, 0o700, dir_fd=rfd)
        sbh_fd = os.open(sbh_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rfd)
        with os.scandir(sbh_fd) as init_it:
            if any(True for _ in init_it):
                raise SandboxError(f"Refusing non-empty replaced sandbox_home {sbh_name!r} before registration")
        sbh_verified_fresh = True
        os.fchmod(sbh_fd, 0o700)
        set_cred_owner_token(sbh_fd, sbh_tok)
        os.setxattr(sbh_fd, b"user.ap_sub_id", sub_tok.encode("ascii"))
        os.fsync(sbh_fd)
        os.fsync(rfd)
        st_sbh = os.fstat(sbh_fd)
        if db is not None and claim_epoch is not None:
            db.register_claim_credential_dir(
                int(claim_epoch), int(st_sbh.st_dev), int(st_sbh.st_ino), sbh_name, entry_kind="dir", owner_token=sbh_tok
            )
            registered_in_ledger = True

        if family == "claude":
            os.mkdir(".claude", 0o700, dir_fd=sbh_fd)
            sub_fd = os.open(".claude", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=sbh_fd)
            with os.scandir(sub_fd) as sub_it:
                if any(True for _ in sub_it):
                    raise SandboxError("Refusing non-empty replaced .claude subdir before registration")
            created_sub_name = ".claude"
            sub_verified_fresh = True
            os.fchmod(sub_fd, 0o700)
            set_cred_owner_token(sub_fd, sub_tok)
            os.fsync(sub_fd)
            os.fsync(sbh_fd)
            st_sub = os.fstat(sub_fd)
            if db is not None and claim_epoch is not None:
                db.register_claim_credential_dir(
                    int(claim_epoch), int(st_sub.st_dev), int(st_sub.st_ino), f"{sbh_name}/.claude", entry_kind="dir", owner_token=sub_tok
                )
                registered_sub_in_ledger = True
            cred_src = hhome / ".claude" / ".credentials.json"
            lock_path = hhome / ".claude" / ".credentials.lock"
            if cred_src.is_file():
                lock_path.parent.mkdir(parents=True, exist_ok=True)
                lfd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    fcntl.flock(lfd, fcntl.LOCK_SH)
                    raw = json.loads(cred_src.read_text(encoding="utf-8"))
                finally:
                    with contextlib.suppress(OSError):
                        fcntl.flock(lfd, fcntl.LOCK_UN)
                    os.close(lfd)
                oauth = raw.get("claudeAiOauth")
                if isinstance(oauth, dict) and oauth.get("accessToken"):
                    projected = {
                        "claudeAiOauth": {
                            "accessToken": oauth["accessToken"],
                            "expiresAt": oauth.get("expiresAt"),
                            "scopes": oauth.get("scopes", []),
                        }
                    }
                    f_dev, f_ino, f_tok_c = _write_registered_secret_file_at_dirfd(
                        sub_fd,
                        ".credentials.json",
                        (json.dumps(projected, indent=2) + "\n").encode("utf-8"),
                        0o600,
                        db=db,
                        claim_epoch=claim_epoch,
                        label=f"{sbh_name}/.claude/.credentials.json",
                        dir_owner_token=sub_tok,
                        local_tracker=local_secret_file_toks,
                    )
                    created_sub_files.append(".credentials.json")
                    local_secret_file_toks[(f_dev, f_ino)] = f_tok_c
                    if db is not None and claim_epoch is not None:
                        registered_secret_files.append((".credentials.json", f_dev, f_ino))

            role_spec = POLICY_MANIFEST["role_matrix"].get(role_key or "claude:readonly_model", {})
            allowed_tools = list(role_spec.get("claude_tools") or ["Read", "Glob", "Grep"])
            settings = {
                "permissions": {
                    "allow": allowed_tools,
                    "deny": list(POLICY_MANIFEST["claude_permission_deny"]),
                }
            }
            _write_file_at_dirfd(sub_fd, "settings.json", (json.dumps(settings, indent=2) + "\n").encode("utf-8"), 0o600, dir_owner_token=sub_tok)
            created_sub_files.append("settings.json")

        elif family == "codex":
            os.mkdir(".codex", 0o700, dir_fd=sbh_fd)
            sub_fd = os.open(".codex", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=sbh_fd)
            with os.scandir(sub_fd) as sub_it:
                if any(True for _ in sub_it):
                    raise SandboxError("Refusing non-empty replaced .codex subdir before registration")
            created_sub_name = ".codex"
            sub_verified_fresh = True
            os.fchmod(sub_fd, 0o700)
            set_cred_owner_token(sub_fd, sub_tok)
            os.fsync(sub_fd)
            os.fsync(sbh_fd)
            st_sub = os.fstat(sub_fd)
            if db is not None and claim_epoch is not None:
                db.register_claim_credential_dir(
                    int(claim_epoch), int(st_sub.st_dev), int(st_sub.st_ino), f"{sbh_name}/.codex", entry_kind="dir", owner_token=sub_tok
                )
                registered_sub_in_ledger = True
            host_codex = hhome / ".codex"
            auth_src = host_codex / "auth.json"
            lock_path = host_codex / ".auth.lock"
            if auth_src.is_file():
                lock_path.parent.mkdir(parents=True, exist_ok=True)
                lfd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    fcntl.flock(lfd, fcntl.LOCK_SH)
                    raw_auth = json.loads(auth_src.read_text(encoding="utf-8"))
                finally:
                    with contextlib.suppress(OSError):
                        fcntl.flock(lfd, fcntl.LOCK_UN)
                    os.close(lfd)
                projected_codex = _project_codex_auth_for_sandbox(raw_auth)
                if projected_codex:
                    f_dev, f_ino, f_tok_x = _write_registered_secret_file_at_dirfd(
                        sub_fd,
                        "auth.json",
                        (json.dumps(projected_codex, indent=2) + "\n").encode("utf-8"),
                        0o600,
                        db=db,
                        claim_epoch=claim_epoch,
                        label=f"{sbh_name}/.codex/auth.json",
                        dir_owner_token=sub_tok,
                        local_tracker=local_secret_file_toks,
                    )
                    created_sub_files.append("auth.json")
                    local_secret_file_toks[(f_dev, f_ino)] = f_tok_x
                    if db is not None and claim_epoch is not None:
                        registered_secret_files.append(("auth.json", f_dev, f_ino))

            mc_src = host_codex / "models_cache.json"
            if mc_src.is_file():
                _write_file_at_dirfd(sub_fd, "models_cache.json", mc_src.read_bytes(), 0o644, dir_owner_token=sub_tok)
                created_sub_files.append("models_cache.json")
            _write_file_at_dirfd(sub_fd, "config.toml", b"[features]\nmulti_agent = false\n", 0o600, dir_owner_token=sub_tok)
            created_sub_files.append("config.toml")
        else:
            raise SandboxError(f"Unsupported model family: {family!r}")

        sb_path = (pinned_proc_fd_path(run_dir_fd) / sbh_name) if run_dir_fd is not None else (Path(os.path.normpath(str(run_dir))) / sbh_name)
        ret_sbh_fd = sbh_fd
        sbh_fd = None
        return sb_path, ret_sbh_fd, sbh_name, int(st_sbh.st_ino)
    except BaseException:
        if sbh_verified_fresh:
            from .models import empty_and_fsync_dirfd

            can_rmdir = False
            try:
                unpurged_rb = (
                    db.list_unpurged_claim_credential_dirs(int(claim_epoch))
                    if (db is not None and claim_epoch is not None)
                    else []
                )
                rb_file_toks = {
                    (int(r["dir_dev"]), int(r["dir_ino"])): str(r.get("owner_token") or "")
                    for r in unpurged_rb
                    if r.get("entry_kind") == "file"
                }
                rb_cb = (
                    (lambda d, i: db.mark_claim_credential_dir_purged(int(claim_epoch), d, i))
                    if (db is not None and claim_epoch is not None)
                    else None
                )
                if sub_fd is not None and sub_verified_fresh:
                    empty_and_fsync_dirfd(
                        sub_fd,
                        on_dir_emptied=rb_cb,
                        on_file_purged=rb_cb,
                        expected_owner_token=sub_tok,
                        allowed_child_dirs={},
                        tracked_files=rb_file_toks if (db is not None and claim_epoch is not None) else dict(local_secret_file_toks),
                    )
                    if registered_sub_in_ledger and st_sub is not None and rb_cb is not None:
                        rb_cb(int(st_sub.st_dev), int(st_sub.st_ino))
                    os.close(sub_fd)
                    sub_fd = None
                if sbh_fd is not None:
                    if created_sub_name is not None and sub_verified_fresh:
                        with contextlib.suppress(FileNotFoundError):
                            os.rmdir(created_sub_name, dir_fd=sbh_fd)
                    with os.scandir(sbh_fd) as rem_chk:
                        if any(True for _ in rem_chk):
                            raise SandboxError("Unexpected foreign entries in sandbox_home during rollback")
                    os.fsync(sbh_fd)
                    # Only settle top-level `sbh_fd` and `rmdir` if ZERO registered secret files remain unpurged!
                    rem_unpurged_files = (
                        [r for r in db.list_unpurged_claim_credential_dirs(int(claim_epoch)) if r.get("entry_kind") == "file"]
                        if (db is not None and claim_epoch is not None)
                        else []
                    )
                    if rem_unpurged_files:
                        raise SandboxError("Registered secret file was moved away before rollback; retaining claim")
                    if registered_in_ledger and rb_cb is not None:
                        rb_cb(int(st_sbh.st_dev), int(st_sbh.st_ino))
                    can_rmdir = True
            except Exception:
                # Keep empty/partial shell in `rfd` so supervisor reclaim can find `(dev, ino)` and settle the ledger!
                can_rmdir = False
            finally:
                if sub_fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(sub_fd)
                    sub_fd = None
                if sbh_fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(sbh_fd)
                    sbh_fd = None
            if can_rmdir:
                with contextlib.suppress(OSError):
                    os.rmdir(sbh_name, dir_fd=rfd)
                    os.fsync(rfd)
        raise
    finally:
        if sub_fd is not None:
            with contextlib.suppress(OSError):
                os.close(sub_fd)
        if sbh_fd is not None:
            with contextlib.suppress(OSError):
                os.close(sbh_fd)
        with contextlib.suppress(OSError):
            os.close(rfd)


def prepare_sandbox_home(
    run_dir: Path,
    family: str,
    *,
    role_key: str = "",
    host_home: Path | None = None,
    run_dir_fd: int | None = None,
    db: Any = None,
    claim_epoch: int | None = None,
) -> Path:
    """Create a fresh per-turn 0700 sandbox_home strictly via `run_dir_fd` (`O_NOFOLLOW`), projecting ONLY short-lived OAuth tokens."""
    sb_path, sbh_fd, _, _ = prepare_sandbox_home_fd(
        run_dir,
        family,
        role_key=role_key,
        host_home=host_home,
        run_dir_fd=run_dir_fd,
        db=db,
        claim_epoch=claim_epoch,
    )
    os.close(sbh_fd)
    return sb_path


def purge_credential_file_at_dirfd(
    parent_fd: int,
    filename: str,
    *,
    expected_dev: int | None = None,
    expected_ino: int | None = None,
    expected_owner_token: str = "",
    on_purged: Any = None,
) -> None:
    """Stage into private `qfd`, check `(dev, ino, user.ap_cred_id)` AND `st_nlink == 1` BEFORE `ftruncate(0)`, commit `purged=1` BEFORE `unlink`!"""
    from .models import (
        AutopilotError,
        create_private_qbox_at_dirfd,
        renameat2_noreplace,
        restore_from_qbox_noreplace,
        verify_cred_owner_token,
    )

    if "/" in filename or "\\" in filename or filename in ("", ".", ".."):
        raise SandboxError(f"Invalid credential filename: {filename!r}")
    try:
        qname, qfd = create_private_qbox_at_dirfd(parent_fd)
    except (AutopilotError, OSError) as exc:
        raise SandboxError(f"Unable to create private qbox for {filename!r}: {exc}") from exc
    ffd: int | None = None
    moved = False
    try:
        renameat2_noreplace(parent_fd, filename, qfd, "item")
        moved = True
        ffd = os.open("item", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=qfd)
        st_f = os.fstat(ffd)
        if (
            not stat.S_ISREG(st_f.st_mode)
            or (expected_dev is not None and int(st_f.st_dev) != int(expected_dev))
            or (expected_ino is not None and int(st_f.st_ino) != int(expected_ino))
            or not verify_cred_owner_token(ffd, expected_owner_token)
        ):
            restore_from_qbox_noreplace(qfd, parent_fd, filename)
            moved = False
            raise SandboxError(f"Credential file {filename!r} identity/owner_token mismatch (restored untouched)")
        if st_f.st_nlink != 1:
            restore_from_qbox_noreplace(qfd, parent_fd, filename)
            moved = False
            raise SandboxError(f"Credential file {filename!r} has extra hardlinks (st_nlink={st_f.st_nlink}); refusing to truncate")
        os.ftruncate(ffd, 0)
        os.fsync(ffd)
        os.fsync(qfd)
        os.fsync(parent_fd)
        if on_purged is not None:
            on_purged(int(st_f.st_dev), int(st_f.st_ino))
        os.unlink("item", dir_fd=qfd)
        moved = False
        os.fsync(qfd)
    except OSError as exc:
        if moved and ffd is None:
            with contextlib.suppress(OSError):
                restore_from_qbox_noreplace(qfd, parent_fd, filename)
        raise SandboxError(f"Failed to purge staged credential file {filename!r}: {exc}") from exc
    finally:
        if ffd is not None:
            os.close(ffd)
        os.close(qfd)
        with contextlib.suppress(OSError):
            os.rmdir(qname, dir_fd=parent_fd)


def cleanup_sandbox_home_at_dirfd(
    run_dir_fd: int,
    entry_name: str,
    *,
    expected_ino: int | None = None,
    expected_dev: int | None = None,
    expected_owner_token: str = "",
    allowed_child_dirs: dict[tuple[int, int], str] | None = None,
    purged_child_dirs: dict[tuple[int, int], str] | None = None,
    tracked_files: dict[tuple[int, int], str] | None = None,
    purged_files: dict[tuple[int, int], str] | None = None,
    on_emptied_before_rmdir: Any = None,
) -> tuple[int, int]:
    """Empty & fsync `entry_name` via retained `sbh_fd`, invoke `on_emptied_before_rmdir(dev, ino)` BEFORE `rmdir`, and ONLY `os.rmdir` empty shell!"""
    from .models import AutopilotError, empty_and_fsync_dirfd

    if "/" in entry_name or "\\" in entry_name or entry_name in ("", ".", ".."):
        raise SandboxError(f"Invalid sandbox_home entry name: {entry_name!r}")
    try:
        sbh_fd = os.open(entry_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=run_dir_fd)
    except FileNotFoundError as exc:
        raise SandboxError(f"Enumerated sandbox_home {entry_name!r} disappeared or was renamed during purge") from exc
    except OSError as exc:
        raise SandboxError(f"Refusing symlink/non-dir sandbox_home {entry_name!r}: {exc}") from exc
    try:
        st_sbh = os.fstat(sbh_fd)
        if expected_dev is not None and int(st_sbh.st_dev) != int(expected_dev):
            raise SandboxError(f"Enumerated sandbox_home {entry_name!r} dev drifted ({st_sbh.st_dev} != {expected_dev})")
        if expected_ino is not None and int(st_sbh.st_ino) != int(expected_ino):
            raise SandboxError(
                f"Enumerated sandbox_home {entry_name!r} inode drifted ({st_sbh.st_ino} != {expected_ino})"
            )
        try:
            empty_and_fsync_dirfd(
                sbh_fd,
                on_dir_emptied=on_emptied_before_rmdir,
                on_file_purged=on_emptied_before_rmdir,
                expected_owner_token=expected_owner_token,
                allowed_child_dirs=allowed_child_dirs,
                purged_child_dirs=purged_child_dirs,
                tracked_files=tracked_files,
                purged_files=purged_files,
            )
        except (AutopilotError, OSError) as exc:
            raise SandboxError(f"Failed to empty credential sandbox_home {entry_name!r}: {exc}") from exc
        if on_emptied_before_rmdir is not None:
            on_emptied_before_rmdir(int(st_sbh.st_dev), int(st_sbh.st_ino))
    finally:
        os.close(sbh_fd)

    # Remove ONLY the empty top-level directory shell (`os.rmdir` refuses symlinks and non-empty replacement directories!)
    with contextlib.suppress(FileNotFoundError):
        try:
            os.rmdir(entry_name, dir_fd=run_dir_fd)
        except OSError as exc:
            # If `entry_name` was swapped to a non-empty directory B after A was emptied & ledger-committed, B is preserved untouched!
            if on_emptied_before_rmdir is None:
                raise SandboxError(f"Failed to rmdir emptied sandbox_home {entry_name!r}: {exc}") from exc
    return int(st_sbh.st_dev), int(st_sbh.st_ino)


def cleanup_sandbox_home(sb_home: Path | None) -> None:
    """Unconditionally destroy per-turn sandbox_home and verify removal; raise SandboxError if residue remains."""
    if sb_home is None or not sb_home.exists():
        return
    for root, dirs, files in os.walk(sb_home, topdown=True, followlinks=False):
        rp = Path(root)
        with contextlib.suppress(OSError):
            os.chmod(rp, 0o700)
        for d in dirs:
            dp = rp / d
            if not dp.is_symlink():
                with contextlib.suppress(OSError):
                    os.chmod(dp, 0o700)
        for f in files:
            fp = rp / f
            if not fp.is_symlink():
                with contextlib.suppress(OSError):
                    os.chmod(fp, 0o600)
    try:
        shutil.rmtree(sb_home, ignore_errors=False)
    except OSError as exc:
        raise SandboxError(f"Failed to purge credential sandbox_home {sb_home}: {exc}") from exc
    if sb_home.exists():
        raise SandboxError(f"sandbox_home {sb_home} still exists after rmtree")


def safe_read_outbox_file_fd(outbox_fd: int, filename: str, *, max_bytes: int = 262144) -> str | None:
    """Safely read a regular file directly from retained `outbox_fd` (`O_NOFOLLOW|O_NONBLOCK`), immune to path swaps!"""
    if "/" in filename or "\\" in filename or filename in ("", ".", ".."):
        raise SandboxError(f"Invalid outbox filename: {filename!r}")
    try:
        ffd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=outbox_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SandboxError(f"Refusing symlinked outbox file: {filename}") from exc
        raise
    try:
        st = os.fstat(ffd)
        if not stat.S_ISREG(st.st_mode):
            raise SandboxError(f"Outbox entry is not a regular file (e.g. FIFO/device): {filename}")
        if st.st_size > max_bytes:
            raise SandboxError(f"Outbox file exceeds {max_bytes} bytes: {st.st_size}")
        chunks: list[bytes] = []
        rem = max_bytes + 1
        while rem > 0:
            b = os.read(ffd, min(65536, rem))
            if not b:
                break
            chunks.append(b)
            rem -= len(b)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            raise SandboxError(f"Outbox file exceeded {max_bytes} bytes while reading")
        return raw.decode("utf-8")
    finally:
        os.close(ffd)


def safe_read_outbox_file(outbox_dir: Path, filename: str, *, max_bytes: int = 262144) -> str | None:
    """Safely read a regular file inside model-writable outbox_dir using O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK."""
    if "/" in filename or "\\" in filename or filename in ("", ".", ".."):
        raise SandboxError(f"Invalid outbox filename: {filename!r}")
    if not outbox_dir.exists() or outbox_dir.is_symlink():
        return None
    dfd = os.open(str(outbox_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return safe_read_outbox_file_fd(dfd, filename, max_bytes=max_bytes)
    finally:
        os.close(dfd)


def build_model_ring_bwrap(
    *,
    role_key: str,
    host_binaries: dict[str, Path],
    sandbox_home: Path,
    outbox_dir: Path,
    proxy_sock: Path | None,
    inner_cmd: list[str],
    worktree: Path | None = None,
    shared_tmp: Path | None = None,
    shell_snapshots: Path | None = None,
    tool_sock: Path | None = None,
    review_bundle_dir: Path | None = None,
    elf_lib_stage_dir: Path | None = None,
    sandbox_home_fd: int | None = None,
    sandbox_file_fds: dict[str, int] | None = None,
    outbox_fd: int | None = None,
    retain_fds: list[int] | None = None,
) -> list[str]:
    """Assemble bwrap + ap-sandbox-init argv strictly from policy_manifest.json role_matrix."""
    if (sandbox_home_fd is not None or sandbox_file_fds is not None or outbox_fd is not None) and retain_fds is None:
        raise SandboxError("retain_fds list is required whenever sandbox_home_fd, sandbox_file_fds, or outbox_fd is passed")
    role_matrix = POLICY_MANIFEST["role_matrix"]
    if role_key not in role_matrix:
        raise SandboxError(f"Unknown model_ring role_key: {role_key!r}")
    spec = role_matrix[role_key]

    ap_init = host_binaries["ap_sandbox_init"]
    ap_sh = host_binaries["ap_safe_sh"]
    verify_native_binaries(ap_init, ap_sh)

    bwrap_bin = shutil.which("bwrap") or "/usr/bin/bwrap"
    argv: list[str] = [
        bwrap_bin,
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-net",
        "--new-session",
        "--clearenv",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--dir",
        "/tmp",
        "--dir",
        "/usr/bin",
        "--dir",
        "/usr/local/bin",
        "--dir",
        "/usr/lib",
        "--dir",
        "/usr/lib64",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--dir",
        "/etc",
    ]
    for etc_item in (
        "/etc/resolv.conf",
        "/etc/ssl",
        "/etc/ca-certificates",
        "/etc/localtime",
        "/usr/share/zoneinfo",
        "/usr/share/ca-certificates",
    ):
        if Path(etc_item).exists():
            argv.extend(["--ro-bind", etc_item, etc_item])

    # Binary mounts (host /usr/bin/{bash,sh,dash} are NEVER mounted!)
    mounted_exec_targets: list[str] = []
    for container_dst, slot_name in spec["binary_mounts"].items():
        if slot_name not in host_binaries:
            raise SandboxError(f"Missing host binary slot {slot_name!r} for role {role_key}")
        src_bin = host_binaries[slot_name]
        argv.extend(["--ro-bind", str(src_bin), container_dst])
        if container_dst != "/usr/local/bin/ap-sandbox-init":
            mounted_exec_targets.append(container_dst)
    if role_key.startswith("codex:") and "codex_code_mode_host" in host_binaries:
        cmh_dst = "/usr/local/bin/codex-code-mode-host"
        argv.extend(["--ro-bind", str(host_binaries["codex_code_mode_host"]), cmh_dst])
        if cmh_dst not in mounted_exec_targets:
            mounted_exec_targets.append(cmh_dst)

    if spec.get("dynamic_elf_libs"):
        if role_key.startswith("claude:"):
            main_slot = "claude_cli"
        elif role_key.startswith("agy:"):
            main_slot = "agy_cli"
        else:
            main_slot = "codex_cli"
        st_dir = elf_lib_stage_dir or (sandbox_home.parent / "elf_libs_stage")
        st_prefix = str(st_dir).rstrip("/") + "/"
        for host_lib, target_lib in resolve_elf_runtime_mounts(host_binaries[main_slot], st_dir):
            if retain_fds is not None and host_lib.startswith(st_prefix):
                # bwrap resolves path sources after entering its user namespace, where the caller's /proc/<pid>/fd
                # magic links (pinned run dirs) are not traversable: hand it an already-open, inode-pinned fd instead.
                lib_fd = os.open(host_lib, os.O_RDONLY | os.O_NOFOLLOW)
                retain_fds.append(lib_fd)
                argv.extend(["--ro-bind-fd", str(lib_fd), target_lib])
            else:
                argv.extend(["--ro-bind", host_lib, target_lib])
            if "ld-linux" in target_lib and target_lib not in mounted_exec_targets:
                mounted_exec_targets.append(target_lib)

    from .models import AutopilotError, get_sub_intent_token, open_dir_nofollow, verify_cred_owner_token, verify_owned_file_token

    role_is_agy = role_key.startswith("agy:")
    writable_set = set(spec["writable_mounts"])

    if role_is_agy and (retain_fds is None or sandbox_file_fds is None):
        raise SandboxError("agy roles require retain_fds and memfd-projected sandbox_file_fds (host-disk HOME fallback forbidden)")

    if retain_fds is not None:
        try:
            role_is_claude = role_key.startswith("claude:")
            if role_is_agy:
                agy_allowed_dsts = {
                    "/home/sandbox/.gemini/antigravity-cli/antigravity-oauth-token",
                    "/home/sandbox/.gemini/antigravity-cli/settings.json",
                    "/home/sandbox/.gemini/config/mcp_config.json",
                    "/home/sandbox/.gemini/config/hooks.json",
                    "/home/sandbox/.gemini/config/config.json",
                }
                argv.extend([
                    "--tmpfs", "/home/sandbox",
                    "--dir", "/home/sandbox/.gemini",
                    "--dir", "/home/sandbox/.gemini/antigravity-cli",
                    "--dir", "/home/sandbox/.gemini/config",
                ])
                assert sandbox_file_fds is not None
                if "/home/sandbox/.gemini/antigravity-cli/antigravity-oauth-token" not in sandbox_file_fds:
                    raise SandboxError(f"Missing projected AGY OAuth memfd for role {role_key}")
                for dst_p in sandbox_file_fds:
                    if dst_p not in agy_allowed_dsts:
                        raise SandboxError(f"Unauthorized sandbox_file_fds destination {dst_p!r} for role {role_key}")
                # Validate caller OAuth payload and re-synthesize a fresh canonical host-owned memfd (never binding raw FD!)
                src_tok_fd = sandbox_file_fds["/home/sandbox/.gemini/antigravity-cli/antigravity-oauth-token"]
                dup_read_fd = os.dup(src_tok_fd)
                try:
                    os.lseek(dup_read_fd, 0, os.SEEK_SET)
                    raw_tok_b = os.read(dup_read_fd, 65537)
                    if len(raw_tok_b) > 65536:
                        raise SandboxError("AGY OAuth memfd exceeds 64 KiB cap")
                    try:
                        tok_doc = json.loads(raw_tok_b.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc_j:
                        raise SandboxError(f"Invalid AGY OAuth memfd JSON: {exc_j}") from exc_j
                    if not isinstance(tok_doc, dict) or "id_token_email" in tok_doc:
                        raise SandboxError("Unprojected AGY OAuth payload rejected at sandbox boundary (id_token_email present)")
                    tok_inner = tok_doc.get("token")
                    if not isinstance(tok_inner, dict) or "refresh_token" in tok_inner:
                        raise SandboxError("Unprojected AGY OAuth payload rejected at sandbox boundary (refresh_token present)")
                    canon_oauth = _project_agy_auth_for_sandbox(tok_doc)
                    if not canon_oauth:
                        raise SandboxError("AGY OAuth projection empty or missing access_token at sandbox boundary")
                finally:
                    os.close(dup_read_fd)

                # Always synthesize canonical OAuth, role-authoritative settings.json, and empty MCP/hooks memfds here!
                deny_rules = [
                    *list(POLICY_MANIFEST.get("agy_permission_deny") or []),
                    *list(spec.get("agy_extra_permission_deny") or []),
                ]
                allow_rules = list(spec.get("agy_permission_allow") or [])
                canon_settings = {"permissions": {"allow": allow_rules, "deny": deny_rules}}
                synth_files: list[tuple[str, str, bytes]] = [
                    (
                        "/home/sandbox/.gemini/antigravity-cli/antigravity-oauth-token",
                        "ap_agy_oauth_canon",
                        (json.dumps(canon_oauth, indent=2) + "\n").encode("utf-8"),
                    ),
                    (
                        "/home/sandbox/.gemini/antigravity-cli/settings.json",
                        "ap_agy_settings_canon",
                        (json.dumps(canon_settings, indent=2) + "\n").encode("utf-8"),
                    ),
                    ("/home/sandbox/.gemini/config/hooks.json", "ap_agy_hooks_canon", b"{}\n"),
                    ("/home/sandbox/.gemini/config/mcp_config.json", "ap_agy_mcp_canon", b"{}\n"),
                ]
                for dst_p, mname, payload_b in synth_files:
                    mfd = _make_memfd_with_bytes(mname, payload_b)
                    retain_fds.append(mfd)
                    argv.extend(["--ro-bind-data", str(mfd), dst_p])
            else:
                exp_sub_nm = ".claude" if role_is_claude else ".codex"
                allowed_fnames = (
                    {".credentials.json", "settings.json"}
                    if role_is_claude
                    else {"auth.json", "models_cache.json", "config.toml"}
                )
                argv.extend(["--tmpfs", "/home/sandbox", "--dir", f"/home/sandbox/{exp_sub_nm}"])
                if sandbox_file_fds is not None:
                    for dst_p, src_mfd in sorted(sandbox_file_fds.items()):
                        if Path(dst_p).parent != Path(f"/home/sandbox/{exp_sub_nm}") or Path(dst_p).name not in allowed_fnames:
                            raise SandboxError(f"Unauthorized sandbox_file_fds destination {dst_p!r} for role {role_key}")
                        dup_mfd = os.dup(src_mfd)
                        os.lseek(dup_mfd, 0, os.SEEK_SET)
                        retain_fds.append(dup_mfd)
                        argv.extend(["--ro-bind-data", str(dup_mfd), dst_p])
                else:
                    sbh_b_fd = os.dup(sandbox_home_fd) if sandbox_home_fd is not None else open_dir_nofollow(sandbox_home, create=True, mode=0o700)
                    try:
                        try:
                            sub_b_fd = os.open(exp_sub_nm, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=sbh_b_fd)
                        except FileNotFoundError:
                            sub_b_fd = None
                        if sub_b_fd is not None:
                            try:
                                try:
                                    exp_sub_tok = os.getxattr(sbh_b_fd, b"user.ap_sub_id").decode("ascii", errors="replace")
                                except OSError as exc_xt:
                                    raise SandboxError(
                                        f"Missing or unreadable user.ap_sub_id on sandbox_home_fd; refusing unverified {exp_sub_nm}: {exc_xt}"
                                    ) from exc_xt
                                if not exp_sub_tok or not verify_cred_owner_token(sub_b_fd, exp_sub_tok):
                                    raise SandboxError(f"Refusing replaced/foreign {exp_sub_nm} directory inside sandbox_home")
                                with os.scandir(sub_b_fd) as s_it:
                                    fnames = sorted(e.name for e in s_it if not e.name.startswith(".ap-qbox-"))
                                for fn in fnames:
                                    if fn not in allowed_fnames:
                                        raise SandboxError(f"Unauthorized file {fn!r} inside sandbox_home/{exp_sub_nm} for {role_key}")
                                    f_ro_fd = os.open(fn, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=sub_b_fd)
                                    if not stat.S_ISREG(os.fstat(f_ro_fd).st_mode) or not verify_owned_file_token(f_ro_fd, exp_sub_tok):
                                        os.close(f_ro_fd)
                                        raise SandboxError(f"Foreign or non-regular file inside sandbox_home/{exp_sub_nm}: {fn!r}")
                                    retain_fds.append(f_ro_fd)
                                    argv.extend(["--ro-bind-fd", str(f_ro_fd), f"/home/sandbox/{exp_sub_nm}/{fn}"])
                            finally:
                                os.close(sub_b_fd)
                    finally:
                        os.close(sbh_b_fd)
            if "outbox" in writable_set:
                obox_b_fd = os.dup(outbox_fd) if outbox_fd is not None else open_dir_nofollow(outbox_dir, create=True, mode=0o700)
                retain_fds.append(obox_b_fd)
                argv.extend(["--bind-fd", str(obox_b_fd), "/ap-outbox"])

            if "shared_tmp" in writable_set:
                if shared_tmp is None:
                    raise SandboxError(f"{role_key} requires shared_tmp")
                stmp_fd = open_dir_nofollow(shared_tmp, create=True, mode=0o700)
                retain_fds.append(stmp_fd)
                argv.extend(["--bind-fd", str(stmp_fd), "/tmp"])
            if "shell_snapshots" in writable_set and shell_snapshots is not None:
                snap_fd = open_dir_nofollow(shell_snapshots, create=True, mode=0o700)
                retain_fds.append(snap_fd)
                argv.extend(["--bind-fd", str(snap_fd), "/ap-shell-snapshots"])

            if "worktree" in writable_set:
                if worktree is None:
                    raise SandboxError(f"{role_key} requires worktree")
                wt_fd_m = open_dir_nofollow(worktree, create=False)
                retain_fds.append(wt_fd_m)
                wt_real = os.readlink(f"/proc/self/fd/{wt_fd_m}")
                argv.extend(["--bind-fd", str(wt_fd_m), wt_real, "--chdir", wt_real])
                if spec.get("readonly_worktree_dot_git"):
                    dg_fd = os.open(".git", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=wt_fd_m)
                    retain_fds.append(dg_fd)
                    argv.extend(["--ro-bind-fd", str(dg_fd), f"{wt_real}/.git"])
                if role_is_agy:
                    # Always mask ALL 4 AGY workspace customization dirs (`.agents`, `.agent`, `_agent`, `_agents`)
                    # with host-owned empty read-only dirs (creating empty mountpoints if absent, refusing symlinks/non-dirs)!
                    for ag_dir_name in (".agents", ".agent", "_agent", "_agents"):
                        try:
                            st_ag = os.stat(ag_dir_name, dir_fd=wt_fd_m, follow_symlinks=False)
                        except FileNotFoundError:
                            os.mkdir(ag_dir_name, 0o700, dir_fd=wt_fd_m)
                            st_ag = os.stat(ag_dir_name, dir_fd=wt_fd_m, follow_symlinks=False)
                        if stat.S_ISLNK(st_ag.st_mode) or not stat.S_ISDIR(st_ag.st_mode):
                            raise SandboxError(f"Refusing symlinked or non-directory {ag_dir_name} in worktree for AGY")
                        empty_ag_dir = ensure_secure_dir(sandbox_home.parent / f".ap-empty-agents-{uuid.uuid4().hex[:8]}", 0o500)
                        empty_ag_fd = open_dir_nofollow(empty_ag_dir, create=False)
                        retain_fds.append(empty_ag_fd)
                        argv.extend(["--ro-bind-fd", str(empty_ag_fd), f"{wt_real}/{ag_dir_name}"])
            elif spec.get("readonly_review_bundle_mount"):
                if review_bundle_dir is None:
                    raise SandboxError(f"{role_key} requires existing review_bundle_dir")
                rb_b_fd = open_dir_nofollow(review_bundle_dir, create=False)
                retain_fds.append(rb_b_fd)
                mnt = str(spec["readonly_review_bundle_mount"])
                argv.extend(["--ro-bind-fd", str(rb_b_fd), mnt, "--chdir", mnt])
                if role_is_agy:
                    for ag_dir_name in (".agents", ".agent", "_agent", "_agents"):
                        try:
                            st_rb_ag = os.stat(ag_dir_name, dir_fd=rb_b_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            st_rb_ag = None
                        if st_rb_ag is not None:
                            if stat.S_ISLNK(st_rb_ag.st_mode) or not stat.S_ISDIR(st_rb_ag.st_mode):
                                raise SandboxError(f"Refusing symlinked or non-directory {ag_dir_name} in review_bundle for AGY")
                            empty_rb_ag = ensure_secure_dir(sandbox_home.parent / f".ap-empty-agents-{uuid.uuid4().hex[:8]}", 0o500)
                            empty_rb_fd = open_dir_nofollow(empty_rb_ag, create=False)
                            retain_fds.append(empty_rb_fd)
                            argv.extend(["--ro-bind-fd", str(empty_rb_fd), f"{mnt}/{ag_dir_name}"])
        except (AutopilotError, OSError) as exc:
            raise SandboxError(f"Failed to bind-fd model_ring directories for {role_key}: {exc}") from exc
    else:
        ensure_secure_dir(sandbox_home, 0o700)
        argv.extend(["--bind", str(sandbox_home.resolve()), "/home/sandbox"])
        if "outbox" in writable_set:
            ensure_secure_dir(outbox_dir, 0o700)
            argv.extend(["--bind", str(outbox_dir.resolve()), "/ap-outbox"])

        if "shared_tmp" in writable_set:
            if shared_tmp is None:
                raise SandboxError(f"{role_key} requires shared_tmp")
            ensure_secure_dir(shared_tmp, 0o700)
            argv.extend(["--bind", str(shared_tmp.resolve()), "/tmp"])
        if "shell_snapshots" in writable_set and shell_snapshots is not None:
            ensure_secure_dir(shell_snapshots, 0o700)
            argv.extend(["--bind", str(shell_snapshots.resolve()), "/ap-shell-snapshots"])

        if "worktree" in writable_set:
            if worktree is None:
                raise SandboxError(f"{role_key} requires worktree")
            wt_real = str(worktree.resolve())
            argv.extend(["--bind", wt_real, wt_real, "--chdir", wt_real])
            if spec.get("readonly_worktree_dot_git"):
                dot_git = worktree.resolve() / ".git"
                if not dot_git.exists():
                    raise SandboxError(f"Missing worktree .git for readonly overlay: {dot_git}")
                argv.extend(["--ro-bind", str(dot_git), str(dot_git)])
        elif spec.get("readonly_review_bundle_mount"):
            if review_bundle_dir is None or not review_bundle_dir.is_dir():
                raise SandboxError(f"{role_key} requires existing review_bundle_dir")
            mnt = str(spec["readonly_review_bundle_mount"])
            argv.extend(["--ro-bind", str(review_bundle_dir.resolve()), mnt, "--chdir", mnt])

    argv.extend(["--dir", "/run/ap"])
    if spec.get("mount_tool_sock"):
        if tool_sock is None:
            raise SandboxError(f"{role_key} requires tool_sock")
        argv.extend(["--ro-bind", str(tool_sock), "/run/ap/tool.sock"])
        argv.extend(["--setenv", "AP_TOOL_SOCK", "/run/ap/tool.sock"])

    if proxy_sock is not None:
        argv.extend(["--ro-bind", str(proxy_sock), "/run/ap/proxy.sock"])

    argv.extend(
        [
            "--setenv",
            "HOME",
            "/home/sandbox",
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin",
            "--setenv",
            "LANG",
            "C.UTF-8",
        ]
    )
    if "outbox" in writable_set:
        argv.extend(["--setenv", "AP_OUTBOX_DIR", "/ap-outbox"])

    # ap-sandbox-init wrapper + Landlock allowlist derived strictly from mounted container executables
    allowed_manifest_set = set(spec["landlock_allow_exec"])
    known_linux_loaders = {
        "/usr/lib64/ld-linux-x86-64.so.2",
        "/usr/lib/ld-linux-aarch64.so.1",
        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
    }
    if spec.get("dynamic_elf_libs"):
        allowed_manifest_set |= known_linux_loaders
    init_args = ["/usr/local/bin/ap-sandbox-init"]
    if proxy_sock is not None:
        init_args.extend(["--proxy-sock", "/run/ap/proxy.sock"])
    for allow_p in mounted_exec_targets:
        if allow_p in allowed_manifest_set:
            init_args.extend(["--allow-exec", allow_p])
    init_args.append("--")

    if role_key.startswith("claude:"):
        mandatory_flags = list(spec.get("claude_cli_flags", []))
        tools_csv = ",".join(spec.get("claude_tools", []))
        cli_bin = inner_cmd[0]
        rest = list(inner_cmd[1:])
        for fl in mandatory_flags:
            if fl not in rest:
                rest = [*mandatory_flags, *rest]
                break
        if tools_csv and "--tools" not in rest and rest != ["--version"]:
            rest = ["--tools", tools_csv, *rest]
        init_args.extend([cli_bin, *rest])
    elif role_key.startswith("agy:"):
        cli_bin = inner_cmd[0]
        rest = list(inner_cmd[1:])
        is_version_probe = rest == ["--version"]
        if not is_version_probe:
            # Parse flags strictly by flag name AND value (both `--flag` and `--flag=val`)
            forbidden_all = {"--remote-agent", "--remote-control", "--settings", "--dangerously-skip-permissions"}
            forbidden_ro = forbidden_all | {"--add-dir", "--continue", "-c", "--conversation", "--prompt-interactive", "-i"}
            forbidden_set = forbidden_ro if role_key == "agy:readonly_model" else forbidden_all
            expected_mode = "plan" if role_key == "agy:readonly_model" else "accept-edits"
            cleaned_rest: list[str] = []
            i = 0
            while i < len(rest):
                tok = rest[i]
                fname = tok.split("=", 1)[0]
                if fname in forbidden_set:
                    raise SandboxError(f"Forbidden flag {fname!r} for role {role_key}")
                if fname == "--mode":
                    if "=" in tok:
                        mval = tok.split("=", 1)[1]
                    elif i + 1 < len(rest):
                        mval = rest[i + 1]
                        i += 1
                    else:
                        raise SandboxError(f"Missing value for --mode in role {role_key}")
                    if mval != expected_mode:
                        raise SandboxError(f"{role_key} requires --mode {expected_mode}, got {mval!r}")
                    # Host emits canonical `--mode <expected_mode>` once below!
                    i += 1
                    continue
                if fname == "--disable-slash-commands":
                    if "=" in tok:
                        dval = tok.split("=", 1)[1].strip().lower()
                        if dval not in ("true", "1"):
                            raise SandboxError(f"{role_key} forbids disabling --disable-slash-commands (got {tok!r})")
                    # Host emits canonical `--disable-slash-commands` once below!
                    i += 1
                    continue
                cleaned_rest.append(tok)
                i += 1
            mandatory_flags = list(spec.get("agy_cli_flags", []))
            rest = [*mandatory_flags, *cleaned_rest]
        init_args.extend([cli_bin, *rest])
    else:
        init_args.extend(inner_cmd)

    argv.extend(init_args)
    return argv


def _open_nofollow_subdir_fd(base_dir: Path, rel: Path) -> int | None:
    """Open `base_dir / rel` step-by-step with O_DIRECTORY|O_NOFOLLOW; return None if missing, raise SandboxError on any symlink!"""
    if base_dir.is_symlink():
        raise SandboxError(f"Target root {base_dir} must not be a symlink")
    cur_fd = os.open(str(base_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in rel.parts:
            if part in ("", "."):
                continue
            if part == "..":
                raise SandboxError(f"Parent traversal forbidden in workspace rel path: {rel}")
            try:
                nxt_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur_fd)
            except FileNotFoundError:
                os.close(cur_fd)
                return None
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise SandboxError(f"Refusing symlink/non-dir workspace package path {base_dir / rel} ({part})") from exc
                raise
            os.close(cur_fd)
            cur_fd = nxt_fd
        return cur_fd
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(cur_fd)
        raise


def open_verified_trusted_base_cache_fd(
    tbc_dir: Path | None,
    *,
    source_tbc_fd: int | None = None,
) -> tuple[int, Path]:
    """Open `tbc_dir` (or dup `source_tbc_fd`) via `O_NOFOLLOW`, audit integrity on pinned `root_fd`, and return OPEN `(root_fd, mount_dest)`!"""
    import posixpath

    from .models import AutopilotError, open_dir_nofollow, pinned_proc_fd_path

    if source_tbc_fd is not None:
        try:
            root_fd = os.dup(source_tbc_fd)
        except OSError as exc:
            raise SandboxError(f"Invalid source_tbc_fd {source_tbc_fd}: {exc}") from exc
    else:
        if tbc_dir is None:
            raise SandboxError("trusted_base_cache path or source_tbc_fd required")
        if not str(tbc_dir).startswith(f"/proc/{os.getpid()}/fd/") and tbc_dir.is_symlink():
            raise SandboxError(f"Refusing symlinked trusted_base_cache root: {tbc_dir}")
        try:
            root_fd = open_dir_nofollow(tbc_dir, create=False)
        except (AutopilotError, OSError) as exc:
            raise SandboxError(f"Invalid trusted_base_cache directory {tbc_dir}: {exc}") from exc
    try:
        tbc_pin = pinned_proc_fd_path(root_fd)
        tbc_mount_dest = Path(os.readlink(f"/proc/self/fd/{root_fd}"))
        for cur_root, dirs, files in os.walk(tbc_pin, followlinks=False):
            rp = Path(cur_root)
            rel_cur = rp.relative_to(tbc_pin)
            rel_posix = "" if str(rel_cur) == "." else rel_cur.as_posix()
            for entry_name in [*dirs, *files]:
                full_p = rp / entry_name
                st = os.lstat(full_p)
                if stat.S_ISLNK(st.st_mode):
                    if entry_name in ("node_modules", "cargo_home", "go_mod_cache", ".ready"):
                        raise SandboxError(f"Refusing symlinked {entry_name!r} inside trusted_base_cache: {full_p}")
                    raw_target = os.readlink(full_p)
                    if os.path.isabs(raw_target):
                        raise SandboxError(f"Refusing absolute symlink inside trusted_base_cache: {full_p} -> {raw_target}")
                    joined = posixpath.join(rel_posix, raw_target) if rel_posix else raw_target
                    norm = posixpath.normpath(joined)
                    if norm == ".." or norm.startswith("../"):
                        raise SandboxError(f"Refusing escaping relative symlink inside trusted_base_cache: {full_p} -> {raw_target}")
                elif stat.S_ISFIFO(st.st_mode) or stat.S_ISSOCK(st.st_mode) or stat.S_ISBLK(st.st_mode) or stat.S_ISCHR(st.st_mode):
                    raise SandboxError(f"Refusing special device/FIFO/socket inside trusted_base_cache: {full_p}")
        ret_fd = root_fd
        root_fd = -1
        return ret_fd, tbc_mount_dest
    finally:
        if root_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(root_fd)


def verify_trusted_base_cache_integrity(tbc_dir: Path) -> Path:
    """Verify `tbc_dir` via O_NOFOLLOW + lstat: reject symlinked root/node_modules/cargo_home/.ready or any symlink escaping tbc_dir."""
    root_fd, tbc_real = open_verified_trusted_base_cache_fd(tbc_dir)
    os.close(root_fd)
    return tbc_real


def _open_nofollow_from_base_fd(base_fd: int, rel: Path) -> int | None:
    cur_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base_fd)
    try:
        for part in rel.parts:
            if part in ("", "."):
                continue
            if part == "..":
                raise SandboxError(f"Parent traversal forbidden in rel path: {rel}")
            try:
                nxt_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur_fd)
            except FileNotFoundError:
                os.close(cur_fd)
                return None
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise SandboxError(f"Refusing symlink/non-dir subpath {rel} ({part})") from exc
                raise
            os.close(cur_fd)
            cur_fd = nxt_fd
        return cur_fd
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(cur_fd)
        raise


def prepare_workspace_node_modules_bind_args(
    trusted_base_cache: Path | None,
    target_tree: Path,
    *,
    tbc_fd: int | None = None,
    target_fd: int | None = None,
    container_target_root: Path | None = None,
    retain_fds: list[int] | None = None,
) -> list[str]:
    """Verify BOTH source (from single retained `tbc_fd`!) and destination mountpoints so cache swaps CANNOT mix dependency trees!"""
    if (tbc_fd is not None or target_fd is not None) and retain_fds is None:
        raise SandboxError("retain_fds list is required whenever tbc_fd or target_fd is passed")
    from .models import pinned_proc_fd_path

    owned_tbc_fd: int | None = None
    if tbc_fd is not None:
        eff_tbc_fd = tbc_fd
        tbc_walk_root = pinned_proc_fd_path(tbc_fd)
    else:
        if trusted_base_cache is None or not trusted_base_cache.exists():
            return []
        owned_tbc_fd, _ = open_verified_trusted_base_cache_fd(trusted_base_cache)
        eff_tbc_fd = owned_tbc_fd
        tbc_walk_root = pinned_proc_fd_path(owned_tbc_fd)

    try:
        tgt_real: Path | None = None
        if target_fd is None:
            if target_tree.is_symlink():
                raise SandboxError(f"Refusing symlinked target_tree: {target_tree}")
            tgt_real = target_tree.resolve()
        bind_args: list[str] = []
        rel_list: list[Path] = []
        for root, dirs, _ in os.walk(tbc_walk_root, followlinks=False):
            rp = Path(root)
            if "node_modules" in dirs:
                nm_candidate = rp / "node_modules"
                st_nm = os.lstat(nm_candidate)
                if stat.S_ISLNK(st_nm.st_mode) or not stat.S_ISDIR(st_nm.st_mode):
                    raise SandboxError(f"Refusing symlink/non-dir source node_modules in cache: {nm_candidate}")
                dirs.remove("node_modules")
                rel_list.append(rp.relative_to(tbc_walk_root))
        rel_list.sort(key=lambda r: len(r.parts))

        for rel in rel_list:
            src_rel = rel / "node_modules" if str(rel) != "." else Path("node_modules")
            src_fd = _open_nofollow_from_base_fd(eff_tbc_fd, src_rel)
            if src_fd is None:
                raise SandboxError(f"Missing source node_modules directory in pinned cache: {src_rel}")
            verified_src = os.readlink(f"/proc/self/fd/{src_fd}")

            if target_fd is not None:
                pkg_fd = _open_nofollow_from_base_fd(target_fd, rel)
            else:
                assert tgt_real is not None
                pkg_fd = _open_nofollow_subdir_fd(tgt_real, rel)

            if pkg_fd is None:
                os.close(src_fd)
                continue
            try:
                try:
                    st = os.stat("node_modules", dir_fd=pkg_fd, follow_symlinks=False)
                    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                        raise SandboxError(f"Refusing symlink/non-dir node_modules mountpoint at {rel / 'node_modules'}")
                except FileNotFoundError:
                    os.mkdir("node_modules", 0o755, dir_fd=pkg_fd)
                dst_fd = os.open("node_modules", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pkg_fd)
                try:
                    verified_dst = os.readlink(f"/proc/self/fd/{dst_fd}")
                finally:
                    os.close(dst_fd)
            except BaseException:
                os.close(src_fd)
                raise
            finally:
                os.close(pkg_fd)

            if retain_fds is not None and container_target_root is not None:
                retain_fds.append(src_fd)
                bind_args.extend(["--ro-bind-fd", str(src_fd), str(container_target_root / src_rel)])
            else:
                os.close(src_fd)
                bind_args.extend(["--ro-bind", verified_src, verified_dst])
        return bind_args
    finally:
        if owned_tbc_fd is not None:
            with contextlib.suppress(OSError):
                os.close(owned_tbc_fd)


def prepare_ro_workspace_dep_bind_args(
    repo_main: Path | None,
    rel_deps: tuple[str, ...] | list[str],
    target_tree: Path,
    *,
    target_fd: int | None = None,
    container_target_root: Path | None = None,
    retain_fds: list[int] | None = None,
) -> list[str]:
    """Mount operator-declared read-only workspace dependency dirs via `O_NOFOLLOW` + `--ro-bind-fd` (zero path TOCTOU)."""
    if not repo_main or not rel_deps:
        return []
    if retain_fds is None:
        raise SandboxError("retain_fds list is required whenever ro_workspace_deps are mounted")
    if repo_main.is_symlink() or not repo_main.is_dir():
        return []
    tgt_real = target_tree.resolve() if target_fd is None else None
    eff_container_root = container_target_root if container_target_root is not None else tgt_real
    assert eff_container_root is not None
    bind_args: list[str] = []
    for raw_rel in rel_deps:
        rel = Path(str(raw_rel).strip().strip("/"))
        if not str(rel) or str(rel) == "." or ".." in rel.parts:
            continue
        src_fd = _open_nofollow_subdir_fd(repo_main.resolve(), rel)
        if src_fd is None:
            continue
        pkg_fd: int | None = None
        transferred = False
        try:
            parent_rel = rel.parent
            leaf = rel.name
            if target_fd is not None:
                pkg_fd = _open_nofollow_from_base_fd(target_fd, parent_rel)
            else:
                assert tgt_real is not None
                pkg_fd = _open_nofollow_subdir_fd(tgt_real, parent_rel)
            if pkg_fd is None:
                continue
            try:
                st = os.stat(leaf, dir_fd=pkg_fd, follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                    raise SandboxError(f"Refusing symlink/non-dir ro_workspace_deps mountpoint at {rel}")
            except FileNotFoundError:
                os.mkdir(leaf, 0o755, dir_fd=pkg_fd)
            dst_fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pkg_fd)
            os.close(dst_fd)
            retain_fds.append(src_fd)
            transferred = True
            bind_args.extend(["--ro-bind-fd", str(src_fd), str(eff_container_root / rel)])
            if leaf == "node_modules":
                for scratch_sub in (".vite-temp", ".vite", ".cache"):
                    with contextlib.suppress(FileExistsError, PermissionError, OSError):
                        os.mkdir(scratch_sub, 0o755, dir_fd=src_fd)
                    try:
                        sub_fd = os.open(scratch_sub, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=src_fd)
                    except FileNotFoundError:
                        continue
                    os.close(sub_fd)
                    bind_args.extend(["--tmpfs", str(eff_container_root / rel / scratch_sub)])
        finally:
            if pkg_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(pkg_fd)
            if not transferred:
                with contextlib.suppress(OSError):
                    os.close(src_fd)
    return bind_args


def cleanup_workspace_node_modules_mountpoints(
    trusted_base_cache: Path | None,
    target_tree: Path,
    *,
    extra_rel_mounts: tuple[str, ...] | list[str] = (),
) -> None:
    """Remove empty host node_modules / ro_workspace_deps mountpoint directories (via O_NOFOLLOW) before Git tree sampling."""
    if not target_tree.is_dir():
        return
    tgt_real = target_tree.resolve()
    rel_targets: list[tuple[Path, str]] = []
    if trusted_base_cache is not None and trusted_base_cache.is_dir():
        tbc_real = trusted_base_cache.resolve()
        for root, dirs, _ in os.walk(tbc_real, followlinks=False):
            rp = Path(root)
            if "node_modules" in dirs:
                dirs.remove("node_modules")
                rel_targets.append((rp.relative_to(tbc_real), "node_modules"))
    for raw_rel in extra_rel_mounts:
        rel = Path(str(raw_rel).strip().strip("/"))
        if str(rel) and str(rel) != "." and ".." not in rel.parts:
            rel_targets.append((rel.parent, rel.name))
    for parent_rel, leaf in sorted(rel_targets, key=lambda item: len(item[0].parts), reverse=True):
        with contextlib.suppress(SandboxError, OSError):
            pkg_fd = _open_nofollow_subdir_fd(tgt_real, parent_rel)
            if pkg_fd is not None:
                try:
                    st = os.stat(leaf, dir_fd=pkg_fd, follow_symlinks=False)
                    if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                        os.rmdir(leaf, dir_fd=pkg_fd)
                finally:
                    os.close(pkg_fd)


def copy_clean_tree_no_hardlinks_fds(
    clean_tree: Path,
    verify_out_dir: Path,
    *,
    source_clean_tree_fd: int | None = None,
    target_verify_out_fd: int | None = None,
) -> tuple[int, int]:
    """Populate `verify_out_dir` via retained fds (NEVER `rmtree`ing!) and return OPEN `(ct_fd, vo_fd)` for `--ro-bind-fd`/`--bind-fd`!"""
    from .models import AutopilotError, open_dir_nofollow, pinned_proc_fd_path

    try:
        ct_fd = os.dup(source_clean_tree_fd) if source_clean_tree_fd is not None else open_dir_nofollow(clean_tree, create=False)
    except (AutopilotError, OSError) as exc:
        raise SandboxError(f"Invalid clean_tree directory {clean_tree}: {exc}") from exc
    vo_parent_fd: int | None = None
    vo_fd: int | None = None
    try:
        norm_vo = Path(os.path.normpath(str(verify_out_dir)))
        is_direct_proc_fd = (
            len(norm_vo.parts) == 5
            and norm_vo.parts[1:4] == ("proc", str(os.getpid()), "fd")
            and norm_vo.parts[4].isdigit()
        )
        if target_verify_out_fd is not None:
            vo_fd = os.dup(target_verify_out_fd)
        elif is_direct_proc_fd:
            vo_fd = open_dir_nofollow(norm_vo, create=False)
        else:
            try:
                vo_parent_fd = open_dir_nofollow(verify_out_dir.parent, create=True, mode=0o700)
            except (AutopilotError, OSError) as exc:
                raise SandboxError(f"Invalid verify_out_dir parent {verify_out_dir.parent}: {exc}") from exc

            vo_name = verify_out_dir.name
            if not vo_name or vo_name in (".", "..") or "/" in vo_name:
                raise SandboxError(f"Invalid verify_out_dir leaf name: {vo_name!r}")
            try:
                os.mkdir(vo_name, 0o700, dir_fd=vo_parent_fd)
            except FileExistsError:
                pass
            try:
                vo_fd = os.open(vo_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=vo_parent_fd)
            except OSError as exc:
                raise SandboxError(f"Refusing symlink or non-directory verify_out_dir {verify_out_dir}: {exc}") from exc

        with os.scandir(vo_fd) as vo_it:
            if any(True for _ in vo_it):
                raise SandboxError(
                    f"Refusing to delete or overwrite non-empty verify_out_dir {verify_out_dir} (preserving existing contents)"
                )

        ct_pin = pinned_proc_fd_path(ct_fd)
        vo_pin = pinned_proc_fd_path(vo_fd)
        subprocess.run(
            ["cp", "-a", "--reflink=auto", f"{ct_pin}/.", f"{vo_pin}/"],
            check=True,
            timeout=120,
        )
        clean_inodes: set[tuple[int, int]] = set()
        for root, _, files in os.walk(ct_pin, followlinks=False):
            rp = Path(root)
            for fn in files:
                st = (rp / fn).lstat()
                clean_inodes.add((st.st_dev, st.st_ino))
        for root, _, files in os.walk(vo_pin, followlinks=False):
            rp = Path(root)
            for fn in files:
                p = rp / fn
                st = p.lstat()
                if (st.st_dev, st.st_ino) in clean_inodes:
                    raise SandboxError(f"Hardlink detected between CLEAN_TREE and verify_out_dir: {p}")

        ret_ct, ret_vo = ct_fd, vo_fd
        ct_fd = -1
        vo_fd = None
        return ret_ct, ret_vo
    finally:
        if vo_fd is not None:
            with contextlib.suppress(OSError):
                os.close(vo_fd)
        if vo_parent_fd is not None:
            with contextlib.suppress(OSError):
                os.close(vo_parent_fd)
        if ct_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(ct_fd)


def copy_clean_tree_no_hardlinks(clean_tree: Path, verify_out_dir: Path) -> tuple[Path, Path]:
    """Copy `clean_tree` to `verify_out_dir` via fds and return their verified paths (closing fds on return)."""
    ct_fd, vo_fd = copy_clean_tree_no_hardlinks_fds(clean_tree, verify_out_dir)
    try:
        return Path(os.readlink(f"/proc/self/fd/{ct_fd}")), Path(os.readlink(f"/proc/self/fd/{vo_fd}"))
    finally:
        os.close(vo_fd)
        os.close(ct_fd)


def _parse_go_sdk_version(sdk_dir: Path) -> tuple[int, int, int] | None:
    """Extract semantic `(major, minor, patch)` from validated Go SDK `VERSION` file or directory name."""
    raw = ""
    ver_file = sdk_dir / "VERSION"
    if ver_file.is_file() and not ver_file.is_symlink():
        with contextlib.suppress(OSError):
            raw = ver_file.read_text(encoding="utf-8", errors="replace").splitlines()[0].strip()
    if not raw:
        raw = sdk_dir.name
    m = re.search(r"go(\d+)\.(\d+)(?:\.(\d+))?", raw)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or "0"))


def _host_go_arch_tag() -> str:
    import platform as _plat

    mach = _plat.machine().lower()
    if mach in ("x86_64", "amd64"):
        return "amd64"
    if mach in ("aarch64", "arm64"):
        return "arm64"
    return mach


def discover_host_stateless_toolchains(hhome: Path | None = None) -> tuple[list[Path], list[Path], Path | None]:
    """Validate SDK layout & arch BEFORE adding to `ro_dirs`; sort Go toolchains semantically (never mounting non-SDK dirs)."""
    base = hhome or Path.home()
    ro_dirs: list[Path] = []
    tail_bins: list[Path] = []
    seen: set[Path] = set()
    go_arch = _host_go_arch_tag()

    def _register_ro(real: Path) -> None:
        if real not in seen:
            seen.add(real)
            ro_dirs.append(real)

    # Preserve `.is_dir()` + `.resolve()` for corepack/cargo/rustup (supports symlinked rustup/cargo roots):
    for fixed in (base / ".cache" / "node" / "corepack", base / ".cargo" / "bin", base / ".rustup"):
        if fixed.is_dir():
            _register_ro(fixed.resolve())

    node_name_re = re.compile(r"^(?:node(?:-?v?\d[\d.]*)?|v?\d+\.\d+\.\d+)$")
    for parent_dir in (base / ".local", base / ".nvm" / "versions" / "node"):
        if not parent_dir.is_dir():
            continue
        for nd in sorted(parent_dir.iterdir()):
            if not node_name_re.fullmatch(nd.name) or not nd.is_dir():
                continue
            real_nd = nd.resolve()
            if (real_nd / "bin" / "node").is_file() and (real_nd / "lib" / "node_modules" / "npm").is_dir():
                _register_ro(real_nd)
                tail_bins.append(real_nd / "bin")

    go_candidates: list[tuple[tuple[int, int, int], Path]] = []
    local_dir = base / ".local"
    go_local_re = re.compile(r"^go(?:\d[\d.]*)?$")
    if local_dir.is_dir():
        for gd in sorted(local_dir.iterdir()):
            if not go_local_re.fullmatch(gd.name) or not gd.is_dir():
                continue
            real_gd = gd.resolve()
            ver = _parse_go_sdk_version(real_gd)
            if ver is not None and (real_gd / "bin" / "go").is_file() and (real_gd / "src" / "runtime").is_dir():
                _register_ro(real_gd)
                go_candidates.append((ver, real_gd))

    tc_parent = base / "go" / "pkg" / "mod" / "golang.org"
    tc_re = re.compile(rf"^toolchain@.*-go\d[\d.]*\.linux-{re.escape(go_arch)}$")
    if tc_parent.is_dir() and not tc_parent.is_symlink():
        for tc in sorted(tc_parent.iterdir()):
            if not tc_re.fullmatch(tc.name) or not tc.is_dir() or tc.is_symlink():
                continue
            real_tc = tc.resolve()
            ver_tc = _parse_go_sdk_version(real_tc)
            if ver_tc is not None and (real_tc / "bin" / "go").is_file() and (real_tc / "src" / "runtime").is_dir():
                _register_ro(real_tc)
                go_candidates.append((ver_tc, real_tc))

    go_candidates.sort(key=lambda item: item[0])
    go_root = go_candidates[-1][1] if go_candidates else None
    return ro_dirs, tail_bins, go_root


def resolve_host_go_toolchain_root(hhome: Path | None = None) -> Path | None:
    """Resolve highest semantic Go compiler distribution on host generically."""
    _, _, go_root = discover_host_stateless_toolchains(hhome)
    return go_root


def build_execution_ring_bwrap(
    *,
    ring_kind: str,  # tool_ring | git_ops_ring | verify_ring
    inner_cmd: list[str],
    cwd: Path,
    worktree: Path | None = None,
    managed_gitdir: Path | None = None,
    repo_main_objects: Path | None = None,
    trusted_base_cache: Path | None = None,
    ephemeral_tool_cache: Path | None = None,
    shared_tmp: Path | None = None,
    shell_snapshots: Path | None = None,
    clean_tree: Path | None = None,
    verify_out_dir: Path | None = None,
    scratch_objects: Path | None = None,
    stage_dir: Path | None = None,
    git_cleanup_writable: bool = False,
    enable_ui_verify: bool = False,
    skip_clean_tree_copy: bool = False,
    extra_env: dict[str, str] | None = None,
    retain_fds: list[int] | None = None,
    clean_tree_fd: int | None = None,
    verify_out_fd: int | None = None,
    trusted_base_cache_fd: int | None = None,
    repo_main_dir: Path | None = None,
    ro_workspace_deps: tuple[str, ...] | list[str] = (),
    mask_ro_empty_dirs: tuple[str, ...] | list[str] = (),
) -> list[str]:
    """Assemble network-isolated, credential-free execution rings (tool_ring, git_ops_ring, verify_ring)."""
    if (clean_tree_fd is not None or verify_out_fd is not None or trusted_base_cache_fd is not None or bool(ro_workspace_deps)) and retain_fds is None:
        raise SandboxError("retain_fds list is required whenever clean_tree_fd, verify_out_fd, trusted_base_cache_fd, or ro_workspace_deps is passed")
    if ring_kind not in ("tool_ring", "git_ops_ring", "verify_ring"):
        raise SandboxError(f"Unknown execution ring_kind: {ring_kind!r}")

    bwrap_bin = shutil.which("bwrap") or "/usr/bin/bwrap"
    argv: list[str] = [
        bwrap_bin,
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-net",
        "--new-session",
        "--clearenv",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--dir",
        "/etc",
        "--dir",
        "/tmp",
    ]
    for etc_p in ("/etc/localtime", "/etc/passwd", "/etc/group", "/etc/hosts", "/etc/nsswitch.conf", "/etc/ssl", "/etc/fonts"):
        if Path(etc_p).exists():
            argv.extend(["--ro-bind", etc_p, etc_p])

    path_dirs = ["/usr/local/bin", "/usr/bin", "/bin"]
    if ring_kind in ("tool_ring", "verify_ring"):
        from .models import build_pnpm_exec_cmd
        hhome = Path.home()
        # NEVER mount shared cross-project package/source caches (~/.cargo/registry, ~/.cargo/git, ~/.local/share/pnpm);
        # mount ONLY stateless toolchain binaries (corepack, cargo/bin, rustup) + project's own trusted_base_cache!
        ro_tcs, tail_node_bins, go_tc_root = discover_host_stateless_toolchains(hhome)
        for tc_real in ro_tcs:
            argv.extend(["--ro-bind", str(tc_real), str(tc_real)])
        if (hhome / ".rustup").is_dir():
            argv.extend(["--setenv", "RUSTUP_HOME", str((hhome / ".rustup").resolve())])
        if (hhome / ".cargo" / "bin").is_dir():
            path_dirs.insert(0, str((hhome / ".cargo" / "bin").resolve()))
        for nb in tail_node_bins:
            path_dirs.append(str(nb))
        shim_dir = ensure_secure_dir(Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}") / "ap-toolchain-shims", 0o700)
        argv.extend(["--dir", "/ap-toolchain-bin"])
        for tool_name in ("pnpm", "kustomize", "terraform", "uv"):
            cand_tool = hhome / ".local" / "bin" / tool_name
            if cand_tool.exists():
                real_tool = cand_tool.resolve()
                argv.extend(["--ro-bind", str(real_tool), str(real_tool)])
                if tool_name == "pnpm" and build_pnpm_exec_cmd(real_tool)[0] == "/bin/sh":
                    pnpm_wrap = shim_dir / "pnpm"
                    pnpm_wrap.write_text(f"#!/bin/sh\nexec /bin/sh {real_tool} \"$@\"\n", encoding="utf-8")
                    os.chmod(pnpm_wrap, 0o755)
                    argv.extend(["--ro-bind", str(pnpm_wrap), "/ap-toolchain-bin/pnpm"])
                else:
                    argv.extend(["--symlink", str(real_tool), f"/ap-toolchain-bin/{tool_name}"])
        if go_tc_root is not None:
            argv.extend([
                "--symlink", str(go_tc_root / "bin" / "go"), "/ap-toolchain-bin/go",
                "--setenv", "GOROOT", str(go_tc_root),
                "--setenv", "GOTOOLCHAIN", "local",
            ])
            if (go_tc_root / "bin" / "gofmt").is_file():
                argv.extend(["--symlink", str(go_tc_root / "bin" / "gofmt"), "/ap-toolchain-bin/gofmt"])
        path_dirs.insert(0, "/ap-toolchain-bin")

    if ring_kind == "tool_ring":
        if worktree is None or ephemeral_tool_cache is None or shared_tmp is None:
            raise SandboxError("tool_ring requires worktree, ephemeral_tool_cache, and shared_tmp")
        from .models import AutopilotError, open_dir_nofollow

        ensure_secure_dir(ephemeral_tool_cache, 0o700)
        ensure_secure_dir(shared_tmp, 0o700)
        wt_fd_tool: int | None = None
        if retain_fds is not None:
            try:
                wt_fd_tool = open_dir_nofollow(worktree, create=False)
                retain_fds.append(wt_fd_tool)
                wt_real = Path(os.readlink(f"/proc/self/fd/{wt_fd_tool}"))
                cwd_real = cwd.resolve()
                wt_arg_real = worktree.resolve()
                if cwd == worktree or cwd_real == wt_real or cwd_real == wt_arg_real:
                    cwd_real = wt_real
                elif wt_real in cwd_real.parents:
                    pass
                elif wt_arg_real in cwd_real.parents:
                    cwd_real = wt_real / cwd_real.relative_to(wt_arg_real)
                else:
                    raise SandboxError(f"tool_ring cwd {cwd_real} escapes worktree {wt_real}")
                argv.extend(["--bind-fd", str(wt_fd_tool), str(wt_real)])
                dg_fd_tool = os.open(".git", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=wt_fd_tool)
                if not stat.S_ISREG(os.fstat(dg_fd_tool).st_mode):
                    os.close(dg_fd_tool)
                    raise SandboxError(f"tool_ring requires regular .git gitfile inside worktree {wt_real}")
                retain_fds.append(dg_fd_tool)
                argv.extend(["--ro-bind-fd", str(dg_fd_tool), f"{wt_real}/.git"])
            except (AutopilotError, OSError) as exc:
                raise SandboxError(f"tool_ring failed to bind-fd worktree or readonly .git ({worktree}): {exc}") from exc
        else:
            wt_real = worktree.resolve()
            cwd_real = cwd.resolve()
            if cwd_real != wt_real and wt_real not in cwd_real.parents:
                raise SandboxError(f"tool_ring cwd {cwd_real} escapes worktree {wt_real}")
            argv.extend(["--bind", str(wt_real), str(wt_real)])
            dot_git = wt_real / ".git"
            if dot_git.is_symlink() or not dot_git.is_file():
                raise SandboxError(f"tool_ring requires regular .git gitfile at {dot_git}")
            argv.extend(["--ro-bind", str(dot_git), str(dot_git)])
        if managed_gitdir and managed_gitdir.exists():
            argv.extend(["--ro-bind", str(managed_gitdir.resolve()), str(managed_gitdir.resolve())])
        if repo_main_objects and repo_main_objects.exists():
            argv.extend(["--ro-bind", str(repo_main_objects.resolve()), str(repo_main_objects.resolve())])
        if trusted_base_cache_fd is not None or (trusted_base_cache and trusted_base_cache.exists()):
            if retain_fds is not None:
                tbc_fd, tbc_mount_dest = open_verified_trusted_base_cache_fd(
                    trusted_base_cache, source_tbc_fd=trusted_base_cache_fd
                )
                retain_fds.append(tbc_fd)
                tbc_pin = Path(f"/proc/{os.getpid()}/fd/{tbc_fd}")
                argv.extend(["--ro-bind-fd", str(tbc_fd), str(tbc_mount_dest)])
                argv.extend(
                    prepare_workspace_node_modules_bind_args(
                        trusted_base_cache or tbc_mount_dest,
                        wt_real,
                        tbc_fd=tbc_fd,
                        target_fd=wt_fd_tool,
                        container_target_root=wt_real,
                        retain_fds=retain_fds,
                    )
                )
                if (tbc_pin / "node_modules" / ".bin").is_dir():
                    path_dirs.insert(0, str(tbc_mount_dest / "node_modules" / ".bin"))
                if (tbc_pin / "cargo_home").is_dir():
                    argv.extend([
                        "--setenv", "CARGO_HOME", str(tbc_mount_dest / "cargo_home"),
                        "--setenv", "CARGO_NET_OFFLINE", "true",
                        "--setenv", "CARGO_TARGET_DIR", "/tmp/ap-cargo-target",
                    ])
                if (tbc_pin / "go_mod_cache").is_dir():
                    argv.extend([
                        "--setenv", "GOMODCACHE", str(tbc_mount_dest / "go_mod_cache"),
                        "--setenv", "GOPROXY", "off",
                        "--setenv", "GOSUMDB", "off",
                    ])
            elif trusted_base_cache is not None:
                tbc_real = verify_trusted_base_cache_integrity(trusted_base_cache)
                argv.extend(["--ro-bind", str(tbc_real), str(tbc_real)])
                argv.extend(prepare_workspace_node_modules_bind_args(tbc_real, wt_real))
                if (tbc_real / "node_modules" / ".bin").is_dir():
                    path_dirs.insert(0, str(tbc_real / "node_modules" / ".bin"))
                if (tbc_real / "cargo_home").is_dir():
                    argv.extend([
                        "--setenv", "CARGO_HOME", str(tbc_real / "cargo_home"),
                        "--setenv", "CARGO_NET_OFFLINE", "true",
                        "--setenv", "CARGO_TARGET_DIR", "/tmp/ap-cargo-target",
                    ])
                if (tbc_real / "go_mod_cache").is_dir():
                    argv.extend([
                        "--setenv", "GOMODCACHE", str(tbc_real / "go_mod_cache"),
                        "--setenv", "GOPROXY", "off",
                        "--setenv", "GOSUMDB", "off",
                    ])
        if ro_workspace_deps and repo_main_dir is not None:
            argv.extend(
                prepare_ro_workspace_dep_bind_args(
                    repo_main_dir,
                    ro_workspace_deps,
                    wt_real,
                    target_fd=wt_fd_tool,
                    container_target_root=wt_real if wt_fd_tool is not None else None,
                    retain_fds=retain_fds,
                )
            )
        if mask_ro_empty_dirs:
            if retain_fds is None or wt_fd_tool is None:
                raise SandboxError("tool_ring mask_ro_empty_dirs requires retain_fds")
            # Host-only empty directory strictly OUTSIDE `/ap-tool-cache`, `worktree`, and `/tmp` so tool_ring cannot mutate it!
            writable_roots = (wt_real, ephemeral_tool_cache.resolve(), shared_tmp.resolve())
            rt_mask_base = Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}")
            mask_candidates: list[Path] = []
            if rt_mask_base.is_dir() and os.access(rt_mask_base, os.W_OK):
                mask_candidates.append(rt_mask_base / "ap-ro-masks")
            mask_candidates.append(Path.home() / ".cache" / "ap-ro-masks")
            mask_parent: Path | None = None
            for cand_mp in mask_candidates:
                cand_res = cand_mp.resolve()
                if any(cand_res == wr or cand_res.is_relative_to(wr) or wr.is_relative_to(cand_res) for wr in writable_roots):
                    continue
                mask_parent = cand_mp
                break
            if mask_parent is None:
                raise SandboxError(
                    "Refusing tool_ring RO mask: all candidate mask roots overlap writable worktree/cache/shared_tmp"
                )
            ensure_secure_dir(mask_parent, 0o700)
            empty_t_dir = ensure_secure_dir(mask_parent / "empty", 0o500)
            empty_t_res = empty_t_dir.resolve()
            if any(empty_t_res == wr or empty_t_res.is_relative_to(wr) or wr.is_relative_to(empty_t_res) for wr in writable_roots):
                raise SandboxError(f"Refusing tool_ring RO mask overlapping writable mount: {empty_t_res}")
            for mdir_name in mask_ro_empty_dirs:
                if "/" in mdir_name or "\\" in mdir_name or mdir_name in ("", ".", ".."):
                    raise SandboxError(f"Invalid mask_ro_empty_dirs entry: {mdir_name!r}")
                try:
                    st_m = os.stat(mdir_name, dir_fd=wt_fd_tool, follow_symlinks=False)
                except FileNotFoundError:
                    os.mkdir(mdir_name, 0o700, dir_fd=wt_fd_tool)
                    st_m = os.stat(mdir_name, dir_fd=wt_fd_tool, follow_symlinks=False)
                if stat.S_ISLNK(st_m.st_mode) or not stat.S_ISDIR(st_m.st_mode):
                    raise SandboxError(f"Refusing symlinked or non-directory {mdir_name} in tool_ring worktree")
                empty_t_fd = open_dir_nofollow(empty_t_dir, create=False)
                if any(os.scandir(empty_t_fd)):
                    os.close(empty_t_fd)
                    raise SandboxError(f"Host RO empty mask directory is not empty: {empty_t_dir}")
                retain_fds.append(empty_t_fd)
                argv.extend(["--ro-bind-fd", str(empty_t_fd), f"{wt_real}/{mdir_name}"])
        if shell_snapshots and shell_snapshots.exists():
            argv.extend(["--ro-bind", str(shell_snapshots.resolve()), "/ap-shell-snapshots"])
        argv.extend(["--bind", str(ephemeral_tool_cache.resolve()), "/ap-tool-cache"])
        argv.extend(["--bind", str(shared_tmp.resolve()), "/tmp"])
        argv.extend(["--chdir", str(cwd_real)])
        argv.extend(["--setenv", "XDG_CACHE_HOME", "/ap-tool-cache", "--setenv", "HOME", "/ap-tool-cache"])

    elif ring_kind == "git_ops_ring":
        if worktree is None or managed_gitdir is None:
            raise SandboxError("git_ops_ring requires worktree and managed_gitdir")
        wt_real = worktree.resolve()
        mg_real = managed_gitdir.resolve()
        if repo_main_objects and repo_main_objects.exists():
            argv.extend(["--ro-bind", str(repo_main_objects.resolve()), str(repo_main_objects.resolve())])
        if git_cleanup_writable:
            argv.extend(["--bind", str(mg_real), str(mg_real)])
            argv.extend(["--bind", str(wt_real), str(wt_real)])
        else:
            if scratch_objects is None or stage_dir is None:
                raise SandboxError("git_ops_ring sampling mode requires scratch_objects and stage_dir")
            ensure_secure_dir(scratch_objects, 0o700)
            ensure_secure_dir(stage_dir, 0o700)
            argv.extend(["--ro-bind", str(mg_real), str(mg_real)])
            argv.extend(["--ro-bind", str(wt_real), str(wt_real)])
            argv.extend(["--bind", str(scratch_objects.resolve()), str(scratch_objects.resolve())])
            argv.extend(["--bind", str(stage_dir.resolve()), str(stage_dir.resolve())])
        argv.extend(
            [
                "--chdir",
                str(wt_real),
                "--setenv",
                "GIT_OPTIONAL_LOCKS",
                "0",
                "--setenv",
                "GIT_CONFIG_NOSYSTEM",
                "1",
                "--setenv",
                "GIT_CONFIG_GLOBAL",
                "/dev/null",
                "--setenv",
                "HOME",
                "/tmp",
            ]
        )

    elif ring_kind == "verify_ring":
        if clean_tree is None or verify_out_dir is None:
            raise SandboxError("verify_ring requires clean_tree and verify_out_dir")
        from .models import AutopilotError, open_dir_nofollow

        if retain_fds is not None:
            try:
                if not skip_clean_tree_copy:
                    ct_fd, vo_fd = copy_clean_tree_no_hardlinks_fds(
                        clean_tree,
                        verify_out_dir,
                        source_clean_tree_fd=clean_tree_fd,
                        target_verify_out_fd=verify_out_fd,
                    )
                else:
                    ct_fd = os.dup(clean_tree_fd) if clean_tree_fd is not None else open_dir_nofollow(clean_tree, create=False)
                    vo_fd = os.dup(verify_out_fd) if verify_out_fd is not None else open_dir_nofollow(verify_out_dir, create=False)
            except (AutopilotError, OSError) as exc:
                raise SandboxError(f"Invalid verify_ring directory identity: {exc}") from exc
            retain_fds.extend([ct_fd, vo_fd])
            vo_container = Path("/ap-verify-work")
            argv.extend(["--ro-bind-fd", str(ct_fd), "/ap-clean-tree"])
            argv.extend(["--bind-fd", str(vo_fd), str(vo_container), "--chdir", str(vo_container)])
            if trusted_base_cache_fd is not None or (trusted_base_cache and trusted_base_cache.exists()):
                tbc_fd, tbc_mount_dest = open_verified_trusted_base_cache_fd(
                    trusted_base_cache, source_tbc_fd=trusted_base_cache_fd
                )
                retain_fds.append(tbc_fd)
                tbc_pin = Path(f"/proc/{os.getpid()}/fd/{tbc_fd}")
                argv.extend(["--ro-bind-fd", str(tbc_fd), str(tbc_mount_dest)])
                argv.extend(
                    prepare_workspace_node_modules_bind_args(
                        trusted_base_cache or tbc_mount_dest,
                        vo_container,
                        tbc_fd=tbc_fd,
                        target_fd=vo_fd,
                        container_target_root=vo_container,
                        retain_fds=retain_fds,
                    )
                )
                if (tbc_pin / "node_modules" / ".bin").is_dir():
                    path_dirs.insert(0, str(tbc_mount_dest / "node_modules" / ".bin"))
                if (tbc_pin / "cargo_home").is_dir():
                    argv.extend([
                        "--setenv", "CARGO_HOME", str(tbc_mount_dest / "cargo_home"),
                        "--setenv", "CARGO_NET_OFFLINE", "true",
                        "--setenv", "CARGO_TARGET_DIR", "/ap-verify-work/.ap-cargo-target",
                    ])
                if (tbc_pin / "go_mod_cache").is_dir():
                    argv.extend([
                        "--setenv", "GOMODCACHE", str(tbc_mount_dest / "go_mod_cache"),
                        "--setenv", "GOPROXY", "off",
                        "--setenv", "GOSUMDB", "off",
                    ])
            if ro_workspace_deps and repo_main_dir is not None:
                argv.extend(
                    prepare_ro_workspace_dep_bind_args(
                        repo_main_dir,
                        ro_workspace_deps,
                        vo_container,
                        target_fd=vo_fd,
                        container_target_root=vo_container,
                        retain_fds=retain_fds,
                    )
                )
        else:
            if not skip_clean_tree_copy:
                ct_real, vo_real = copy_clean_tree_no_hardlinks(clean_tree, verify_out_dir)
            else:
                try:
                    _ct_fd = open_dir_nofollow(clean_tree, create=False)
                    _vo_fd = open_dir_nofollow(verify_out_dir, create=False)
                    try:
                        ct_real = Path(os.readlink(f"/proc/self/fd/{_ct_fd}"))
                        vo_real = Path(os.readlink(f"/proc/self/fd/{_vo_fd}"))
                    finally:
                        os.close(_vo_fd)
                        os.close(_ct_fd)
                except (AutopilotError, OSError) as exc:
                    raise SandboxError(f"Invalid verify_ring directory identity: {exc}") from exc
            argv.extend(["--ro-bind", str(ct_real), "/ap-clean-tree"])
            argv.extend(["--bind", str(vo_real), str(vo_real), "--chdir", str(vo_real)])
            if trusted_base_cache and trusted_base_cache.exists():
                tbc_real = verify_trusted_base_cache_integrity(trusted_base_cache)
                argv.extend(["--ro-bind", str(tbc_real), str(tbc_real)])
                argv.extend(prepare_workspace_node_modules_bind_args(tbc_real, vo_real))
                if (tbc_real / "node_modules" / ".bin").is_dir():
                    path_dirs.insert(0, str(tbc_real / "node_modules" / ".bin"))
                if (tbc_real / "cargo_home").is_dir():
                    argv.extend([
                        "--setenv", "CARGO_HOME", str(tbc_real / "cargo_home"),
                        "--setenv", "CARGO_NET_OFFLINE", "true",
                        "--setenv", "CARGO_TARGET_DIR", str(vo_real / ".ap-cargo-target"),
                    ])
                if (tbc_real / "go_mod_cache").is_dir():
                    argv.extend([
                        "--setenv", "GOMODCACHE", str(tbc_real / "go_mod_cache"),
                        "--setenv", "GOPROXY", "off",
                        "--setenv", "GOSUMDB", "off",
                    ])
            if ro_workspace_deps and repo_main_dir is not None:
                argv.extend(
                    prepare_ro_workspace_dep_bind_args(
                        repo_main_dir,
                        ro_workspace_deps,
                        vo_real,
                        container_target_root=vo_real,
                        retain_fds=retain_fds,
                    )
                )
        if enable_ui_verify and Path("/opt/google/chrome").exists():
            argv.extend(["--ro-bind", "/opt/google/chrome", "/opt/google/chrome"])
        argv.extend(["--setenv", "HOME", "/tmp", "--setenv", "CI", "1"])

    argv.extend(["--setenv", "PATH", ":".join(path_dirs), "--setenv", "LANG", "C.UTF-8"])
    if ring_kind in ("tool_ring", "verify_ring"):
        # Cap toolchain-internal process/thread pools (go test, rayon, libuv, playwright) on small burstable hosts;
        # explicit extra_env below (e.g. WORKFLOW verify_env) is emitted later and therefore still wins.
        for k, v in CPU_FANOUT_LIMIT_ENV.items():
            if k not in (extra_env or {}):
                argv.extend(["--setenv", k, v])
    for k, v in (extra_env or {}).items():
        argv.extend(["--setenv", k, v])
    argv.extend(["--", *inner_cmd])
    return argv


_PREFETCH_REGISTRY_DOMAINS: frozenset[str] = frozenset(
    {
        "registry.npmjs.org",
        "index.crates.io",
        "static.crates.io",
        "crates.io",
        "proxy.golang.org",
        "sum.golang.org",
    }
)

_IN_NETNS_PROXY_BRIDGE_PY = """
import json, os, select, socket, subprocess, sys, threading
usock_path = sys.argv[1]
inner_argv = json.loads(sys.argv[2])
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lsock.bind(("127.0.0.1", 0))
port = lsock.getsockname()[1]
lsock.listen(32)
def _pump(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 60.0)
            if not r:
                break
            for s in r:
                d = s.recv(65536)
                if not d:
                    return
                (b if s is a else a).sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try: s.close()
            except OSError: pass
def _serve():
    while True:
        try:
            c, _ = lsock.accept()
            u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            u.connect(usock_path)
            threading.Thread(target=_pump, args=(c, u), daemon=True).start()
        except OSError:
            break
threading.Thread(target=_serve, daemon=True).start()
env = dict(os.environ)
px = f"http://127.0.0.1:{port}"
for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "CARGO_HTTP_PROXY", "npm_config_https_proxy", "npm_config_proxy"):
    env[k] = px
sys.exit(subprocess.run(inner_argv, env=env).returncode)
"""


def build_deps_prefetch_bwrap(
    *,
    inner_cmd: list[str],
    cwd: Path,
    stage_dir: Path,
    proxy_sock: Path,
    ro_source_tree: Path | None = None,
    extra_env: dict[str, str] | None = None,
    stage_fd: int | None = None,
    ro_source_tree_fd: int | None = None,
    retain_fds: list[int] | None = None,
) -> list[str]:
    """Assemble `--unshare-net` prefetch bwrap isolated from host network/loopback & $HOME, bridged ONLY to registry allowlist proxy."""
    from .models import build_pnpm_exec_cmd

    bwrap_bin = shutil.which("bwrap") or "/usr/bin/bwrap"
    if not Path(bwrap_bin).is_file():
        raise SandboxError("bwrap binary is required for isolated dependency prefetch")

    argv: list[str] = [
        bwrap_bin,
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-net",
        "--new-session",
        "--clearenv",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--dir",
        "/etc",
        "--dir",
        "/run/ap",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        str(proxy_sock),
        "/run/ap/proxy.sock",
    ]
    for etc_p in ("/etc/localtime", "/etc/passwd", "/etc/group", "/etc/hosts", "/etc/nsswitch.conf", "/etc/ssl", "/etc/ca-certificates"):
        p_obj = Path(etc_p)
        if p_obj.exists():
            argv.extend(["--ro-bind", str(p_obj.resolve()), etc_p])

    path_dirs = ["/usr/local/bin", "/usr/bin", "/bin"]
    hhome = Path.home()
    ro_tcs_pf, tail_node_pf, go_tc_pf = discover_host_stateless_toolchains(hhome)
    for tc_real in ro_tcs_pf:
        argv.extend(["--ro-bind", str(tc_real), str(tc_real)])
    for nb_pf in tail_node_pf:
        path_dirs.append(str(nb_pf))
    if (hhome / ".rustup").is_dir():
        argv.extend(["--setenv", "RUSTUP_HOME", str((hhome / ".rustup").resolve())])
    if (hhome / ".cargo" / "bin").is_dir():
        path_dirs.insert(0, str((hhome / ".cargo" / "bin").resolve()))

    shim_dir = ensure_secure_dir(Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}") / "ap-toolchain-shims", 0o700)
    argv.extend(["--dir", "/ap-toolchain-bin"])
    cand_pnpm = hhome / ".local" / "bin" / "pnpm"
    if cand_pnpm.exists():
        real_pnpm = cand_pnpm.resolve()
        argv.extend(["--ro-bind", str(real_pnpm), str(real_pnpm)])
        if build_pnpm_exec_cmd(real_pnpm)[0] == "/bin/sh":
            pnpm_wrap = shim_dir / "pnpm"
            pnpm_wrap.write_text(f"#!/bin/sh\nexec /bin/sh {real_pnpm} \"$@\"\n", encoding="utf-8")
            os.chmod(pnpm_wrap, 0o755)
            argv.extend(["--ro-bind", str(pnpm_wrap), "/ap-toolchain-bin/pnpm"])
        else:
            argv.extend(["--symlink", str(real_pnpm), "/ap-toolchain-bin/pnpm"])
    if go_tc_pf is not None:
        argv.extend([
            "--symlink", str(go_tc_pf / "bin" / "go"), "/ap-toolchain-bin/go",
            "--setenv", "GOROOT", str(go_tc_pf),
            "--setenv", "GOTOOLCHAIN", "local",
        ])
    path_dirs.insert(0, "/ap-toolchain-bin")

    if stage_fd is not None and retain_fds is not None:
        dup_st_fd = os.dup(stage_fd)
        retain_fds.append(dup_st_fd)
        st_dest = Path(os.readlink(f"/proc/self/fd/{dup_st_fd}"))
        argv.extend(["--bind-fd", str(dup_st_fd), str(st_dest)])
    else:
        st_dest = stage_dir.resolve()
        argv.extend(["--bind", str(st_dest), str(st_dest)])

    src_dest: Path | None = None
    if ro_source_tree_fd is not None and retain_fds is not None:
        dup_src_fd = os.dup(ro_source_tree_fd)
        retain_fds.append(dup_src_fd)
        src_dest = Path(os.readlink(f"/proc/self/fd/{dup_src_fd}"))
        argv.extend(["--ro-bind-fd", str(dup_src_fd), str(src_dest)])
    elif ro_source_tree is not None and ro_source_tree.exists():
        src_dest = ro_source_tree.resolve()
        argv.extend(["--ro-bind", str(src_dest), str(src_dest)])

    # Derive container `--chdir` strictly from pinned `stage_fd` / `ro_source_tree_fd` destinations when provided!
    if stage_fd is not None and cwd == Path(f"/proc/{os.getpid()}/fd/{stage_fd}"):
        cwd_dest = st_dest
    elif ro_source_tree_fd is not None and src_dest is not None and str(cwd).startswith(f"/proc/{os.getpid()}/fd/{ro_source_tree_fd}"):
        rel_cwd = Path(str(cwd)).relative_to(Path(f"/proc/{os.getpid()}/fd/{ro_source_tree_fd}"))
        cwd_dest = (src_dest / rel_cwd) if str(rel_cwd) != "." else src_dest
    else:
        cwd_dest = cwd.resolve()

    argv.extend([
        "--chdir", str(cwd_dest),
        "--setenv", "HOME", "/tmp",
        "--setenv", "XDG_CACHE_HOME", "/tmp/xdg-cache",
        "--setenv", "CI", "1",
        "--setenv", "LANG", "C.UTF-8",
        "--setenv", "PATH", ":".join(path_dirs),
    ])
    for k, v in (extra_env or {}).items():
        argv.extend(["--setenv", k, v])
    argv.extend([
        "--",
        "/usr/bin/python3",
        "-c",
        _IN_NETNS_PROXY_BRIDGE_PY,
        "/run/ap/proxy.sock",
        json.dumps(inner_cmd),
    ])
    return argv


def run_isolated_deps_prefetch(
    *,
    inner_cmd: list[str],
    cwd: Path,
    stage_dir: Path,
    ro_source_tree: Path | None = None,
    extra_env: dict[str, str] | None = None,
    timeout: int = 300,
    stage_fd: int | None = None,
    ro_source_tree_fd: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run dependency prefetch inside `--unshare-net` bwrap bridged ONLY through registry-allowlisted CONNECT proxy."""
    rt_base = Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}")
    sroot = (rt_base / "ap-pf") if (rt_base.is_dir() and os.access(rt_base, os.W_OK)) else (Path.home() / ".cache" / "ap-pf")
    ensure_secure_dir(sroot, 0o700)
    sdir = ensure_secure_dir(sroot / uuid.uuid4().hex[:10], 0o700)
    psock = sdir / "p.sock"
    proxy = AllowlistConnectProxyServer(psock, allowed_domains=set(_PREFETCH_REGISTRY_DOMAINS))
    proxy.start()
    pf_fds: list[int] = []
    try:
        argv = build_deps_prefetch_bwrap(
            inner_cmd=inner_cmd,
            cwd=cwd,
            stage_dir=stage_dir,
            proxy_sock=psock,
            ro_source_tree=ro_source_tree,
            extra_env=extra_env,
            stage_fd=stage_fd,
            ro_source_tree_fd=ro_source_tree_fd,
            retain_fds=pf_fds,
        )
        return subprocess.run(argv, capture_output=True, text=True, pass_fds=tuple(pf_fds), timeout=timeout, check=False)
    finally:
        for _pfd in pf_fds:
            with contextlib.suppress(OSError):
                os.close(_pfd)
        proxy.close()
        shutil.rmtree(sdir, ignore_errors=True)


class AllowlistConnectProxyServer:
    """Unix-socket HTTP CONNECT proxy strictly enforcing policy_manifest llm_proxy_allowlist_domains on port 443."""

    def __init__(self, sock_path: Path, allowed_domains: set[str] | None = None) -> None:
        self.sock_path = sock_path
        self.allowed_domains = {
            d.lower() for d in (allowed_domains if allowed_domains is not None else POLICY_MANIFEST["llm_proxy_allowlist_domains"])
        }
        self._srv: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        ensure_secure_dir(self.sock_path.parent, 0o700)
        with contextlib.suppress(FileNotFoundError):
            self.sock_path.unlink()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(self.sock_path))
        os.chmod(self.sock_path, 0o600)
        srv.listen(64)
        srv.settimeout(0.25)
        self._srv = srv
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._srv is not None:
            with contextlib.suppress(OSError):
                self._srv.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        with contextlib.suppress(OSError):
            self.sock_path.unlink()

    def _accept_loop(self) -> None:
        assert self._srv is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def _handle_client(self, conn: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            conn.settimeout(10.0)
            hdr = b""
            while b"\r\n\r\n" not in hdr and len(hdr) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                hdr += chunk
            if b"\r\n\r\n" not in hdr:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            first_line = hdr.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
            m = _CONNECT_LINE_RE.match(first_line)
            if not m:
                conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return
            host = m.group(1).lower().rstrip(".")
            port = int(m.group(2))
            if port != 443 or _IP_LITERAL_RE.match(host) or host not in self.allowed_domains:
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                return
            upstream = socket.create_connection((host, 443), timeout=15.0)
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._pump(conn, upstream)
        except OSError:
            with contextlib.suppress(OSError):
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        finally:
            with contextlib.suppress(OSError):
                conn.close()
            if upstream is not None:
                with contextlib.suppress(OSError):
                    upstream.close()

    def _pump(self, a: socket.socket, b: socket.socket) -> None:
        a.setblocking(False)
        b.setblocking(False)
        sockets = [a, b]
        while not self._stop.is_set():
            rlist, _, _ = select.select(sockets, [], [], 30.0)
            if not rlist:
                break
            for src in rlist:
                dst = b if src is a else a
                try:
                    data = src.recv(32768)
                except BlockingIOError:
                    continue
                if not data:
                    return
                dst.setblocking(True)
                dst.settimeout(15.0)
                dst.sendall(data)
                dst.setblocking(False)


class ToolExecServer:
    """Non-blocking Unix-socket server handling ap-safe-sh requests and killing tool_ring pgroup on client abort."""

    def __init__(
        self,
        sock_path: Path,
        worktree: Path,
        *,
        cmd_builder: Callable[[Path, list[str]], list[str]] | None = None,
    ) -> None:
        self.sock_path = sock_path
        self.worktree = worktree.resolve()
        self.cmd_builder = cmd_builder
        self.killed_pgids: list[int] = []
        self._srv: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        ensure_secure_dir(self.sock_path.parent, 0o700)
        with contextlib.suppress(FileNotFoundError):
            self.sock_path.unlink()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(self.sock_path))
        os.chmod(self.sock_path, 0o600)
        srv.listen(32)
        srv.settimeout(0.2)
        self._srv = srv
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._srv is not None:
            with contextlib.suppress(OSError):
                self._srv.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        with contextlib.suppress(OSError):
            self.sock_path.unlink()

    def _accept_loop(self) -> None:
        assert self._srv is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_conn, args=(conn,), daemon=True).start()

    @staticmethod
    def _recv_exact(buf: bytearray, sock: socket.socket, n: int) -> bytes:
        while len(buf) < n:
            chunk = sock.recv(max(4096, n - len(buf)))
            if not chunk:
                raise EOFError("unexpected EOF reading frame")
            buf.extend(chunk)
        out = bytes(buf[:n])
        del buf[:n]
        return out

    @staticmethod
    def _recv_line(buf: bytearray, sock: socket.socket) -> str:
        while b"\n" not in buf:
            if len(buf) > 256:
                raise ValueError("header line too long")
            chunk = sock.recv(4096)
            if not chunk:
                raise EOFError("EOF waiting for header newline")
            buf.extend(chunk)
        idx = buf.index(b"\n")
        line = bytes(buf[:idx]).decode("utf-8")
        del buf[: idx + 1]
        return line

    @staticmethod
    def _drain_rx_frames_to_stdin_queue(rx: bytearray, stdin_tx: bytearray) -> bool:
        """Parse any complete I:<len> / Z:0 frames already buffered in rx; returns True if Z:0 seen."""
        saw_eof = False
        while b"\n" in rx:
            nl = rx.index(b"\n")
            line = bytes(rx[:nl]).decode("ascii", errors="replace")
            if line == "Z:0":
                del rx[: nl + 1]
                saw_eof = True
                break
            if not line.startswith("I:"):
                raise ValueError(f"bad stdin tag: {line!r}")
            ilen = int(line[2:])
            if len(rx) < nl + 1 + ilen:
                break
            stdin_tx.extend(rx[nl + 1 : nl + 1 + ilen])
            del rx[: nl + 1 + ilen]
        return saw_eof

    def _serve_conn(self, conn: socket.socket) -> None:
        proc: subprocess.Popen[bytes] | None = None
        sent_rc = False
        try:
            conn.settimeout(10.0)
            rx = bytearray()
            cwd_hdr = self._recv_line(rx, conn)
            argc_hdr = self._recv_line(rx, conn)
            if not cwd_hdr.startswith("CWD:") or not argc_hdr.startswith("ARGC:"):
                return
            cwd_len = int(cwd_hdr[4:])
            argc = int(argc_hdr[5:])
            cwd_bytes = self._recv_exact(rx, conn, cwd_len + 1)
            if not cwd_bytes.endswith(b"\n"):
                return
            req_cwd_str = cwd_bytes[:-1].decode("utf-8")
            argv: list[str] = []
            for _ in range(argc):
                ahdr = self._recv_line(rx, conn)
                if not ahdr.startswith("A:"):
                    return
                alen = int(ahdr[2:])
                abytes = self._recv_exact(rx, conn, alen + 1)
                if not abytes.endswith(b"\n"):
                    return
                argv.append(abytes[:-1].decode("utf-8", errors="surrogateescape"))

            req_cwd = Path(req_cwd_str).resolve() if Path(req_cwd_str).exists() else self.worktree
            if req_cwd != self.worktree and self.worktree not in req_cwd.parents:
                err_msg = f"tool_ring rejected cwd outside worktree: {req_cwd}\n".encode("utf-8")
                conn.sendall(f"E:{len(err_msg)}\n".encode("ascii") + err_msg + b"R:126\n")
                sent_rc = True
                return

            pass_fds_tool: list[int] = []
            try:
                if self.cmd_builder is not None:
                    built = self.cmd_builder(req_cwd, argv)
                    if isinstance(built, tuple):
                        exec_argv, pass_fds_tool = built
                    else:
                        exec_argv = built
                else:
                    exec_argv = ["/bin/bash", *argv]
                proc = subprocess.Popen(
                    exec_argv,
                    cwd=str(req_cwd),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=tuple(pass_fds_tool),
                    start_new_session=True,
                )
            finally:
                for _tfd in pass_fds_tool:
                    with contextlib.suppress(OSError):
                        os.close(_tfd)
            assert proc.stdin and proc.stdout and proc.stderr
            os.set_blocking(proc.stdin.fileno(), False)
            os.set_blocking(proc.stdout.fileno(), False)
            os.set_blocking(proc.stderr.fileno(), False)
            conn.setblocking(False)

            stdin_tx = bytearray()
            rx_eof_seen = self._drain_rx_frames_to_stdin_queue(rx, stdin_tx)
            stdin_pipe_open = True
            if rx_eof_seen and not stdin_tx:
                stdin_pipe_open = False
                with contextlib.suppress(OSError):
                    proc.stdin.close()

            out_open = True
            err_open = True
            hangup_mask = select.POLLHUP | select.POLLERR | getattr(select, "POLLRDHUP", 0)
            conn_fd = conn.fileno()
            out_fd = proc.stdout.fileno()
            err_fd = proc.stderr.fileno()

            while True:
                # Poll conn for POLLRDHUP/POLLHUP/POLLERR EVEN when stdin_tx is backpressured (unread bytes in sk_receive_queue)!
                backpressured = len(stdin_tx) >= 262144
                poller = select.poll()
                poller.register(conn_fd, hangup_mask if backpressured else (select.POLLIN | hangup_mask))
                if out_open:
                    poller.register(out_fd, select.POLLIN | select.POLLHUP)
                if err_open:
                    poller.register(err_fd, select.POLLIN | select.POLLHUP)
                if stdin_pipe_open and len(stdin_tx) > 0:
                    poller.register(proc.stdin.fileno(), select.POLLOUT | select.POLLERR | select.POLLHUP)

                ev_map = dict(poller.poll(50))
                conn_ev = ev_map.get(conn_fd, 0)

                if (conn_ev & (select.POLLHUP | select.POLLERR)) or (
                    (conn_ev & hangup_mask) and (backpressured or not rx_eof_seen)
                ):
                    if proc.poll() is None:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(proc.pid, signal.SIGKILL)
                        self.killed_pgids.append(proc.pid)
                    return

                if stdin_pipe_open and stdin_tx and (ev_map.get(proc.stdin.fileno(), 0) & (select.POLLOUT | select.POLLERR | select.POLLHUP)):
                    try:
                        nw = os.write(proc.stdin.fileno(), bytes(stdin_tx[:16384]))
                        if nw > 0:
                            del stdin_tx[:nw]
                    except BlockingIOError:
                        pass
                    except (BrokenPipeError, OSError):
                        stdin_tx.clear()
                        stdin_pipe_open = False
                        with contextlib.suppress(OSError):
                            proc.stdin.close()
                    if rx_eof_seen and not stdin_tx and stdin_pipe_open:
                        stdin_pipe_open = False
                        with contextlib.suppress(OSError):
                            proc.stdin.close()

                if not backpressured and (conn_ev & select.POLLIN):
                    try:
                        data = conn.recv(16384)
                    except BlockingIOError:
                        data = None
                    except OSError:
                        data = b""
                    if data == b"":
                        if proc.poll() is None:
                            with contextlib.suppress(ProcessLookupError):
                                os.killpg(proc.pid, signal.SIGKILL)
                            self.killed_pgids.append(proc.pid)
                        return
                    if data and not rx_eof_seen:
                        rx.extend(data)
                        if self._drain_rx_frames_to_stdin_queue(rx, stdin_tx):
                            rx_eof_seen = True
                        if rx_eof_seen and not stdin_tx and stdin_pipe_open:
                            stdin_pipe_open = False
                            with contextlib.suppress(OSError):
                                proc.stdin.close()

                for tag, pipe_obj, pfd in (("O", proc.stdout, out_fd), ("E", proc.stderr, err_fd)):
                    if ev_map.get(pfd, 0) & (select.POLLIN | select.POLLHUP):
                        chunk = pipe_obj.read(32768)
                        if chunk:
                            frame = f"{tag}:{len(chunk)}\n".encode("ascii") + chunk
                            conn.setblocking(True)
                            conn.settimeout(10.0)
                            conn.sendall(frame)
                            conn.setblocking(False)
                        else:
                            if tag == "O":
                                out_open = False
                            else:
                                err_open = False

                rc = proc.poll()
                if rc is not None and not out_open and not err_open:
                    if stdin_pipe_open:
                        stdin_pipe_open = False
                        with contextlib.suppress(OSError):
                            proc.stdin.close()
                    exit_u8 = rc if rc >= 0 else (128 + min(127, -rc))
                    conn.setblocking(True)
                    conn.settimeout(10.0)
                    conn.sendall(f"R:{exit_u8 & 0xFF}\n".encode("ascii"))
                    sent_rc = True
                    return
        except Exception:
            if proc is not None and proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                self.killed_pgids.append(proc.pid)
        finally:
            if proc is not None and not sent_rc and proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
            if proc is not None:
                for p_stream in (proc.stdin, proc.stdout, proc.stderr):
                    if p_stream is not None:
                        with contextlib.suppress(OSError):
                            p_stream.close()
                with contextlib.suppress(Exception):
                    proc.wait(timeout=2.0)
            with contextlib.suppress(OSError):
                conn.close()


def expected_transient_cgroup_dir(unit_name: str, slice_name: str = "app-autopilot.slice", uid: int | None = None) -> Path:
    anchor = user_systemd_permanent_anchor(uid)
    uname = unit_name if unit_name.endswith(".service") else f"{unit_name}.service"
    return anchor / "app.slice" / slice_name / uname


def spawn_transient_unit_under_flock(
    *,
    unit_name: str,
    cmd: list[str],
    flock_fd: int | None = None,
    flock_fds: tuple[int, ...] = (),
    wait: bool,
    unit_kind: str = "cleanup",  # cleanup | worker
    slice_name: str = "app-autopilot.slice",
    extra_env: dict[str, str] | None = None,
    timeout_overrides: dict[str, int] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Submit systemd-run --user holding pass_fds across D-Bus submission without leaking into unit."""
    uname = unit_name if unit_name.endswith(".service") else f"{unit_name}.service"
    if unit_kind == "worker":
        limits: dict[str, int] = {
            "timeout_start_sec": 30,
            "runtime_max_sec": 3600,
            "timeout_stop_sec": 20,
            "wrapper_sigterm_sec": 3660,
            "wrapper_kill_after_sec": 10,
        }
    else:
        limits = dict(POLICY_MANIFEST["cleanup_unit_limits"])
    if timeout_overrides:
        limits.update(timeout_overrides)

    all_fds: tuple[int, ...] = tuple(dict.fromkeys([*( [flock_fd] if flock_fd is not None else [] ), *flock_fds]))

    sd_args: list[str] = [
        "systemd-run",
        "--user",
        "--collect",
        "--no-ask-password",
        "--expand-environment=no",
        "-q",
        f"--unit={uname}",
        f"--slice={slice_name}",
        "-p",
        "KillMode=control-group",
        "-p",
        f"TimeoutStartSec={limits['timeout_start_sec']}s",
        "-p",
        f"RuntimeMaxSec={limits['runtime_max_sec']}s",
        "-p",
        f"TimeoutStopSec={limits['timeout_stop_sec']}s",
        "-p",
        f"Nice={BACKGROUND_UNIT_NICE}",
    ]
    for k, v in (extra_env or {}).items():
        sd_args.extend([f"--setenv={k}={v}"])

    if wait:
        sd_args.extend(["--wait", "--", *cmd])
        full_argv = [
            "/usr/bin/timeout",
            "-s",
            "TERM",
            "-k",
            f"{limits['wrapper_kill_after_sec']}s",
            f"{limits['wrapper_sigterm_sec']}s",
            *sd_args,
        ]
        hard_py_timeout = int(limits["wrapper_sigterm_sec"]) + int(limits["wrapper_kill_after_sec"]) + 5
    else:
        sd_args.extend(["--no-block", "--", *cmd])
        full_argv = ["/usr/bin/timeout", "-s", "TERM", "-k", "3s", "15s", *sd_args]
        hard_py_timeout = 20

    return subprocess.run(
        full_argv,
        capture_output=True,
        text=True,
        pass_fds=all_fds,
        timeout=hard_py_timeout,
        check=False,
    )


def verify_self_in_expected_cgroup(expected_cgroup_dir: Path | str) -> bool:
    """Verify current process executes inside the exact registered systemd transient cgroup."""
    exp = Path(expected_cgroup_dir).resolve()
    try:
        cg_lines = Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for line in cg_lines:
        if line.startswith("0::/"):
            rel = line[3:]
            actual = Path(f"/sys/fs/cgroup{rel}").resolve()
            return actual == exp
    return False


def verify_unit_terminated(unit_name: str, expected_cgroup_dir: Path | str, *, uid: int | None = None) -> bool:
    """Verify transient systemd unit has 0 live processes using permanent user@<uid>.service cgroup anchor."""
    anchor = user_systemd_permanent_anchor(uid)
    if not anchor.is_dir():
        return False

    uname = unit_name if unit_name.endswith(".service") else f"{unit_name}.service"
    exp_dir = Path(expected_cgroup_dir)
    if anchor not in exp_dir.parents:
        return False

    show = subprocess.run(
        [
            "systemctl",
            "--user",
            "show",
            uname,
            "--property=LoadState,ActiveState,SubState,MainPID,ControlGroup",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if show.returncode != 0:
        return False

    props: dict[str, str] = {}
    for line in show.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()

    load_state = props.get("LoadState", "")
    active_state = props.get("ActiveState", "")
    main_pid = props.get("MainPID", "")
    cgroup_prop = props.get("ControlGroup", "")

    if active_state not in ("inactive", "failed") or main_pid != "0":
        return False

    if exp_dir.exists():
        if cgroup_prop and Path(f"/sys/fs/cgroup{cgroup_prop}") != exp_dir:
            return False
        try:
            procs_txt = (exp_dir / "cgroup.procs").read_text(encoding="utf-8").strip()
            events_txt = (exp_dir / "cgroup.events").read_text(encoding="utf-8")
        except OSError:
            return False
        if procs_txt != "":
            return False
        if "populated 0" not in events_txt:
            return False
        return True

    if cgroup_prop != "":
        return False
    if load_state == "not-found" and active_state == "inactive":
        return True
    if load_state == "loaded" and active_state in ("inactive", "failed"):
        with contextlib.suppress(Exception):
            subprocess.run(["systemctl", "--user", "reset-failed", uname], timeout=5, check=False, capture_output=True)
        return True
    return False


def _safe_nonneg_int(val: Any) -> int | None:
    if isinstance(val, bool):
        return None
    if isinstance(val, int) and val >= 0:
        return val
    return None


def _safe_nonneg_float(val: Any) -> float | None:
    if isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        f = float(val)
        if math.isfinite(f) and f >= 0.0:
            return f
    return None


def parse_cli_turn_output(
    family: str,
    raw_stdout: str,
    *,
    raw_stderr: str = "",
    exit_code: int = 0,
    strict_envelope: bool = False,
    output_format: str = "",
) -> dict[str, Any]:
    """Decode CLI protocol envelope (Claude JSON/JSONL, Codex JSONL, AGY JSON/stream-json) into normalized text + token/cost usage."""
    base: dict[str, Any] = {
        "ok": exit_code == 0,
        "status": "ok" if exit_code == 0 else "error",
        "text": raw_stdout or "",
        "model_reported": "",
        "input_tokens": 0,
        "output_tokens": 0,
        "thinking_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "cost_usd": None,
        "cost_known": False,
        "usage_known": False,
        "error_detail": "",
        "envelope_detected": False,
    }
    stripped = (raw_stdout or "").strip()
    if not stripped:
        if strict_envelope:
            base["ok"] = False
            base["status"] = "error"
            base["error_detail"] = f"{family} CLI produced empty stdout"
        return base

    if family == "agy":
        res_obj: dict[str, Any] | None = None
        model_rep = ""
        # Accept bare single JSON object ONLY when not explicitly in stream-json mode
        if output_format != "stream-json" and stripped.startswith("{") and stripped.endswith("}"):
            try:
                cand = json.loads(stripped)
                if isinstance(cand, dict):
                    if cand.get("event") == "result" and isinstance(cand.get("result"), dict):
                        res_obj = cand["result"]
                    elif "status" in cand and ("response" in cand or "usage" in cand or "error" in cand):
                        res_obj = cand
            except json.JSONDecodeError:
                pass
        # NDJSON (`--output-format stream-json`): accept ONLY explicit `event == "result"` terminal objects!
        # Split strictly on `\n` (NOT str.splitlines(), which breaks legal RFC 8259 U+2028/U+2029 inside JSON strings!).
        if res_obj is None:
            for line in stripped.split("\n"):
                s = line.strip()
                if not s.startswith("{"):
                    continue
                try:
                    ev = json.loads(s)
                except json.JSONDecodeError:
                    continue
                if not isinstance(ev, dict):
                    continue
                if ev.get("event") == "init" and isinstance(ev.get("init"), dict):
                    m0 = ev["init"].get("model")
                    if isinstance(m0, str) and m0.strip():
                        model_rep = m0.strip()
                elif ev.get("event") == "result" and isinstance(ev.get("result"), dict):
                    res_obj = ev["result"]
        if res_obj is None:
            if strict_envelope:
                base["ok"] = False
                base["status"] = "error"
                base["error_detail"] = "AGY CLI output missing terminal JSON result envelope"
            return base
        base["envelope_detected"] = True
        if model_rep:
            base["model_reported"] = model_rep
        st_str = str(res_obj.get("status") or "").strip().upper()
        base["text"] = str(res_obj.get("response") or "")
        err_str = str(res_obj.get("error") or "").strip()
        if err_str:
            base["error_detail"] = err_str
        usage = res_obj.get("usage")
        if isinstance(usage, dict):
            in_t = _safe_nonneg_int(usage.get("input_tokens"))
            out_t = _safe_nonneg_int(usage.get("output_tokens"))
            thk_t = _safe_nonneg_int(usage.get("thinking_tokens"))
            cr_t = _safe_nonneg_int(usage.get("cache_read_tokens"))
            cw_t = _safe_nonneg_int(usage.get("cache_write_tokens"))
            if in_t is not None or out_t is not None:
                base["input_tokens"] = in_t or 0
                base["output_tokens"] = out_t or 0
                base["thinking_tokens"] = thk_t or 0
                base["cache_read_tokens"] = cr_t or 0
                base["cache_write_tokens"] = cw_t or 0
                base["usage_known"] = True
        cost_val = _safe_nonneg_float(res_obj.get("total_cost_usd"))
        if cost_val is None:
            cost_val = _safe_nonneg_float(res_obj.get("cost_usd"))
        base["cost_usd"] = cost_val
        base["cost_known"] = cost_val is not None
        if exit_code != 0 or st_str != "SUCCESS":
            base["ok"] = False
            base["status"] = "error"
            if not base["error_detail"]:
                base["error_detail"] = f"AGY terminal status={st_str or 'UNKNOWN'}"
        return base

    if family == "claude":
        ev_res: dict[str, Any] | None = None
        _claude_res_keys = ("result", "usage", "is_error", "total_cost_usd", "cost_usd")
        # Try single JSON object first; on JSONDecodeError (e.g. multi-line JSONL starting/ending with braces!), scan lines!
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                single = json.loads(stripped)
                if isinstance(single, dict) and single.get("type") == "result" and any(k in single for k in _claude_res_keys):
                    ev_res = single
            except json.JSONDecodeError:
                pass
        if ev_res is None:
            for line in stripped.split("\n"):
                s = line.strip()
                if not s.startswith("{"):
                    continue
                try:
                    obj = json.loads(s)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict) and obj.get("type") == "result" and any(k in obj for k in _claude_res_keys):
                    ev_res = obj
        if ev_res is None:
            if strict_envelope:
                base["ok"] = False
                base["status"] = "error"
                base["error_detail"] = "Claude CLI output missing terminal result JSON envelope"
            return base
        base["envelope_detected"] = True
        res_txt = ev_res.get("result")
        base["text"] = res_txt if isinstance(res_txt, str) else (json.dumps(res_txt) if res_txt is not None else "")
        is_err = bool(ev_res.get("is_error"))
        subtype = str(ev_res.get("subtype") or "").strip().lower()
        usage = ev_res.get("usage")
        if isinstance(usage, dict):
            raw_in = _safe_nonneg_int(usage.get("input_tokens")) or 0
            cr = _safe_nonneg_int(usage.get("cache_read_input_tokens")) or 0
            cw = _safe_nonneg_int(usage.get("cache_creation_input_tokens")) or 0
            out_t = _safe_nonneg_int(usage.get("output_tokens"))
            if out_t is not None or raw_in > 0 or cr > 0 or cw > 0:
                base["input_tokens"] = raw_in + cr + cw
                base["output_tokens"] = out_t or 0
                base["cache_read_tokens"] = cr
                base["cache_write_tokens"] = cw
                base["usage_known"] = True
        claude_cost = _safe_nonneg_float(ev_res.get("total_cost_usd"))
        if claude_cost is None:
            claude_cost = _safe_nonneg_float(ev_res.get("cost_usd"))
        base["cost_usd"] = claude_cost
        base["cost_known"] = claude_cost is not None
        if exit_code != 0 or is_err or (subtype and subtype != "success"):
            base["ok"] = False
            base["status"] = "error"
            base["error_detail"] = str(ev_res.get("error") or base["text"] or f"Claude result subtype={subtype or 'error'}")[:500]
        return base

    if family == "codex":
        # Codex emits thread-cumulative token snapshots on `turn.completed`; keep latest snapshot per thread_id!
        thread_snapshots: dict[str, tuple[int, int, int, int, int]] = {}
        thread_costs: dict[str, float] = {}
        thread_cost_complete: dict[str, bool] = {}
        started_threads: set[str] = set()
        completed_threads: set[str] = set()
        current_thread_id = "default"
        saw_codex_event = False
        saw_turn_completed = False
        last_turn_terminal = ""
        last_err_msg = ""
        last_agent_msg: str | None = None
        for line in stripped.split("\n"):
            s = line.strip()
            if not s.startswith("{"):
                continue
            try:
                ev = json.loads(s)
            except json.JSONDecodeError:
                continue
            if not isinstance(ev, dict):
                continue
            etype = ev.get("type")
            if not isinstance(etype, str):
                continue
            if etype in ("thread.started", "turn.started", "turn.completed", "turn.failed", "item.started", "item.completed", "error"):
                saw_codex_event = True
            if etype == "thread.started":
                tid_val = ev.get("thread_id")
                if isinstance(tid_val, str) and tid_val.strip():
                    current_thread_id = tid_val.strip()
            elif etype == "turn.started":
                # Reset terminal status, message, and cost completeness on each new turn so timeout/failure keeps subtotal marked incomplete!
                last_turn_terminal = "started"
                last_agent_msg = None
                started_threads.add(current_thread_id)
                thread_cost_complete[current_thread_id] = False
            elif etype == "item.completed" and isinstance(ev.get("item"), dict):
                item = ev["item"]
                if item.get("type") == "agent_message" and isinstance(item.get("text"), str):
                    last_agent_msg = item["text"]
            elif etype == "turn.completed":
                saw_turn_completed = True
                last_turn_terminal = "completed"
                completed_threads.add(current_thread_id)
                cv = _safe_nonneg_float(ev.get("cost_usd"))
                if cv is None:
                    cv = _safe_nonneg_float(ev.get("total_cost_usd"))
                if cv is not None:
                    prev_c = thread_costs.get(current_thread_id)
                    thread_costs[current_thread_id] = max(prev_c, cv) if prev_c is not None else cv
                    thread_cost_complete[current_thread_id] = True
                else:
                    # Latest completed turn on this thread omitted cumulative cost -> subtotal is incomplete!
                    thread_cost_complete[current_thread_id] = False
                if isinstance(ev.get("usage"), dict):
                    u = ev["usage"]
                    in_v = _safe_nonneg_int(u.get("input_tokens"))
                    out_v = _safe_nonneg_int(u.get("output_tokens"))
                    cr_v = _safe_nonneg_int(u.get("cached_input_tokens"))
                    cw_v = _safe_nonneg_int(u.get("cache_write_input_tokens"))
                    thk_v = _safe_nonneg_int(u.get("reasoning_output_tokens"))
                    if in_v is not None or out_v is not None:
                        prev = thread_snapshots.get(current_thread_id)
                        if prev is None:
                            thread_snapshots[current_thread_id] = (
                                in_v or 0,
                                out_v or 0,
                                cr_v or 0,
                                cw_v or 0,
                                thk_v or 0,
                            )
                        else:
                            # Keep monotonic latest cumulative thread snapshot (prevents double-counting replays & multi-turn snapshots!)
                            thread_snapshots[current_thread_id] = (
                                max(prev[0], in_v or 0),
                                max(prev[1], out_v or 0),
                                max(prev[2], cr_v or 0),
                                max(prev[3], cw_v or 0),
                                max(prev[4], thk_v or 0),
                            )
            elif etype == "turn.failed":
                last_turn_terminal = "failed"
                started_threads.add(current_thread_id)
                thread_cost_complete[current_thread_id] = False
                err_obj = ev.get("error")
                if isinstance(err_obj, dict) and err_obj.get("message"):
                    last_err_msg = str(err_obj["message"])
                elif isinstance(ev.get("message"), str):
                    last_err_msg = str(ev["message"])
            elif etype == "error":
                # Transient mid-turn error is diagnostic only; final turn.completed / turn.failed + exit_code decides outcome!
                err_obj = ev.get("error")
                if isinstance(err_obj, dict) and err_obj.get("message"):
                    last_err_msg = str(err_obj["message"])
                elif isinstance(ev.get("message"), str):
                    last_err_msg = str(ev["message"])
        if not saw_codex_event:
            if strict_envelope:
                base["ok"] = False
                base["status"] = "error"
                base["error_detail"] = "Codex CLI output missing JSONL event stream"
            return base
        base["envelope_detected"] = True
        if last_agent_msg is not None:
            base["text"] = last_agent_msg
        if thread_snapshots:
            base["input_tokens"] = sum(s[0] for s in thread_snapshots.values())
            base["output_tokens"] = sum(s[1] for s in thread_snapshots.values())
            base["cache_read_tokens"] = sum(s[2] for s in thread_snapshots.values())
            base["cache_write_tokens"] = sum(s[3] for s in thread_snapshots.values())
            base["thinking_tokens"] = sum(s[4] for s in thread_snapshots.values())
            base["usage_known"] = True
        all_threads = set(thread_snapshots.keys()) | completed_threads | started_threads | set(thread_costs.keys())
        base["cost_usd"] = sum(thread_costs.values()) if thread_costs else None
        base["cost_known"] = bool(all_threads) and all(thread_cost_complete.get(tid, False) for tid in all_threads)
        # Require confirmed successful `turn.completed` on the FINAL turn (turn.started-only or trailing unfinished turn MUST fail!)
        if exit_code != 0 or not saw_turn_completed or last_turn_terminal != "completed":
            base["ok"] = False
            base["status"] = "error"
            base["error_detail"] = last_err_msg or "Codex JSONL stream missing successful terminal turn.completed event"
        return base

    return base


def parse_session_usage(jsonl_lines: list[str]) -> dict[str, Any]:
    """Parse full-session deduplicated token usage & cost from Claude, Codex, or AGY JSON/JSONL streams."""
    raw = "\n".join(jsonl_lines)
    for fam in ("claude", "agy", "codex"):
        parsed = parse_cli_turn_output(fam, raw, exit_code=0, strict_envelope=False)
        if parsed["envelope_detected"] and (parsed["usage_known"] or parsed["cost_usd"] is not None):
            return {
                "input_tokens": int(parsed["input_tokens"]),
                "output_tokens": int(parsed["output_tokens"]),
                "cache_read_tokens": int(parsed["cache_read_tokens"]),
                "cache_write_tokens": int(parsed["cache_write_tokens"]),
                "thinking_tokens": int(parsed["thinking_tokens"]),
                "cost_usd": float(parsed["cost_usd"]) if parsed["cost_usd"] is not None else 0.0,
                "cost_known": bool(parsed["cost_known"]),
            }
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "thinking_tokens": 0,
        "cost_usd": 0.0,
        "cost_known": False,
    }


def run_optional_ui_verify(
    *,
    clean_tree_dir: Path,
    verify_out_dir: Path,
    ui_url: str,
    dod_and_server_cmd: str = "",
    trusted_base_cache: Path | None = None,
    timeout_sec: int = 90,
    clean_tree_fd: int | None = None,
    trusted_base_cache_fd: int | None = None,
    extra_env: dict[str, str] | None = None,
    repo_main_dir: Path | None = None,
    ro_workspace_deps: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    """Execute DoD + loopback server + headless Chrome DOM/HTTP check & screenshot inside ONE offline verify_ring."""
    chrome_bin = Path("/opt/google/chrome/chrome")
    if not chrome_bin.exists():
        return {"ok": False, "reason": "/opt/google/chrome/chrome not installed"}
    if not ui_url.startswith(("http://127.0.0.1", "http://localhost", "file://")):
        return {"ok": False, "reason": "UI verify inside offline verify_ring only permits loopback or file:// URLs"}

    from .models import open_dir_nofollow, pinned_proc_fd_path

    # Fresh empty out-of-tree UI artifact dir opened via `O_NOFOLLOW` + `--bind-fd` so pre-existing files or volume swaps cannot spoof Chrome!
    ui_art_fd = open_dir_nofollow(verify_out_dir.parent / f".ui-artifacts-{uuid.uuid4().hex[:8]}", create=True, mode=0o700)
    retain_fds: list[int] = [ui_art_fd]
    try:
        ui_pin = pinned_proc_fd_path(ui_art_fd)
        shot_host = ui_pin / "screenshot.png"
        dom_host = ui_pin / "dom.html"
        done_host = ui_pin / "chrome.done"

        combined_sh = (
            "set -euo pipefail\n"
            + (f"( {dod_and_server_cmd}\n)\n" if dod_and_server_cmd else "")
            + (
                f"python3 -c 'import urllib.request, sys; r = urllib.request.urlopen({json.dumps(ui_url)}, timeout=10); sys.exit(0 if 200 <= r.status < 400 else 1)'\n"
                if ui_url.startswith("http://")
                else ""
            )
            + f"{json.dumps(str(chrome_bin))} --headless=new --disable-gpu --no-sandbox --disable-dev-shm-usage "
            + "--screenshot=/ap-ui-artifacts/screenshot.png --dump-dom "
            + f"{json.dumps(ui_url)} > /ap-ui-artifacts/dom.html\n"
            + "printf 'ok\\n' > /ap-ui-artifacts/chrome.done\n"
        )
        argv = build_execution_ring_bwrap(
            ring_kind="verify_ring",
            inner_cmd=["/bin/bash", "-lc", combined_sh],
            cwd=verify_out_dir,
            clean_tree=clean_tree_dir,
            verify_out_dir=verify_out_dir,
            trusted_base_cache=trusted_base_cache,
            enable_ui_verify=True,
            skip_clean_tree_copy=False,
            retain_fds=retain_fds,
            clean_tree_fd=clean_tree_fd,
            trusted_base_cache_fd=trusted_base_cache_fd,
            extra_env=extra_env,
            repo_main_dir=repo_main_dir,
            ro_workspace_deps=ro_workspace_deps,
        )
        sep_idx = argv.index("--")
        argv = [*argv[:sep_idx], "--bind-fd", str(ui_art_fd), "/ap-ui-artifacts", *argv[sep_idx:]]
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            pass_fds=tuple(retain_fds),
            timeout=timeout_sec,
            check=False,
        )
        dom_txt = dom_host.read_text(encoding="utf-8", errors="replace") if dom_host.is_file() else ""
        is_chrome_err = ("chrome-error://" in dom_txt) or ("ERR_CONNECTION_REFUSED" in dom_txt) or ("ERR_FILE_NOT_FOUND" in dom_txt)
        ok = (
            proc.returncode == 0
            and done_host.is_file()
            and shot_host.is_file()
            and shot_host.stat().st_size > 0
            and bool(dom_txt.strip())
            and not is_chrome_err
        )
        shot_real = str(Path(os.readlink(f"/proc/self/fd/{ui_art_fd}")) / "screenshot.png") if shot_host.is_file() else None
        return {
            "ok": ok,
            "exit_code": proc.returncode,
            "chrome_error_page": is_chrome_err,
            "stdout": sanitize_terminal_text(proc.stdout, 1000),
            "stderr": sanitize_terminal_text(proc.stderr, 1000),
            "screenshot": shot_real,
        }
    finally:
        for _fd in retain_fds:
            with contextlib.suppress(OSError):
                os.close(_fd)
