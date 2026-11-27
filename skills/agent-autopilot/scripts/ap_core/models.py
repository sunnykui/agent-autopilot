"""Domain models, policy manifest loader, WORKFLOW.md parser, Chef fill-in validators, and quota parser."""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

POLICY_MANIFEST_PATH = Path(__file__).resolve().with_name("policy_manifest.json")

_ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_CLIXML_TAG_RE = re.compile(r"#<\s*CLIXML\b|<Objs\b[^>]*>.*?</Objs>", re.DOTALL | re.IGNORECASE)
_QUOTA_RESETS_RE = re.compile(
    r"(?:hit your [^\n]*?limit|rate limit|usage limit|quota exceeded)[^\n]*?resets\s+"
    r"(?:(?P<month>[A-Za-z]{3,9})\s+(?P<day>\d{1,2}),?\s+(?:at\s+)?)?"
    r"(?P<hour>\d{1,2})(?::(?P<minute>\d{2}))?\s*(?P<ampm>am|pm)?\s*"
    r"(?:\((?P<tz>[A-Za-z0-9_+-/]+)\))?",
    re.IGNORECASE,
)


class AutopilotError(Exception):
    """Base deterministic error in agent-autopilot."""


class ScopeConflictError(AutopilotError):
    """Raised when caller pr_id conflicts with a unit's bound PR identity."""


class PolicyFreezeError(AutopilotError):
    """Raised when authoritative WORKFLOW.md is invalid, missing, or violates hard invariants."""


class SandboxError(AutopilotError):
    """Raised when sandbox setup, cgroup verification, or native binary checks fail."""


class ScopeViolationError(AutopilotError):
    """Raised when candidate git tree violates raw path, hard-stop, allowlist, or secret gates."""

    def __init__(self, message: str, *, violations: list[str], is_lockfile: bool = False) -> None:
        super().__init__(message)
        self.violations = violations
        self.is_lockfile = is_lockfile


class EmptyCandidateError(AutopilotError):
    """Raised when the writer's worktree has no changes against the authorized base."""


class QuotaExhaustedError(AutopilotError):
    """Raised when an LLM CLI reports a subscription window limit with a parseable reset timestamp."""

    def __init__(self, message: str, *, wake_at_iso: str, family: str) -> None:
        super().__init__(message)
        self.wake_at_iso = wake_at_iso
        self.family = family


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def now_iso() -> str:
    return now_utc().isoformat()


def read_nonempty_token_file(token_file: str | Path) -> str:
    """Read and strip a dedicated token file; convert any I/O or decode failure into AutopilotError."""
    tp = Path(token_file).expanduser()
    try:
        if not tp.is_file():
            raise AutopilotError(f"Dedicated token_file missing: {tp}")
        tok = tp.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise AutopilotError(f"Dedicated token_file unreadable ({tp}): {exc}") from exc
    if not tok:
        raise AutopilotError(f"Dedicated token_file is empty or whitespace-only: {tp}")
    return tok


def build_pnpm_exec_cmd(pnpm_bin: str | Path) -> list[str]:
    """Invoke ELF or #!-script pnpm directly; fall back to `/bin/sh` ONLY for Corepack's shebang-less sh shim."""
    real = Path(pnpm_bin).resolve()
    try:
        with real.open("rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        raise AutopilotError(f"Unable to inspect pnpm binary {real}: {exc}") from exc
    if magic.startswith(b"\x7fELF") or magic.startswith(b"#!"):
        return [str(real)]
    return ["/bin/sh", str(real)]


def load_policy_manifest(path: Path | None = None) -> dict[str, Any]:
    target = path or POLICY_MANIFEST_PATH
    data = json.loads(target.read_text(encoding="utf-8"))
    if data.get("schema_version") != 16:
        raise AutopilotError(f"Unexpected policy_manifest schema_version: {data.get('schema_version')}")
    if not data.get("one_mutation_per_op_id"):
        raise AutopilotError("policy_manifest must enforce one_mutation_per_op_id=true")
    return data


POLICY_MANIFEST: dict[str, Any] = load_policy_manifest()
EXTERNAL_OP_STATUSES: tuple[str, ...] = tuple(POLICY_MANIFEST["external_op_statuses"])
PENDING_OP_STATUSES: tuple[str, ...] = ("prepared_local", "in_flight", "unknown_paused")
ACTION_TYPES: tuple[str, ...] = tuple(POLICY_MANIFEST["action_transport_map"].keys())
SUPERVISOR_ADMIN_ACTIONS: frozenset[str] = frozenset(POLICY_MANIFEST["supervisor_admin_actions"])
CANDIDATE_BOUND_WORKER_ACTIONS: frozenset[str] = frozenset(
    {"push_branch", "create_draft_pr", "mark_pr_ready", "merge_pr", "enqueue_pr"}
)


def default_config_root() -> Path:
    raw = os.environ.get("AGENT_AUTOPILOT_CONFIG_DIR")
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".config" / "agent-autopilot").resolve()


def default_state_root() -> Path:
    raw = os.environ.get("AGENT_AUTOPILOT_STATE_DIR")
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".local" / "state" / "agent-autopilot").resolve()


def default_cache_root() -> Path:
    raw = os.environ.get("AGENT_AUTOPILOT_CACHE_DIR")
    if raw:
        return Path(raw).expanduser().resolve()
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg).expanduser() if xdg else (Path.home() / ".cache")
    return (base / "agent-work" / "autopilot").resolve()


def open_dir_nofollow(
    path: Path,
    *,
    create: bool = False,
    mode: int = 0o700,
    expected_dev: int | None = None,
    expected_ino: int | None = None,
    fsync_ancestors: bool = False,
) -> int:
    """Walk `path` component-by-component from `/` using `O_RDONLY|O_DIRECTORY|O_NOFOLLOW` (never following or chmodding symlinks)."""
    import contextlib as _contextlib
    import errno as _errno
    import stat as _stat

    norm = Path(os.path.normpath(str(path)))
    if not norm.is_absolute():
        norm = Path(os.path.normpath(str(Path.cwd() / norm)))
    parts = norm.parts[1:]
    if (
        len(parts) >= 4
        and parts[0] == "proc"
        and parts[1] == str(os.getpid())
        and parts[2] == "fd"
        and parts[3].isdigit()
    ):
        base_fd = int(parts[3])
        st_base = os.fstat(base_fd)
        if not _stat.S_ISDIR(st_base.st_mode):
            raise AutopilotError(f"Pinned fd {base_fd} is not a directory")
        fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base_fd)
        walk_parts = parts[4:]
    else:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        walk_parts = parts
    try:
        if fsync_ancestors and create:
            os.fsync(fd)
        for idx, part in enumerate(walk_parts):
            mkdir_created = False
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode, dir_fd=fd)
                    mkdir_created = True
                except FileExistsError:
                    pass
                try:
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except OSError as exc2:
                    if exc2.errno in (_errno.ELOOP, _errno.ENOTDIR):
                        raise AutopilotError(f"Refusing symlink or non-directory component {part!r} in {norm}") from exc2
                    raise
            except OSError as exc:
                if exc.errno in (_errno.ELOOP, _errno.ENOTDIR):
                    raise AutopilotError(f"Refusing symlink or non-directory component {part!r} in {norm}") from exc
                raise
            if create and walk_parts and idx == len(walk_parts) - 1:
                with _contextlib.suppress(OSError):
                    os.fchmod(next_fd, mode)
            if mkdir_created or (fsync_ancestors and create):
                os.fsync(next_fd)
                os.fsync(fd)
            os.close(fd)
            fd = next_fd
        st = os.fstat(fd)
        if not _stat.S_ISDIR(st.st_mode):
            raise AutopilotError(f"Opened path is not a directory: {norm}")
        if expected_dev is not None and expected_ino is not None:
            if int(st.st_dev) != int(expected_dev) or int(st.st_ino) != int(expected_ino):
                raise AutopilotError(
                    f"Directory identity drifted at {norm}: ({st.st_dev}, {st.st_ino}) != ({expected_dev}, {expected_ino})"
                )
        return fd
    except BaseException:
        os.close(fd)
        raise


def pinned_proc_fd_path(dir_fd: int) -> Path:
    """Return a current-process `/proc/<pid>/fd/<dir_fd>` path anchored to the open kernel directory object."""
    return Path(f"/proc/{os.getpid()}/fd/{dir_fd}")


def renameat2_noreplace(src_dir_fd: int, src_name: str, dst_dir_fd: int, dst_name: str) -> None:
    """Atomically rename `(src_dir_fd, src_name) -> (dst_dir_fd, dst_name)` using Linux `renameat2(..., RENAME_NOREPLACE=1)`."""
    import ctypes as _ctypes

    libc = _ctypes.CDLL("libc.so.6", use_errno=True)
    rc = libc.renameat2(int(src_dir_fd), os.fsencode(src_name), int(dst_dir_fd), os.fsencode(dst_name), 1)
    if rc != 0:
        err = _ctypes.get_errno()
        raise OSError(err, os.strerror(err), src_name, None, dst_name)


def rename_noreplace_at_dirfd(dir_fd: int, src_name: str, dst_name: str) -> None:
    """Atomically rename `src_name -> dst_name` inside `dir_fd` using Linux `renameat2(..., RENAME_NOREPLACE=1)`."""
    renameat2_noreplace(dir_fd, src_name, dir_fd, dst_name)


def restore_from_qbox_noreplace(qfd: int, parent_fd: int, orig_name: str) -> None:
    """Restore `(qfd, 'item')` back into `parent_fd` without overwriting any concurrent entry."""
    import errno as _errno
    import uuid as _uuid

    try:
        renameat2_noreplace(qfd, "item", parent_fd, orig_name)
        return
    except OSError as exc:
        if exc.errno != _errno.EEXIST:
            raise
    for _ in range(64):
        alt = f"{orig_name}.restored-{_uuid.uuid4().hex[:12]}"
        try:
            renameat2_noreplace(qfd, "item", parent_fd, alt)
            return
        except OSError as exc2:
            if exc2.errno == _errno.EEXIST:
                continue
            raise
    raise AutopilotError(f"Failed to restore quarantined {orig_name!r} without overwrite")


def create_private_qbox_at_dirfd(parent_fd: int) -> tuple[str, int]:
    """Create an exclusive `0700` `.ap-qbox-<12hex>` dir inside `parent_fd`, verify 0 entries, durably stamp `user.ap_qbox`, and return `(qname, qfd)`."""
    import errno as _errno
    import uuid as _uuid

    for _ in range(64):
        qname = f".ap-qbox-{_uuid.uuid4().hex[:12]}"
        try:
            os.mkdir(qname, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        qfd = os.open(qname, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            with os.scandir(qfd) as qit:
                if any(True for _ in qit):
                    raise AutopilotError(f"Unexpected non-empty private qbox {qname!r}")
            os.fchmod(qfd, 0o700)
            os.setxattr(qfd, b"user.ap_qbox", b"1")
            os.fsync(qfd)
            ret = qfd
            qfd = -1
            return qname, ret
        except OSError as exc:
            if exc.errno == _errno.EEXIST:
                continue
            raise
        finally:
            if qfd >= 0:
                os.close(qfd)
    raise AutopilotError("Failed to create unique private quarantine directory")


def _read_xattr_ascii_strict(fd: int, attr_name: bytes) -> str:
    """Read ASCII `user.*` xattr from open `fd`; return `""` ONLY when absent (`ENODATA`/`ENOTSUP`), raising on `EIO`!"""
    import errno as _errno

    no_attr_codes = {getattr(_errno, "ENODATA", 61), getattr(_errno, "ENOATTR", 61), _errno.ENOTSUP, _errno.EOPNOTSUPP}
    try:
        return os.getxattr(fd, attr_name).decode("ascii", errors="replace")
    except OSError as exc:
        if exc.errno in no_attr_codes:
            return ""
        raise


def _settle_qbox_item_at_dirfd(
    parent_fd: int,
    qfd: int,
    restore_name: str,
    *,
    tracked_files: dict[tuple[int, int], str] | None = None,
    purged_files: dict[tuple[int, int], str] | None = None,
    expected_dir_owner_token: str = "",
    on_file_purged: Any = None,
    restore_on_reject: bool = True,
) -> None:
    """Inspect `(qfd, 'item')` strictly by post-move `fstat` + actual xattrs, zero-truncate & settle secrets, or restore foreign files."""
    import contextlib as _ctx
    import stat as _stat

    try:
        rfd_i = os.open("item", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=qfd)
    except OSError as exc_open:
        if restore_on_reject:
            with _ctx.suppress(OSError, AutopilotError):
                restore_from_qbox_noreplace(qfd, parent_fd, restore_name)
        raise AutopilotError(f"Refusing unreadable/non-regular entry {restore_name!r}: {exc_open}") from exc_open

    try:
        st_r = os.fstat(rfd_i)
        if not _stat.S_ISREG(st_r.st_mode):
            if restore_on_reject:
                restore_from_qbox_noreplace(qfd, parent_fd, restore_name)
            raise AutopilotError(f"Refusing non-regular entry {restore_name!r} inside credential directory")
        ikey = (int(st_r.st_dev), int(st_r.st_ino))
        actual_cred_tok = _read_xattr_ascii_strict(rfd_i, b"user.ap_cred_id")
        actual_owned_tok = _read_xattr_ascii_strict(rfd_i, b"user.ap_owned_file")

        in_tracked = tracked_files is not None and ikey in tracked_files
        if bool(actual_cred_tok) or in_tracked:
            # Secret credential file branch (chosen by post-move inode + actual `user.ap_cred_id` xattr!):
            if tracked_files is None:
                if (
                    not actual_cred_tok
                    or st_r.st_nlink != 1
                    or (expected_dir_owner_token and actual_owned_tok != expected_dir_owner_token)
                ):
                    if restore_on_reject:
                        restore_from_qbox_noreplace(qfd, parent_fd, restore_name)
                    raise AutopilotError(f"Credential file {restore_name!r} failed standalone token/hardlink check")
                with _ctx.suppress(OSError):
                    os.fchmod(rfd_i, 0o600)
                wfd = os.open("item", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=qfd)
                try:
                    st_w = os.fstat(wfd)
                    if (int(st_w.st_dev), int(st_w.st_ino)) != ikey or st_w.st_nlink != 1:
                        if restore_on_reject:
                            restore_from_qbox_noreplace(qfd, parent_fd, restore_name)
                        raise AutopilotError(f"Credential file {restore_name!r} hardlink/identity check failed")
                    os.ftruncate(wfd, 0)
                    os.fsync(wfd)
                finally:
                    os.close(wfd)
                os.fsync(qfd)
                os.fsync(parent_fd)
                if on_file_purged is not None:
                    on_file_purged(ikey[0], ikey[1])
                os.unlink("item", dir_fd=qfd)
                os.fsync(qfd)
                return

            if in_tracked and bool(tracked_files[ikey]) and actual_cred_tok == tracked_files[ikey]:
                if st_r.st_nlink != 1:
                    if restore_on_reject:
                        restore_from_qbox_noreplace(qfd, parent_fd, restore_name)
                    raise AutopilotError(
                        f"Credential file {restore_name!r} has extra hardlinks (st_nlink={st_r.st_nlink}); refusing to truncate"
                    )
                with _ctx.suppress(OSError):
                    os.fchmod(rfd_i, 0o600)
                wfd = os.open("item", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=qfd)
                try:
                    st_w = os.fstat(wfd)
                    if (int(st_w.st_dev), int(st_w.st_ino)) != ikey or st_w.st_nlink != 1:
                        if restore_on_reject:
                            restore_from_qbox_noreplace(qfd, parent_fd, restore_name)
                        raise AutopilotError(f"Credential file {restore_name!r} hardlink/identity check failed")
                    os.ftruncate(wfd, 0)
                    os.fsync(wfd)
                finally:
                    os.close(wfd)
                os.fsync(qfd)
                os.fsync(parent_fd)
                if on_file_purged is not None:
                    on_file_purged(ikey[0], ikey[1])
                os.unlink("item", dir_fd=qfd)
                os.fsync(qfd)
                return

            if (
                purged_files is not None
                and ikey in purged_files
                and bool(purged_files[ikey])
                and actual_cred_tok == purged_files[ikey]
                and st_r.st_size == 0
                and st_r.st_nlink == 1
            ):
                os.unlink("item", dir_fd=qfd)
                os.fsync(qfd)
                return

            if (
                not in_tracked
                and st_r.st_size == 0
                and st_r.st_nlink == 1
                and bool(expected_dir_owner_token)
                and actual_owned_tok == expected_dir_owner_token
            ):
                # 0-byte secret shell interrupted prior to SQLite registration & prior to writing secret bytes
                # (including when `(dev, ino)` reused a previous turn's `purged=1` inode with a distinct `owner_token`!):
                os.unlink("item", dir_fd=qfd)
                os.fsync(qfd)
                return

            if restore_on_reject:
                restore_from_qbox_noreplace(qfd, parent_fd, restore_name)
            raise AutopilotError(f"Credential file {restore_name!r} identity/owner_token/hardlink check failed")

        # Non-secret file branch (`actual_cred_tok == ""` and `ikey not in tracked_files` — even if `ikey` reused a historical `purged_files` inode!):
        if (not restore_on_reject and not expected_dir_owner_token) or (
            expected_dir_owner_token and actual_owned_tok != expected_dir_owner_token
        ):
            if restore_on_reject:
                restore_from_qbox_noreplace(qfd, parent_fd, restore_name)
            raise AutopilotError(f"Refusing to delete unowned foreign file {restore_name!r} inside credential directory")
        os.unlink("item", dir_fd=qfd)
        os.fsync(qfd)
    finally:
        os.close(rfd_i)


def try_clean_crashed_qbox_at_dirfd(
    parent_fd: int,
    qname: str,
    *,
    tracked_files: dict[tuple[int, int], str] | None = None,
    purged_files: dict[tuple[int, int], str] | None = None,
    expected_dir_owner_token: str = "",
    on_file_purged: Any = None,
) -> bool:
    """Recover `.ap-qbox-*` across EVERY crash point (including `mkdir`->`setxattr` empty shell & reused-inode config)!"""
    import contextlib as _ctx

    if not qname.startswith(".ap-qbox-"):
        return False
    try:
        qfd = os.open(qname, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError:
        return False
    try:
        with os.scandir(qfd) as qit:
            qentries = [e.name for e in qit]
        if not qentries:
            # 0-entry `.ap-qbox-*` shell (crashed right after `mkdir` before `user.ap_qbox`, or after `unlink('item')`):
            pass
        elif qentries == ["item"]:
            try:
                if _read_xattr_ascii_strict(qfd, b"user.ap_qbox") != "1":
                    return False
                _settle_qbox_item_at_dirfd(
                    parent_fd,
                    qfd,
                    "restored_entry",
                    tracked_files=tracked_files,
                    purged_files=purged_files,
                    expected_dir_owner_token=expected_dir_owner_token,
                    on_file_purged=on_file_purged,
                    restore_on_reject=False,
                )
            except (AutopilotError, OSError):
                return False
        else:
            return False
    finally:
        os.close(qfd)
    with _ctx.suppress(OSError):
        os.rmdir(qname, dir_fd=parent_fd)
        return True
    return False


def quarantine_noreplace_at_dirfd(dir_fd: int, src_name: str, dst_prefix: str) -> str:
    """Atomically rename `src_name` inside `dir_fd` using Linux `renameat2(..., RENAME_NOREPLACE=1)`, retrying on `EEXIST`."""
    import errno as _errno
    import uuid as _uuid

    for _ in range(64):
        cand = f"{dst_prefix}-{_uuid.uuid4().hex[:12]}"
        try:
            rename_noreplace_at_dirfd(dir_fd, src_name, cand)
            return cand
        except OSError as exc:
            if exc.errno == _errno.EEXIST:
                continue
            raise
    raise AutopilotError(f"Failed to pick unique RENAME_NOREPLACE quarantine name for {src_prefix_msg(dst_prefix)}")


def src_prefix_msg(p: str) -> str:
    return p


def set_cred_owner_token(fd: int, token: str) -> None:
    """Bind unique creation `token` to an open file/directory inode via `user.ap_cred_id` xattr."""
    if token:
        os.setxattr(fd, b"user.ap_cred_id", token.encode("ascii"))


def verify_cred_owner_token(fd: int, expected_token: str) -> bool:
    """Verify open file/directory `fd` carries exact `user.ap_cred_id == expected_token` (defeating freed-inode reuse!)."""
    if not expected_token:
        return True
    try:
        raw = os.getxattr(fd, b"user.ap_cred_id")
    except OSError:
        return False
    return raw.decode("ascii", errors="replace") == expected_token


def set_owned_file_token(fd: int, dir_owner_token: str) -> None:
    """Stamp an exclusively-created file inside `sub_fd` with `user.ap_owned_file = dir_owner_token`."""
    if dir_owner_token:
        os.setxattr(fd, b"user.ap_owned_file", dir_owner_token.encode("ascii"))


def verify_owned_file_token(fd: int, expected_dir_token: str) -> bool:
    """Verify regular file `fd` carries `user.ap_owned_file == expected_dir_token`."""
    if not expected_dir_token:
        return True
    try:
        raw = os.getxattr(fd, b"user.ap_owned_file")
    except OSError:
        return False
    return raw.decode("ascii", errors="replace") == expected_dir_token


def get_sub_intent_token(fd: int) -> str:
    """Read `user.ap_sub_id` child-creation intent token persisted on `sbh_fd` before child creation."""
    try:
        return os.getxattr(fd, b"user.ap_sub_id").decode("ascii", errors="replace")
    except OSError:
        return ""


def empty_and_fsync_dirfd(
    target_fd: int,
    *,
    on_dir_emptied: Any = None,
    on_file_purged: Any = None,
    expected_owner_token: str = "",
    allowed_child_dirs: dict[tuple[int, int], str] | None = None,
    purged_child_dirs: dict[tuple[int, int], str] | None = None,
    tracked_files: dict[tuple[int, int], str] | None = None,
    purged_files: dict[tuple[int, int], str] | None = None,
    credential_mode: bool = False,
) -> None:
    """Recursively unlink/rmdir entries strictly inside open `target_fd` (`O_NOFOLLOW`), staging credential-mode files into `qfd` first!"""
    import contextlib as _contextlib
    import stat as _stat

    if not verify_cred_owner_token(target_fd, expected_owner_token):
        raise AutopilotError("Credential directory owner_token mismatch (refusing to empty reused/foreign inode)")

    is_cred_mode = bool(
        credential_mode
        or expected_owner_token
        or allowed_child_dirs is not None
        or purged_child_dirs is not None
        or tracked_files is not None
        or purged_files is not None
        or on_file_purged is not None
        or on_dir_emptied is not None
    )
    sub_intent_tok = get_sub_intent_token(target_fd) if is_cred_mode else ""
    eff_file_cb = on_file_purged if on_file_purged is not None else on_dir_emptied
    with _contextlib.suppress(OSError):
        os.fchmod(target_fd, 0o700)
    with os.scandir(target_fd) as it:
        names = sorted(e.name for e in it)
    for name in names:
        if is_cred_mode and name.startswith(".ap-qbox-"):
            if try_clean_crashed_qbox_at_dirfd(
                target_fd,
                name,
                tracked_files=tracked_files,
                purged_files=purged_files,
                expected_dir_owner_token=expected_owner_token,
                on_file_purged=eff_file_cb,
            ):
                continue
            raise AutopilotError(f"Unrecoverable or foreign entry inside private qbox {name!r}")
        try:
            st = os.stat(name, dir_fd=target_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if _stat.S_ISDIR(st.st_mode) and not _stat.S_ISLNK(st.st_mode):
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=target_fd)
            already_purged_empty_shell = False
            try:
                st_child = os.fstat(child_fd)
                ckey = (int(st_child.st_dev), int(st_child.st_ino))
                if allowed_child_dirs is not None:
                    if ckey in allowed_child_dirs:
                        child_tok = allowed_child_dirs[ckey]
                    else:
                        purged_tok_ok = (
                            purged_child_dirs is not None
                            and ckey in purged_child_dirs
                            and bool(purged_child_dirs[ckey])
                            and verify_cred_owner_token(child_fd, purged_child_dirs[ckey])
                        )
                        intent_tok_ok = bool(sub_intent_tok) and verify_cred_owner_token(child_fd, sub_intent_tok)
                        if purged_tok_ok or intent_tok_ok:
                            cand_child_tok = (
                                purged_child_dirs[ckey]
                                if (purged_child_dirs is not None and ckey in purged_child_dirs)
                                else sub_intent_tok
                            )
                            with os.scandir(child_fd) as q_scan:
                                sub_q_names = [e.name for e in q_scan if e.name.startswith(".ap-qbox-")]
                            for sub_q in sub_q_names:
                                try_clean_crashed_qbox_at_dirfd(
                                    child_fd,
                                    sub_q,
                                    tracked_files=tracked_files,
                                    purged_files=purged_files,
                                    expected_dir_owner_token=cand_child_tok,
                                    on_file_purged=eff_file_cb,
                                )
                        with os.scandir(child_fd) as c_empty_it:
                            child_is_empty = not any(True for _ in c_empty_it)
                        unpublished_empty_sub = bool(expected_owner_token) and name in (".codex", ".claude")
                        if child_is_empty and (purged_tok_ok or intent_tok_ok or unpublished_empty_sub):
                            already_purged_empty_shell = True
                            child_tok = ""
                        else:
                            raise AutopilotError(
                                f"Refusing to recurse into unregistered subdirectory {name!r} inside credential directory"
                            )
                else:
                    child_tok = ""
                if not already_purged_empty_shell:
                    empty_and_fsync_dirfd(
                        child_fd,
                        on_dir_emptied=on_dir_emptied,
                        on_file_purged=eff_file_cb,
                        expected_owner_token=child_tok,
                        allowed_child_dirs=allowed_child_dirs,
                        purged_child_dirs=purged_child_dirs,
                        tracked_files=tracked_files,
                        purged_files=purged_files,
                        credential_mode=is_cred_mode,
                    )
                    if on_dir_emptied is not None:
                        on_dir_emptied(ckey[0], ckey[1])
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=target_fd)
        elif is_cred_mode:
            # Stage into private `qfd` FIRST, then inspect `fstat` + actual xattrs on the isolated fd (immune to pre-move swaps!):
            if not _stat.S_ISREG(st.st_mode) or _stat.S_ISLNK(st.st_mode):
                raise AutopilotError(f"Refusing non-regular/symlink entry {name!r} inside credential directory")
            qname, qfd = create_private_qbox_at_dirfd(target_fd)
            moved_into_qbox = False
            try:
                renameat2_noreplace(target_fd, name, qfd, "item")
                moved_into_qbox = True
                _settle_qbox_item_at_dirfd(
                    target_fd,
                    qfd,
                    name,
                    tracked_files=tracked_files,
                    purged_files=purged_files,
                    expected_dir_owner_token=expected_owner_token,
                    on_file_purged=eff_file_cb,
                    restore_on_reject=True,
                )
                moved_into_qbox = False
            except OSError as exc_q:
                if moved_into_qbox:
                    with _contextlib.suppress(OSError, AutopilotError):
                        with os.scandir(qfd) as qchk:
                            has_item = any(e.name == "item" for e in qchk)
                        if has_item:
                            restore_from_qbox_noreplace(qfd, target_fd, name)
                raise AutopilotError(f"Failed to purge staged entry {name!r}: {exc_q}") from exc_q
            finally:
                os.close(qfd)
                with _contextlib.suppress(OSError):
                    os.rmdir(qname, dir_fd=target_fd)
        else:
            os.unlink(name, dir_fd=target_fd)
    with os.scandir(target_fd) as check_it:
        if any(True for _ in check_it):
            raise AutopilotError("Directory still non-empty after empty_and_fsync_dirfd")
    os.fsync(target_fd)


def ensure_secure_dir(path: Path, mode: int = 0o700) -> Path:
    fd = open_dir_nofollow(path, create=True, mode=mode)
    os.close(fd)
    return Path(os.path.normpath(str(path)))


def ensure_sealed_tokens_dir(state_root: Path) -> Path:
    """Open `state_root` and `sealed_tokens` via `O_DIRECTORY|O_NOFOLLOW` before applying `fchmod(0700)`."""
    import errno as _errno

    sfd = open_dir_nofollow(state_root, create=True, mode=0o700)
    try:
        try:
            os.mkdir("sealed_tokens", 0o700, dir_fd=sfd)
        except FileExistsError:
            pass
        try:
            tfd = os.open("sealed_tokens", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=sfd)
        except OSError as exc:
            if exc.errno in (_errno.ELOOP, _errno.ENOTDIR):
                raise AutopilotError(f"Refusing symlinked or non-directory sealed_tokens under {state_root}") from exc
            raise
        try:
            os.fchmod(tfd, 0o700)
        finally:
            os.close(tfd)
    finally:
        os.close(sfd)
    return Path(os.path.normpath(str(state_root))) / "sealed_tokens"


def sanitize_terminal_text(raw: str, max_chars: int = 4000) -> str:
    text = _CLIXML_TAG_RE.sub("", raw or "")
    text = _ANSI_OSC_RE.sub("", text)
    text = _ANSI_CSI_RE.sub("", text)
    cleaned = "".join(ch for ch in text if ch in ("\n", "\t") or (ord(ch) >= 32 and ord(ch) != 127))
    cleaned = cleaned.strip()
    if len(cleaned) > max_chars:
        return cleaned[: max_chars - 3] + "..."
    return cleaned


def compute_ref_id_hmac(secret_key: bytes, unit_key: str, op_type: str, discriminator: str = "") -> str:
    msg = f"{unit_key}|{op_type}|{discriminator}".encode("utf-8")
    digest = hmac.new(secret_key, msg, hashlib.sha256).hexdigest()[:24]
    return f"ap-{digest}"


def parse_quota_reset(raw_output: str, *, now: dt.datetime | None = None) -> str | None:
    """Detect subscription quota exhaustion messages and compute concrete UTC wake ISO timestamp."""
    ref_now = now or now_utc()
    cleaned = sanitize_terminal_text(raw_output, max_chars=8000)
    m = _QUOTA_RESETS_RE.search(cleaned)
    if not m:
        return None
    tz_name = m.group("tz") or "America/Los_Angeles"
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("America/Los_Angeles")
    local_now = ref_now.astimezone(tz)
    hour = int(m.group("hour"))
    minute = int(m.group("minute") or "0")
    ampm = (m.group("ampm") or "").lower()
    if ampm == "pm" and hour < 12:
        hour += 12
    elif ampm == "am" and hour == 12:
        hour = 0
    if hour > 23 or minute > 59:
        return None

    month_str = m.group("month")
    day_str = m.group("day")
    if month_str and day_str:
        month_lookup = {
            "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
            "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
        }
        mon = month_lookup.get(month_str[:3].lower())
        if mon:
            year = local_now.year
            candidate = dt.datetime(year, mon, int(day_str), hour, minute, 5, tzinfo=tz)
            if candidate <= local_now - dt.timedelta(days=180):
                candidate = candidate.replace(year=year + 1)
            return candidate.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat()

    candidate = local_now.replace(hour=hour, minute=minute, second=5, microsecond=0)
    if candidate <= local_now:
        candidate += dt.timedelta(days=1)
    # Add 60s safety cushion so we wake cleanly after reset
    candidate += dt.timedelta(seconds=60)
    return candidate.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class SendGrant:
    granted: bool
    op_id: str
    op_type: str
    owner_kind: str
    owner_epoch: int
    grant_token: str = ""
    unit_key: str = ""
    pr_id: str | None = None
    candidate_sha: str | None = None
    authorized_base_ref: str | None = None
    authorized_head_ref: str | None = None
    ref_id_hmac: str | None = None
    op_seq: int = 0


@dataclass(frozen=True)
class PrSnapshot:
    pr_id: str
    state: str  # OPEN | MERGED | CLOSED
    is_draft: bool
    head_ref_oid: str
    head_ref_name: str
    base_ref_name: str
    merge_queue_entry_id: str | None = None
    merge_queue_enqueuer: str | None = None
    merge_queue_enqueued_at: str | None = None
    enqueue_event_timestamps: tuple[str, ...] | None = None
    auto_merge_enabled: bool = False
    snapshot_seq: int = 0
    number: int | None = None
    body: str = ""


@dataclass(frozen=True)
class ScopeResolution:
    eff_pr_id: str | None
    scope_units: tuple[str, ...]
    pending_cnt: int
    any_veto: int
    max_op_seq: int


@dataclass(frozen=True)
class WorkflowConfig:
    project_id: str
    kind: str  # issue | routine | delegated
    enabled: bool
    repos: tuple[str, ...]
    workspace_path: str
    authorized_base_ref: str = "main"
    branch_prefix: str = "agent/"
    trust_tier: str = "T1"
    max_in_progress: int = 1
    max_per_day: int = 5
    write_scope: tuple[str, ...] = ()
    merge_paths: tuple[str, ...] = ()
    merge_method: str = "SQUASH"
    verify_cmd: str = ""
    enable_ui_verify: bool = False
    ui_verify_url: str = ""
    writer_family: str = "codex"
    schedule_interval_sec: int = 300
    routine_driver: str = ""
    delegated_cmd: str = ""
    token_file: str = ""
    merge_token_file: str = ""
    assignee: str = "@me"
    require_labels: tuple[str, ...] = ()
    skip_labels: tuple[str, ...] = ("needs-decision", "agent:needs-human", "agent:blocked")
    priority_labels: tuple[str, ...] = ("P0", "P1")
    extra: dict[str, Any] = field(default_factory=dict)
    prompt_body: str = ""
    policy_version: str = ""
    source_path: str = ""

    def to_frontmatter_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d.pop("prompt_body", None)
        d.pop("policy_version", None)
        d.pop("source_path", None)
        for k, v in list(d.items()):
            if isinstance(v, tuple):
                d[k] = list(v)
        return d


def render_workflow_markdown(cfg: WorkflowConfig) -> str:
    header = json.dumps(cfg.to_frontmatter_dict(), ensure_ascii=False, indent=2)
    body = cfg.prompt_body.strip() or f"# {cfg.project_id} Authoritative Autopilot Workflow\n"
    return f"---\n{header}\n---\n\n{body}\n"


def _parse_simple_frontmatter(raw_fm: str) -> dict[str, Any]:
    stripped = raw_fm.strip()
    if stripped.startswith("{"):
        obj = json.loads(stripped)
        if not isinstance(obj, dict):
            raise PolicyFreezeError("WORKFLOW.md JSON frontmatter must be an object")
        return obj
    # Minimal deterministic YAML subset (key: scalar / JSON array / inline list)
    result: dict[str, Any] = {}
    current_list_key: str | None = None
    for raw_line in stripped.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith("- ") and current_list_key:
            item = line.lstrip()[2:].strip().strip("\"'")
            result.setdefault(current_list_key, []).append(item)
            continue
        current_list_key = None
        if ":" not in line:
            raise PolicyFreezeError(f"Unsupported frontmatter line in WORKFLOW.md: {raw_line!r}")
        key, val_raw = line.split(":", 1)
        key = key.strip()
        val = val_raw.strip()
        if not val:
            current_list_key = key
            result[key] = []
        elif val.startswith(("[", "{", '"')):
            result[key] = json.loads(val)
        elif val.lower() in ("true", "false"):
            result[key] = val.lower() == "true"
        elif re.fullmatch(r"-?\d+", val):
            result[key] = int(val)
        else:
            result[key] = val.strip("\"'")
    return result


def _coerce_label_tuple(raw: Any, field_name: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        return tuple(p.strip() for p in raw.split(",") if p.strip())
    if isinstance(raw, (list, tuple)):
        return tuple(str(x).strip() for x in raw if str(x).strip())
    raise PolicyFreezeError(f"{field_name} must be a list of strings or comma-separated string")


def parse_workflow_file(path: Path) -> WorkflowConfig:
    if not path.is_file():
        raise PolicyFreezeError(f"Authoritative WORKFLOW.md not found: {path}")
    raw_bytes = path.read_bytes()
    policy_version = hashlib.sha256(raw_bytes).hexdigest()
    raw_text = raw_bytes.decode("utf-8")
    if not raw_text.startswith("---\n"):
        raise PolicyFreezeError(f"WORKFLOW.md must start with '---\\n' frontmatter: {path}")
    end_idx = raw_text.find("\n---\n", 4)
    if end_idx < 0:
        raise PolicyFreezeError(f"WORKFLOW.md missing closing '\\n---\\n' frontmatter delimiter: {path}")
    fm_text = raw_text[4:end_idx]
    body_text = raw_text[end_idx + 5 :].strip()
    fm = _parse_simple_frontmatter(fm_text)

    project_id = str(fm.get("project_id") or "").strip()
    kind = str(fm.get("kind") or "").strip()
    if not project_id or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project_id):
        raise PolicyFreezeError(f"Invalid project_id in {path}: {project_id!r}")
    if kind not in ("issue", "routine", "delegated"):
        raise PolicyFreezeError(f"Invalid kind in {path}: {kind!r}")
    trust_tier = str(fm.get("trust_tier") or "T1").strip()
    if trust_tier not in ("T1", "T2", "T3", "T4"):
        raise PolicyFreezeError(f"Invalid trust_tier in {path}: {trust_tier!r}")
    writer_family = str(fm.get("writer_family") or "codex").strip()
    if writer_family not in ("codex", "claude"):
        raise PolicyFreezeError(f"Invalid writer_family in {path}: {writer_family!r}")

    write_scope = tuple(str(x).strip() for x in (fm.get("write_scope") or []) if str(x).strip())
    if kind == "issue" and not write_scope:
        raise PolicyFreezeError(f"Issue project {project_id} MUST define non-empty write_scope in {path}")
    branch_prefix = str(fm.get("branch_prefix") or POLICY_MANIFEST["default_branch_prefix"]).strip()
    if not branch_prefix.endswith("/"):
        branch_prefix += "/"
    authorized_base_ref = str(fm.get("authorized_base_ref") or "main").strip()
    if kind == "issue" and not authorized_base_ref:
        raise PolicyFreezeError(f"Issue project {project_id} MUST define authorized_base_ref")

    max_in_progress = int(fm.get("max_in_progress", 1))
    if max_in_progress < 1 or max_in_progress > max(POLICY_MANIFEST["chef_pipeline"]["staircase_concurrency_steps"]):
        raise PolicyFreezeError(f"max_in_progress={max_in_progress} out of bounds [1..3]")

    raw_req_src = fm["require_labels"] if "require_labels" in fm else (fm.get("extra") or {}).get("require_labels")
    req_labels = _coerce_label_tuple(raw_req_src, "require_labels")
    skip_labels = _coerce_label_tuple(
        fm["skip_labels"] if "skip_labels" in fm else ["needs-decision", "agent:needs-human", "agent:blocked"],
        "skip_labels",
    )
    prio_labels = _coerce_label_tuple(
        fm["priority_labels"] if "priority_labels" in fm else ["P0", "P1"],
        "priority_labels",
    )
    overlap_lbls = {r.lower() for r in req_labels} & {s.lower() for s in skip_labels}
    if overlap_lbls:
        raise PolicyFreezeError(f"require_labels and skip_labels cannot overlap in {path}: {sorted(overlap_lbls)}")

    return WorkflowConfig(
        project_id=project_id,
        kind=kind,
        enabled=bool(fm.get("enabled", True)),
        repos=tuple(str(x).strip() for x in (fm.get("repos") or []) if str(x).strip()),
        workspace_path=str(fm.get("workspace_path") or "").strip(),
        authorized_base_ref=authorized_base_ref,
        branch_prefix=branch_prefix,
        trust_tier=trust_tier,
        max_in_progress=max_in_progress,
        max_per_day=int(fm.get("max_per_day", 5)),
        write_scope=write_scope,
        merge_paths=tuple(str(x).strip() for x in (fm.get("merge_paths") or []) if str(x).strip()),
        merge_method=str(fm.get("merge_method") or "SQUASH").upper(),
        verify_cmd=str(fm.get("verify_cmd") or "").strip(),
        enable_ui_verify=bool(fm.get("enable_ui_verify", False)),
        ui_verify_url=str(fm.get("ui_verify_url") or "").strip(),
        writer_family=writer_family,
        schedule_interval_sec=max(30, int(fm.get("schedule_interval_sec", 300))),
        routine_driver=str(fm.get("routine_driver") or "").strip(),
        delegated_cmd=str(fm.get("delegated_cmd") or "").strip(),
        token_file=str(fm.get("token_file") or "").strip(),
        merge_token_file=str(fm.get("merge_token_file") or "").strip(),
        assignee=str(fm.get("assignee") or "@me").strip(),
        require_labels=req_labels,
        skip_labels=skip_labels,
        priority_labels=prio_labels,
        extra=dict(fm.get("extra") or {}),
        prompt_body=body_text,
        policy_version=policy_version,
        source_path=str(path),
    )


def resolve_cross_family_referee(writer_family: str) -> str:
    mapping = POLICY_MANIFEST["chef_pipeline"]["cross_family_referee_map"]
    if writer_family not in mapping:
        raise AutopilotError(f"Unsupported writer_family: {writer_family!r}")
    referee = str(mapping[writer_family])
    if referee == writer_family:
        raise AutopilotError("Referee family MUST differ from writer family")
    return referee


def extract_json_object(raw_text: str) -> dict[str, Any]:
    stripped = raw_text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        obj = json.loads(stripped)
        if isinstance(obj, dict):
            return obj
    # Look for ```json ... ``` fenced block from the end
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, flags=re.DOTALL)
    for block in reversed(fenced):
        try:
            obj = json.loads(block)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    # Fallback: last balanced brace object
    last_brace = raw_text.rfind("}")
    first_brace = raw_text.find("{")
    if 0 <= first_brace < last_brace:
        obj = json.loads(raw_text[first_brace : last_brace + 1])
        if isinstance(obj, dict):
            return obj
    raise AutopilotError("No valid JSON object found in model output")


def validate_scout_output(data: dict[str, Any]) -> dict[str, Any]:
    req = POLICY_MANIFEST["chef_pipeline"]["required_fill_in_schemas"]["scout"]
    missing = [k for k in req if k not in data]
    if missing:
        raise AutopilotError(f"Scout output missing required fill-in fields: {missing}")
    if not str(data["dod_check"]).strip():
        raise AutopilotError("Scout dod_check must be a non-empty executable verification command")
    if not isinstance(data["exemplar_files"], list) or not isinstance(data["uncertainties"], list):
        raise AutopilotError("Scout exemplar_files and uncertainties must be lists")
    if not isinstance(data["ui_verify_needed"], bool):
        raise AutopilotError("Scout ui_verify_needed must be boolean")
    return data


def validate_writer_output(data: dict[str, Any]) -> dict[str, Any]:
    req = POLICY_MANIFEST["chef_pipeline"]["required_fill_in_schemas"]["writer"]
    missing = [k for k in req if k not in data]
    if missing:
        raise AutopilotError(f"Writer output missing required fill-in fields: {missing}")
    summary = str(data["summary_le_300_chars"]).strip()
    if not summary or len(summary) > 300:
        raise AutopilotError(f"Writer summary_le_300_chars must be 1..300 chars (got {len(summary)})")
    if not isinstance(data["changed_files"], list) or not isinstance(data["executed_checks"], list) or not isinstance(data["uncertainties"], list):
        raise AutopilotError("Writer changed_files, executed_checks, and uncertainties must be lists")
    return data


def validate_referee_output(data: dict[str, Any], *, expected_round: int | None = None) -> dict[str, Any]:
    req = POLICY_MANIFEST["chef_pipeline"]["required_fill_in_schemas"]["referee"]
    missing = [k for k in req if k not in data]
    if missing:
        raise AutopilotError(f"Referee output missing required fill-in fields: {missing}")
    verdict = str(data["verdict"]).strip()
    if verdict not in ("APPROVE", "REVISE"):
        raise AutopilotError(f"Referee verdict must be APPROVE or REVISE, got {verdict!r}")
    defects = data["three_col_defects"]
    if not isinstance(defects, list) or not isinstance(data["uncertainties"], list):
        raise AutopilotError("Referee three_col_defects and uncertainties must be lists")
    defect_count = int(data["defect_count"])
    if defect_count != len(defects):
        raise AutopilotError(f"Referee defect_count={defect_count} != len(three_col_defects)={len(defects)}")
    for idx, row in enumerate(defects):
        if not isinstance(row, dict) or not all(str(row.get(col) or "").strip() for col in ("location", "failure_case", "minimal_fix")):
            raise AutopilotError(f"Referee defect #{idx} must contain non-empty 3-column keys: location, failure_case, minimal_fix")
    if verdict == "APPROVE" and defect_count != 0:
        raise AutopilotError("Referee cannot APPROVE when defect_count > 0")
    if verdict == "REVISE" and defect_count == 0:
        raise AutopilotError("Referee REVISE must report >= 1 concrete 3-column defect")
    if expected_round is not None and int(data["round_index"]) != expected_round:
        raise AutopilotError(f"Referee round_index={data['round_index']} != expected_round={expected_round}")
    return data
