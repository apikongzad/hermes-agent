"""disk_cleanup — ephemeral file cleanup library behind the disk-cleanup plugin.

Rules: test files delete at task end (age >= 0); temp after 7 days; cron-output
after 14 days; empty dirs under HERMES_HOME always. Prompt-only: research
(keep 10 newest, > 30 days), chrome-profile > 14 days, any file > 500 MB.
Scope: strictly HERMES_HOME and scratch hermes-*; never logs or system dirs.
"""

from __future__ import annotations

import functools
import json
import logging
import os as _os_mod
from dataclasses import dataclass
from datetime import datetime, timezone, UTC
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from hermes_constants import get_hermes_home

logger = logging.getLogger(__name__)

_LARGE_FILE_BYTES = 500 * 1024 * 1024


# ── Rev6 A-ROOTS-1: explicit allowed-roots registry of RootCapability ──
# Each entry: symbolic_root_id UNIQUE STABLE identifier, dev_ino_identity
# SEPARATE revalidation identity (never used as ID), held_dirfd open for
# whole operation. ONLY hermes_home + ONE per approved hermes temp instance.

@dataclass
class RootCapability:
    symbolic_root_id: str
    dev_ino_identity: tuple
    held_dirfd: int


def _validate_basename(name: str) -> bool:
    if not name or name in (".", ".."):
        return False
    if "\x00" in name or "/" in name:
        return False
    return True


def _validate_relative(relative: str) -> list[str] | None:
    if not relative or "\x00" in relative:
        return None
    if _os_mod.path.isabs(relative):
        return None
    parts = relative.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    for p in parts:
        if not _validate_basename(p):
            return None
    return parts


def _allowed_temp_prefixes() -> list[str]:
    """Scratch-root temp prefixes (no system-temp literal): Hermes scratch + TMPDIR-aware temp.

    Resolves via get_scratch_dir() (Hermes <home>/cache/scratch, TMPDIR-backed)
    and tempfile.gettempdir() (TMPDIR-aware). Preserves confinement: callers
    still require first component hermes-*, validated basename, no dot-dot.
    Fail-closed to the prefixes that did resolve; an unresolvable root is
    skipped after logging its traceback.
    """
    prefixes: list[str] = []
    try:
        from hermes_constants import get_scratch_dir as _get_scratch

        prefixes.append(str(_get_scratch(prune=False)).rstrip("/") + "/")
    except Exception:
        logger.debug("scratch temp root resolve failed, skipping", exc_info=True)
    try:
        import tempfile as _tf

        prefixes.append(_tf.gettempdir().rstrip("/") + "/")
    except Exception:
        logger.debug("system temp root resolve failed, skipping", exc_info=True)
    return sorted(set(prefixes), key=len, reverse=True)


def _match_temp_prefix(s: str) -> str | None:
    """Remainder after an allowed scratch-temp prefix, else None (outside)."""
    for prefix in _allowed_temp_prefixes():
        if s.startswith(prefix):
            return s[len(prefix):]
    return None


def _require_nofollow_capability() -> None:
    """Fail-closed when O_NOFOLLOW/O_DIRECTORY absent (no silent downgrade)."""
    if not hasattr(_os_mod, "O_NOFOLLOW") or not hasattr(_os_mod, "O_DIRECTORY"):
        raise OSError("refused: missing O_NOFOLLOW/O_DIRECTORY capability (fail-closed)")


def _open_single(parent_fd: int, name: str, *, is_dir: bool) -> int:
    _require_nofollow_capability()
    if not _validate_basename(name):
        raise OSError("refused-escape: invalid basename")
    flags = _os_mod.O_RDONLY | _os_mod.O_NOFOLLOW | getattr(_os_mod, "O_CLOEXEC", 0)
    if is_dir:
        flags |= _os_mod.O_DIRECTORY
    return _os_mod.open(name, flags, dir_fd=parent_fd)


def tracer_available() -> bool:
    """Real tracer (strace runnable or seccomp module). Never fake audit-hook."""
    try:
        import subprocess as _sp
        # Manual PATH search (no helper imports on slice).

        def _which(name: str) -> str | None:
            for d in _os_mod.environ.get("PATH", "").split(_os_mod.pathsep):
                if not d:
                    continue
                cand = _os_mod.path.join(d, name)
                try:
                    if _os_mod.path.isfile(cand) and _os_mod.access(cand, _os_mod.X_OK):
                        return cand
                except OSError:
                    continue
            return None

        strace = _which("strace")
        if strace:
            p = _sp.run([strace, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5, check=False)
            if p.returncode == 0:
                return True
    except Exception:
        pass
    try:
        import seccomp  # type: ignore
        return True
    except Exception:
        return False


_openat2_probe_cache: dict = {}


def openat2_supported() -> bool:
    """True when the kernel exposes a real openat2 syscall (never mocked).

    Behavioral probe: issues the real syscall with an invalid fd and
    differentiates errno — ENOSYS means the kernel has no such syscall
    (unsupported); EBADF/EINVAL/ENOENT/EACCES/EPERM/ENOTDIR mean the kernel
    accepted and dispatched it (supported). Numbers: Linux x86_64=437,
    ARM64/aarch64=437, i386=382 (437 verified on actual aarch64 kernel via
    EBADF, not ENOSYS).
    """
    if "v" in _openat2_probe_cache:
        return bool(_openat2_probe_cache["v"])
    try:
        import ctypes as _ct
        import ctypes.util as _ctu
        libname = _ctu.find_library("c")
        if not libname:
            _openat2_probe_cache["v"] = False
            return False
        libc = _ct.CDLL(libname, use_errno=True)
        # openat2 syscall numbers: x86_64=437, arm64/aarch64=437, i386=382
        import platform as _pf
        mach = _pf.machine().lower()
        if mach in ("x86_64", "aarch64", "arm64"):
            nr = 437
        elif mach in ("i386", "i686"):
            nr = 382
        else:
            nr = 437
        # Probe with invalid fd: ENOSYS means unsupported, any dispatched
        # error (EBADF/EINVAL/...) means present.
        class _How(_ct.Structure):
            _fields_ = [("flags", _ct.c_uint64), ("mode", _ct.c_uint64), ("resolve", _ct.c_uint64)]
        how = _How(0, 0, 0)
        libc.syscall.argtypes = [_ct.c_long, _ct.c_int, _ct.c_char_p, _ct.POINTER(_How), _ct.c_size_t]
        libc.syscall.restype = _ct.c_long
        _ct.set_errno(0)
        ret = libc.syscall(nr, -1, b".", _ct.byref(how), _ct.sizeof(how))
        err = _ct.get_errno()
        import errno as _en
        if ret == -1 and err == _en.ENOSYS:
            _openat2_probe_cache["v"] = False
            return False
        if ret == -1 and err in (
            _en.EBADF, _en.EINVAL, _en.ENOENT, _en.EACCES,
            _en.EPERM, getattr(_en, "ENOTDIR", 20),
        ):
            _openat2_probe_cache["v"] = True
            return True
        # Any other dispatched outcome (including ret==0, unexpected errno)
        # still proves the syscall exists; only ENOSYS proves absence.
        if ret == -1 and err == _en.ENOSYS:
            _openat2_probe_cache["v"] = False
            return False
        _openat2_probe_cache["v"] = True
        return True
    except Exception:
        _openat2_probe_cache["v"] = False
        return False


def _open_bootstrap_root() -> int:
    _require_nofollow_capability()
    return _os_mod.open("/", _os_mod.O_RDONLY | _os_mod.O_DIRECTORY
                        | _os_mod.O_NOFOLLOW | getattr(_os_mod, "O_CLOEXEC", 0))


def _walk_to_home(bfd: int) -> RootCapability | None:
    """Walk / -> HERMES_HOME via single validated basenames, holding parents.

    Returns RootCapability with retained held_dirfd on success, None on refuse.
    Bounded fds: all intermediates closed except retained held.
    """
    try:
        home = get_hermes_home()
    except Exception:
        return None
    home_parts: list[str] = [p for p in str(home).split("/") if p]
    if not home_parts:
        return None
    cur = bfd
    owned: list[int] = []
    try:
        for comp in home_parts:
            if not _validate_basename(comp):
                return None
            try:
                child = _open_single(cur, comp, is_dir=True)
            except OSError:
                return None
            try:
                st = _os_mod.fstat(child)
                import stat as _stat
                if not _stat.S_ISDIR(st.st_mode):
                    try:
                        _os_mod.close(child)
                    except OSError:
                        pass
                    return None
            except OSError:
                try:
                    _os_mod.close(child)
                except OSError:
                    pass
                return None
            if cur is not bfd:
                owned.append(cur)
            cur = child
        try:
            st = _os_mod.fstat(cur)
        except OSError:
            try:
                if cur is not bfd:
                    _os_mod.close(cur)
            except OSError:
                pass
            return None
        held = cur
        cur = bfd  # prevent close of retained below
        for fd in owned:
            try:
                _os_mod.close(fd)
            except OSError:
                pass
        return RootCapability(symbolic_root_id="hermes_home",
                              dev_ino_identity=(st.st_dev, st.st_ino),
                              held_dirfd=held)
    finally:
        # Close intermediates on failure; on success owned already closed, cur==bfd
        if cur is not bfd:
            # failure path: cur is last child not retained
            try:
                _os_mod.close(cur)
            except OSError:
                pass
            for fd in owned:
                try:
                    _os_mod.close(fd)
                except OSError:
                    pass


def bootstrap_roots() -> dict[str, RootCapability]:
    """Open / once to locate ONLY hermes_home into registry, then close bootstrap.

    Lazy temp: NEVER enumerates scratch hermes-* (unbounded FD census exceeds
    RLIMIT). Temp instances bind lazily via bind_temp_basename() for the
    specifically requested allowed basename only, with bounded fds close.
    """
    registry: dict[str, RootCapability] = {}
    try:
        bfd = _open_bootstrap_root()
    except OSError:
        return registry
    try:
        cap = _walk_to_home(bfd)
        if cap is not None:
            registry["hermes_home"] = cap
    finally:
        try:
            _os_mod.close(bfd)
        except OSError:
            pass
    return registry


def open_roots_registry() -> dict[str, RootCapability]:
    return bootstrap_roots()


def bind_temp_basename(basename: str) -> dict:
    """Lazily bind ONE specifically requested allowed temp basename.

    Validates hermes- prefix + basename, walks / -> tmp -> basename via single
    nofollow steps, rejects symlink ancestor (ELOOP), fail-closed when
    O_NOFOLLOW missing. Bounded fds: at most 3 held during walk, all but
    retained held closed. Caller must close via close_capability().
    """
    if not isinstance(basename, str) or not basename.startswith("hermes-"):
        return {"refused": True, "reason": "refused-escape"}
    if not _validate_basename(basename):
        return {"refused": True, "reason": "refused-escape"}
    try:
        bfd = _open_bootstrap_root()
    except OSError as exc:
        import errno as _en0
        if exc.errno == getattr(_en0, "ELOOP", 40):
            return {"refused": True, "reason": "refused-symlink"}
        return {"refused": True, "reason": "refused-io"}
    tfd = None
    child = None
    try:
        try:
            tfd = _open_single(bfd, "tmp", is_dir=True)
        except OSError as exc:
            import errno as _en1
            if exc.errno == _en1.ELOOP:
                return {"refused": True, "reason": "refused-symlink"}
            return {"refused": True, "reason": "refused-io"}
        try:
            child = _open_single(tfd, basename, is_dir=True)
        except OSError as exc:
            import errno as _en2
            if exc.errno == _en2.ELOOP:
                return {"refused": True, "reason": "refused-symlink"}
            return {"refused": True, "reason": "refused-escape"}
        try:
            st = _os_mod.fstat(child)
            import stat as _stb
            if not _stb.S_ISDIR(st.st_mode):
                return {"refused": True, "reason": "refused-escape"}
        except OSError:
            return {"refused": True, "reason": "refused-io"}
        held = child
        child = None  # retained
        cap = RootCapability(symbolic_root_id=f"hermes_tmp:{basename}",
                             dev_ino_identity=(st.st_dev, st.st_ino),
                             held_dirfd=held)
        return {"ok": True, "symbolic_root_id": cap.symbolic_root_id,
                "relative": "", "capability": cap}
    finally:
        if child is not None:
            try:
                _os_mod.close(child)
            except OSError:
                pass
        if tfd is not None:
            try:
                _os_mod.close(tfd)
            except OSError:
                pass
        try:
            _os_mod.close(bfd)
        except OSError:
            pass


def close_capability(cap) -> None:
    """Bounded close of a lazily bound capability's held fd."""
    try:
        fd = cap.held_dirfd if hasattr(cap, "held_dirfd") else cap.get("capability").held_dirfd
        _os_mod.close(fd)
    except Exception:
        try:
            _os_mod.close(cap["capability"].held_dirfd)
        except Exception:
            pass


def _real_openat2_bind(held_fd: int, parts: list[str], *, is_dir_last: bool = False) -> dict:
    """Real openat2 in one kernel-checked step from selected held fd.

    Uses RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS (+NO_XDEV where supported).
    Returns ok/refused; raises OSError(ENOSYS) as openat2-unsupported when
    the syscall is absent (explicit refusal, never mock walk).
    """
    import ctypes as _ct
    import ctypes.util as _ctu
    import errno as _en
    import platform as _pf
    libname = _ctu.find_library("c")
    if not libname:
        raise OSError(_en.ENOSYS, "openat2 unsupported (no libc)")
    libc = _ct.CDLL(libname, use_errno=True)
    mach = _pf.machine().lower()
    nr = 437 if mach in ("x86_64", "aarch64", "arm64", "") else (382 if mach in ("i386", "i686") else 437)
    RESOLVE_BENEATH = 0x08
    RESOLVE_NO_SYMLINKS = 0x04
    RESOLVE_NO_XDEV = 0x02
    O_RDONLY = _os_mod.O_RDONLY
    O_NOFOLLOW = getattr(_os_mod, "O_NOFOLLOW", 0)
    O_CLOEXEC = getattr(_os_mod, "O_CLOEXEC", 0)

    class _How(_ct.Structure):
        _fields_ = [("flags", _ct.c_uint64), ("mode", _ct.c_uint64), ("resolve", _ct.c_uint64)]
    rel = "/".join(parts)
    if not rel:
        raise OSError(_en.ENOENT, "empty relative")
    flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    # Last component may be file; intermediate must be dirs (kernel checks via BENEATH+NO_SYMLINKS)
    resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS
    try:
        resolve |= RESOLVE_NO_XDEV
    except Exception:
        pass
    how = _How(flags, 0, resolve)
    libc.syscall.argtypes = [_ct.c_long, _ct.c_int, _ct.c_char_p, _ct.POINTER(_How), _ct.c_size_t]
    libc.syscall.restype = _ct.c_long
    fd = libc.syscall(nr, held_fd, rel.encode("utf-8"), _ct.byref(how), _ct.sizeof(how))
    if fd < 0:
        err = _ct.get_errno()
        if err == _en.ENOSYS:
            raise OSError(err, "openat2 unsupported")
        if err == _en.ELOOP:
            return {"refused": True, "reason": "refused-symlink"}
        if err in (_en.EXDEV,):
            return {"refused": True, "reason": "refused-escape"}
        return {"refused": True, "reason": "refused-escape"}
    try:
        _os_mod.close(fd)
    except OSError:
        pass
    return {"ok": True}


def bind_candidate(candidate: dict, *, via: str = "walk", anchor_fd=None) -> dict:
    """ONE bind policy for walk AND openat2 from SAME cap fd (A-BIND-1).

    candidate carries ONLY {symbolic_root_id, relative}. Unknown ID -> refuse.
    Both paths start from SELECTED entry held_dirfd, NEVER from /. openat2
    from / or non-retained fd raises. via=openat2 uses REAL openat2 syscall;
    when unsupported returns explicit openat2-unsupported refusal (never mock).
    Lazy temp: hermes_tmp:<basename> binds ONLY the requested basename.
    """
    sid = candidate.get("symbolic_root_id")
    rel = candidate.get("relative", "")
    if not isinstance(sid, str) or not isinstance(rel, str):
        return {"refused": True, "reason": "refused-escape"}
    # Lazy registry: hermes_home via bootstrap, temp via single basename bind
    entry = None
    _temp_cap = None
    _home_reg: dict = {}
    if sid == "hermes_home":
        _home_reg = bootstrap_roots()
        entry = _home_reg.get(sid)
    elif sid.startswith("hermes_tmp:"):
        base = sid.split(":", 1)[1] if ":" in sid else ""
        if not base.startswith("hermes-") or not _validate_basename(base):
            return {"refused": True, "reason": "refused-escape"}
        res = bind_temp_basename(base)
        if not res.get("ok"):
            return {"refused": True, "reason": res.get("reason", "refused-escape")}
        _temp_cap = res["capability"]
        entry = _temp_cap
    else:
        # Unknown symbolic ID without enumerating temp (lazy, bounded)
        return {"refused": True, "reason": "unknown-symbolic-id"}
    def _close_all():
        for e in _home_reg.values():
            try:
                _os_mod.close(e.held_dirfd)
            except OSError:
                pass
        if _temp_cap is not None:
            try:
                _os_mod.close(_temp_cap.held_dirfd)
            except OSError:
                pass

    if entry is None:
        _close_all()
        return {"refused": True, "reason": "unknown-symbolic-id"}
    if anchor_fd is not None:
        if anchor_fd == "/" or anchor_fd == b"/" or anchor_fd == 0:
            _close_all()
            raise ValueError("openat2 from / refused (A-BIND-1)")
        try:
            is_selected = (int(anchor_fd) == int(entry.held_dirfd))
        except Exception:
            is_selected = False
        if not is_selected:
            _close_all()
            raise ValueError("openat2 from non-selected fd refused (A-BIND-1)")
    parts = _validate_relative(rel)
    if parts is None:
        _close_all()
        return {"refused": True, "reason": "refused-escape"}
    # Re-validate selected held fd identity
    try:
        cur_st = _os_mod.fstat(entry.held_dirfd)
        if (cur_st.st_dev, cur_st.st_ino) != entry.dev_ino_identity:
            _close_all()
            return {"refused": True, "reason": "identity-mismatch"}
    except OSError:
        _close_all()
        return {"refused": True, "reason": "refused-io"}
    # via=openat2: REAL openat2 in one kernel step, same policy, never mock.
    if via == "openat2":
        try:
            if not openat2_supported():
                _close_all()
                return {"refused": True, "reason": "openat2-unsupported"}
            # Same per-basename validation already done; kernel enforces BENEATH+NO_SYMLINKS
            res = _real_openat2_bind(entry.held_dirfd, parts)
            if res.get("ok"):
                _close_all()
                return {"ok": True, "symbolic_root_id": sid, "relative": rel, "via": "openat2"}
            _close_all()
            return res
        except OSError as exc:
            import errno as _enO
            if exc.errno == _enO.ENOSYS:
                _close_all()
                return {"refused": True, "reason": "openat2-unsupported"}
            _close_all()
            return {"refused": True, "reason": "refused-escape"}
        except Exception:
            _close_all()
            return {"refused": True, "reason": "refused-io"}
    # via=walk: each descent step opens exactly one validated basename holding parent.
    parent = entry.held_dirfd
    walk_parent = parent
    opened_child: int | None = None
    try:
        for i, comp in enumerate(parts):
            last = (i == len(parts) - 1)
            try:
                child = _open_single(walk_parent, comp, is_dir=not last)
            except OSError as exc:
                import errno as _en
                if exc.errno == _en.ELOOP:
                    return {"refused": True, "reason": "refused-symlink"}
                return {"refused": True, "reason": "refused-escape"}
            try:
                cst = _os_mod.fstat(child)
                import stat as _st3
                if not last and not _st3.S_ISDIR(cst.st_mode):
                    try:
                        _os_mod.close(child)
                    except OSError:
                        pass
                    return {"refused": True, "reason": "refused-escape"}
            except OSError:
                try:
                    _os_mod.close(child)
                except OSError:
                    pass
                return {"refused": True, "reason": "refused-io"}
            if walk_parent is not parent:
                try:
                    _os_mod.close(walk_parent)
                except OSError:
                    pass
            walk_parent = child
            opened_child = child
        return {"ok": True, "symbolic_root_id": sid, "relative": rel, "via": "walk"}
    finally:
        if opened_child is not None and walk_parent is not parent:
            try:
                _os_mod.close(walk_parent)
            except OSError:
                pass
        _close_all()


def _state_file(name: str) -> Path:
    """Locator only (no open/stat). Bound reads use held fds, never this path."""
    return get_hermes_home() / "disk-cleanup" / name


def is_safe_path(path: Path) -> bool:
    """Anchored verdict without Path.resolve (no symlink-follow, no alias relax).

    Lexical registry check only: under HERMES_HOME or scratch hermes-* basename.
    Symlink/alias resolution happens only via held-fd bind (ELOOP refuse).
    """
    try:
        s = str(path)
        if not s or "\x00" in s:
            return False
        try:
            home_s = str(get_hermes_home())
        except Exception:
            return False
        if s == home_s or s.startswith(home_s.rstrip("/") + "/"):
            # Reject .. lexically; symlink check deferred to held-fd bind
            rel = s[len(home_s.rstrip("/")) + 1:] if s != home_s else ""
            if rel == "":
                return True
            if ".." in rel.split("/") or "" in rel.split("/"):
                return False
            return True
        rest = _match_temp_prefix(s)
        if rest is not None:
            first = rest.split("/", 1)[0] if rest else ""
            if not first.startswith("hermes-"):
                return False
            if not _validate_basename(first):
                return False
            # Reject .. and empty components lexically
            if ".." in rest.split("/"):
                return False
            return True
        return False
    except Exception:
        return False


def _log(message: str) -> None:
    """Report-only slice: refuse log writes (no dir creation, no open, no write).

    Diagnostics are in-memory return values only. Direct calls refuse.
    """
    raise RuntimeError(f"refused: report-only slice, no log writes (A-NOIMPLICIT-1): {message}")


def _is_link_no_follow(p: Path) -> bool:
    """True when *p* itself is a symlink (lstat, never follows)."""
    try:
        return p.is_symlink()
    except OSError:
        return False


def _strict_fsync_dir(dir_path: Path) -> None:
    """Report-only slice: no dir sync authority (no open, no sync calls)."""
    raise RuntimeError("refused: report-only slice, no sync authority (A-NONE-1)")


def _read_bytes_no_follow(p: Path) -> bytes:
    """Report-only slice: no pathname reads (use held-fd bound reads)."""
    raise RuntimeError("refused: report-only slice, use bound reads (A-BIND-1)")


def _atomic_bytes_no_follow(target: Path, data: bytes, *, mode: int | None) -> None:
    """Report-only slice: no write authority (no temp staging, no replace, no sync)."""
    raise RuntimeError("refused: report-only slice, no write authority (A-NONE-1)")


def _mode_of_regular_file(p: Path) -> int | None:
    """Report-only slice: metadata never authority, no stat on state paths."""
    return None


def _default_new_mode() -> int | None:
    """Report-only slice: no mode sampling (never gates writes)."""
    return None


def load_tracked() -> list[dict[str, Any]]:
    """Report-only slice: bound-read-or-refuse, no dir creation, no backup, no log writes.

    Delegates to _bound_read_tracked (held-fd, nofollow). Symlink/XDEV/
    identity surprise -> empty with refused/corrupt signalled via bound read.
    """
    items, _refused, _corrupt = _bound_read_tracked()
    return items


def save_tracked(tracked: list[dict[str, Any]]) -> None:
    """Report-only slice: refuse durable writes (no dir creation, no staging, no sync)."""
    raise RuntimeError("refused: report-only slice, no state writes (A-E4/A-NONE-1)")


ALLOWED_CATEGORIES = {
    "temp", "test", "research", "download", "chrome-profile", "cron-output", "other"}

# Top-level HERMES_HOME dirs whose empty subdirs are never swept (last row: user project trees).
_EMPTY_DIR_PROTECTED_TOP_LEVEL = frozenset({
    "logs", "memories", "sessions", "cron", "cronjobs",
    "cache", "skills", "plugins", "disk-cleanup", "optional-skills",
    "hermes-agent", "backups", "profiles", ".worktrees",
    "patches", "projects", "skins", "themes", "contributors",
    # Per-profile user trees bootstrapped by ``profiles.py::_PROFILE_DIRS`` (#112859).
    "workspace", "plans", "home",
    # Kanban owns its own lifecycle (workspaces GC'd at terminal state, attachments live with the task).
    "kanban"})

_EMPTY_DIR_SWEEP_PRUNE_DIRS = frozenset({
    ".git", "node_modules", "venv", ".venv", "site-packages", "__pycache__"})

# Top-level HERMES_HOME entries guess_category() never auto-tracks: state, logs, memory,
# sessions, config/secrets, and user project trees (test_* inside projects/ is not disposable).
_NEVER_TRACK_TOP_LEVEL = frozenset({
    "disk-cleanup", "logs", "memories", "sessions", "config.yaml",
    "skills", "plugins", ".env", "USER.md", "MEMORY.md", "SOUL.md",
    "auth.json", "hermes-agent",
    # User-authored project trees — never sweep empty directories inside these (#75403).
    # User-authored and project trees — never auto-delete files inside these just because they happen to be
    # named test_* or tmp_* (#75403, also #32164, #37721). ``workspace``, ``plans`` and ``home`` are the
    # per-profile user trees bootstrapped by ``profiles.py::_PROFILE_DIRS`` (#112859).
    "patches", "projects", "skins", "themes", "contributors",
    "profiles", "backups", "optional-skills", "workspace", "plans", "home",
    # Kanban task attachments/workspaces have their own lifecycle; test_* staging files there are
    # not disposable (#114552).
    "kanban"})


def _is_protected_dir(p: Path) -> bool:
    """Lexical protected-top check (no resolve/stat on state paths)."""
    try:
        s = str(p)
        home_s = str(get_hermes_home())
        if s == home_s:
            return True
        if s.startswith(home_s.rstrip("/") + "/"):
            rel = s[len(home_s.rstrip("/")) + 1:]
            top = rel.split("/")[0] if rel else ""
            return top in _EMPTY_DIR_PROTECTED_TOP_LEVEL
        return False
    except Exception:
        return False

@functools.lru_cache(maxsize=8)  # keyed by home: a multiplexed process serves several profiles
def _protected_cron_paths(home: Path) -> frozenset:
    """Defense-in-depth for quick(): EXACT cron control-plane paths (``cron/``, ``output/`` root,
    ``jobs.json``, ``.tick.lock``) never deleted regardless of stored category (stale tracked.json).
    Never widen to everything under ``cron/output/``: run artifacts there are disposable; only
    wholesale deletion of ``output/`` is fatal."""
    return frozenset(str(x) for parent in ("cron", "cronjobs") for base in (home / parent,)
                     for x in (base, base / "output", base / "jobs.json", base / ".tick.lock"))


# Paths under $HERMES_HOME that must NEVER be deleted by quick(), regardless of what the stored category
# says. Lexical only (no resolve on state paths); bound bind refuses escapes.
def _is_protected_cron_path(p: Path) -> bool:
    try:
        s = str(p)
        home_s = str(get_hermes_home())
        if s == home_s or s.startswith(home_s.rstrip("/") + "/"):
            rel = s[len(home_s.rstrip("/")) + 1:] if s != home_s else ""
            parts = rel.split("/") if rel else []
            if len(parts) >= 1 and parts[0] in ("cron", "cronjobs"):
                if len(parts) == 1 or (len(parts) == 2 and parts[1] in ("output", "jobs.json", ".tick.lock")):
                    return True
        return False
    except Exception:
        return False


def fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def track(path_str: str, category: str, silent: bool = False) -> bool:
    """Rev6 initial slice: refuse-or-report-only verdict, zero writes (A-E6).

    Validates name per anchored policy, returns verdict, performs no state
    change and emits only in-memory verdict. No durable write occurs here.
    """
    if category not in ALLOWED_CATEGORIES:
        category = "other"
    # Lexical validation only (no multi-component open, no symlink follow).
    if not isinstance(path_str, str) or not path_str or "\x00" in path_str:
        return False
    if _os_mod.path.isabs(path_str):
        # Map absolute to registry-relative lexically for verdict only.
        try:
            home_s = str(get_hermes_home())
            if path_str == home_s or path_str.startswith(home_s.rstrip("/") + "/"):
                rel = path_str[len(home_s.rstrip("/")) + 1:] if path_str != home_s else ""
                if rel == "" or ".." in rel.split("/"):
                    return False
            else:
                rest = _match_temp_prefix(path_str)
                if rest is None:
                    return False
                first = rest.split("/", 1)[0] if rest else ""
                if not first.startswith("hermes-"):
                    return False
        except Exception:
            return False
    else:
        if ".." in path_str.split("/"):
            return False
    # Lexical verdict only: no Path.exists/is_symlink on state paths (anchor
    # split banned). Existence is proven only via held-fd bind by the caller;
    # here we return True for lexically valid registry names (report-only).
    # Symlink itself is refused at bind (ELOOP), not via pathname lstat split.
    if path_str.endswith("/") or "/../" in path_str or path_str in (".", ".."):
        return False
    return True


def forget(path_str: str) -> int:
    """Rev6 initial slice: verdict only, zero writes (A-E7). Lexical only."""
    if not isinstance(path_str, str) or not path_str or "\x00" in path_str:
        return 0
    if ".." in path_str.split("/"):
        return 0
    # Report-only keeps durable state untouched; no pathname stat split.
    return 0


def _live_items(tracked: list[dict], now: datetime, *, log_stale: bool = False) -> Iterator[tuple[dict, Path, int]]:
    """Report-only slice: no pathname exists checks (use bound reads only).

    Kept for shape compat; yields nothing without held-fd bind. Callers use
    _bound_read_tracked + in-memory age, never Path.exists on state paths.
    """
    # Refuse to enumerate via pathname: return empty (report-only, no authority).
    # Real enumeration happens in quick()/dry_run() via _bound_read_tracked.
    return
    yield  # pragma: no cover - generator shape


def _is_auto_delete(cat: str, age: int) -> bool:
    return cat == "test" or (cat == "temp" and age > 7) or (cat == "cron-output" and age > 14)


def _prompt_group(item: dict, age: int) -> Optional[str]:
    """Prompt-only bucket: ``research`` / ``chrome`` / ``large`` or None."""
    cat = item["category"]
    if cat == "research" and age > 30:
        return "research"
    if cat == "chrome-profile" and age > 14:
        return "chrome"
    return "large" if item["size"] > _LARGE_FILE_BYTES else None


def _delete_item(item: dict) -> Optional[str]:
    """Report-only slice: refuse deletion (no removal, no log writes)."""
    raise RuntimeError("refused: report-only slice, no deletion authority (A-E2/A-NONE-1)")


# Stored categories re-validated against guess_category() before use: old tracked.json entries
# may carry "cron-output" for control-plane files or "test" for files under protected trees.
_STALE_SKIP_NOTE = {"cron-output": "", "test": " — under protected tree"}


def dry_run() -> tuple[list[dict], list[dict]]:
    """Return (auto_delete_list, needs_prompt_list) without touching files."""
    auto, prompt = [], []
    tracked, _refused, _corrupt = _bound_read_tracked()
    now = datetime.now(UTC)
    for item in tracked:
        try:
            cat = str(item.get("category", "other"))
            try:
                age = (now - datetime.fromisoformat(str(item.get("timestamp", now.isoformat())))).days
            except Exception:
                age = 0
            if _is_auto_delete(cat, age):
                auto.append(item)
            elif _prompt_group(item, age):
                prompt.append(item)
        except Exception:
            continue
    return auto, prompt


def _bound_read_tracked() -> tuple[list[dict], list[dict], bool]:
    """Bound-read-or-refuse single-file read of tracked state (A-ROOTS/BIND/JSON).

    Returns (items, refused, corrupt_flag). No directory creation, no backup
    authority, diagnostics are return values only. Symlink/XDEV/identity
    surprise -> refuse before any read.
    """
    refused: list[dict] = []
    try:
        registry = bootstrap_roots()
    except Exception:
        return [], [{"reason": "durable-state-unknown"}], True
    entry = registry.get("hermes_home")
    if entry is None:
        for e in registry.values():
            try:
                _os_mod.close(e.held_dirfd)
            except OSError:
                pass
        return [], [{"reason": "durable-state-unknown"}], True
    # Re-validate held fd identity
    try:
        st = _os_mod.fstat(entry.held_dirfd)
        if (st.st_dev, st.st_ino) != entry.dev_ino_identity:
            for e in registry.values():
                try:
                    _os_mod.close(e.held_dirfd)
                except OSError:
                    pass
            return [], [{"reason": "identity-mismatch"}], True
    except OSError:
        for e in registry.values():
            try:
                _os_mod.close(e.held_dirfd)
            except OSError:
                pass
        return [], [{"reason": "durable-state-unknown"}], True
    # Open disk-cleanup dir then tracked.json via single-basename steps
    data: list[dict] = []
    corrupt = False
    dir_fd = None
    file_fd = None
    try:
        try:
            dir_fd = _open_single(entry.held_dirfd, "disk-cleanup", is_dir=True)
        except OSError as exc:
            import errno as _en2
            if exc.errno == _en2.ELOOP:
                refused.append({"reason": "refused-symlink"})
            elif exc.errno == _en2.ENOENT:
                pass
            else:
                refused.append({"reason": "refused-io"})
            return [], refused, False
        try:
            dst = _os_mod.fstat(dir_fd)
            import stat as _st4
            if not _st4.S_ISDIR(dst.st_mode):
                refused.append({"reason": "refused-escape"})
                return [], refused, False
        except OSError:
            refused.append({"reason": "refused-io"})
            return [], refused, False
        try:
            _require_nofollow_capability()
            file_fd = _os_mod.open("tracked.json",
                                   _os_mod.O_RDONLY | _os_mod.O_NOFOLLOW
                                   | getattr(_os_mod, "O_CLOEXEC", 0),
                                   dir_fd=dir_fd)
        except OSError as exc:
            import errno as _en3
            if exc.errno == _en3.ELOOP:
                refused.append({"reason": "refused-symlink"})
            elif exc.errno == _en3.ENOENT:
                pass
            else:
                refused.append({"reason": "refused-io"})
            return [], refused, False
        chunks: list[bytes] = []
        while True:
            try:
                ch = _os_mod.read(file_fd, 65536)
            except OSError:
                refused.append({"reason": "refused-io"})
                return [], refused, False
            if not ch:
                break
            chunks.append(ch)
        raw = b"".join(chunks)
        try:
            parsed = json.loads(raw.decode("utf-8-sig"))
        except Exception:
            return [], refused, True
        if not isinstance(parsed, list):
            return [], refused, True
        for it in parsed:
            if not isinstance(it, dict) or "path" not in it:
                corrupt = True
                continue
            data.append(it)
        return data, refused, corrupt
    finally:
        if file_fd is not None:
            try:
                _os_mod.close(file_fd)
            except OSError:
                pass
        if dir_fd is not None:
            try:
                _os_mod.close(dir_fd)
            except OSError:
                pass
        for e in registry.values():
            try:
                _os_mod.close(e.held_dirfd)
            except OSError:
                pass


def quick() -> dict[str, Any]:
    """Rev6 initial slice: report-only sweep, zero writes (A-E1).

    Enumerates only via bound reads, returns in-memory report with
    touched always []. Zero calls to destructive/state paths.
    """
    tracked, refused, corrupt = _bound_read_tracked()
    candidates: list[dict] = []
    now = datetime.now(UTC)
    for item in tracked:
        try:
            # Classification via anchored names/ages/policy tables only
            # (no git spawn, no side channels).
            cat = str(item.get("category", "other"))
            try:
                age = (now - datetime.fromisoformat(str(item.get("timestamp", now.isoformat())))).days
            except Exception:
                age = 0
            # Protected tops never produce candidates (report-only, no authority)
            try:
                home_s = str(get_hermes_home())
                ps = str(item.get("path", ""))
                top = ""
                if ps == home_s or ps.startswith(home_s.rstrip("/") + "/"):
                    rest = ps[len(home_s.rstrip("/")) + 1:] if ps != home_s else ""
                    top = rest.split("/")[0] if rest else ""
                if top in _EMPTY_DIR_PROTECTED_TOP_LEVEL or top in _NEVER_TRACK_TOP_LEVEL:
                    refused.append({"path": ps, "reason": "refused-escape"})
                    continue
            except Exception:
                pass
            if _is_auto_delete(cat, age) or _prompt_group(item, age):
                candidates.append(item)
        except Exception:
            refused.append({"reason": "refused-io"})
            continue
    durable_unknown = (len(tracked) == 0 and len(refused) == 0 and corrupt) or False
    report: dict[str, Any] = {
        "candidates": candidates,
        "refused": refused,
        "corrupt": corrupt,
        "durable_state_unknown": durable_unknown,
        "touched": [],
        # Legacy shape compat (zeros, no authority)
        "deleted": 0,
        "empty_dirs": 0,
        "freed": 0,
        "errors": [],
    }
    return report


def _subdirs(dirpath: Path, exclude: frozenset) -> list[Path]:
    """Report-only slice: no Path.iterdir on state paths (use held-fd only)."""
    # Enumerate via held fd in _sweep_empty_dirs; direct Path walk refused.
    return []


def _sweep_empty_dirs(hermes_home: Path) -> int:
    """Rev6 initial slice: enumeration via held dirfd only, no deletion.

    Lists candidate empty dirs via held-fd entries only. Returns 0 always
    (report-only, no authority).
    """
    try:
        registry = bootstrap_roots()
        entry = registry.get("hermes_home")
        if entry is None:
            for e in registry.values():
                try:
                    _os_mod.close(e.held_dirfd)
                except OSError:
                    pass
            return 0
        try:
            names = _os_mod.listdir(entry.held_dirfd)
        except OSError:
            names = []
        # Lexical filter only; no per-entry probe. Protected tops + prune excluded.
        _ = [n for n in names
             if n not in _EMPTY_DIR_PROTECTED_TOP_LEVEL
             and n not in _EMPTY_DIR_SWEEP_PRUNE_DIRS
             and _validate_basename(n)]
        for e in registry.values():
            try:
                _os_mod.close(e.held_dirfd)
            except OSError:
                pass
    except Exception:
        pass
    return 0


def status() -> dict[str, Any]:
    """Return per-category breakdown and top 10 largest tracked files."""
    tracked, _refused, _corrupt = _bound_read_tracked()
    cats: dict[str, dict] = {}
    for item in tracked:
        try:
            c = cats.setdefault(str(item.get("category", "other")), {"count": 0, "size": 0})
            c["count"] += 1
            c["size"] += int(item.get("size", 0))
        except Exception:
            continue
    existing = sorted(((str(i.get("path", "")), int(i.get("size", 0)), str(i.get("category", "")))
                       for i in tracked),
                      key=lambda x: x[1], reverse=True)
    return {"categories": cats, "top10": existing[:10], "total_tracked": len(tracked)}


def format_status(s: dict[str, Any]) -> str:
    """Human-readable status string (for slash command output)."""
    lines = [f"{'Category':<20} {'Files':>6}  {'Size':>10}", "-" * 40]
    cats = s["categories"]
    for cat, d in sorted(cats.items(), key=lambda x: x[1]["size"], reverse=True):
        lines.append(f"{cat:<20} {d['count']:>6}  {fmt_size(d['size']):>10}")
    if not cats:
        lines.append("(nothing tracked yet)")
    lines += ["", "Top 10 largest tracked files:"]
    if not s["top10"]:
        lines.append("  (none)")
    for rank, (path, size, cat) in enumerate(s["top10"], 1):
        lines.append(f"  {rank:>2}. {fmt_size(size):>8}  [{cat}]  {path}")
    return "\n".join(lines)


_TEST_PATTERNS = ("test_", "tmp_")
_TEST_SUFFIXES = (".test.py", ".test.js", ".test.ts", ".test.md")


def _git_tracks(path: Path) -> bool:
    """Report-only slice: no git spawn (no subprocess, no .git/index writes)."""
    raise RuntimeError("refused: report-only slice, no git spawn (A-NOIMPLICIT-2)")


def _inside_git_worktree(path: Path) -> bool:
    """Report-only slice: no git worktree probe (no resolve/exists/spawn)."""
    raise RuntimeError("refused: report-only slice, no git probe (A-NOIMPLICIT-2)")


def guess_category(path: Path) -> Optional[str]:
    """Rev6 initial slice: name/age/policy only, no git spawn (A-NOIMPLICIT-2).

    Classification uses only anchored names and policy tables. Zero subprocess.
    """
    try:
        ps = str(path)
        if "\x00" in ps:
            return None
        # Lexical top extraction without symlink-following open.
        try:
            home_s = str(get_hermes_home())
        except Exception:
            home_s = ""
        top = ""
        rest = ""
        if home_s and (ps == home_s or ps.startswith(home_s.rstrip("/") + "/")):
            rest = ps[len(home_s.rstrip("/")) + 1:] if ps != home_s else ""
            top = rest.split("/")[0] if rest else ""
            if top in _NEVER_TRACK_TOP_LEVEL:
                return None
            if top in ("cron", "cronjobs"):
                parts = rest.split("/") if rest else []
                return "cron-output" if len(parts) >= 3 and parts[1] == "output" else None
            if top == "cache":
                # Dir itself never tracked (rest without slash); files under age as temp.
                # Lexical only, no lstat/open on state paths.
                if "/" not in rest:
                    return None
                return "temp"
            # Protected dir check lexical (no directory open here)
            if top in _EMPTY_DIR_PROTECTED_TOP_LEVEL:
                # Only files age out; dirs themselves are not classified here.
                pass
        elif _match_temp_prefix(ps) is not None:
            # Name rules only for scratch temp instances outside home.
            pass
        else:
            # Outside registry lexically: still apply name rules for verdict,
            # bind step will refuse outside-registry temp.
            if home_s and not ps.startswith(home_s.rstrip("/") + "/"):
                # Project trees and outside temp are refused at bind; for
                # classification return None to avoid candidate creation.
                # Lexical project check:
                for proj in ("projects/", "workspace/", "plans/", "home/", "/mnt/"):
                    if proj in ps:
                        return None
        name = path.name
        if name.startswith(_TEST_PATTERNS) or name.endswith(_TEST_SUFFIXES):
            return "test"
        return None
    except Exception:
        return None
