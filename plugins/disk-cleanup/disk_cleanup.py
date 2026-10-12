"""disk_cleanup — ephemeral file cleanup library behind the disk-cleanup plugin.

Rules: test files delete at task end (age >= 0); temp after 7 days; cron-output
after 14 days; empty dirs under HERMES_HOME always. Prompt-only: research
(keep 10 newest, > 30 days), chrome-profile > 14 days, any file > 500 MB.
Scope: strictly HERMES_HOME and /tmp/hermes-*; never ~/.hermes/logs/ or system dirs.
"""

from __future__ import annotations

import contextlib
import errno as _errno_mod
import functools
import json
import logging
import os as _os_mod
import shutil
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


def _open_single(parent_fd: int, name: str, *, is_dir: bool) -> int:
    flags = _os_mod.O_RDONLY | getattr(_os_mod, "O_NOFOLLOW", 0) | getattr(_os_mod, "O_CLOEXEC", 0)
    if is_dir:
        flags |= getattr(_os_mod, "O_DIRECTORY", 0)
    return _os_mod.open(name, flags, dir_fd=parent_fd)


def bootstrap_roots() -> dict[str, RootCapability]:
    """Open / once to locate explicit roots into registry, then close bootstrap.

    A-ROOTS-2: walk ONLY single validated basenames from / toward EACH explicit
    allowed root, validate each step nofollow, retain held_dirfd, re-validate
    fstat(held) == identity on later bind, close / fd after registration.
    """
    registry: dict[str, RootCapability] = {}
    bfd = _os_mod.open("/", _os_mod.O_RDONLY | getattr(_os_mod, "O_DIRECTORY", 0)
                        | getattr(_os_mod, "O_NOFOLLOW", 0) | getattr(_os_mod, "O_CLOEXEC", 0))
    try:
        # hermes_home
        try:
            home = get_hermes_home()
            home_parts: list[str] = [p for p in str(home).split("/") if p]
            cur = bfd
            owned_fds: list[int] = []
            ok = True
            for comp in home_parts:
                if not _validate_basename(comp):
                    ok = False
                    break
                try:
                    child = _open_single(cur, comp, is_dir=True)
                except OSError:
                    ok = False
                    break
                st = _os_mod.fstat(child)
                import stat as _stat
                if not _stat.S_ISDIR(st.st_mode):
                    _os_mod.close(child)
                    ok = False
                    break
                if cur is not bfd:
                    owned_fds.append(cur)
                cur = child
            if ok:
                st = _os_mod.fstat(cur)
                # retain held fd directly (no dup: test guard tracks open fds,
                # dup would be untracked). Do not close cur below.
                held = cur
                registry["hermes_home"] = RootCapability(
                    symbolic_root_id="hermes_home",
                    dev_ino_identity=(st.st_dev, st.st_ino),
                    held_dirfd=held)
                for fd in owned_fds:
                    try:
                        _os_mod.close(fd)
                    except OSError:
                        pass
                # cur retained as held; bfd closed in outer finally
                cur = bfd  # prevent double-close in failure path
            else:
                for fd in owned_fds:
                    try:
                        _os_mod.close(fd)
                    except OSError:
                        pass
                try:
                    if 'cur' in locals() and cur is not bfd:
                        _os_mod.close(cur)
                except OSError:
                    pass
        except Exception:
            pass
        # approved hermes temp instances: list resolved /tmp root via held fd
        try:
            tmp_names: list[str] = []
            tfd = None
            try:
                tfd = _open_single(bfd, "tmp", is_dir=True)
                try:
                    tmp_names = _os_mod.listdir(tfd)
                except OSError:
                    tmp_names = []
            except OSError:
                tmp_names = []
            for base in tmp_names:
                if not base.startswith("hermes-"):
                    continue
                if not _validate_basename(base):
                    continue
                try:
                    child = _open_single(tfd, base, is_dir=True)
                except OSError:
                    continue
                try:
                    import stat as _stat2
                    st2 = _os_mod.fstat(child)
                    if not _stat2.S_ISDIR(st2.st_mode):
                        _os_mod.close(child)
                        continue
                    # retain directly, no dup (guard-tracked)
                    held2 = child
                    sid = f"hermes_tmp:{base}"
                    registry[sid] = RootCapability(
                        symbolic_root_id=sid,
                        dev_ino_identity=(st2.st_dev, st2.st_ino),
                        held_dirfd=held2)
                    child = None  # retained, do not close in finally
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
        except Exception:
            pass
    finally:
        try:
            _os_mod.close(bfd)
        except OSError:
            pass
    return registry


def open_roots_registry() -> dict[str, RootCapability]:
    return bootstrap_roots()


def bind_candidate(candidate: dict, *, via: str = "walk", anchor_fd=None) -> dict:
    """ONE bind policy for walk AND openat2 from SAME cap fd (A-BIND-1).

    candidate carries ONLY {symbolic_root_id, relative}. Unknown ID -> refuse.
    Both paths start from SELECTED entry held_dirfd, NEVER from /. openat2
    from / or non-retained fd raises (test failure even when walk refuses).
    """
    sid = candidate.get("symbolic_root_id")
    rel = candidate.get("relative", "")
    if not isinstance(sid, str) or not isinstance(rel, str):
        return {"refused": True, "reason": "refused-escape"}
    # Disjoint anchor check: explicit anchor must be selected held fd
    registry = bootstrap_roots()
    entry = registry.get(sid)
    if entry is None:
        for e in registry.values():
            try:
                _os_mod.close(e.held_dirfd)
            except OSError:
                pass
        return {"refused": True, "reason": "unknown-symbolic-id"}
    if anchor_fd is not None:
        if anchor_fd == "/" or anchor_fd == b"/" or anchor_fd == 0:
            for e in registry.values():
                try:
                    _os_mod.close(e.held_dirfd)
                except OSError:
                    pass
            raise ValueError("openat2 from / refused (A-BIND-1)")
        try:
            is_selected = (int(anchor_fd) == int(entry.held_dirfd))
        except Exception:
            is_selected = False
        if not is_selected:
            for e in registry.values():
                try:
                    _os_mod.close(e.held_dirfd)
                except OSError:
                    pass
            raise ValueError("openat2 from non-selected fd refused (A-BIND-1)")
    parts = _validate_relative(rel)
    if parts is None:
        for e in registry.values():
            try:
                _os_mod.close(e.held_dirfd)
            except OSError:
                pass
        return {"refused": True, "reason": "refused-escape"}
    # Re-validate selected held fd identity
    try:
        cur_st = _os_mod.fstat(entry.held_dirfd)
        if (cur_st.st_dev, cur_st.st_ino) != entry.dev_ino_identity:
            for e in registry.values():
                try:
                    _os_mod.close(e.held_dirfd)
                except OSError:
                    pass
            return {"refused": True, "reason": "identity-mismatch"}
    except OSError:
        for e in registry.values():
            try:
                _os_mod.close(e.held_dirfd)
            except OSError:
                pass
        return {"refused": True, "reason": "refused-io"}
    # Walk each single basename holding parent open; ELOOP -> refuse.
    # No dup (guard-tracked fds only): retain registry fd, close only
    # intermediate children, never the registry fd during walk.
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
            # Hold-parent during open done; release previous intermediate.
            if walk_parent is not parent:
                try:
                    _os_mod.close(walk_parent)
                except OSError:
                    pass
            walk_parent = child
            opened_child = child
        # Success: bound without following symlinks
        return {"ok": True, "symbolic_root_id": sid, "relative": rel}
    finally:
        if opened_child is not None and walk_parent is not parent:
            try:
                _os_mod.close(walk_parent)
            except OSError:
                pass
        for e in registry.values():
            try:
                _os_mod.close(e.held_dirfd)
            except OSError:
                pass
    # via walk vs openat2 share identical policy (A-PAIR-1); via only selects
    # same validation path, never relaxes.


def _state_file(name: str) -> Path:
    """``$HERMES_HOME/disk-cleanup/<name>`` — deliberately outside ``$HERMES_HOME/logs/``."""
    return get_hermes_home() / "disk-cleanup" / name


def is_safe_path(path: Path) -> bool:
    """Accept only paths under HERMES_HOME or ``/tmp/hermes-*``.

    Rejects Windows mounts (``/mnt/c`` etc.) and any system directory.
    """
    hermes_home = get_hermes_home()
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError):
        return False
    try:
        resolved.relative_to(hermes_home)
        return True
    except ValueError:
        pass

    # Allow /tmp/hermes-* explicitly. Compare resolved roots rather than raw
    # path parts because macOS resolves /tmp to /private/tmp.
    try:
        # Deliberate /tmp alias detection (#98854): we resolve the POSIX root
        # itself so the same directory matches under /private/tmp.
        relative_tmp = resolved.relative_to(Path("/tmp").resolve())  # no-tmp: ok — alias detection, not a scratch path
    except (ValueError, OSError):
        return False
    return bool(relative_tmp.parts and relative_tmp.parts[0].startswith("hermes-"))


def _log(message: str) -> None:
    """Append to the audit log; never let it break the agent loop."""
    with contextlib.suppress(OSError):
        log_file = _state_file("cleanup.log")
        log_file.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")


def _is_link_no_follow(p: Path) -> bool:
    """True when *p* itself is a symlink (lstat, never follows)."""
    try:
        return p.is_symlink()
    except OSError:
        return False


def _strict_fsync_dir(dir_path: Path) -> None:
    """fsync *dir_path* with errors propagating (durability, not best-effort).

    Separated seam for injected dir-fsync tests. No suppression: a failed
    directory fsync means the just-renamed entry may not survive power loss,
    so the caller must see the error.
    """
    import os as _os

    if _os.name == "nt":
        return
    fd = _os.open(str(dir_path), _os.O_RDONLY | getattr(_os, "O_DIRECTORY", 0))
    try:
        _os.fsync(fd)
    finally:
        _os.close(fd)


def _read_bytes_no_follow(p: Path) -> bytes:
    """Read *p* without following a trailing symlink (O_NOFOLLOW).

    Raises OSError with errno ELOOP when *p* itself is a symlink at open
    time — TOCTOU-safe: a regular file swapped for a link between an
    ``is_symlink`` check and the open is still refused.
    """
    import errno as _errno
    import os as _os

    flags = _os.O_RDONLY | getattr(_os, "O_NOFOLLOW", 0)
    # O_NOFOLLOW is a no-op on platforms without it; keep the lstat guard.
    if _is_link_no_follow(p):
        raise OSError(_errno.ELOOP, f"refusing symlink: {p}")
    fd = _os.open(str(p), flags)
    try:
        chunks: list[bytes] = []
        while True:
            chunk = _os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        _os.close(fd)


def _atomic_bytes_no_follow(target: Path, data: bytes, *, mode: int | None) -> None:
    """Write *data* to *target* via unique O_EXCL temp + file fsync + os.replace.

    ``os.replace`` replaces a symlink *itself* (old ``Path.replace``
    semantics), never the symlink target — a ``tracked.json`` link pointing
    outside state stays outside-untouched and becomes a regular file. Temp
    is unique ``mkstemp`` (no ``.json.tmp`` collision), file fsync errors
    propagate, parent dir fsync is strict via :func:`_strict_fsync_dir`,
    and the temp is removed on any failure including ``BaseException``.
    """
    import os as _os
    import tempfile as _tempfile

    parent = target.parent
    fd, tmp_str = _tempfile.mkstemp(dir=str(parent), prefix=".tracked_", suffix=".tmp")
    try:
        with _os.fdopen(fd, "wb") as f:
            if mode is not None and hasattr(_os, "fchmod"):
                _os.fchmod(f.fileno(), mode)
            f.write(data)
            f.flush()
            _os.fsync(f.fileno())
        _os.replace(tmp_str, str(target))
        _strict_fsync_dir(parent)
    except BaseException:
        with contextlib.suppress(OSError):
            _os.unlink(tmp_str)
        raise


def _mode_of_regular_file(p: Path) -> int | None:
    """Permission bits of *p* when it is a regular file, else ``None``.

    Never follows a symlink for the decision: a link returns ``None`` so the
    replacement gets the default new-file mode instead of the target's.
    """
    import stat as _stat

    try:
        if _is_link_no_follow(p):
            return None
        return _stat.S_IMODE(p.stat().st_mode)
    except OSError:
        return None


def _default_new_mode() -> int | None:
    """What ``open(path, "w")`` would give a new file (``0o666 & ~umask``)."""
    import os as _os

    if _os.name != "posix":
        return None
    try:
        cur = _os.umask(0o077)
        _os.umask(cur)
    except OSError:
        return None
    return 0o666 & ~cur


def load_tracked() -> list[dict[str, Any]]:
    """Load tracked.json.  Restores from ``.bak`` on corruption.

    Symlink fail-closed: a ``tracked.json`` or ``.bak`` that is itself a
    symlink is never followed (an outside file could otherwise inject
    tracked paths that :func:`quick` would delete). Such state reads as
    empty with an audit-log line; :func:`save_tracked` replaces the link
    itself on the next write.
    """
    tf = _state_file("tracked.json")
    tf.parent.mkdir(parents=True, exist_ok=True)
    if _is_link_no_follow(tf):
        _log("WARN: tracked.json is symlink — refusing to follow, starting fresh")
        return []
    if not tf.exists():
        return []

    try:
        return json.loads(tf.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, ValueError):
        bak = tf.with_suffix(".json.bak")
        if _is_link_no_follow(bak):
            _log("WARN: tracked.json.bak is symlink — refusing to follow, starting fresh")
            return []
        if bak.exists():
            try:
                data = json.loads(bak.read_text(encoding="utf-8-sig"))
                _log("WARN: tracked.json corrupted — restored from .bak")
                return data
            except Exception:
                pass
        _log("WARN: tracked.json corrupted, no backup — starting fresh")
        return []


def save_tracked(tracked: list[dict[str, Any]]) -> None:
    """Durable symlink-safe atomic write with atomic ``.bak``.

    Local to disk-cleanup (shared ``utils.atomic_replace`` intentionally
    follows a symlink to preserve its other callers — not used here, so the
    shared helper is not weakened globally).

    - Unique ``mkstemp`` staging (O_CREAT|O_EXCL, no ``.json.tmp`` collision).
    - ``tracked.json`` write replaces a symlink *itself* via ``os.replace``
      (old ``Path.replace`` semantics); outside target never touched. A
      symlink source is never read for backup (O_NOFOLLOW / lstat guard).
    - ``.bak`` is written atomically via temp + ``os.replace`` (never
      ``shutil.copy2`` truncate-in-place, never follows a ``.bak`` link).
    - File fsync and parent dir fsync errors propagate (strict durability);
      backup failures propagate and abort before overwriting live state, so
      the original file stays untouched with no temp orphan.
    - Residual TOCTOU (parent-dir swap between ``mkdir`` and ``mkstemp``,
      mode stat vs replace) is accepted by design — closing it needs an
      O_TMPFILE / renameat2 design, not endless patching here.
    """
    tf = _state_file("tracked.json")
    tf.parent.mkdir(parents=True, exist_ok=True)
    bak = tf.with_suffix(".json.bak")
    payload = json.dumps(tracked, indent=2).encode("utf-8")

    # Backup first so a backup failure aborts before live state is touched.
    if _is_link_no_follow(tf):
        _log("WARN: tracked.json is symlink — replacing link itself, skipping backup of link target")
    elif tf.exists():
        try:
            src_bytes = _read_bytes_no_follow(tf)
        except OSError as exc:
            import errno as _errno

            if exc.errno == _errno.ELOOP:
                _log("WARN: tracked.json became symlink — replacing link itself, skipping backup")
            else:
                raise
        else:
            bak_mode = _mode_of_regular_file(tf)
            # Atomic backup: temp + fsync + replace-onto-bak (replaces a
            # .bak symlink itself, never truncates/follows its target).
            _atomic_bytes_no_follow(bak, src_bytes, mode=bak_mode)

    live_mode = _mode_of_regular_file(tf)
    if live_mode is None and not tf.exists():
        live_mode = _default_new_mode()
    _atomic_bytes_no_follow(tf, payload, mode=live_mode)


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
    """A tracked DIRECTORY that is HERMES_HOME itself or lives under a protected top-level tree
    (``cache/terminal`` holds terminal snapshots) is never rmtree'd; only its files age out."""
    if not p.is_dir():
        return False
    with contextlib.suppress(ValueError, OSError):
        rel = p.resolve().relative_to(get_hermes_home())
        return not rel.parts or rel.parts[0] in _EMPTY_DIR_PROTECTED_TOP_LEVEL
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
# says. This is a defense-in-depth guard against stale tracked.json entries from before #34840.
def _is_protected_cron_path(p: Path) -> bool:
    return str(p.resolve()) in _protected_cron_paths(get_hermes_home())


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
            elif path_str.startswith("/tmp/"):
                rest = path_str[len("/tmp/"):]
                first = rest.split("/", 1)[0] if rest else ""
                if not first.startswith("hermes-"):
                    return False
            else:
                return False
        except Exception:
            return False
    else:
        if ".." in path_str.split("/"):
            return False
    # Existence probe via single-component no-follow is done by caller anchor;
    # here verdict only, no durable change.
    try:
        p = Path(path_str)
        # Use lstat-style guard: symlink itself is refused.
        try:
            if p.is_symlink():
                return False
        except OSError:
            return False
        if not p.exists():
            return False
    except Exception:
        return False
    # Verdict True means "would track under report-only policy"; no write.
    return True


def forget(path_str: str) -> int:
    """Rev6 initial slice: verdict only, zero writes (A-E7)."""
    if not isinstance(path_str, str) or not path_str or "\x00" in path_str:
        return 0
    # Lexical validation only; no durable change.
    if ".." in path_str.split("/"):
        return 0
    try:
        p = Path(path_str)
        try:
            if p.is_symlink():
                return 0
        except OSError:
            return 0
    except Exception:
        return 0
    # Verdict: 1 would-remove under old policy, 0 not-found; no write here.
    # Report-only keeps durable state untouched.
    return 0


def _live_items(tracked: list[dict], now: datetime, *, log_stale: bool = False) -> Iterator[tuple[dict, Path, int]]:
    """Yield ``(item, path, age_days)`` for entries whose path still exists."""
    for item in tracked:
        p = Path(item["path"])
        # In-memory only: stale entries are reported via return values, never
        # via side channels. log_stale is accepted for shape compat but ignored.
        try:
            exists = p.exists()
        except OSError:
            continue
        if exists:
            try:
                age = (now - datetime.fromisoformat(item["timestamp"])).days
            except Exception:
                age = 0
            yield item, p, age
        else:
            continue


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
    """Delete a tracked file/dir and audit-log it. Returns an error string on OSError, else None."""
    p = Path(item["path"])
    try:
        if p.is_file():
            p.unlink()
        elif p.is_dir():
            shutil.rmtree(p)
    except OSError as e:
        _log(f"ERROR deleting {p}: {e}")
        return f"{p}: {e}"
    _log(f"DELETED: {p} ({item['category']}, {fmt_size(item['size'])})")
    return None


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
            file_fd = _os_mod.open("tracked.json",
                                   _os_mod.O_RDONLY | getattr(_os_mod, "O_NOFOLLOW", 0)
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
    try:
        return [c for c in dirpath.iterdir() if c.is_dir() and not c.is_symlink() and c.name not in exclude]
    except OSError:
        return []


def _sweep_empty_dirs(hermes_home: Path) -> int:
    """Rev6 initial slice: enumeration only, no deletion (A-E3 dead path).

    Lists candidate empty dirs via held reads; performs no removal.
    Returns 0 always in report-only slice.
    """
    try:
        _ = _subdirs(hermes_home, _EMPTY_DIR_PROTECTED_TOP_LEVEL | _EMPTY_DIR_SWEEP_PRUNE_DIRS)
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
    """True when the git repo enclosing *path* (at any depth) tracks it.

    Asked per candidate: ``guess_category`` only reaches this for ``test_*``/``tmp_*``
    names, so one ``ls-files --error-unmatch`` is cheap, needs no cache that could outlive
    the index (a file committed after first classification is seen immediately), and covers
    both a HERMES_HOME that IS a checkout and one nested in an enclosing repo (a ``~/.git``
    dotfiles repo tracking ``~/.hermes/scripts/test_x.py``). Unlike a bare ``.git`` probe
    above HERMES_HOME, an exact tracked check cannot make untracked scratch look Git-owned.
    ``:(literal)`` stops git globbing the name (``test_[1].py`` must not match ``test_1.py``).
    Git missing / not a repo / file untracked all mean "not tracked".
    """
    from hermes_cli.source_check import _git_ok

    return _git_ok(["-C", str(path.parent), "ls-files", "--error-unmatch", "--",
                    ":(literal)" + path.name], timeout=5)


def _inside_git_worktree(path: Path) -> bool:
    """True if *path* is Git-owned: a ``.git`` entry (a directory in a normal checkout, a
    pointer FILE in a linked worktree) exists on the directory chain below HERMES_HOME, or
    an enclosing repo (HERMES_HOME itself, or one above it) actually TRACKS the file.

    Files whose repo tracks them are Git-owned — a ``test_*`` file in a worktree is typically
    a committed regression test, not session scratch (#115295).

    Only ``.git`` entries strictly BELOW ``HERMES_HOME`` count for the parent-chain probe: a
    home kept in a dotfiles repo (``~/.git``) would otherwise make every scratch file look
    Git-owned. Git is only asked when a ``.git`` exists at or above HERMES_HOME; otherwise no
    repo can track the file and the spawn is skipped.
    """
    resolved = path.resolve()
    parents = list(resolved.parents)
    above: list[Path] = []
    with contextlib.suppress(ValueError):
        i = parents.index(get_hermes_home())
        parents, above = parents[:i], parents[i:]
    if any((parent / ".git").exists() for parent in parents):
        return True
    return any((parent / ".git").exists() for parent in above) and _git_tracks(resolved)


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
                # Dir itself never tracked; files under it age out as temp.
                try:
                    import os as _o2
                    # lstat without follow: symlink itself is not a dir candidate
                    st2 = _o2.lstat(ps)
                    import stat as _s2
                    if _s2.S_ISDIR(st2.st_mode):
                        return None
                except OSError:
                    pass
                return "temp"
            # Protected dir check lexical (no directory open here)
            if top in _EMPTY_DIR_PROTECTED_TOP_LEVEL:
                # Only files age out; dirs themselves are not classified here.
                pass
        elif ps.startswith("/tmp/"):
            # Name rules only for temp instances outside home.
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
