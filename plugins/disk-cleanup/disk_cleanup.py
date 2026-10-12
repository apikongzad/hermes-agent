"""disk_cleanup — ephemeral file cleanup library behind the disk-cleanup plugin.

Rules: test files delete at task end (age >= 0); temp after 7 days; cron-output
after 14 days; empty dirs under HERMES_HOME always. Prompt-only: research
(keep 10 newest, > 30 days), chrome-profile > 14 days, any file > 500 MB.
Scope: strictly HERMES_HOME and /tmp/hermes-*; never ~/.hermes/logs/ or system dirs.
"""

from __future__ import annotations

import contextlib
import functools
import json
import logging
import shutil
from datetime import datetime, timezone, UTC
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from hermes_constants import get_hermes_home

logger = logging.getLogger(__name__)

_LARGE_FILE_BYTES = 500 * 1024 * 1024


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
    tmp = Path(tmp_str)
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
    """Register a file for tracking. Returns True if newly tracked."""
    if category not in ALLOWED_CATEGORIES:
        _log(f"WARN: unknown category '{category}', using 'other'")
        category = "other"

    try:
        path = Path(path_str).resolve()
    except (OSError, RuntimeError):
        _log(f"REJECT: {path_str} (could not resolve path)")
        return False

    if not path.exists():
        _log(f"SKIP: {path} (does not exist)")
        return False
    if not is_safe_path(path):
        _log(f"REJECT: {path} (outside HERMES_HOME)")
        return False
    size = path.stat().st_size if path.is_file() else 0
    tracked = load_tracked()
    if any(item["path"] == str(path) for item in tracked):
        return False
    tracked.append({"path": str(path), "timestamp": datetime.now(UTC).isoformat(),
                    "category": category, "size": size})
    save_tracked(tracked)
    _log(f"TRACKED: {path} ({category}, {fmt_size(size)})")
    if not silent:
        print(f"Tracked: {path} ({category}, {fmt_size(size)})")
    return True


def forget(path_str: str) -> int:
    """Remove a path from tracking without deleting the file."""
    p = Path(path_str).resolve()
    tracked = load_tracked()
    kept = [i for i in tracked if Path(i["path"]).resolve() != p]
    removed = len(tracked) - len(kept)
    if removed:
        save_tracked(kept)
        _log(f"FORGOT: {p} ({removed} entries)")
    return removed


def _live_items(tracked: list[dict], now: datetime, *, log_stale: bool = False) -> Iterator[tuple[dict, Path, int]]:
    """Yield ``(item, path, age_days)`` for entries whose path still exists."""
    for item in tracked:
        p = Path(item["path"])
        if p.exists():
            yield item, p, (now - datetime.fromisoformat(item["timestamp"])).days
        elif log_stale:
            _log(f"STALE: {p} (removed from tracking)")


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
    for item, p, age in _live_items(load_tracked(), datetime.now(UTC)):
        cat = item["category"]
        # Stale cron-output entries and protected dirs are skipped by quick(); omit them here too.
        if (cat == "cron-output" and guess_category(p) != "cron-output") or _is_protected_dir(p):
            continue
        if _is_auto_delete(cat, age):
            auto.append(item)
        elif _prompt_group(item, age):
            prompt.append(item)
    return auto, prompt


def quick() -> dict[str, Any]:
    """Safe deterministic cleanup — no prompts. Returns ``{deleted, empty_dirs, freed, errors}``."""
    deleted = freed = 0
    new_tracked: list[dict] = []
    errors: list[str] = []
    for item, p, age in _live_items(load_tracked(), datetime.now(UTC), log_stale=True):
        cat = item["category"]
        if cat in _STALE_SKIP_NOTE and (re_cat := guess_category(p)) != cat:
            # Misclassified stale entry — drop it rather than delete the file.
            _log(f"SKIP stale {cat} entry: {p} (re-classified as {re_cat!r}{_STALE_SKIP_NOTE[cat]})")
            continue
        # Hard safety net even if re-validation above somehow let it through.
        if _is_protected_cron_path(p):
            _log(f"SKIP protected cron path: {p}")
            continue
        if _is_protected_dir(p):
            _log(f"SKIPPED: {p} (protected top-level dir)")
            continue
        if not _is_auto_delete(cat, age):
            new_tracked.append(item)
            continue
        err = _delete_item(item)
        if err is None:
            freed += item["size"]
            deleted += 1
        else:
            errors.append(err)
            new_tracked.append(item)
    empty_removed = _sweep_empty_dirs(get_hermes_home())
    save_tracked(new_tracked)
    _log(f"QUICK_SUMMARY: {deleted} files, {empty_removed} dirs, {fmt_size(freed)}")
    return {"deleted": deleted, "empty_dirs": empty_removed, "freed": freed, "errors": errors}


def _subdirs(dirpath: Path, exclude: frozenset) -> list[Path]:
    try:
        return [c for c in dirpath.iterdir() if c.is_dir() and not c.is_symlink() and c.name not in exclude]
    except OSError:
        return []


def _sweep_empty_dirs(hermes_home: Path) -> int:
    """Remove empty dirs under HERMES_HOME without recursing into durable/heavy trees (a full
    rglob over a checkout+venv under HERMES_HOME can stall the gateway loop for minutes).
    Iterative post-order so parents emptied by child removal are caught."""
    removed = 0
    stack: list[tuple[Path, bool]] = [
        (top, False) for top in _subdirs(hermes_home, _EMPTY_DIR_PROTECTED_TOP_LEVEL | _EMPTY_DIR_SWEEP_PRUNE_DIRS)]
    while stack:
        dirpath, visited = stack.pop()
        if visited:
            with contextlib.suppress(OSError):
                if not any(dirpath.iterdir()):
                    dirpath.rmdir()
                    removed += 1
                    _log(f"DELETED: {dirpath} (empty dir)")
            continue
        stack.append((dirpath, True))
        stack.extend((child, False) for child in _subdirs(dirpath, _EMPTY_DIR_SWEEP_PRUNE_DIRS))
    return removed


def status() -> dict[str, Any]:
    """Return per-category breakdown and top 10 largest tracked files."""
    tracked = load_tracked()
    cats: dict[str, dict] = {}
    for item in tracked:
        c = cats.setdefault(item["category"], {"count": 0, "size": 0})
        c["count"] += 1
        c["size"] += item["size"]
    existing = sorted(((i["path"], i["size"], i["category"]) for i in tracked
                       if Path(i["path"]).exists()), key=lambda x: x[1], reverse=True)
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
    """Category label for *path*, or None if we shouldn't track it (``post_tool_call`` hook)."""
    if not is_safe_path(path):
        return None
    with contextlib.suppress(ValueError):  # not under HERMES_HOME (/tmp/hermes-*) — name rules only
        rel = path.resolve().relative_to(get_hermes_home())
        top = rel.parts[0] if rel.parts else ""
        if top in _NEVER_TRACK_TOP_LEVEL or _is_protected_dir(path):
            return None
        if top in ("cron", "cronjobs"):
            # Only the disposable ``output/`` subtree; control-plane state (jobs.json,
            # .tick.lock) must never be tracked — deleting it wipes the scheduler registry.
            return "cron-output" if len(rel.parts) >= 3 and rel.parts[1] == "output" else None
        if top == "cache":
            return "temp"
    name = path.name
    if name.startswith(_TEST_PATTERNS) or name.endswith(_TEST_SUFFIXES):
        # Git-owned trees manage their own files: never classify a test_* there as disposable,
        # so neither tracking nor quick() (which re-validates stored "test" entries through
        # this function) touches it (#115295).
        return None if _inside_git_worktree(path) else "test"
    return None
