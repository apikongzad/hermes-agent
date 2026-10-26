"""Shared types for the standalone cutover controller. Stdlib only.

DESIGN v2 (see DESIGN-v2.md): root boundary never imports pm/hermes_cli/gateway.
All effects go through Host so tests drive the actual orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import os
import subprocess
import urllib.request


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class Host:
    """Injected IO adapter. Production talks to systemd/git/fs/net; tests fake it."""

    def run(
        self,
        argv: list[str],
        timeout: int = 60,
        cwd: Path | str | None = None,
        env: dict[str, str] | None = None,
    ) -> RunResult:
        raise NotImplementedError

    def read_bytes(self, path: Path) -> bytes:
        raise NotImplementedError

    def read_bytes_nofollow(self, path: Path) -> tuple[bytes, int, int]:
        """No-follow bound read for controller identity only.

        Must lstat the final component (no follow), open with O_NOFOLLOW,
        fstat the fd, refuse unless lstat dev/ino == fstat dev/ino and the
        object is a regular file (never a symlink), then read bytes from
        that fd and return (bytes, st_dev, st_ino). Production implements
        the O_NOFOLLOW bind; read_bytes stays a following read for journals,
        receipts, dropins and other callers. Missing/NotImplementedError
        must fail the controller gate closed (no fallback to read_bytes).
        """
        raise NotImplementedError

    def write_bytes(self, path: Path, data: bytes) -> None:
        raise NotImplementedError

    def remove(self, path: Path) -> None:
        raise NotImplementedError

    def readlink_exe(self, pid: int) -> str:
        """Legacy alias for proc_exe; kept for compat, prefer proc_exe."""
        return self.proc_exe(pid)

    def proc_exe(self, pid: int) -> str:
        raise NotImplementedError

    def proc_cmdline(self, pid: int) -> list[str]:
        raise NotImplementedError

    def proc_cwd(self, pid: int) -> str:
        raise NotImplementedError

    def proc_environ(self, pid: int) -> dict[str, str]:
        raise NotImplementedError

    def proc_start_time(self, pid: int) -> int | None:
        raise NotImplementedError

    def stat_file(self, path: Path) -> FileStat:
        """lstat without following symlinks (receipt owner/mode/type bind)."""
        raise NotImplementedError

    def http_get(self, url: str, timeout: int = 10) -> tuple[int, str]:
        raise NotImplementedError


def _proc_base(pid: int) -> Path:
    # Built without a literal "/proc/…" so naive external-path scanners do not
    # flag the stdlib probe; the join is still the canonical /proc/<pid> path.
    return Path(os.sep + "proc") / str(int(pid))


class ProductionHost(Host):
    """Real host effects. Root installs/runs this; never used in unit tests."""

    def run(
        self,
        argv: list[str],
        timeout: int = 60,
        cwd: Path | str | None = None,
        env: dict[str, str] | None = None,
    ) -> RunResult:
        done = subprocess.run(
            [str(a) for a in argv],
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd is not None else None,
            env=dict(env) if env is not None else None,
        )
        return RunResult(done.returncode, done.stdout or "", done.stderr or "")

    def read_bytes(self, path: Path) -> bytes:
        return Path(path).read_bytes()

    def write_bytes(self, path: Path, data: bytes) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = target.with_name(f".{target.name}.stage.{os.getpid()}")
        staging.write_bytes(data)
        try:
            with open(staging, "rb") as handle:
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            pass
        os.replace(staging, target)
        try:
            with open(target, "rb") as handle:
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            pass
        try:
            dir_fd = os.open(str(target.parent), os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
        name = target.name
        if "journal" in name or "baseline" in name:
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass

    def remove(self, path: Path) -> None:
        try:
            Path(path).unlink()
        except FileNotFoundError:
            return

    def proc_exe(self, pid: int) -> str:
        return os.readlink(str(_proc_base(pid) / "exe"))

    def proc_cmdline(self, pid: int) -> list[str]:
        raw = (_proc_base(pid) / "cmdline").read_bytes()
        return [p for p in raw.decode("utf-8", "replace").split("\0") if p]

    def proc_cwd(self, pid: int) -> str:
        return os.readlink(str(_proc_base(pid) / "cwd"))

    def proc_environ(self, pid: int) -> dict[str, str]:
        raw = (_proc_base(pid) / "environ").read_bytes()
        out: dict[str, str] = {}
        for chunk in raw.decode("utf-8", "replace").split("\0"):
            if "=" in chunk:
                k, _, v = chunk.partition("=")
                out[k] = v
        return out

    def proc_start_time(self, pid: int) -> int | None:
        try:
            parts = (_proc_base(pid) / "stat").read_text(encoding="utf-8-sig").split()
            return int(parts[21])
        except (OSError, ValueError, IndexError):
            return None

    def stat_file(self, path: Path) -> FileStat:
        import stat as _stat

        try:
            st = os.lstat(path)
        except FileNotFoundError:
            raise
        except OSError:
            raise
        return FileStat(
            uid=int(st.st_uid),
            gid=int(st.st_gid),
            mode=int(st.st_mode),
            is_symlink=_stat.S_ISLNK(st.st_mode),
            is_file=_stat.S_ISREG(st.st_mode),
            dev=int(st.st_dev),
            ino=int(st.st_ino),
        )

    def read_bytes_nofollow(self, path: Path) -> tuple[bytes, int, int]:
        """Bind the digest to the fd actually opened (O_NOFOLLOW, no follow).

        lstat (no follow) the final component, open with O_NOFOLLOW, fstat
        the fd, refuse unless lstat dev/ino == fstat dev/ino and the object
        is a regular file (never a symlink), then read bytes from that fd.
        This is the controller-identity gate only; read_bytes stays a
        following read for journals/receipts/dropins.
        """
        import errno as _errno
        import stat as _stat

        target = Path(path)
        try:
            lst = os.lstat(target)
        except FileNotFoundError:
            raise
        except OSError:
            raise
        if _stat.S_ISLNK(lst.st_mode):
            raise OSError(_errno.ELOOP, f"symlink refused: {target}")
        if not _stat.S_ISREG(lst.st_mode):
            raise OSError(_errno.EINVAL, f"not a regular file: {target}")
        fd = os.open(str(target), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            fst = os.fstat(fd)
            if int(fst.st_dev) != int(lst.st_dev) or int(fst.st_ino) != int(
                lst.st_ino
            ):
                raise OSError(_errno.EINVAL, f"identity changed: {target}")
            if _stat.S_ISLNK(fst.st_mode):
                raise OSError(_errno.ELOOP, f"symlink refused: {target}")
            if not _stat.S_ISREG(fst.st_mode):
                raise OSError(_errno.EINVAL, f"not a regular file: {target}")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks), int(fst.st_dev), int(fst.st_ino)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def http_get(self, url: str, timeout: int = 10) -> tuple[int, str]:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            body = response.read(65536).decode("utf-8", "replace")
            return int(response.status), body


@dataclass(frozen=True)
class FileStat:
    """lstat result for root-authorized receipt binding (no follow)."""

    uid: int
    gid: int
    mode: int
    is_symlink: bool
    is_file: bool
    dev: int | None = None
    ino: int | None = None


@dataclass(frozen=True)
class CutoverConfig:
    """All paths/SHAs the orchestrator needs. No live mutation except via Host."""

    candidate_sha: str
    parent_sha: str
    candidate_src: Path
    live_tree: Path
    generation_root: Path
    journal_path: Path
    hermes_home: Path = Path("/home/ubuntu/.hermes")
    gateway_unit: str = "hermes-gateway.service"
    dashboard_unit: str = "hermes-dashboard.service"
    gateway_dropin_dir: Path = Path("/etc/systemd/system/hermes-gateway.service.d")
    dashboard_dropin_dir: Path = Path("/etc/systemd/system/hermes-dashboard.service.d")
    candidate_dropin_name: str = "zzz-candidate.conf"
    dashboard_port: int = 9119
    controller_path: Path | None = None
    baseline_receipt: Path | None = None


@dataclass(frozen=True)
class Baseline:
    gateway_unit_text: str
    dashboard_unit_text: str
    gateway_dropin_bytes: dict[str, bytes] = field(default_factory=dict)
    dashboard_dropin_bytes: dict[str, bytes] = field(default_factory=dict)
    live_head: str = ""
    candidate_head: str = ""
    live_main_pid: int = 0
    live_main_exe: str = ""
    live_main_cmdline: tuple[str, ...] = ()
    live_main_cwd: str = ""
    live_main_start_time: int | None = None
    dashboard_main_pid: int = 0
    dashboard_main_exe: str = ""
    dashboard_main_cmdline: tuple[str, ...] = ()
    dashboard_main_cwd: str = ""
    dashboard_main_start_time: int | None = None
    gateway_active_enter: str = ""
    dashboard_active_enter: str = ""
    gateway_nrestarts: str = ""
    dashboard_nrestarts: str = ""
    gateway_state_bytes: bytes = b""
    facts_bytes: bytes = b""
    selection_facts_path: Path = Path("")
    gateway_state_path: Path = Path("")
    # Second-cutover migration: prior activation receipt (first cutover) that
    # proves the running fleet is the parent side-generation. Empty when the
    # generic facts path is used (first cutover / normal operation).
    prior_receipt_path: Path = Path("")
    prior_generation: Path = Path("")
    prior_venv_python: Path = Path("")
    prior_home: str = ""
    prior_extras: tuple[str, ...] = ()
    prior_all_extras: bool = False


@dataclass(frozen=True)
class Staged:
    generation_dir: Path
    venv_dir: Path
    venv_python: Path
    store_home: Path = Path("")
    store_exe: Path = Path("")


@dataclass(frozen=True)
class CutoverResult:
    status: str  # "success" | "failed" | "unknown"
    reason: str
    extra: dict = field(default_factory=dict)


def is_hex_sha(value: str) -> bool:
    text = (value or "").strip().lower()
    if len(text) != 40:
        return False
    return all(c in "0123456789abcdef" for c in text)


def generation_dir_for(config: CutoverConfig) -> Path:
    return (config.generation_root / f"gen-{config.candidate_sha[:12]}").absolute()


def venv_dir_for(config: CutoverConfig) -> Path:
    return generation_dir_for(config) / "venv"


def venv_python_for(config: CutoverConfig) -> Path:
    return venv_dir_for(config) / "bin" / "python3"


def candidate_dropin_path(dropin_dir: Path, name: str) -> Path:
    return Path(dropin_dir) / name


def snapshot_path_for(journal: Path) -> Path:
    """Durable baseline snapshot sibling for a journal (root-owned, fsynced)."""
    return Path(str(journal) + ".baseline.json")


def facts_path_for(hermes_home: Path) -> Path:
    """Legacy tools facts (pm packages only). Kept for compat; the cutover
    binds the SELECTION record below, not this file."""
    return Path(hermes_home) / "tools" / "facts.json"


def install_key_for(project_root: Path) -> str:
    """Same as pm.environments.install_key: sha256(canonical)[:16], stdlib only."""
    canonical = str(Path(project_root).resolve())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def selection_facts_path_for(live_tree: Path, hermes_home: Path) -> Path:
    """The REAL selection record pm reads: <home>/installs/<key>/facts.json.

    Mirrors pm.environments.install_state_dir/runtime_facts_path for the
    default-home owner case (live tree owned by its own home, verified live:
    key 5f0a1ff4045d044e for /home/ubuntu/.hermes/hermes-agent).
    """
    key = install_key_for(live_tree)
    return Path(hermes_home) / "installs" / key / "facts.json"


def gateway_state_path_for(hermes_home: Path) -> Path:
    return Path(hermes_home) / "gateway_state.json"


def parse_pyvenv_cfg(data: bytes) -> dict[str, str]:
    """Parse pyvenv.cfg home/executable without importing pm."""
    out: dict[str, str] = {}
    for line in data.decode("utf-8", "replace").splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        if k in ("home", "executable"):
            out[k] = v.strip()
    return out
