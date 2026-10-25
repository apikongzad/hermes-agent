"""Shared types for the standalone cutover controller. Stdlib only."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
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

    def run(self, argv: list[str], timeout: int = 60) -> RunResult:
        raise NotImplementedError

    def read_bytes(self, path: Path) -> bytes:
        raise NotImplementedError

    def write_bytes(self, path: Path, data: bytes) -> None:
        raise NotImplementedError

    def remove(self, path: Path) -> None:
        raise NotImplementedError

    def readlink_exe(self, pid: int) -> str:
        raise NotImplementedError

    def http_get(self, url: str, timeout: int = 10) -> tuple[int, str]:
        raise NotImplementedError


class ProductionHost(Host):
    """Real host effects. Root installs/runs this; never used in unit tests."""

    def run(self, argv: list[str], timeout: int = 60) -> RunResult:
        done = subprocess.run(
            argv,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return RunResult(done.returncode, done.stdout or "", done.stderr or "")

    def read_bytes(self, path: Path) -> bytes:
        return Path(path).read_bytes()

    def write_bytes(self, path: Path, data: bytes) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = target.with_name(f".{target.name}.stage.{os.getpid()}")
        staging.write_bytes(data)
        os.replace(staging, target)

    def remove(self, path: Path) -> None:
        try:
            Path(path).unlink()
        except FileNotFoundError:
            return

    def readlink_exe(self, pid: int) -> str:
        return os.readlink(f"/proc/{pid}/exe")

    def http_get(self, url: str, timeout: int = 10) -> tuple[int, str]:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            body = response.read(65536).decode("utf-8", "replace")
            return int(response.status), body


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
    facts_bytes: bytes = b""


@dataclass(frozen=True)
class Staged:
    generation_dir: Path
    venv_dir: Path
    venv_python: Path


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


def facts_path_for(hermes_home: Path) -> Path:
    return Path(hermes_home) / "tools" / "facts.json"


def gateway_state_path_for(hermes_home: Path) -> Path:
    return Path(hermes_home) / "gateway_state.json"
