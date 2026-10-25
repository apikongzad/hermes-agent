"""Read-only health: candidate SHA + /proc/PID/exe + 9119. No --version probe."""

from __future__ import annotations

import json
from dataclasses import dataclass

from scripts.maintenance.cutover_journal import append
from scripts.maintenance.cutover_types import (
    CutoverConfig,
    Host,
    Staged,
    facts_path_for,
    gateway_state_path_for,
)


@dataclass(frozen=True)
class HealthReport:
    ok: bool
    detail: str


def _is_active(host: Host, unit: str) -> bool:
    res = host.run(["systemctl", "is-active", unit], timeout=30)
    return res.returncode == 0 and (res.stdout or "").strip() == "active"


def _main_pid(host: Host, unit: str) -> int:
    res = host.run(["systemctl", "show", unit, "-p", "MainPID", "--value"], timeout=30)
    if res.returncode != 0:
        return 0
    text = (res.stdout or "").strip().splitlines()
    if not text:
        return 0
    last = text[-1].strip()
    if last.startswith("MainPID="):
        last = last.split("=", 1)[1].strip()
    try:
        return int(last.split()[0])
    except (ValueError, IndexError):
        return 0


def _code_sha_from_state(host: Host, config: CutoverConfig) -> str | None:
    try:
        raw = host.read_bytes(gateway_state_path_for(config.hermes_home))
    except (OSError, FileNotFoundError):
        return None
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    for key in ("code_sha", "sha", "candidate"):
        value = payload.get(key)
        if isinstance(value, str) and len(value.strip()) == 40:
            return value.strip()
    return None


def check_health(host: Host, config: CutoverConfig, staged: Staged) -> HealthReport:
    """Verify the running fleet is the staged candidate. Read-only (no sends)."""
    if config.dashboard_port != 9119:
        return HealthReport(False, "dashboard port must be 9119")
    if not _is_active(host, config.gateway_unit):
        return HealthReport(False, f"{config.gateway_unit} is not active")
    if not _is_active(host, config.dashboard_unit):
        return HealthReport(False, f"{config.dashboard_unit} is not active")

    pid = _main_pid(host, config.gateway_unit)
    if pid <= 0:
        return HealthReport(False, "gateway MainPID unknown")
    try:
        exe = host.readlink_exe(pid)
    except OSError as exc:
        return HealthReport(False, f"cannot read /proc/{pid}/exe: {exc}")
    generation_text = str(staged.generation_dir)
    if generation_text not in exe:
        return HealthReport(False, f"gateway exe {exe!r} is not the staged generation")

    head = host.run(
        ["git", "-C", str(config.candidate_src), "rev-parse", "HEAD"], timeout=30
    )
    candidate_head = (head.stdout or "").strip()
    if head.returncode != 0 or candidate_head != config.candidate_sha:
        return HealthReport(False, "candidate tree HEAD does not match candidate SHA")

    state_sha = _code_sha_from_state(host, config)
    if state_sha is not None and state_sha != config.candidate_sha:
        return HealthReport(False, f"gateway state SHA {state_sha[:12]} != candidate")

    url = f"http://127.0.0.1:{config.dashboard_port}/health"
    try:
        status, _body = host.http_get(url, timeout=10)
    except OSError as exc:
        return HealthReport(False, f"dashboard 9119 unreachable: {exc}")
    if status not in (200, 302):
        return HealthReport(False, f"dashboard 9119 unhealthy: HTTP {status}")

    append(
        host,
        config.journal_path,
        "health-ok",
        True,
        {
            "pid": pid,
            "exe": exe,
            "candidate": config.candidate_sha,
        },
    )
    return HealthReport(True, "candidate healthy")


def check_rollback_health(host: Host, config: CutoverConfig) -> HealthReport:
    """Post-rollback liveness: units active + dashboard 9119 (no SHA bind)."""
    if not _is_active(host, config.gateway_unit):
        return HealthReport(
            False, f"{config.gateway_unit} is not active after rollback"
        )
    if not _is_active(host, config.dashboard_unit):
        return HealthReport(
            False, f"{config.dashboard_unit} is not active after rollback"
        )
    url = f"http://127.0.0.1:{config.dashboard_port}/health"
    try:
        status, _body = host.http_get(url, timeout=10)
    except OSError as exc:
        return HealthReport(False, f"dashboard 9119 unreachable after rollback: {exc}")
    if status not in (200, 302):
        return HealthReport(
            False, f"dashboard 9119 unhealthy after rollback: HTTP {status}"
        )
    return HealthReport(True, "rollback fleet live")
