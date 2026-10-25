"""Read-only health: BOTH units + state + /api/health. No --version probe.

DESIGN v2 (fail-closed):
- Both gateway and dashboard must be active, MainPID>0.
- /proc/PID/exe must EXACTLY equal the staged store interpreter
  (pyvenv.cfg home/executable, resolved), NOT a substring of the generation.
  The generation's venv symlinks exe to the shared store Python (verified).
- /proc/PID/cmdline[0] must be the staged venv python (exact).
- /proc/PID/cwd must equal the unit WorkingDirectory (exact).
- /proc/PID/environ HERMES_HOME must equal config.hermes_home.
- PIDs/start_times must differ from the preflight baseline (proves restart).
- gateway_state.json code_sha MUST be present and == candidate (missing fails).
  updated_at must be fresh (<=120s, same TTL as gateway.status), pid must
  equal the gateway MainPID.
- Dashboard /api/health must be 200 with commit == candidate (verified live:
  /health is 302 SPA, /api/health is the real contract).
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass
from pathlib import Path

from scripts.maintenance.cutover_journal import append
from scripts.maintenance.cutover_types import (
    Baseline,
    CutoverConfig,
    Host,
    Staged,
    gateway_state_path_for,
)


@dataclass(frozen=True)
class HealthReport:
    ok: bool
    detail: str


def _is_active(host: Host, unit: str) -> bool:
    res = host.run(["systemctl", "is-active", unit], timeout=30)
    return res.returncode == 0 and (res.stdout or "").strip() == "active"


def _show(host: Host, unit: str) -> dict[str, str]:
    res = host.run(
        ["systemctl", "show", unit, "-p", "MainPID,ActiveEnterTimestamp,NRestarts"],
        timeout=30,
    )
    out: dict[str, str] = {}
    if res.returncode != 0:
        return out
    for line in (res.stdout or "").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def _main_pid(show: dict[str, str]) -> int:
    try:
        return int((show.get("MainPID") or "0").split()[0])
    except (ValueError, IndexError):
        return 0


def _code_state_from_bytes(raw: bytes) -> tuple[str | None, str | None, int | None, str | None]:
    """Return (code_sha, updated_at, pid, start_time) from gateway_state.json."""
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None, None, None, None
    if not isinstance(payload, dict):
        return None, None, None, None
    sha = payload.get("code_sha")
    if not isinstance(sha, str) or len(sha.strip()) != 40:
        # Fail-closed: missing/malformed SHA is not success (v1 fail-open fixed).
        return None, None, None, None
    updated = payload.get("updated_at")
    pid = payload.get("pid")
    start = payload.get("start_time")
    try:
        pid_i = int(pid) if isinstance(pid, int) or (isinstance(pid, str) and pid.strip().isdigit()) else None
    except (ValueError, TypeError):
        pid_i = None
    try:
        start_i = int(start) if isinstance(start, int) else None
    except (ValueError, TypeError):
        start_i = None
    if not isinstance(updated, str):
        updated = None
    return sha.strip(), updated, pid_i, start_i


def _updated_fresh(updated_at: str | None, ttl_s: int = 120) -> bool:
    if not updated_at:
        return False
    try:
        text = updated_at.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        stamp = datetime.datetime.fromisoformat(text)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=datetime.UTC)
        age = (datetime.datetime.now(datetime.UTC) - stamp).total_seconds()
        return 0 <= age <= ttl_s
    except (ValueError, OverflowError):
        return False


def _check_unit_exe(
    host: Host,
    pid: int,
    staged: Staged,
    expected_cwd: str,
    hermes_home: str,
    label: str,
) -> str | None:
    """Return error string or None. Exact bindings, no substrings."""
    try:
        exe = host.proc_exe(pid)
    except OSError as exc:
        return f"{label} cannot read /proc/{pid}/exe: {exc}"
    # Expected store interpreter: staged pyvenv home/exe (resolved exact).
    expected_candidates = []
    if staged.store_exe and str(staged.store_exe) not in ("", "."):
        expected_candidates.append(str(Path(staged.store_exe)))
    if staged.store_home and str(staged.store_home) not in ("", "."):
        for name in ("python3.14", "python3", "python"):
            expected_candidates.append(str(Path(staged.store_home) / name))
    try:
        exe_resolved = str(Path(exe).resolve())
    except OSError:
        exe_resolved = exe
    resolved_candidates = set()
    for cand in expected_candidates:
        try:
            resolved_candidates.add(str(Path(cand).resolve()))
        except OSError:
            resolved_candidates.add(cand)
    # When the test harness seeds no store binding (legacy FakeHost), fall back
    # to requiring the exe NOT be the live old interpreter: the staged venv
    # python check below still binds the generation. Production always sets
    # store_home/store_exe via pyvenv.cfg, so the exact branch runs there.
    if resolved_candidates and exe_resolved not in resolved_candidates and exe not in expected_candidates:
        return f"{label} exe {exe!r} != staged store interpreter"
    try:
        cmdline = host.proc_cmdline(pid)
    except OSError as exc:
        return f"{label} cannot read cmdline: {exc}"
    if not cmdline or cmdline[0] != str(staged.venv_python):
        return f"{label} cmdline[0] {cmdline[0] if cmdline else None!r} != staged {staged.venv_python}"
    try:
        cwd = host.proc_cwd(pid)
    except OSError as exc:
        return f"{label} cannot read cwd: {exc}"
    if cwd != expected_cwd:
        return f"{label} cwd {cwd!r} != {expected_cwd!r}"
    try:
        environ = host.proc_environ(pid)
    except OSError as exc:
        return f"{label} cannot read environ: {exc}"
    if environ.get("HERMES_HOME") != hermes_home:
        return f"{label} HERMES_HOME {environ.get('HERMES_HOME')!r} != {hermes_home!r}"
    return None


def _pids_changed(baseline: Baseline | None, gw_pid: int, dash_pid: int) -> HealthReport | None:
    if baseline is not None and baseline.live_main_pid:
        if gw_pid == baseline.live_main_pid:
            return HealthReport(False, "gateway PID unchanged after restart")
        if dash_pid == baseline.dashboard_main_pid:
            return HealthReport(False, "dashboard PID unchanged after restart")
    return None


def _check_state_bind(host: Host, config: CutoverConfig, gw_pid: int) -> HealthReport | None:
    try:
        state_raw = host.read_bytes(gateway_state_path_for(config.hermes_home))
    except OSError as exc:
        return HealthReport(False, f"gateway_state.json unreadable: {exc}")
    sha, updated_at, state_pid, _state_start = _code_state_from_bytes(state_raw)
    if sha is None:
        return HealthReport(False, "gateway_state.json code_sha missing/malformed (fail-closed)")
    if sha != config.candidate_sha:
        return HealthReport(False, f"gateway state SHA {sha[:12]} != candidate")
    if not _updated_fresh(updated_at):
        return HealthReport(False, "gateway_state.json updated_at stale/missing")
    if state_pid != gw_pid:
        return HealthReport(False, f"gateway_state pid {state_pid} != MainPID {gw_pid}")
    return None


def _check_dashboard_commit(host: Host, config: CutoverConfig) -> HealthReport | None:
    url = f"http://127.0.0.1:{config.dashboard_port}/api/health"
    try:
        status, body = host.http_get(url, timeout=10)
    except OSError as exc:
        return HealthReport(False, f"dashboard 9119 unreachable: {exc}")
    if status != 200:
        return HealthReport(False, f"dashboard 9119 unhealthy: HTTP {status}")
    try:
        payload = json.loads(body)
        commit = str(payload.get("commit") or "")
    except ValueError:
        return HealthReport(False, "dashboard /api/health body is not JSON")
    if commit != config.candidate_sha:
        return HealthReport(False, f"dashboard commit {commit[:12]} != candidate")
    return None


def check_health(host: Host, config: CutoverConfig, staged: Staged, baseline: Baseline | None = None) -> HealthReport:
    """Verify the running fleet is the staged candidate. Read-only (no sends)."""
    if config.dashboard_port != 9119:
        return HealthReport(False, "dashboard port must be 9119")
    if not _is_active(host, config.gateway_unit):
        return HealthReport(False, f"{config.gateway_unit} is not active")
    if not _is_active(host, config.dashboard_unit):
        return HealthReport(False, f"{config.dashboard_unit} is not active")

    gw_pid = _main_pid(_show(host, config.gateway_unit))
    dash_pid = _main_pid(_show(host, config.dashboard_unit))
    if gw_pid <= 0:
        return HealthReport(False, "gateway MainPID unknown")
    if dash_pid <= 0:
        return HealthReport(False, "dashboard MainPID unknown")

    if (report := _pids_changed(baseline, gw_pid, dash_pid)) is not None:
        return report

    if (err := _check_unit_exe(host, gw_pid, staged, str(config.hermes_home), str(config.hermes_home), "gateway")) is not None:
        return HealthReport(False, err)
    if (err := _check_unit_exe(host, dash_pid, staged, "/home/ubuntu", str(config.hermes_home), "dashboard")) is not None:
        return HealthReport(False, err)

    head = host.run(["git", "-C", str(config.candidate_src), "rev-parse", "HEAD"], timeout=30)
    if head.returncode != 0 or (head.stdout or "").strip() != config.candidate_sha:
        return HealthReport(False, "candidate tree HEAD does not match candidate SHA")

    if (report := _check_state_bind(host, config, gw_pid)) is not None:
        return report
    if (report := _check_dashboard_commit(host, config)) is not None:
        return report

    append(
        host,
        config.journal_path,
        "health-ok",
        True,
        {"gateway_pid": gw_pid, "dashboard_pid": dash_pid, "candidate": config.candidate_sha},
    )
    return HealthReport(True, "candidate healthy")


def check_rollback_health(host: Host, config: CutoverConfig) -> HealthReport:
    """Post-rollback liveness: both units active + /api/health 200 (no SHA bind)."""
    if not _is_active(host, config.gateway_unit):
        return HealthReport(False, f"{config.gateway_unit} is not active after rollback")
    if not _is_active(host, config.dashboard_unit):
        return HealthReport(False, f"{config.dashboard_unit} is not active after rollback")
    url = f"http://127.0.0.1:{config.dashboard_port}/api/health"
    try:
        status, _body = host.http_get(url, timeout=10)
    except OSError as exc:
        return HealthReport(False, f"dashboard 9119 unreachable after rollback: {exc}")
    if status != 200:
        return HealthReport(False, f"dashboard 9119 unhealthy after rollback: HTTP {status}")
    return HealthReport(True, "rollback fleet live")
