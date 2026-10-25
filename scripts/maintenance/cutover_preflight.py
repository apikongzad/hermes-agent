"""Fail-closed baseline capture. Stdlib only; no cgroup gate, no sends.

DESIGN v2: binds BOTH units (MainPID, exe, cmdline, cwd, start_time,
ActiveEnterTimestamp, NRestarts), the REAL selection facts
(installs/<key>/facts.json), gateway_state.json bytes, unit texts and
provenance (parent/candidate SHAs). Any failure is fail-closed.
"""

from __future__ import annotations

from pathlib import Path

from scripts.maintenance.cutover_journal import append
from scripts.maintenance.cutover_types import (
    Baseline,
    CutoverConfig,
    Host,
    facts_path_for,
    gateway_state_path_for,
    is_hex_sha,
    selection_facts_path_for,
)


class PreflightError(RuntimeError):
    pass


def _run_ok_text(
    host: Host, argv: list[str], timeout: int = 60, cwd: Path | None = None
) -> str:
    res = host.run(argv, timeout=timeout, cwd=cwd)
    if res.returncode != 0:
        raise PreflightError(
            f"preflight command failed: {' '.join(argv)}: {(res.stderr or '').strip()[:300]}"
        )
    return (res.stdout or "").strip()


def _read_optional(host: Host, path: Path) -> bytes | None:
    try:
        return host.read_bytes(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PreflightError(f"preflight cannot read {path}: {exc}") from exc


def _list_dropin_bytes(host: Host, dropin_dir: Path) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    for name in ("zz-runtime-3.14.9.conf", "zzz-candidate.conf", "zz-candidate.conf"):
        body = _read_optional(host, dropin_dir / name)
        if body is not None:
            found[name] = body
    return found


def _show_field(text: str, field: str) -> str:
    """Parse `systemctl show -p A,B` output (KEY=value lines) for one field."""
    for line in text.splitlines():
        if line.startswith(field + "="):
            return line.split("=", 1)[1].strip()
    return ""


def _main_pid_from_show(text: str) -> int:
    raw = _show_field(text, "MainPID")
    # systemctl show --value prints bare number; tolerate MainPID= prefix.
    if raw.startswith("MainPID="):
        raw = raw.split("=", 1)[1].strip()
    try:
        return int(raw.split()[0])
    except (ValueError, IndexError):
        return 0


def _capture_unit(
    host: Host, unit: str
) -> tuple[str, int, str, str, str, str, str, str]:
    """Return (cat_text, pid, exe, cmdline0, cwd, start_time, active_enter, nrestarts)."""
    cat_text = _run_ok_text(host, ["systemctl", "cat", unit])
    if "ExecStart=" not in cat_text:
        raise PreflightError(f"baseline unit {unit} text missing ExecStart")
    show_text = _run_ok_text(
        host,
        ["systemctl", "show", unit, "-p", "MainPID,ActiveEnterTimestamp,NRestarts,ExecStart"],
    )
    pid = _main_pid_from_show(show_text)
    if pid <= 0:
        raise PreflightError(f"live {unit} MainPID is unknown (refusing to proceed)")
    try:
        exe = host.proc_exe(pid)
    except OSError as exc:
        raise PreflightError(f"cannot read /proc/{pid}/exe: {exc}") from exc
    if not exe:
        raise PreflightError(f"live {unit} exe is empty (refusing to proceed)")
    try:
        cmdline = host.proc_cmdline(pid)
    except OSError as exc:
        raise PreflightError(f"cannot read /proc/{pid}/cmdline: {exc}") from exc
    try:
        cwd = host.proc_cwd(pid)
    except OSError as exc:
        raise PreflightError(f"cannot read /proc/{pid}/cwd: {exc}") from exc
    try:
        start_time = host.proc_start_time(pid)
    except OSError:
        start_time = None
    return (
        cat_text,
        pid,
        exe,
        cmdline[0] if cmdline else "",
        cwd,
        start_time,  # type: ignore[return-value]
        _show_field(show_text, "ActiveEnterTimestamp"),
        _show_field(show_text, "NRestarts"),
    )


def preflight(host: Host, config: CutoverConfig) -> Baseline:
    """Capture reversible baseline. Any failure is fail-closed (raise, no mutation)."""
    if not is_hex_sha(config.candidate_sha):
        raise PreflightError("candidate_sha must be a 40-hex SHA")
    if not is_hex_sha(config.parent_sha):
        raise PreflightError("parent_sha must be a 40-hex SHA")
    if config.candidate_sha == config.parent_sha:
        raise PreflightError("candidate must differ from parent baseline")
    if config.dashboard_port != 9119:
        raise PreflightError("dashboard health port must be 9119 (never 3000/8501)")
    if "HERMES_EXE" in config.candidate_dropin_name:
        raise PreflightError("dropin name must not imply HERMES_EXE selects the interpreter")

    candidate_controller = (
        Path(config.candidate_src) / "scripts" / "maintenance" / "cutover.py"
    )
    try:
        controller_bytes = host.read_bytes(candidate_controller)
    except FileNotFoundError:
        raise PreflightError(f"candidate tree has no controller: {candidate_controller}")
    except OSError as exc:
        raise PreflightError(f"cannot read candidate controller: {exc}") from exc
    if b"def orchestrate" not in controller_bytes:
        raise PreflightError("candidate controller is not the cutover orchestrator")

    if not (config.candidate_dropin_name > "zz-runtime-3.14.9.conf"):
        raise PreflightError("candidate dropin must sort AFTER zz-runtime-3.14.9.conf")

    (
        gateway_text,
        gw_pid,
        gw_exe,
        gw_cmd0,
        gw_cwd,
        gw_start,
        gw_enter,
        gw_restarts,
    ) = _capture_unit(host, config.gateway_unit)
    (
        dash_text,
        dash_pid,
        dash_exe,
        dash_cmd0,
        dash_cwd,
        dash_start,
        dash_enter,
        dash_restarts,
    ) = _capture_unit(host, config.dashboard_unit)

    live_head = _run_ok_text(host, ["git", "-C", str(config.live_tree), "rev-parse", "HEAD"])
    candidate_head = _run_ok_text(
        host, ["git", "-C", str(config.candidate_src), "rev-parse", "HEAD"]
    )
    if live_head != config.parent_sha:
        raise PreflightError(f"live tree HEAD {live_head[:12]} != parent {config.parent_sha[:12]}")
    if candidate_head != config.candidate_sha:
        raise PreflightError(
            f"candidate tree HEAD {candidate_head[:12]} != candidate {config.candidate_sha[:12]}"
        )

    # REAL selection facts (installs/<key>/facts.json), not tools/facts.json.
    sel_path = selection_facts_path_for(config.live_tree, config.hermes_home)
    facts_bytes = _read_optional(host, sel_path)
    if facts_bytes is None:
        raise PreflightError(f"selection facts missing: {sel_path}")
    # Keep legacy tools facts as a compat read (never restored over selection).
    _read_optional(host, facts_path_for(config.hermes_home))

    state_path = gateway_state_path_for(config.hermes_home)
    state_bytes = _read_optional(host, state_path)
    if state_bytes is None:
        raise PreflightError(f"gateway_state.json missing: {state_path}")

    gateway_dropins = _list_dropin_bytes(host, config.gateway_dropin_dir)
    dashboard_dropins = _list_dropin_bytes(host, config.dashboard_dropin_dir)

    baseline = Baseline(
        gateway_unit_text=gateway_text,
        dashboard_unit_text=dash_text,
        gateway_dropin_bytes=gateway_dropins,
        dashboard_dropin_bytes=dashboard_dropins,
        live_head=live_head,
        candidate_head=candidate_head,
        live_main_pid=gw_pid,
        live_main_exe=gw_exe,
        live_main_cmdline=(gw_cmd0,),
        live_main_cwd=gw_cwd,
        live_main_start_time=gw_start,
        dashboard_main_pid=dash_pid,
        dashboard_main_exe=dash_exe,
        dashboard_main_cmdline=(dash_cmd0,),
        dashboard_main_cwd=dash_cwd,
        dashboard_main_start_time=dash_start,
        gateway_active_enter=gw_enter,
        dashboard_active_enter=dash_enter,
        gateway_nrestarts=gw_restarts,
        dashboard_nrestarts=dash_restarts,
        gateway_state_bytes=state_bytes,
        facts_bytes=facts_bytes,
        selection_facts_path=sel_path,
        gateway_state_path=state_path,
    )
    append(
        host,
        config.journal_path,
        "preflight-ok",
        True,
        {
            "candidate": config.candidate_sha,
            "parent": config.parent_sha,
            "live_pid": gw_pid,
            "live_exe": gw_exe,
            "dashboard_pid": dash_pid,
            "dashboard_exe": dash_exe,
            "selection_facts": str(sel_path),
        },
    )
    return baseline
