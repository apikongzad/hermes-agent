"""Fail-closed baseline capture. Stdlib only; no cgroup gate, no sends."""

from __future__ import annotations

from pathlib import Path

from scripts.maintenance.cutover_journal import append
from scripts.maintenance.cutover_types import (
    Baseline,
    CutoverConfig,
    Host,
    facts_path_for,
    is_hex_sha,
)


class PreflightError(RuntimeError):
    pass


def _run_ok_text(host: Host, argv: list[str], timeout: int = 60) -> str:
    res = host.run(argv, timeout=timeout)
    if res.returncode != 0:
        raise PreflightError(
            f"preflight command failed: {' '.join(argv)}: {res.stderr.strip()[:300]}"
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
    # The fake host exposes list_dir via run fallback; production lists via run ls.
    # Keep the controller portable: probe the two known override names plus the
    # candidate name. Anything else is preserved by never touching it.
    found: dict[str, bytes] = {}
    for name in ("zz-runtime-3.14.9.conf", "zzz-candidate.conf", "zz-candidate.conf"):
        body = _read_optional(host, dropin_dir / name)
        if body is not None:
            found[name] = body
    return found


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
        raise PreflightError(
            "dropin name must not imply HERMES_EXE selects the interpreter"
        )

    # Controller must live inside the candidate tree (never /tmp staging):
    # the candidate source under test must carry its own controller copy.
    candidate_controller = (
        Path(config.candidate_src) / "scripts" / "maintenance" / "cutover.py"
    )
    try:
        controller_bytes = host.read_bytes(candidate_controller)
    except FileNotFoundError:
        raise PreflightError(
            f"candidate tree has no controller: {candidate_controller}"
        )
    except OSError as exc:
        raise PreflightError(f"cannot read candidate controller: {exc}") from exc
    if b"def orchestrate" not in controller_bytes:
        raise PreflightError("candidate controller is not the cutover orchestrator")

    # Sorted AFTER existing zz-runtime override so systemd prefers the candidate.
    if not (config.candidate_dropin_name > "zz-runtime-3.14.9.conf"):
        raise PreflightError("candidate dropin must sort AFTER zz-runtime-3.14.9.conf")

    gateway_text = _run_ok_text(host, ["systemctl", "cat", config.gateway_unit])
    dashboard_text = _run_ok_text(host, ["systemctl", "cat", config.dashboard_unit])
    if "ExecStart=" not in gateway_text or "ExecStart=" not in dashboard_text:
        raise PreflightError(
            "baseline unit text missing ExecStart (refusing to proceed)"
        )

    show_text = _run_ok_text(
        host, ["systemctl", "show", config.gateway_unit, "-p", "MainPID", "--value"]
    )
    # systemctl show --value prints a bare number; tolerate both spellings.
    pid_text = show_text.splitlines()[-1].strip() if show_text else "0"
    if pid_text.startswith("MainPID="):
        pid_text = pid_text.split("=", 1)[1].strip()
    try:
        main_pid = int(pid_text.split()[0])
    except (ValueError, IndexError):
        main_pid = 0
    if main_pid <= 0:
        raise PreflightError("live gateway MainPID is unknown (refusing to proceed)")
    try:
        live_exe = host.readlink_exe(main_pid)
    except OSError as exc:
        raise PreflightError(f"cannot read /proc/{main_pid}/exe: {exc}") from exc
    if not live_exe:
        raise PreflightError("live gateway exe is empty (refusing to proceed)")

    live_head = _run_ok_text(
        host, ["git", "-C", str(config.live_tree), "rev-parse", "HEAD"]
    )
    candidate_head = _run_ok_text(
        host, ["git", "-C", str(config.candidate_src), "rev-parse", "HEAD"]
    )
    if live_head != config.parent_sha:
        raise PreflightError(
            f"live tree HEAD {live_head[:12]} != parent {config.parent_sha[:12]}"
        )
    if candidate_head != config.candidate_sha:
        raise PreflightError(
            f"candidate tree HEAD {candidate_head[:12]} != candidate {config.candidate_sha[:12]}"
        )

    facts_bytes = _read_optional(host, facts_path_for(config.hermes_home))
    if facts_bytes is None:
        raise PreflightError(
            f"facts snapshot missing: {facts_path_for(config.hermes_home)}"
        )

    gateway_dropins = _list_dropin_bytes(host, config.gateway_dropin_dir)
    dashboard_dropins = _list_dropin_bytes(host, config.dashboard_dropin_dir)

    baseline = Baseline(
        gateway_unit_text=gateway_text,
        dashboard_unit_text=dashboard_text,
        gateway_dropin_bytes=gateway_dropins,
        dashboard_dropin_bytes=dashboard_dropins,
        live_head=live_head,
        candidate_head=candidate_head,
        live_main_pid=main_pid,
        live_main_exe=live_exe,
        facts_bytes=facts_bytes,
    )
    append(
        host,
        config.journal_path,
        "preflight-ok",
        True,
        {
            "candidate": config.candidate_sha,
            "parent": config.parent_sha,
            "live_pid": main_pid,
            "live_exe": live_exe,
        },
    )
    return baseline
