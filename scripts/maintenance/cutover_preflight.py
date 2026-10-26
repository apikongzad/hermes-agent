"""Fail-closed baseline capture. Stdlib only; no cgroup gate, no sends.

DESIGN v2: binds BOTH units (MainPID, exe, cmdline, cwd, start_time,
ActiveEnterTimestamp, NRestarts), the REAL selection facts
(installs/<key>/facts.json), gateway_state.json bytes, unit texts and
provenance (parent/candidate SHAs). Any failure is fail-closed.

Second-cutover migration (v2.4): when --baseline-receipt names the root-owned
PRIOR activation receipt (first cutover success for candidate==parent), the
selection facts file derived from live_tree may be absent (old worktree key
was never installed directly; the fleet runs from the prior side generation).
Preflight then binds the prior generation via the receipt (stage-ok extras +
generation/venv/home, terminal receipt-success, current proc cmdline match,
state code_sha + /api/health commit == parent) and leaves facts_bytes empty
instead of inventing blank facts. Stage derives extras from the receipt and
rollback restores ONLY the captured dropin bytes.
"""

from __future__ import annotations

from pathlib import Path

from scripts.maintenance.cutover_git import run_owner_git
from scripts.maintenance.cutover_journal import append
from scripts.maintenance.cutover_manifest import (
    ManifestError,
    external_controller_provenance,
)
from scripts.maintenance.cutover_receipt import (
    PriorActivation,
    ReceiptError,
    load_prior_activation,
)
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


def _run_git_ok_text(host: Host, repo: Path, args: list[str], timeout: int = 30) -> str:
    """rev-parse etc as the repo owner (never bare root git)."""
    res = run_owner_git(host, repo, args, timeout=timeout)
    if res.returncode != 0:
        joined = " ".join([*args])
        raise PreflightError(
            f"preflight command failed: git -C {repo} {joined}: {(res.stderr or '').strip()[:300]}"
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
    except OSError as exc:
        raise PreflightError(f"cannot read /proc/{pid}/start_time: {exc}") from exc
    if start_time is None:
        raise PreflightError(f"live {unit} start_time is unknown (refusing to proceed)")
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


def _code_sha_from_state_bytes(raw: bytes) -> str | None:
    import json as _json

    try:
        payload = _json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    sha = payload.get("code_sha")
    if not isinstance(sha, str) or len(sha.strip()) != 40:
        return None
    return sha.strip().lower()


def _check_receipt_generation(
    prior: PriorActivation, gw_cmd0: str, dash_cmd0: str
) -> None:
    """Both live units must run from the prior side generation (no drift)."""
    expect = str(prior.venv_python)
    for label, cmd0 in (("gateway", gw_cmd0), ("dashboard", dash_cmd0)):
        if not cmd0:
            raise PreflightError(
                f"prior receipt generation mismatch: live {label} cmdline empty"
            )
        # Exact venv python bind; generation dir containment is implied.
        if cmd0.strip() != expect:
            raise PreflightError(
                f"live {label} {cmd0[:80]!r} != prior generation {expect[:80]!r} "
                "(wrong generation? refusing)"
            )
    # Generation dir itself must be the parent side-generation.
    if prior.generation.name != f"gen-{prior.candidate_sha[:12]}":
        raise PreflightError("prior receipt generation is not the parent side-gen")


def _check_receipt_parent_running(
    host: Host, config: CutoverConfig, state_bytes: bytes
) -> None:
    """Parent proof comes from the RUNNING fleet, not the original main HEAD.

    gateway_state.json:code_sha and dashboard /api/health commit must both
    equal parent_sha (the prior candidate 1d9a...). A stale main HEAD (50e82)
    never satisfies this.
    """
    sha = _code_sha_from_state_bytes(state_bytes)
    if sha is None:
        raise PreflightError("gateway_state.json code_sha missing/malformed")
    if sha != config.parent_sha.strip().lower():
        raise PreflightError(
            f"running state {sha[:12]} != parent {config.parent_sha[:12]} "
            "(fleet is not the parent side-gen?)"
        )
    url = f"http://127.0.0.1:{config.dashboard_port}/api/health"
    try:
        status, body = host.http_get(url, timeout=10)
    except OSError as exc:
        raise PreflightError(f"dashboard 9119 unreachable in preflight: {exc}") from exc
    if int(status) != 200:
        raise PreflightError(f"dashboard 9119 unhealthy in preflight: HTTP {status}")
    try:
        import json as _json

        payload = _json.loads(body)
        commit = str(payload.get("commit") or "").strip().lower()
    except ValueError as exc:
        raise PreflightError("dashboard /api/health body is not JSON") from exc
    if commit != config.parent_sha.strip().lower():
        raise PreflightError(
            f"dashboard commit {commit[:12]} != parent {config.parent_sha[:12]}"
        )


def _load_prior_for_preflight(
    host: Host, config: CutoverConfig, gw_cmd0: str, dash_cmd0: str
) -> PriorActivation | None:
    """Load prior receipt when configured; None on the generic facts path."""
    receipt_opt = getattr(config, "baseline_receipt", None)
    want = receipt_opt is not None and str(receipt_opt) not in ("", ".", "None")
    if not want:
        return None
    try:
        prior = load_prior_activation(host, config)
    except ReceiptError as exc:
        raise PreflightError(f"baseline receipt refused: {exc}") from exc
    _check_receipt_generation(prior, gw_cmd0, dash_cmd0)
    return prior


def _resolve_selection_facts(
    host: Host, sel_path: Path, prior: PriorActivation | None
) -> bytes:
    """Real selection facts; empty (no invention) on receipt migration."""
    facts_bytes = _read_optional(host, sel_path)
    if facts_bytes is not None:
        return facts_bytes
    if prior is None:
        raise PreflightError(f"selection facts missing: {sel_path}")
    # Receipt migration: facts optional, extras come from stage-ok.
    # Do NOT invent blank facts; leave bytes empty for stage/rollback.
    return b""


def _make_preflight_baseline(
    *,
    gateway_text: str,
    dash_text: str,
    gateway_dropins: dict[str, bytes],
    dashboard_dropins: dict[str, bytes],
    live_head: str,
    candidate_head: str,
    gw_pid: int,
    gw_exe: str,
    gw_cmd0: str,
    gw_cwd: str,
    gw_start: int,
    gw_enter: str,
    gw_restarts: str,
    dash_pid: int,
    dash_exe: str,
    dash_cmd0: str,
    dash_cwd: str,
    dash_start: int,
    dash_enter: str,
    dash_restarts: str,
    state_bytes: bytes,
    facts_bytes: bytes,
    sel_path: Path,
    state_path: Path,
    prior: PriorActivation | None,
) -> Baseline:
    """Build Baseline with or without a verified prior receipt."""
    if prior is not None:
        return Baseline(
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
            prior_receipt_path=prior.receipt_path,
            prior_generation=prior.generation,
            prior_venv_python=prior.venv_python,
            prior_home=prior.home,
            prior_extras=tuple(prior.extras),
            prior_all_extras=bool(prior.all_extras),
        )
    return Baseline(
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


def _resolve_external_facade(config: CutoverConfig) -> Path:
    """Controller identity comes from the executing external tool, never the candidate."""
    ctrl = getattr(config, "controller_path", None)
    if ctrl is not None and str(ctrl) not in ("", "."):
        return Path(ctrl)
    # Fallback: the running maintenance module file (imported package), not the candidate.
    return Path(__file__).resolve().parent / "cutover.py"


def _refuse_controller_inside_candidate(facade: Path, candidate_src: Path) -> None:
    """A copy planted in the candidate must not satisfy the gate.

    Resolves the facade AND every EXPECTED_SIBLINGS path beside it. A
    parent-directory symlink or containment for any sibling refuses. This
    check is necessary but not sufficient: symlinks to outside and
    same-name hardlinks are refused by the no-follow fd bind in
    external_controller_provenance.
    """
    from scripts.maintenance.cutover_manifest import EXPECTED_SIBLINGS

    try:
        cand_res = Path(candidate_src).resolve()
    except OSError as exc:
        raise PreflightError(
            f"external controller missing: cannot resolve candidate {candidate_src}: {exc}"
        ) from exc
    facade_path = Path(facade)
    if facade_path.suffix != ".py":
        ctrl_dir = facade_path
    else:
        ctrl_dir = facade_path.parent
    names: list[Path] = [facade_path]
    for _name in EXPECTED_SIBLINGS:
        _p = ctrl_dir / _name
        if _p not in names:
            names.append(_p)
    for _candidate in names:
        try:
            res = Path(_candidate).resolve()
        except OSError as exc:
            raise PreflightError(
                f"external controller missing: cannot resolve {_candidate}: {exc}"
            ) from exc
        try:
            inside = res == cand_res or res.is_relative_to(cand_res)
        except (OSError, RuntimeError, ValueError):
            c_str = str(cand_res)
            f_str = str(res)
            inside = f_str == c_str or f_str.startswith(c_str.rstrip("/") + "/")
        if inside:
            raise PreflightError(
                f"external controller refused: resolved path inside candidate_src: {res}"
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

    # External controller gate (never the candidate tree): stock candidates have
    # no scripts/maintenance. Verify the executing tool's sibling set via the
    # no-follow fd bind only (never host.read_bytes, never candidate bytes).
    # Missing/unreadable/tampered/aliased/uncertain external siblings fail
    # closed before any mutation. Candidate copies are never consulted.
    facade = _resolve_external_facade(config)
    _refuse_controller_inside_candidate(facade, Path(config.candidate_src))
    try:
        controller_provenance = external_controller_provenance(
            host, facade, Path(config.candidate_src)
        )
    except ManifestError as exc:
        raise PreflightError(str(exc)) from exc

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

    live_head = _run_git_ok_text(host, Path(config.live_tree), ["rev-parse", "HEAD"])
    candidate_head = _run_git_ok_text(
        host, Path(config.candidate_src), ["rev-parse", "HEAD"]
    )
    if live_head != config.parent_sha:
        raise PreflightError(f"live tree HEAD {live_head[:12]} != parent {config.parent_sha[:12]}")
    if candidate_head != config.candidate_sha:
        raise PreflightError(
            f"candidate tree HEAD {candidate_head[:12]} != candidate {config.candidate_sha[:12]}"
        )

    # REAL selection facts (installs/<key>/facts.json), not tools/facts.json.
    # Second-cutover migration: when --baseline-receipt is configured, the
    # facts file for the old worktree key may be absent (side generation was
    # never installed under that key). The receipt then supplies the extras;
    # facts_bytes stays empty and no blank facts are invented.
    sel_path = selection_facts_path_for(config.live_tree, config.hermes_home)
    prior = _load_prior_for_preflight(host, config, gw_cmd0, dash_cmd0)
    facts_bytes = _resolve_selection_facts(host, sel_path, prior)
    # Keep legacy tools facts as a compat read (never restored over selection).
    _read_optional(host, facts_path_for(config.hermes_home))

    state_path = gateway_state_path_for(config.hermes_home)
    state_bytes = _read_optional(host, state_path)
    if state_bytes is None:
        raise PreflightError(f"gateway_state.json missing: {state_path}")

    if prior is not None:
        # Parent proof from the RUNNING fleet (state + /api/health), not the
        # original main HEAD. Refuses before any mutation.
        _check_receipt_parent_running(host, config, state_bytes)

    gateway_dropins = _list_dropin_bytes(host, config.gateway_dropin_dir)
    dashboard_dropins = _list_dropin_bytes(host, config.dashboard_dropin_dir)

    baseline = _make_preflight_baseline(
        gateway_text=gateway_text,
        dash_text=dash_text,
        gateway_dropins=gateway_dropins,
        dashboard_dropins=dashboard_dropins,
        live_head=live_head,
        candidate_head=candidate_head,
        gw_pid=gw_pid,
        gw_exe=gw_exe,
        gw_cmd0=gw_cmd0,
        gw_cwd=gw_cwd,
        gw_start=gw_start,
        gw_enter=gw_enter,
        gw_restarts=gw_restarts,
        dash_pid=dash_pid,
        dash_exe=dash_exe,
        dash_cmd0=dash_cmd0,
        dash_cwd=dash_cwd,
        dash_start=dash_start,
        dash_enter=dash_enter,
        dash_restarts=dash_restarts,
        state_bytes=state_bytes,
        facts_bytes=facts_bytes,
        sel_path=sel_path,
        state_path=state_path,
        prior=prior,
    )
    detail: dict = {
        "candidate": config.candidate_sha,
        "parent": config.parent_sha,
        "live_pid": gw_pid,
        "live_exe": gw_exe,
        "dashboard_pid": dash_pid,
        "dashboard_exe": dash_exe,
        "selection_facts": str(sel_path),
        "controller_provenance": controller_provenance,
    }
    if prior is not None:
        detail["baseline_receipt"] = str(prior.receipt_path)
        detail["prior_generation"] = str(prior.generation)
        detail["prior_extras"] = list(prior.extras)
        detail["prior_all_extras"] = bool(prior.all_extras)
        detail["facts_bytes_empty"] = not bool(facts_bytes)
    append(
        host,
        config.journal_path,
        "preflight-ok",
        True,
        detail,
    )
    return baseline
