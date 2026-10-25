"""Full orchestration: preflight -> stage -> dropins -> reload -> restart -> verify.

Fail-closed at every step; start/health failure triggers automatic rollback.
Success/failure is a local journal receipt only (never an outbound send).
Stdlib only.
"""

from __future__ import annotations

from scripts.maintenance.cutover_dropin import write_candidate_dropins
from scripts.maintenance.cutover_health import check_health
from scripts.maintenance.cutover_journal import append, has_terminal_receipt
from scripts.maintenance.cutover_preflight import PreflightError, preflight
from scripts.maintenance.cutover_restore import rollback
from scripts.maintenance.cutover_stage import (
    StageError,
    stage,
    verify_isolated_launch,
)
from scripts.maintenance.cutover_types import CutoverConfig, CutoverResult, Host


def _receipt(
    host: Host,
    config: CutoverConfig,
    status: str,
    reason: str,
    extra: dict | None = None,
) -> CutoverResult:
    detail = {"status": status, "reason": reason, "candidate": config.candidate_sha}
    if extra:
        detail.update(extra)
    append(host, config.journal_path, f"receipt-{status}", status == "success", detail)
    return CutoverResult(status=status, reason=reason, extra=detail)


def _fail_with_rollback(
    host: Host,
    config: CutoverConfig,
    baseline: object,
    kind: str,
    detail: str,
) -> CutoverResult:
    from scripts.maintenance.cutover_types import Baseline as _Baseline

    assert isinstance(baseline, _Baseline)
    try:
        errors = rollback(host, config, baseline)
    except OSError as rollback_exc:
        return _receipt(
            host,
            config,
            "unknown",
            f"{kind} failed; rollback IO failed: {rollback_exc}",
        )
    if errors:
        return _receipt(
            host,
            config,
            "unknown",
            f"{kind} failed ({detail}); rollback errors: {'; '.join(errors)}",
        )
    return _receipt(
        host, config, "failed", f"{kind} failed and fleet restored: {detail}"
    )


def orchestrate(host: Host, config: CutoverConfig) -> CutoverResult:
    try:
        baseline = preflight(host, config)
    except PreflightError as exc:
        return _receipt(host, config, "unknown", f"preflight fail-closed: {exc}")
    except OSError as exc:
        return _receipt(host, config, "unknown", f"preflight IO fail-closed: {exc}")

    try:
        staged = stage(host, config)
    except (StageError, OSError, RuntimeError) as exc:
        return _fail_with_rollback(host, config, baseline, "staging", str(exc))

    try:
        verify_isolated_launch(host, config, staged, baseline.live_main_exe)
    except (StageError, OSError, RuntimeError) as exc:
        return _fail_with_rollback(host, config, baseline, "launch verify", str(exc))

    try:
        write_candidate_dropins(host, config, staged)
    except (OSError, RuntimeError) as exc:
        return _fail_with_rollback(host, config, baseline, "dropin write", str(exc))

    reloaded = host.run(["systemctl", "daemon-reload"], timeout=60)
    if reloaded.returncode != 0:
        return _fail_with_rollback(
            host, config, baseline, "daemon-reload", (reloaded.stderr or "")[-200:]
        )

    restarted = host.run(
        ["systemctl", "restart", config.gateway_unit, config.dashboard_unit],
        timeout=180,
    )
    if restarted.returncode != 0:
        return _fail_with_rollback(
            host, config, baseline, "restart", (restarted.stderr or "")[-200:]
        )

    report = check_health(host, config, staged, baseline)
    if not report.ok:
        return _fail_with_rollback(host, config, baseline, "health", report.detail)

    return _receipt(
        host,
        config,
        "success",
        "candidate cut over and healthy",
        {
            "generation": str(staged.generation_dir),
            "exe": str(staged.venv_python),
        },
    )


def resume(host: Host, config: CutoverConfig) -> CutoverResult:
    """Durable resume for interruption (OnFailure/reboot): finish or roll back."""
    if has_terminal_receipt(host, config.journal_path):
        return CutoverResult(
            status="unknown",
            reason="journal already has a terminal receipt; refusing to re-run",
        )
    # No terminal receipt means the previous run was interrupted before it could
    # restore. Re-capture the baseline fail-closed, then restore to the parent.
    try:
        baseline = preflight(host, config)
    except (PreflightError, OSError) as exc:
        return _receipt(host, config, "unknown", f"resume preflight fail-closed: {exc}")
    try:
        errors = rollback(host, config, baseline)
    except OSError as exc:
        return _receipt(host, config, "unknown", f"resume rollback IO failed: {exc}")
    if errors:
        return _receipt(
            host, config, "unknown", f"resume rollback errors: {'; '.join(errors)}"
        )
    return _receipt(
        host,
        config,
        "failed",
        "interrupted cutover resumed and fleet restored to parent",
    )
