"""Full orchestration: preflight -> snapshot -> stage -> dropins -> reload -> restart -> verify.

Fail-closed at every step. Pre-mutation failures (stage/launch-verify)
return `failed` with ZERO lifecycle writes (no source/facts/dropin
restore, no daemon-reload/restart). Only post-mutation failures
(dropin/reload/restart/health) trigger automatic rollback.
Success/failure is a local journal receipt only (never an outbound send).
Stdlib only.
"""

from __future__ import annotations

import subprocess

from scripts.maintenance.cutover_dropin import write_candidate_dropins
from scripts.maintenance.cutover_health import check_health
from scripts.maintenance.cutover_journal import append, has_terminal_receipt
from scripts.maintenance.cutover_manifest import assert_no_candidate_import
from scripts.maintenance.cutover_preflight import PreflightError, preflight
from scripts.maintenance.cutover_restore import rollback
from scripts.maintenance.cutover_snapshot import (
    SnapshotError,
    load_baseline,
    save_baseline,
)
from scripts.maintenance.cutover_stage import (
    StageError,
    stage,
    verify_isolated_launch,
)
from scripts.maintenance.cutover_types import Baseline, CutoverConfig, CutoverResult, Host

_TIMEOUT_TYPES = (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired)


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
    baseline: Baseline,
    kind: str,
    detail: str,
) -> CutoverResult:
    assert isinstance(baseline, Baseline)
    try:
        errors = rollback(host, config, baseline)
    except (OSError, RuntimeError, SnapshotError) as rollback_exc:
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


def _fail_no_rollback(
    host: Host,
    config: CutoverConfig,
    kind: str,
    detail: str,
) -> CutoverResult:
    return _receipt(
        host,
        config,
        "failed",
        f"{kind} failed before any live mutation; fleet untouched: {detail}",
    )


def orchestrate(host: Host, config: CutoverConfig) -> CutoverResult:
    try:
        assert_no_candidate_import(config.candidate_src)
    except (OSError, RuntimeError) as exc:
        return _receipt(host, config, "unknown", f"manifest boundary refused: {exc}")
    try:
        baseline = preflight(host, config)
    except PreflightError as exc:
        return _receipt(host, config, "unknown", f"preflight fail-closed: {exc}")
    except (OSError, RuntimeError) as exc:
        return _receipt(host, config, "unknown", f"preflight IO fail-closed: {exc}")

    try:
        save_baseline(host, config, baseline)
    except SnapshotError as exc:
        return _receipt(host, config, "unknown", f"snapshot persist fail-closed: {exc}")
    append(
        host,
        config.journal_path,
        "snapshot-ok",
        True,
        {"candidate": config.candidate_sha, "parent": config.parent_sha},
    )

    try:
        staged = stage(host, config)
    except (StageError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return _fail_no_rollback(host, config, "staging", str(exc))

    try:
        verify_isolated_launch(host, config, staged, baseline.live_main_exe)
    except (StageError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return _fail_no_rollback(host, config, "launch verify", str(exc))

    live_mutated = False
    try:
        write_candidate_dropins(host, config, staged)
        live_mutated = True
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        live_mutated = True
        return _fail_with_rollback(host, config, baseline, "dropin write", str(exc))

    try:
        try:
            reloaded = host.run(["systemctl", "daemon-reload"], timeout=60)
        except _TIMEOUT_TYPES as exc:
            return _fail_with_rollback(
                host, config, baseline, "daemon-reload", f"{type(exc).__name__}: {exc}"[-300:]
            )
        if reloaded.returncode != 0:
            return _fail_with_rollback(
                host, config, baseline, "daemon-reload", (reloaded.stderr or "")[-200:]
            )

        try:
            restarted = host.run(
                ["systemctl", "restart", config.gateway_unit, config.dashboard_unit],
                timeout=180,
            )
        except _TIMEOUT_TYPES as exc:
            return _fail_with_rollback(
                host, config, baseline, "restart", f"{type(exc).__name__}: {exc}"[-300:]
            )
        if restarted.returncode != 0:
            return _fail_with_rollback(
                host, config, baseline, "restart", (restarted.stderr or "")[-200:]
            )

        try:
            report = check_health(host, config, staged, baseline)
        except _TIMEOUT_TYPES as exc:
            return _fail_with_rollback(
                host, config, baseline, "health", f"{type(exc).__name__}: {exc}"[-300:]
            )
        if not report.ok:
            return _fail_with_rollback(host, config, baseline, "health", report.detail)
    except Exception as exc:  # outer lifecycle guarantee after mutation
        if live_mutated:
            return _fail_with_rollback(
                host, config, baseline, "unexpected", f"{type(exc).__name__}: {exc}"[-300:]
            )
        return _receipt(host, config, "unknown", f"unexpected pre-mutation: {exc}"[-300:])

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
    """Durable resume for interruption (OnFailure/reboot): restore original.

    Uses ONLY the authenticated snapshot persisted BEFORE FIRST MUTATION.
    Never recaptures live state via preflight: a written candidate dropin
    or a stopped unit must not become the rollback baseline.
    """
    if has_terminal_receipt(host, config.journal_path):
        return CutoverResult(
            status="unknown",
            reason="journal already has a terminal receipt; refusing to re-run",
        )
    try:
        baseline = load_baseline(host, config)
    except SnapshotError as exc:
        return _receipt(host, config, "unknown", f"resume snapshot fail-closed: {exc}")
    try:
        errors = rollback(host, config, baseline)
    except (OSError, RuntimeError) as exc:
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
