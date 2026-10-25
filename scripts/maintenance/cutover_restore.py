"""Reversible rollback: source/facts/dropins, daemon-reload, restart, verify.

DESIGN v2: provenance-bound (baseline must name parent/candidate SHAs),
restores the REAL selection facts (installs/<key>/facts.json), never
start-before-restore, every error journaled + returned.
"""

from __future__ import annotations

import subprocess
import traceback

from scripts.maintenance.cutover_dropin import remove_candidate_dropins
from scripts.maintenance.cutover_health import check_rollback_health
from scripts.maintenance.cutover_journal import append
from scripts.maintenance.cutover_types import (
    Baseline,
    CutoverConfig,
    Host,
)


class RestoreError(RuntimeError):
    pass


def _check_provenance(config: CutoverConfig, baseline: Baseline) -> None:
    if baseline.live_head != config.parent_sha:
        raise RestoreError(
            f"baseline live HEAD {baseline.live_head[:12]} != parent {config.parent_sha[:12]}"
        )
    if baseline.candidate_head != config.candidate_sha:
        raise RestoreError("baseline candidate HEAD != candidate SHA")
    if not baseline.facts_bytes:
        raise RestoreError("baseline has no selection facts bytes to restore")
    if not baseline.selection_facts_path or str(baseline.selection_facts_path) in ("", "."):
        raise RestoreError("baseline has no selection facts path")


def _restore_source(host: Host, config: CutoverConfig, baseline: Baseline) -> None:
    try:
        res = host.run(
            ["git", "-C", str(config.live_tree), "rev-parse", "HEAD"], timeout=30
        )
    except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        raise RestoreError(f"source HEAD read failed: {type(exc).__name__}: {exc}") from exc
    current = (res.stdout or "").strip() if res.returncode == 0 else ""
    if current == config.parent_sha:
        return
    try:
        back = host.run(
            ["git", "-C", str(config.live_tree), "checkout", "--detach", config.parent_sha],
            timeout=120,
        )
    except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        raise RestoreError(
            f"source restore transport failed: {type(exc).__name__}: {exc}"
        ) from exc
    if back.returncode != 0:
        raise RestoreError(f"source restore failed: {(back.stderr or '')[-300:]}")


def _restore_facts(host: Host, config: CutoverConfig, baseline: Baseline) -> None:
    try:
        host.write_bytes(baseline.selection_facts_path, baseline.facts_bytes)
    except OSError as exc:
        raise RestoreError(f"selection facts restore failed: {exc}") from exc


def _restore_dropins(host: Host, config: CutoverConfig, baseline: Baseline) -> None:
    remove_candidate_dropins(host, config)
    for dropin_dir, snapshot in (
        (config.gateway_dropin_dir, baseline.gateway_dropin_bytes),
        (config.dashboard_dropin_dir, baseline.dashboard_dropin_bytes),
    ):
        prior = snapshot.get(config.candidate_dropin_name)
        if prior is not None:
            target = dropin_dir / config.candidate_dropin_name
            try:
                host.write_bytes(target, prior)
            except OSError as exc:
                raise RestoreError(f"dropin restore failed for {target}: {exc}") from exc


def rollback(host: Host, config: CutoverConfig, baseline: Baseline) -> list[str]:
    """Restore in the mandated order. Never swallow: errors are returned + journaled."""
    errors: list[str] = []
    try:
        _check_provenance(config, baseline)
    except RestoreError as exc:
        msg = f"rollback provenance refused: {exc}"
        append(host, config.journal_path, "restore-provenance-failed", False, {"error": msg})
        return [msg]

    try:
        _restore_source(host, config, baseline)
    except RestoreError as exc:
        errors.append(str(exc))
        append(host, config.journal_path, "restore-source-failed", False, {"error": str(exc)})

    if not errors:
        try:
            _restore_facts(host, config, baseline)
        except RestoreError as exc:
            errors.append(str(exc))
            append(host, config.journal_path, "restore-facts-failed", False, {"error": str(exc)})

    if not errors:
        try:
            _restore_dropins(host, config, baseline)
        except RuntimeError as exc:
            errors.append(str(exc))
            append(host, config.journal_path, "restore-dropins-failed", False, {"error": str(exc)})

    if not errors:
        try:
            reloaded = host.run(["systemctl", "daemon-reload"], timeout=60)
        except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
            errors.append(f"daemon-reload transport failed: {type(exc).__name__}: {exc}"[-300:])
            append(
                host, config.journal_path, "restore-reload-failed", False,
                {"error": errors[-1][-300:]},
            )
            reloaded = None
        if reloaded is not None and reloaded.returncode != 0:
            errors.append(f"daemon-reload failed: {(reloaded.stderr or '')[-200:]}")
            append(
                host, config.journal_path, "restore-reload-failed", False,
                {"stderr": (reloaded.stderr or "")[-300:]},
            )

    if not errors:
        try:
            restarted = host.run(
                ["systemctl", "restart", config.gateway_unit, config.dashboard_unit],
                timeout=180,
            )
        except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
            errors.append(f"restart transport failed: {type(exc).__name__}: {exc}"[-300:])
            append(
                host, config.journal_path, "restore-restart-failed", False,
                {"error": errors[-1][-300:]},
            )
            restarted = None
        if restarted is not None and restarted.returncode != 0:
            errors.append(f"restart failed: {(restarted.stderr or '')[-200:]}")
            append(
                host, config.journal_path, "restore-restart-failed", False,
                {"stderr": (restarted.stderr or "")[-300:]},
            )

    if not errors:
        try:
            report = check_rollback_health(host, config)
        except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
            errors.append(
                f"rollback verify transport failed: {type(exc).__name__}: {exc}"[-300:]
            )
            append(
                host, config.journal_path, "restore-verify-failed", False,
                {"error": errors[-1][-300:]},
            )
            report = None
        if report is not None and not report.ok:
            errors.append(f"rollback verify failed: {report.detail}")
            append(host, config.journal_path, "restore-verify-failed", False, {"detail": report.detail})

    if errors:
        append(
            host, config.journal_path, "rollback-errors", False,
            {"errors": errors, "trace": traceback.format_exc(limit=3)},
        )
    else:
        append(host, config.journal_path, "rollback-ok", True, {"parent": config.parent_sha})
    return errors
