"""Reversible rollback: source/facts/dropins, daemon-reload, restart, verify."""

from __future__ import annotations

import traceback

from scripts.maintenance.cutover_dropin import remove_candidate_dropins
from scripts.maintenance.cutover_health import check_rollback_health
from scripts.maintenance.cutover_journal import append
from scripts.maintenance.cutover_types import (
    Baseline,
    CutoverConfig,
    Host,
    facts_path_for,
)


class RestoreError(RuntimeError):
    pass


def _restore_source(host: Host, config: CutoverConfig, baseline: Baseline) -> None:
    res = host.run(
        ["git", "-C", str(config.live_tree), "rev-parse", "HEAD"], timeout=30
    )
    current = (res.stdout or "").strip() if res.returncode == 0 else ""
    if current == config.parent_sha:
        return
    back = host.run(
        ["git", "-C", str(config.live_tree), "checkout", "--detach", config.parent_sha],
        timeout=120,
    )
    if back.returncode != 0:
        raise RestoreError(f"source restore failed: {(back.stderr or '')[-300:]}")


def _restore_facts(host: Host, config: CutoverConfig, baseline: Baseline) -> None:
    try:
        host.write_bytes(facts_path_for(config.hermes_home), baseline.facts_bytes)
    except OSError as exc:
        raise RestoreError(f"facts restore failed: {exc}") from exc


def _restore_dropins(host: Host, config: CutoverConfig, baseline: Baseline) -> None:
    # Reversible bytes: remove what we added; restore any prior bytes we overwrote.
    # Baseline captured prior bytes for the candidate name (usually absent).
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
                raise RestoreError(
                    f"dropin restore failed for {target}: {exc}"
                ) from exc


def rollback(host: Host, config: CutoverConfig, baseline: Baseline) -> list[str]:
    """Restore in the mandated order. Never swallow: errors are returned + journaled."""
    errors: list[str] = []

    try:
        _restore_source(host, config, baseline)
    except RestoreError as exc:
        errors.append(str(exc))
        append(
            host,
            config.journal_path,
            "restore-source-failed",
            False,
            {"error": str(exc)},
        )

    if not errors:
        try:
            _restore_facts(host, config, baseline)
        except RestoreError as exc:
            errors.append(str(exc))
            append(
                host,
                config.journal_path,
                "restore-facts-failed",
                False,
                {"error": str(exc)},
            )

    if not errors:
        try:
            _restore_dropins(host, config, baseline)
        except RuntimeError as exc:
            errors.append(str(exc))
            append(
                host,
                config.journal_path,
                "restore-dropins-failed",
                False,
                {"error": str(exc)},
            )

    # daemon-reload before restart, restart before verify: never start-before-restore.
    if not errors:
        reloaded = host.run(["systemctl", "daemon-reload"], timeout=60)
        if reloaded.returncode != 0:
            errors.append(f"daemon-reload failed: {(reloaded.stderr or '')[-200:]}")
            append(
                host,
                config.journal_path,
                "restore-reload-failed",
                False,
                {
                    "stderr": (reloaded.stderr or "")[-300:],
                },
            )

    if not errors:
        restarted = host.run(
            ["systemctl", "restart", config.gateway_unit, config.dashboard_unit],
            timeout=180,
        )
        if restarted.returncode != 0:
            errors.append(f"restart failed: {(restarted.stderr or '')[-200:]}")
            append(
                host,
                config.journal_path,
                "restore-restart-failed",
                False,
                {
                    "stderr": (restarted.stderr or "")[-300:],
                },
            )

    if not errors:
        report = check_rollback_health(host, config)
        if not report.ok:
            errors.append(f"rollback verify failed: {report.detail}")
            append(
                host,
                config.journal_path,
                "restore-verify-failed",
                False,
                {
                    "detail": report.detail,
                },
            )

    if errors:
        append(
            host,
            config.journal_path,
            "rollback-errors",
            False,
            {
                "errors": errors,
                "trace": traceback.format_exc(limit=3),
            },
        )
    else:
        append(
            host,
            config.journal_path,
            "rollback-ok",
            True,
            {"parent": config.parent_sha},
        )
    return errors
