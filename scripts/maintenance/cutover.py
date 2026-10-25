"""Cutover facade: public entry points re-exported from topical siblings.

Behaviour lives in cutover_* siblings; this file only wires the CLI.
Stdlib only so a root-owned copy never imports mutable user modules.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scripts.maintenance.cutover_dropin import (
    render_dashboard_dropin,
    render_gateway_dropin,
)
from scripts.maintenance.cutover_health import check_health, check_rollback_health
from scripts.maintenance.cutover_journal import append, has_terminal_receipt, read_all
from scripts.maintenance.cutover_orchestrate import orchestrate, resume
from scripts.maintenance.cutover_preflight import PreflightError, preflight
from scripts.maintenance.cutover_restore import RestoreError, rollback
from scripts.maintenance.cutover_stage import StageError, stage, verify_isolated_launch
from scripts.maintenance.cutover_types import (
    Baseline,
    CutoverConfig,
    CutoverResult,
    Host,
    ProductionHost,
    RunResult,
    Staged,
    is_hex_sha,
)

__all__ = [
    "Baseline",
    "CutoverConfig",
    "CutoverResult",
    "Host",
    "PreflightError",
    "ProductionHost",
    "RestoreError",
    "RunResult",
    "StageError",
    "Staged",
    "append",
    "check_health",
    "check_rollback_health",
    "has_terminal_receipt",
    "is_hex_sha",
    "orchestrate",
    "preflight",
    "read_all",
    "render_dashboard_dropin",
    "render_gateway_dropin",
    "resume",
    "rollback",
    "stage",
    "verify_isolated_launch",
]


def _build_config(args: argparse.Namespace) -> CutoverConfig:
    return CutoverConfig(
        candidate_sha=args.candidate_sha,
        parent_sha=args.parent_sha,
        candidate_src=Path(args.candidate_src),
        live_tree=Path(args.live_tree),
        generation_root=Path(args.generation_root),
        journal_path=Path(args.journal),
        hermes_home=Path(args.hermes_home),
        gateway_unit=args.gateway_unit,
        dashboard_unit=args.dashboard_unit,
        gateway_dropin_dir=Path(args.gateway_dropin_dir),
        dashboard_dropin_dir=Path(args.dashboard_dropin_dir),
        candidate_dropin_name=args.candidate_dropin_name,
        dashboard_port=int(args.dashboard_port),
        controller_path=Path(__file__).resolve(),
    )


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--parent-sha", required=True)
    parser.add_argument("--candidate-src", required=True)
    parser.add_argument("--live-tree", required=True)
    parser.add_argument("--generation-root", required=True)
    parser.add_argument("--journal", required=True)
    parser.add_argument("--hermes-home", default="/home/ubuntu/.hermes")
    parser.add_argument("--gateway-unit", default="hermes-gateway.service")
    parser.add_argument("--dashboard-unit", default="hermes-dashboard.service")
    parser.add_argument(
        "--gateway-dropin-dir", default="/etc/systemd/system/hermes-gateway.service.d"
    )
    parser.add_argument(
        "--dashboard-dropin-dir",
        default="/etc/systemd/system/hermes-dashboard.service.d",
    )
    parser.add_argument("--candidate-dropin-name", default="zzz-candidate.conf")
    parser.add_argument("--dashboard-port", default="9119")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Hermes standalone runtime cutover controller"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("full", "preflight", "stage", "health", "rollback", "resume"):
        child = sub.add_parser(name)
        _add_common(child)
    args = parser.parse_args(argv)
    config = _build_config(args)
    host: Host = ProductionHost()
    if args.command == "full":
        result = orchestrate(host, config)
    elif args.command == "resume":
        result = resume(host, config)
    elif args.command == "preflight":
        try:
            preflight(host, config)
        except (PreflightError, OSError) as exc:
            print(f"preflight fail-closed: {exc}", file=sys.stderr)
            return 2
        print("preflight ok")
        return 0
    elif args.command == "stage":
        try:
            baseline = preflight(host, config)
            staged = stage(host, config)
            verify_isolated_launch(host, config, staged, baseline.live_main_exe)
        except (PreflightError, StageError, OSError, RuntimeError) as exc:
            print(f"stage failed: {exc}", file=sys.stderr)
            return 1
        print(f"staged {staged.generation_dir}")
        return 0
    elif args.command == "health":
        try:
            baseline = preflight(host, config)
            staged = stage(host, config)
        except (PreflightError, StageError, OSError, RuntimeError) as exc:
            print(f"health setup failed: {exc}", file=sys.stderr)
            return 2
        report = check_health(host, config, staged)
        print(report.detail)
        return 0 if report.ok else 1
    else:  # rollback
        try:
            baseline = preflight(host, config)
        except (PreflightError, OSError) as exc:
            print(f"rollback preflight fail-closed: {exc}", file=sys.stderr)
            return 2
        errors = rollback(host, config, baseline)
        if errors:
            print(f"rollback errors: {'; '.join(errors)}", file=sys.stderr)
            return 1
        print("rollback ok")
        return 0
    print(f"{result.status}: {result.reason}")
    return 0 if result.status == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
