"""Cutover facade: public entry points re-exported from topical siblings.

Behaviour lives in cutover_* siblings; this file only wires the CLI.
Stdlib only so a root-owned copy never imports mutable user modules.

DESIGN v2: runs under `python3 -I -B <abs path>/cutover.py` with NO PYTHONPATH.
The preamble inserts the root-owned prefix (`/opt/hermes-maintenance`) at
sys.path[0] via stdlib pathlib and pops PYTHON* vars like the real launcher,
so `-I` isolation does not break imports and no user PYTHONPATH is honored.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# --- Safe sys.path for -I isolation (no PYTHONPATH) ---
# When installed root-owned at /opt/hermes-maintenance/scripts/maintenance/,
# the layout is /opt/hermes-maintenance/scripts/maintenance/cutover.py with
# siblings beside it and the `scripts` package two levels up:
#   <prefix>/scripts/maintenance/cutover.py
#   <prefix>/ == sys.path entry so `scripts.maintenance.*` resolves to
#   root-owned bytes. In a checkout (tests), this file lives at
#   <repo>/scripts/maintenance/cutover.py, so the repo root is the entry.
# Never trust PYTHONPATH under -I (it is ignored for sys.path by design).
_here = Path(__file__).resolve()
_prefix_candidate = _here.parent.parent.parent
_repo_candidate = _here.parent.parent.parent
# Prefer the root-owned prefix when it exists and holds our siblings;
# otherwise fall back to the enclosing repo checkout (tests).
_safe_entry: Path | None = None
for _cand in (_prefix_candidate, _repo_candidate):
    try:
        if ((_cand / "scripts" / "maintenance" / "cutover.py").is_file()
                or (_cand / "scripts.maintenance").exists()):
            _safe_entry = _cand
            break
    except OSError:
        continue
if _safe_entry is None:
    # Last resort: walk up until a `scripts/maintenance` dir is found.
    for _parent in (*_here.parents,):
        try:
            if (_parent / "scripts" / "maintenance" / "cutover.py").is_file():
                _safe_entry = _parent
                break
            if (_parent.name == "scripts" and (_parent / "maintenance" / "cutover.py").is_file()):
                _safe_entry = _parent.parent
                break
        except OSError:
            continue
if _safe_entry is not None:
    _entry_str = str(_safe_entry)
    if _entry_str not in sys.path:
        sys.path.insert(0, _entry_str)
for _var in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"):
    os.environ.pop(_var, None)

import argparse
from pathlib import Path as _Path

from scripts.maintenance.cutover_dropin import (
    render_dashboard_dropin,
    render_gateway_dropin,
)
from scripts.maintenance.cutover_health import check_health, check_rollback_health, wait_for_health
from scripts.maintenance.cutover_journal import append, has_terminal_receipt, read_all
from scripts.maintenance.cutover_receipt import ReceiptError, load_prior_activation
from scripts.maintenance.cutover_git import (
    git_inner_argv,
    owner_git_env,
    run_owner_git,
    wrap_owner_git,
)
from scripts.maintenance.cutover_manifest import (
    EXPECTED_SIBLINGS,
    ManifestError,
    assert_no_candidate_import,
    is_root_installed,
)
from scripts.maintenance.cutover_orchestrate import orchestrate, resume
from scripts.maintenance.cutover_preflight import PreflightError, preflight
from scripts.maintenance.cutover_restore import RestoreError, rollback
from scripts.maintenance.cutover_snapshot import SnapshotError, load_baseline, save_baseline
from scripts.maintenance.cutover_stage import (
    StageError,
    selected_extras_from_facts,
    stage,
    verify_candidate_help,
    verify_candidate_web_dist,
    verify_isolated_launch,
    verify_staged_extras,
)
from scripts.maintenance.cutover_types import (
    Baseline,
    CutoverConfig,
    CutoverResult,
    FileStat,
    Host,
    ProductionHost,
    RunResult,
    Staged,
    is_hex_sha,
    snapshot_path_for,
)

__all__ = [
    "EXPECTED_SIBLINGS",
    "Baseline",
    "CutoverConfig",
    "CutoverResult",
    "FileStat",
    "Host",
    "ManifestError",
    "PreflightError",
    "ProductionHost",
    "ReceiptError",
    "RestoreError",
    "RunResult",
    "SnapshotError",
    "StageError",
    "Staged",
    "append",
    "assert_no_candidate_import",
    "check_health",
    "check_rollback_health",
    "git_inner_argv",
    "has_terminal_receipt",
    "is_hex_sha",
    "is_root_installed",
    "load_baseline",
    "load_prior_activation",
    "orchestrate",
    "owner_git_env",
    "preflight",
    "read_all",
    "render_dashboard_dropin",
    "render_gateway_dropin",
    "resume",
    "rollback",
    "run_owner_git",
    "save_baseline",
    "selected_extras_from_facts",
    "snapshot_path_for",
    "stage",
    "verify_candidate_help",
    "verify_candidate_web_dist",
    "verify_isolated_launch",
    "verify_staged_extras",
    "wait_for_health",
    "wrap_owner_git",
]


def _build_config(args: argparse.Namespace) -> CutoverConfig:
    receipt_raw = getattr(args, "baseline_receipt", None)
    receipt_path = _Path(receipt_raw) if receipt_raw else None
    return CutoverConfig(
        candidate_sha=args.candidate_sha,
        parent_sha=args.parent_sha,
        candidate_src=_Path(args.candidate_src),
        live_tree=_Path(args.live_tree),
        generation_root=_Path(args.generation_root),
        journal_path=_Path(args.journal),
        hermes_home=_Path(args.hermes_home),
        gateway_unit=args.gateway_unit,
        dashboard_unit=args.dashboard_unit,
        gateway_dropin_dir=_Path(args.gateway_dropin_dir),
        dashboard_dropin_dir=_Path(args.dashboard_dropin_dir),
        candidate_dropin_name=args.candidate_dropin_name,
        dashboard_port=int(args.dashboard_port),
        controller_path=_here,
        baseline_receipt=receipt_path,
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
    parser.add_argument("--gateway-dropin-dir", default="/etc/systemd/system/hermes-gateway.service.d")
    parser.add_argument("--dashboard-dropin-dir", default="/etc/systemd/system/hermes-dashboard.service.d")
    parser.add_argument("--candidate-dropin-name", default="zzz-candidate.conf")
    parser.add_argument("--dashboard-port", default="9119")
    parser.add_argument(
        "--baseline-receipt",
        default=None,
        help=(
            "Optional root-owned prior activation receipt for second-cutover "
            "migration (e.g. /var/lib/hermes-cutover/activation-<parent12>.jsonl). "
            "When set, preflight binds owner/mode/non-symlink/type/path, "
            "receipt candidate==parent, live cmdline generation==prior stage, "
            "terminal success, and derives extras from stage-ok. Facts stay "
            "optional; no blank facts are invented."
        ),
    )


def _cmd_full(host: Host, config: CutoverConfig) -> int:
    result = orchestrate(host, config)
    print(f"{result.status}: {result.reason}")
    return 0 if result.status == "success" else 1


def _cmd_resume(host: Host, config: CutoverConfig) -> int:
    result = resume(host, config)
    print(f"{result.status}: {result.reason}")
    return 0 if result.status == "success" else 1


def _cmd_preflight(host: Host, config: CutoverConfig) -> int:
    try:
        preflight(host, config)
    except (PreflightError, ReceiptError, OSError) as exc:
        print(f"preflight fail-closed: {exc}", file=sys.stderr)
        return 2
    print("preflight ok")
    return 0


def _extras_for_verify(baseline: Baseline) -> tuple[list[str], bool]:
    # Mirrors stage(): facts win, otherwise prior receipt extras.
    if baseline.facts_bytes:
        return selected_extras_from_facts(baseline.facts_bytes)
    if str(getattr(baseline, "prior_generation", "") or "") not in ("", "."):
        return (sorted(set(str(x) for x in (baseline.prior_extras or ()))), bool(baseline.prior_all_extras))
    return ([], False)


def _cmd_stage(host: Host, config: CutoverConfig) -> int:
    try:
        baseline = preflight(host, config)
        staged = stage(host, config, baseline)
        verify_isolated_launch(host, config, staged, baseline.live_main_exe)
        verify_candidate_web_dist(host, config)
        extras, use_all = _extras_for_verify(baseline)
        verify_staged_extras(host, config, staged, extras, use_all)
        verify_candidate_help(host, config, staged)
    except (PreflightError, ReceiptError, StageError, OSError, RuntimeError) as exc:
        print(f"stage failed: {exc}", file=sys.stderr)
        return 1
    print(f"staged {staged.generation_dir}")
    return 0


def _cmd_health(host: Host, config: CutoverConfig) -> int:
    try:
        baseline = preflight(host, config)
        staged = stage(host, config, baseline)
    except (PreflightError, ReceiptError, StageError, OSError, RuntimeError) as exc:
        print(f"health setup failed: {exc}", file=sys.stderr)
        return 2
    report = check_health(host, config, staged, baseline)
    print(report.detail)
    return 0 if report.ok else 1


def _cmd_rollback(host: Host, config: CutoverConfig) -> int:
    try:
        baseline = load_baseline(host, config)
    except SnapshotError:
        try:
            baseline = preflight(host, config)
        except (PreflightError, ReceiptError, OSError) as exc:
            print(f"rollback preflight fail-closed: {exc}", file=sys.stderr)
            return 2
    errors = rollback(host, config, baseline)
    if errors:
        print(f"rollback errors: {'; '.join(errors)}", file=sys.stderr)
        return 1
    print("rollback ok")
    return 0


_COMMANDS = {
    "full": _cmd_full,
    "resume": _cmd_resume,
    "preflight": _cmd_preflight,
    "stage": _cmd_stage,
    "health": _cmd_health,
    "rollback": _cmd_rollback,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hermes standalone runtime cutover controller")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in _COMMANDS:
        child = sub.add_parser(name)
        _add_common(child)
    args = parser.parse_args(argv)
    config = _build_config(args)
    host: Host = ProductionHost()
    handler = _COMMANDS.get(args.command)
    if handler is None:
        parser.error(f"unknown command {args.command!r}")
    return handler(host, config)


if __name__ == "__main__":
    raise SystemExit(main())
