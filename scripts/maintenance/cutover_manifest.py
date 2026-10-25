"""Bound controller package manifest: root-installed vs candidate semantics.

Stdlib only. Root NEVER imports mutable candidate code; the child (as
`ubuntu`, `cwd=candidate`) is the only importer of candidate `pm` /
`hermes_bootstrap`. This module names the root-owned sibling set and
enforces the boundary in the root process.
"""

from __future__ import annotations

import sys
from pathlib import Path

EXPECTED_SIBLINGS = (
    "cutover.py",
    "cutover_types.py",
    "cutover_journal.py",
    "cutover_snapshot.py",
    "cutover_manifest.py",
    "cutover_preflight.py",
    "cutover_stage.py",
    "cutover_dropin.py",
    "cutover_health.py",
    "cutover_restore.py",
    "cutover_orchestrate.py",
)

ROOT_PREFIX = Path("/opt/hermes-maintenance")


class ManifestError(RuntimeError):
    pass


def is_root_installed(controller_path: Path | None) -> bool:
    if controller_path is None:
        return False
    try:
        return Path(controller_path).resolve().is_relative_to(ROOT_PREFIX.resolve())
    except (OSError, RuntimeError):
        return False


def assert_no_candidate_import(candidate_src: Path) -> None:
    """Refuse when the mutable candidate tree is on the root sys.path."""
    try:
        needle = str(Path(candidate_src).resolve())
    except OSError:
        return
    for entry in sys.path:
        if not entry or entry in ("", "."):
            continue
        try:
            resolved = str(Path(entry).resolve())
        except OSError:
            continue
        if resolved == needle:
            raise ManifestError(
                f"root process must not import mutable candidate: {needle} on sys.path"
            )
