"""Bound controller package manifest: root-installed vs candidate semantics.

Stdlib only. Root NEVER imports mutable candidate code; the child (as
`ubuntu`, `cwd=candidate`) is the only importer of candidate `pm` /
`hermes_bootstrap`. This module names the root-owned sibling set and
enforces the boundary in the root process.

The controller is an EXTERNAL tool. Its identity comes from the executing
facade (config.controller_path), never from candidate_src. Stock candidates
have no scripts/maintenance; a copy planted in the candidate must not
satisfy the gate. Provenance is a self-measured digest, never a signature:
there is no signature verifier, a root-owned copy is an operator install
snapshot, and ownership/mode is not attestation.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

EXPECTED_SIBLINGS = (
    "cutover.py",
    "cutover_types.py",
    "cutover_journal.py",
    "cutover_snapshot.py",
    "cutover_manifest.py",
    "cutover_git.py",
    "cutover_preflight.py",
    "cutover_receipt.py",
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


def _default_facade() -> Path:
    """Facade beside the running maintenance package (never the candidate)."""
    return Path(__file__).resolve().parent / "cutover.py"


def _facade_and_dir(controller_path: Path | None) -> tuple[Path, Path]:
    """Split an external controller path into (facade file, sibling dir)."""
    if controller_path is None:
        facade = _default_facade()
    else:
        facade = Path(controller_path)
    # Directory form (no .py suffix) means the controller dir itself.
    if facade.suffix != ".py":
        ctrl_dir = facade
        facade = ctrl_dir / "cutover.py"
    else:
        ctrl_dir = facade.parent
    return facade, ctrl_dir


def external_controller_provenance(host, controller_path: Path | None) -> dict:
    """Prove the EXTERNAL controller via host.read_bytes only (stdlib only).

    Reads every EXPECTED_SIBLINGS file beside the facade, checks the
    orchestrator/facade content markers, and records only honest fields.
    No signature is verified (none exists); digests are self-measured.
    """
    facade, ctrl_dir = _facade_and_dir(controller_path)
    sibling_sha256: dict[str, str] = {}
    contents: dict[str, bytes] = {}
    for name in EXPECTED_SIBLINGS:
        sibling = ctrl_dir / name
        try:
            data = host.read_bytes(sibling)
        except FileNotFoundError as exc:
            raise ManifestError(
                f"external controller missing: {sibling}: {exc}"
            ) from exc
        except OSError as exc:
            raise ManifestError(
                f"external controller unreadable: {sibling}: {exc}"
            ) from exc
        if not isinstance(data, (bytes, bytearray)):
            raise ManifestError(
                f"external controller refused: {sibling} did not return bytes"
            )
        raw = bytes(data)
        sibling_sha256[name] = hashlib.sha256(raw).hexdigest()
        contents[name] = raw
    orch = contents.get("cutover_orchestrate.py", b"")
    fac = contents.get("cutover.py", b"")
    if b"def orchestrate" not in orch:
        raise ManifestError(
            "external controller refused: sibling set lacks 'def orchestrate'"
        )
    if b"orchestrate" not in fac:
        raise ManifestError(
            "external controller refused: facade sibling lacks 'orchestrate'"
        )
    stat_available = False
    try:
        st = host.stat_file(facade)
    except NotImplementedError:
        stat_available = False
    except OSError:
        stat_available = False
    else:
        stat_available = True
        try:
            is_link = bool(getattr(st, "is_symlink", False))
            is_file = bool(getattr(st, "is_file", True))
        except Exception as exc:
            raise ManifestError(
                f"external controller refused: bad stat for {facade}: {exc}"
            ) from exc
        if is_link:
            raise ManifestError(
                f"external controller refused: symlink at {facade}"
            )
        if not is_file:
            raise ManifestError(
                f"external controller refused: not a regular file at {facade}"
            )
    root_installed = is_root_installed(facade)
    trust_limit = (
        "operator-install-snapshot-not-signature"
        if root_installed
        else "user-writable-source-untrusted-no-signature"
    )
    return {
        "controller_path": str(facade),
        "sibling_sha256": dict(sibling_sha256),
        "root_installed": bool(root_installed),
        "signed": False,
        "trust_limit": trust_limit,
        "stat_available": bool(stat_available),
    }
