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


def _strict_sibling_identity(host, sibling: Path) -> tuple[int, int]:
    """No-follow lstat for one sibling; fail closed on any uncertainty.

    Returns (st_dev, st_ino). Refuses NotImplementedError, OSError (other
    than FileNotFoundError which the caller maps to missing), a missing
    stat method, a non-FileStat result, non-bool is_symlink/is_file, any
    exception while reading identity fields, non-int dev/ino, symlinks,
    and non-regular files. FileNotFoundError propagates for missing.
    """
    from scripts.maintenance.cutover_types import FileStat as _FileStat

    stat_fn = getattr(host, "stat_file", None)
    if stat_fn is None or not callable(stat_fn):
        raise ManifestError(
            f"external controller refused: no lstat for {sibling}"
        )
    try:
        st = stat_fn(sibling)
    except FileNotFoundError:
        raise
    except NotImplementedError as exc:
        raise ManifestError(
            f"external controller refused: uncertain identity for {sibling}: {exc}"
        ) from exc
    except OSError as exc:
        raise ManifestError(
            f"external controller refused: uncertain identity for {sibling}: {exc}"
        ) from exc
    except Exception as exc:
        raise ManifestError(
            f"external controller refused: uncertain identity for {sibling}: {exc}"
        ) from exc
    try:
        if not isinstance(st, _FileStat):
            raise ManifestError(
                f"external controller refused: bad stat type for {sibling}"
            )
        try:
            raw_link = st.is_symlink
            raw_file = st.is_file
        except Exception as exc:
            raise ManifestError(
                f"external controller refused: bad stat for {sibling}: {exc}"
            ) from exc
        if not isinstance(raw_link, bool) or not isinstance(raw_file, bool):
            raise ManifestError(
                f"external controller refused: bad stat fields for {sibling}"
            )
        try:
            raw_dev = st.dev
            raw_ino = st.ino
        except Exception as exc:
            raise ManifestError(
                f"external controller refused: bad identity for {sibling}: {exc}"
            ) from exc
        if type(raw_dev) is not int or type(raw_ino) is not int:
            raise ManifestError(
                f"external controller refused: uncertain device/inode for {sibling}"
            )
        if raw_link:
            raise ManifestError(
                f"external controller refused: symlink at {sibling}"
            )
        if not raw_file:
            raise ManifestError(
                f"external controller refused: not a regular file at {sibling}"
            )
        return raw_dev, raw_ino
    except ManifestError:
        raise
    except Exception as exc:
        raise ManifestError(
            f"external controller refused: bad stat for {sibling}: {exc}"
        ) from exc


def _bound_sibling_bytes(host, sibling: Path) -> tuple[bytes, int, int]:
    """Read one sibling via the explicit no-follow bound read only.

    Never falls back to host.read_bytes. Missing method or
    NotImplementedError fails closed. FileNotFoundError propagates for
    missing. Other OSError fails closed as unreadable/identity failure.
    """
    bound = getattr(host, "read_bytes_nofollow", None)
    if bound is None or not callable(bound):
        raise ManifestError(
            f"external controller refused: no no-follow bound read for {sibling}"
        )
    try:
        result = bound(sibling)
    except FileNotFoundError:
        raise
    except NotImplementedError as exc:
        raise ManifestError(
            f"external controller refused: no-follow bound read unavailable for {sibling}: {exc}"
        ) from exc
    except OSError as exc:
        raise ManifestError(
            f"external controller refused: no-follow read failed for {sibling}: {exc}"
        ) from exc
    except Exception as exc:
        raise ManifestError(
            f"external controller refused: no-follow read failed for {sibling}: {exc}"
        ) from exc
    try:
        if not isinstance(result, tuple) or len(result) != 3:
            raise ManifestError(
                f"external controller refused: bad bound read for {sibling}"
            )
        data, bdev, bino = result
        if not isinstance(data, (bytes, bytearray)):
            raise ManifestError(
                f"external controller refused: {sibling} did not return bytes"
            )
        if type(bdev) is not int or type(bino) is not int:
            raise ManifestError(
                f"external controller refused: bad bound identity for {sibling}"
            )
        return bytes(data), bdev, bino
    except ManifestError:
        raise
    except Exception as exc:
        raise ManifestError(
            f"external controller refused: bad bound read for {sibling}: {exc}"
        ) from exc


def _refuse_candidate_alias(
    host, sibling: Path, name: str, dev: int, ino: int, candidate_src: Path
) -> None:
    """Refuse resolved-inside-candidate and same-name hardlink aliases."""
    try:
        cand_res = Path(candidate_src).resolve()
    except OSError as exc:
        raise ManifestError(
            f"external controller missing: cannot resolve candidate {candidate_src}: {exc}"
        ) from exc
    try:
        sib_res = Path(sibling).resolve()
    except OSError as exc:
        raise ManifestError(
            f"external controller refused: cannot resolve {sibling}: {exc}"
        ) from exc
    try:
        inside = sib_res == cand_res or sib_res.is_relative_to(cand_res)
    except (OSError, RuntimeError, ValueError):
        c_str = str(cand_res)
        f_str = str(sib_res)
        inside = f_str == c_str or f_str.startswith(c_str.rstrip("/") + "/")
    if inside:
        raise ManifestError(
            f"external controller refused: resolved path inside candidate_src: {sib_res}"
        )
    candidate_same = Path(candidate_src) / "scripts" / "maintenance" / name
    stat_fn = getattr(host, "stat_file", None)
    if stat_fn is None or not callable(stat_fn):
        raise ManifestError(
            f"external controller refused: uncertain candidate alias identity for {candidate_same}"
        )
    try:
        cst = stat_fn(candidate_same)
    except FileNotFoundError:
        return
    except NotImplementedError as exc:
        raise ManifestError(
            f"external controller refused: uncertain candidate alias identity for {candidate_same}: {exc}"
        ) from exc
    except OSError as exc:
        raise ManifestError(
            f"external controller refused: uncertain candidate alias identity for {candidate_same}: {exc}"
        ) from exc
    except Exception as exc:
        raise ManifestError(
            f"external controller refused: uncertain candidate alias identity for {candidate_same}: {exc}"
        ) from exc
    try:
        from scripts.maintenance.cutover_types import FileStat as _FileStat

        if not isinstance(cst, _FileStat):
            raise ManifestError(
                f"external controller refused: uncertain candidate alias identity for {candidate_same}"
            )
        try:
            cdev = cst.dev
            cino = cst.ino
        except Exception as exc:
            raise ManifestError(
                f"external controller refused: uncertain candidate alias identity for {candidate_same}: {exc}"
            ) from exc
        if type(cdev) is not int or type(cino) is not int:
            raise ManifestError(
                f"external controller refused: uncertain candidate alias identity for {candidate_same}"
            )
        if type(dev) is not int or type(ino) is not int:
            raise ManifestError(
                f"external controller refused: uncertain device/inode for {sibling}"
            )
        if cdev == dev and cino == ino:
            raise ManifestError(
                f"external controller refused: same device/inode as candidate {candidate_same}"
            )
    except ManifestError:
        raise
    except Exception as exc:
        raise ManifestError(
            f"external controller refused: uncertain candidate alias identity for {candidate_same}: {exc}"
        ) from exc


def external_controller_provenance(
    host, controller_path: Path | None, candidate_src: Path | None = None
) -> dict:
    """Prove the EXTERNAL controller via no-follow bound reads only.

    Every EXPECTED_SIBLINGS name is identity-bound before its bytes are
    accepted: no-follow lstat plus O_NOFOLLOW open/fstat/read, with
    lstat dev/ino == fd dev/ino, regular file, never a symlink. Uncertain
    lstat fails closed for every sibling. Candidate copies/aliases never
    satisfy the gate. Digests bind the fd bytes; signed is always False.
    This measurement is not a kernel-immutable generation: a same-UID
    writer can replace an inode after preflight and before a later import.
    """
    facade, ctrl_dir = _facade_and_dir(controller_path)
    sibling_sha256: dict[str, str] = {}
    sibling_stat: dict[str, dict[str, int]] = {}
    contents: dict[str, bytes] = {}
    for name in EXPECTED_SIBLINGS:
        sibling = ctrl_dir / name
        try:
            dev, ino = _strict_sibling_identity(host, sibling)
        except FileNotFoundError as exc:
            raise ManifestError(
                f"external controller missing: {sibling}: {exc}"
            ) from exc
        try:
            raw, bdev, bino = _bound_sibling_bytes(host, sibling)
        except FileNotFoundError as exc:
            raise ManifestError(
                f"external controller missing: {sibling}: {exc}"
            ) from exc
        if bdev != dev or bino != ino:
            raise ManifestError(
                f"external controller refused: identity changed for {sibling}"
            )
        if candidate_src is not None and str(candidate_src) not in ("", "."):
            _refuse_candidate_alias(host, sibling, name, dev, ino, Path(candidate_src))
        sibling_sha256[name] = hashlib.sha256(raw).hexdigest()
        sibling_stat[name] = {"dev": dev, "ino": ino}
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
    root_installed = is_root_installed(facade)
    trust_limit = (
        "operator-install-snapshot-not-signature"
        if root_installed
        else "user-writable-source-untrusted-no-signature"
    )
    return {
        "controller_path": str(facade),
        "sibling_sha256": dict(sibling_sha256),
        "sibling_stat": {k: dict(v) for k, v in sibling_stat.items()},
        "root_installed": bool(root_installed),
        "signed": False,
        "trust_limit": trust_limit,
        "stat_available": True,
    }
