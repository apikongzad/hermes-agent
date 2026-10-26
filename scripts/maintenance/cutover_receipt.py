"""Prior-activation receipt for second-cutover migration. Stdlib only.

First cutover moved the fleet from a direct checkout (main 50e82) to a side
generation (gen-1d9a...) via zzz-candidate.conf. The second cutover's parent
is that side generation (1d9a...), not the original main HEAD. The live
selection facts path derived from live_tree
(<home>/installs/<key>/facts.json) belongs to the old worktree key and is
likely absent -- PM never installed that worktree directly, it staged a side
generation. Refusing on "selection facts missing" would block the migration.

This module binds the root-owned PREVIOUS activation receipt instead:
  /var/lib/hermes-cutover/activation-<hex>.jsonl
which the parent verified (receipt-success for candidate==parent, stage-ok
with all_extras/true extras list, generation/home/venv matching the running
Gateway+Dashboard argv). The CLI passes --baseline-receipt; preflight
validates it BEFORE any mutation and derives baseline extras from its
stage-ok. No blank facts are invented and no PM facts are rewritten for the
side generation.

Trust rule: stat (owner/mode/non-symlink/type/path) is checked FIRST via
Host.stat_file (lstat, no follow). Only a root-owned, mode-hardened regular
file that is a direct child of /var/lib/hermes-cutover/ is trusted, and the
parent dir itself must be root-owned 0700 (no symlink). Candidate values
inside the receipt are NEVER an independent trust root when the caller
supplied no root ownership -- malformed/stale/wrong-generation receipts
refuse fail-closed. The filename is informational only; the authoritative
bind is receipt-success candidate == parent_sha exact.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from scripts.maintenance.cutover_types import CutoverConfig, FileStat, Host

RECEIPT_DIR = Path("/var/lib/hermes-cutover")
# Activation files are activation-<hex>.jsonl (observed
# activation-1d9a377fa0.jsonl carries 10 hex chars). The filename is
# informational only; the authoritative bind remains receipt-success
# candidate==parent_sha exact. Accept 8-40 hex for shape only.
RECEIPT_RE = re.compile(r"^activation-([0-9a-fA-F]{8,40})\.jsonl$")
EXTRA_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


class ReceiptError(RuntimeError):
    pass


@dataclass(frozen=True)
class PriorActivation:
    candidate_sha: str
    generation: Path
    venv_python: Path
    home: str
    extras: tuple[str, ...]
    all_extras: bool
    receipt_path: Path


def _receipt_path_ok(path: Path) -> str:
    """Validate path shape; return the hex id from the basename (informational)."""
    try:
        p = Path(path)
    except (ValueError, TypeError) as exc:
        raise ReceiptError(f"baseline receipt path invalid: {exc}") from exc
    if not p.is_absolute():
        raise ReceiptError("baseline receipt must be an absolute path")
    # No symlink escape: the string must already live under the allowed dir.
    # Host.stat_file (lstat) additionally refuses symlinks on the live file.
    try:
        rel = p.relative_to(RECEIPT_DIR)
    except ValueError:
        raise ReceiptError(
            f"baseline receipt must live under {RECEIPT_DIR} (refusing)"
        ) from None
    if ".." in rel.parts or str(path) != str(p):
        raise ReceiptError("baseline receipt path must be canonical (refusing)")
    # Direct child only: no subdir escape under the fixed root.
    if len(rel.parts) != 1 or p.parent != RECEIPT_DIR:
        raise ReceiptError(
            f"baseline receipt must be a direct child of {RECEIPT_DIR} (refusing)"
        )
    m = RECEIPT_RE.match(p.name)
    if not m:
        raise ReceiptError(
            "baseline receipt name must be activation-<hex>.jsonl (refusing)"
        )
    return m.group(1).lower()


def _check_receipt_dir(host: Host) -> None:
    """Bind the fixed parent dir: root-owned 0700, no symlink (lstat)."""
    try:
        st = host.stat_file(RECEIPT_DIR)
    except FileNotFoundError as exc:
        raise ReceiptError(f"baseline receipt parent dir missing: {RECEIPT_DIR}") from exc
    except OSError as exc:
        raise ReceiptError(f"baseline receipt parent dir stat failed: {exc}") from exc
    if st.is_symlink:
        raise ReceiptError("baseline receipt parent dir must not be a symlink (refusing)")
    if st.is_file:
        raise ReceiptError("baseline receipt parent dir must be a directory (refusing)")
    if int(st.uid) != 0:
        raise ReceiptError("baseline receipt parent dir must be root-owned (refusing)")
    if (int(st.mode) & 0o777) != 0o700:
        raise ReceiptError(
            "baseline receipt parent dir mode must be 0700 (refusing)"
        )


def _check_stat(path: Path, st: FileStat) -> None:
    if st.is_symlink:
        raise ReceiptError("baseline receipt must not be a symlink (refusing)")
    if not st.is_file:
        raise ReceiptError("baseline receipt must be a regular file (refusing)")
    if int(st.uid) != 0:
        raise ReceiptError("baseline receipt must be root-owned (refusing)")
    mode = int(st.mode)
    # Owner must be able to read; no group/other permissions at all.
    if (mode & 0o400) == 0:
        raise ReceiptError("baseline receipt must be owner-readable (refusing)")
    if (mode & 0o077) != 0:
        raise ReceiptError(
            "baseline receipt mode must grant no group/other access (refusing)"
        )
    # No execute bits in any scope: 0600/0400 only, never 0700.
    if (mode & 0o111) != 0:
        raise ReceiptError(
            "baseline receipt mode must grant no execute access (refusing)"
        )


def _clean_extras(raw: object) -> tuple[list[str], bool]:
    if not isinstance(raw, dict):
        raise ReceiptError("receipt stage-ok detail is not an object")
    extras_raw = raw.get("extras", [])
    if not isinstance(extras_raw, list):
        raise ReceiptError("receipt stage-ok extras is not a list")
    cleaned: list[str] = []
    for item in extras_raw:
        if not isinstance(item, str) or not item.strip():
            raise ReceiptError("receipt stage-ok contains a non-string extra")
        name = item.strip()
        if not EXTRA_RE.match(name):
            raise ReceiptError(f"receipt stage-ok has invalid extra {name!r}")
        cleaned.append(name)
    cleaned = sorted(set(cleaned))
    use_all = raw.get("all_extras", False)
    if not isinstance(use_all, bool):
        # Older journals may record 0/1; accept ints strictly as bool.
        if use_all in (0, 1):
            use_all = bool(use_all)
        else:
            raise ReceiptError("receipt stage-ok all_extras is not a bool")
    return cleaned, bool(use_all)


def _read_receipt_rows(host: Host, receipt_path: Path) -> list[dict]:
    """Read bytes -> UTF-8 -> JSONL rows. Fail-closed on any malformation."""
    try:
        raw = host.read_bytes(receipt_path)
    except FileNotFoundError as exc:
        raise ReceiptError(f"baseline receipt missing: {receipt_path}") from exc
    except OSError as exc:
        raise ReceiptError(f"baseline receipt unreadable: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReceiptError(f"baseline receipt is not UTF-8: {exc}") from exc
    rows: list[dict] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError as exc:
            raise ReceiptError(
                f"baseline receipt line {lineno} is not JSON (malformed)"
            ) from exc
        if not isinstance(item, dict):
            raise ReceiptError(
                f"baseline receipt line {lineno} is not an object (malformed)"
            )
        rows.append(item)
    if not rows:
        raise ReceiptError("baseline receipt is empty (malformed)")
    return rows


def _select_stage_ok(rows: list[dict]) -> dict:
    """Last stage-ok wins (resume may append); keep iterating."""
    stage_ok: dict | None = None
    for row in rows:
        if row.get("phase") == "stage-ok" and isinstance(row.get("detail"), dict):
            stage_ok = row
    if stage_ok is None:
        raise ReceiptError("baseline receipt has no stage-ok (stale/malformed)")
    return stage_ok


def _select_terminal(rows: list[dict]) -> dict:
    """Last phase starting with receipt- must be receipt-success."""
    terminal: dict | None = None
    for row in reversed(rows):
        phase = str(row.get("phase") or "")
        if phase.startswith("receipt-"):
            terminal = row
            break
    if terminal is None:
        raise ReceiptError("baseline receipt has no terminal receipt (malformed)")
    if terminal.get("phase") != "receipt-success":
        raise ReceiptError(
            f"baseline receipt terminal is {terminal.get('phase')} (must be receipt-success)"
        )
    if terminal.get("ok") is not True:
        raise ReceiptError("baseline receipt terminal is not ok (refusing)")
    return terminal


def _check_terminal_detail(terminal: dict, parent_sha: str) -> str:
    """Validate terminal detail; return the candidate SHA (lowercased)."""
    detail = terminal.get("detail")
    if not isinstance(detail, dict):
        raise ReceiptError("baseline receipt-success detail is not an object")
    term_status = str(detail.get("status") or "")
    term_candidate = str(detail.get("candidate") or "").strip().lower()
    if term_status != "success":
        raise ReceiptError("baseline receipt terminal status is not success")
    if term_candidate != parent_sha.strip().lower():
        raise ReceiptError("baseline receipt candidate != parent SHA (stale receipt?)")
    return term_candidate


def _bind_generation_paths(
    s_detail: dict, parent_sha: str
) -> tuple[Path, Path, str]:
    """Bind generation/venv/home from stage-ok detail."""
    generation_raw = str(s_detail.get("generation") or "").strip()
    venv_raw = str(s_detail.get("venv_python") or s_detail.get("venv") or "").strip()
    home_raw = str(s_detail.get("home") or "").strip()
    if not generation_raw or not venv_raw:
        raise ReceiptError("baseline receipt stage-ok has no generation/venv")
    generation = Path(generation_raw)
    venv_python = Path(venv_raw)
    # Generation must be the parent side-generation, not an arbitrary path.
    expect_tail = f"gen-{parent_sha[:12]}"
    if generation.name != expect_tail:
        raise ReceiptError(
            f"baseline receipt generation {generation.name} != {expect_tail} (stale?)"
        )
    try:
        venv_python.relative_to(generation)
    except ValueError:
        raise ReceiptError(
            "baseline receipt venv is not inside its generation (malformed)"
        ) from None
    if not home_raw:
        raise ReceiptError("baseline receipt stage-ok has no home (malformed)")
    return generation, venv_python, home_raw


def load_prior_activation(host: Host, config: CutoverConfig) -> PriorActivation:
    """Load and authenticate the prior activation receipt. Fail-closed.

    Order is load-bearing: path shape -> parent-dir bind -> lstat bind ->
    bytes -> JSONL -> stage-ok -> terminal receipt-success ->
    candidate==parent -> generation bind. Receipt candidate values are never
    trusted before the root bind. The filename is informational only.
    """
    receipt_opt = getattr(config, "baseline_receipt", None)
    if receipt_opt is None or str(receipt_opt) in ("", ".", "None"):
        raise ReceiptError("baseline receipt is not configured")
    receipt_path = Path(receipt_opt)
    _receipt_path_ok(receipt_path)
    _check_receipt_dir(host)
    try:
        st = host.stat_file(receipt_path)
    except FileNotFoundError as exc:
        raise ReceiptError(f"baseline receipt missing: {receipt_path}") from exc
    except OSError as exc:
        raise ReceiptError(f"baseline receipt stat failed: {exc}") from exc
    _check_stat(receipt_path, st)
    rows = _read_receipt_rows(host, receipt_path)
    stage_ok = _select_stage_ok(rows)
    terminal = _select_terminal(rows)
    term_candidate = _check_terminal_detail(terminal, config.parent_sha)
    s_detail = stage_ok.get("detail")
    if not isinstance(s_detail, dict):
        raise ReceiptError("baseline receipt stage-ok detail is not an object")
    extras, all_extras = _clean_extras(s_detail)
    generation, venv_python, home_raw = _bind_generation_paths(
        s_detail, config.parent_sha
    )
    return PriorActivation(
        candidate_sha=term_candidate,
        generation=generation,
        venv_python=venv_python,
        home=home_raw,
        extras=tuple(extras),
        all_extras=bool(all_extras),
        receipt_path=receipt_path,
    )
