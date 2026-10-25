"""Durable original-baseline snapshot: persist BEFORE FIRST MUTATION.

Stdlib only. The snapshot is the ONLY rollback source `resume()` may use;
it never recaptures live state via `preflight()` after interruption.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from scripts.maintenance.cutover_types import (
    Baseline,
    CutoverConfig,
    Host,
    snapshot_path_for,
)

SNAPSHOT_VERSION = 1


class SnapshotError(RuntimeError):
    pass


def _b64_encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64_decode(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise SnapshotError(f"snapshot bytes are not base64: {exc}") from exc


def _baseline_to_dict(baseline: Baseline) -> dict:
    return {
        "gateway_unit_text": baseline.gateway_unit_text,
        "dashboard_unit_text": baseline.dashboard_unit_text,
        "gateway_dropin_bytes": {
            k: _b64_encode(v) for k, v in baseline.gateway_dropin_bytes.items()
        },
        "dashboard_dropin_bytes": {
            k: _b64_encode(v) for k, v in baseline.dashboard_dropin_bytes.items()
        },
        "live_head": baseline.live_head,
        "candidate_head": baseline.candidate_head,
        "live_main_pid": baseline.live_main_pid,
        "live_main_exe": baseline.live_main_exe,
        "live_main_cmdline": list(baseline.live_main_cmdline),
        "live_main_cwd": baseline.live_main_cwd,
        "live_main_start_time": baseline.live_main_start_time,
        "dashboard_main_pid": baseline.dashboard_main_pid,
        "dashboard_main_exe": baseline.dashboard_main_exe,
        "dashboard_main_cmdline": list(baseline.dashboard_main_cmdline),
        "dashboard_main_cwd": baseline.dashboard_main_cwd,
        "dashboard_main_start_time": baseline.dashboard_main_start_time,
        "gateway_active_enter": baseline.gateway_active_enter,
        "dashboard_active_enter": baseline.dashboard_active_enter,
        "gateway_nrestarts": baseline.gateway_nrestarts,
        "dashboard_nrestarts": baseline.dashboard_nrestarts,
        "gateway_state_bytes": _b64_encode(baseline.gateway_state_bytes),
        "facts_bytes": _b64_encode(baseline.facts_bytes),
        "selection_facts_path": str(baseline.selection_facts_path),
        "gateway_state_path": str(baseline.gateway_state_path),
    }


def _baseline_from_dict(data: dict) -> Baseline:
    try:
        return Baseline(
            gateway_unit_text=str(data["gateway_unit_text"]),
            dashboard_unit_text=str(data["dashboard_unit_text"]),
            gateway_dropin_bytes={
                str(k): _b64_decode(str(v))
                for k, v in dict(data.get("gateway_dropin_bytes") or {}).items()
            },
            dashboard_dropin_bytes={
                str(k): _b64_decode(str(v))
                for k, v in dict(data.get("dashboard_dropin_bytes") or {}).items()
            },
            live_head=str(data["live_head"]),
            candidate_head=str(data["candidate_head"]),
            live_main_pid=int(data["live_main_pid"]),
            live_main_exe=str(data["live_main_exe"]),
            live_main_cmdline=tuple(str(x) for x in (data.get("live_main_cmdline") or [])),
            live_main_cwd=str(data["live_main_cwd"]),
            live_main_start_time=(
                int(data["live_main_start_time"])
                if data.get("live_main_start_time") is not None
                else None
            ),
            dashboard_main_pid=int(data["dashboard_main_pid"]),
            dashboard_main_exe=str(data["dashboard_main_exe"]),
            dashboard_main_cmdline=tuple(
                str(x) for x in (data.get("dashboard_main_cmdline") or [])
            ),
            dashboard_main_cwd=str(data["dashboard_main_cwd"]),
            dashboard_main_start_time=(
                int(data["dashboard_main_start_time"])
                if data.get("dashboard_main_start_time") is not None
                else None
            ),
            gateway_active_enter=str(data.get("gateway_active_enter") or ""),
            dashboard_active_enter=str(data.get("dashboard_active_enter") or ""),
            gateway_nrestarts=str(data.get("gateway_nrestarts") or ""),
            dashboard_nrestarts=str(data.get("dashboard_nrestarts") or ""),
            gateway_state_bytes=_b64_decode(str(data["gateway_state_bytes"])),
            facts_bytes=_b64_decode(str(data["facts_bytes"])),
            selection_facts_path=Path(str(data["selection_facts_path"])),
            gateway_state_path=Path(str(data["gateway_state_path"])),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise SnapshotError(f"snapshot baseline malformed: {exc}") from exc


def _checksum(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def save_baseline(host: Host, config: CutoverConfig, baseline: Baseline) -> Path:
    """Persist the ORIGINAL baseline before any live mutation. Returns path."""
    snapshot = snapshot_path_for(config.journal_path)
    body: dict = {
        "version": SNAPSHOT_VERSION,
        "candidate_sha": config.candidate_sha,
        "parent_sha": config.parent_sha,
        "journal": str(config.journal_path),
        "baseline": _baseline_to_dict(baseline),
    }
    body["sha256"] = _checksum(body)
    raw = (json.dumps(body, sort_keys=True, indent=2) + "\n").encode("utf-8")
    try:
        host.write_bytes(snapshot, raw)
    except OSError as exc:
        raise SnapshotError(f"cannot persist baseline snapshot: {exc}") from exc
    return snapshot


def load_baseline(host: Host, config: CutoverConfig) -> Baseline:
    """Load and authenticate the ORIGINAL baseline. Never recaptures live."""
    snapshot = snapshot_path_for(config.journal_path)
    try:
        raw = host.read_bytes(snapshot)
    except FileNotFoundError as exc:
        raise SnapshotError(f"baseline snapshot missing: {snapshot}") from exc
    except OSError as exc:
        raise SnapshotError(f"cannot read baseline snapshot: {exc}") from exc
    try:
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SnapshotError(f"baseline snapshot is not JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise SnapshotError("baseline snapshot is not an object")
    if body.get("version") != SNAPSHOT_VERSION:
        raise SnapshotError("baseline snapshot version mismatch")
    if body.get("candidate_sha") != config.candidate_sha:
        raise SnapshotError("snapshot candidate SHA does not match config (refusing)")
    if body.get("parent_sha") != config.parent_sha:
        raise SnapshotError("snapshot parent SHA does not match config (refusing)")
    if body.get("journal") != str(config.journal_path):
        raise SnapshotError("snapshot journal path does not match config (refusing)")
    expect = str(body.get("sha256") or "")
    probe = dict(body)
    probe.pop("sha256", None)
    if not expect or _checksum(probe) != expect:
        raise SnapshotError("baseline snapshot checksum mismatch (refusing)")
    baseline = _baseline_from_dict(body.get("baseline") or {})
    if baseline.live_head != config.parent_sha:
        raise SnapshotError("snapshot live HEAD != parent (stale snapshot, refusing)")
    if baseline.candidate_head != config.candidate_sha:
        raise SnapshotError("snapshot candidate HEAD != candidate (stale snapshot, refusing)")
    if not baseline.facts_bytes:
        raise SnapshotError("snapshot has no selection facts bytes (refusing)")
    return baseline
