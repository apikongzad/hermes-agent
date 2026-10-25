"""Durable state journal for the cutover controller. Stdlib only."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

from scripts.maintenance.cutover_types import Host


def _utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def append(
    host: Host,
    journal: Path,
    phase: str,
    ok: bool,
    detail: dict[str, Any] | None = None,
) -> None:
    payload = {"ts": _utc_now(), "phase": phase, "ok": ok, "detail": detail or {}}
    line = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    try:
        existing = host.read_bytes(journal)
    except (OSError, FileNotFoundError):
        existing = b""
    host.write_bytes(journal, existing + line)


def read_all(host: Host, journal: Path) -> list[dict[str, Any]]:
    try:
        raw = host.read_bytes(journal).decode("utf-8", "replace")
    except (OSError, FileNotFoundError):
        return []
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def last_terminal_status(host: Host, journal: Path) -> str | None:
    for row in reversed(read_all(host, journal)):
        if row.get("phase") in ("receipt-success", "receipt-failed", "receipt-unknown"):
            status = row.get("detail", {}).get("status")
            if isinstance(status, str):
                return status
    return None


def has_terminal_receipt(host: Host, journal: Path) -> bool:
    return last_terminal_status(host, journal) is not None
