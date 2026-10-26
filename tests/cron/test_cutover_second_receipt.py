"""Second-cutover migration via prior activation receipt (v2.4).

Covers the explicit migration between the old direct side-gen (parent 1d9a)
and the next side-gen (candidate 3e4d...): --baseline-receipt binds the
root-owned previous activation, derives extras from stage-ok, leaves facts
optional, restores ONLY dropin bytes, and never checks out source.

No live effects: all I/O via FakeHost, no systemctl/git/outbound.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
from pathlib import Path

from scripts.maintenance.cutover_orchestrate import orchestrate, resume
from scripts.maintenance.cutover_preflight import PreflightError, preflight
from scripts.maintenance.cutover_types import (
    CutoverConfig,
    FileStat,
    Host,
    RunResult,
    selection_facts_path_for,
)


PARENT_SHA = "1d9a377fa00ce0e663e274e16b63c75e36233b9e"
CANDIDATE_SHA = "3e4da19c408c8caf7b63eb3736c496c1faf58821"
RECEIPT_PATH = Path("/var/lib/hermes-cutover/activation-1d9a377fa0.jsonl")
RECEIPT_DIR = Path("/var/lib/hermes-cutover")


class FakeHost(Host):
    def __init__(self) -> None:
        self.timeline: list[tuple[str, str]] = []
        self.files: dict[str, bytes | Exception] = {}
        self.stats: dict[str, FileStat | Exception] = {}
        self.exes: dict[int, str | Exception] = {}
        self.cmdlines: dict[int, list[str]] = {}
        self.cwds: dict[int, str] = {}
        self.environs: dict[int, dict[str, str]] = {}
        self.start_times: dict[int, int] = {}
        self.http: dict[str, tuple[int, str] | Exception] = {}
        self.run_handlers: list[tuple[str, object]] = []
        self.run_cwds: list[str | None] = []
        self.run_envs: list[dict[str, str] | None] = []

    def on_run(self, prefix: str, result: object) -> None:
        self.run_handlers.append((prefix, result))

    def run(self, argv, timeout=60, cwd=None, env=None) -> RunResult:
        self.timeline.append(("run", " ".join(argv)))
        self.run_cwds.append(str(cwd) if cwd is not None else None)
        self.run_envs.append(dict(env) if env is not None else None)
        key = " ".join(argv)
        for prefix, result in self.run_handlers:
            if prefix in key:
                if callable(result):
                    return result(argv)
                assert isinstance(result, RunResult)
                return result
        return RunResult(0, "", "")

    def read_bytes(self, path: Path) -> bytes:
        self.timeline.append(("read", str(path)))
        key = str(path)
        if key in self.files:
            v = self.files[key]
            if isinstance(v, Exception):
                raise v
            assert isinstance(v, bytes)
            return v
        raise FileNotFoundError(key)

    def write_bytes(self, path: Path, data: bytes) -> None:
        self.timeline.append(("write", str(path)))
        self.files[str(path)] = bytes(data)

    def remove(self, path: Path) -> None:
        self.timeline.append(("remove", str(path)))
        self.files.pop(str(path), None)

    def proc_exe(self, pid: int) -> str:
        self.timeline.append(("exe", str(pid)))
        if pid in self.exes:
            v = self.exes[pid]
            if isinstance(v, Exception):
                raise v
            return str(v)
        raise OSError(f"no exe for {pid}")

    def proc_cmdline(self, pid: int) -> list[str]:
        self.timeline.append(("cmdline", str(pid)))
        if pid in self.cmdlines:
            return list(self.cmdlines[pid])
        raise OSError(f"no cmdline for {pid}")

    def proc_cwd(self, pid: int) -> str:
        self.timeline.append(("cwd", str(pid)))
        if pid in self.cwds:
            return self.cwds[pid]
        raise OSError(f"no cwd for {pid}")

    def proc_environ(self, pid: int) -> dict[str, str]:
        self.timeline.append(("environ", str(pid)))
        if pid in self.environs:
            return dict(self.environs[pid])
        raise OSError(f"no environ for {pid}")

    def proc_start_time(self, pid: int) -> int | None:
        self.timeline.append(("start", str(pid)))
        return self.start_times.get(pid, 100)

    def stat_file(self, path: Path) -> FileStat:
        self.timeline.append(("stat", str(path)))
        key = str(path)
        if key in self.stats:
            v = self.stats[key]
            if isinstance(v, Exception):
                raise v
            assert isinstance(v, FileStat)
            return v
        raise FileNotFoundError(key)

    def http_get(self, url: str, timeout: int = 10):
        self.timeline.append(("http", url))
        if url in self.http:
            v = self.http[url]
            if isinstance(v, Exception):
                raise v
            return v
        raise OSError(f"refused {url}")


def _make_config(tmp_path: Path, **overrides: object) -> CutoverConfig:
    fields: dict[str, object] = {
        "candidate_sha": CANDIDATE_SHA,
        "parent_sha": PARENT_SHA,
        "candidate_src": tmp_path / "candidate-new",
        "live_tree": tmp_path / "live-old",
        "generation_root": tmp_path / "generations",
        "journal_path": tmp_path / "journal2.jsonl",
        "hermes_home": tmp_path / "home",
        "gateway_unit": "hermes-gateway.service",
        "dashboard_unit": "hermes-dashboard.service",
        "gateway_dropin_dir": tmp_path / "gw.d",
        "dashboard_dropin_dir": tmp_path / "dash.d",
        "candidate_dropin_name": "zzz-candidate.conf",
        "dashboard_port": 9119,
        "controller_path": None,
        "baseline_receipt": RECEIPT_PATH,
    }
    fields.update(overrides)
    return CutoverConfig(**fields)  # type: ignore[arg-type]


def _fresh_state(pid: int, sha: str) -> bytes:
    now = datetime.datetime.now(datetime.UTC).isoformat()
    return json.dumps(
        {"code_sha": sha, "updated_at": now, "pid": pid, "start_time": 100}
    ).encode()


def _prior_generation(config: CutoverConfig) -> Path:
    return (config.generation_root / f"gen-{PARENT_SHA[:12]}").absolute()


def _prior_venv(config: CutoverConfig) -> Path:
    return _prior_generation(config) / "venv" / "bin" / "python3"


def _seed_parent_dir(
    host: FakeHost,
    *,
    uid: int = 0,
    mode: int = 0o40700,
    is_symlink: bool = False,
    is_file: bool = False,
) -> None:
    host.stats[str(RECEIPT_DIR)] = FileStat(
        uid=uid, gid=0, mode=mode, is_symlink=is_symlink, is_file=is_file
    )


def _seed_receipt_success(
    host: FakeHost,
    config: CutoverConfig,
    *,
    extras: list[str] | None = None,
    all_extras: bool = True,
    terminal_ok: bool = True,
    receipt_candidate: str | None = None,
) -> None:
    if extras is None:
        extras = ["web", "telegram"]
    gen = _prior_generation(config)
    venv_python = _prior_venv(config)
    _seed_parent_dir(host)
    host.stats[str(RECEIPT_PATH)] = FileStat(
        uid=0, gid=0, mode=0o600, is_symlink=False, is_file=True
    )
    lines = [
        json.dumps(
            {"ts": "2026-10-26T00:00:00+00:00", "phase": "preflight-ok", "ok": True, "detail": {}}
        ),
        json.dumps(
            {
                "ts": "2026-10-26T00:01:00+00:00",
                "phase": "stage-ok",
                "ok": True,
                "detail": {
                    "generation": str(gen),
                    "venv_python": str(venv_python),
                    "home": "/opt/store/python-3.14.9",
                    "extras": extras,
                    "all_extras": all_extras,
                },
            }
        ),
    ]
    if terminal_ok:
        lines.append(
            json.dumps(
                {
                    "ts": "2026-10-26T00:05:00+00:00",
                    "phase": "receipt-success",
                    "ok": True,
                    "detail": {
                        "status": "success",
                        "reason": "candidate cut over",
                        "candidate": receipt_candidate or PARENT_SHA,
                    },
                }
            )
        )
    host.files[str(RECEIPT_PATH)] = ("\n".join(lines) + "\n").encode()


def _seed_live_fleet(host: FakeHost, config: CutoverConfig, *, facts_missing: bool = True) -> Path:
    """Seed old worktree live fleet running the prior side-gen (1d9a)."""
    gen_new = config.generation_root / f"gen-{CANDIDATE_SHA[:12]}"
    venv_new = gen_new / "venv" / "bin" / "python3"
    store_home = Path("/opt/store/python/bin")
    store_exe = store_home / "python3.14"
    host.files[str(config.candidate_src / "scripts" / "maintenance" / "cutover.py")] = (
        b"from scripts.maintenance.cutover_orchestrate import orchestrate, resume"
    )
    host.files[
        str(config.candidate_src / "scripts" / "maintenance" / "cutover_orchestrate.py")
    ] = b"def orchestrate(host, config): pass\ndef resume(host, config): pass\n"
    host.files[str(gen_new / "venv" / "pyvenv.cfg")] = (
        f"home = {store_home}\nexecutable = {store_exe}\nversion_info = 3.14.9\n".encode()
    )
    if not facts_missing:
        sel = selection_facts_path_for(config.live_tree, config.hermes_home)
        host.files[str(sel)] = b'{"packages": {"venv": {"environment": "x"}}}'
    # Prior effective dropins (first cutover output): gen-1d9a fleet.
    prior_venv = _prior_venv(config)
    gw_dropin = (
        "[Service]\nExecStart=\n"
        f"ExecStart={prior_venv} {config.live_tree}/hermes_cli/main.py gateway run\n"
        f"WorkingDirectory={config.hermes_home}\n"
        'Environment="PATH=/x"\n'
        f'Environment="HERMES_HOME={config.hermes_home}"\n'
    ).encode()
    dash_dropin = (
        "[Service]\nExecStart=\n"
        f"ExecStart={prior_venv} {config.live_tree}/hermes_cli/main.py dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build\n"
        "WorkingDirectory=/home/ubuntu\n"
        'Environment="PATH=/x"\n'
        f'Environment="HERMES_HOME={config.hermes_home}"\n'
    ).encode()
    host.files[str(config.gateway_dropin_dir / "zzz-candidate.conf")] = gw_dropin
    host.files[str(config.dashboard_dropin_dir / "zzz-candidate.conf")] = dash_dropin

    gw_pid, dash_pid = 5242, 5243
    new_gw, new_dash = 5342, 5343
    host.files[str(config.hermes_home / "gateway_state.json")] = _fresh_state(gw_pid, PARENT_SHA)
    host.on_run("systemctl cat hermes-gateway", RunResult(0, "ExecStart=/x\ngateway", ""))
    host.on_run("systemctl cat hermes-dashboard", RunResult(0, "ExecStart=/y\ndash", ""))
    host.on_run("systemctl is-active", RunResult(0, "active", ""))
    state = {"restarted": False}

    def _show_gw(argv: list[str]) -> RunResult:
        if state["restarted"]:
            return RunResult(0, f"MainPID={new_gw}\nActiveEnterTimestamp=2026-10-26 12:05:00\nNRestarts=0", "")
        return RunResult(0, f"MainPID={gw_pid}\nActiveEnterTimestamp=2026-10-26 12:00:00\nNRestarts=0", "")

    def _show_dash(argv: list[str]) -> RunResult:
        if state["restarted"]:
            return RunResult(0, f"MainPID={new_dash}\nActiveEnterTimestamp=2026-10-26 12:05:01\nNRestarts=0", "")
        return RunResult(0, f"MainPID={dash_pid}\nActiveEnterTimestamp=2026-10-26 12:00:01\nNRestarts=0", "")

    host.on_run("systemctl show hermes-gateway", _show_gw)
    host.on_run("systemctl show hermes-dashboard", _show_dash)

    candidate = config.candidate_src
    dist = candidate / "hermes_cli" / "web_dist"
    host.files[str(dist / "index.html")] = (
        b"<!doctype html><html><head></head><body>"
        b"<div id=\"root\"></div><script src=\"assets/index.js\"></script>"
        b"</body></html>" + b"<!-- pad -->" * 20
    )
    host.files[str(dist / "hermes-build.json")] = json.dumps(
        {"schema": 1, "product": "web", "platform": "linux", "arch": "x64",
         "node": "24.0.0", "inputs": {}, "outputHash": "abc"}
    ).encode()
    host.files[str(candidate / "web" / "package.json")] = b'{"name": "web"}'

    def _git_head(argv: list[str]) -> RunResult:
        text = " ".join(argv)
        if "check-ignore" in text:
            return RunResult(0, "", "")
        if str(config.live_tree) in text:
            return RunResult(0, PARENT_SHA, "")
        if str(config.candidate_src) in text:
            return RunResult(0, CANDIDATE_SHA, "")
        return RunResult(1, "", "no repo")

    host.on_run("git -C", _git_head)
    host.on_run("pm.build_env", RunResult(0, str(venv_new), ""))

    def _staged_probe(argv: list[str]) -> RunResult:
        if str(venv_new) in argv and "-c" in argv:
            blob = " ".join(argv)
            if "hermes_bootstrap" in blob and "get_code_identity" in blob:
                before = {"exe": str(venv_new), "prefix": str(venv_new.parent.parent)}
                payload = {
                    "sha": CANDIDATE_SHA,
                    "short_sha": CANDIDATE_SHA[:8],
                    "version": "test",
                    "source": "git",
                    "before": before,
                    "after": dict(before),
                    "relaunch": "None",
                    "relaunch_error": None,
                }
                return RunResult(0, json.dumps(payload), "")
            if "importlib.util" in blob and "find_spec" in blob:
                import re as _re
                m = _re.search(r"_anchors=(\[.*?\])", blob)
                if m:
                    try:
                        asked = json.loads(m.group(1))
                    except Exception:
                        asked = []
                    return RunResult(0, json.dumps({str(a): True for a in asked}), "")
                return RunResult(0, json.dumps({"fastapi": True}), "")
            return RunResult(1, "", "probe must use real Hermes launch prep")
        if str(venv_new) in argv and "--help" in argv:
            return RunResult(0, "usage: hermes", "")
        return RunResult(0, "", "")

    host.on_run(str(venv_new), _staged_probe)
    prior_exe = "/opt/store/python-3.14.9/bin/python3.14"
    prior_venv_s = str(_prior_venv(config))
    for pid, cwd in ((gw_pid, str(config.hermes_home)), (dash_pid, "/home/ubuntu")):
        host.exes[pid] = prior_exe
        host.cmdlines[pid] = [prior_venv_s, "hermes"]
        host.cwds[pid] = cwd
        host.environs[pid] = {"HERMES_HOME": str(config.hermes_home)}
        host.start_times[pid] = 100
    host.on_run("systemctl daemon-reload", RunResult(0, "", ""))

    def _restart(argv: list[str]) -> RunResult:
        state["restarted"] = True
        for pid in (new_gw, new_dash):
            host.exes[pid] = str(store_exe)
            host.cmdlines[pid] = [str(venv_new), f"{config.candidate_src}/hermes_cli/main.py"]
            host.environs[pid] = {"HERMES_HOME": str(config.hermes_home)}
            host.start_times[pid] = 200
        host.cwds[new_gw] = str(config.hermes_home)
        host.cwds[new_dash] = "/home/ubuntu"
        host.files[str(config.hermes_home / "gateway_state.json")] = _fresh_state(new_gw, CANDIDATE_SHA)
        return RunResult(0, "", "")

    host.on_run("systemctl restart", _restart)
    host.http["http://127.0.0.1:9119/api/health"] = (
        200,
        json.dumps({"ok": True, "commit": PARENT_SHA}),
    )
    # After restart the health endpoint serves the candidate; the restart
    # handler above flips state, but http stays parent until restart. Patch
    # http lazily: orchestrate polls after restart, so make http dynamic.
    orig_http = dict(host.http)

    def _dynamic_http(url: str, timeout: int = 10):
        host.timeline.append(("http", url))
        if state["restarted"]:
            return (200, json.dumps({"ok": True, "commit": CANDIDATE_SHA}))
        return orig_http[url]

    host.http_get = _dynamic_http  # type: ignore[method-assign]
    return venv_new


def test_receipt_migration_succeeds_with_missing_facts(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config)
    _seed_live_fleet(host, config, facts_missing=True)
    result = orchestrate(host, config)
    assert result.status == "success", result.reason
    # Extras came from the receipt (all_extras), not blank facts.
    assert any(
        kind == "run" and "pm.build_env" in detail and "--all-extras" in detail
        for kind, detail in host.timeline
    )
    # No facts were invented or rewritten.
    sel = str(selection_facts_path_for(config.live_tree, config.hermes_home))
    assert sel not in host.files
    assert not any(kind == "write" and "installs" in detail for kind, detail in host.timeline)


def test_receipt_migration_preflight_binds_prior_generation(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config, extras=["web", "telegram"], all_extras=True)
    _seed_live_fleet(host, config, facts_missing=True)
    baseline = preflight(host, config)
    assert baseline.facts_bytes == b""
    assert str(baseline.prior_generation).endswith(f"gen-{PARENT_SHA[:12]}")
    assert list(baseline.prior_extras) == ["telegram", "web"] or sorted(baseline.prior_extras) == ["telegram", "web"]
    assert baseline.prior_all_extras is True


def test_receipt_malformed_refuses_before_mutation(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_live_fleet(host, config, facts_missing=True)
    _seed_parent_dir(host)
    host.stats[str(RECEIPT_PATH)] = FileStat(uid=0, gid=0, mode=0o600, is_symlink=False, is_file=True)
    host.files[str(RECEIPT_PATH)] = b"not json\n"
    try:
        preflight(host, config)
        assert False, "malformed receipt must refuse"
    except PreflightError as exc:
        assert "receipt" in str(exc).lower()
    assert not any(kind == "run" and "daemon-reload" in detail for kind, detail in host.timeline)
    assert not any(kind == "run" and "systemctl restart" in detail for kind, detail in host.timeline)


def test_receipt_stale_candidate_refuses(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config, receipt_candidate="b" * 40)
    _seed_live_fleet(host, config, facts_missing=True)
    result = orchestrate(host, config)
    assert result.status == "failed"
    assert "fleet untouched" in result.reason


def test_receipt_wrong_generation_refuses(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config)
    _seed_live_fleet(host, config, facts_missing=True)
    # Drift the live cmdline away from the prior generation.
    host.cmdlines[5242] = ["/tmp/other-venv/bin/python3"]
    try:
        preflight(host, config)
        assert False, "wrong generation must refuse"
    except PreflightError as exc:
        assert "generation" in str(exc).lower()


def test_receipt_requires_terminal_success(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_live_fleet(host, config, facts_missing=True)
    gen = _prior_generation(config)
    venv_python = _prior_venv(config)
    _seed_parent_dir(host)
    host.stats[str(RECEIPT_PATH)] = FileStat(uid=0, gid=0, mode=0o600, is_symlink=False, is_file=True)
    host.files[str(RECEIPT_PATH)] = (
        json.dumps({"phase": "stage-ok", "ok": True, "detail": {
            "generation": str(gen), "venv_python": str(venv_python),
            "home": "/opt/store/python-3.14.9", "extras": ["web"], "all_extras": False}}) + "\n"
        + json.dumps({"phase": "receipt-failed", "ok": False,
                      "detail": {"status": "failed", "candidate": PARENT_SHA}}) + "\n"
    ).encode()
    try:
        preflight(host, config)
        assert False, "terminal failed must refuse"
    except PreflightError as exc:
        assert "receipt" in str(exc).lower()


def test_receipt_untrusted_owner_never_trusts_candidate(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config)
    _seed_live_fleet(host, config, facts_missing=True)
    # Non-root owner: must refuse even though candidate matches.
    host.stats[str(RECEIPT_PATH)] = FileStat(uid=1000, gid=1000, mode=0o600, is_symlink=False, is_file=True)
    try:
        preflight(host, config)
        assert False, "non-root receipt must refuse"
    except PreflightError as exc:
        assert "root" in str(exc).lower()


def test_receipt_bad_mode_and_symlink_and_path_refuse(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config)
    _seed_live_fleet(host, config, facts_missing=True)
    # Bad mode (group-readable).
    host.stats[str(RECEIPT_PATH)] = FileStat(uid=0, gid=0, mode=0o640, is_symlink=False, is_file=True)
    try:
        preflight(host, config)
        assert False
    except PreflightError:
        pass
    # Symlink.
    host.stats[str(RECEIPT_PATH)] = FileStat(uid=0, gid=0, mode=0o600, is_symlink=True, is_file=True)
    try:
        preflight(host, config)
        assert False
    except PreflightError:
        pass
    # Wrong directory.
    bad = _make_config(tmp_path, baseline_receipt=tmp_path / "evil.jsonl")
    host2 = FakeHost()
    _seed_live_fleet(host2, bad, facts_missing=True)
    host2.stats[str(tmp_path / "evil.jsonl")] = FileStat(uid=0, gid=0, mode=0o600, is_symlink=False, is_file=True)
    host2.files[str(tmp_path / "evil.jsonl")] = host.files[str(RECEIPT_PATH)]
    try:
        preflight(host2, bad)
        assert False
    except PreflightError:
        pass


def test_receipt_subdir_refuses_direct_child_only(tmp_path: Path) -> None:
    sub = RECEIPT_DIR / "subdir" / "activation-1d9a377fa0.jsonl"
    config = _make_config(tmp_path, baseline_receipt=sub)
    host = FakeHost()
    _seed_receipt_success(host, _make_config(tmp_path))
    _seed_live_fleet(host, config, facts_missing=True)
    host.stats[str(sub)] = FileStat(uid=0, gid=0, mode=0o600, is_symlink=False, is_file=True)
    host.files[str(sub)] = host.files[str(RECEIPT_PATH)]
    try:
        preflight(host, config)
        assert False, "subdir receipt must refuse"
    except PreflightError as exc:
        assert "direct child" in str(exc).lower() or "receipt" in str(exc).lower()


def test_receipt_parent_symlink_refuses(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config)
    _seed_live_fleet(host, config, facts_missing=True)
    host.stats[str(RECEIPT_DIR)] = FileStat(
        uid=0, gid=0, mode=0o40700, is_symlink=True, is_file=False
    )
    try:
        preflight(host, config)
        assert False, "symlink parent must refuse"
    except PreflightError as exc:
        assert "parent" in str(exc).lower() or "symlink" in str(exc).lower()


def test_receipt_parent_bad_mode_and_owner_refuse(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config)
    _seed_live_fleet(host, config, facts_missing=True)
    # Group/other-readable parent (0755) must refuse.
    host.stats[str(RECEIPT_DIR)] = FileStat(
        uid=0, gid=0, mode=0o40755, is_symlink=False, is_file=False
    )
    try:
        preflight(host, config)
        assert False
    except PreflightError as exc:
        assert "0700" in str(exc) or "parent" in str(exc).lower()
    # Non-root parent owner must refuse.
    host.stats[str(RECEIPT_DIR)] = FileStat(
        uid=1000, gid=0, mode=0o40700, is_symlink=False, is_file=False
    )
    try:
        preflight(host, config)
        assert False
    except PreflightError as exc:
        assert "root" in str(exc).lower() or "parent" in str(exc).lower()


def test_receipt_exec_mode_refuses(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config)
    _seed_live_fleet(host, config, facts_missing=True)
    # Owner-executable receipt (0700) must refuse even though owner-readable.
    host.stats[str(RECEIPT_PATH)] = FileStat(
        uid=0, gid=0, mode=0o700, is_symlink=False, is_file=True
    )
    try:
        preflight(host, config)
        assert False, "exec receipt must refuse"
    except PreflightError as exc:
        assert "execute" in str(exc).lower() or "receipt" in str(exc).lower()


def test_receipt_state_and_health_must_match_parent(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config)
    _seed_live_fleet(host, config, facts_missing=True)
    # Stale state (main 50e82, not parent 1d9a) must refuse.
    host.files[str(config.hermes_home / "gateway_state.json")] = _fresh_state(
        5242, "50e82ad783100da9e72a8b7ee6331b604f087fbe"
    )
    try:
        preflight(host, config)
        assert False
    except PreflightError as exc:
        assert "parent" in str(exc).lower() or "state" in str(exc).lower()


def test_rollback_restores_only_dropins_no_facts_no_checkout(tmp_path: Path) -> None:
    from scripts.maintenance.cutover_snapshot import load_baseline
    from scripts.maintenance.cutover_restore import rollback

    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config)
    venv_new = _seed_live_fleet(host, config, facts_missing=True)
    baseline = preflight(host, config)
    from scripts.maintenance.cutover_snapshot import save_baseline

    save_baseline(host, config, baseline)
    # Simulate post-mutation: dropins overwritten with candidate, then rollback.
    host.files[str(config.gateway_dropin_dir / "zzz-candidate.conf")] = (
        f"[Service]\nExecStart=\nExecStart={venv_new} x\n".encode()
    )
    snapshot = load_baseline(host, config)
    assert snapshot.facts_bytes == b""
    errors = rollback(host, config, snapshot)
    assert errors == [], ";".join(errors)
    # Prior dropins restored (gen-parent), no facts written, no checkout.
    body = host.files[str(config.gateway_dropin_dir / "zzz-candidate.conf")].decode()
    assert str(_prior_venv(config)) in body
    assert not any(kind == "write" and "installs" in detail for kind, detail in host.timeline)
    assert not any("checkout" in detail for _, detail in host.timeline)


def test_rollback_refuses_on_source_drift(tmp_path: Path) -> None:
    from scripts.maintenance.cutover_restore import _restore_source
    from scripts.maintenance.cutover_snapshot import save_baseline

    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_receipt_success(host, config)
    _seed_live_fleet(host, config, facts_missing=True)
    baseline = preflight(host, config)
    save_baseline(host, config, baseline)
    # Drift live HEAD away from parent.
    host.run_handlers = [h for h in host.run_handlers if "git -C" not in h[0]]

    def _drifted(argv: list[str]) -> RunResult:
        if "rev-parse" in " ".join(argv):
            return RunResult(0, "c" * 40, "")
        return RunResult(0, "", "")

    host.on_run("git -C", _drifted)
    host.on_run("rev-parse", _drifted)
    try:
        _restore_source(host, config, baseline)
        assert False, "drift must refuse, not checkout"
    except Exception as exc:
        assert "drift" in str(exc).lower() or "refusing" in str(exc).lower()
    assert not any("checkout" in detail for _, detail in host.timeline)


def test_generic_facts_path_unchanged_without_receipt(tmp_path: Path) -> None:
    config = _make_config(tmp_path, baseline_receipt=None)
    host = FakeHost()
    _seed_live_fleet(host, config, facts_missing=False)
    # Point receipt away; generic path must still succeed with facts present.
    baseline = preflight(host, config)
    assert baseline.facts_bytes != b""
    assert str(baseline.prior_generation) in ("", ".")


def test_cli_accepts_baseline_receipt_flag(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "maintenance" / "cutover.py"
    done = subprocess.run(
        [sys.executable, "-I", "-B", str(script), "preflight", "--help"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert done.returncode == 0
    assert "--baseline-receipt" in (done.stdout or "")
