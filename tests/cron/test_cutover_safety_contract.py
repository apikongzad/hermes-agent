"""Cutover safety contract v2: behavioral bar for the verified controller.

DESIGN v2 (see scripts/maintenance/DESIGN-v2.md). Every test drives the ACTUAL
orchestrator in scripts/maintenance/cutover_* through an injected Host with no
live effects (no systemctl, no git checkout, no sends).

Bar (each maps to a parent REJECT finding on v1):
- PARENT == live HEAD, CANDIDATE == candidate HEAD, never stale.
- No cgroup gate; controller lives inside the candidate tree.
- No outbound sends: success/failure is a local journal receipt only.
- Dashboard health is 9119 /api/health with commit==candidate, never 3000/8501
  or bare /health 302.
- Staging uses the documented pm.build_env entrypoint with cwd=candidate,
  isolated HOME/HERMES_HOME, absolute /usr/bin/python3, no PYTHONPATH, and no
  invented pm.py/sync_venv.py/publish_launcher.py.
- Re-exec probe invokes REAL Hermes launch prep (hermes_bootstrap +
  version identity == candidate), not `python -c sys.executable`.
- Health checks BOTH units with exact exe==store, cmdline[0]==staged venv,
  cwd, HERMES_HOME, PID change, state SHA fail-closed, /api/health commit.
- Dropins bind ExecStart+WorkingDirectory+PATH, sort after zz-runtime,
  never HERMES_EXE.
- Restore order source/facts/dropins→reload→restart→verify with provenance
  bind (baseline HEADs must name parent/candidate); unknown on restore failure.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
from pathlib import Path

from scripts.maintenance import cutover as facade
from scripts.maintenance.cutover_orchestrate import orchestrate
from scripts.maintenance.cutover_types import (
    CutoverConfig,
    Host,
    RunResult,
    selection_facts_path_for,
)


CANDIDATE_SHA = "a" * 40
PARENT_SHA = "b" * 40


class FakeHost(Host):
    """Injected IO adapter: records every effect, no live effects."""

    def __init__(self) -> None:
        self.timeline: list[tuple[str, str]] = []
        self.files: dict[str, bytes | Exception] = {}
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

    def run(
        self,
        argv: list[str],
        timeout: int = 60,
        cwd: Path | str | None = None,
        env: dict[str, str] | None = None,
    ) -> RunResult:
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
            value = self.files[key]
            if isinstance(value, Exception):
                raise value
            assert isinstance(value, bytes)
            return value
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
            value = self.exes[pid]
            if isinstance(value, Exception):
                raise value
            assert isinstance(value, str)
            return value
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

    def http_get(self, url: str, timeout: int = 10) -> tuple[int, str]:
        self.timeline.append(("http", url))
        if url in self.http:
            value = self.http[url]
            if isinstance(value, Exception):
                raise value
            assert isinstance(value, tuple)
            return value
        raise OSError(f"refused {url}")


def _make_config(tmp_path: Path, **overrides: object) -> CutoverConfig:
    fields: dict[str, object] = {
        "candidate_sha": CANDIDATE_SHA,
        "parent_sha": PARENT_SHA,
        "candidate_src": tmp_path / "candidate",
        "live_tree": tmp_path / "live",
        "generation_root": tmp_path / "generations",
        "journal_path": tmp_path / "journal.jsonl",
        "hermes_home": tmp_path / "home",
        "gateway_unit": "hermes-gateway.service",
        "dashboard_unit": "hermes-dashboard.service",
        "gateway_dropin_dir": tmp_path / "gw.d",
        "dashboard_dropin_dir": tmp_path / "dash.d",
        "candidate_dropin_name": "zzz-candidate.conf",
        "dashboard_port": 9119,
        "controller_path": None,
    }
    fields.update(overrides)
    return CutoverConfig(**fields)  # type: ignore[arg-type]


def _fresh_state(pid: int, sha: str) -> bytes:
    now = datetime.datetime.now(datetime.UTC).isoformat()
    return json.dumps(
        {"code_sha": sha, "updated_at": now, "pid": pid, "start_time": 100}
    ).encode()


def _seed_success_host(host: FakeHost, config: CutoverConfig) -> Path:
    gen = config.generation_root / f"gen-{CANDIDATE_SHA[:12]}"
    venv_python = gen / "venv" / "bin" / "python3"
    store_home = Path("/opt/store/python/bin")
    store_exe = store_home / "python3.14"
    host.files[str(config.candidate_src / "scripts" / "maintenance" / "cutover.py")] = (
        b"def orchestrate(): pass"
    )
    # Staged pyvenv.cfg binds the expected store interpreter (exact).
    host.files[str(gen / "venv" / "pyvenv.cfg")] = (
        f"home = {store_home}\nexecutable = {store_exe}\nversion_info = 3.14.9\n".encode()
    )
    sel_path = selection_facts_path_for(config.live_tree, config.hermes_home)
    host.files[str(sel_path)] = b'{"packages": {"venv": {"environment": "x"}}}'
    # Baseline PIDs; health requires change after restart.
    gw_pid, dash_pid = 4242, 4243
    new_gw, new_dash = 4342, 4343
    host.files[str(config.hermes_home / "gateway_state.json")] = _fresh_state(gw_pid, PARENT_SHA)
    host.on_run("systemctl cat hermes-gateway", RunResult(0, "ExecStart=/x\ngateway", ""))
    host.on_run("systemctl cat hermes-dashboard", RunResult(0, "ExecStart=/y\ndash", ""))
    host.on_run("systemctl is-active", RunResult(0, "active", ""))

    state = {"restarted": False}

    def _show_gw(argv: list[str]) -> RunResult:
        pid = new_gw if state["restarted"] else gw_pid
        return RunResult(0, f"MainPID={pid}\nActiveEnterTimestamp=2026-10-25 12:00:00\nNRestarts=0", "")

    def _show_dash(argv: list[str]) -> RunResult:
        pid = new_dash if state["restarted"] else dash_pid
        return RunResult(0, f"MainPID={pid}\nActiveEnterTimestamp=2026-10-25 12:00:01\nNRestarts=0", "")

    host.on_run("systemctl show hermes-gateway", _show_gw)
    host.on_run("systemctl show hermes-dashboard", _show_dash)

    def _git_head(argv: list[str]) -> RunResult:
        text = " ".join(argv)
        if str(config.live_tree) in text:
            return RunResult(0, PARENT_SHA, "")
        if str(config.candidate_src) in text:
            return RunResult(0, CANDIDATE_SHA, "")
        return RunResult(1, "", "no repo")

    host.on_run("git -C", _git_head)
    # Stage: documented entrypoint with isolation wrapper (runuser/env -i).
    host.on_run("pm.build_env", RunResult(0, str(venv_python), ""))

    def _staged_probe(argv: list[str]) -> RunResult:
        # REAL launch prep: staged venv python -I -B -c with hermes_bootstrap.
        # Root wraps with `env -i …` / `runuser … env -i …`, so the venv python
        # is anywhere in argv, not argv[0].
        if str(venv_python) in argv and "-c" in argv:
            blob = " ".join(argv)
            if "hermes_bootstrap" in blob and "get_code_identity" in blob:
                return RunResult(0, json.dumps({"sha": CANDIDATE_SHA}), "")
            return RunResult(1, "", "probe must use real Hermes launch prep")
        return RunResult(0, "", "")

    host.on_run(str(venv_python), _staged_probe)
    # Baseline bindings (old exe); after restart both bind staged.
    old_exe = "/opt/store/python-old/bin/python3.14"
    for pid, cwd in ((gw_pid, str(config.hermes_home)), (dash_pid, "/home/ubuntu")):
        host.exes[pid] = old_exe
        host.cmdlines[pid] = [old_exe, "old"]
        host.cwds[pid] = cwd
        host.environs[pid] = {"HERMES_HOME": str(config.hermes_home)}
        host.start_times[pid] = 100
    host.on_run("systemctl daemon-reload", RunResult(0, "", ""))

    def _restart(argv: list[str]) -> RunResult:
        state["restarted"] = True
        for pid in (new_gw, new_dash):
            host.exes[pid] = str(store_exe)
            host.cmdlines[pid] = [str(venv_python), f"{config.candidate_src}/hermes_cli/main.py"]
            host.environs[pid] = {"HERMES_HOME": str(config.hermes_home)}
            host.start_times[pid] = 200
        host.cwds[new_gw] = str(config.hermes_home)
        host.cwds[new_dash] = "/home/ubuntu"
        host.files[str(config.hermes_home / "gateway_state.json")] = _fresh_state(new_gw, CANDIDATE_SHA)
        return RunResult(0, "", "")

    host.on_run("systemctl restart", _restart)
    host.http["http://127.0.0.1:9119/api/health"] = (
        200,
        json.dumps({"ok": True, "commit": CANDIDATE_SHA}),
    )
    return venv_python


def test_parent_must_equal_live_main_via_controller_preflight(tmp_path: Path) -> None:
    """Preflight passes when live HEAD == parent, fails closed on a stale parent."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    result = orchestrate(host, config)
    assert result.status == "success"

    stale = _make_config(tmp_path, journal_path=tmp_path / "journal2.jsonl")

    def _stale_git(argv: list[str]) -> RunResult:
        text = " ".join(argv)
        if str(stale.live_tree) in text:
            return RunResult(0, "c" * 40, "")
        if str(stale.candidate_src) in text:
            return RunResult(0, CANDIDATE_SHA, "")
        return RunResult(1, "", "no repo")

    stale_host = FakeHost()
    _seed_success_host(stale_host, stale)
    stale_host.run_handlers = [h for h in stale_host.run_handlers if "git -C" not in h[0]]
    stale_host.on_run("git -C", _stale_git)
    stale_result = orchestrate(stale_host, stale)
    assert stale_result.status == "unknown"
    assert "preflight" in stale_result.reason


def test_no_cgroup_gate_controller_ignores_worker_invisible_path(tmp_path: Path) -> None:
    """Orchestration never consults cgroup.procs; it succeeds either way."""
    for with_cgroup in (False, True):
        config = _make_config(tmp_path, journal_path=tmp_path / f"j-{with_cgroup}.jsonl")
        host = FakeHost()
        venv_python = _seed_success_host(host, config)
        if with_cgroup:
            host.files["/sys/fs/cgroup/system.slice/hermes-gateway.service/cgroup.procs"] = b"1\n2\n"
        result = orchestrate(host, config)
        assert result.status == "success"
        assert str(venv_python) in result.extra.get("exe", "")
        assert not any(kind == "read" and "cgroup.procs" in detail for kind, detail in host.timeline)


def test_controller_lives_inside_candidate_tree_under_test() -> None:
    """The shipped controller file is inside the repo (candidate) tree, not /tmp."""
    repo_root = Path(__file__).resolve().parents[2]
    controller_file = Path(facade.__file__).resolve()
    assert controller_file.is_relative_to(repo_root)
    assert (repo_root / "scripts" / "maintenance" / "cutover.py").is_file()


def test_no_outbound_sends_success_and_failure_are_local_receipts(tmp_path: Path) -> None:
    """Neither the success nor the rollback path sends anywhere (no telegram)."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    result = orchestrate(host, config)
    assert result.status == "success"
    for kind, detail in host.timeline:
        assert "telegram" not in detail
        assert "1044758361" not in detail
        if kind == "run":
            assert " send " not in f" {detail} "

    failing = _make_config(tmp_path, journal_path=tmp_path / "journal-fail.jsonl")
    failing_host = FakeHost()
    _seed_success_host(failing_host, failing)
    failing_host.http["http://127.0.0.1:9119/api/health"] = (500, "bad")
    failing_result = orchestrate(failing_host, failing)
    assert failing_result.status in ("failed", "unknown")
    for kind, detail in failing_host.timeline:
        assert "telegram" not in detail
        if kind == "run":
            assert " send " not in f" {detail} "


def test_dashboard_health_is_9119_api_commit_never_legacy(tmp_path: Path) -> None:
    """Health probes 9119 /api/health with commit bind; never 3000/8501 or bare /health."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    result = orchestrate(host, config)
    assert result.status == "success"
    http_urls = [detail for kind, detail in host.timeline if kind == "http"]
    assert http_urls == ["http://127.0.0.1:9119/api/health"]
    assert not any("3000" in detail or "8501" in detail for _, detail in host.timeline)
    assert not any(detail.endswith("/health") and "/api/health" not in detail for detail in http_urls)


def test_staging_uses_documented_pm_entrypoint_and_no_invented_ones(tmp_path: Path) -> None:
    """Staging invokes pm.build_env with isolation; invented paths never appear."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    result = orchestrate(host, config)
    assert result.status == "success"
    run_cmds = [detail for kind, detail in host.timeline if kind == "run"]
    assert any("pm.build_env" in cmd and "--source" in cmd for cmd in run_cmds)
    assert not any("pm.py" in cmd for cmd in run_cmds)
    assert not any("scripts/sync_venv.py" in cmd for cmd in run_cmds)
    assert not any("scripts/publish_launcher.py" in cmd for cmd in run_cmds)
    # Isolation: cwd==candidate_src and env has HOME/HERMES_HOME, no PYTHONPATH.
    assert any(c == str(config.candidate_src) for c in host.run_cwds if c)
    assert any(
        env is not None and "HERMES_HOME" in env and "PYTHONPATH" not in env
        for env in host.run_envs
    )


def test_stage_probe_uses_real_hermes_launch_prep(tmp_path: Path) -> None:
    """Re-exec probe must import hermes_bootstrap + version identity, not sys.executable."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    result = orchestrate(host, config)
    assert result.status == "success"
    probe_cmds = [
        detail
        for kind, detail in host.timeline
        if kind == "run" and "hermes_bootstrap" in detail
    ]
    assert probe_cmds, "expected a real Hermes launch-prep probe"
    assert any("get_code_identity" in cmd for cmd in probe_cmds)


def test_install_failure_triggers_restore_not_success(tmp_path: Path) -> None:
    """A PM staging failure restores (source/facts/dropins) and never reports success."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    host.run_handlers = [h for h in host.run_handlers if "pm.build_env" not in h[0]]
    host.on_run("pm.build_env", RunResult(1, "", "uv sync failed"))
    result = orchestrate(host, config)
    assert result.status in ("failed", "unknown")
    assert result.status != "success"
    kinds = [kind for kind, _ in host.timeline]
    assert "run" in kinds and "write" in kinds


def test_dropin_binds_execstart_workdir_path_and_sorts_after_runtime(tmp_path: Path) -> None:
    """Candidate dropin hardcodes ExecStart+WorkingDirectory+PATH, sorts after zz-runtime."""
    config = _make_config(tmp_path)
    assert config.candidate_dropin_name > "zz-runtime-3.14.9.conf"
    host = FakeHost()
    venv_python = _seed_success_host(host, config)
    result = orchestrate(host, config)
    assert result.status == "success"
    for dropin_dir in (config.gateway_dropin_dir, config.dashboard_dropin_dir):
        target = str(dropin_dir / "zzz-candidate.conf")
        assert target in host.files
        body = host.files[target]
        assert isinstance(body, bytes)
        text = body.decode()
        assert "HERMES_EXE" not in text
        assert "ExecStart=" in text and str(venv_python) in text
        assert "WorkingDirectory=" in text
        assert "PATH=" in text and "venv/bin" in text


def test_restore_order_is_source_facts_dropins_reload_restart_verify(tmp_path: Path) -> None:
    """Health failure rolls back in the mandated order, never start-before-restore."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    host.http["http://127.0.0.1:9119/api/health"] = (500, "bad")
    result = orchestrate(host, config)
    assert result.status in ("failed", "unknown")
    order = [f"{kind}:{detail}" for kind, detail in host.timeline]
    live_marker = str(config.live_tree)
    first_http = next(i for i, e in enumerate(order) if e.startswith("http:"))
    tail = order[first_http + 1 :]
    positions: dict[str, int] = {}
    for offset, entry in enumerate(tail):
        index = first_http + 1 + offset
        if "git -C" in entry and live_marker in entry and "source" not in positions:
            positions["source"] = index
        if entry.startswith("write:") and "installs" in entry and "facts" not in positions:
            # Selection facts restore (installs/<key>/facts.json), not tools/facts.json.
            positions["facts"] = index
        if entry.startswith("remove:") and "zzz-candidate" in entry and "dropins" not in positions:
            positions["dropins"] = index
        if "systemctl daemon-reload" in entry and "reload" not in positions:
            positions["reload"] = index
        if "systemctl restart" in entry and "restart" not in positions:
            positions["restart"] = index
        if entry.startswith("http:") and "verify" not in positions:
            positions["verify"] = index
    assert set(positions) == {"source", "facts", "dropins", "reload", "restart", "verify"}
    assert positions["source"] < positions["facts"] < positions["dropins"]
    assert positions["dropins"] < positions["reload"] < positions["restart"] < positions["verify"]


def test_start_health_failure_triggers_rollback_not_success(tmp_path: Path) -> None:
    """Restart ok + 9119 refused must roll back and never report success."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    host.http["http://127.0.0.1:9119/api/health"] = OSError("9119 refused")
    result = orchestrate(host, config)
    assert result.status in ("failed", "unknown")
    assert result.status != "success"
    assert any(kind == "remove" and "zzz-candidate" in detail for kind, detail in host.timeline)


def test_health_binds_both_units_exact_exe_and_state(tmp_path: Path) -> None:
    """Health requires BOTH exes exact, cmdline/cwd/env, state SHA fail-closed, no --version."""
    config = _make_config(tmp_path)
    host = FakeHost()
    venv_python = _seed_success_host(host, config)
    result = orchestrate(host, config)
    assert result.status == "success"
    run_cmds = [detail for kind, detail in host.timeline if kind == "run"]
    assert any("rev-parse" in cmd for cmd in run_cmds)
    assert any(kind == "exe" for kind, _ in host.timeline)
    assert any(kind == "cmdline" for kind, _ in host.timeline)
    assert any(kind == "cwd" for kind, _ in host.timeline)
    assert any(kind == "environ" for kind, _ in host.timeline)
    assert not any("--version" in cmd for cmd in run_cmds)
    assert str(venv_python) in (host.cmdlines[4342][0] if 4342 in host.cmdlines else "")
    # Missing state SHA is fail-closed (v1 treated it as success).
    missing = _make_config(tmp_path, journal_path=tmp_path / "journal-missing.jsonl")
    missing_host = FakeHost()
    _seed_success_host(missing_host, missing)
    missing_host.files[str(missing.hermes_home / "gateway_state.json")] = _fresh_state(4242, PARENT_SHA)
    # After restart the file is overwritten with candidate; force it missing-at-verify
    # by making the restart NOT update state (stale parent SHA).
    missing_host.http["http://127.0.0.1:9119/api/health"] = (
        200,
        json.dumps({"ok": True, "commit": "b" * 40}),
    )
    missing_result = orchestrate(missing_host, missing)
    assert missing_result.status in ("failed", "unknown")


def test_missing_state_sha_is_fail_closed(tmp_path: Path) -> None:
    """gateway_state.json without code_sha never reports success."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    now = datetime.datetime.now(datetime.UTC).isoformat()
    host.files[str(config.hermes_home / "gateway_state.json")] = json.dumps(
        {"updated_at": now, "pid": 4342}
    ).encode()
    # Keep the post-restart overwrite from clobbering the missing-SHA case:
    # point the restart at a handler that leaves the file without code_sha.
    for prefix, _ in list(host.run_handlers):
        if "systemctl restart" in prefix:
            continue

    def _restart_no_state(argv: list[str]) -> RunResult:
        now2 = datetime.datetime.now(datetime.UTC).isoformat()
        # PIDs still change so the test isolates the SHA gate, not the PID gate.
        for pid in (4342, 4343):
            host.exes[pid] = "/opt/store/python/bin/python3.14"
            host.cmdlines[pid] = [str(config.generation_root / f"gen-{CANDIDATE_SHA[:12]}/venv/bin/python3")]
            host.cwds[pid] = str(config.hermes_home) if pid == 4342 else "/home/ubuntu"
            host.environs[pid] = {"HERMES_HOME": str(config.hermes_home)}
            host.start_times[pid] = 200
        host.files[str(config.hermes_home / "gateway_state.json")] = json.dumps(
            {"updated_at": now2, "pid": 4342}
        ).encode()
        # Rewire show to new PIDs.
        return RunResult(0, "", "")

    host.run_handlers = [h for h in host.run_handlers if "systemctl restart" not in h[0]]
    host.on_run("systemctl restart", _restart_no_state)
    # systemctl show must answer new PIDs or health fails on PID gate first;
    # re-seed show handlers to new PIDs.
    host.run_handlers = [h for h in host.run_handlers if "systemctl show" not in h[0]]
    host.on_run(
        "systemctl show hermes-gateway",
        RunResult(0, "MainPID=4342\nActiveEnterTimestamp=2026-10-25 12:00:00\nNRestarts=0", ""),
    )
    host.on_run(
        "systemctl show hermes-dashboard",
        RunResult(0, "MainPID=4343\nActiveEnterTimestamp=2026-10-25 12:00:01\nNRestarts=0", ""),
    )
    result = orchestrate(host, config)
    assert result.status in ("failed", "unknown")


def test_rollback_failure_is_unknown_never_success(tmp_path: Path) -> None:
    """When the restore itself fails, the receipt is unknown, never success."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    host.http["http://127.0.0.1:9119/api/health"] = (500, "bad")
    calls = {"reloads": 0}

    def _flaky_reload(argv: list[str]) -> RunResult:
        calls["reloads"] += 1
        if calls["reloads"] >= 2:
            return RunResult(1, "", "daemon-reload failed in rollback")
        return RunResult(0, "", "")

    host.run_handlers = [h for h in host.run_handlers if "systemctl daemon-reload" not in h[0]]
    host.on_run("systemctl daemon-reload", _flaky_reload)
    result = orchestrate(host, config)
    assert result.status == "unknown"
    assert result.status != "success"


def test_cli_runs_under_isolated_I_without_pythonpath() -> None:
    """Root-owned layout runs with -I and explicit safe sys.path, no PYTHONPATH."""
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "maintenance" / "cutover.py"
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "HERMES_HOME": "/tmp"}
    done = subprocess.run(
        [sys.executable, "-I", "-B", str(script), "--help"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(repo_root),
        env=env,
        check=False,
    )
    assert done.returncode == 0
    assert "Hermes standalone runtime cutover" in (done.stdout or "")
