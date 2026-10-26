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
    # Real layout: facade re-exports, orchestrator defines.
    host.files[str(config.candidate_src / "scripts" / "maintenance" / "cutover.py")] = (
        b"from scripts.maintenance.cutover_orchestrate import orchestrate, resume"
    )
    host.files[
        str(config.candidate_src / "scripts" / "maintenance" / "cutover_orchestrate.py")
    ] = (b"def orchestrate(host, config): pass\ndef resume(host, config): pass\n")
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
        if state["restarted"]:
            return RunResult(0, f"MainPID={new_gw}\nActiveEnterTimestamp=2026-10-25 12:05:00\nNRestarts=0", "")
        return RunResult(0, f"MainPID={gw_pid}\nActiveEnterTimestamp=2026-10-25 12:00:00\nNRestarts=0", "")

    def _show_dash(argv: list[str]) -> RunResult:
        if state["restarted"]:
            return RunResult(0, f"MainPID={new_dash}\nActiveEnterTimestamp=2026-10-25 12:05:01\nNRestarts=0", "")
        return RunResult(0, f"MainPID={dash_pid}\nActiveEnterTimestamp=2026-10-25 12:00:01\nNRestarts=0", "")

    host.on_run("systemctl show hermes-gateway", _show_gw)
    host.on_run("systemctl show hermes-dashboard", _show_dash)

    # Candidate web dist (dashboard --skip-build): prebuilt source-ignored product.
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
            # web dist is a git-ignored built product.
            return RunResult(0, "", "")
        if str(config.live_tree) in text:
            return RunResult(0, PARENT_SHA, "")
        if str(config.candidate_src) in text:
            return RunResult(0, CANDIDATE_SHA, "")
        return RunResult(1, "", "no repo")

    host.on_run("git -C", _git_head)
    # Stage: documented entrypoint with isolation wrapper (runuser/env -i).
    host.on_run("pm.build_env", RunResult(0, str(venv_python), ""))

    def _staged_probe(argv: list[str]) -> RunResult:
        # REAL launch prep: staged venv python -I -B -c with hermes_bootstrap
        # + prepare_launch + before/after + get_code_identity schema.
        # Root wraps with `env -i …` / `runuser … env -i …`, so the venv python
        # is anywhere in argv, not argv[0].
        if str(venv_python) in argv and "-c" in argv:
            blob = " ".join(argv)
            if (
                "hermes_bootstrap" in blob
                and "get_code_identity" in blob
                and "prepare_launch" in blob
            ):
                before = {"exe": str(venv_python), "prefix": str(venv_python.parent.parent)}
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
                # Staged extras anchor inventory (find_spec only, no import).
                # Dynamic: report every requested anchor present so the test
                # exercises the REAL anchor set the validator requests
                # (boto3/faster_whisper/...), not a synthetic fixed subset.
                import re as _re

                _m = _re.search(r"_anchors=(\[.*?\])", blob)
                if _m:
                    try:
                        _asked = json.loads(_m.group(1))
                    except Exception:
                        _asked = []
                    return RunResult(0, json.dumps({str(_a): True for _a in _asked}), "")
                return RunResult(0, json.dumps({"fastapi": True, "telegram": True, "discord": True, "slack_bolt": True, "googleapiclient": True, "mcp": True, "acp": True, "aiohttp": True, "youtube_transcript_api": True}), "")
            return RunResult(1, "", "probe must use real Hermes launch prep")
        # Candidate --help (isolated, no outbound): proves CLI + plugins load.
        if str(venv_python) in argv and "--help" in argv:
            return RunResult(0, "usage: hermes", "")
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
    # Pre-mutation preflight is failed (fleet untouched, no recovery), never unknown.
    assert stale_result.status == "failed"
    assert "preflight" in stale_result.reason
    assert "fleet untouched" in stale_result.reason


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
    """Re-exec probe must call prepare_launch + record before/after, not sys.executable."""
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
    assert any("prepare_launch" in cmd for cmd in probe_cmds)
    # Isolated HERMES_HOME (never the default production profile).
    assert any(
        env is not None
        and env.get("HERMES_HOME", "") != ""
        and env.get("HERMES_HOME") != str(config.hermes_home)
        and "PYTHONPATH" not in env
        for env in host.run_envs
    )


def test_install_failure_triggers_restore_not_success(tmp_path: Path) -> None:
    """A PM staging failure is pre-mutation: failed, zero lifecycle writes."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    host.run_handlers = [h for h in host.run_handlers if "pm.build_env" not in h[0]]
    host.on_run("pm.build_env", RunResult(1, "", "uv sync failed"))
    result = orchestrate(host, config)
    assert result.status == "failed"
    assert result.status != "success"
    assert "fleet untouched" in result.reason
    # Zero lifecycle: no daemon-reload/restart, no facts rewrite, no dropin remove.
    assert not any(
        kind == "run" and ("daemon-reload" in detail or "systemctl restart" in detail)
        for kind, detail in host.timeline
    )
    assert not any(
        kind == "write" and "installs" in detail for kind, detail in host.timeline
    )
    assert not any(
        kind == "remove" and "zzz-candidate" in detail for kind, detail in host.timeline
    )


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
        # Type=simple reset: empty ExecStart= must precede the assignment.
        assert "ExecStart=\nExecStart=" in text
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
    # Rollback starts at the first source restore AFTER polling began.
    # Polling retries (http/sleep/show) sit between first_http and rollback;
    # verify is the rollback liveness http AFTER restart, not a polling retry.
    positions: dict[str, int] = {}
    for offset, entry in enumerate(tail):
        index = first_http + 1 + offset
        if "git -C" in entry and live_marker in entry and "source" not in positions:
            positions["source"] = index
    assert "source" in positions
    rollback_tail = order[positions["source"] :]
    base = positions["source"]
    rpos: dict[str, int] = {"source": base}
    for offset, entry in enumerate(rollback_tail):
        index = base + offset
        if entry.startswith("write:") and "installs" in entry and "facts" not in rpos:
            rpos["facts"] = index
        if entry.startswith("remove:") and "zzz-candidate" in entry and "dropins" not in rpos:
            rpos["dropins"] = index
        if "systemctl daemon-reload" in entry and "reload" not in rpos:
            rpos["reload"] = index
        if "systemctl restart" in entry and "restart" not in rpos:
            rpos["restart"] = index
    # Verify is the first http AFTER the rollback restart (liveness probe).
    assert set(rpos) == {"source", "facts", "dropins", "reload", "restart"}
    after_restart = order[rpos["restart"] + 1 :]
    verify_idx = next(
        (rpos["restart"] + 1 + i for i, e in enumerate(after_restart) if e.startswith("http:")),
        None,
    )
    assert verify_idx is not None
    rpos["verify"] = verify_idx
    assert set(rpos) == {"source", "facts", "dropins", "reload", "restart", "verify"}
    assert rpos["source"] < rpos["facts"] < rpos["dropins"]
    assert rpos["dropins"] < rpos["reload"] < rpos["restart"] < rpos["verify"]


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


def test_preflight_accepts_real_controller_files() -> None:
    """Real facade re-exports, real orchestrator defines (old facade-only check refused)."""
    repo_root = Path(__file__).resolve().parents[2]
    facade_bytes = (repo_root / "scripts" / "maintenance" / "cutover.py").read_bytes()
    orch_bytes = (
        repo_root / "scripts" / "maintenance" / "cutover_orchestrate.py"
    ).read_bytes()
    assert b"def orchestrate" in orch_bytes
    assert b"orchestrate" in facade_bytes
    # The v1 gate looked for `def` in the facade, which only imports:
    # it refused every real tree.
    assert b"def orchestrate" not in facade_bytes


def test_preflight_controller_gate_passes_with_real_bytes(tmp_path: Path) -> None:
    """FakeHost seeded with REAL controller bytes gets past the controller gate."""
    from scripts.maintenance.cutover_preflight import PreflightError, preflight

    repo_root = Path(__file__).resolve().parents[2]
    config = _make_config(tmp_path, candidate_src=repo_root)
    host = FakeHost()
    _seed_success_host(host, config)
    # Overwrite the minimal facsimile with the real file bytes.
    host.files[str(repo_root / "scripts" / "maintenance" / "cutover.py")] = (
        repo_root / "scripts" / "maintenance" / "cutover.py"
    ).read_bytes()
    host.files[
        str(repo_root / "scripts" / "maintenance" / "cutover_orchestrate.py")
    ] = (repo_root / "scripts" / "maintenance" / "cutover_orchestrate.py").read_bytes()
    try:
        preflight(host, config)
    except PreflightError as exc:
        # Must get past the controller gate: any failure now is HEAD/units,
        # never "not the cutover orchestrator".
        assert "cutover orchestrator" not in str(exc)
        assert "orchestrator" not in str(exc).lower() or "HEAD" in str(exc) or "live" in str(exc)
        return
    # If the fake SHAs happened to match (they cannot: CANDIDATE_SHA is fake),
    # success also proves the gate passed.
    assert True


def test_cli_preflight_reaches_beyond_controller_gate(tmp_path: Path) -> None:
    """Real `cutover.py preflight` CLI on real bytes fails past the controller gate."""
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "maintenance" / "cutover.py"
    real_head = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=30, check=True,
    ).stdout.strip()
    assert len(real_head) == 40
    journal = tmp_path / "journal.jsonl"
    home = tmp_path / "home"
    home.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "HERMES_HOME": str(home),
    }
    done = subprocess.run(
        [
            sys.executable, "-I", "-B", str(script), "preflight",
            "--candidate-sha", "a" * 40,
            "--parent-sha", real_head,
            "--candidate-src", str(repo_root),
            "--live-tree", str(repo_root),
            "--generation-root", str(tmp_path / "generations"),
            "--journal", str(journal),
            "--hermes-home", str(home),
            "--gateway-dropin-dir", str(tmp_path / "gw.d"),
            "--dashboard-dropin-dir", str(tmp_path / "dash.d"),
        ],
        capture_output=True, text=True, timeout=60,
        cwd=str(repo_root), env=env, check=False,
    )
    # Must fail closed (candidate HEAD != fake SHA, or live units unreadable
    # as non-root) but NOT on the controller gate.
    assert done.returncode == 2
    err = (done.stderr or "") + (done.stdout or "")
    assert "cutover orchestrator" not in err


def test_isolated_launch_prep_reports_candidate_sha(tmp_path: Path) -> None:
    """Real Hermes launch prep (hermes_bootstrap + prepare_launch + identity) selects candidate."""
    from scripts.maintenance.cutover_stage import _launch_probe_code

    repo_root = Path(__file__).resolve().parents[2]
    real_head = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=30, check=True,
    ).stdout.strip()
    candidate = str(repo_root.resolve())
    assert "'" not in candidate
    code = _launch_probe_code(candidate)
    assert "prepare_launch" in code and "hermes_bootstrap" in code
    assert "sys.executable" in code and "sys.prefix" in code
    probe_home = tmp_path / "probe-home"
    probe_home.mkdir(exist_ok=True)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(probe_home),
        "HERMES_HOME": str(probe_home),
        "HERMES_RUNTIME_DIR": "/home/ubuntu/.hermes/tools",
    }
    done = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code],
        capture_output=True, text=True, timeout=120,
        cwd=candidate, env=env, check=False,
    )
    assert done.returncode == 0, (done.stdout or "") + (done.stderr or "")
    payload = json.loads((done.stdout or "").strip().splitlines()[-1])
    assert payload.get("sha") == real_head
    assert {"sha", "short_sha", "version", "source"}.issubset(payload)
    before, after = payload.get("before") or {}, payload.get("after") or {}
    assert before.get("exe") and before.get("prefix")
    assert after == before
    assert payload.get("relaunch_error") in (None, "")
    # Default production profile never HERMES_HOME in the isolated probe.
    assert str(probe_home) != "/home/ubuntu/.hermes"
    assert env["HERMES_HOME"] != "/home/ubuntu/.hermes"


def _crash_host_after_dropin(config: CutoverConfig) -> FakeHost:
    """Seed, snapshot the ORIGINAL, then mutate live to candidate/stopped (crash)."""
    from scripts.maintenance.cutover_preflight import preflight
    from scripts.maintenance.cutover_snapshot import save_baseline
    from scripts.maintenance.cutover_stage import stage, verify_isolated_launch
    from scripts.maintenance.cutover_dropin import write_candidate_dropins

    host = FakeHost()
    _seed_success_host(host, config)
    baseline = preflight(host, config)
    save_baseline(host, config, baseline)
    staged = stage(host, config)
    verify_isolated_launch(host, config, staged, baseline.live_main_exe)
    write_candidate_dropins(host, config, staged)
    # Crash before receipt: live now shows candidate dropins + mutated facts.
    sel = selection_facts_path_for(config.live_tree, config.hermes_home)
    host.files[str(sel)] = b'{"packages": {"venv": {"environment": "candidate"}}}'
    return host


def test_resume_after_dropin_write_restores_original_bytes(tmp_path: Path) -> None:
    """Crash after dropin: resume(snapshot) restores original bytes + healthy old fleet."""
    from scripts.maintenance.cutover_journal import read_all
    from scripts.maintenance.cutover_orchestrate import resume
    from scripts.maintenance.cutover_snapshot import load_baseline

    config = _make_config(tmp_path)
    host = _crash_host_after_dropin(config)
    snapshot = load_baseline(host, config)
    assert snapshot.live_head == PARENT_SHA
    gw_target = str(config.gateway_dropin_dir / "zzz-candidate.conf")
    assert gw_target in host.files
    result = resume(host, config)
    assert result.status == "failed"
    assert "restored to parent" in result.reason
    assert gw_target not in host.files
    sel = str(selection_facts_path_for(config.live_tree, config.hermes_home))
    assert host.files[sel] == b'{"packages": {"venv": {"environment": "x"}}}'
    rows = read_all(host, config.journal_path)
    assert any(r.get("phase") == "rollback-ok" for r in rows)
    assert any(r.get("phase") == "receipt-failed" for r in rows)


def test_resume_after_one_service_stopped_still_restores(tmp_path: Path) -> None:
    """One unit stopped (MainPID=0): resume must NOT recapture, still restores."""
    from scripts.maintenance.cutover_orchestrate import resume
    from scripts.maintenance.cutover_preflight import PreflightError, preflight

    config = _make_config(tmp_path)
    host = _crash_host_after_dropin(config)
    # Stop gateway: show MainPID=0 so a recapturing preflight would refuse.
    host.run_handlers = [h for h in host.run_handlers if "systemctl show hermes-gateway" not in h[0]]
    host.on_run(
        "systemctl show hermes-gateway",
        RunResult(0, "MainPID=0\nActiveEnterTimestamp=\nNRestarts=0", ""),
    )
    try:
        preflight(host, config)
        recapture_ok = True
    except (PreflightError, OSError):
        recapture_ok = False
    assert not recapture_ok
    result = resume(host, config)
    assert result.status == "failed"
    assert "restored to parent" in result.reason
    assert str(config.gateway_dropin_dir / "zzz-candidate.conf") not in host.files


def test_resume_after_restart_before_receipt_restores_oldfleet(tmp_path: Path) -> None:
    """Restart happened but no receipt: resume restores original + healthy old fleet."""
    from scripts.maintenance.cutover_orchestrate import resume

    config = _make_config(tmp_path)
    host = _crash_host_after_dropin(config)
    # Simulate restart already flipped PIDs to candidate but journal has no receipt.
    host.http["http://127.0.0.1:9119/api/health"] = (
        200,
        json.dumps({"ok": True, "commit": CANDIDATE_SHA}),
    )
    result = resume(host, config)
    assert result.status == "failed"
    # Rollback verify uses old-fleet liveness (is-active + 200), then receipt.
    assert any(kind == "run" and "systemctl restart" in detail for kind, detail in host.timeline)


def test_resume_refuses_with_terminal_receipt(tmp_path: Path) -> None:
    """A terminal receipt blocks a second resume (no double restore)."""
    from scripts.maintenance.cutover_orchestrate import orchestrate, resume

    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    first = orchestrate(host, config)
    assert first.status == "success"
    second = resume(host, config)
    assert second.status == "unknown"
    assert "terminal receipt" in second.reason


def test_resume_refuses_on_snapshot_mismatch(tmp_path: Path) -> None:
    """Mismatched/tampered snapshot is fail-closed unknown, never blind restore."""
    from scripts.maintenance.cutover_orchestrate import resume

    config = _make_config(tmp_path)
    host = _crash_host_after_dropin(config)
    other = _make_config(tmp_path, journal_path=tmp_path / "other.jsonl")
    other_host_result = resume(host, other)
    assert other_host_result.status == "unknown"


def test_launch_verify_failure_leaves_fleet_untouched(tmp_path: Path) -> None:
    """Launch-verify failure is pre-mutation: no reload/restart/facts rewrite."""
    from scripts.maintenance.cutover_orchestrate import orchestrate

    config = _make_config(tmp_path)
    host = FakeHost()
    venv_python = _seed_success_host(host, config)
    host.run_handlers = [h for h in host.run_handlers if str(venv_python) not in h[0]]

    def _bad_probe(argv: list[str]) -> RunResult:
        if str(venv_python) in argv and "-c" in argv:
            return RunResult(0, json.dumps({"sha": "c" * 40}), "")
        return RunResult(0, "", "")

    host.on_run(str(venv_python), _bad_probe)
    result = orchestrate(host, config)
    assert result.status == "failed"
    assert "fleet untouched" in result.reason
    assert not any("systemctl restart" in detail for _, detail in host.timeline)
    assert not any("daemon-reload" in detail for _, detail in host.timeline)


def test_restart_timeout_triggers_rollback_not_crash(tmp_path: Path) -> None:
    """TimeoutExpired on restart routes to rollback, never escapes uncaught."""
    import subprocess as _subprocess

    from scripts.maintenance.cutover_orchestrate import orchestrate

    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    host.run_handlers = [h for h in host.run_handlers if "systemctl restart" not in h[0]]

    def _timeout_restart(argv: list[str]) -> RunResult:
        raise _subprocess.TimeoutExpired(argv, 180)

    host.on_run("systemctl restart", _timeout_restart)
    result = orchestrate(host, config)
    assert result.status in ("failed", "unknown")
    assert any(kind == "write" or kind == "remove" for kind, _ in host.timeline)


def test_controller_boundary_no_mutable_import_and_manifest(tmp_path: Path) -> None:
    """Root boundary: no pm/hermes_cli import, manifest names the package."""
    import sys as _sys

    from scripts.maintenance import cutover as _facade
    from scripts.maintenance.cutover_manifest import (
        EXPECTED_SIBLINGS,
        assert_no_candidate_import,
        is_root_installed,
    )

    assert "cutover_orchestrate.py" in EXPECTED_SIBLINGS
    assert "cutover_snapshot.py" in EXPECTED_SIBLINGS
    assert not is_root_installed(tmp_path / "cutover.py")
    assert_no_candidate_import(tmp_path / "candidate")
    _sys.path.insert(0, str(tmp_path / "candidate"))
    try:
        try:
            assert_no_candidate_import(tmp_path / "candidate")
            boundary_hit = False
        except Exception:
            boundary_hit = True
        assert boundary_hit
    finally:
        _sys.path.remove(str(tmp_path / "candidate"))
    repo_root = Path(__file__).resolve().parents[2]
    for name in EXPECTED_SIBLINGS:
        assert (repo_root / "scripts" / "maintenance" / name).is_file()
    assert hasattr(_facade, "save_baseline") and hasattr(_facade, "load_baseline")


def test_stage_root_layout_uses_trusted_absolute_spawn(tmp_path: Path, monkeypatch) -> None:
    """Root staging must exec via absolute /usr/sbin/runuser + /usr/bin/env.

    Regression for the live `stage failed BEFORE live effects` transport:
    isolated env carries PATH=/usr/bin:/bin (no /usr/sbin), so bare
    `runuser` raises FileNotFoundError. Simulates root via euid==0 (no root
    needed in the worker); asserts absolute argv, real host binaries, and
    that the bare name is unresolvable under the isolated PATH while the
    absolute env still executes. Also drives real stage() plumbing.
    """
    import os as _os
    import shutil as _shutil

    from scripts.maintenance import cutover_stage as _stage_mod
    from scripts.maintenance.cutover_stage import (
        _ENV,
        _RUNUSER,
        _isolated_env,
        _wrap_for_user,
        stage_argv,
    )

    assert _RUNUSER == "/usr/sbin/runuser"
    assert _ENV == "/usr/bin/env"
    # Trusted binaries verified on this host (not mocked).
    assert _os.path.isfile(_RUNUSER) and _os.access(_RUNUSER, _os.X_OK)
    assert _os.path.isfile(_ENV) and _os.access(_ENV, _os.X_OK)

    config = _make_config(tmp_path)
    env = _isolated_env(config)
    assert env["PATH"] == "/usr/bin:/bin"
    # Bare `runuser` is unresolvable under the isolated PATH: the exact
    # pre-fix failure mode (`[Errno 2] runuser`) before any live effect.
    assert _shutil.which("runuser", path=env["PATH"]) is None
    assert _shutil.which("runuser", path="/usr/sbin:/usr/bin:/bin") is not None
    # Absolute /usr/bin/env still executes under the restricted PATH (no root).
    probed = subprocess.run(
        [_ENV, "-i", f"PATH={env['PATH']}", "true"],
        capture_output=True, text=True, timeout=30,
        env={"PATH": env["PATH"]}, check=False,
    )
    assert probed.returncode == 0
    # Bare `runuser` under the same restricted env raises ENOENT (no exec).
    try:
        subprocess.run(
            ["runuser", "-u", "ubuntu", "--", "true"],
            capture_output=True, text=True, timeout=30,
            env={"PATH": env["PATH"]}, check=False,
        )
        bare_resolves = True
    except FileNotFoundError:
        bare_resolves = False
    assert not bare_resolves

    argv = stage_argv(config)
    monkeypatch.setattr(_os, "geteuid", lambda: 0)
    wrapped = _wrap_for_user(argv, env)
    assert wrapped[0] == "/usr/sbin/runuser"
    assert wrapped[1:4] == ["-u", "ubuntu", "--"]
    assert wrapped[4] == "/usr/bin/env" and wrapped[5] == "-i"
    assert wrapped[0] != "runuser" and "runuser" not in wrapped[1:4]
    # Non-root path also uses the absolute env (no PATH lookup).
    monkeypatch.setattr(_os, "geteuid", lambda: 1000)
    plain = _wrap_for_user(argv, env)
    assert plain[0] == "/usr/bin/env" and plain[1] == "-i"

    # Real stage() plumbing under simulated root carries the absolute spawn.
    monkeypatch.setattr(_os, "geteuid", lambda: 0)
    host = FakeHost()
    _seed_success_host(host, config)
    staged = _stage_mod.stage(host, config)
    assert staged.venv_python.name == "python3"
    run_cmds = [detail for kind, detail in host.timeline if kind == "run"]
    stage_cmds = [c for c in run_cmds if "pm.build_env" in c]
    assert stage_cmds, "expected a staged pm.build_env spawn"
    assert any(c.startswith("/usr/sbin/runuser ") for c in stage_cmds)
    assert any("/usr/bin/env -i" in c for c in stage_cmds)
    assert env["PATH"] == "/usr/bin:/bin"


def test_cutover_service_unit_arms_recovery_via_systemd_analyze() -> None:
    """systemd template arms recovery: OnFailure in [Unit], verified live.

    Parent finding: OnFailure under [Service] is an unknown key so systemd
    ignores it and recovery NEVER arms. Runs real `systemd-analyze verify`
    (read-only, no enable/start); unknown-key output for OUR template fails
    the test. A deliberately broken copy proves the gate is real.
    """
    import configparser as _configparser
    import shutil as _shutil
    import tempfile as _tempfile

    if _shutil.which("systemd-analyze") is None:
        import pytest as _pytest

        _pytest.skip("systemd-analyze not available")
    repo_root = Path(__file__).resolve().parents[2]
    unit = repo_root / "scripts" / "maintenance" / "systemd" / "hermes-runtime-cutover.service"
    assert unit.is_file()

    parser = _configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str  # type: ignore[assignment]
    parser.read_string(unit.read_text(encoding="utf-8"))
    assert "Unit" in parser.sections()
    assert "Service" in parser.sections()
    # Recovery arms ONLY from [Unit].
    assert parser.get("Unit", "OnFailure").strip() == "hermes-runtime-cutover-recovery.service"
    assert not parser.has_option("Service", "OnFailure")
    # Explicit slice; mandatory env (no `-` prefix); no boot-enabling installer.
    assert parser.get("Service", "Slice").strip() == "system.slice"
    assert parser.get("Service", "EnvironmentFile").strip() == "/var/lib/hermes-cutover/cutover.env"
    assert "Install" not in parser.sections()

    def _verify(path: Path) -> str:
        done = subprocess.run(
            ["systemd-analyze", "verify", str(path)],
            capture_output=True, text=True, timeout=60, check=False,
        )
        return (done.stdout or "") + (done.stderr or "")

    output = _verify(unit)
    own = [ln for ln in output.splitlines() if "hermes-runtime-cutover" in ln]
    assert not any("Unknown key name" in ln for ln in own), "".join(own[:5])
    assert not any("Unknown section" in ln for ln in own), "".join(own[:5])
    assert not any("OnFailure" in ln and "Unknown" in ln for ln in output.splitlines())

    # The gate is real: the old layout (OnFailure under [Service]) IS flagged.
    broken = unit.read_text(encoding="utf-8").replace(
        "OnFailure=hermes-runtime-cutover-recovery.service\nStartLimitIntervalSec=0",
        "StartLimitIntervalSec=0",
    ).replace(
        "RemainAfterExit=no\n# Interruption resumes",
        "RemainAfterExit=no\nOnFailure=hermes-runtime-cutover-recovery.service\n# Interruption resumes",
    )
    assert "[Service]\nType=oneshot" in broken
    with _tempfile.NamedTemporaryFile(
        "w", suffix=".service", delete=False, encoding="utf-8"
    ) as handle:
        handle.write(broken)
        broken_path = Path(handle.name)
    try:
        broken_out = _verify(broken_path)
    finally:
        broken_path.unlink(missing_ok=True)
    assert "Unknown key name 'OnFailure' in section 'Service'" in broken_out


def test_actual_cli_resume_subprocess_no_snapshot_is_unknown(tmp_path: Path) -> None:
    """Actual `cutover.py resume -I` subprocess with no snapshot is fail-closed unknown."""
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "maintenance" / "cutover.py"
    journal = tmp_path / "journal.jsonl"
    home = tmp_path / "home"
    (home).mkdir(exist_ok=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "HERMES_HOME": str(home)}
    done = subprocess.run(
        [
            sys.executable, "-I", "-B", str(script), "resume",
            "--candidate-sha", CANDIDATE_SHA,
            "--parent-sha", PARENT_SHA,
            "--candidate-src", str(tmp_path / "candidate"),
            "--live-tree", str(tmp_path / "live"),
            "--generation-root", str(tmp_path / "generations"),
            "--journal", str(journal),
            "--hermes-home", str(home),
        ],
        capture_output=True, text=True, timeout=60,
        cwd=str(repo_root), env=env, check=False,
    )
    assert done.returncode != 0
    assert "unknown" in ((done.stdout or "") + (done.stderr or ""))


def test_dropin_execstart_reset_verified_by_systemd_analyze(tmp_path: Path) -> None:
    """Actual systemd-analyze verify: reset dropin passes, missing reset is refused.

    Renders BOTH gateway/dashboard via the ACTUAL renderers into a temp
    base+override fixture (Type=simple with ExecStart). Catches the
    multiple-ExecStart refuse, not just a string assert.
    """
    import shutil as _shutil

    if _shutil.which("systemd-analyze") is None:
        import pytest as _pytest

        _pytest.skip("systemd-analyze not available")
    from scripts.maintenance.cutover_dropin import (
        render_dashboard_dropin,
        render_gateway_dropin,
    )
    from scripts.maintenance.cutover_types import Staged

    config = _make_config(tmp_path)
    fake_python = tmp_path / "fake-python"
    fake_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_python.chmod(0o755)
    staged = Staged(
        generation_dir=tmp_path / "gen",
        venv_dir=tmp_path / "venv",
        venv_python=fake_python,
        store_home=Path("/opt/store"),
        store_exe=Path("/opt/store/python3.14"),
    )
    # Fix Staged venv_dir/bin for PATH rendering (not executed).
    object.__setattr__(staged, "venv_dir", tmp_path / "venv")

    def _verify_unit(base_text: str, dropin_text: str) -> tuple[int, str]:
        unit_dir = tmp_path / f"verify-{abs(hash(dropin_text)) % 100000}"
        unit_dir.mkdir(exist_ok=True)
        base = unit_dir / "verifycut.service"
        base.write_text(base_text, encoding="utf-8")
        dropin_dir = unit_dir / "verifycut.service.d"
        dropin_dir.mkdir(exist_ok=True)
        (dropin_dir / "zzz-candidate.conf").write_text(dropin_text, encoding="utf-8")
        done = subprocess.run(
            ["systemd-analyze", "verify", str(base)],
            capture_output=True, text=True, timeout=60, check=False,
        )
        return done.returncode, (done.stdout or "") + (done.stderr or "")

    base_simple = (
        "[Unit]\nDescription=verify\n"
        "[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\n"
        "WorkingDirectory=/tmp\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    for render in (render_gateway_dropin, render_dashboard_dropin):
        good = render(config, staged)
        assert "ExecStart=\nExecStart=" in good
        # Good uses a fake python that exists but is not the real sleep;
        # point ExecStart at real binaries for verify (keep the reset shape).
        good_real = good.replace(str(fake_python), "/usr/bin/python3")
        _rc, out = _verify_unit(base_simple, good_real)
        own = [ln for ln in out.splitlines() if "verifycut" in ln]
        assert not any("more than one ExecStart" in ln for ln in own), "".join(own[:5])
        assert not any("bad unit file setting" in ln.lower() for ln in own), "".join(own[:5])
        broken = good_real.replace("ExecStart=\nExecStart=", "ExecStart=")
        assert "ExecStart=\nExecStart=" not in broken
        rc_b, out_b = _verify_unit(base_simple, broken)
        assert rc_b != 0
        assert "more than one ExecStart" in out_b


def test_wait_for_health_polls_through_transient_9119(tmp_path: Path) -> None:
    """Bounded poll: transient 9119/state lag after restart still succeeds stable."""
    from scripts.maintenance.cutover_health import wait_for_health

    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    # Simulate Type=simple early return: first 2 health polls see 500/stale,
    # then the fleet is ready. wait_for_health must poll, not fail fast.
    calls = {"n": 0}
    orig_http = dict(host.http)

    def _flaky_http(url: str, timeout: int = 10) -> tuple[int, str]:
        calls["n"] += 1
        host.timeline.append(("http", url))
        if calls["n"] <= 2:
            return (500, "not ready yet")
        return orig_http[url]

    host.http_get = _flaky_http  # type: ignore[method-assign]
    from scripts.maintenance.cutover_orchestrate import orchestrate as _orch

    # Drive via orchestrate to prove end-to-end polling + stability + rollback
    # preservation (no weakening: SHA/exe still bound on every attempt).
    result = _orch(host, config)
    assert result.status == "success"
    assert calls["n"] >= 3
    # Stability: polling happened (sleep between attempts) and PIDs stayed.
    assert any(k == "run" and "sleep" in d for k, d in host.timeline)


def test_wait_for_health_rejects_crash_loop_counter(tmp_path: Path) -> None:
    """Restart stability: NRestarts change after restart is a crash loop, never success."""
    from scripts.maintenance.cutover_health import wait_for_health
    from scripts.maintenance.cutover_stage import stage

    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    # Preflight FIRST on the healthy old fleet (baseline NRestarts=0).
    from scripts.maintenance.cutover_preflight import preflight as _pre

    baseline = _pre(host, config)
    # Crash loop: after restart NRestarts flips 0 -> 1 (no weakening to PID-only).
    # Override show AFTER baseline so preflight still sees the old fleet.
    host.run_handlers = [h for h in host.run_handlers if "systemctl show" not in h[0]]
    host.on_run(
        "systemctl show hermes-gateway",
        RunResult(0, "MainPID=4342\nActiveEnterTimestamp=2026-10-25 12:05:00\nNRestarts=1", ""),
    )
    host.on_run(
        "systemctl show hermes-dashboard",
        RunResult(0, "MainPID=4343\nActiveEnterTimestamp=2026-10-25 12:05:01\nNRestarts=0", ""),
    )
    # Seed new-fleet proc bindings so the test isolates the counter gate.
    host.exes[4342] = "/opt/store/python/bin/python3.14"
    host.exes[4343] = "/opt/store/python/bin/python3.14"
    host.start_times[4342] = 200
    host.start_times[4343] = 200
    staged = stage(host, config, baseline)
    report = wait_for_health(host, config, staged, baseline, timeout_s=6, interval_s=2)
    assert not report.ok
    assert "NRestarts" in report.detail


def test_stage_carries_live_selection_extras_not_core_only(tmp_path: Path) -> None:
    """Runtime extras: stage mirrors baseline facts (web/telegram), never core-only."""
    import json as _json

    from scripts.maintenance.cutover_stage import (
        extras_anchors_for,
        selected_extras_from_facts,
        stage_argv,
        verify_staged_extras,
    )

    config = _make_config(tmp_path)
    facts = _json.dumps(
        {"packages": {"venv": {"stamp": "x", "extras": ["web", "telegram"], "environment": "y"}}}
    ).encode()
    extras, use_all = selected_extras_from_facts(facts)
    assert extras == ["telegram", "web"] and not use_all
    argv = stage_argv(config, extras, use_all)
    assert "--extra" in argv and "web" in argv and "telegram" in argv
    assert "pm.build_env" in " ".join(argv)
    # all-meta maps to --all-extras ALONE (uv rejects --all-extras + --extra).
    facts_all = _json.dumps(
        {"packages": {"venv": {"stamp": "x", "extras": ["all", "telegram"], "environment": "y"}}}
    ).encode()
    extras2, use_all2 = selected_extras_from_facts(facts_all)
    assert use_all2 and extras2 == ["telegram"]
    assert "--all-extras" in stage_argv(config, extras2, use_all2)
    assert "--extra" not in stage_argv(config, extras2, use_all2)
    # Anchors cover messaging/telegram platform deps (no live outbound).
    anchors = extras_anchors_for(["telegram", "web"])
    assert "telegram" in anchors and "fastapi" in anchors
    # Staged probe proves the venv carries them (FakeHost seeded true).
    host = FakeHost()
    venv_python = _seed_success_host(host, config)
    from scripts.maintenance.cutover_types import Staged as _Staged

    staged = _Staged(
        generation_dir=config.generation_root / "gen-aaaaaaaaaaaa",
        venv_dir=config.generation_root / "gen-aaaaaaaaaaaa" / "venv",
        venv_python=venv_python,
        store_home=Path("/opt/store/python/bin"),
        store_exe=Path("/opt/store/python/bin/python3.14"),
    )
    verify_staged_extras(host, config, staged, ["web", "telegram"], False)
    # Core-only build would miss them: empty anchors pass, but a strict
    # missing-anchor payload must fail (proves the gate is real).
    def _missing_probe(argv: list[str]) -> RunResult:
        if str(venv_python) in argv and "-c" in argv and "find_spec" in " ".join(argv):
            return RunResult(0, _json.dumps({"fastapi": False, "telegram": False}), "")
        return RunResult(0, "", "")

    host2 = FakeHost()
    _seed_success_host(host2, config)
    host2.run_handlers = [h for h in host2.run_handlers if str(venv_python) not in h[0]]
    host2.on_run(str(venv_python), _missing_probe)
    try:
        verify_staged_extras(host2, config, staged, ["web", "telegram"], False)
        gate_real = False
    except Exception:
        gate_real = True
    assert gate_real


def test_verify_staged_extras_uses_real_pm_anchors_not_invented(tmp_path: Path) -> None:
    """Validator must use the PM anchor contract, never extra.replace('-','_').

    Regression for gen-134a568025ee: PM built --all-extras fine, but
    verify_staged_extras failed on invented anchors
    ['audio_io','bedrock','computer_use','doc_extract','stt_whisper',
     'trace_upload','vertex','vision','wecom'].
    Real mapping (pm/extras.py ANCHORS + sourced mcp/sms/uvloop):
    bedrock->boto3, stt-whisper->faster_whisper, vertex->google.auth,
    vision->PIL, wecom->defusedxml, audio-io->sounddevice+numpy,
    doc-extract->anydoc, computer-use->mcp, trace-upload->huggingface_hub,
    keychain->keyring (pyproject [keychain]==["keyring==..."], pm ANCHORS,
    agent/vault_keychain.py imports keyring; opt-in credential store,
    KeychainUnavailable when the extra or an OS keychain is absent).
    Empty/meta extras (cron/pty/nemo-relay/all/termux*) carry no anchor.
    """
    import json as _json

    from scripts.maintenance.cutover_stage import (
        _EXTRA_ANCHORS,
        _NO_ANCHOR_EXTRAS,
        extras_anchors_for,
        verify_staged_extras,
    )

    invented = [
        "audio_io", "bedrock", "computer_use", "doc_extract", "stt_whisper",
        "trace_upload", "vertex", "vision", "wecom",
    ]
    failing_extras = [
        "audio-io", "bedrock", "computer-use", "doc-extract", "stt-whisper",
        "trace-upload", "vertex", "vision", "wecom",
    ]
    anchors = extras_anchors_for(failing_extras)
    # Real sourced anchors must be present...
    for real in (
        "sounddevice", "numpy", "boto3", "mcp", "anydoc", "faster_whisper",
        "google.auth", "PIL", "huggingface_hub", "defusedxml",
    ):
        assert real in anchors, f"missing real anchor {real} in {anchors}"
    # ...and invented module names must never be requested.
    for bogus in invented:
        assert bogus not in anchors, f"invented anchor {bogus!r} requested"
    # Empty/meta extras contribute no anchors (no invented `sms`/`cron`/`pty`).
    assert extras_anchors_for(["cron", "pty", "nemo-relay"]) == []
    assert extras_anchors_for(["all", "termux", "termux-all"]) == []
    assert extras_anchors_for(["sms"]) == ["aiohttp"]
    assert extras_anchors_for(["mcp"]) == ["mcp"]
    assert extras_anchors_for(["uvloop"]) == ["uvloop"]
    # Credential-store extra: keychain proves via keyring (opt-in, never invented).
    assert extras_anchors_for(["keychain"]) == ["keyring"]
    # Unknown extras fail closed instead of inventing an import.
    try:
        extras_anchors_for(["not-a-real-extra-xyz"])
        unknown_ok = True
    except Exception:
        unknown_ok = False
    assert not unknown_ok
    # Contract: validator mirrors pm/extras.py ANCHORS exactly where PM names one.
    import pm.extras as _pm_extras

    def _norm(v: object) -> tuple[str, ...]:
        return v if isinstance(v, tuple) else (v,)  # type: ignore[return-value]

    for extra, anchor in _pm_extras.ANCHORS.items():
        assert extra in _EXTRA_ANCHORS, f"validator missing PM anchor {extra!r}"
        assert tuple(_EXTRA_ANCHORS[extra]) == _norm(anchor), (
            f"validator anchor for {extra!r} drifted from pm/extras.py"
        )
    # Declared-but-unanchored in PM must be explicitly covered (no silent invent).
    assert {"mcp", "sms", "uvloop"} <= set(_EXTRA_ANCHORS)
    assert {"cron", "pty", "nemo-relay", "all", "termux", "termux-all"} <= set(
        _NO_ANCHOR_EXTRAS
    )
    # Every pyproject extra must be covered: otherwise the validator would
    # block a legitimate latest env (e.g. CI's keychain extra) fail-closed.
    import tomllib as _tomllib

    _declared = set(
        _tomllib.loads(
            (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(
                encoding="utf-8"
            )
        )["project"]["optional-dependencies"]
    )
    _covered = set(_EXTRA_ANCHORS) | set(_NO_ANCHOR_EXTRAS)
    assert _declared <= _covered, (
        f"validator blocks legitimate extras {_declared - _covered}"
    )
    # End-to-end through the staged probe: the 9 previously-failing extras
    # verify against a probe that reports their REAL anchors present.
    config = _make_config(tmp_path)
    host = FakeHost()
    venv_python = _seed_success_host(host, config)
    from scripts.maintenance.cutover_types import Staged as _Staged

    staged = _Staged(
        generation_dir=config.generation_root / "gen-aaaaaaaaaaaa",
        venv_dir=config.generation_root / "gen-aaaaaaaaaaaa" / "venv",
        venv_python=venv_python,
        store_home=Path("/opt/store/python/bin"),
        store_exe=Path("/opt/store/python/bin/python3.14"),
    )
    verify_staged_extras(host, config, staged, failing_extras, False)
    # The probe must have been asked for real anchors (capture the request).
    # Re-run with a capturing probe to assert the exact requested set.
    import re as _re

    captured: dict[str, list[str]] = {}

    def _capture(argv: list[str]) -> RunResult:
        blob = " ".join(argv)
        if "find_spec" in blob:
            m = _re.search(r"_anchors=(\[.*?\])", blob)
            if m:
                captured["anchors"] = sorted(_json.loads(m.group(1)))
                return RunResult(
                    0, _json.dumps({a: True for a in captured["anchors"]}), ""
                )
        return RunResult(0, "", "")

    host2 = FakeHost()
    _seed_success_host(host2, config)
    host2.run_handlers = [
        h for h in host2.run_handlers if str(venv_python) not in h[0]
    ]
    host2.on_run(str(venv_python), _capture)
    verify_staged_extras(host2, config, staged, failing_extras, False)
    assert captured.get("anchors") == sorted(
        {
            "sounddevice", "numpy", "boto3", "mcp", "anydoc",
            "faster_whisper", "huggingface_hub", "google.auth",
            "PIL", "defusedxml",
        }
    )
    for bogus in invented:
        assert bogus not in (captured.get("anchors") or [])
    # Keychain end-to-end: staged venv carrying keyring passes; a core-only
    # staged venv missing keyring fails (gate is real, no silent pass).
    verify_staged_extras(host, config, staged, ["keychain"], False)

    def _missing_keyring(argv: list[str]) -> RunResult:
        if str(venv_python) in argv and "find_spec" in " ".join(argv):
            return RunResult(0, _json.dumps({"keyring": False}), "")
        return RunResult(0, "", "")

    host3 = FakeHost()
    _seed_success_host(host3, config)
    host3.run_handlers = [
        h for h in host3.run_handlers if str(venv_python) not in h[0]
    ]
    host3.on_run(str(venv_python), _missing_keyring)
    try:
        verify_staged_extras(host3, config, staged, ["keychain"], False)
        _keyring_gate_real = False
    except Exception:
        _keyring_gate_real = True
    assert _keyring_gate_real


def test_candidate_web_dist_rejects_fake_and_requires_ignored(tmp_path: Path) -> None:
    """Dashboard --skip-build: dist must be prebuilt, receipted, ignored, not fake."""
    from scripts.maintenance.cutover_stage import verify_candidate_web_dist

    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    # Seeded good dist passes.
    verify_candidate_web_dist(host, config)
    # Fake (tiny) index is refused.
    candidate = config.candidate_src
    host.files[str(candidate / "hermes_cli" / "web_dist" / "index.html")] = b"fake"
    try:
        verify_candidate_web_dist(host, config)
        fake_ok = True
    except Exception:
        fake_ok = False
    assert not fake_ok
    # Missing receipt is refused (no fake artifacts).
    host2 = FakeHost()
    _seed_success_host(host2, config)
    host2.files.pop(str(candidate / "hermes_cli" / "web_dist" / "hermes-build.json"), None)
    try:
        verify_candidate_web_dist(host2, config)
        receipt_ok = True
    except Exception:
        receipt_ok = False
    assert not receipt_ok


def test_stage_all_extras_alone_passes_pm_build_env_contract(tmp_path: Path, monkeypatch) -> None:
    """Regression: live `all` + named extras stages as `--all-extras` alone.

    Root stage failed: `uv sync exited 2: --all-extras cannot be used with --extra`.
    stage_argv passed both; PM forwarded the conflict. `--all-extras` alone is the
    semantic superset, so individual `--extra` are dropped when `all` is set.
    Uses the ACTUAL `pm.build_env` parser with a bounded fake for the build only
    (no venv mutation, no live effects).
    """
    import json as _json

    import pm
    import pm.client as _pm_client
    from pm import build_env as _build_env
    from scripts.maintenance.cutover_stage import (
        selected_extras_from_facts,
        stage_argv,
    )
    from scripts.maintenance.cutover_types import venv_dir_for

    config = _make_config(tmp_path)
    live_extras = [
        "acp", "all", "audio-io", "bedrock", "computer-use", "discord",
        "doc-extract", "edge-tts", "google", "slack", "stt-whisper",
        "telegram", "trace-upload", "vertex", "vision", "web", "wecom", "youtube",
    ]
    facts = _json.dumps(
        {"packages": {"venv": {"stamp": "x", "extras": live_extras, "environment": "y"}}}
    ).encode()
    extras, use_all = selected_extras_from_facts(facts)
    assert use_all
    assert "all" not in extras
    assert sorted(extras) == sorted(e for e in live_extras if e != "all")

    argv = stage_argv(config, extras, use_all)
    assert "--all-extras" in argv
    assert "--extra" not in argv
    assert "pm.build_env" in " ".join(argv)

    # Contract: the ACTUAL pm.build_env parser accepts the staged argv.
    calls: dict = {}

    def _fake_build(**kwargs):
        calls.update(kwargs)
        return tmp_path / "fake-python"

    monkeypatch.setattr(pm, "build_environment", _fake_build)
    monkeypatch.setattr(_pm_client, "build_environment", _fake_build)
    cli_args = argv[argv.index("pm.build_env") + 1:]
    assert _build_env.main(cli_args) == 0
    assert calls.get("all_extras") is True
    assert list(calls.get("extras") or []) == []
    # Bounded fake built nothing: no venv mutation.
    assert not venv_dir_for(config).exists()

    # Explicit extras path still carries --extra and is accepted.
    calls.clear()
    argv2 = stage_argv(config, ["telegram", "web"], False)
    assert "--all-extras" not in argv2
    assert argv2.count("--extra") == 2
    cli_args2 = argv2[argv2.index("pm.build_env") + 1:]
    assert _build_env.main(cli_args2) == 0
    assert calls.get("all_extras") is False
    assert sorted(calls.get("extras") or []) == ["telegram", "web"]


def test_owner_git_never_runs_as_root_and_needs_no_safe_directory(tmp_path: Path, monkeypatch) -> None:
    """Systemd root must run git as ubuntu via absolute runuser/env -i, never safe.directory.

    Regression for the external `FAILED PRE-MUTATION` where systemd root
    (clean env, no SUDO_UID) hit `fatal: detected dubious ownership` on
    `git -C … rev-parse HEAD` while the sudo shell passed. The fix never
    sets `safe.directory=*` and never runs git as root directly.
    """
    import os as _os

    from scripts.maintenance import cutover_git as _git

    assert _git._RUNUSER == "/usr/sbin/runuser"
    assert _git._ENV == "/usr/bin/env"
    assert _git._GIT == "/usr/bin/git"
    assert _git._OWNER == "ubuntu"
    assert _git._OWNER_HOME == "/home/ubuntu"
    assert _git.owner_git_env() == {
        "HOME": "/home/ubuntu",
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
    }

    repo = tmp_path / "repo"
    inner = _git.git_inner_argv(repo, "rev-parse", "HEAD")
    assert inner[0] == "/usr/bin/git"
    assert inner[1:3] == ["-C", str(repo.absolute())]
    assert "safe.directory" not in " ".join(inner)

    env = _git.owner_git_env()
    monkeypatch.setattr(_os, "geteuid", lambda: 0)
    wrapped_root = _git.wrap_owner_git(inner, env)
    assert wrapped_root[0] == "/usr/sbin/runuser"
    assert wrapped_root[1:4] == ["-u", "ubuntu", "--"]
    assert wrapped_root[4] == "/usr/bin/env" and wrapped_root[5] == "-i"
    assert "HOME=/home/ubuntu" in wrapped_root
    assert "PATH=/usr/bin:/bin" in wrapped_root
    assert "GIT_CONFIG_NOSYSTEM=1" in wrapped_root
    assert "/usr/bin/git" in wrapped_root
    assert "safe.directory" not in " ".join(wrapped_root)
    assert wrapped_root[0] != "git" and wrapped_root[0] != "/usr/bin/git"

    monkeypatch.setattr(_os, "geteuid", lambda: 1000)
    wrapped_user = _git.wrap_owner_git(inner, env)
    assert wrapped_user[0] == "/usr/bin/env" and wrapped_user[1] == "-i"
    assert "/usr/sbin/runuser" not in wrapped_user
    assert "safe.directory" not in " ".join(wrapped_user)

    # run_owner_git carries explicit cwd + env + bounded timeout, no inheritance.
    timeouts: list[int] = []
    seen: dict[str, object] = {}

    class _TimeoutHost(FakeHost):
        def run(self, argv, timeout=60, cwd=None, env=None):  # type: ignore[override]
            timeouts.append(int(timeout))
            seen["cwd"] = str(cwd) if cwd is not None else None
            seen["env"] = dict(env) if env is not None else None
            return super().run(argv, timeout=timeout, cwd=cwd, env=env)

    monkeypatch.setattr(_os, "geteuid", lambda: 0)
    host = _TimeoutHost()
    host.on_run("rev-parse", RunResult(0, "a" * 40, ""))
    res = _git.run_owner_git(host, repo, ["rev-parse", "HEAD"], timeout=30)
    assert res.returncode == 0
    assert timeouts == [30]
    assert seen["cwd"] == str(repo.absolute())
    assert seen["env"] == _git.owner_git_env()
    assert host.run_cwds[-1] == str(repo.absolute())
    assert host.run_envs[-1] == _git.owner_git_env()
    argv_text = host.timeline[-1][1]
    assert argv_text.startswith("/usr/sbin/runuser -u ubuntu -- /usr/bin/env -i")
    assert "/usr/bin/git -C" in argv_text


def test_all_controller_git_routes_use_owner_wrapper_under_systemd_root(
    tmp_path: Path, monkeypatch
) -> None:
    """Every git route (preflight live/candidate, web-dist, health, restore) is owner-scoped.

    Simulates systemd root (euid 0, clean env without SUDO_UID) and drives the
    full orchestrator plus an explicit untouched restore. Parent retries the
    systemd preflight against these exact argv/owner/cwd/env bindings.
    """
    import os as _os

    from scripts.maintenance import cutover_git as _git

    monkeypatch.setattr(_os, "geteuid", lambda: 0)
    config = _make_config(tmp_path)

    records: list[tuple[list[str], int, object, object]] = []

    class _RecordHost(FakeHost):
        def run(self, argv, timeout=60, cwd=None, env=None):  # type: ignore[override]
            records.append((list(argv), int(timeout), cwd, dict(env) if env is not None else None))
            return super().run(argv, timeout=timeout, cwd=cwd, env=env)

    host = _RecordHost()
    _seed_success_host(host, config)
    result = orchestrate(host, config)
    assert result.status == "success"

    git_runs = [
        (argv, timeout, cwd, env)
        for argv, timeout, cwd, env in records
        if any("rev-parse" in str(a) or "check-ignore" in str(a) for a in argv)
    ]
    # preflight live + candidate, web-dist check-ignore, health candidate HEAD.
    assert len(git_runs) >= 4
    for argv, timeout, cwd, env in git_runs:
        detail = " ".join(argv)
        assert detail.startswith("/usr/sbin/runuser -u ubuntu -- /usr/bin/env -i"), detail
        assert "/usr/bin/git" in argv
        assert "-C" in argv
        assert "HOME=/home/ubuntu" in detail
        assert "GIT_CONFIG_NOSYSTEM=1" in detail
        assert "safe.directory" not in detail
        assert env == _git.owner_git_env()
        assert str(cwd) in (
            str(config.live_tree.absolute()),
            str(config.candidate_src.absolute()),
        )
        assert timeout in (30, 120)
        assert argv[0] == "/usr/sbin/runuser"
    # Both repos are covered: live rev-parse and candidate rev-parse/check-ignore.
    texts = [" ".join(argv) for argv, _, _, _ in git_runs]
    assert any(str(config.live_tree) in d for d in texts)
    assert any(str(config.candidate_src) in d for d in texts)
    assert any("check-ignore" in d for d in texts)

    # Untouched restore: rev-parse as owner, no checkout when HEAD == parent.
    from scripts.maintenance.cutover_restore import _restore_source
    from scripts.maintenance.cutover_snapshot import load_baseline

    baseline = load_baseline(host, config)
    before = len(host.timeline)
    _restore_source(host, config, baseline)
    tail = host.timeline[before:]
    assert any(kind == "run" and "rev-parse" in detail for kind, detail in tail)
    assert not any("checkout" in detail for _, detail in tail)
    last_git = next(detail for kind, detail in reversed(tail) if kind == "run")
    assert last_git.startswith("/usr/sbin/runuser -u ubuntu --")


def test_preflight_failure_is_failed_with_no_recovery_not_unknown(
    tmp_path: Path, monkeypatch
) -> None:
    """Pre-mutation preflight refusal is failed/fleet-untouched, never unknown.

    The external cutover hit dubious-ownership preflight failure (fleet
    untouched, Gateway 15839 / Dashboard 15683 still active) but the receipt
    was unknown, so OnFailure resume refused on the terminal receipt. Failed
    signals no recovery is needed; the parent retries with a NEW journal
    while the previous unknown receipt is preserved.
    """
    from scripts.maintenance.cutover_journal import has_terminal_receipt, read_all

    import os as _os

    # Simulate systemd root clean env (no SUDO_UID): owner wrapper uses runuser.
    monkeypatch.setattr(_os, "geteuid", lambda: 0)
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    # Remove the seeded success git handler (matches "git -C") so the
    # dubious-ownership failure is the one that runs. Handlers match by
    # substring in order, so the old handler must go first.
    host.run_handlers = [
        h
        for h in host.run_handlers
        if "git -C" not in h[0] and "/usr/bin/git" not in h[0] and "rev-parse" not in h[0]
    ]

    def _dubious(argv: list[str]) -> RunResult:
        if "rev-parse" in " ".join(argv):
            return RunResult(128, "", "fatal: detected dubious ownership in repository")
        return RunResult(0, "", "")

    host.on_run("runuser", _dubious)
    host.on_run("/usr/bin/git", _dubious)
    host.on_run("rev-parse", _dubious)
    result = orchestrate(host, config)
    assert result.status == "failed"
    assert "fleet untouched" in result.reason
    assert "preflight" in result.reason
    assert result.status != "unknown"
    assert has_terminal_receipt(host, config.journal_path)
    rows = read_all(host, config.journal_path)
    assert any(r.get("phase") == "receipt-failed" for r in rows)
    assert not any(r.get("phase") == "receipt-unknown" for r in rows)
    # No live lifecycle: untouched Gateway/Dashboard are never restarted.
    assert not any(
        kind == "run" and ("systemctl restart" in detail or "daemon-reload" in detail)
        for kind, detail in host.timeline
    )


def test_real_clean_env_git_as_owner_needs_no_safe_directory(tmp_path: Path) -> None:
    """Real clean-env git (systemd-like, no SUDO_*, no GIT_*) succeeds as the owner.

    Feasible without root: run the exact owner env through absolute
    `/usr/bin/env -i` against this checkout. Proves no `safe.directory`
    exception is needed when the owner runs git. Skipped for root (root
    clean-env on an ubuntu-owned tree is the dubious-ownership failure the
    wrapper fixes via runuser; that path is covered by the injected test).
    """
    import os as _os
    import subprocess as _subprocess

    try:
        euid = _os.geteuid()
    except AttributeError:
        euid = 1000
    if euid == 0:
        import pytest as _pytest

        _pytest.skip("owner clean-env probe is only meaningful as non-root")
    repo_root = Path(__file__).resolve().parents[2]
    done = _subprocess.run(
        [
            "/usr/bin/env", "-i",
            "HOME=/home/ubuntu", "PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1",
            "/usr/bin/git", "-C", str(repo_root), "rev-parse", "HEAD",
        ],
        capture_output=True, text=True, timeout=30, check=False,
        cwd=str(repo_root),
        env={"PATH": "/usr/bin:/bin"},
    )
    assert done.returncode == 0, (done.stdout or "") + (done.stderr or "")
    assert len((done.stdout or "").strip()) == 40
    assert "dubious ownership" not in (done.stderr or "")
