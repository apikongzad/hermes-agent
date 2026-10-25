"""Cutover safety contract: behavioral bar for the standalone maintenance controller.

Replaces the e5 placeholders (hardcoded SHA inequality, manually ordered
list, FakeHost never invoking production code, assert True, source-reading
swallow detector). Every test below drives the ACTUAL orchestrator in
scripts/maintenance/cutover_* through an injected Host with no live effects
(no systemctl, no git checkout, no sends, no game changes).

Bar (each maps to a concrete parent finding):
- PARENT must equal the live main SHA, never a stale merge parent.
- No cgroup count==2 gate on a worker-invisible path.
- Controller file must live inside the candidate tree under test.
- No outbound sends (no telegram): success/failure is a local receipt only.
- Dashboard health is 9119, never 3000/8501.
- No invented PM entrypoints (pm.py, scripts/sync_venv.py,
  scripts/publish_launcher.py do not exist); supported entrypoints are
  `hermes pm install`, pm.sync_venv, pm.build_environment,
  pm.ensure_environment, hermes_cli.venv_sync.publish_launchers.
- HERMES_EXE env dropin does not select the interpreter: units hardcode
  ExecStart to the venv python, so a safe cutover must bind ExecStart +
  WorkingDirectory to the staged tree and save/restore reversible dropin bytes.
- Restore order is source/facts/dropins, then daemon-reload, then restart,
  then verify; never start-before-restore, never swallow restore errors.
- Health binds candidate SHA plus /proc/PID/exe interpreter, not a launcher
  --version string and not the old runtime's version.
"""

from __future__ import annotations

from pathlib import Path

from scripts.maintenance import cutover as facade
from scripts.maintenance.cutover_orchestrate import orchestrate
from scripts.maintenance.cutover_types import CutoverConfig, Host, RunResult


CANDIDATE_SHA = "a" * 40
PARENT_SHA = "b" * 40


class FakeHost(Host):
    """Injected IO adapter: records every effect, no live effects."""

    def __init__(self) -> None:
        self.timeline: list[tuple[str, str]] = []
        self.files: dict[str, bytes | Exception] = {}
        self.exes: dict[int, str | Exception] = {}
        self.http: dict[str, tuple[int, str] | Exception] = {}
        self.run_handlers: list[tuple[str, object]] = []

    def on_run(self, prefix: str, result: object) -> None:
        self.run_handlers.append((prefix, result))

    def run(self, argv: list[str], timeout: int = 60) -> RunResult:
        self.timeline.append(("run", " ".join(argv)))
        key = " ".join(argv)
        for prefix, result in self.run_handlers:
            if key.startswith(prefix):
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

    def readlink_exe(self, pid: int) -> str:
        self.timeline.append(("exe", str(pid)))
        if pid in self.exes:
            value = self.exes[pid]
            if isinstance(value, Exception):
                raise value
            assert isinstance(value, str)
            return value
        raise OSError(f"no exe for {pid}")

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


def _seed_success_host(host: FakeHost, config: CutoverConfig) -> Path:
    gen = config.generation_root / f"gen-{CANDIDATE_SHA[:12]}"
    venv_python = gen / "venv" / "bin" / "python3"
    host.files[str(config.candidate_src / "scripts" / "maintenance" / "cutover.py")] = (
        b"def orchestrate(): pass"
    )
    host.files[str(config.hermes_home / "tools" / "facts.json")] = b'{"packages": {}}'
    host.files[str(config.hermes_home / "gateway_state.json")] = (
        f'{{"code_sha": "{CANDIDATE_SHA}"}}'.encode()
    )
    host.on_run(
        "systemctl cat hermes-gateway", RunResult(0, "ExecStart=/x\ngateway", "")
    )
    host.on_run(
        "systemctl cat hermes-dashboard", RunResult(0, "ExecStart=/y\ndash", "")
    )
    host.on_run("systemctl show hermes-gateway", RunResult(0, "MainPID=4242", ""))
    host.on_run("systemctl is-active", RunResult(0, "active", ""))

    def _git_head(argv: list[str]) -> RunResult:
        text = " ".join(argv)
        if str(config.live_tree) in text:
            return RunResult(0, PARENT_SHA, "")
        if str(config.candidate_src) in text:
            return RunResult(0, CANDIDATE_SHA, "")
        return RunResult(1, "", "no repo")

    host.on_run("git -C", _git_head)
    host.on_run("python3 -m pm.build_env", RunResult(0, str(venv_python), ""))

    def _staged_probe(argv: list[str]) -> RunResult:
        if argv[0] == str(venv_python) and "-c" in argv:
            return RunResult(0, f"{venv_python}\n{gen}/venv", "")
        return RunResult(0, "", "")

    host.on_run(str(venv_python), _staged_probe)
    old_exe = "/home/ubuntu/.hermes/old-venv/bin/python3"
    host.exes[4242] = old_exe
    host.on_run("systemctl daemon-reload", RunResult(0, "", ""))

    def _restart(argv: list[str]) -> RunResult:
        host.exes[4242] = str(venv_python)
        return RunResult(0, "", "")

    host.on_run("systemctl restart", _restart)
    host.http["http://127.0.0.1:9119/health"] = (200, "ok")
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
    stale_host.run_handlers = [
        h for h in stale_host.run_handlers if not h[0].startswith("git -C")
    ]
    stale_host.on_run("git -C", _stale_git)
    stale_result = orchestrate(stale_host, stale)
    assert stale_result.status == "unknown"
    assert "preflight" in stale_result.reason


def test_no_cgroup_gate_controller_ignores_worker_invisible_path(
    tmp_path: Path,
) -> None:
    """Orchestration never consults cgroup.procs; it succeeds either way."""
    for with_cgroup in (False, True):
        config = _make_config(
            tmp_path, journal_path=tmp_path / f"j-{with_cgroup}.jsonl"
        )
        host = FakeHost()
        venv_python = _seed_success_host(host, config)
        if with_cgroup:
            host.files[
                "/sys/fs/cgroup/system.slice/hermes-gateway.service/cgroup.procs"
            ] = b"1\n2\n"
        result = orchestrate(host, config)
        assert result.status == "success"
        assert str(venv_python) in result.extra.get("exe", "")
        assert not any(
            kind == "read" and "cgroup.procs" in detail
            for kind, detail in host.timeline
        )


def test_controller_lives_inside_candidate_tree_under_test() -> None:
    """The shipped controller file is inside the repo (candidate) tree, not /tmp."""
    repo_root = Path(__file__).resolve().parents[2]
    controller_file = Path(facade.__file__).resolve()
    assert controller_file.is_relative_to(repo_root)
    assert (repo_root / "scripts" / "maintenance" / "cutover.py").is_file()


def test_no_outbound_sends_success_and_failure_are_local_receipts(
    tmp_path: Path,
) -> None:
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
    failing_host.http["http://127.0.0.1:9119/health"] = (500, "bad")
    failing_result = orchestrate(failing_host, failing)
    assert failing_result.status in ("failed", "unknown")
    for kind, detail in failing_host.timeline:
        assert "telegram" not in detail
        if kind == "run":
            assert " send " not in f" {detail} "


def test_dashboard_health_is_9119_never_legacy_ports(tmp_path: Path) -> None:
    """Health probes 9119; the orchestrator never touches 3000/8501."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    result = orchestrate(host, config)
    assert result.status == "success"
    http_urls = [detail for kind, detail in host.timeline if kind == "http"]
    assert http_urls == ["http://127.0.0.1:9119/health"]
    assert not any("3000" in detail or "8501" in detail for _, detail in host.timeline)


def test_staging_uses_documented_pm_entrypoint_and_no_invented_ones(
    tmp_path: Path,
) -> None:
    """Staging invokes python -m pm.build_env; invented pm.py paths never appear."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    result = orchestrate(host, config)
    assert result.status == "success"
    run_cmds = [detail for kind, detail in host.timeline if kind == "run"]
    assert any(cmd.startswith("python3 -m pm.build_env --source") for cmd in run_cmds)
    assert not any("pm.py" in cmd for cmd in run_cmds)
    assert not any("scripts/sync_venv.py" in cmd for cmd in run_cmds)
    assert not any("scripts/publish_launcher.py" in cmd for cmd in run_cmds)


def test_install_failure_triggers_restore_not_success(tmp_path: Path) -> None:
    """A PM staging failure restores (source/facts/dropins) and never reports success."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    host.run_handlers = [
        h for h in host.run_handlers if not h[0].startswith("python3 -m pm.build_env")
    ]
    host.on_run("python3 -m pm.build_env", RunResult(1, "", "uv sync failed"))
    result = orchestrate(host, config)
    assert result.status in ("failed", "unknown")
    assert result.status != "success"
    kinds = [kind for kind, _ in host.timeline]
    assert "run" in kinds and "write" in kinds


def test_dropin_binds_execstart_workdir_path_and_sorts_after_runtime(
    tmp_path: Path,
) -> None:
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


def test_restore_order_is_source_facts_dropins_reload_restart_verify(
    tmp_path: Path,
) -> None:
    """Health failure rolls back in the mandated order, never start-before-restore."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    host.http["http://127.0.0.1:9119/health"] = (500, "bad")
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
        if (
            entry.startswith("write:")
            and "facts.json" in entry
            and "facts" not in positions
        ):
            positions["facts"] = index
        if (
            entry.startswith("remove:")
            and "zzz-candidate" in entry
            and "dropins" not in positions
        ):
            positions["dropins"] = index
        if "systemctl daemon-reload" in entry and "reload" not in positions:
            positions["reload"] = index
        if "systemctl restart" in entry and "restart" not in positions:
            positions["restart"] = index
        if entry.startswith("http:") and "verify" not in positions:
            positions["verify"] = index
    assert set(positions) == {
        "source",
        "facts",
        "dropins",
        "reload",
        "restart",
        "verify",
    }
    assert positions["source"] < positions["facts"] < positions["dropins"]
    assert (
        positions["dropins"]
        < positions["reload"]
        < positions["restart"]
        < positions["verify"]
    )


def test_start_health_failure_triggers_rollback_not_success(tmp_path: Path) -> None:
    """Restart ok + 9119 refused must roll back and never report success."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    host.http["http://127.0.0.1:9119/health"] = OSError("9119 refused")
    result = orchestrate(host, config)
    assert result.status in ("failed", "unknown")
    assert result.status != "success"
    assert any(
        kind == "remove" and "zzz-candidate" in detail for kind, detail in host.timeline
    )


def test_health_binds_sha_and_proc_exe_not_version_string(tmp_path: Path) -> None:
    """Health requires candidate SHA + staged exe; it never runs --version."""
    config = _make_config(tmp_path)
    host = FakeHost()
    venv_python = _seed_success_host(host, config)
    result = orchestrate(host, config)
    assert result.status == "success"
    run_cmds = [detail for kind, detail in host.timeline if kind == "run"]
    assert any("rev-parse" in cmd for cmd in run_cmds)
    assert any(kind == "exe" for kind, _ in host.timeline)
    assert not any("--version" in cmd for cmd in run_cmds)
    assert str(venv_python) in (host.exes[4242] or "")
    assert (
        CANDIDATE_SHA
        in host.files[str(config.hermes_home / "gateway_state.json")].decode()
    )  # type: ignore[union-attr]


def test_rollback_failure_is_unknown_never_success(tmp_path: Path) -> None:
    """When the restore itself fails, the receipt is unknown, never success."""
    config = _make_config(tmp_path)
    host = FakeHost()
    _seed_success_host(host, config)
    host.http["http://127.0.0.1:9119/health"] = (500, "bad")
    calls = {"reloads": 0}

    def _flaky_reload(argv: list[str]) -> RunResult:
        calls["reloads"] += 1
        if calls["reloads"] >= 2:
            return RunResult(1, "", "daemon-reload failed in rollback")
        return RunResult(0, "", "")

    host.run_handlers = [
        h for h in host.run_handlers if not h[0].startswith("systemctl daemon-reload")
    ]
    host.on_run("systemctl daemon-reload", _flaky_reload)
    result = orchestrate(host, config)
    assert result.status == "unknown"
    assert result.status != "success"
