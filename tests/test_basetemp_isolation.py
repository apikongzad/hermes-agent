"""pytest's basetemp must never sit inside the operator's platform-native Hermes home.

Every per-test sandbox is ``<basetemp>/.../hermes_test`` and ``get_default_hermes_root()``
prefers the platform-native home whenever ``HERMES_HOME`` sits *under* it — so a basetemp
inside the home silently turns the sandbox back into the live install (#111101).
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import hermes_constants
from tests import conftest as suite_conftest


@pytest.fixture(autouse=True)
def _sibling_root_only(monkeypatch):
    """Relocate into the sibling-of-native root, never the host's shared disk root: these
    tests use a fake native home under tmp_path and must not create or prune anything real."""
    import os

    real_isdir = os.path.isdir
    monkeypatch.setattr(suite_conftest.os.path, "isdir", lambda p: False if p == "/var/tmp" else real_isdir(p))  # no-tmp: ok — disables the disk-root branch


def _config_with_basetemp(given: Path | None) -> SimpleNamespace:
    return SimpleNamespace(
        _tmp_path_factory=SimpleNamespace(_given_basetemp=given),
        option=SimpleNamespace(basetemp=str(given) if given else None),
    )


def test_basetemp_inside_the_native_home_is_relocated_outside_it(tmp_path, monkeypatch):
    native = tmp_path / "native-home"
    native.mkdir()
    monkeypatch.setattr(hermes_constants, "_get_platform_default_hermes_home", lambda: native)
    config = _config_with_basetemp(native / ".repro")

    suite_conftest._relocate_basetemp_outside_operator_home(config)

    relocated = config._tmp_path_factory._given_basetemp
    assert relocated is not None and not relocated.resolve().is_relative_to(native.resolve())
    assert config.option.basetemp == str(relocated)
    # One shared, prunable root (never a loose dir in the operator's $HOME) and gone when
    # this pytest exits; a run killed before that is swept as soon as the root is idle.
    assert relocated.parent.name == "hermes-pytest" and relocated.parent != Path.home()
    # Isolate teardown from ambient /proc: controlled empty inventory, never a real scan
    # that could see (and resolve) an unrelated live HERMES_HOME or signal it.
    seen: dict = {}

    def _no_processes(roots):
        seen["roots"] = list(roots)
        return []

    monkeypatch.setattr(suite_conftest, "_processes_with_hermes_home_under", _no_processes)
    killed: list = []
    monkeypatch.setattr(suite_conftest.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    suite_conftest.pytest_unconfigure(config)
    assert seen["roots"][0] == relocated
    assert killed == []
    assert not relocated.exists()
    # The sandbox derived from it no longer resolves to the native root.
    monkeypatch.setenv("HERMES_HOME", str(relocated / "t0" / "hermes_test"))
    assert hermes_constants.get_default_hermes_root() == relocated / "t0" / "hermes_test"


def test_basetemp_outside_the_native_home_is_left_alone(tmp_path, monkeypatch):
    native = tmp_path / "native-home"
    native.mkdir()
    monkeypatch.setattr(hermes_constants, "_get_platform_default_hermes_home", lambda: native)
    given = tmp_path / "elsewhere"
    config = _config_with_basetemp(given)

    suite_conftest._relocate_basetemp_outside_operator_home(config)

    assert config._tmp_path_factory._given_basetemp == given
    assert config.option.basetemp == str(given)


def test_fallback_root_escapes_a_repo_checked_out_inside_the_native_home(tmp_path, monkeypatch):
    # Default install: repo at ~/.hermes/hermes-agent and TEMP under the home (Windows).
    native = tmp_path / "native-home"
    (native / "hermes-agent").mkdir(parents=True)
    monkeypatch.setattr(hermes_constants, "_get_platform_default_hermes_home", lambda: native)
    monkeypatch.setattr(suite_conftest, "PROJECT_ROOT", native / "hermes-agent")
    monkeypatch.setattr(suite_conftest.tempfile, "gettempdir", lambda: str(native / "tmp"))
    monkeypatch.delenv("PYTEST_DEBUG_TEMPROOT", raising=False)
    config = _config_with_basetemp(None)

    suite_conftest._relocate_basetemp_outside_operator_home(config)

    relocated = config._tmp_path_factory._given_basetemp
    assert relocated is not None and not relocated.resolve().is_relative_to(native.resolve())


def test_relocation_root_sweeps_basetemps_of_killed_runs_and_keeps_live_ones(tmp_path, monkeypatch):
    import os
    import time

    native = tmp_path / "native-home"
    native.mkdir()
    root = native.parent / "hermes-pytest"
    dead, live = root / "b-dead", root / "b-live"
    dead.mkdir(parents=True)
    live.mkdir()
    (dead / "f").write_text("x", encoding="utf-8")
    (live / "f").write_text("x", encoding="utf-8")
    ancient = time.time() - 30 * 3600
    for p in (dead, dead / "f", live):
        os.utime(p, (ancient, ancient))
    assert suite_conftest._pytest_disk_temp_root(native) == root
    assert not dead.exists() and live.exists()


def _fake_proc_inventory(monkeypatch, entries):
    """Controlled /proc inventory: pid -> HERMES_HOME bytes (or None for no var)."""
    import builtins
    import io
    import os

    class _Entry:
        def __init__(self, name):
            self.name = name

    def _fake_scandir(path):
        assert os.fspath(path) == "/proc"
        return [_Entry(str(pid)) for pid in entries]

    real_open = builtins.open

    def _fake_open(path, *args, **kwargs):
        path_s = os.fspath(path)
        if path_s.startswith("/proc/") and path_s.endswith("/environ"):
            try:
                pid = int(path_s.split("/")[2])
            except ValueError:
                return real_open(path, *args, **kwargs)
            home = entries.get(pid)
            data = b"" if home is None else b"HERMES_HOME=" + home + b"\0OTHER=1\0"
            return io.BytesIO(data)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", _fake_scandir)
    monkeypatch.setattr(builtins, "open", _fake_open)


@pytest.mark.platforms("linux")
def test_processes_scan_ignores_unrelated_real_home_without_resolving_it(tmp_path, monkeypatch):
    """Unrelated live HERMES_HOME is never selected and never filesystem-touched.

    Regression for the full-suite worker that listed an ambient
    ``HERMES_HOME=/home/ubuntu/.hermes/runtime/...`` process: resolving it stats
    guarded ancestors and trips HomeIOGuard. The lexical prefilter must skip it
    before ``Path.resolve()`` while the owned tmp fixture still qualifies.
    """
    import os

    owned_root = tmp_path / "owned"
    owned_root.mkdir()
    owned_home = owned_root / "hermes_test"
    owned_home.mkdir()
    try:
        real_roots = suite_conftest._REAL_HERMES_ROOT_CANDIDATES
        unrelated = (
            real_roots[0] / "runtime" / "cutover-generations-next"
            if real_roots
            else Path.home() / ".hermes" / "runtime-probe"
        )
    except Exception:
        unrelated = Path.home() / ".hermes" / "runtime-probe"
    owned_pid, foreign_pid, empty_pid = 424201, 424202, 424203
    self_pid = os.getpid()
    _fake_proc_inventory(
        monkeypatch,
        {
            owned_pid: os.fsencode(str(owned_home)),
            foreign_pid: os.fsencode(str(unrelated)),
            empty_pid: None,
            self_pid: os.fsencode(str(owned_home)),
        },
    )
    real_resolve = Path.resolve
    resolved_seen: list[str] = []

    def _tracking_resolve(self, *args, **kwargs):
        resolved_seen.append(os.fspath(self))
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", _tracking_resolve)
    found = suite_conftest._processes_with_hermes_home_under([owned_root])
    assert found == [owned_pid]
    assert os.fspath(unrelated) not in resolved_seen


@pytest.mark.platforms("linux")
def test_reap_only_signals_owned_fixture_home(tmp_path, monkeypatch):
    """Identity never broadens: teardown SIGTERMs the owned pid, never the foreign one."""
    import os
    import signal

    owned_root = tmp_path / "session-root"
    owned_root.mkdir()
    owned_home = owned_root / "hermes_test"
    owned_home.mkdir()
    try:
        real_roots = suite_conftest._REAL_HERMES_ROOT_CANDIDATES
        unrelated = (
            real_roots[0] / "runtime" / "cutover-generations-next"
            if real_roots
            else Path.home() / ".hermes" / "runtime-probe"
        )
    except Exception:
        unrelated = Path.home() / ".hermes" / "runtime-probe"
    owned_pid, foreign_pid = 424211, 424212
    _fake_proc_inventory(
        monkeypatch,
        {
            owned_pid: os.fsencode(str(owned_home)),
            foreign_pid: os.fsencode(str(unrelated)),
        },
    )
    assert suite_conftest._processes_with_hermes_home_under([owned_root]) == [owned_pid]
    killed: list = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))
    config = SimpleNamespace(
        _tmp_path_factory=SimpleNamespace(_basetemp=owned_root),
        _hermes_relocated_basetemp=None,
        option=SimpleNamespace(basetemp=str(owned_root)),
    )
    # Keep the session-sandbox root from widening identity: point it at the owned root.
    monkeypatch.setenv("HERMES_TEST_SANDBOX_HOME", str(owned_root))
    reaped = suite_conftest._reap_session_hermes_processes(config)
    assert reaped == [owned_pid]
    assert killed == [(owned_pid, signal.SIGTERM)]
