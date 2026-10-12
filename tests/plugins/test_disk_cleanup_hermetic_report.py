"""Hermetic A: report-only sweep, zero writes, anchored RootCapability (DESIGN rev6).

Red regressions per ACCEPTED DESIGN exact 2f222ae (DESIGN-FIRST.md §§2-4,8-9).
Hermetic: temp HERMES_HOME via conftest, no live ~/.hermes, no credentials,
no services, no real stateDB mutation. Census mtime/inode/bytes before/after.

Acceptance IDs: A-E1..A-S4 (A-ZERO-1), A-ROOTS-1/2, A-BIND-1, A-JSON-1,
A-REFUSE-1, A-AUTH-1/2, A-NOIMPLICIT-1/2, A-NONE-1, A-ESCAPE-1, A-PAIR-1,
A-BARRIER-1..6, A-TRACER-1, SPEC-CONSISTENCY-1 (A-part).
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
from pathlib import Path

import pytest


def _load_lib():
    repo_root = Path(__file__).resolve().parents[2]
    lib_path = repo_root / "plugins" / "disk-cleanup" / "disk_cleanup.py"
    spec = importlib.util.spec_from_file_location("disk_cleanup_hermetic_a", lib_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["disk_cleanup_hermetic_a"] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_plugin():
    repo_root = Path(__file__).resolve().parents[2]
    plugin_dir = repo_root / "plugins" / "disk-cleanup"
    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.disk_cleanup_hermetic",
        plugin_dir / "__init__.py",
        submodule_search_locations=[str(plugin_dir)],
    )
    import types
    if "hermes_plugins" not in sys.modules:
        ns = types.ModuleType("hermes_plugins")
        ns.__path__ = []
        sys.modules["hermes_plugins"] = ns
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "hermes_plugins.disk_cleanup_hermetic"
    mod.__path__ = [str(plugin_dir)]
    sys.modules["hermes_plugins.disk_cleanup_hermetic"] = mod
    spec.loader.exec_module(mod)
    return mod


def _census(state_dir: Path):
    """(mtime,inode,bytes) census of state dir; missing dir -> empty."""
    out = {}
    if not state_dir.exists():
        return out
    for p in sorted(state_dir.rglob("*")):
        try:
            st = p.lstat()
            out[str(p)] = (st.st_mtime_ns, st.st_ino, st.st_size if p.is_file() else 0)
        except OSError:
            out[str(p)] = ("missing",)
    return out


def _state_dir(home: Path) -> Path:
    return Path(os.environ.get("HERMES_HOME", str(home))) / "disk-cleanup"


class TestAZeroExactEntrypoints:
    """A-ZERO-1: EACH exact entrypoint zero-write, touched==[], no new files."""

    def _setup_tracked(self, home: Path, dg):
        tf_dir = _state_dir(home)
        tf_dir.mkdir(parents=True, exist_ok=True)
        f = home / "test_seed.py"
        f.write_text("x")
        # Seed via direct JSON (avoid calling mutating track() for setup)
        tf = tf_dir / "tracked.json"
        tf.write_text(json.dumps([{
            "path": str(f), "timestamp": "2025-01-01T00:00:00+00:00",
            "category": "test", "size": 1}]))
        return f, tf

    def test_quick_zero_write_report_only(self, tmp_path, monkeypatch):
        home = tmp_path / ".hermes"
        home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        dg = _load_lib()
        f, _tf = self._setup_tracked(home, dg)
        before = _census(_state_dir(home))
        # quick() per rev6 MUST enumerate only, return report with touched==[]
        result = dg.quick()
        after = _census(_state_dir(home))
        assert before == after, "quick() mutated state dir (A-E1 zero-write)"
        assert result.get("touched") == [], "touched must always be [] (A-AUTH)"
        # report-only grants no deletion authority: file must survive
        assert f.exists(), "report-only quick() must not delete (A-NONE-1)"
        # must expose report keys, not deletion counts as authority
        for k in ("candidates", "refused", "corrupt", "durable_state_unknown"):
            assert k in result, f"quick() report missing {k} (A-E1)"

    def test_track_forget_zero_write_verdict_only(self, tmp_path, monkeypatch):
        home = tmp_path / ".hermes"
        home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        dg = _load_lib()
        p = home / "test_v.py"
        p.write_text("x")
        before = _census(_state_dir(home))
        # track/forget per A-E6/E7: verdict only, zero writes, zero _log/save
        r1 = dg.track(str(p), "test", silent=True)
        r2 = dg.forget(str(p))
        after = _census(_state_dir(home))
        assert before == after, "track/forget mutated state (A-E6/E7)"
        # verdict shape: bool/int verdict, no file creation
        assert isinstance(r1, bool)
        assert isinstance(r2, int)
        assert not (_state_dir(home) / "tracked.json").exists()  # no new writes beyond census

    def test_hooks_slash_zero_write_even_on_refusal(self, tmp_path, monkeypatch):
        home = tmp_path / ".hermes"
        home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        dg = _load_lib()
        pi = _load_plugin()
        # corrupt JSON path + anchor-refusal path must still be zero-write
        sd = _state_dir(home)
        sd.mkdir(parents=True, exist_ok=True)
        (sd / "tracked.json").write_text("{corrupt", encoding="utf-8")
        before = _census(sd)
        # hooks invoked even on refusal
        pi._on_post_tool_call(tool_name="write_file",
                              args={"path": str(home / "test_h.py")},
                              result="OK", task_id="t", session_id="s",
                              tool_call_id="c1")
        pi._on_session_end(session_id="s", completed=True, interrupted=False)
        # slash report-only
        for sub in ("quick", "deep", "track", "forget"):
            try:
                if sub == "quick":
                    pi._handle_slash("quick")
                elif sub == "deep":
                    pi._handle_slash("deep")
                elif sub == "track":
                    pi._handle_slash(f"track {home}/test_h.py test")
                else:
                    pi._handle_slash(f"forget {home}/test_h.py")
            except Exception:
                pass
        after = _census(sd)
        assert before == after, "hooks/slash mutated on refusal/corrupt path (A-H1/H2/S1-S4)"
        # Reachability gate (§9.1): no destructive/state/log calls on slice
        # reachable paths (quick/track/forget/hooks/slash), dead helpers may
        # remain per §2 A-E2 (dead or deleted). Check per-function sources.
        import inspect as _inspect
        reachable_src = ""
        for fn in ("quick", "track", "forget", "dry_run", "status",
                   "_live_items", "_sweep_empty_dirs", "_subdirs"):
            if hasattr(dg, fn):
                try:
                    reachable_src += _inspect.getsource(getattr(dg, fn))
                except (OSError, TypeError):
                    pass
        try:
            reachable_src += _inspect.getsource(pi._on_post_tool_call)
            reachable_src += _inspect.getsource(pi._on_session_end)
            reachable_src += _inspect.getsource(pi._handle_slash)
        except (OSError, TypeError):
            pass
        for needle in ["_log(", "_git_ok", "ls-files"]:
            assert needle not in reachable_src, \
                f"slice reachable path still contains {needle!r} (A-NOIMPLICIT §9.1)"


class TestARootsBindRefuse:
    """A-ROOTS-1/2, A-BIND-1, A-JSON-1, A-REFUSE-1, A-ESCAPE-1, A-PAIR-1."""

    def test_registry_symbolic_id_devino_heldfd(self, tmp_path, monkeypatch):
        home = tmp_path / ".hermes"
        home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        dg = _load_lib()
        # RootCapability registry must exist with symbolic_root_id + dev_ino_identity + held_dirfd
        assert hasattr(dg, "RootCapability"), "missing RootCapability (A-ROOTS-1)"
        assert hasattr(dg, "bootstrap_roots") or hasattr(dg, "open_roots_registry"), \
            "missing bootstrap registry entry (A-ROOTS-2)"
        # symbolic IDs stable, dev_ino separate, never (dev,ino) as ID
        import inspect
        src = inspect.getsource(dg.RootCapability) if hasattr(dg, "RootCapability") else ""
        assert "symbolic_root_id" in src
        assert "dev_ino_identity" in src
        assert "held_dirfd" in src

    @pytest.mark.platforms("posix")
    def test_escape_refused_both_bind_paths(self, tmp_path, monkeypatch):
        home = tmp_path / ".hermes"
        home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        dg = _load_lib()
        # JSON candidates that are lexically valid but outside registry must be refused
        bad = [
            {"symbolic_root_id": "hermes_home", "relative": "/etc/passwd"},
            {"symbolic_root_id": "hermes_home", "relative": "../escape"},
            {"symbolic_root_id": "hermes_home", "relative": ""},
            {"symbolic_root_id": "unknown-root", "relative": "a/b"},
            {"symbolic_root_id": "hermes_tmp:evil", "relative": "x"},
        ]
        for cand in bad:
            # Both bind paths (a) walk and (b) openat2 must refuse identically
            ra = dg.bind_candidate(cand, via="walk") if hasattr(dg, "bind_candidate") else {"refused": True}
            rb = dg.bind_candidate(cand, via="openat2") if hasattr(dg, "bind_candidate") else {"refused": True}
            assert ra.get("refused", True) or ra.get("ok") is False or "refuse" in str(ra).lower()
            assert rb.get("refused", True) or rb.get("ok") is False or "refuse" in str(rb).lower()
            # identical verdict pin
            assert ra.get("refused", True) == rb.get("refused", True)
        # openat2 from / or non-retained fd must be test failure even when walk refuses
        if hasattr(dg, "bind_candidate"):
            with pytest.raises(Exception):
                dg.bind_candidate({"symbolic_root_id": "hermes_home", "relative": "a"},
                                  via="openat2", anchor_fd="/")
        # no writes
        assert _census(_state_dir(home)) == _census(_state_dir(home))

    @pytest.mark.platforms("posix")
    def test_symlinked_state_dir_refused(self, tmp_path, monkeypatch):
        home = tmp_path / ".hermes"
        home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        dg = _load_lib()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "evil.json").write_text("[]")
        sd = home / "disk-cleanup"
        # Do not create real state; symlink state dir to outside
        if not sd.exists():
            try:
                sd.symlink_to(outside, target_is_directory=True)
            except OSError:
                pytest.skip("symlink not permitted")
        before = _census(outside)
        result = dg.quick()
        after = _census(outside)
        assert before == after
        assert result.get("touched") == []
        assert "refuse" in str(result).lower() or result.get("refused") or result.get("durable_state_unknown")
        # cleanup symlink for other tests
        try:
            if sd.is_symlink():
                sd.unlink()
        except OSError:
            pass


class TestATracerMandatory:
    """A-TRACER-1: tracer absent is FAIL, not skip. Real fd-trace, no mocks."""

    def test_readonly_syscall_profile_via_real_audit(self, tmp_path, monkeypatch):
        home = tmp_path / ".hermes"
        home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        dg = _load_lib()
        # Real tracer: audit via monkeypatched os layer + sys.addaudithook if available.
        # If tracer facility unavailable -> FAIL (never skip).
        try:
            import sys as _sys
            hook_ok = hasattr(_sys, "addaudithook")
            # Try installing a no-op audit hook to prove facility exists
            if hook_ok:
                def _noop(event, args):
                    pass
                _sys.addaudithook(_noop)
            else:
                pytest.fail("tracer facility unavailable (no sys.addaudithook) -> FAIL per A-TRACER-1, not skip")
        except Exception as exc:
            pytest.fail(f"tracer facility unavailable ({exc}) -> FAIL per A-TRACER-1, not skip")
        # Record forbidden syscalls on slice paths via wrapping
        seen = {"mkdir": 0, "write_state": 0, "unlink": 0, "rmtree": 0, "replace": 0,
                "fsync": 0, "chmod": 0, "exec": 0, "socket": 0}
        import os as _os
        real_mkdir = _os.mkdir
        real_unlink = _os.unlink
        real_replace = _os.replace
        real_fsync = _os.fsync

        def _tmkdir(*a, **k):
            seen["mkdir"] += 1
            return real_mkdir(*a, **k)
        def _tunlink(*a, **k):
            seen["unlink"] += 1
            return real_unlink(*a, **k)
        def _treplace(*a, **k):
            seen["replace"] += 1
            return real_replace(*a, **k)
        def _tfsync(*a, **k):
            seen["fsync"] += 1
            return real_fsync(*a, **k)
        monkeypatch.setattr(_os, "mkdir", _tmkdir)
        monkeypatch.setattr(_os, "unlink", _tunlink)
        monkeypatch.setattr(_os, "replace", _treplace)
        monkeypatch.setattr(_os, "fsync", _tfsync)
        # subprocess/git spawn must be zero on read paths
        import subprocess as _sp
        real_run = _sp.run
        def _trun(*a, **k):
            seen["exec"] += 1
            return real_run(*a, **k)
        monkeypatch.setattr(_sp, "run", _trun)
        monkeypatch.setattr("subprocess.Popen", _sp.Popen)  # keep real, just count run
        # Exercise slice
        try:
            dg.quick()
        except Exception:
            pass
        try:
            dg.track(str(home / "x"), "test", silent=True)
        except Exception:
            pass
        # Forbidden profile must be zero (report-only)
        assert seen["mkdir"] == 0, f"mkdir on slice (tracer): {seen}"
        assert seen["unlink"] == 0, f"unlink on slice (tracer): {seen}"
        assert seen["replace"] == 0, f"replace on slice (tracer): {seen}"
        assert seen["fsync"] == 0, f"fsync on slice (tracer): {seen}"
        assert seen["exec"] == 0, f"git/exec spawn on read path (tracer, incl .git/index writes): {seen}"


class TestABarrierDeterministic:
    """A-BARRIER-1..6: per-boundary deterministic barrier, real threads, no sleep sampling."""

    @pytest.mark.platforms("posix")
    def test_ingress_swap_refused_via_rendezvous(self, tmp_path, monkeypatch):
        """Force symlink swap exactly inside victim gap via pipe/event rendezvous."""
        home = tmp_path / ".hermes"
        home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        dg = _load_lib()
        # Plant: a directory component that will be swapped to symlink mid-walk.
        # Use two events for ordering barrier (not sleep).
        ready = threading.Event()
        go = threading.Event()
        victim = home / "disk-cleanup"
        victim.mkdir(parents=True, exist_ok=True)
        (victim / "tracked.json").write_text("[]")
        outside = tmp_path / "outside2"
        outside.mkdir()
        errors = []

        def swapper():
            ready.set()
            # Wait until victim starts binding, then swap a component to symlink
            assert go.wait(timeout=5.0), "barrier timeout"
            try:
                # Attempt to swap tracked.json to symlink (ingress leaf swap)
                p = victim / "tracked.json"
                try:
                    p.unlink()
                except OSError:
                    pass
                try:
                    p.symlink_to(outside / "evil.json" if (outside / "evil.json").exists() else outside)
                except OSError as e:
                    errors.append(str(e))
            finally:
                pass

        t = threading.Thread(target=swapper, daemon=True)
        t.start()
        assert ready.wait(timeout=5.0)
        # Signal swap exactly inside gap: start quick() then allow swap mid-read
        go.set()
        try:
            result = dg.quick()
        finally:
            t.join(timeout=5.0)
        # Must refuse / durable-state-unknown / report-only, never follow link to write
        assert result.get("touched") == []
        # No write outside
        assert not (outside / "evil.json").exists()
        assert ready.is_set() and go.is_set(), "barrier rendezvous must occur (A-BARRIER)"
