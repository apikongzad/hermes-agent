"""RED A: exact repros for independent-review failures on ef2390d3.

Functional (no source-string checks): direct invocation must refuse, no
writes, lazy temp bind, real openat2 refusal, symlink/O_NOFOLLOW fail-closed,
real tracer BLOCKED when missing. Hermetic temp HERMES_HOME, no live host.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest


def _load_lib():
    repo_root = Path(__file__).resolve().parents[2]
    lib_path = repo_root / "plugins" / "disk-cleanup" / "disk_cleanup.py"
    spec = importlib.util.spec_from_file_location("disk_cleanup_red_a", lib_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["disk_cleanup_red_a"] = mod
    spec.loader.exec_module(mod)
    return mod


def _census(state_dir: Path):
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


def _home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


class TestARedDirectMutationRefused:
    def test_delete_item_direct_refused_no_delete(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        f = home / "test_victim.py"
        f.write_text("victim")
        sd = _state_dir(home)
        before = _census(sd)
        # Direct private invocation must refuse, never delete.
        refused = False
        try:
            out = dg._delete_item({"path": str(f), "category": "test", "size": 6})
            # If it returns without raising, file must still survive and no log write.
            if out is not None and "refus" in str(out).lower():
                refused = True
            elif f.exists():
                # Survived but did it refuse explicitly? Require explicit refusal signal.
                refused = False
        except Exception as exc:
            refused = "refus" in str(exc).lower() or "report-only" in str(exc).lower() or "denied" in str(exc).lower()
        after = _census(sd)
        assert f.exists(), "RED A: _delete_item directly deleted file (must refuse, report-only)"
        assert before == after, "RED A: _delete_item wrote state (mkdir/log)"
        assert refused, "RED A: _delete_item must explicitly refuse (raise/report refused), not silent no-op"

    def test_log_no_mkdir_write(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        sd = _state_dir(home)
        # Ensure absent before
        assert not sd.exists() or _census(sd) == _census(sd)
        before = _census(sd)
        try:
            dg._log("probe-line")
        except Exception:
            pass
        after = _census(sd)
        assert before == after, "RED A: _log created mkdir/log write (must be no-write)"
        assert not (sd / "cleanup.log").exists(), "RED A: _log wrote cleanup.log"

    def test_save_tracked_direct_refused(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        sd = _state_dir(home)
        before = _census(sd)
        refused = False
        try:
            dg.save_tracked([{"path": str(home / "x"), "timestamp": "2025-01-01T00:00:00+00:00",
                              "category": "test", "size": 1}])
        except Exception as exc:
            refused = "refus" in str(exc).lower() or "report-only" in str(exc).lower() or "denied" in str(exc).lower()
        after = _census(sd)
        assert before == after, "RED A: save_tracked wrote state"
        assert not (sd / "tracked.json").exists(), "RED A: save_tracked created tracked.json"
        assert refused, "RED A: save_tracked must explicitly refuse on direct call"

    def test_load_no_mkdir_nobak(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        sd = _state_dir(home)
        # Remove state dir if exists
        import shutil as _sh
        if sd.exists():
            _sh.rmtree(sd)
        assert not sd.exists()
        try:
            out = dg.load_tracked()
            # If it returns, it must not have created dir, and must be list (bound read empty)
            assert isinstance(out, list), "load_tracked must return list via bound read"
        except Exception as exc:
            # Refusal also acceptable only if bound read path is via _bound_read_tracked?
            # For report-only, load must be bound-read-or-refuse with no mkdir: raise with refuse is ok
            assert "refus" in str(exc).lower() or "report-only" in str(exc).lower() or "unknown" in str(exc).lower()
        assert not sd.exists(), "RED A: load_tracked mkdir'd state dir (must be no-mkdir bound read)"

    def test_git_no_spawn_all_routes(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        import subprocess as _sp
        calls = []

        def _boom_run(*a, **k):
            calls.append(("run", a))
            raise AssertionError("RED A: git/subprocess spawn on read path (must be zero)")

        def _boom_popen(*a, **k):
            calls.append(("popen", a))
            raise AssertionError("RED A: Popen spawn on read path (must be zero)")

        monkeypatch.setattr(_sp, "run", _boom_run)
        monkeypatch.setattr(_sp, "Popen", _boom_popen)
        # All git routes must be dead/refuse without spawn, incl private direct
        p = home / "test_g.py"
        p.write_text("x")
        # guess_category must not spawn
        try:
            dg.guess_category(p)
        except Exception:
            pass
        # private git helpers must refuse without spawn if they still exist
        for fn in ("_git_tracks", "_inside_git_worktree"):
            if hasattr(dg, fn):
                try:
                    getattr(dg, fn)(p)
                except Exception as exc:
                    # Must refuse, not spawn (spawn already blocked by boom)
                    assert "refus" in str(exc).lower() or "report-only" in str(exc).lower() or "denied" in str(exc).lower()
        assert calls == [], f"RED A: subprocess spawn occurred on slice: {calls}"


class TestARedRegistryLazyOpenat2:
    def test_no_enumerate_all_tmp_lazy_bind(self, tmp_path, monkeypatch):
        _home(tmp_path, monkeypatch)
        dg = _load_lib()
        # Create two temp instances under real /tmp (allowed /tmp/**) with unique basenames
        import tempfile as _tf
        bases = []
        for _ in range(2):
            d = _tf.mkdtemp(prefix="hermes-redA-", dir="/tmp")
            bases.append(os.path.basename(d))
        try:
            reg = dg.bootstrap_roots() if hasattr(dg, "bootstrap_roots") else dg.open_roots_registry()
            try:
                # Lazy registry must contain ONLY hermes_home, NOT pre-enumerated temp
                assert "hermes_home" in reg, "registry must contain hermes_home"
                tmp_keys = [k for k in reg if k.startswith("hermes_tmp:")]
                assert tmp_keys == [], f"RED A: registry enumerated all /tmp/hermes-* {tmp_keys} (must lazily bind only requested, bounded fds)"
            finally:
                for e in reg.values():
                    try:
                        os.close(e.held_dirfd)
                    except OSError:
                        pass
            # Lazy bind of specifically requested basename must work without enumerating other
            if hasattr(dg, "bind_temp_basename"):
                cap = dg.bind_temp_basename(bases[0])
                try:
                    assert cap is not None and cap.get("ok") or "symbolic_root_id" in str(cap)
                finally:
                    # bounded fds close: helper must expose close or auto-close
                    if hasattr(dg, "close_capability"):
                        try:
                            dg.close_capability(cap)
                        except Exception:
                            pass
            else:
                pytest.fail("RED A: missing lazy bind_temp_basename (must lazily bind specifically requested basename, bounded fds close)")
        finally:
            import shutil as _sh
            for b in bases:
                try:
                    _sh.rmtree(os.path.join("/tmp", b))
                except OSError:
                    pass

    def test_symlink_ancestor_rejected(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        # Symlinked state dir must be refused
        outside = tmp_path / "outside_sym"
        outside.mkdir()
        (outside / "evil.json").write_text("[]")
        sd = home / "disk-cleanup"
        if not sd.exists():
            try:
                sd.symlink_to(outside, target_is_directory=True)
            except OSError:
                pytest.skip("symlink not permitted")
        try:
            res = dg.quick()
            assert res.get("touched") == []
            s = str(res).lower()
            assert "refus" in s or res.get("refused") or res.get("durable_state_unknown") or res.get("corrupt"), \
                "RED A: symlinked ancestor must be refused"
        finally:
            try:
                if sd.is_symlink():
                    sd.unlink()
            except OSError:
                pass

    def test_missing_nofollow_fail_closed(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        # Simulate platform without O_NOFOLLOW/O_DIRECTORY: must fail closed, not downgrade
        import os as _os
        had_nofollow = hasattr(_os, "O_NOFOLLOW")
        had_dir = hasattr(_os, "O_DIRECTORY")
        if not had_nofollow and not had_dir:
            pytest.skip("platform already lacks capabilities")
        # Patch _open_single path by removing attrs temporarily via monkeypatch on os module?
        # Instead assert helper explicitly checks capability and refuses when missing.
        # We verify by calling with monkeypatched missing flag if helper supports it,
        # else assert helper source does not silently getattr-default to 0.
        # Functional: bind with symlink leaf must refuse even when O_NOFOLLOW present (ELOOP).
        # Here we assert ELOOP refusal works (fail-closed basis).
        victim = home / "disk-cleanup"
        victim.mkdir(parents=True, exist_ok=True)
        (victim / "tracked.json").write_text("[]")
        link = victim / "linkleaf"
        try:
            if link.exists() or link.is_symlink():
                link.unlink()
        except OSError:
            pass
        try:
            link.symlink_to(victim / "tracked.json")
        except OSError:
            pytest.skip("symlink not permitted")
        try:
            # Candidate pointing at symlink leaf via relative must refuse
            if hasattr(dg, "bind_candidate"):
                r = dg.bind_candidate({"symbolic_root_id": "hermes_home", "relative": "disk-cleanup/linkleaf"}, via="walk")
                assert r.get("refused"), f"RED A: symlink leaf must refuse, got {r}"
            else:
                pytest.fail("missing bind_candidate")
        finally:
            try:
                if link.is_symlink():
                    link.unlink()
            except OSError:
                pass

    def test_openat2_unsupported_explicit_refusal(self, tmp_path, monkeypatch):
        _home(tmp_path, monkeypatch)
        dg = _load_lib()
        assert hasattr(dg, "bind_candidate"), "missing bind_candidate"
        # Determine real openat2 support via helper if exposed, else via direct syscall probe
        supported = None
        if hasattr(dg, "openat2_supported"):
            try:
                supported = bool(dg.openat2_supported())
            except Exception:
                supported = None
        if supported is False:
            r = dg.bind_candidate({"symbolic_root_id": "hermes_home", "relative": "disk-cleanup/tracked.json"}, via="openat2")
            assert r.get("refused") and "openat2" in str(r.get("reason", "") + str(r)).lower(), \
                f"RED A: openat2 unsupported must explicit refusal (not mock walk), got {r}"
        elif supported is True:
            # When supported, openat2 path must use real openat2 (not same walk): verify identical refuse
            bad = {"symbolic_root_id": "hermes_home", "relative": "../escape"}
            ra = dg.bind_candidate(bad, via="walk")
            rb = dg.bind_candidate(bad, via="openat2")
            assert ra.get("refused") and rb.get("refused"), "both paths must refuse escape"
            assert ra.get("refused") == rb.get("refused")
        else:
            # Helper missing: current impl mocks same walk labelled openat2 -> must fail
            # Prove mock: both vias return identical ok for a valid relative without real syscall
            # We require explicit openat2_supported helper + explicit refusal, so fail red.
            pytest.fail("RED A: missing openat2_supported + explicit openat2-unsupported refusal (must not mock same walk labelled openat2)")


class TestARedTracerBlocked:
    def test_real_tracer_required_blocked_when_missing(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        # Real tracer: strace or seccomp or kernel fd-trace. If missing, acceptance BLOCKED (fail), never fake pass.
        has_real = False
        detail = ""
        # Probe 1: strace binary runnable (bounded, no live changes: --version only)
        try:
            import subprocess as _sp

            def _which(name: str):
                for d in __import__("os").environ.get("PATH", "").split(__import__("os").pathsep):
                    cand = __import__("os").path.join(d, name)
                    try:
                        if __import__("os").path.isfile(cand) and __import__("os").access(cand, __import__("os").X_OK):
                            return cand
                    except OSError:
                        continue
                return None

            strace = _which("strace")
            if strace:
                p = _sp.run([strace, "--version"], capture_output=True, text=True, timeout=5, check=False)
                if p.returncode == 0:
                    has_real = True
                    detail = "strace"
        except Exception as e:
            detail = f"strace probe failed: {e}"
        # Probe 2: seccomp python module
        if not has_real:
            try:
                import seccomp  # type: ignore
                has_real = True
                detail = "seccomp"
            except Exception:
                pass
        # Probe 3: explicit helper from lib exposing real trace support
        if not has_real and hasattr(dg, "tracer_available"):
            try:
                if bool(dg.tracer_available()):
                    has_real = True
                    detail = "lib-tracer"
            except Exception:
                pass
        if not has_real:
            pytest.fail(f"BLOCKED A-TRACER-1: no real tracer (strace/seccomp) available [{detail}] — must not fake audit-hook pass; do not install packages (parent handles)")
        # If real tracer exists, exercise slice under it and assert zero forbidden syscalls
        # (minimal: run quick() under strace -f -e trace=%file,%process and assert no mkdir/unlink etc)
        # Hermetic bounded: trace only quick() with temp home, output cap.
        try:
            import subprocess as _sp2
            strace2 = _which("strace") if "_which" in dir() else None
            if strace2 and detail == "strace":
                # Run quick() in subprocess under strace to get real syscall profile
                code = (
                    "import os,sys; os.environ['HERMES_HOME']=sys.argv[1]; "
                    "sys.path.insert(0, '.'); "
                    "import importlib.util; spec=importlib.util.spec_from_file_location('m','plugins/disk-cleanup/disk_cleanup.py'); "
                    "m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.quick()"
                )
                _sp2.run([strace2, "-f", "-e", "trace=%file,%process", "-o", "/tmp/redA-strace.log",
                               sys.executable, "-c", code, str(home)],
                              capture_output=True, text=True, timeout=15, check=False)
                # Read log bounded
                try:
                    log = Path("/tmp/redA-strace.log").read_text(encoding="utf-8", errors="replace")[:8000]
                except OSError:
                    log = ""
                for forb in ("mkdir", "unlink", "rmdir", "rename", "execve(\"git\"", "execve(\"./git\""):
                    assert forb not in log, f"RED A-TRACER: forbidden syscall {forb} on slice"
                try:
                    Path("/tmp/redA-strace.log").unlink()
                except OSError:
                    pass
        except Exception as e:
            pytest.fail(f"RED A-TRACER real-trace assertion failed: {e}")
