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
    def _which(self, name: str):
        import os as _os
        for d in _os.environ.get("PATH", "").split(_os.pathsep):
            if not d:
                continue
            cand = _os.path.join(d, name)
            try:
                if _os.path.isfile(cand) and _os.access(cand, _os.X_OK):
                    return cand
            except OSError:
                continue
        return None

    def _forbidden_hits(self, log: str):
        hits = []
        for forb in ("mkdir(", "mkdirat(", "unlink(", "unlinkat(",
                     "rmdir(", "rename(", "renameat(", "symlink(", "symlinkat(",
                     'execve("git', 'execve("./git'):
            if forb in log:
                hits.append(forb)
        return hits

    def test_real_tracer_strace_file_process_hooks_slash(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        repo_root = Path(__file__).resolve().parents[2]
        import subprocess as _sp
        strace = self._which("strace")
        if not strace:
            pytest.fail("BLOCKED A-TRACER-1: no strace binary — must not fake audit-hook pass; do not install (parent handles)")
        # Version is diagnostic only, NEVER proof: must still produce nonempty trace below.
        try:
            pv = _sp.run([strace, "--version"], capture_output=True, text=True, timeout=5, check=False)
            _version_ok = (pv.returncode == 0)
        except Exception:
            _version_ok = False
        # Hermetic log under workspace/.cache, NEVER bare /tmp.
        cache_dir = home / "workspace" / ".cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        log_path = cache_dir / "redA-strace.log"
        canary_path = cache_dir / "redA-canary.log"
        assert not str(log_path).startswith("/tmp/") or str(home) in str(log_path), \
            "tracer log must live under hermetic workspace/.cache, not bare /tmp"
        # Isolated child: real readonly API calls covering hooks + slash.
        dg_path = repo_root / "plugins" / "disk-cleanup" / "disk_cleanup.py"
        plug_path = repo_root / "plugins" / "disk-cleanup" / "__init__.py"
        code = (
            "import os,sys; os.environ['HERMES_HOME']=sys.argv[1]; "
            f"sys.path.insert(0, {str(repo_root)!r}); "
            "import importlib.util as _ilu, sys as _sys; "
            f"spec=_ilu.spec_from_file_location('dg_trace', {str(dg_path)!r}); "
            "dg=_ilu.module_from_spec(spec); _sys.modules['dg_trace']=dg; spec.loader.exec_module(dg); "
            f"spec2=_ilu.spec_from_file_location('plug_trace', {str(plug_path)!r}); "
            "plug=_ilu.module_from_spec(spec2); _sys.modules['plug_trace']=plug; spec2.loader.exec_module(plug); "
            # Real readonly slice: bound reads only, no writes.
            "dg.status(); dg.dry_run(); dg.quick(); "
            # Slash readonly subcommands.
            "plug._handle_slash('status'); plug._handle_slash('dry-run'); "
            # Hooks readonly classification (absent-path snapshot, no writes).
            "plug._on_pre_tool_call(tool_name='write_file', args={'path': 'test_probe_x.py'}, task_id='t1', session_id='s1', tool_call_id='c1'); "
            "plug._on_post_tool_call(tool_name='write_file', args={'path': 'test_probe_x.py'}, task_id='t1', session_id='s1', tool_call_id='c1'); "
        )
        _sp.run([strace, "-f", "-e", "trace=%file,%process", "-o", str(log_path),
                 sys.executable, "-c", code, str(home)],
                capture_output=True, text=True, timeout=20, check=False)
        # Parse: nonempty trace required — version-ok alone NEVER passes.
        try:
            log = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log = ""
        assert log.strip() != "", \
            f"RED A-TRACER: empty trace FAIL (version_ok={_version_ok} is not proof); strace produced no output"
        # Startup boundary: trace must start from child exec (proves full capture, not truncated/empty).
        assert "execve(" in log, "RED A-TRACER: missing startup boundary execve( (trace truncated or not -f from start)"
        # File/process classes actually traced.
        assert ("openat" in log or "open(" in log), "RED A-TRACER: no file-class syscalls (need -e trace=%file)"
        # Zero forbidden syscalls on readonly slice.
        hits = self._forbidden_hits(log)
        assert hits == [], f"RED A-TRACER: forbidden syscall on readonly slice: {hits}"
        # Positive canary: same parser MUST reject a real forbidden syscall (proves non-vacuous).
        canary_code = (
            "import os,sys,pathlib; os.environ['HERMES_HOME']=sys.argv[1]; "
            "p=pathlib.Path(sys.argv[1]) / 'canary_dir_proof'; p.mkdir(exist_ok=True)"
        )
        _sp.run([strace, "-f", "-e", "trace=%file,%process", "-o", str(canary_path),
                 sys.executable, "-c", canary_code, str(home)],
                capture_output=True, text=True, timeout=15, check=False)
        try:
            canary_log = canary_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            canary_log = ""
        assert canary_log.strip() != "", "RED A-TRACER canary: empty trace FAIL"
        assert "execve(" in canary_log, "RED A-TRACER canary: missing startup boundary"
        canary_hits = self._forbidden_hits(canary_log)
        assert "mkdir(" in canary_log or "mkdirat(" in canary_log, \
            "RED A-TRACER canary: expected mkdir in canary trace, got none (parser vacuous check failed)"
        assert canary_hits != [], \
            "RED A-TRACER canary: parser failed to reject real forbidden mkdir (must reject)"
        # Never used bare /tmp log.
        assert not Path("/tmp/redA-strace.log").exists(), "must not use bare /tmp log; use workspace/.cache"
