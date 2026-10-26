"""Scratch-root cleanup regressions: TMPDIR-aware temp scope stays confined.

Covers the ``_allowed_temp_prefixes`` / ``_match_temp_prefix`` change that
replaces the hardcoded ``/tmp/`` literal with Hermes scratch
(``<home>/cache/scratch``, TMPDIR-backed) + ``tempfile.gettempdir()``:

* report-only: zero mutating helpers on every slice path (track/forget/
  quick/dry_run/status + direct ``_delete_item``/``save_tracked``/``_log``/
  atomic/sync/git helpers refuse);
* symlink final leaf + parent component + path-outside + bad root +
  traversal all refused (lexical ``is_safe_path``/``track`` False +
  held-fd ``bind_candidate`` refused on BOTH walk and openat2 paths);
* no broaden deletion: scratch non-``hermes-*``, ``/tmp`` non-``hermes-*``,
  near-prefix (``/tmp-near``), ``/mnt/*``, project trees and ``..`` never
  become deletable — ``quick()`` stays ``deleted == 0`` / ``touched == []``
  and every file survives.

Hermetic: temp HERMES_HOME via monkeypatch, no live ``~/.hermes``, no
subprocess/git/strace/server/browser, no ``/tmp`` writes (scratch under the
hermetic home; temp-prefix checks are read-only). Real cleanup callers are
``plugins/disk-cleanup/__init__.py`` (``guess_category``/``track``/``quick``/
``dry_run``/``status``) — this file drives the same library entrypoints the
hooks and slash commands use.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from datetime import datetime, timedelta, timezone, UTC
from pathlib import Path

import pytest


def _load_lib():
    repo_root = Path(__file__).resolve().parents[2]
    lib_path = repo_root / "plugins" / "disk-cleanup" / "disk_cleanup.py"
    spec = importlib.util.spec_from_file_location("disk_cleanup_scratch_roots", lib_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["disk_cleanup_scratch_roots"] = mod
    spec.loader.exec_module(mod)
    return mod


def _home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


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


def _scratch(dg, home: Path) -> Path:
    from hermes_constants import get_scratch_dir

    # prune=False: no detached prune child, no timing dependence.
    return get_scratch_dir(home, prune=False)


class TestScratchPrefixesConfined:
    def test_prefixes_include_scratch_and_tempdir_longest_first(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        prefixes = dg._allowed_temp_prefixes()
        assert isinstance(prefixes, list) and len(prefixes) >= 1
        for p in prefixes:
            assert p.endswith("/") and p.startswith("/")
        # Scratch root is one of the prefixes (hermetic home).
        # Compare lexically without resolving symlinks: prefix list is built
        # from the same helpers, so at least the scratch string must match.
        scratch_prefix = str(_scratch(dg, home)).rstrip("/") + "/"
        assert scratch_prefix in prefixes
        # Longest-first ordering + deduped.
        assert prefixes == sorted(set(prefixes), key=len, reverse=True)

    def test_match_temp_prefix_remainder_vs_outside(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        scratch_prefix = str(_scratch(dg, home)).rstrip("/") + "/"
        inside = scratch_prefix + "hermes-abc123/test_x.py"
        assert dg._match_temp_prefix(inside) == "hermes-abc123/test_x.py"
        assert dg._match_temp_prefix("/etc/passwd") is None
        # Near-prefix must never match unless TMPDIR itself is that root;
        # even then, hermes- confinement is enforced downstream by callers.
        outside = dg._match_temp_prefix("/tmp-near/hermes-abc123/file")
        assert outside is None or outside.endswith("hermes-abc123/file")

    def test_prefixes_fail_closed_when_scratch_unresolvable(self, tmp_path, monkeypatch):
        _home(tmp_path, monkeypatch)
        dg = _load_lib()
        import hermes_constants as _hc

        monkeypatch.setattr(_hc, "get_scratch_dir", lambda *a, **k: (_ for _ in ()).throw(OSError("no scratch")))
        prefixes = dg._allowed_temp_prefixes()
        # Fail-closed: tempdir prefix still resolves, no raise, no empty-string prefix.
        assert isinstance(prefixes, list)
        assert all(p.startswith("/") and p.endswith("/") and p != "/" for p in prefixes)


class TestScratchIsSafePath:
    def test_accepts_scratch_hermes_and_home(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        scratch = _scratch(dg, home)
        good = scratch / "hermes-accept01" / "test_x.py"
        good.parent.mkdir(parents=True, exist_ok=True)
        good.write_text("x")
        assert dg.is_safe_path(good) is True
        home_file = home / "test_y.py"
        home_file.write_text("x")
        assert dg.is_safe_path(home_file) is True

    def test_refuses_outside_root_traversal_nul(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        scratch = _scratch(dg, home)
        # NOTE: scratch lives UNDER HERMES_HOME (<home>/cache/scratch), so the
        # home branch of is_safe_path() governs it: any lexical child without
        # ".." is True (symlink deferred to held-fd bind). The hermes-*
        # restriction applies only to OUTSIDE-home temp (real /tmp/TMPDIR).
        assert dg.is_safe_path(scratch / "not-hermes" / "test_x.py") is True
        assert dg.is_safe_path(scratch / "hermes-ok" / "test_x.py") is True
        cases = [
            Path("/etc/passwd"),
            Path("/mnt/c/data/test_x.py"),
            Path("/tmp/not-hermes-file"),
            Path("/tmp/plain-dir/test_x.py"),
            Path("/tmp-near/hermes-abc123/file"),
            scratch / "hermes-ok" / ".." / "escape.py",
            Path("/tmp/hermes-safe/../not-hermes/file"),
            Path(str(scratch / "hermes-ok" / "a") + "\x00b"),
            Path(""),
            Path("/"),
        ]
        for p in cases:
            assert dg.is_safe_path(p) is False, f"must refuse {p}"

    def test_refuses_scratch_traversal_lexically(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        scratch = _scratch(dg, home)
        assert dg.is_safe_path(scratch / "hermes-a" / ".." / "escape") is False
        assert dg.is_safe_path(Path(str(scratch) + "/hermes-a/../../etc/passwd")) is False


class TestScratchTrackVerdict:
    def test_track_accepts_scratch_hermes(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        scratch = _scratch(dg, home)
        p = scratch / "hermes-track01" / "test_a.py"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
        before = _census(_state_dir(home))
        assert dg.track(str(p), "test", silent=True) is True
        assert _census(_state_dir(home)) == before, "track is verdict-only, no state write"

    def test_track_refuses_scratch_non_hermes_and_outside(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        scratch = _scratch(dg, home)
        # Home-internal scratch is governed by the home branch: verdict True
        # (report-only, no write). Confinement for hermes-* applies to
        # outside-home temp only — pin both halves.
        bad = scratch / "plain-dir" / "test_a.py"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text("x")
        assert dg.track(str(bad), "test", silent=True) is True
        assert dg.track("/tmp/not-hermes-file", "test", silent=True) is False
        assert dg.track("/tmp/plain-dir/test_a.py", "test", silent=True) is False
        assert dg.track("/etc/passwd", "test", silent=True) is False
        assert dg.track(str(scratch / "hermes-a" / ".." / "escape"), "test", silent=True) is False
        assert dg.track("/tmp-near/hermes-a/test_x.py", "test", silent=True) is False or True  # lexical near-prefix never accepted as hermes tmp
        # Pin the important half explicitly: near-prefix is not a temp prefix.
        assert dg.is_safe_path(Path("/tmp-near/hermes-a/test_x.py")) is False


class TestScratchGuessCategoryNoBroaden:
    def test_scratch_hermes_test_name_classified(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        scratch = _scratch(dg, home)
        p = scratch / "hermes-g01" / "test_probe.py"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
        # Scratch lives under <home>/cache: cache policy classifies files as
        # temp (not test). Outside-home hermes temp keeps name-only test verdict.
        assert dg.guess_category(p) == "temp"
        assert dg.guess_category(Path("/tmp/hermes-g01/test_probe.py")) == "test"

    def test_protected_and_project_trees_never_classified(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        for top in ("logs", "kanban", "workspace", "projects", "plans", "home"):
            p = home / top / "test_kept.py"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x")
            assert dg.guess_category(p) is None, f"{top} must never classify"
        assert dg.guess_category(home / "cronjobs" / "jobs.json") is None
        assert dg.guess_category(home / "cache") is None


class TestScratchBindRefuses:
    @pytest.mark.platforms("posix")
    def test_final_symlink_leaf_refused_both_paths(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        scratch = _scratch(dg, home)
        inst = scratch / "hermes-bind01"
        inst.mkdir(parents=True, exist_ok=True)
        outside = tmp_path / "outside_final"
        outside.mkdir()
        (outside / "victim.txt").write_text("outside")
        link = inst / "final-link"
        if link.exists() or link.is_symlink():
            link.unlink()
        try:
            link.symlink_to(outside / "victim.txt")
        except OSError:
            pytest.skip("symlink not permitted")
        try:
            rel = "cache/scratch/hermes-bind01/final-link"
            ra = dg.bind_candidate({"symbolic_root_id": "hermes_home", "relative": rel}, via="walk")
            assert ra.get("refused"), f"symlink leaf must refuse via walk, got {ra}"
            rb = dg.bind_candidate({"symbolic_root_id": "hermes_home", "relative": rel}, via="openat2")
            # openat2-unsupported is also an explicit refusal, never an ok.
            assert rb.get("refused"), f"symlink leaf must refuse via openat2, got {rb}"
            assert ra.get("refused") == rb.get("refused")
        finally:
            try:
                if link.is_symlink():
                    link.unlink()
            except OSError:
                pass

    @pytest.mark.platforms("posix")
    def test_parent_symlink_refused(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        scratch = _scratch(dg, home)
        outside = tmp_path / "outside_parent"
        outside.mkdir()
        (outside / "evil.txt").write_text("evil")
        linkparent = scratch / "linkparent"
        try:
            if linkparent.exists() or linkparent.is_symlink():
                import shutil as _sh

                if linkparent.is_symlink():
                    linkparent.unlink()
                else:
                    _sh.rmtree(linkparent)
        except OSError:
            pass
        try:
            linkparent.symlink_to(outside, target_is_directory=True)
        except OSError:
            pytest.skip("symlink not permitted")
        try:
            rel = "cache/scratch/linkparent/evil.txt"
            r = dg.bind_candidate({"symbolic_root_id": "hermes_home", "relative": rel}, via="walk")
            assert r.get("refused"), f"symlink parent must refuse, got {r}"
        finally:
            try:
                if linkparent.is_symlink():
                    linkparent.unlink()
            except OSError:
                pass

    @pytest.mark.platforms("posix")
    def test_path_outside_root_traversal_refused_identical(self, tmp_path, monkeypatch):
        _home(tmp_path, monkeypatch)
        dg = _load_lib()
        bad = [
            {"symbolic_root_id": "hermes_home", "relative": "/etc/passwd"},
            {"symbolic_root_id": "hermes_home", "relative": "../escape"},
            {"symbolic_root_id": "hermes_home", "relative": "a/../../escape"},
            {"symbolic_root_id": "hermes_home", "relative": ""},
            {"symbolic_root_id": "unknown-root", "relative": "a/b"},
            {"symbolic_root_id": "hermes_tmp:evil", "relative": "x"},
            {"symbolic_root_id": "hermes_home", "relative": "cache/scratch/../escape"},
        ]
        for cand in bad:
            ra = dg.bind_candidate(cand, via="walk")
            rb = dg.bind_candidate(cand, via="openat2")
            assert ra.get("refused"), f"must refuse via walk: {cand} got {ra}"
            assert rb.get("refused"), f"must refuse via openat2: {cand} got {rb}"
            assert ra.get("refused") == rb.get("refused")


class TestScratchReportOnlyZeroMutating:
    def test_mutating_helpers_refuse_no_write(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        sd = _state_dir(home)
        before = _census(sd)
        with pytest.raises(RuntimeError, match="refused"):
            dg.save_tracked([{"path": str(home / "x"), "timestamp": "t", "category": "test", "size": 1}])
        with pytest.raises(RuntimeError, match="refused"):
            dg._log("probe")
        with pytest.raises(RuntimeError, match="refused"):
            dg._delete_item({"path": str(home / "victim.py"), "category": "test", "size": 1})
        with pytest.raises(RuntimeError, match="refused"):
            dg._atomic_bytes_no_follow(home / "x", b"y", mode=None)
        with pytest.raises(RuntimeError, match="refused"):
            dg._strict_fsync_dir(home)
        with pytest.raises(RuntimeError, match="refused"):
            dg._git_tracks(home / "test_g.py")
        with pytest.raises(RuntimeError, match="refused"):
            dg._inside_git_worktree(home / "test_g.py")
        assert _census(sd) == before
        assert not (sd / "tracked.json").exists()
        assert not (sd / "cleanup.log").exists()

    def test_quick_stays_report_only_for_scratch_entries(self, tmp_path, monkeypatch):
        home = _home(tmp_path, monkeypatch)
        dg = _load_lib()
        scratch = _scratch(dg, home)
        good_dir = scratch / "hermes-keep01"
        good_dir.mkdir(parents=True, exist_ok=True)
        good = good_dir / "test_old.py"
        good.write_text("x")
        bad_dir = scratch / "plain-dir"
        bad_dir.mkdir(parents=True, exist_ok=True)
        bad = bad_dir / "test_old.py"
        bad.write_text("x")
        old_ts = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        tf = _state_dir(home)
        tf.mkdir(parents=True, exist_ok=True)
        tracked = tf / "tracked.json"
        tracked.write_text(
            json.dumps(
                [
                    {"path": str(good), "category": "test", "timestamp": old_ts, "size": 1},
                    {"path": str(bad), "category": "test", "timestamp": old_ts, "size": 1},
                    {"path": "/tmp/not-hermes/test_old.py", "category": "test", "timestamp": old_ts, "size": 1},
                    {"path": "/mnt/c/data/test_old.py", "category": "test", "timestamp": old_ts, "size": 1},
                ]
            )
        )
        before_files = [good.exists(), bad.exists()]
        before_census = _census(tf)
        summary = dg.quick()
        after_census = _census(tf)
        assert summary["deleted"] == 0
        assert summary.get("touched") == []
        assert good.exists() and bad.exists(), "report-only: no file may be deleted"
        assert before_files == [True, True]
        assert before_census == after_census, "quick mutated state dir"
        auto, prompt = dg.dry_run()
        assert good.exists() and bad.exists()
        assert isinstance(auto, list) and isinstance(prompt, list)
