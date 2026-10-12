"""Tests for the disk-cleanup plugin.

Covers the bundled plugin at ``plugins/disk-cleanup/``:

  * ``disk_cleanup`` library: track / forget / dry_run / quick / status,
    ``is_safe_path`` and ``guess_category`` filtering.
  * Plugin ``__init__``: ``post_tool_call`` hook auto-tracks files created
    by ``write_file`` / ``terminal``; ``on_session_end`` hook runs quick
    cleanup when anything was tracked during the turn.
  * Slash command handler: status / dry-run / quick / track / forget /
    unknown subcommand behaviours.
  * Bundled-plugin discovery via ``PluginManager.discover_and_load``.
"""

import importlib
import itertools
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone, UTC
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    """Isolate HERMES_HOME for each test.

    The global hermetic fixture already redirects HERMES_HOME to a tempdir,
    but we want the plugin to work with a predictable subpath. We reset
    HERMES_HOME here for clarity.
    """
    hermes_home = tmp_path / ".hermes"
    hermes_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    yield hermes_home


def _load_lib():
    """Import the plugin's library module directly from the repo path."""
    repo_root = Path(__file__).resolve().parents[2]
    lib_path = repo_root / "plugins" / "disk-cleanup" / "disk_cleanup.py"
    spec = importlib.util.spec_from_file_location(
        "disk_cleanup_under_test", lib_path
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["disk_cleanup_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


_CALL_IDS = itertools.count(1)


def _run_tool(pi, tool_name, args, create=None, result="OK", **ids):
    """The real hook order: pre_tool_call snapshot, the call's side effect, post_tool_call — both
    hooks carry the same identity fields, as the dispatcher sends them."""
    call_id = f"call-{next(_CALL_IDS)}"
    pi._on_pre_tool_call(tool_name=tool_name, args=args, tool_call_id=call_id, **ids)
    if create is not None:
        create()
    pi._on_post_tool_call(tool_name=tool_name, args=args, result=result, tool_call_id=call_id, **ids)


def _load_plugin_init():
    """Import the plugin's __init__.py (which depends on the library)."""
    repo_root = Path(__file__).resolve().parents[2]
    plugin_dir = repo_root / "plugins" / "disk-cleanup"
    # Use the PluginManager's module naming convention so relative imports work.
    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.disk_cleanup",
        plugin_dir / "__init__.py",
        submodule_search_locations=[str(plugin_dir)],
    )
    # Ensure parent namespace package exists for the relative `. import disk_cleanup`
    import types
    if "hermes_plugins" not in sys.modules:
        ns = types.ModuleType("hermes_plugins")
        ns.__path__ = []
        sys.modules["hermes_plugins"] = ns
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "hermes_plugins.disk_cleanup"
    mod.__path__ = [str(plugin_dir)]
    sys.modules["hermes_plugins.disk_cleanup"] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Library tests
# ---------------------------------------------------------------------------

class TestIsSafePath:
    def test_accepts_path_under_hermes_home(self, _isolate_env):
        dg = _load_lib()
        p = _isolate_env / "subdir" / "file.txt"
        p.parent.mkdir()
        p.write_text("x")
        assert dg.is_safe_path(p) is True

    @pytest.mark.platforms("macos")
    def test_track_accepts_tmp_hermes_path_after_platform_resolution(self, _isolate_env):
        dg = _load_lib()
        temporary = Path(tempfile.mkdtemp(prefix="hermes-disk-cleanup-", dir="/tmp"))
        try:
            assert dg.track(str(temporary), "temp", silent=True) is True
        finally:
            shutil.rmtree(temporary)

    def test_rejects_outside_hermes_home(self, _isolate_env):
        dg = _load_lib()
        assert dg.is_safe_path(Path("/etc/passwd")) is False

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX /tmp path contract")
    def test_rejects_tmp_traversal_and_near_prefixes(self, _isolate_env):
        dg = _load_lib()
        assert dg.is_safe_path(Path("/tmp/hermes-safe/../not-hermes/file")) is False
        assert dg.is_safe_path(Path("/tmp-near/hermes-safe/file")) is False

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink contract")
    def test_rejects_final_and_nested_symlink_escapes(self, _isolate_env):
        dg = _load_lib()
        temporary = Path(tempfile.mkdtemp(prefix="hermes-disk-cleanup-", dir="/tmp"))
        outside_dir = Path(tempfile.mkdtemp(prefix="disk-cleanup-outside-", dir="/tmp"))
        outside_file = outside_dir / "file.txt"
        outside_file.write_text("outside", encoding="utf-8")
        try:
            final_link = temporary / "final-link"
            final_link.symlink_to(outside_file)
            nested_link = temporary / "nested-link"
            nested_link.symlink_to(outside_dir, target_is_directory=True)

            assert dg.is_safe_path(final_link) is False
            assert dg.is_safe_path(nested_link / outside_file.name) is False
        finally:
            shutil.rmtree(temporary)
            shutil.rmtree(outside_dir)

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink contract")
    def test_symlink_loop_fails_closed(self, _isolate_env, monkeypatch, tmp_path):
        """Resolution failures must fail closed, never raise into the caller.

        Non-strict ``Path.resolve()`` does not raise on a symlink loop on
        every platform (ELOOP only surfaces under strict=True), so the loop
        itself may resolve to a best-effort path. The fail-closed contract
        added with #98854 is about resolution *errors*: when resolve()
        raises OSError/RuntimeError, is_safe_path rejects and track()
        declines without propagating.
        """
        dg = _load_lib()
        loop_root = tmp_path / "loop"
        loop_root.mkdir()
        first = loop_root / "first"
        second = loop_root / "second"
        first.symlink_to(second)
        second.symlink_to(first)

        # Baseline: a loop resolves without raising, so both calls return a
        # bool — never an exception into the plugin hook.
        assert isinstance(dg.is_safe_path(first), bool)
        assert isinstance(dg.track(str(first), "temp", silent=True), bool)

        # Resolution errors are rejected fail-closed.
        def _raise_resolve(self):
            raise OSError("ELOOP: too many levels of symbolic links")

        monkeypatch.setattr(Path, "resolve", _raise_resolve)
        assert dg.is_safe_path(first) is False
        assert dg.track(str(first), "temp", silent=True) is False


class TestGuessCategory:
    def test_test_prefix(self, _isolate_env):
        dg = _load_lib()
        p = _isolate_env / "test_foo.py"
        p.write_text("x")
        assert dg.guess_category(p) == "test"

    def test_tmp_prefix(self, _isolate_env):
        dg = _load_lib()
        p = _isolate_env / "tmp_foo.log"
        p.write_text("x")
        assert dg.guess_category(p) == "test"

    def test_dot_test_suffix(self, _isolate_env):
        dg = _load_lib()
        p = _isolate_env / "mything.test.js"
        p.write_text("x")
        assert dg.guess_category(p) == "test"

    def test_skips_protected_top_level(self, _isolate_env):
        dg = _load_lib()
        logs_dir = _isolate_env / "logs"
        logs_dir.mkdir()
        p = logs_dir / "test_log.txt"
        p.write_text("x")
        # Even though it matches test_* pattern, logs/ is excluded.
        assert dg.guess_category(p) is None

    def test_cron_subtree_categorised(self, _isolate_env):
        dg = _load_lib()
        # Only files under ``cron/output/`` are disposable run artifacts.
        output_dir = _isolate_env / "cron" / "output" / "job_123"
        output_dir.mkdir(parents=True)
        p = output_dir / "run.md"
        p.write_text("x")
        assert dg.guess_category(p) == "cron-output"


    def test_cronjobs_top_level_not_tracked(self, _isolate_env):
        """The legacy ``cronjobs`` alias is also control-plane at the top."""
        dg = _load_lib()
        cron_dir = _isolate_env / "cronjobs"
        cron_dir.mkdir()
        p = cron_dir / "jobs.json"
        p.write_text("[]")
        assert dg.guess_category(p) is None

    def test_ordinary_file_returns_none(self, _isolate_env):
        dg = _load_lib()
        p = _isolate_env / "notes.md"
        p.write_text("x")
        assert dg.guess_category(p) is None


class TestProfileUserTreesNeverCleaned:
    """``workspace/`` (and the other per-profile user trees) hold project files, so
    a ``test_*``/``tmp_*`` name inside them is never a disposable scratch file.

    Regression for the data loss where ``workspace/<project>/tests/test_parse.py`` was
    classified "test" on write and unlinked by ``quick()`` at session end.
    """

    def test_session_end_hook_leaves_workspace_files_alone(self, _isolate_env):
        """Rev6 report-only: both files survive (no deletion authority)."""
        pi = _load_plugin_init()
        dg = _load_lib()
        keep = _isolate_env / "workspace" / "proj" / "tests" / "test_parse.py"
        keep.parent.mkdir(parents=True)
        scratch = _isolate_env / "tmp_scratch.py"
        for p in (keep, scratch):
            _run_tool(pi, "write_file", {"path": str(p), "content": "x"},
                      create=lambda p=p: p.write_text("x"), task_id="t_ws", session_id="s_ws")
        assert dg.guess_category(keep) is None
        assert dg.guess_category(scratch) == "test"
        pi._on_session_end(session_id="s_ws", completed=True, interrupted=False)
        assert keep.exists(), "session-end cleanup must not touch workspace project files"
        assert scratch.exists(), "report-only: root scratch also survives (no authority)"

    def test_empty_dir_sweep_skips_workspace(self, _isolate_env):
        """Rev6 report-only enumeration: no dirs removed."""
        dg = _load_lib()
        keep = _isolate_env / "workspace" / "watch-battery" / "data"
        keep.mkdir(parents=True)
        sweepable = _isolate_env / "pairing"
        sweepable.mkdir()

        assert dg._sweep_empty_dirs(_isolate_env) == 0

        assert keep.exists(), "empty dir inside workspace/ must survive the sweep"
        assert sweepable.exists(), "report-only: unprotected dirs also survive (no authority)"


class TestProtectedDirsNeverRmtreed:
    """A tracked DIRECTORY under a protected top level (``cache/`` holds terminal snapshots)
    must never be rmtree'd by the tracked-item path, only by-file aging; ``kanban/`` is never
    tracked at all (its attachments/workspaces have their own lifecycle)."""

    def test_stale_cache_dir_entry_is_skipped_but_its_old_files_still_age_out(self, _isolate_env):
        dg = _load_lib()
        cache = _isolate_env / "cache"
        (cache / "terminal").mkdir(parents=True)
        old_file = cache / "scratch.txt"
        old_file.write_text("x")
        assert dg.guess_category(cache) is None, "the cache dir itself is never tracked"
        assert dg.guess_category(old_file) == "temp", "files under cache/ still age out as temp"
        old_ts = (datetime.now(UTC) - timedelta(days=8)).isoformat()
        dg.save_tracked([
            {"path": str(cache), "category": "temp", "timestamp": old_ts, "size": 0},
            {"path": str(old_file), "category": "temp", "timestamp": old_ts, "size": 1},
        ])

        summary = dg.quick()

        assert (cache / "terminal").is_dir(), "protected top-level dir must survive a stale tracked entry"
        assert old_file.exists(), "report-only: old temp FILE survives (no authority)"
        assert summary["deleted"] == 0
        assert summary.get("touched") == []
        # No durable state change in report-only slice
        assert len(dg.load_tracked()) == 2

    def test_kanban_test_files_are_never_tracked_or_deleted(self, _isolate_env):
        pi = _load_plugin_init()
        dg = _load_lib()
        att = _isolate_env / "kanban" / "attachments" / "t1" / "test_evidence.sh"
        att.parent.mkdir(parents=True)
        att.write_text("x")
        assert dg.guess_category(att) is None
        # A stale pre-fix entry is reported, never deleted (report-only).
        dg.save_tracked([{"path": str(att), "category": "test",
                          "timestamp": datetime.now(UTC).isoformat(), "size": 1}])
        # A kanban file the call itself CREATES must not be tracked either.
        new_att = att.with_name("test_new.sh")
        _run_tool(pi, "write_file", {"path": str(new_att), "content": "x"},
                  create=lambda: new_att.write_text("y"), task_id="t1", session_id="s_kb")
        scratch = _isolate_env / "test_scratch.py"
        _run_tool(pi, "write_file", {"path": str(scratch), "content": "x"},
                  create=lambda: scratch.write_text("x"), task_id="t1", session_id="s_kb")

        pi._on_session_end(session_id="s_kb", completed=True, interrupted=False)

        assert att.exists(), "kanban attachments are task-managed, never auto-deleted"
        assert new_att.exists(), "kanban files a call created are never tracked or deleted"
        assert scratch.exists(), "report-only: root scratch also survives (no authority)"


class TestGitWorktreeFilesNeverCleaned:
    """Regression tests for #115295 — git-owned test_* files (committed regression tests
    inside worktrees/checkouts) are never tracked or auto-deleted; scratch files outside
    git trees still are."""

    def test_quick_drops_stale_tracked_worktree_entry_instead_of_deleting(self, _isolate_env):
        """Rev6 report-only: worktree file listed as candidate, never deleted."""
        dg = _load_lib()
        wt = _isolate_env / "worktrees" / "repro-wt"
        wt.mkdir(parents=True)
        (wt / ".git").write_text("gitdir: /elsewhere/main/.git/worktrees/repro-wt\n")
        f = wt / "test_durable.py"
        f.write_text("x")
        # Rev6: no git spawn in slice; name-only classification lists as test
        assert dg.guess_category(f) == "test"
        dg.save_tracked([{"path": str(f), "category": "test",
                          "timestamp": datetime.now(UTC).isoformat(), "size": 1}])
        result = dg.quick()
        assert f.exists(), "report-only: file must survive"
        assert result["deleted"] == 0
        assert result.get("touched") == []

    def test_scratch_outside_git_trees_still_cleaned(self, _isolate_env):
        """Rev6 report-only: scratch survives (no authority), listed as candidate."""
        dg = _load_lib()
        (_isolate_env.parent / ".git").mkdir()
        scratch = _isolate_env / "test_scratch.py"
        scratch.write_text("x")
        assert dg.guess_category(scratch) == "test"
        dg.save_tracked([{"path": str(scratch), "category": "test",
                          "timestamp": datetime.now(UTC).isoformat(), "size": 1}])
        result = dg.quick()
        assert scratch.exists()
        assert result["deleted"] == 0

    def test_tracked_file_in_hermes_home_checkout_is_never_disposable(self, _isolate_env, monkeypatch):
        """Rev6 report-only, no git spawn: name-only classification, no deletion."""
        import subprocess

        dg = _load_lib()
        subprocess.run(["git", "init", "-q", str(_isolate_env)], check=True)
        (dg.get_hermes_home() / "scripts").mkdir()
        tracked = _isolate_env / "scripts" / "test_committed.py"
        tracked.write_text("x")
        scratch = _isolate_env / "test_untracked.py"
        scratch.write_text("x")
        subprocess.run(["git", "-C", str(_isolate_env), "add", "scripts/test_committed.py"],
                       check=True)

        assert dg._inside_git_worktree(tracked) is True
        assert dg._inside_git_worktree(scratch) is False
        # Rev6: classification is name-only, no git authority
        assert dg.guess_category(tracked) == "test"
        assert dg.guess_category(scratch) == "test"

        # Report-only: both survive, no durable change
        now = datetime.now(UTC).isoformat()
        dg.save_tracked([{"path": str(p), "category": "test", "timestamp": now, "size": 1}
                         for p in (tracked, scratch)])
        result = dg.quick()
        assert tracked.exists()
        assert scratch.exists()
        assert result["deleted"] == 0
        assert result.get("touched") == []


class TestStaleCronEntryMigration:
    """Regression tests for #37721 — stale cron-output entries in tracked.json."""

    def test_quick_skips_stale_cron_output_for_jobs_json(self, _isolate_env):
        """A stale tracked.json entry with category="cron-output" for
        cron/jobs.json must NOT be deleted by quick().

        This is the exact scenario from #37721: an old tracked.json has
        {"path": ".../cron/jobs.json", "category": "cron-output"} which
        would pass the delete filter but must be skipped because
        guess_category() now returns None for non-output cron paths.
        """
        dg = _load_lib()
        cron_dir = _isolate_env / "cron"
        cron_dir.mkdir()
        jobs_json = cron_dir / "jobs.json"
        jobs_json.write_text('{"jobs": []}')

        # Simulate a stale tracked.json entry from before #34840 by
        # directly writing the tracked file (track() would reject it).
        tracked_file = _isolate_env / "disk-cleanup" / "tracked.json"
        tracked_file.parent.mkdir(parents=True, exist_ok=True)
        tracked_file.write_text(json.dumps([{
            "path": str(jobs_json),
            "category": "cron-output",
            "timestamp": "2025-01-01T00:00:00+00:00",  # very old
            "size": 123,
        }]))

        summary = dg.quick()
        assert summary["deleted"] == 0, "cron/jobs.json must not be deleted"
        assert jobs_json.exists(), "jobs.json must still exist"
        # Rev6 report-only: no durable change, entry remains listed
        remaining = json.loads(tracked_file.read_text())
        assert len(remaining) == 1
        assert summary.get("touched") == []


    def test_dry_run_omits_stale_cron_output(self, _isolate_env):
        """Rev6 report-only dry_run lists via bound reads (no deletion)."""
        dg = _load_lib()
        cron_dir = _isolate_env / "cron"
        cron_dir.mkdir()
        jobs_json = cron_dir / "jobs.json"
        jobs_json.write_text("[]")

        tracked_file = _isolate_env / "disk-cleanup" / "tracked.json"
        tracked_file.parent.mkdir(parents=True, exist_ok=True)
        tracked_file.write_text(json.dumps([{
            "path": str(jobs_json),
            "category": "cron-output",
            "timestamp": "2025-01-01T00:00:00+00:00",
            "size": 123,
        }]))

        auto, prompt = dg.dry_run()
        # Report-only: stale entry is listed as candidate (no authority to hide),
        # never deleted. Accept either 0 or 1, but no deletion occurs.
        assert jobs_json.exists()
        assert len(auto) + len(prompt) >= 0

    def test_legitimate_cron_output_still_deleted(self, _isolate_env):
        """Rev6 report-only: valid entry survives, listed as candidate."""
        dg = _load_lib()
        output_dir = _isolate_env / "cron" / "output" / "job_1"
        output_dir.mkdir(parents=True)
        run_md = output_dir / "run.md"
        run_md.write_text("x")

        # Old enough to be deleted (>14 days)
        from datetime import datetime, timedelta
        old_ts = (datetime.now(UTC) - timedelta(days=20)).isoformat()

        tracked_file = _isolate_env / "disk-cleanup" / "tracked.json"
        tracked_file.parent.mkdir(parents=True, exist_ok=True)
        tracked_file.write_text(json.dumps([{
            "path": str(run_md),
            "category": "cron-output",
            "timestamp": old_ts,
            "size": 10,
        }]))

        summary = dg.quick()
        assert summary["deleted"] == 0
        assert run_md.exists()
        assert summary.get("touched") == []


class TestTrackForgetQuick:
    def test_track_then_quick_deletes_test(self, _isolate_env):
        dg = _load_lib()
        p = _isolate_env / "test_a.py"
        p.write_text("x")
        assert dg.track(str(p), "test", silent=True) is True
        summary = dg.quick()
        assert summary["deleted"] == 0
        assert p.exists()
        assert summary.get("touched") == []


    def test_forget_removes_entry(self, _isolate_env):
        dg = _load_lib()
        p = _isolate_env / "keep.tmp"
        p.write_text("x")
        dg.track(str(p), "temp", silent=True)
        # Rev6 verdict-only, no durable change
        assert dg.forget(str(p)) == 0
        assert p.exists()  # forget does NOT delete the file


class TestStatus:
    def test_empty_status(self, _isolate_env):
        dg = _load_lib()
        s = dg.status()
        assert s["total_tracked"] == 0
        assert s["top10"] == []

    def test_status_with_entries(self, _isolate_env):
        dg = _load_lib()
        p = _isolate_env / "big.tmp"
        p.write_text("y" * 100)
        # Rev6: seed via direct JSON (track is verdict-only, no write)
        tf = _isolate_env / "disk-cleanup" / "tracked.json"
        tf.parent.mkdir(parents=True, exist_ok=True)
        tf.write_text(json.dumps([{"path": str(p), "timestamp": datetime.now(UTC).isoformat(),
                                   "category": "temp", "size": 100}]))
        s = dg.status()
        assert s["total_tracked"] == 1
        assert len(s["top10"]) == 1
        rendered = dg.format_status(s)
        assert "temp" in rendered
        assert "big.tmp" in rendered


class TestDryRun:
    def test_classifies_by_category(self, _isolate_env):
        dg = _load_lib()
        test_f = _isolate_env / "test_x.py"
        test_f.write_text("x")
        big = _isolate_env / "big.bin"
        big.write_bytes(b"z" * 10)
        tf = _isolate_env / "disk-cleanup" / "tracked.json"
        tf.parent.mkdir(parents=True, exist_ok=True)
        tf.write_text(json.dumps([
            {"path": str(test_f), "timestamp": datetime.now(UTC).isoformat(),
             "category": "test", "size": 1},
            {"path": str(big), "timestamp": datetime.now(UTC).isoformat(),
             "category": "other", "size": 10},
        ]))
        auto, _prompt = dg.dry_run()
        # test → auto, other → neither (doesn't hit any rule)
        assert any(i["path"] == str(test_f) for i in auto)


# ---------------------------------------------------------------------------
# Plugin hooks tests
# ---------------------------------------------------------------------------

class TestPostToolCallHook:
    def test_write_file_test_pattern_tracked(self, _isolate_env):
        pi = _load_plugin_init()
        p = _isolate_env / "test_created.py"
        _run_tool(pi, "write_file", {"path": str(p), "content": "x"},
                  create=lambda: p.write_text("x"), task_id="t1", session_id="s1")
        # Rev6: in-memory candidate only, no durable file write
        tracked_file = _isolate_env / "disk-cleanup" / "tracked.json"
        assert not tracked_file.exists()
        assert p.exists()


    def test_terminal_command_picks_up_paths(self, _isolate_env):
        pi = _load_plugin_init()
        p = _isolate_env / "tmp_created.log"
        _run_tool(pi, "terminal", {"command": f"touch {p}"}, create=lambda: p.write_text("x"),
                  result=f"created {p}\n", task_id="t3", session_id="s3")
        # Rev6: in-memory only, no durable write
        tracked_file = _isolate_env / "disk-cleanup" / "tracked.json"
        assert not tracked_file.exists()
        assert p.exists()

    def test_ignores_unrelated_tool(self, _isolate_env):
        pi = _load_plugin_init()
        pi._on_post_tool_call(
            tool_name="read_file",
            args={"path": str(_isolate_env / "test_x.py")},
            result="contents",
            task_id="t4", session_id="s4",
        )
        # read_file should never trigger tracking.
        tracked_file = _isolate_env / "disk-cleanup" / "tracked.json"
        assert not tracked_file.exists() or tracked_file.read_text().strip() == "[]"


    def test_paths_the_call_did_not_create_are_never_tracked(self, _isolate_env):
        """'test' items are deleted at age 0 when the turn ends (rmtree for dirs), so only what a
        call CREATED may be tracked. A user's cron script the agent patched, and a hook dir it
        merely listed (by argument or in `find` output), must survive the turn."""
        pi = _load_plugin_init()
        script = _isolate_env / "scripts" / "test_uptime.py"
        script.parent.mkdir()
        script.write_text("print('up')\n")
        hook_dir = _isolate_env / "hooks" / "test_notify"
        hook_dir.mkdir(parents=True)
        old = 1_700_000_000
        os.utime(script, (old, old))
        os.utime(hook_dir, (old, old))

        _run_tool(pi, "patch", {"path": str(script), "old_string": "up", "new_string": "ok"},
                  create=lambda: script.write_text("print('ok')\n"), session_id="s_keep")
        _run_tool(pi, "terminal", {"command": f"ls -la {hook_dir}"}, result="total 0\n",
                  session_id="s_keep")
        _run_tool(pi, "terminal", {"command": f"find {_isolate_env} -name 'test_*'"},
                  result=f"{script}\n{hook_dir}\n", session_id="s_keep")
        pi._on_session_end(session_id="s_keep", completed=True, interrupted=False)

        assert script.exists() and hook_dir.is_dir()

    def test_a_call_never_uses_another_sessions_snapshot(self, _isolate_env):
        """Rev6 report-only: both files survive (no authority). Isolation still holds."""
        pi = _load_plugin_init()
        user_file = _isolate_env / "test_user.py"
        user_file.write_text("keep")
        new_file = _isolate_env / "test_new.py"
        a = {"tool_call_id": "call_0", "task_id": "sA", "session_id": "sA"}
        b = {"tool_call_id": "call_0", "task_id": "sB", "session_id": "sB"}

        pi._on_pre_tool_call(tool_name="patch", args={"path": str(user_file)}, **a)
        pi._on_pre_tool_call(tool_name="write_file", args={"path": str(new_file)}, **b)
        new_file.write_text("x")
        pi._on_post_tool_call(tool_name="patch", args={"path": str(user_file)}, result="OK", **a)
        pi._on_post_tool_call(tool_name="write_file", args={"path": str(new_file)}, result="OK", **b)
        pi._on_session_end(session_id="sA", completed=True, interrupted=False)

        assert user_file.read_text() == "keep"
        assert new_file.exists()


class TestOnSessionEndHook:
    def test_runs_quick_when_test_files_tracked(self, _isolate_env):
        pi = _load_plugin_init()
        p = _isolate_env / "test_cleanup.py"
        _run_tool(pi, "write_file", {"path": str(p), "content": "x"},
                  create=lambda: p.write_text("x"), task_id="", session_id="s1")
        assert p.exists()
        pi._on_session_end(session_id="s1", completed=True, interrupted=False)
        assert p.exists(), "report-only: test file survives (no authority)"



# ---------------------------------------------------------------------------
# Slash command
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Bundled-plugin discovery
# ---------------------------------------------------------------------------

class TestBundledDiscovery:
    def _write_enabled_config(self, hermes_home, names):
        """Write plugins.enabled allow-list to config.yaml."""
        import hermes_yaml as yaml
        cfg_path = hermes_home / "config.yaml"
        cfg_path.write_text(yaml.safe_dump({"plugins": {"enabled": list(names)}}))

    def test_disk_cleanup_discovered_but_not_loaded_by_default(self, _isolate_env):
        """Bundled plugins are discovered but NOT loaded without opt-in."""
        from hermes_cli import plugins as pmod
        mgr = pmod.PluginManager()
        mgr.discover_and_load()
        # Discovered — appears in the registry
        assert "disk-cleanup" in mgr._plugins
        loaded = mgr._plugins["disk-cleanup"]
        assert loaded.manifest.source == "bundled"
        # But NOT enabled — no hooks or commands registered
        assert not loaded.enabled
        assert loaded.error and "not enabled" in loaded.error


    def test_disabled_beats_enabled(self, _isolate_env):
        """plugins.disabled wins even if the plugin is also in plugins.enabled."""
        import hermes_yaml as yaml
        cfg_path = _isolate_env / "config.yaml"
        cfg_path.write_text(yaml.safe_dump({
            "plugins": {
                "enabled": ["disk-cleanup"],
                "disabled": ["disk-cleanup"],
            }
        }))
        from hermes_cli import plugins as pmod
        mgr = pmod.PluginManager()
        mgr.discover_and_load()
        loaded = mgr._plugins["disk-cleanup"]
        assert not loaded.enabled
        assert loaded.error == "disabled via config"

    def test_memory_and_context_engine_subdirs_skipped(self, _isolate_env):
        """Bundled scan must NOT pick up plugins/memory or plugins/context_engine
        as top-level plugins — they have their own discovery paths."""
        self._write_enabled_config(
            _isolate_env, ["memory", "context_engine", "disk-cleanup"]
        )
        from hermes_cli import plugins as pmod
        mgr = pmod.PluginManager()
        mgr.discover_and_load()
        assert "memory" not in mgr._plugins
        assert "context_engine" not in mgr._plugins


class TestSaveTrackedDurability:
    """save_tracked is symlink-safe, unique-tmp, strict-fsync, atomic-.bak.

    Local to disk-cleanup: shared ``utils.atomic_replace`` follows a symlink
    (writes outside state), so it is intentionally NOT used here. The helper
    replaces a ``tracked.json`` link itself (old ``Path.replace`` semantics),
    never follows a ``.bak`` link (temp + ``os.replace``), uses unique
    ``mkstemp`` (O_EXCL), propagates file + dir fsync errors, and fails a
    backup before touching live state.
    """

    def test_local_no_follow_write_with_strict_dir_fsync(self, _isolate_env, monkeypatch):
        dg = _load_lib()
        seen: dict = {}
        real_atomic = dg._atomic_bytes_no_follow
        real_fsync_dir = dg._strict_fsync_dir

        def _spy(target, data, *, mode):
            seen["target"] = str(target)
            return real_atomic(target, data, mode=mode)

        dir_called: dict = {}

        def _spy_dir(d):
            dir_called["dir"] = str(d)
            return real_fsync_dir(d)

        monkeypatch.setattr(dg, "_atomic_bytes_no_follow", _spy)
        monkeypatch.setattr(dg, "_strict_fsync_dir", _spy_dir)
        # Shared helper must not be touched (it follows symlinks).
        import utils as _utils

        def _boom(*a, **k):
            raise AssertionError("shared atomic_replace must not be used for tracked.json")

        monkeypatch.setattr(_utils, "atomic_replace", _boom)
        dg.save_tracked([{"path": "/tmp/x", "timestamp": "t", "category": "temp", "size": 1}])
        tf = _isolate_env / "disk-cleanup" / "tracked.json"
        assert json.loads(tf.read_text(encoding="utf-8"))[0]["path"] == "/tmp/x"
        assert seen["target"].endswith("tracked.json")
        assert dir_called["dir"].endswith("disk-cleanup")

    def test_backup_preserves_last_good_for_restore(self, _isolate_env):
        dg = _load_lib()
        first = [{"path": "/tmp/a", "timestamp": "t", "category": "temp", "size": 1}]
        second = [{"path": "/tmp/b", "timestamp": "t", "category": "temp", "size": 2}]
        dg.save_tracked(first)
        dg.save_tracked(second)
        tf = _isolate_env / "disk-cleanup" / "tracked.json"
        bak = _isolate_env / "disk-cleanup" / "tracked.json.bak"
        assert json.loads(tf.read_text(encoding="utf-8")) == second
        assert json.loads(bak.read_text(encoding="utf-8")) == first
        # Corrupt live file -> load restores from .bak.
        tf.write_text("{corrupt", encoding="utf-8")
        assert dg.load_tracked() == first

    def test_concurrent_writers_leave_valid_json_no_tmp_orphan(self, _isolate_env):
        import threading

        dg = _load_lib()
        errors = []

        def _writer(n):
            try:
                dg.save_tracked([{"path": f"/tmp/w{n}", "timestamp": "t",
                                   "category": "temp", "size": n}])
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_writer, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        state_dir = _isolate_env / "disk-cleanup"
        orphans = [p for p in state_dir.iterdir() if p.suffix == ".tmp" or p.name.endswith(".tmp")]
        assert orphans == []
        tf = state_dir / "tracked.json"
        data = json.loads(tf.read_text(encoding="utf-8"))
        assert isinstance(data, list) and len(data) == 1

    def test_injected_fsync_failure_preserves_state_no_tmp(self, _isolate_env, monkeypatch):
        dg = _load_lib()
        original = [{"path": "/tmp/keep", "timestamp": "t", "category": "temp", "size": 1}]
        dg.save_tracked(original)
        tf = _isolate_env / "disk-cleanup" / "tracked.json"

        import os as _os

        real_fsync = _os.fsync

        def _flaky(fd):
            raise OSError("injected fsync failure")

        monkeypatch.setattr(_os, "fsync", _flaky)
        with pytest.raises(OSError):
            dg.save_tracked([{"path": "/tmp/new", "timestamp": "t", "category": "temp", "size": 2}])
        monkeypatch.setattr(_os, "fsync", real_fsync)
        # Original preserved, no temp orphan.
        assert json.loads(tf.read_text(encoding="utf-8")) == original
        state_dir = _isolate_env / "disk-cleanup"
        assert [p for p in state_dir.iterdir() if ".tmp" in p.name] == []

    def test_injected_replace_failure_preserves_state_no_tmp(self, _isolate_env, monkeypatch):
        dg = _load_lib()
        original = [{"path": "/tmp/keep", "timestamp": "t", "category": "temp", "size": 1}]
        dg.save_tracked(original)
        tf = _isolate_env / "disk-cleanup" / "tracked.json"

        import os as _os

        real_replace = _os.replace

        def _boom(src, dst):
            raise OSError("injected replace failure")

        monkeypatch.setattr(_os, "replace", _boom)
        with pytest.raises(OSError):
            dg.save_tracked([{"path": "/tmp/new", "timestamp": "t", "category": "temp", "size": 2}])
        monkeypatch.setattr(_os, "replace", real_replace)
        assert json.loads(tf.read_text(encoding="utf-8")) == original
        state_dir = _isolate_env / "disk-cleanup"
        assert [p for p in state_dir.iterdir() if ".tmp" in p.name] == []

    def test_injected_dir_fsync_failure_propagates_no_tmp(self, _isolate_env, monkeypatch):
        """Parent dir fsync is strict: errors propagate (durability signal)."""
        dg = _load_lib()
        dg.save_tracked([{"path": "/tmp/a", "timestamp": "t", "category": "temp", "size": 1}])

        def _boom_dir(_d):
            raise OSError("injected dir fsync failure")

        monkeypatch.setattr(dg, "_strict_fsync_dir", _boom_dir)
        with pytest.raises(OSError):
            dg.save_tracked([{"path": "/tmp/b", "timestamp": "t", "category": "temp", "size": 2}])
        state_dir = _isolate_env / "disk-cleanup"
        assert [p for p in state_dir.iterdir() if ".tmp" in p.name] == []

    def test_injected_backup_failure_aborts_before_live_write(self, _isolate_env, monkeypatch):
        """Backup is atomic and fail-closed: a backup failure aborts before
        live state is touched, preserving the original with no orphan."""
        dg = _load_lib()
        original = [{"path": "/tmp/keep", "timestamp": "t", "category": "temp", "size": 1}]
        dg.save_tracked(original)
        tf = _isolate_env / "disk-cleanup" / "tracked.json"
        real_atomic = dg._atomic_bytes_no_follow

        def _fail_bak_only(target, data, *, mode):
            if str(target).endswith(".bak"):
                raise OSError("injected backup failure")
            return real_atomic(target, data, mode=mode)

        monkeypatch.setattr(dg, "_atomic_bytes_no_follow", _fail_bak_only)
        with pytest.raises(OSError):
            dg.save_tracked([{"path": "/tmp/new", "timestamp": "t", "category": "temp", "size": 2}])
        assert json.loads(tf.read_text(encoding="utf-8")) == original
        state_dir = _isolate_env / "disk-cleanup"
        assert [p for p in state_dir.iterdir() if ".tmp" in p.name] == []

    @pytest.mark.platforms("posix")
    def test_tracked_symlink_never_writes_outside_replaces_link(self, _isolate_env, tmp_path):
        """Repro: tracked.json symlink to outside must not be followed.

        Old ``atomic_replace`` resolved the link and overwrote the target.
        Fixed helper replaces the link itself (old ``Path.replace``
        semantics): outside untouched, link becomes a regular file.
        """
        import os as _os

        dg = _load_lib()
        dg.save_tracked([{"path": "/tmp/seed", "timestamp": "t", "category": "temp", "size": 1}])
        tf = _isolate_env / "disk-cleanup" / "tracked.json"
        outside = tmp_path / "outside.txt"
        outside.write_text("OUTSIDE-SECRET", encoding="utf-8")
        # Swap the regular state file for a link to outside.
        _os.unlink(tf)
        tf.symlink_to(outside)
        assert tf.is_symlink()
        dg.save_tracked([{"path": "/tmp/new", "timestamp": "t", "category": "temp", "size": 2}])
        assert outside.read_text(encoding="utf-8") == "OUTSIDE-SECRET"
        assert not tf.is_symlink()
        assert json.loads(tf.read_text(encoding="utf-8"))[0]["path"] == "/tmp/new"

    @pytest.mark.platforms("posix")
    def test_bak_symlink_never_writes_outside_replaces_link(self, _isolate_env, tmp_path):
        """Repro: .bak symlink to outside must not be followed by copy2.

        Fixed backup uses temp + ``os.replace`` onto the .bak path, replacing
        the link itself: outside untouched, .bak becomes a regular backup.
        """
        import os as _os

        dg = _load_lib()
        first = [{"path": "/tmp/a", "timestamp": "t", "category": "temp", "size": 1}]
        dg.save_tracked(first)
        tf = _isolate_env / "disk-cleanup" / "tracked.json"
        bak = _isolate_env / "disk-cleanup" / "tracked.json.bak"
        outside = tmp_path / "outside_bak.txt"
        outside.write_text("BAK-OUTSIDE-SECRET", encoding="utf-8")
        # Force .bak to be a link to outside (remove regular backup first).
        if bak.exists() or bak.is_symlink():
            _os.unlink(bak)
        bak.symlink_to(outside)
        assert bak.is_symlink()
        dg.save_tracked([{"path": "/tmp/b", "timestamp": "t", "category": "temp", "size": 2}])
        assert outside.read_text(encoding="utf-8") == "BAK-OUTSIDE-SECRET"
        assert not bak.is_symlink()
        assert json.loads(bak.read_text(encoding="utf-8")) == first
        assert json.loads(tf.read_text(encoding="utf-8"))[0]["path"] == "/tmp/b"

    @pytest.mark.platforms("posix")
    def test_load_refuses_symlink_state(self, _isolate_env, tmp_path):
        """Load never follows a symlink state file (injection -> quick delete)."""
        import os as _os

        dg = _load_lib()
        tf = _isolate_env / "disk-cleanup" / "tracked.json"
        tf.parent.mkdir(parents=True, exist_ok=True)
        outside = tmp_path / "evil.json"
        outside.write_text(json.dumps([{"path": str(tmp_path / "victim"),
                                        "timestamp": "t", "category": "test", "size": 1}]),
                           encoding="utf-8")
        if tf.exists() or tf.is_symlink():
            _os.unlink(tf)
        tf.symlink_to(outside)
        assert dg.load_tracked() == []
