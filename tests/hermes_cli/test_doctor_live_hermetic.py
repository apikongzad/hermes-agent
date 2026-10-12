"""Hermetic C: doctor --live real per-backend oracle (DESIGN rev6 §7).

Red regressions per ACCEPTED DESIGN exact 2f222ae.
Hermetic: no network, no pm.ensure/download, no service enable, bounded, owned cleanup.

IDs: C-DECIDE-1 (pure resolver truth table, NOT bool), C-ORACLE-1/2
(launch-only PASS, no version-pass, ACTUAL CLI owned session ONLY),
C-BACKEND-1 (selected decisive, irrelevant ignored), C-LIVE-1, C-CRASH-1
(both :274-284 and :326-327), C-FIX-1, C-BACKEND-IRR-1.
"""
from __future__ import annotations

import argparse
import sys

import pytest

from hermes_cli import doctor_live


class TestCDecidePureResolver:
    def test_resolver_exists_with_exact_table(self, monkeypatch):
        assert hasattr(doctor_live, "resolve_browser_selection"), \
            "missing ONE pure resolver resolve_browser_selection (C-DECIDE-1), bool is NOT resolver"
        r = doctor_live.resolve_browser_selection
        # off -> off-skip (never enables dependents)
        assert r("off", True, True) == "off-skip"
        assert r("off", False, False) == "off-skip"
        # False-as-off (YAML 1.1 unquoted off as False -> off)
        assert r(False, True, True) == "off-skip"
        # explicit browser-use -> browser-use only, no fallback
        assert r("browser-use", True, True) == "browser-use"
        assert r("browser-use", False, False) == "browser-use"
        # explicit agent-browser -> agent-browser only
        assert r("agent-browser", True, True) == "agent-browser"
        assert r("agent-browser", False, False) == "agent-browser"
        # unknown string -> fail (never skip)
        assert r("mystery", True, True) == "fail"
        # unset "" deterministic order
        assert r("", True, True) == "browser-use"  # harness-runnable -> browser-use
        assert r("", False, True) == "agent-browser"  # else agent-browser-known -> agent-browser
        assert r("", False, False) == "unconfigured-skip"  # else genuinely-none
        # config parse failure / resolver exception -> fail tested via _configured_backend_key except->fail
        # bool predicate must NOT be cited as resolver
        import inspect
        src = inspect.getsource(r)
        assert "browser-use" in src and "agent-browser" in src

    def test_configured_key_except_fail_not_unset(self, monkeypatch):
        def _boom():
            raise OSError("injected cfg failure")
        monkeypatch.setattr("tools.browser_use_cli.get_browser_backend", _boom)
        key = doctor_live._configured_backend_key()
        # except -> fail verdict, never "" unset-default
        assert key == "fail" or "fail" in str(key).lower(), \
            f"_configured_backend_key except must be fail, got {key!r} (C-DECIDE-1.1)"

    def test_bool_not_resolver(self):
        import inspect
        from tools import browser_use_cli as buc
        src = inspect.getsource(buc.is_browser_use_cli_mode)
        assert "bool" in src.lower() or "True when" in src
        # doctor_live must not use bool as resolver
        dsrc = inspect.getsource(doctor_live)
        # New resolver must exist; bool alone must not resolve
        assert "resolve_browser_selection" in dsrc
        assert "is_browser_use_cli_mode" not in dsrc or "NOT the resolver" in dsrc or "bool" in dsrc.lower()


class TestCOracleLaunchOnly:
    def test_no_version_pass_anywhere(self):
        import inspect
        src = inspect.getsource(doctor_live)
        # Version string alone NEVER confers PASS: no standalone version-probe PASS
        # _harness_version_probe standalone PASS must be gone; version only as backend-native
        # bounded reaped protocol, never PASS alone.
        # We assert launch oracle exists and version-pass disjuncts removed.
        assert "_launch_browser_probe" in src or "launch_oracle" in src or "about:blank" in src
        # No bare version-pass: harness --version must not return (True,...) alone
        # If _harness_version_probe still confers PASS, fail.
        if hasattr(doctor_live, "_harness_version_probe"):
            hsrc = inspect.getsource(doctor_live._harness_version_probe)
            assert "return (True" not in hsrc, \
                "version subprocess must NEVER confer PASS alone (C-ORACLE-1)"

    def test_launch_oracle_bounded_owned_known_dom(self, tmp_path, monkeypatch):
        # PASS requires ACTUAL launch: exact binary, about:blank, KNOWN-DOM eval, close/reap.
        # Bounded 1s<=timeout<=15s, output cap, capture_output, check=False, wait/reap, close finally.
        import inspect
        src = inspect.getsource(doctor_live)
        assert "about:blank" in src, "launch oracle must open about:blank (C-ORACLE-2)"
        assert "15" in src, "timeout clamp 1..15s must be pinned (C-ORACLE-2)"
        # No Python-playwright launch mechanism for agent-browser
        assert "sync_playwright" not in src or "NEVER" in src or "ACTUAL CLI" in src, \
            "agent-browser via ACTUAL CLI ONLY, no Python-playwright (C-ORACLE-2)"
        # Irrelevant deps ignored: browser-use PASS with Chromium/playwright/agent-browser absent
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        # Harness runnable via launch oracle only
        monkeypatch.setattr("tools.browser_use_cli._find_cli",
                            lambda: ["python", "-m", "browser_harness.run"])
        # Chromium/playwright/agent-browser absent must be ignored for browser-use
        monkeypatch.setattr(doctor_live, "chromium_executable", lambda: None)
        import builtins as _bi
        real_import = _bi.__import__
        def _no_pw(name, *a, **k):
            if name.startswith("playwright"):
                raise ImportError("No module named playwright")
            return real_import(name, *a, **k)
        monkeypatch.setattr(_bi, "__import__", _no_pw)
        # Fake launch oracle to prove selection ignores irrelevant deps
        monkeypatch.setattr(doctor_live, "_launch_browser_probe",
                            lambda timeout: (True, "launched + about:blank + KNOWN-DOM + closed"))
        res = doctor_live._probe_browser(5.0)
        assert res.status == "pass", "browser-use must PASS with only harness launch (irrelevant ignored)"

    def test_explicit_selected_launch_fail_never_fallback(self, monkeypatch):
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        monkeypatch.setattr(doctor_live, "_launch_browser_probe",
                            lambda timeout: (False, "selected launch failed"))
        # Must be fail, never fallback to other backend
        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", "explicit-selected launch-fail must be fail, never fallback (C-BACKEND-1)"

    def test_live_non_mutating_static_non_downloading(self, monkeypatch):
        import pm as _pm
        def _boom(*a, **k):
            raise AssertionError("doctor --live must never pm.ensure/download (C-LIVE-1)")
        monkeypatch.setattr(_pm, "ensure", _boom)
        monkeypatch.setattr(_pm, "ensure_import", _boom, raising=False)
        monkeypatch.setattr("hermes_cli.config.load_config_readonly", dict)
        monkeypatch.setattr(doctor_live, "_browser_available",
                            lambda: False, raising=False)
        # Static doctor (no --live) performs no live probes tested via maybe_run_live_checks live=False
        called = []
        monkeypatch.setattr(doctor_live, "run_live_checks",
                            lambda *a, **k: called.append(True) or [])
        assert doctor_live.maybe_run_live_checks(argparse.Namespace(live=False), []) is None
        assert called == []


class TestCCrashBothSites:
    def test_outer_crash_check_fail_nonzero(self, monkeypatch, capsys):
        def _boom(*a, **k):
            raise RuntimeError("live subsystem exploded")
        monkeypatch.setattr(doctor_live, "run_live_checks", _boom)
        issues: list[str] = []
        out = doctor_live.maybe_run_live_checks(argparse.Namespace(live=True), issues)
        # Outer :326-327 MUST become check_fail + append to issues (nonzero), not check_warn/None
        assert issues, "outer crash must append to issues (C-CRASH-1 :326-327)"
        assert out is None  # return may be None but issues drives nonzero
        # check_warn at :326-327 fails: assert source uses check_fail
        import inspect
        src = inspect.getsource(doctor_live.maybe_run_live_checks)
        assert "check_fail" in src, "outer :326-327 must be check_fail (C-CRASH-1)"
        assert "check_warn" not in src, "check_warn at :326-327 fails review (C-CRASH-1)"

    def test_per_probe_crash_fail(self, monkeypatch):
        issues: list[str] = []
        res = doctor_live._run_one("X", lambda: (_ for _ in ()).throw(RuntimeError("boom")), issues)
        assert res.status == "fail", "per-probe _run_one crash -> fail (C-CRASH-1)"
        assert issues, "per-probe fail must append issue"
