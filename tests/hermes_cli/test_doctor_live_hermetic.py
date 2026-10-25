"""Hermetic live checks: bounded, no network/download, owned cleanup.

Covers the CURRENT Chromium backend (chromium_executable + launch_chromium /
stop_browser) plus the preserved 8-line contract: timeout clamped 1..15s and
every failure appends to issues (fail-closed, never silent green).
"""
from __future__ import annotations

import argparse
import sys
from types import ModuleType

import pytest

from hermes_cli import doctor_live


def _args(live: bool = True) -> argparse.Namespace:
    return argparse.Namespace(live=live)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("FIRECRAWL_API_KEY", "FAL_KEY", "OPENAI_API_KEY", "ELEVENLABS_API_KEY", "GROQ_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("hermes_cli.config.load_config_readonly", dict)
    monkeypatch.setattr(doctor_live, "_browser_available", lambda: False)


class TestHermeticTimeoutClamp:
    @pytest.mark.parametrize(
        "cfg,expected",
        [(0, 1.0), (0.5, 1.0), (3, 3.0), (15, 15.0), (100, 15.0)],
    )
    def test_timeout_clamped_1_to_15(self, monkeypatch, cfg, expected):
        monkeypatch.setattr("hermes_cli.config.load_config_readonly", lambda: {"doctor": {"live_probe_timeout": cfg}})
        seen: dict = {}
        monkeypatch.setattr(doctor_live, "_http_get", lambda *a, **k: seen.setdefault("http", k.get("timeout")))
        monkeypatch.setattr(
            doctor_live, "_launch_browser_probe", lambda timeout: seen.setdefault("launch", timeout) or (False, "x")
        )
        monkeypatch.setattr(doctor_live, "_browser_available", lambda: True)
        import os

        monkeypatch.setenv("FIRECRAWL_API_KEY", "fc-test")
        doctor_live.run_live_checks([])
        assert seen["http"] == expected, f"cfg {cfg} must clamp to {expected}, got {seen['http']!r}"
        assert seen["launch"] == expected

    def test_invalid_timeout_falls_back_to_default(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.load_config_readonly", lambda: {"doctor": {"live_probe_timeout": "bad"}}
        )
        seen: dict = {}
        monkeypatch.setattr(doctor_live, "_http_get", lambda *a, **k: seen.setdefault("timeout", k.get("timeout")))
        import os

        monkeypatch.setenv("FIRECRAWL_API_KEY", "fc-test")
        doctor_live.run_live_checks([])
        assert seen["timeout"] == doctor_live.DEFAULT_PROBE_TIMEOUT


class TestHermeticCrashFailClosed:
    def test_per_probe_crash_fails_and_appends(self, monkeypatch):
        issues: list[str] = []
        res = doctor_live._run_one("X", lambda: (_ for _ in ()).throw(RuntimeError("boom")), issues)
        assert res.status == "fail"
        assert issues, "per-probe crash must append issues"

    def test_outer_crash_check_fails_and_appends(self, monkeypatch):
        def _boom(*a, **k):
            raise RuntimeError("live subsystem exploded")

        monkeypatch.setattr(doctor_live, "run_live_checks", _boom)
        fails: list = []
        warns: list = []
        monkeypatch.setattr(doctor_live, "check_fail", lambda *a, **k: fails.append(a))
        monkeypatch.setattr(doctor_live, "check_warn", lambda *a, **k: warns.append(a))
        issues: list[str] = []
        out = doctor_live.maybe_run_live_checks(_args(live=True), issues)
        assert out is None
        assert issues, "outer crash must append to issues (fail-closed)"
        assert fails and not warns, "outer crash must be check_fail, never check_warn"


class TestHermeticGatingNoDownload:
    def test_no_live_flag_means_zero_probes(self, monkeypatch):
        called: list = []
        monkeypatch.setattr(doctor_live, "run_live_checks", lambda *a, **k: called.append(True) or [])
        assert doctor_live.maybe_run_live_checks(_args(live=False), []) is None
        assert called == []

    def test_unconfigured_never_touches_network_or_pm(self, monkeypatch):
        def _no_net(*a, **k):
            raise AssertionError("HTTP call made for unconfigured backend")

        monkeypatch.setattr(doctor_live, "_http_get", _no_net)
        import pm as _pm

        def _boom(*a, **k):
            raise AssertionError("doctor --live must never pm.ensure/download")

        monkeypatch.setattr(_pm, "ensure", _boom)
        monkeypatch.setattr(_pm, "ensure_import", _boom, raising=False)
        issues: list[str] = []
        results = doctor_live.run_live_checks(issues)
        assert all(r.status == "skip" for r in results)
        assert issues == [], "skips must never append issues"


class TestHermeticOwnedCleanup:
    def _fake_launcher(self, monkeypatch, result):
        calls: list = []
        fake = ModuleType("tools.browser_launcher")
        fake.launch_chromium = lambda key, **kw: calls.append(("launch", key, kw)) or result
        fake.stop_browser = lambda key: calls.append(("stop", key))
        monkeypatch.setitem(sys.modules, "tools.browser_launcher", fake)
        return calls

    def test_success_and_launch_raise_both_stop(self, monkeypatch):
        from types import SimpleNamespace

        calls = self._fake_launcher(monkeypatch, (SimpleNamespace(cdp_url="ws://x"), None))
        ok, _ = doctor_live._launch_browser_probe(5.0)
        assert ok is True
        assert [c[0] for c in calls] == ["launch", "stop"]

        calls2 = self._fake_launcher(monkeypatch, (None, "boom"))
        ok, _ = doctor_live._launch_browser_probe(5.0)
        assert ok is False
        assert [c[0] for c in calls2] == ["launch", "stop"]

        def _raise(key, **kw):
            calls2.append(("launch-raise", key))
            raise TimeoutError("timed out")

        fake = sys.modules["tools.browser_launcher"]
        fake.launch_chromium = _raise
        issues: list[str] = []
        res = doctor_live._run_one("Browser", lambda: doctor_live._probe_browser(2.0), issues)
        # _probe_browser propagates (no _browser_available mock here would skip),
        # so drive via available True:
        monkeypatch.setattr(doctor_live, "_browser_available", lambda: True)
        res = doctor_live._run_one("Browser", lambda: doctor_live._probe_browser(2.0), issues)
        assert res.status == "fail" and issues
        assert "stop" in [c[0] for c in calls2], "stop must run even when launch raises"
