"""Tests for ``hermes doctor --live`` — opt-in bounded real-call tool-backend probes.

All probes are mocked at the HTTP/client layer; no real network calls are made.
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

from hermes_cli import doctor_live
from hermes_cli.doctor_live import (
    maybe_run_live_checks,
    run_live_checks,
)

# The exact environment Clash Verge / mihomo exports (issue #118159): a bracketed-IPv6
# NO_PROXY entry that httpx 0.28.1 cannot parse into a proxy mount.
_CLASH_NO_PROXY = "127.0.0.1,localhost,::1,[::1]"


@pytest.fixture
def clash_env(monkeypatch):
    for key in ("NO_PROXY", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("NO_PROXY", _CLASH_NO_PROXY)
    monkeypatch.setenv("no_proxy", _CLASH_NO_PROXY)


class _Probes(BaseHTTPRequestHandler):
    """Minimal 200-origin for live-path tests; every request is a bare metadata GET."""

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # keep test output clean


def _args(live: bool = True) -> argparse.Namespace:
    return argparse.Namespace(live=live)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Strip backend credentials so each test opts in explicitly."""
    for var in ("FIRECRAWL_API_KEY", "FAL_KEY", "OPENAI_API_KEY",
                "ELEVENLABS_API_KEY", "GROQ_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    # Default: empty config, no MCP servers, local tts/stt.
    monkeypatch.setattr("hermes_cli.config.load_config_readonly", dict)
    # Default: browser not installed.
    monkeypatch.setattr(doctor_live, "_browser_available", lambda: False)


class TestLiveFlagGating:

    def test_no_live_flag_means_zero_probes(self, monkeypatch):
        called = []
        monkeypatch.setattr(
            doctor_live, "run_live_checks",
            lambda *a, **k: called.append(True))
        result = maybe_run_live_checks(_args(live=False), [])
        assert result is None
        assert called == []



    def test_live_check_crash_never_propagates(self, monkeypatch, capsys):
        def _boom(*a, **k):
            raise RuntimeError("probe subsystem exploded")

        monkeypatch.setattr(doctor_live, "run_live_checks", _boom)
        # Must not raise.
        maybe_run_live_checks(_args(live=True), [])


class TestConfiguredOnlySelection:
        # No issues appended for skips.

    def test_unconfigured_backends_do_not_touch_network(self, monkeypatch):
        def _no_net(*a, **k):
            raise AssertionError("HTTP call made for unconfigured backend")

        monkeypatch.setattr(doctor_live, "_http_get", _no_net)
        # Rev6: resolver inputs False -> unconfigured-skip
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: False)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: False)
        results = run_live_checks([])
        assert all(r.status == "skip" for r in results)

    def test_firecrawl_probed_when_key_present(self, monkeypatch):
        monkeypatch.setenv("FIRECRAWL_API_KEY", "fc-test")
        calls = []

        def _fake_get(url, headers=None, timeout=None):
            calls.append(url)
            return SimpleNamespace(status_code=200)

        monkeypatch.setattr(doctor_live, "_http_get", _fake_get)
        results = {r.name: r for r in run_live_checks([])}
        assert results["Firecrawl"].status == "pass"
        assert any("firecrawl" in u for u in calls)

    def test_firecrawl_invalid_key_fails_and_appends_issue(self, monkeypatch):
        monkeypatch.setenv("FIRECRAWL_API_KEY", "fc-bad")
        monkeypatch.setattr(
            doctor_live, "_http_get",
            lambda *a, **k: SimpleNamespace(status_code=401))
        issues: list[str] = []
        results = {r.name: r for r in run_live_checks(issues)}
        assert results["Firecrawl"].status == "fail"
        assert any("FIRECRAWL" in i or "Firecrawl" in i for i in issues)


    def test_mcp_servers_probed_per_configured_server(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.load_config_readonly",
            lambda: {"mcp_servers": {"alpha": {"url": "https://x"},
                                     "beta": {"command": "foo"}}})
        probed = []
        monkeypatch.setattr(
            doctor_live, "_probe_mcp_server",
            lambda name, cfg, timeout: probed.append(name) or [("t", "d")])
        results = [r for r in run_live_checks([]) if r.name.startswith("MCP")]
        assert sorted(probed) == ["alpha", "beta"]
        assert len(results) == 2
        assert all(r.status == "pass" for r in results)

    def test_tts_local_provider_skipped(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.load_config_readonly",
            lambda: {"tts": {"provider": "edge"}})
        results = {r.name: r for r in run_live_checks([])}
        assert results["TTS"].status == "skip"

    def test_tts_openai_probed_with_key(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setattr(
            "hermes_cli.config.load_config_readonly",
            lambda: {"tts": {"provider": "openai"}})
        monkeypatch.setattr(
            doctor_live, "_http_get",
            lambda *a, **k: SimpleNamespace(status_code=200))
        results = {r.name: r for r in run_live_checks([])}
        assert results["TTS"].status == "pass"

    def test_stt_groq_probed_with_key(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
        monkeypatch.setattr(
            "hermes_cli.config.load_config_readonly",
            lambda: {"stt": {"provider": "groq"}})
        monkeypatch.setattr(
            doctor_live, "_http_get",
            lambda *a, **k: SimpleNamespace(status_code=200))
        results = {r.name: r for r in run_live_checks([])}
        assert results["STT"].status == "pass"

    def test_stt_provider_configured_but_key_missing_warns(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.load_config_readonly",
            lambda: {"stt": {"provider": "groq"}})
        results = {r.name: r for r in run_live_checks([])}
        assert results["STT"].status == "warn"

    def test_browser_probed_when_available(self, monkeypatch):
        monkeypatch.setattr(doctor_live, "_browser_available", lambda: True)
        # Rev6 resolver: harness runnable -> browser-use selected
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: True)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: False)
        monkeypatch.setattr(
            doctor_live, "_launch_browser_probe",
            lambda timeout: (True, "about:blank ok"))
        results = {r.name: r for r in run_live_checks([])}
        assert results["Browser"].status == "pass"

    def test_unconfigured_browser_is_optional_skip_not_broken(self, monkeypatch):
        """Unconfigured optional backend must be skip (never fail, never enable)."""
        monkeypatch.setattr(doctor_live, "_browser_available", lambda: False)
        # Rev6: genuinely-none-configured -> unconfigured-skip
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: False)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: False)
        called = []
        monkeypatch.setattr(doctor_live, "_launch_browser_probe",
                            lambda timeout: called.append(True) or (True, "must not run"))
        issues: list[str] = []
        results = {r.name: r for r in run_live_checks(issues)}
        assert results["Browser"].status == "skip"
        assert called == []
        assert issues == []
        # Probes never enable services: no pm.ensure/install path is touched.
        import pm as _pm
        monkeypatch.setattr(_pm, "ensure", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not enable services")))
        # Re-run: still skip without touching ensure.
        results = {r.name: r for r in run_live_checks([])}
        assert results["Browser"].status == "skip"


@pytest.mark.parametrize("kind", ["NO_PROXY", "no_proxy"])
@pytest.mark.parametrize("entry", ["[::1]", "[::1]:8080", "::1/128"])
def test_http_get_sanitizes_bracketed_ipv6_no_proxy(monkeypatch, kind, entry):
    # The Clash Verge / mihomo export from #118159: httpx 0.28.1 turns a bracketed or
    # CIDR IPv6 NO_PROXY entry into an unparseable mount pattern and raises InvalidURL
    # at client construction, before any request. doctor --live's _http_get must not.
    for key in ("NO_PROXY", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv(kind, f"127.0.0.1,localhost,::1,{entry}")
    # A bare local-socket GET proves the client was constructible; 127.0.0.1's own
    # NO_PROXY membership keeps it out of any proxy's reach.
    with HTTPServer(("127.0.0.1", 0), _Probes) as httpd:
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            resp = doctor_live._http_get(
                f"http://127.0.0.1:{httpd.server_port}/", timeout=5.0)
            assert resp.status_code == 200
        finally:
            httpd.shutdown()
            thread.join(timeout=5)


def test_run_live_checks_sanitizes_clash_env_and_probes_pass(clash_env, monkeypatch):
    # Red-on-base end-to-end: _keyed_probe -> _http_get -> bare httpx.get raised
    # InvalidURL under this env; _run_one's catch-all dressed it up as
    # "(Invalid port: ':1]')" — a backend-failure verdict for a healthy service.
    monkeypatch.setenv("FIRECRAWL_API_KEY", "fc-test")
    # Isolate Browser to skip (off) so Firecrawl pass yields no issues; real
    # launch oracle would otherwise FAIL without a live browser (fail-closed).
    monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "off")

    # Real HTTP origin: a 200 from an actual socket proves both client construction
    # and the request reaching a reachable origin. The remote-credential probes would
    # send real auth material or 401 without proving either.
    with HTTPServer(("127.0.0.1", 0), _Probes) as httpd:
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            monkeypatch.setitem(
                doctor_live._KEYED_PROBES, "Firecrawl",
                (f"http://127.0.0.1:{httpd.server_port}/v2/team/credit-usage",
                 "FIRECRAWL_API_KEY", "Bearer"))
            issues: list[str] = []
            results = {r.name: r for r in run_live_checks(issues)}
            assert results["Firecrawl"].status == "pass"
            assert issues == []
            assert "Invalid port" not in (results["Firecrawl"].detail or "")
        finally:
            httpd.shutdown()
            thread.join(timeout=5)
    # The seam rewrote the entry in place, the established pattern of this seam
    # (chat transports and run_probes already do exactly this).
    assert "[::1]" not in os.environ["NO_PROXY"]
    assert os.environ["no_proxy"] == "127.0.0.1,localhost,::1"


def test_run_live_checks_leaves_a_clean_environment_untouched(monkeypatch):
    for key in ("NO_PROXY", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("NO_PROXY", "example.com,10.0.0.0/8")
    # _http_get is untouched by the sanitize-once design; a socket-level 200 proves
    # the live path still works end to end when there is nothing to sanitize.
    with HTTPServer(("127.0.0.1", 0), _Probes) as httpd:
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            assert doctor_live._http_get(
                f"http://127.0.0.1:{httpd.server_port}/", timeout=5.0).status_code == 200
        finally:
            httpd.shutdown()
            thread.join(timeout=5)
    assert os.environ["NO_PROXY"] == "example.com,10.0.0.0/8"


class TestBrowserBackendProbe:
    """Configured-backend probe honors backend and does real exec, no pm.ensure."""

    def test_harness_ready_passes_without_playwright_via_real_version_exec(self, monkeypatch):
        """Rev6 launch-only: version string alone NEVER confers PASS (must FAIL)."""
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "")
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: True)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: False)
        monkeypatch.setattr("tools.browser_use_cli._find_cli",
                            lambda: ["python", "-m", "browser_harness.run"])
        import subprocess as _sp
        from types import SimpleNamespace as _NS

        def _fake_run(*a, **k):
            # Version-only output (no about:blank, no KNOWN-DOM) must never PASS
            return _NS(returncode=0, stdout="0.1.13\n", stderr="")

        monkeypatch.setattr(_sp, "run", _fake_run)
        import builtins as _bi
        real_import = _bi.__import__

        def _no_playwright(name, *a, **k):
            if name.startswith("playwright"):
                raise ImportError("No module named playwright")
            return real_import(name, *a, **k)

        monkeypatch.setattr(_bi, "__import__", _no_playwright)
        import pm as _pm
        monkeypatch.setattr(_pm, "ensure",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not ensure")))
        ok, detail = doctor_live._launch_browser_probe(5.0)
        # Version-only (no real launch) must FAIL per C-ORACLE-1
        assert ok is False
        assert "fail-closed" in detail

    def test_harness_import_alone_does_not_pass_when_version_fails(self, monkeypatch):
        """Rev6: launch failure must fail (no version-pass)."""
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "")
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: True)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: False)
        monkeypatch.setattr("tools.browser_use_cli._find_cli",
                            lambda: ["python", "-m", "browser_harness.run"])
        import subprocess as _sp
        from types import SimpleNamespace as _NS
        monkeypatch.setattr(_sp, "run", lambda *a, **k: _NS(returncode=1, stdout="", stderr="boom"))
        import sys as _sys
        monkeypatch.setitem(_sys.modules, "browser_harness", type(_sys)("browser_harness"))
        ok, detail = doctor_live._launch_browser_probe(5.0)
        assert ok is False
        assert "fail-closed" in detail

    def test_explicit_off_honors_backend_as_not_available(self, monkeypatch):
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "off")
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: True)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: True)
        assert doctor_live._browser_available() is False
        assert doctor_live._probe_configured_backend(5.0) is None

    def test_explicit_browser_use_never_falls_back_to_agent_browser(self, monkeypatch, tmp_path):
        """Explicit browser-use with missing harness fails, not agent-browser."""
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: False)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: True)
        monkeypatch.setattr("tools.browser_use_cli._find_cli", lambda: None)
        ok, detail = doctor_live._launch_browser_probe(5.0)
        # Must fail for the configured backend, never silently probe another.
        assert ok is False
        assert "browser-use" in detail

    def test_missing_backend_fails_not_passes(self, monkeypatch):
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "")
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: False)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: False)
        import builtins as _bi
        real_import = _bi.__import__

        def _no_playwright(name, *a, **k):
            if name.startswith("playwright"):
                raise ImportError("No module named playwright")
            return real_import(name, *a, **k)

        monkeypatch.setattr(_bi, "__import__", _no_playwright)
        ok, detail = doctor_live._launch_browser_probe(5.0)
        assert ok is False
        assert "not configured" in detail or "fail-closed" in detail

    def test_agent_browser_ready_probes_binary_bounded(self, monkeypatch, tmp_path):
        # Fake binary echoes version only (no open/eval/close) -> must FAIL (no --help PASS)
        fake_bin = tmp_path / "agent-browser"
        fake_bin.write_text("#!/bin/sh\necho agent-browser-1.2.3\n")
        fake_bin.chmod(0o755)
        fake_chromium = tmp_path / "chromium"
        fake_chromium.write_text("x")
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: False)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: True)
        monkeypatch.setattr("tools.browser_tool_install._find_agent_browser", lambda **_kw: str(fake_bin))
        monkeypatch.setattr(doctor_live, "chromium_executable", lambda: str(fake_chromium))
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "agent-browser")
        ok, detail = doctor_live._launch_browser_probe(5.0)
        # Help/version-only (no real open/eval/close) must FAIL per C-ORACLE-1/2
        assert ok is False
        assert "fail-closed" in detail

    def test_no_backend_no_playwright_reports_ready_state_not_bare_import(self, monkeypatch):
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: False)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: False)
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "")
        import sys as _sys
        monkeypatch.delitem(_sys.modules, "playwright.sync_api", raising=False)
        # Force ImportError even if playwright happens to be installed in the env.
        import builtins as _bi
        real_import = _bi.__import__

        def _no_playwright(name, *a, **k):
            if name.startswith("playwright"):
                raise ImportError("No module named playwright")
            return real_import(name, *a, **k)

        monkeypatch.setattr(_bi, "__import__", _no_playwright)
        ok, detail = doctor_live._launch_browser_probe(5.0)
        assert ok is False
        assert "not configured" in detail or "fail-closed" in detail


class TestFailureIsolation:
    def test_one_probe_raising_does_not_stop_others(self, monkeypatch):
        monkeypatch.setenv("FIRECRAWL_API_KEY", "fc-test")
        monkeypatch.setenv("FAL_KEY", "fal-test")

        def _get(url, headers=None, timeout=None):
            if "firecrawl" in url:
                raise RuntimeError("connection reset")
            return SimpleNamespace(status_code=200)

        monkeypatch.setattr(doctor_live, "_http_get", _get)
        issues: list[str] = []
        results = {r.name: r for r in run_live_checks(issues)}
        assert results["Firecrawl"].status == "fail"
        assert results["FAL"].status == "pass"

    def test_mcp_probe_failure_isolated_per_server(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.load_config_readonly",
            lambda: {"mcp_servers": {"bad": {"url": "https://x"},
                                     "good": {"url": "https://y"}}})

        def _probe(name, cfg, timeout):
            if name == "bad":
                raise ConnectionError("refused")
            return [("tool", "desc")]

        monkeypatch.setattr(doctor_live, "_probe_mcp_server", _probe)
        results = {r.name: r for r in run_live_checks([])}
        assert results["MCP: bad"].status == "fail"
        assert results["MCP: good"].status == "pass"


class TestTimeoutHandling:
    def test_timeout_reported_as_fail(self, monkeypatch):
        monkeypatch.setenv("FIRECRAWL_API_KEY", "fc-test")

        def _slow(*a, **k):
            raise TimeoutError("timed out")

        monkeypatch.setattr(doctor_live, "_http_get", _slow)
        results = {r.name: r for r in run_live_checks([])}
        assert results["Firecrawl"].status == "fail"
        assert "time" in (results["Firecrawl"].detail or "").lower()

    def test_probe_timeout_bounded_and_configurable(self, monkeypatch):
        monkeypatch.setenv("FIRECRAWL_API_KEY", "fc-test")
        monkeypatch.setattr(
            "hermes_cli.config.load_config_readonly",
            lambda: {"doctor": {"live_probe_timeout": 3}})
        seen = {}

        def _get(url, headers=None, timeout=None):
            seen["timeout"] = timeout
            return SimpleNamespace(status_code=200)

        monkeypatch.setattr(doctor_live, "_http_get", _get)
        run_live_checks([])
        assert seen["timeout"] == 3



class TestReadOnly:

    def test_skips_never_append_issues(self, capsys, monkeypatch):
        # Isolate Browser to skip so clean env (no keys, local audio) yields no issues.
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "off")
        issues: list[str] = []
        run_live_checks(issues)
        assert issues == []
