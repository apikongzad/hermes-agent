"""RED C migrated: single Chromium backend via current launcher API.

No deleted backends (browser-use / agent-browser rows are gone upstream);
this file proves the CURRENT probe (chromium_executable + launch_chromium /
stop_browser) fail-closed:

- bounded launch failure / timeout / crash -> fail (never pass), issues appended
- help-only or echo-only Chromium binary cannot pass
- unavailable Chromium never passes (unset -> skip, missing file -> fail)
- real isolated Chromium (where configured) does a deterministic DOM eval
- cleanup runs even when evaluation fails
"""
from __future__ import annotations

import stat
from pathlib import Path

import pytest

from hermes_cli import doctor_live


def _make_exe(path: Path, body: str) -> str:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def _patch_chromium(monkeypatch, value):
    """Point BOTH resolutions at ``value`` (probe + launcher read different refs)."""
    monkeypatch.setattr("hermes_cli.browser_runtime.chromium_executable", lambda **_kw: value)
    monkeypatch.setattr(doctor_live, "chromium_executable", lambda **_kw: value)


def _real_chromium() -> str | None:
    """Real packaged Chromium (subprocess discovery only: no Python I/O on the real home)."""
    import subprocess

    try:
        out = subprocess.run(
            ["ls", "/home/ubuntu/.hermes/tools"], capture_output=True, text=True, timeout=5, check=False
        )
        if out.returncode == 0:
            for entry in sorted(out.stdout.split()):
                if entry.startswith("chromium-"):
                    for cand in (
                        f"/home/ubuntu/.hermes/tools/{entry}/chrome-linux/chrome",
                        f"/home/ubuntu/.hermes/tools/{entry}/chrome-linux-arm64/chromium",
                    ):
                        chk = subprocess.run(["test", "-x", cand], timeout=5, check=False)
                        if chk.returncode == 0:
                            return cand
    except Exception:
        return None
    return None


class TestRedCFailClosed:
    def test_launch_error_fails_and_stops(self, monkeypatch):
        calls: list = []

        def _launch(key, **kw):
            calls.append(("launch", key, dict(kw)))
            return (None, "Chromium exited with code 1: missing libnss3")

        def _stop(key):
            calls.append(("stop", key))

        monkeypatch.setattr("tools.browser_launcher.launch_chromium", _launch)
        monkeypatch.setattr("tools.browser_launcher.stop_browser", _stop)
        _patch_chromium(monkeypatch, "/tmp/fake-chrome")

        ok, detail = doctor_live._launch_browser_probe(5.0)
        assert ok is False and "libnss3" in detail
        assert [c[0] for c in calls] == ["launch", "stop"]
        assert calls[0][2]["ephemeral"] is True and calls[0][2]["timeout"] == 5.0

        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", f"launch error must be fail, got {res.status}"
        # _run_one path appends issues for fail
        issues: list[str] = []
        out = doctor_live._run_one("Browser", lambda: doctor_live._probe_browser(5.0), issues)
        assert out.status == "fail" and issues, "fail must append issues"

    def test_launch_timeout_and_crash_fail_closed_with_cleanup(self, monkeypatch):
        for exc in (TimeoutError("timed out"), RuntimeError("boom")):
            calls: list = []

            def _launch(_key, _exc=exc, **kw):
                calls.append("launch")
                raise _exc

            def _stop(_key):
                calls.append("stop")

            monkeypatch.setattr("tools.browser_launcher.launch_chromium", _launch)
            monkeypatch.setattr("tools.browser_launcher.stop_browser", _stop)
            _patch_chromium(monkeypatch, "/tmp/fake-chrome")

            issues: list[str] = []
            res = doctor_live._run_one("Browser", lambda: doctor_live._probe_browser(2.0), issues)
            assert res.status == "fail", f"{exc!r} must be fail, got {res.status}"
            assert issues, "crash/timeout must append issues"
            assert calls == ["launch", "stop"], f"stop must run even on raise, got {calls!r}"
            if isinstance(exc, TimeoutError):
                assert "time" in res.detail.lower(), f"timeout detail must name it, got {res.detail!r}"


class TestRedCNoFakePass:
    def test_help_only_binary_cannot_pass(self, tmp_path, monkeypatch):
        fake = tmp_path / "fake-chrome-help"
        _make_exe(
            fake,
            "#!/usr/bin/env python3\nimport sys\n"
            "print('fake chromium help')\n"
            "sys.exit(0)\n",
        )
        _patch_chromium(monkeypatch, str(fake))
        ok, detail = doctor_live._launch_browser_probe(3.0)
        assert ok is False, f"help-only binary must not launch, got {(ok, detail)}"
        res = doctor_live._probe_browser(3.0)
        assert res.status == "fail", f"help-only must be fail (never pass/skip), got {res.status}"

    def test_echo_binary_cannot_pass(self, tmp_path, monkeypatch):
        fake = tmp_path / "fake-chrome-echo"
        _make_exe(
            fake,
            "#!/usr/bin/env python3\nimport sys\n"
            "data = sys.stdin.read() if not sys.stdin.isatty() else ''\n"
            "sys.stdout.write(data or 'echo')\n"
            "sys.exit(0)\n",
        )
        _patch_chromium(monkeypatch, str(fake))
        ok, _ = doctor_live._launch_browser_probe(3.0)
        assert ok is False, "echo binary must not launch"
        res = doctor_live._probe_browser(3.0)
        assert res.status == "fail", f"echo must be fail, got {res.status}"


class TestRedCUnavailableNeverPasses:
    def test_unset_skips_and_missing_fails_never_passes(self, monkeypatch):
        _patch_chromium(monkeypatch, None)
        assert doctor_live._browser_available() is False
        res = doctor_live._probe_browser(5.0)
        assert res.status == "skip", f"unset must be skip, got {res.status}"

        _patch_chromium(monkeypatch, "/nonexistent/chromium-missing-xyz")
        assert doctor_live._browser_available() is True
        res = doctor_live._probe_browser(3.0)
        assert res.status == "fail", f"missing binary must be fail, got {res.status} {res.detail}"
        assert res.status != "pass"


class TestRedCRealDomAndCleanup:
    @pytest.mark.platforms("posix")
    @pytest.mark.live_system_guard_bypass  # real Chromium spawn + parent-first stop is ours to reap
    def test_real_ephemeral_deterministic_eval_and_cleanup(self, monkeypatch):
        exe = _real_chromium()
        if exe is None:
            pytest.skip("real Chromium absent in this env")
        _patch_chromium(monkeypatch, exe)
        from tools import browser_launcher as launcher

        # Bypass the hermetic home guard's isfile probe (existence already
        # proven via subprocess `test -x` above); the launch itself is a
        # native spawn with an ephemeral profile under the isolated HERMES_HOME.
        monkeypatch.setattr(launcher, "_resolve_executable", lambda: exe)

        # Production probe passes on the real backend and owns cleanup.
        res = doctor_live._probe_browser(15.0)
        assert res.status == "pass", f"real Chromium must pass probe, got {res.status} {res.detail}"
        assert launcher.get_browser("doctor-live-probe") is None, "probe must stop what it started"

        # Deterministic DOM op on a second isolated launch: eval must be exact.
        key = "doctor-live-dom"
        browser, err = launcher.launch_chromium(key, executable=exe, ephemeral=True, timeout=15)
        assert err is None and browser is not None, f"real launch failed: {err}"
        try:
            assert browser.cdp_url.startswith("ws://") and browser.http_url.startswith("http://")
            assert browser.owned and browser.ephemeral
            import requests
            from tools.browser_cdp_tool import _cdp_call, _run_async

            targets = requests.get(browser.http_url + "/json/list", timeout=5).json()
            page = next((t for t in targets if t.get("type") == "page"), None)
            assert page is not None and page.get("url") == "about:blank"
            out = _run_async(
                _cdp_call(
                    browser.cdp_url,
                    "Runtime.evaluate",
                    {"expression": "7*6", "returnByValue": True},
                    page["id"],
                    10.0,
                )
            )
            assert out.get("result", {}).get("value") == 42, f"deterministic eval must be 42, got {out!r}"
            url_out = _run_async(
                _cdp_call(
                    browser.cdp_url,
                    "Runtime.evaluate",
                    {"expression": "document.URL", "returnByValue": True},
                    page["id"],
                    10.0,
                )
            )
            assert url_out.get("result", {}).get("value") == "about:blank"
            # Failing eval still raises (fail-closed) — cleanup below must still run.
            with pytest.raises(Exception):
                _run_async(_cdp_call(browser.cdp_url, "NoSuch.method", {}, page["id"], 5.0))
            udd = browser.user_data_dir
            assert Path(udd).exists()
        finally:
            launcher.stop_browser(key)
        assert launcher.get_browser(key) is None
        assert not Path(udd).exists(), "ephemeral profile must be removed on stop"
