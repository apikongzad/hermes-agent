"""RED C: no --help PASS, no fabricated KNOWN-DOM, real launch oracle.

Functional with fake configured-backend binaries (temp executables, no live
host changes): help inspect never PASS, unavailable configured FAIL, unset
includes Chromium, real documented cmds + KNOWN-DOM eval + owned close/reap.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from hermes_cli import doctor_live


def _make_exe(path: Path, body: str) -> str:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


class TestCRedNoHelpPass:
    def test_fake_help_only_must_fail(self, tmp_path, monkeypatch):
        # Fake harness that only implements --help (returns 0) but no open/eval/close.
        fake = tmp_path / "fake-harness"
        _make_exe(fake, "#!/usr/bin/env python3\nimport sys\nif '--help' in sys.argv:\n print('fake harness help')\n sys.exit(0)\nprint('unknown')\n")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        monkeypatch.setattr("tools.browser_use_cli._find_cli", lambda: [sys.executable, str(fake)])
        # Real oracle (no monkeypatched _launch_browser_probe) must FAIL on help-only
        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", \
            f"RED C: fake --help-only CLI must FAIL (no actual launch), got {res.status} {res.detail}"

    def test_unavailable_configured_browser_fail_no_fallback(self, tmp_path, monkeypatch):
        # Configured browser-use but harness missing; agent-browser available -> must FAIL, never fallback pass
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        monkeypatch.setattr("tools.browser_use_cli._find_cli", lambda: None)
        # Agent-browser present must be ignored (no fallback)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: True)
        monkeypatch.setattr("tools.browser_tool_install._find_agent_browser",
                            lambda validate=False: "/tmp/fake-agent-browser", raising=False)
        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", \
            f"RED C: unavailable configured backend must FAIL (no fallback), got {res.status}"

    def test_unset_readiness_includes_chromium(self, monkeypatch):
        # Unset "" with harness missing, binary present but Chromium missing -> unconfigured-skip
        # (agent-browser known requires binary AND chromium per DESIGN C-DECIDE-1)
        # We assert the resolver contract requires Chromium: callers must pass combined readiness.
        # Here we verify _probe_browser with binary-only but no Chromium does NOT select agent-browser pass.
        # Direct resolver check with explicit chromium-aware flag:
        # If resolver only takes binary flag, this documents the gap -> must fail red until fixed.
        # After fix, callers pass (binary and chromium); resolver truth table unchanged but inputs correct.
        # For red, assert that binary-present/Chromium-absent unset is NOT agent-browser.
        # We drive _probe_browser with monkeypatched readiness to prove it.
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "")
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: False)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: True)  # binary only
        monkeypatch.setattr(doctor_live, "chromium_executable", lambda: None)  # chromium missing
        # Also patch underlying finders to match
        monkeypatch.setattr("tools.browser_use_cli._find_cli", lambda: None)
        monkeypatch.setattr("tools.browser_tool_install._find_agent_browser",
                            lambda validate=False: "/tmp/fake-ab", raising=False)
        res = doctor_live._probe_browser(5.0)
        assert res.status == "skip", \
            f"RED C: unset with binary-only (Chromium missing) must be unconfigured-skip, got {res.status} {res.detail}"


class TestCRedRealLaunchOracle:
    def test_agent_browser_real_documented_cmds_known_dom_close_reap(self, tmp_path, monkeypatch):
        # Fake agent-browser implementing DOCUMENTED commands: open, eval, close (+ --help inspect)
        # Oracle must actually invoke them, evaluate KNOWN-DOM actual result, close owned session, reap.
        log = tmp_path / "calls.log"
        fake = tmp_path / "agent-browser"
        _make_exe(fake, f"""#!/usr/bin/env python3
import sys, os
log={str(log)!r}
def rec(s):
    open(log,'a').write(s+'\\n')
args=sys.argv[1:]
rec('CALL:'+' '.join(args))
if args==['--help']:
    print('open <url>\\neval <js>\\nclose\\nget\\nsnapshot')
    sys.exit(0)
# session handling: --session-name <name> <cmd> ...
if '--session-name' in args:
    i=args.index('--session-name')
    sess=args[i+1]
    cmd=args[i+2:]
else:
    sess='default'; cmd=args
if cmd[:1]==['open'] and cmd[1:2]==['about:blank']:
    print('opened about:blank session='+sess)
    sys.exit(0)
if cmd[:1]==['eval']:
    # KNOWN-DOM assertion: evaluate JS, return marker
    print('<html><body data-probe="known-dom">KNOWN-DOM-OK</body></html>')
    sys.exit(0)
if cmd[:1]==['close']:
    print('closed session='+sess)
    sys.exit(0)
print('unknown cmd:'+' '.join(cmd), file=sys.stderr)
sys.exit(2)
""")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "agent-browser")
        monkeypatch.setattr("tools.browser_tool_install._find_agent_browser",
                            lambda validate=False: str(fake), raising=False)
        monkeypatch.setattr(doctor_live, "chromium_executable", lambda: "/tmp/fake-chrome")
        # Real oracle must PASS only via actual open+eval(KNOWN-DOM)+close, not --help alone
        res = doctor_live._probe_browser(5.0)
        assert res.status == "pass", f"RED C: real documented launch must PASS, got {res.status} {res.detail}"
        calls = log.read_text(encoding="utf-8") if log.exists() else ""
        assert "open about:blank" in calls, f"RED C: oracle must actually open about:blank via CLI, calls={calls!r}"
        assert "eval" in calls, f"RED C: oracle must actually evaluate KNOWN-DOM, calls={calls!r}"
        assert "close" in calls, f"RED C: oracle must close owned session in finally, calls={calls!r}"
        # No --help PASS: help may be inspected but must not alone confer PASS (open/eval required)
        assert calls.count("CALL:--help") <= 1, "help inspect at most once, never as PASS"

    def test_browser_use_real_harness_launch_known_dom(self, tmp_path, monkeypatch):
        # Fake browser-harness entrypoint: [sys.executable, fake.py] implementing --help + stdin PY protocol
        # (like real browser_exec: cmd with code via stdin). Oracle must run it with PY containing
        # about:blank + KNOWN-DOM eval and check actual result, not --help text.
        log = tmp_path / "harness-calls.log"
        fake = tmp_path / "fake_harness.py"
        fake.write_text(f"""import sys
log={str(log)!r}
def rec(s):
    open(log,'a').write(s+'\\n')
args=sys.argv[1:]
data=sys.stdin.read() if not sys.stdin.isatty() else ''
rec('ARGV:'+' '.join(args)+' STDIN:'+data[:500])
if '--help' in args:
    print('browser-harness\\nCommands:\\n --version\\n --doctor\\n')
    sys.exit(0)
# Real launch: stdin PY must contain about:blank + documented KNOWN-DOM eval (outerHTML/js)
if 'about:blank' in data and ('outerHTML' in data or 'js(' in data):
    print('<html><body data-probe="known-dom">KNOWN-DOM-OK</body></html>')
    sys.exit(0)
print('harness: missing about:blank+KNOWN-DOM eval', file=sys.stderr)
sys.exit(2)
""", encoding="utf-8")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        monkeypatch.setattr("tools.browser_use_cli._find_cli",
                            lambda: [sys.executable, str(fake)])
        res = doctor_live._probe_browser(5.0)
        assert res.status == "pass", f"RED C: harness real launch must PASS via about:blank+KNOWN-DOM, got {res.status} {res.detail}"
        calls = log.read_text(encoding="utf-8") if log.exists() else ""
        assert "about:blank" in calls, f"RED C: harness oracle must send about:blank PY, calls={calls!r}"
        assert "outerHTML" in calls or "js(" in calls, f"RED C: must eval KNOWN-DOM via documented js/outerHTML, calls={calls!r}"
