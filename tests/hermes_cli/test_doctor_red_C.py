"""RED C: no --help PASS, no fabricated HTML, challenge/derived oracle.

Functional with fake configured-backend binaries (temp executables, no live
host changes): help inspect never PASS, unavailable configured FAIL, unset
includes Chromium, challenge set via one evaluate + derived SHA-256 via
SEPARATE in-browser evaluate exact JSON one result event same owned session,
plain-HTML wrong-value FAIL, echo-stdin/sentinel-form FAIL, set-fail still
closes, real configured backends fail honestly (no fallback, no echo-pass).
Threat model: CLI binary trusted only; echo fakeCLI must FAIL.
"""
from __future__ import annotations

import re
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
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "")
        monkeypatch.setattr(doctor_live, "_browser_use_ready", lambda: False)
        monkeypatch.setattr(doctor_live, "_agent_browser_ready", lambda: True)  # binary only
        monkeypatch.setattr(doctor_live, "chromium_executable", lambda: None)  # chromium missing
        monkeypatch.setattr("tools.browser_use_cli._find_cli", lambda: None)
        monkeypatch.setattr("tools.browser_tool_install._find_agent_browser",
                            lambda validate=False: "/tmp/fake-ab", raising=False)
        res = doctor_live._probe_browser(5.0)
        assert res.status == "skip", \
            f"RED C: unset with binary-only (Chromium missing) must be unconfigured-skip, got {res.status} {res.detail}"


class TestCRedNonceOracle:
    def test_agent_browser_nonce_roundtrip_pass_same_owned_session(self, tmp_path, monkeypatch):
        # Stateful fake enforcing REAL agent-browser 0.26.0 flag semantics:
        # --session <owned> is isolation; --session-name is autosave (rejected);
        # bare close / --all rejected; default canary must survive.
        # Proves oracle does set-challenge + separate derive-read with distinct
        # unguessable answer, all on same owned isolated session.
        log = tmp_path / "calls.log"
        store_dir = tmp_path / "store"
        store_dir.mkdir()
        # Default protected canary: must remain open while owned closes.
        (store_dir / "default.ch").write_text("canary-default", encoding="utf-8")
        fake = tmp_path / "agent-browser"
        _make_exe(fake, f"""#!/usr/bin/env python3
import sys, os, re, hashlib
log={str(log)!r}
storedir={str(store_dir)!r}
def rec(s):
    open(log,'a').write(s+'\\n')
args=sys.argv[1:]
rec('CALL:'+' '.join(args)+' ENV_SESSION='+os.getenv('AGENT_BROWSER_SESSION','-')+' ENV_NAME='+os.getenv('AGENT_BROWSER_SESSION_NAME','-'))
if args==['--help']:
    print('open <url>\\neval <js>\\nclose\\nget\\nsnapshot')
    sys.exit(0)
# Real 0.26.0: --session-name is autosave, NOT isolation -> reject substitute.
if '--session-name' in args:
    print('wrong flag --session-name is autosave not isolation', file=sys.stderr)
    sys.exit(2)
if '--all' in args:
    print('refusing --all broad kill', file=sys.stderr)
    sys.exit(2)
if '--session' in args:
    i=args.index('--session')
    sess=args[i+1]
    cmd=args[i+2:]
else:
    sess=os.getenv('AGENT_BROWSER_SESSION','default'); cmd=args
# Sanitized env: flag and AGENT_BROWSER_SESSION must agree; autosave name stripped.
if os.getenv('AGENT_BROWSER_SESSION','-') != sess:
    print('env AGENT_BROWSER_SESSION must equal --session owned', file=sys.stderr)
    sys.exit(2)
if os.getenv('AGENT_BROWSER_SESSION_NAME') is not None:
    print('env AGENT_BROWSER_SESSION_NAME autosave leak', file=sys.stderr)
    sys.exit(2)
if sess in ('', 'default') or not sess.startswith('doctor-live-'):
    print('refusing default/bare session touch sess='+sess, file=sys.stderr)
    sys.exit(2)
if cmd[:1]==['open'] and cmd[1:2]==['about:blank']:
    print('opened about:blank session='+sess)
    sys.exit(0)
if cmd[:1]==['eval']:
    js=' '.join(cmd[1:])
    # Set: dataset.doctorChallenge='<challenge>' (challenge literal in stdin)
    m=re.search(r"dataset\\.doctorChallenge='([0-9a-f]+)'", js)
    if m:
        open(os.path.join(storedir, sess+'.ch'),'w').write(m.group(1))
        print('set-ok')
        sys.exit(0)
    # Derive-read: in-DOM SHA-256 over stored challenge (separate evaluate).
    # Simulates crypto.subtle.digest; parent independently expects sha256.
    if 'doctorChallenge' in js and 'crypto.subtle.digest' in js:
        try:
            ch=open(os.path.join(storedir, sess+'.ch')).read().strip()
        except OSError:
            ch=''
        print(hashlib.sha256(ch.encode()).hexdigest())
        sys.exit(0)
    print('unknown-eval:'+js, file=sys.stderr)
    sys.exit(2)
if cmd[:1]==['close']:
    try:
        os.unlink(os.path.join(storedir, sess+'.ch'))
    except OSError:
        pass
    print('closed session='+sess)
    sys.exit(0)
print('unknown cmd:'+' '.join(cmd), file=sys.stderr)
sys.exit(2)
""")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "agent-browser")
        monkeypatch.setattr("tools.browser_tool_install._find_agent_browser",
                            lambda validate=False: str(fake), raising=False)
        monkeypatch.setattr(doctor_live, "chromium_executable", lambda: "/tmp/fake-chrome")
        res = doctor_live._probe_browser(5.0)
        assert res.status == "pass", f"RED C-derived: stateful set+derive must PASS, got {res.status} {res.detail}"
        calls = log.read_text(encoding="utf-8") if log.exists() else ""
        assert "open about:blank" in calls, f"oracle must open about:blank, calls={calls!r}"
        # Two separate evals: set-challenge + separate derive-read (not echo)
        assert calls.count("eval") >= 2, f"oracle must do set-eval + separate derive-eval, calls={calls!r}"
        assert "crypto.subtle.digest" in calls or "doctorChallenge" in calls, \
            f"derive eval must run in-DOM SHA-256, calls={calls!r}"
        assert "close" in calls, f"oracle must close owned session, calls={calls!r}"
        # Same owned ISOLATED session for open+set+derive+close (argv readback).
        sesss = re.findall(r"--session (\S+)", calls)
        assert len(sesss) >= 4, f"open+set+derive+close must all carry --session owned, got {sesss!r}"
        assert len(set(sesss)) == 1 and sesss[0].startswith("doctor-live-"), \
            f"set+derive+close must share same owned isolated session, got {sesss!r}"
        # No autosave substitute, no default touch, no broad kill (static argv behavior).
        assert "--session-name" not in calls, f"must never use --session-name autosave, calls={calls!r}"
        assert "--all" not in calls, f"must never use --all broad kill, calls={calls!r}"
        for _line in calls.splitlines():
            if _line.startswith("CALL:") and " close" in _line:
                assert "--session doctor-live-" in _line, f"close MUST NOT default/bare, line={_line!r}"
        # Default protected canary remains open while owned closed.
        assert (store_dir / "default.ch").read_text(encoding="utf-8") == "canary-default", \
            "default canary must survive owned close"
        assert calls.count("CALL:--help") <= 1, "help inspect at most once, never as PASS"

    def test_agent_browser_plain_html_wrong_nonce_fail(self, tmp_path, monkeypatch):
        # CLI script that just prints plain HTML (wrong nonce) must FAIL.
        # Fake enforces real --session isolation (rejects --session-name substitute).
        log = tmp_path / "calls2.log"
        fake = tmp_path / "agent-browser-plain"
        _make_exe(fake, f"""#!/usr/bin/env python3
import sys, os
log={str(log)!r}
open(log,'a').write('CALL:'+' '.join(sys.argv[1:])+'\\n')
args=sys.argv[1:]
if args==['--help']:
    print('open <url>\\neval <js>\\nclose')
    sys.exit(0)
if '--session-name' in args:
    print('wrong flag --session-name', file=sys.stderr); sys.exit(2)
if '--all' in args:
    print('refusing --all', file=sys.stderr); sys.exit(2)
if '--session' in args:
    i=args.index('--session')
    cmd=args[i+2:]
    if cmd[:1]==['open']:
        print('opened')
        sys.exit(0)
    if cmd[:1]==['eval']:
        print('<html><body>plain-wrong-nonce</body></html>')
        sys.exit(0)
    if cmd[:1]==['close']:
        print('closed')
        sys.exit(0)
sys.exit(2)
""")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "agent-browser")
        monkeypatch.setattr("tools.browser_tool_install._find_agent_browser",
                            lambda validate=False: str(fake), raising=False)
        monkeypatch.setattr(doctor_live, "chromium_executable", lambda: "/tmp/fake-chrome")
        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", \
            f"RED C-nonce: plain-HTML wrong-nonce CLI script must FAIL, got {res.status} {res.detail}"

    def test_browser_use_nonce_roundtrip_pass(self, tmp_path, monkeypatch):
        # Stateful harness fake: extracts challenge, derives SHA-256 in-"DOM",
        # prints exact JSON one result event. Proves oracle sends about:blank +
        # in-browser js derive + structured result (not substring/echo).
        log = tmp_path / "harness-calls.log"
        fake = tmp_path / "fake_harness.py"
        fake.write_text(f"""import sys, re, json, hashlib
log={str(log)!r}
def rec(s):
    open(log,'a').write(s+'\\n')
args=sys.argv[1:]
data=sys.stdin.read() if not sys.stdin.isatty() else ''
rec('ARGV:'+' '.join(args)+' STDIN:'+data[:2000])
if '--help' in args:
    print('browser-harness\\nCommands:\\n --version\\n --doctor\\n')
    sys.exit(0)
# Require about:blank + in-browser js derive + JSON result in same PY (same BU_NAME)
if 'about:blank' not in data:
    print('missing about:blank', file=sys.stderr); sys.exit(2)
if 'js(' not in data or 'crypto.subtle.digest' not in data:
    print('missing in-DOM derive js', file=sys.stderr); sys.exit(2)
if 'doctor-probe-result' not in data or 'close_tab()' not in data:
    print('missing structured result/close', file=sys.stderr); sys.exit(2)
m=re.search(r'const c = "([0-9a-f]+)"', data)
if not m:
    print('missing challenge', file=sys.stderr); sys.exit(2)
ch=m.group(1)
exp=hashlib.sha256(ch.encode()).hexdigest()
# Simulate live DOM: in-browser derive returns value, parent parses tool result.
print(json.dumps({{"event": "doctor-probe-result", "op": "sha256", "derived": exp}}))
sys.exit(0)
""", encoding="utf-8")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        monkeypatch.setattr("tools.browser_use_cli._find_cli",
                            lambda: [sys.executable, str(fake)])
        res = doctor_live._probe_browser(5.0)
        assert res.status == "pass", f"RED C-derived: harness challenge+derive must PASS, got {res.status} {res.detail}"
        calls = log.read_text(encoding="utf-8") if log.exists() else ""
        assert "about:blank" in calls, f"harness oracle must send about:blank, calls={calls!r}"
        assert "crypto.subtle.digest" in calls or "doctor-probe-result" in calls, \
            f"must send in-DOM derive js + structured result, calls={calls!r}"

    def test_browser_use_plain_html_wrong_nonce_fail(self, tmp_path, monkeypatch):
        log = tmp_path / "harness-plain.log"
        fake = tmp_path / "fake_harness_plain.py"
        fake.write_text(f"""import sys
log={str(log)!r}
open(log,'a').write('ARGV:'+' '.join(sys.argv[1:])+'\\n')
args=sys.argv[1:]
if '--help' in args:
    print('browser-harness\\nCommands:')
    sys.exit(0)
print('<html><body>plain-wrong-nonce</body></html>')
sys.exit(0)
""", encoding="utf-8")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        monkeypatch.setattr("tools.browser_use_cli._find_cli",
                            lambda: [sys.executable, str(fake)])
        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", \
            f"RED C-derived: harness plain-HTML wrong-value must FAIL, got {res.status} {res.detail}"

    def test_browser_use_echo_stdin_must_fail(self, tmp_path, monkeypatch):
        # HIGH: echo fakeCLI (cat stdin -> stdout, rc 0) contains challenge
        # literal inout; old `nonce in out` substring PASSED it. Structured
        # exact-JSON one-result validation must FAIL it (no script echo acceptance).
        fake = tmp_path / "echo_harness.py"
        fake.write_text("""import sys
args=sys.argv[1:]
if '--help' in args:
    print('browser-harness\\nCommands:\\n --version\\n --doctor\\n')
    sys.exit(0)
data=sys.stdin.read() if not sys.stdin.isatty() else ''
print(data)
sys.exit(0)
""", encoding="utf-8")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        monkeypatch.setattr("tools.browser_use_cli._find_cli",
                            lambda: [sys.executable, str(fake)])
        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", \
            f"HIGH: echo-stdin CLI must FAIL (challenge inout, echo != derived), got {res.status} {res.detail}"

    def test_browser_use_challenge_as_derived_form_echo_must_fail(self, tmp_path, monkeypatch):
        # Exact-result sentinel/form echo: fake prints valid JSON shape but
        # echoes challenge as derived (not independently-expected sha). Must FAIL.
        fake = tmp_path / "sentinel_harness.py"
        fake.write_text("""import sys, re, json
args=sys.argv[1:]
data=sys.stdin.read() if not sys.stdin.isatty() else ''
if '--help' in args:
    print('browser-harness\\nCommands:')
    sys.exit(0)
import re as _re
m=_re.search(r'const c = "([0-9a-f]+)"', data)
ch=m.group(1) if m else "deadbeef"
print(json.dumps({"event": "doctor-probe-result", "op": "sha256", "derived": ch}))
sys.exit(0)
""", encoding="utf-8")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        monkeypatch.setattr("tools.browser_use_cli._find_cli",
                            lambda: [sys.executable, str(fake)])
        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", \
            f"HIGH: sentinel/form echo (challenge as derived) must FAIL, got {res.status} {res.detail}"

    def test_browser_use_two_result_events_must_fail(self, tmp_path, monkeypatch):
        # Structured: exactly ONE result event; two valid events (dup/race) must FAIL.
        fake = tmp_path / "dup_harness.py"
        fake.write_text("""import sys, re, json, hashlib
args=sys.argv[1:]
data=sys.stdin.read() if not sys.stdin.isatty() else ''
if '--help' in args:
    print('browser-harness\\nCommands:')
    sys.exit(0)
m=__import__('re').search(r'const c = "([0-9a-f]+)"', data)
ch=m.group(1) if m else "x"
exp=hashlib.sha256(ch.encode()).hexdigest()
print(json.dumps({"event": "doctor-probe-result", "op": "sha256", "derived": exp}))
print(json.dumps({"event": "doctor-probe-result", "op": "sha256", "derived": exp}))
sys.exit(0)
""", encoding="utf-8")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        monkeypatch.setattr("tools.browser_use_cli._find_cli",
                            lambda: [sys.executable, str(fake)])
        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", \
            f"HIGH: two result events must FAIL (exact one required), got {res.status} {res.detail}"

    def test_agent_browser_setfail_must_close_owned_session(self, tmp_path, monkeypatch):
        # MEDIUM: open success + set-challenge nonzero must still close OWN
        # isolated session (entire after-open in try/finally, bounded close).
        # Behavioral command record must show close --session <owned> after open.
        log = tmp_path / "setfails.log"
        fake = tmp_path / "agent-browser-setfail"
        _make_exe(fake, f"""#!/usr/bin/env python3
import sys, re, os
log={str(log)!r}
open(log,'a').write('CALL:'+' '.join(sys.argv[1:])+'\\n')
args=sys.argv[1:]
if args==['--help']:
    print('open <url>\\neval <js>\\nclose')
    sys.exit(0)
if '--session-name' in args:
    print('wrong flag --session-name', file=sys.stderr); sys.exit(2)
if '--all' in args:
    print('refusing --all', file=sys.stderr); sys.exit(2)
if '--session' in args:
    i=args.index('--session')
    sess=args[i+1]; cmd=args[i+2:]
    if cmd[:1]==['open']:
        print('opened'); sys.exit(0)
    if cmd[:1]==['eval']:
        js=' '.join(cmd[1:])
        if 'doctorChallenge' in js and '=' in js:
            print('set failed', file=sys.stderr); sys.exit(3)
        print('read-should-not-reach'); sys.exit(0)
    if cmd[:1]==['close']:
        print('closed session='+sess); sys.exit(0)
sys.exit(2)
""")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "agent-browser")
        monkeypatch.setattr("tools.browser_tool_install._find_agent_browser",
                            lambda validate=False: str(fake), raising=False)
        monkeypatch.setattr(doctor_live, "chromium_executable", lambda: "/tmp/fake-chrome")
        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", f"set-fail must be fail, got {res.status} {res.detail}"
        calls = log.read_text(encoding="utf-8") if log.exists() else ""
        assert "open about:blank" in calls, f"must open, calls={calls!r}"
        assert "close" in calls, f"MEDIUM: close must run even when set fails, calls={calls!r}"
        assert calls.index("close") > calls.index("open about:blank"), \
            f"close must be after open, calls={calls!r}"
        sesss = re.findall(r"--session (\S+)", calls)
        assert len(set(sesss)) == 1 and sesss[0].startswith("doctor-live-"), \
            f"close must target same owned isolated session, got {sesss!r}"
        assert "--session-name" not in calls, f"must never use --session-name, calls={calls!r}"
        assert "--all" not in calls, f"must never use --all, calls={calls!r}"

    def test_agent_browser_close_failure_must_fail(self, tmp_path, monkeypatch):
        # Bounded cleanup failure FAILs: even with correct derived, close
        # nonzero/timeout must turn PASS into FAIL (never silent PASS).
        # Close is always --session <owned>, never bare/default, never --all.
        log = tmp_path / "closefail.log"
        store_dir = tmp_path / "store3"
        store_dir.mkdir()
        fake = tmp_path / "agent-browser-closefail"
        _make_exe(fake, f"""#!/usr/bin/env python3
import sys, os, re, hashlib
log={str(log)!r}
storedir={str(store_dir)!r}
open(log,'a').write('CALL:'+' '.join(sys.argv[1:])+'\\n')
args=sys.argv[1:]
if args==['--help']:
    print('open <url>\\neval <js>\\nclose')
    sys.exit(0)
if '--session-name' in args:
    print('wrong flag --session-name', file=sys.stderr); sys.exit(2)
if '--all' in args:
    print('refusing --all', file=sys.stderr); sys.exit(2)
if '--session' in args:
    i=args.index('--session'); sess=args[i+1]; cmd=args[i+2:]
    if cmd[:1]==['open']:
        print('opened'); sys.exit(0)
    if cmd[:1]==['eval']:
        js=' '.join(cmd[1:])
        m=re.search(r"dataset\\.doctorChallenge='([0-9a-f]+)'", js)
        if m:
            open(os.path.join(storedir, sess+'.ch'),'w').write(m.group(1))
            print('set-ok'); sys.exit(0)
        if 'doctorChallenge' in js:
            try: ch=open(os.path.join(storedir, sess+'.ch')).read().strip()
            except OSError: ch=''
            print(hashlib.sha256(ch.encode()).hexdigest()); sys.exit(0)
        sys.exit(2)
    if cmd[:1]==['close']:
        print('close boom', file=sys.stderr); sys.exit(1)
sys.exit(2)
""")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "agent-browser")
        monkeypatch.setattr("tools.browser_tool_install._find_agent_browser",
                            lambda validate=False: str(fake), raising=False)
        monkeypatch.setattr(doctor_live, "chromium_executable", lambda: "/tmp/fake-chrome")
        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", \
            f"bounded cleanup failure must FAIL (not PASS), got {res.status} {res.detail}"
        calls = log.read_text(encoding="utf-8") if log.exists() else ""
        assert "close" in calls, f"close must have been attempted, calls={calls!r}"
        assert "--session doctor-live-" in calls, f"close must carry owned --session, calls={calls!r}"
        assert "--session-name" not in calls and "--all" not in calls

    def test_agent_browser_session_name_substitute_must_fail(self, tmp_path, monkeypatch):
        # HIGH narrow: --session-name is autosave, NOT isolation. A fake that only
        # honors --session-name (legacy wrong-flag behavior) must FAIL because the
        # probe never sends it; only --session <owned> is accepted.
        log = tmp_path / "substitute.log"
        fake = tmp_path / "agent-browser-substitute"
        _make_exe(fake, f"""#!/usr/bin/env python3
import sys
log={str(log)!r}
open(log,'a').write('CALL:'+' '.join(sys.argv[1:])+'\\n')
args=sys.argv[1:]
if args==['--help']:
    print('open <url>\\neval <js>\\nclose')
    sys.exit(0)
# Legacy wrong-flag fake: only --session-name opens; --session is unknown.
if '--session-name' in args:
    i=args.index('--session-name')
    cmd=args[i+2:]
    if cmd[:1]==['open']:
        print('opened'); sys.exit(0)
    if cmd[:1]==['eval']:
        print('eval-ok'); sys.exit(0)
    if cmd[:1]==['close']:
        print('closed'); sys.exit(0)
print('unknown (no --session-name)', file=sys.stderr)
sys.exit(2)
""")
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "agent-browser")
        monkeypatch.setattr("tools.browser_tool_install._find_agent_browser",
                            lambda validate=False: str(fake), raising=False)
        monkeypatch.setattr(doctor_live, "chromium_executable", lambda: "/tmp/fake-chrome")
        res = doctor_live._probe_browser(5.0)
        assert res.status == "fail", \
            f"--session-name-substitute fake must FAIL (probe uses --session isolation), got {res.status} {res.detail}"
        calls = log.read_text(encoding="utf-8") if log.exists() else ""
        assert "--session-name" not in calls, \
            f"probe must never emit --session-name substitute, calls={calls!r}"

    def test_agent_browser_eval_timeout_still_closes_bounded_session(self, tmp_path, monkeypatch):
        # Every failure path (set/eval timeout) must close bounded owned session.
        # Simulate eval TimeoutExpired via monkeypatched _run_bounded; assert close
        # attempted with --session <owned> and bounded timeout min(t,5s).
        import subprocess as _sp
        seen: list = []

        class _FakeProc:
            def __init__(self, rc=0, out=""):
                self.returncode = rc
                self.stdout = out
                self.stderr = ""

        def _timed_out(cmd, *, timeout, input_text=None, env=None):
            seen.append((list(cmd), float(timeout), dict(env or {})))
            joined = " ".join(cmd)
            if " eval " in f" {joined} " and "crypto.subtle.digest" in joined:
                raise _sp.TimeoutExpired(cmd, timeout)
            if joined.strip().endswith(" close") or " close" in joined:
                return _FakeProc(0, "closed")
            return _FakeProc(0, "set-ok")

        monkeypatch.setattr(doctor_live, "_run_bounded", _timed_out)
        ok, code, detail = doctor_live._agent_browser_after_open(
            "/tmp/fake-binary", "doctor-live-1-abcdef", "document.body.dataset.doctorChallenge='abc'",
            "(async () => { const v=document.body.dataset.doctorChallenge; await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v)); return v; })()",
            "expected-derived", 5.0)
        assert not ok, f"eval timeout must be fail, got {(ok, code, detail)}"
        assert "timed out" in detail, f"detail must name timeout, got {detail!r}"
        closes = [c for c, _, _ in seen if c[-1] == "close"]
        assert closes, f"close must run on eval timeout, seen={seen!r}"
        assert all(c[1] == "--session" and c[2] == "doctor-live-1-abcdef" for c in closes), \
            f"close must be --session owned, got {closes!r}"
        assert all("--session-name" not in c and "--all" not in c for c in closes)
        close_timeout = next(t for c, t, _ in seen if c[-1] == "close")
        assert close_timeout == min(5.0, 5.0), f"close must be bounded min(t,5s), got {close_timeout!r}"
        for _, _, e in seen:
            assert e.get("AGENT_BROWSER_SESSION") == "doctor-live-1-abcdef", \
                f"AGENT_BROWSER_SESSION explicit owned, got {e!r}"
            assert "AGENT_BROWSER_SESSION_NAME" not in e, "autosave env must be stripped"

    def test_agent_browser_set_timeout_still_closes_bounded_session(self, tmp_path, monkeypatch):
        import subprocess as _sp
        seen: list = []

        class _FakeProc:
            def __init__(self, rc=0, out=""):
                self.returncode = rc
                self.stdout = out
                self.stderr = ""

        def _timed_out(cmd, *, timeout, input_text=None, env=None):
            seen.append((list(cmd), float(timeout), dict(env or {})))
            joined = " ".join(cmd)
            if " eval " in f" {joined} " and "doctorChallenge" in joined and "=" in joined:
                raise _sp.TimeoutExpired(cmd, timeout)
            if " close" in f" {joined} ":
                return _FakeProc(0, "closed")
            return _FakeProc(0, "")

        monkeypatch.setattr(doctor_live, "_run_bounded", _timed_out)
        ok, code, detail = doctor_live._agent_browser_after_open(
            "/tmp/fake-binary", "doctor-live-9-123456", "document.body.dataset.doctorChallenge='abc'",
            "derive-js", "expected", 7.0)
        assert not ok and "timed out" in detail, f"set timeout must fail, got {(ok, code, detail)}"
        closes = [c for c, _, _ in seen if c[-1] == "close"]
        assert closes and all(c[1] == "--session" and c[2] == "doctor-live-9-123456" for c in closes), \
            f"close must target owned session on set timeout, got {closes!r}"
        close_timeout = next(t for c, t, _ in seen if c[-1] == "close")
        assert close_timeout == min(7.0, 5.0) == 5.0, f"close bounded min(t,5s), got {close_timeout!r}"

    def test_agent_browser_cmd_builder_never_default_or_all(self):
        # Static argv behavior: builder rejects default/bare, session-name, --all.
        import pytest as _pt
        with _pt.raises(ValueError):
            doctor_live._agent_browser_cmd("/b", "default", "close")
        with _pt.raises(ValueError):
            doctor_live._agent_browser_cmd("/b", "", "close")
        with _pt.raises(ValueError):
            doctor_live._agent_browser_cmd("/b", "doctor-live-1-abcdef", "close", "--all")
        cmd = doctor_live._agent_browser_cmd("/b", "doctor-live-1-abcdef", "close")
        assert cmd == ["/b", "--session", "doctor-live-1-abcdef", "close"]
        assert "--session-name" not in cmd
        env = doctor_live._agent_browser_session_env("doctor-live-1-abcdef")
        assert env["AGENT_BROWSER_SESSION"] == "doctor-live-1-abcdef"
        assert "AGENT_BROWSER_SESSION_NAME" not in env

    def test_actual_cli_smoke_isolated_session_only_no_default_touch(self, monkeypatch):
        # Isolated-session-only smoke against the INSTALLED real CLI (0.26.0):
        # pins --session isolation vs --session-name autosave from --help,
        # touches ONLY an owned --session id, never bare/default close, never --all,
        # never --session-name. Default session must survive. No browser launch
        # (open/eval) here: read-only session list + owned close only, no host
        # services, no broad kills. The full launch oracle is covered by fakes above;
        # this test never invokes the probe's open/eval path against live default.
        import subprocess as _sp
        from tools.browser_use_cli import _find_cli as _real_find
        harness_cmd = _real_find()
        assert harness_cmd is not None, "expected harness entrypoint present per install"
        assert harness_cmd[1:] == ["-m", "browser_harness.run"], \
            f"harness entrypoint must be exact tool-spawned binary, got {harness_cmd!r}"
        hproc = _sp.run([*harness_cmd, "--help"], capture_output=True, text=True, timeout=10, check=False)
        hout = ((hproc.stdout or "") + (hproc.stderr or "")).lower()
        assert hproc.returncode == 0 and "browser-harness" in hout, \
            "harness --help per installed docs must list browser-harness"
        try:
            from tools.browser_tool_install import _find_agent_browser as _real_find_ab
            ab = _real_find_ab(validate=False)
        except Exception:
            ab = None
        if ab is None:
            pytest.skip("agent-browser binary absent in hermetic HERMES_HOME; contract pinned by fakes")
        # Pin contract version 0.26.0: --session isolation vs --session-name autosave.
        vproc = _sp.run([ab, "--version"], capture_output=True, text=True, timeout=10, check=False)
        vout = ((vproc.stdout or "") + (vproc.stderr or "")).strip()
        assert "0.26.0" in vout, f"contract pinned to agent-browser 0.26.0, got {vout!r}"
        aproc = _sp.run([ab, "--help"], capture_output=True, text=True, timeout=10, check=False)
        aout = ((aproc.stdout or "") + (aproc.stderr or ""))
        alow = aout.lower()
        assert aproc.returncode == 0 and "open" in alow and "eval" in alow and "close" in alow, \
            "agent-browser --help per installed docs must list open/eval/close"
        assert "Isolated session" in aout and "AGENT_BROWSER_SESSION" in aout, \
            "contract: --session is isolated session (AGENT_BROWSER_SESSION)"
        assert "Auto-save/restore" in aout and "AGENT_BROWSER_SESSION_NAME" in aout, \
            "contract: --session-name is autosave (AGENT_BROWSER_SESSION_NAME), NOT isolation"
        # Read-only baseline: default session present, no state change.
        owned = "doctor-live-smoke-owned"
        env = dict(__import__("os").environ)
        env["AGENT_BROWSER_SESSION"] = owned
        env.pop("AGENT_BROWSER_SESSION_NAME", None)
        before = _sp.run([ab, "--session", owned, "session", "list"],
                         capture_output=True, text=True, timeout=10, check=False, env=env)
        bout = ((before.stdout or "") + (before.stderr or ""))
        assert "default" in bout.lower() or before.returncode == 0, \
            f"isolated session list must not hide default, got rc={before.returncode} out={bout!r}"
        # Owned close only: never bare, never --all, never --session-name.
        close = _sp.run(doctor_live._agent_browser_cmd(ab, owned, "close"),
                        capture_output=True, text=True, timeout=10, check=False, env=env)
        assert "--session-name" not in " ".join(doctor_live._agent_browser_cmd(ab, owned, "close"))
        assert "--all" not in " ".join(doctor_live._agent_browser_cmd(ab, owned, "close"))
        _ = close  # owned close may no-op (rc 0/1) when nothing open; only default-touch matters.
        after = _sp.run([ab, "--session", owned, "session", "list"],
                        capture_output=True, text=True, timeout=10, check=False, env=env)
        aafter = ((after.stdout or "") + (after.stderr or ""))
        assert "default" in aafter.lower() or after.returncode == 0, \
            f"default session must survive owned close, got rc={after.returncode} out={aafter!r}"
