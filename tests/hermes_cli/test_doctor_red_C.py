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
        # Stateful fake: stores challenge per owned session, derives SHA-256
        # in-"DOM" (Python hashlib simulating crypto.subtle) via SEPARATE eval
        # exact match on independently-expected derived. Proves oracle does
        # set-challenge + separate derive-read with distinct unguessable answer.
        log = tmp_path / "calls.log"
        store_dir = tmp_path / "store"
        store_dir.mkdir()
        fake = tmp_path / "agent-browser"
        _make_exe(fake, f"""#!/usr/bin/env python3
import sys, os, re, hashlib
log={str(log)!r}
storedir={str(store_dir)!r}
def rec(s):
    open(log,'a').write(s+'\\n')
args=sys.argv[1:]
rec('CALL:'+' '.join(args))
if args==['--help']:
    print('open <url>\\neval <js>\\nclose\\nget\\nsnapshot')
    sys.exit(0)
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
        # Same owned session for set+derive+close (extract session names)
        sesss = re.findall(r"--session-name (\S+)", calls)
        assert len(set(sesss)) == 1 and sesss[0].startswith("doctor-live-"), \
            f"set+derive+close must share same owned session, got {sesss!r}"
        assert calls.count("CALL:--help") <= 1, "help inspect at most once, never as PASS"

    def test_agent_browser_plain_html_wrong_nonce_fail(self, tmp_path, monkeypatch):
        # CLI script that just prints plain HTML (wrong nonce) must FAIL.
        log = tmp_path / "calls2.log"
        fake = tmp_path / "agent-browser-plain"
        _make_exe(fake, f"""#!/usr/bin/env python3
import sys
log={str(log)!r}
open(log,'a').write('CALL:'+' '.join(sys.argv[1:])+'\\n')
args=sys.argv[1:]
if args==['--help']:
    print('open <url>\\neval <js>\\nclose')
    sys.exit(0)
if '--session-name' in args:
    i=args.index('--session-name')
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
        # MEDIUM: open success + set-challenge nonzero must still close own
        # session (entire after-open in try/finally). Old code returned before
        # finally (no close). Behavioral command record must show close after open.
        log = tmp_path / "setfails.log"
        fake = tmp_path / "agent-browser-setfail"
        _make_exe(fake, f"""#!/usr/bin/env python3
import sys, re
log={str(log)!r}
open(log,'a').write('CALL:'+' '.join(sys.argv[1:])+'\\n')
args=sys.argv[1:]
if args==['--help']:
    print('open <url>\\neval <js>\\nclose')
    sys.exit(0)
if '--session-name' in args:
    i=args.index('--session-name')
    cmd=args[i+2:]
    if cmd[:1]==['open']:
        print('opened'); sys.exit(0)
    if cmd[:1]==['eval']:
        js=' '.join(cmd[1:])
        if 'doctorChallenge' in js and '=' in js:
            print('set failed', file=sys.stderr); sys.exit(3)
        print('read-should-not-reach'); sys.exit(0)
    if cmd[:1]==['close']:
        print('closed'); sys.exit(0)
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
        sesss = re.findall(r"--session-name (\S+)", calls)
        assert len(set(sesss)) == 1 and sesss[0].startswith("doctor-live-"), \
            f"close must target same owned session, got {sesss!r}"

    def test_agent_browser_close_failure_must_fail(self, tmp_path, monkeypatch):
        # Bounded cleanup failure FAILs: even with correct derived, close
        # nonzero/timeout must turn PASS into FAIL (never silent PASS).
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
    i=args.index('--session-name'); sess=args[i+1]; cmd=args[i+2:]
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

    def test_actual_configured_backends_fail_honestly_no_fallback(self, monkeypatch):
        # Actual available-backend operations verified per installed docs.
        # Hermetic HERMES_HOME hides PM tools, so agent-browser/Chromium may be
        # absent here while present on the live host (0.26.0 snap-confine fail);
        # harness (pip module) is present in both. In all cases the real launch
        # must FAIL honestly, never fallback or echo-pass.
        import subprocess as _sp
        from tools.browser_use_cli import _find_cli as _real_find
        harness_cmd = _real_find()
        assert harness_cmd is not None, "expected harness entrypoint present per install"
        # Documented entrypoint: [python, -m, browser_harness.run]
        assert harness_cmd[1:] == ["-m", "browser_harness.run"], \
            f"harness entrypoint must be exact tool-spawned binary, got {harness_cmd!r}"
        hproc = _sp.run([*harness_cmd, "--help"], capture_output=True, text=True, timeout=10, check=False)
        hout = ((hproc.stdout or "") + (hproc.stderr or "")).lower()
        assert hproc.returncode == 0 and "browser-harness" in hout, \
            "harness --help per installed docs must list browser-harness"
        # Agent-browser/Chromium per installed docs when present in this env.
        try:
            from tools.browser_tool_install import _find_agent_browser as _real_find_ab
            ab = _real_find_ab(validate=False)
        except Exception:
            ab = None
        if ab:
            aproc = _sp.run([ab, "--help"], capture_output=True, text=True, timeout=10, check=False)
            aout = ((aproc.stdout or "") + (aproc.stderr or "")).lower()
            assert aproc.returncode == 0 and "open" in aout and "eval" in aout and "close" in aout, \
                "agent-browser --help per installed docs must list open/eval/close"
        # Real launches (no faked launch): unset selects harness (runnable).
        # Must FAIL honestly (daemon/chrome-not-running), not PASS by echo.
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "")
        res_unset = doctor_live._probe_browser(8.0)
        assert res_unset.status == "fail", \
            f"real unset harness run must FAIL honestly (chrome-not-running/daemon), got {res_unset.status} {res_unset.detail}"
        # Explicit harness must FAIL, never fallback to agent-browser pass.
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "browser-use")
        res_h = doctor_live._probe_browser(8.0)
        assert res_h.status == "fail", \
            f"real harness run must FAIL honestly, got {res_h.status} {res_h.detail}"
        # Explicit agent-browser must FAIL (missing binary hermetic, snap-confine live), never PASS.
        monkeypatch.setattr(doctor_live, "_configured_backend_key", lambda: "agent-browser")
        res_a = doctor_live._probe_browser(8.0)
        assert res_a.status == "fail", \
            f"real agent-browser run must FAIL honestly, got {res_a.status} {res_a.detail}"
