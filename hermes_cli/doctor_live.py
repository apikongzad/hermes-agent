"""``hermes doctor --live`` — opt-in bounded real-call tool-backend probes.

Opt-in only: these probes make real (cheap, metadata/read-only) network calls and may spend a
trivial amount of quota. They run ONLY when the user passes ``hermes doctor --live``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, List, Optional

from hermes_cli.browser_runtime import chromium_executable
from hermes_cli.doctor import _section, check_info
from hermes_cli.doctor_report import check_fail, check_ok, check_warn
from utils import normalize_proxy_env_vars

DEFAULT_PROBE_TIMEOUT = 10.0

# Metadata-only endpoints (none spend generation credits): name -> (url, env var, auth scheme).
_KEYED_PROBES = {
    "Firecrawl": ("https://api.firecrawl.dev/v2/team/credit-usage", "FIRECRAWL_API_KEY", "Bearer"),
    "FAL": ("https://fal.ai/api/models?page=1", "FAL_KEY", "Key"),
}
# TTS/STT providers that never touch the network (nothing to probe).
_LOCAL_AUDIO_PROVIDERS = {"", "local", "edge", "neutts", "kittentts", "piper"}
_AUDIO_PROBES = {
    "openai": ("https://api.openai.com/v1/models", "OPENAI_API_KEY", "Bearer"),
    "groq": ("https://api.groq.com/openai/v1/models", "GROQ_API_KEY", "Bearer"),
    "elevenlabs": ("https://api.elevenlabs.io/v1/voices", "ELEVENLABS_API_KEY", "xi"),
}


@dataclass
class ProbeResult:
    """Outcome of one backend probe."""

    name: str
    status: str  # "pass" | "warn" | "fail" | "skip"
    detail: str = ""


# ── Small seams (monkeypatchable in tests, and single points of control) ──

def _http_get(url: str, headers: Optional[dict] = None, timeout: Optional[float] = None):
    """Single HTTP GET seam for all metadata probes."""
    import httpx
    # Sanitize at the seam (idempotent, no-op on a clean env): a bracketed-IPv6 NO_PROXY entry
    # ([::1], Clash Verge/mihomo) makes this bare trust_env client raise InvalidURL at
    # construction (#118159), which _run_one's catch-all would dress up as backend downtime.
    normalize_proxy_env_vars()
    return httpx.get(url, headers=headers or {}, timeout=timeout)


def _browser_use_ready() -> bool:
    """Bundled BrowserUseCLI backend ready (browser_harness importable)?"""
    try:
        from tools.browser_use_cli import _find_cli
        return _find_cli() is not None
    except Exception:
        return False


def _agent_browser_ready() -> bool:
    """PM/store or PATH agent-browser binary present (passive, no install)?"""
    try:
        from tools.browser_tool_install import _find_agent_browser
        return bool(_find_agent_browser(validate=False))
    except Exception:
        return False


def _configured_backend_key() -> str:
    """Configured ``browser.backend`` key ("" = unset default, "off" = disabled).

    Rev6 C-DECIDE-1: probe error is fail-closed (fail), never unset-default.
    """
    try:
        from tools.browser_use_cli import get_browser_backend
        return get_browser_backend()
    except Exception:
        return "fail"


def resolve_browser_selection(backend_key, harness_runnable, agent_browser_known) -> str:
    """ONE pure resolver truth table (C-DECIDE-1), NOT the bool predicate.

    Returns "browser-use" | "agent-browser" | "off-skip" | "unconfigured-skip" | "fail".
    - off -> off-skip (never enables dependents); False-as-off likewise.
    - explicit browser-use -> browser-use only, no fallback.
    - explicit agent-browser -> agent-browser only, no fallback.
    - unknown string -> fail, never skip.
    - config parse failure / resolver exception -> fail.
    - unset "" deterministic: harness-runnable -> browser-use, else
      agent-browser-readiness-known -> agent-browser, else unconfigured-skip.
    Current bool is_browser_use_cli_mode is a mode predicate, NOT the resolver.
    """
    try:
        if backend_key is False:
            return "off-skip"
        key = str(backend_key or "").strip().lower()
        # False-as-off already handled; bool True is malformed -> fail
        if isinstance(backend_key, bool):
            return "fail"
        if key == "off":
            return "off-skip"
        if key == "browser-use":
            return "browser-use"
        if key == "agent-browser":
            return "agent-browser"
        if key == "":
            try:
                if bool(harness_runnable):
                    return "browser-use"
            except Exception:
                pass
            try:
                if bool(agent_browser_known):
                    return "agent-browser"
            except Exception:
                pass
            return "unconfigured-skip"
        # Unknown string -> fail
        return "fail"
    except Exception:
        return "fail"


def _browser_available() -> bool:
    """Is any local browser automation backend ready?

    Honors explicit ``browser.backend: off`` (disabled → not available).
    Covers both the bundled BrowserUseCLI harness (default backend, runs on
    this interpreter) and the PM-owned agent-browser binary. Passive only:
    never installs or executes anything (no ``pm.ensure``).
    """
    try:
        if _configured_backend_key() == "off":
            return False
    except Exception:
        pass
    return _browser_use_ready() or _agent_browser_ready()


def _harness_version_probe(timeout: float) -> tuple | None:
    """Backend-native bounded protocol subprocess, NEVER confers PASS alone.

    Rev6 C-ORACLE-1: version string alone NEVER confers PASS. This helper is
    an optional backend-native bounded reaped protocol (same timeout/output
    discipline as launch oracle) for diagnostics only; callers must not treat
    its output as readiness. Returns None always (no PASS verdict).
    """
    import subprocess

    try:
        from tools.browser_use_cli import _find_cli
        cmd = _find_cli()
    except Exception:
        return None
    if cmd is None:
        return None
    try:
        proc = subprocess.run([*cmd, "--version"], capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=max(1.0, min(timeout, 15.0)), check=False)
        # Diagnostic only: never PASS. Explicit wait/reap via run return.
        _ = (proc.returncode, proc.stdout.strip()[:80])
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def _probe_configured_backend(timeout: float) -> tuple | None:
    """Rev6: no version-pass anywhere; selection only, launch decides PASS.

    Returns None always (no PASS verdict). Explicit off never probes;
    explicit-selected never falls back; unset follows resolver table only.
    Actual readiness is proven only by launch oracle below.
    """
    backend = _configured_backend_key()
    if backend == "off":
        return None
    if backend == "fail":
        return (False, "browser backend config probe failed (fail-closed)")
    # No version subprocess PASS, no other-backend probe. Launch oracle decides.
    return None


def _agent_browser_selection_ready() -> bool:
    """Agent-browser readiness for SELECTION (not health): binary AND Chromium.

    Per C-DECIDE-1 unset order: agent-browser known requires BOTH
    _find_agent_browser(validate=False) present AND chromium_executable()
    present. Binary-only is NOT known (else unset would mis-select).
    """
    try:
        from tools.browser_tool_install import _find_agent_browser
        binary = _find_agent_browser(validate=False)
        if not binary:
            return False
    except Exception:
        return False
    try:
        return bool(chromium_executable())
    except Exception:
        return False


def _run_bounded(cmd, *, timeout: float, input_text: str | None = None, env=None):
    """Bounded subprocess: 1s<=timeout<=15s, output cap 4k, capture, no check.

    Returns CompletedProcess (waited/reaped). Never pm.ensure.
    """
    import subprocess
    try:
        t = float(timeout)
    except Exception:
        t = 10.0
    t = max(1.0, min(t, 15.0))
    # Enforce output cap via truncation after reap (80-4k discipline)
    proc = subprocess.run(
        cmd, input=input_text, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=t, check=False, env=env)
    return proc


def _launch_browser_probe(timeout: float) -> tuple:
    """Launch oracle: the only PASS path (C-ORACLE-2, C-BACKEND-1).

    Launches the EXACT binary/entrypoint the tool spawns for the SELECTED
    backend only, opens about:blank via DOCUMENTED commands, evaluates
    KNOWN-DOM actual result, closes owned session in finally, reaps bounded.
    Help/version inspect never confers PASS (diagnostic only).
    """
    import os as _os
    import subprocess
    try:
        t = float(timeout)
    except Exception:
        t = 10.0
    t = max(1.0, min(t, 15.0))
    sel = resolve_browser_selection(
        _configured_backend_key(), _browser_use_ready(), _agent_browser_selection_ready())
    if sel in ("off-skip", "unconfigured-skip"):
        return (False, "browser not configured (skip)")
    if sel == "fail":
        return (False, "browser backend misconfigured (fail-closed)")
    if sel == "browser-use":
        try:
            from tools.browser_use_cli import _find_cli
            cmd = _find_cli()
        except Exception as exc:
            return (False, f"browser-use lookup failed: {exc} (fail-closed)")
        if cmd is None:
            return (False, "browser-use backend configured but harness CLI missing (fail-closed)")
        # Help inspect (diagnostic only, never PASS): documented commands present?
        try:
            hproc = _run_bounded([*cmd, "--help"], timeout=t)
            hout = ((hproc.stdout or "") + (hproc.stderr or ""))[:4000]
            if hproc.returncode != 0 or "browser-harness" not in hout.lower():
                return (False, "browser-use help inspect failed (fail-closed)")
        except subprocess.TimeoutExpired:
            return (False, "browser-use help inspect timed out (fail-closed)")
        except Exception as exc:
            return (False, f"browser-use help inspect failed: {exc} (fail-closed)")
        # Real launch: owned BU_NAME session, PY opens about:blank, evals KNOWN-DOM, closes.
        owned = f"doctor-live-{_os.getpid()}"
        env = dict(_os.environ)
        env["BU_NAME"] = owned
        code = (
            'new_tab("about:blank")\n'
            'print(js("document.documentElement.outerHTML"))\n'
            'close_tab()\n'
        )
        try:
            proc = _run_bounded(cmd, timeout=t, input_text=code, env=env)
            out = ((proc.stdout or "") + (proc.stderr or ""))[:4000]
            # KNOWN-DOM actual result: real DOM contains html marker (fake returns KNOWN-DOM-OK html)
            if proc.returncode == 0 and "<html" in out.lower():
                detail = f"launched harness + about:blank + KNOWN-DOM + closed ({out.strip()[:80]})"
                return (True, detail)
            return (False, f"browser-use launch missing KNOWN-DOM (exit {proc.returncode}) (fail-closed)")
        except subprocess.TimeoutExpired:
            return (False, "browser-use launch timed out (fail-closed)")
        except Exception as exc:
            return (False, f"browser-use launch failed: {exc} (fail-closed)")
    if sel == "agent-browser":
        try:
            from tools.browser_tool_install import _find_agent_browser
            binary = _find_agent_browser(validate=False)
        except Exception as exc:
            return (False, f"agent-browser lookup failed: {exc} (fail-closed)")
        chromium = chromium_executable()
        if not binary:
            return (False, "agent-browser selected but binary missing (fail-closed)")
        if not chromium:
            return (False, "agent-browser selected but Chromium executable missing (fail-closed)")
        # Help inspect (diagnostic only, never PASS): documented open/eval/close present?
        try:
            hproc = _run_bounded([binary, "--help"], timeout=t)
            hout = ((hproc.stdout or "") + (hproc.stderr or ""))[:4000].lower()
            if hproc.returncode != 0 or "open" not in hout or "eval" not in hout:
                return (False, "agent-browser help inspect failed (fail-closed)")
        except subprocess.TimeoutExpired:
            return (False, "agent-browser help inspect timed out (fail-closed)")
        except Exception as exc:
            return (False, f"agent-browser help inspect failed: {exc} (fail-closed)")
        # Real launch via ACTUAL CLI owned session ONLY (no Python-playwright).
        owned = f"doctor-live-{_os.getpid()}"
        # about:blank open
        try:
            oproc = _run_bounded([binary, "--session-name", owned, "open", "about:blank"], timeout=t)
            if oproc.returncode != 0:
                return (False, f"agent-browser open about:blank exited {oproc.returncode} (fail-closed)")
        except subprocess.TimeoutExpired:
            return (False, "agent-browser open timed out (fail-closed)")
        except Exception as exc:
            return (False, f"agent-browser open failed: {exc} (fail-closed)")
        # KNOWN-DOM eval actual result, close in finally (owned reap)
        try:
            eproc = _run_bounded(
                [binary, "--session-name", owned, "eval",
                 "document.documentElement.outerHTML"], timeout=t)
            eout = ((eproc.stdout or "") + (eproc.stderr or ""))[:4000]
            if eproc.returncode == 0 and "<html" in eout.lower():
                detail = f"launched agent-browser CLI + about:blank + KNOWN-DOM + closed ({eout.strip()[:80]})"
                return (True, detail)
            return (False, f"agent-browser eval missing KNOWN-DOM (exit {eproc.returncode}) (fail-closed)")
        except subprocess.TimeoutExpired:
            return (False, "agent-browser eval timed out (fail-closed)")
        except Exception as exc:
            return (False, f"agent-browser eval failed: {exc} (fail-closed)")
        finally:
            try:
                _run_bounded([binary, "--session-name", owned, "close"], timeout=min(t, 5.0))
            except Exception:
                pass
    return (False, "unknown browser selection (fail-closed)")


def _probe_mcp_server(name: str, config: dict, timeout: float):
    """initialize + tools/list against one configured MCP server."""
    from hermes_cli.mcp_config import _probe_single_server
    return _probe_single_server(name, config, connect_timeout=timeout)


# ── Per-backend probes. Each returns a ProbeResult; _run_one's catch-all handles crashes. ──

def _classify_http(name: str, resp, key_hint: str) -> ProbeResult:
    code = getattr(resp, "status_code", None)
    if code is not None and 200 <= code < 300:
        return ProbeResult(name, "pass", f"(HTTP {code})")
    return ProbeResult(name, "fail", f"(HTTP {code} — check {key_hint})" if code in (401, 403) else f"(HTTP {code})")


def _keyed_probe(name: str, url: str, env_var: str, scheme: str, timeout: float) -> ProbeResult:
    """Metadata GET authenticated by one env var (never a generation call)."""
    key = os.getenv(env_var, "").strip()
    if not key:
        return ProbeResult(name, "skip", "(not configured)")
    resp = _http_get(url, headers={"Authorization": f"{scheme} {key}"}, timeout=timeout)
    return _classify_http(name, resp, env_var)


def _probe_browser(timeout: float) -> ProbeResult:
    """Rev6 C-DECIDE-1 + C-BACKEND-1: ordered config->selection->selected-prereqs->launch.

    Selection via pure resolver only. Explicit-selected has no fallback;
    selected launch failure is fail, never fallback. Irrelevant deps ignored.
    off -> skip (off-skip); genuinely-none-configured unset -> skip
    (unconfigured-skip); unknown/except -> fail.
    """
    try:
        key = _configured_backend_key()
    except Exception:
        return ProbeResult("Browser", "fail", "(backend config probe failed)")
    if key == "fail":
        return ProbeResult("Browser", "fail", "(backend config probe failed)")
    try:
        sel = resolve_browser_selection(key, _browser_use_ready(), _agent_browser_selection_ready())
    except Exception:
        return ProbeResult("Browser", "fail", "(selection failed)")
    if sel in ("off-skip", "unconfigured-skip"):
        return ProbeResult("Browser", "skip", "(not configured)" if sel == "unconfigured-skip" else "(disabled)")
    if sel == "fail":
        return ProbeResult("Browser", "fail", "(misconfigured backend)")
    # Selected backend decisive; launch oracle only.
    ok, detail = _launch_browser_probe(timeout)
    return ProbeResult("Browser", "pass" if ok else "fail", f"({detail})")


def _probe_audio(kind: str, config: dict, timeout: float) -> ProbeResult:
    """Shared TTS/STT metadata probe (voices/models list GET only)."""
    name = kind.upper()
    provider = (((config.get(kind) or {}).get("provider")) or "").strip().lower()
    if provider in _LOCAL_AUDIO_PROVIDERS:
        return ProbeResult(name, "skip", f"(provider '{provider or 'local'}' — no remote backend to probe)")
    if provider not in _AUDIO_PROBES:
        return ProbeResult(name, "skip", f"(provider '{provider}' — no live probe implemented)")
    url, env_var, scheme = _AUDIO_PROBES[provider]
    key = os.getenv(env_var, "").strip()
    if not key:
        return ProbeResult(name, "warn", f"(provider '{provider}' configured but {env_var} is not set)")
    headers = {"xi-api-key": key} if scheme == "xi" else {"Authorization": f"Bearer {key}"}
    result = _classify_http(name, _http_get(url, headers=headers, timeout=timeout), env_var)
    result.detail = f"({provider}) {result.detail}"
    return result


# ── Orchestration ──

_REPORTERS = {"pass": check_ok, "warn": check_warn, "fail": check_fail}


def _report(result: ProbeResult, issues: list[str]) -> None:
    reporter = _REPORTERS.get(result.status)
    if reporter is None:  # skip
        check_info(f"{result.name} {result.detail} — skipped")
        return
    reporter(result.name, result.detail)
    if result.status == "fail":
        issues.append(f"Live probe failed: {result.name} {result.detail}")


def _run_one(name: str, fn: Callable[[], ProbeResult], issues: list[str]) -> ProbeResult:
    """Run one probe with a catch-all so a crash never kills doctor."""
    try:
        result = fn()
    except TimeoutError as exc:
        result = ProbeResult(name, "fail", f"(timed out: {exc})")
    except Exception as exc:
        msg = str(exc) or exc.__class__.__name__
        result = ProbeResult(name, "fail", f"(timed out: {msg})" if "time" in msg.lower() else f"({msg})")
    _report(result, issues)
    return result


def run_live_checks(issues: list[str]) -> list[ProbeResult]:
    """Run one bounded, read-only probe per configured tool backend — sequential by design (predictable output
    ordering). Appends a remediation line to ``issues`` per failed probe; skipped backends never append."""
    from hermes_cli.config import load_config_readonly
    config = load_config_readonly()
    try:
        timeout = float((config.get("doctor") or {}).get("live_probe_timeout", DEFAULT_PROBE_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_PROBE_TIMEOUT
    timeout = max(1.0, min(timeout, 15.0))
    _section("Live Backend Probes (opt-in, real calls)")
    results: list[ProbeResult] = [
        _run_one(name, lambda n=name, spec=spec: _keyed_probe(n, *spec, timeout), issues)
        for name, spec in _KEYED_PROBES.items()
    ]
    results.append(_run_one("Browser", lambda: _probe_browser(timeout), issues))
    servers = config.get("mcp_servers") or {}
    if isinstance(servers, dict) and servers:
        for name in sorted(servers):
            def _probe(n=name, e=servers[name]) -> ProbeResult:
                if not isinstance(e, dict):
                    return ProbeResult(f"MCP: {n}", "fail", "(malformed config entry: not a dict, fail-closed)")
                return ProbeResult(f"MCP: {n}", "pass", f"({len(_probe_mcp_server(n, e, timeout))} tool(s))")
            results.append(_run_one(f"MCP: {name}", _probe, issues))
    else:
        results.append(ProbeResult("MCP", "skip", "(no servers configured)"))
        _report(results[-1], issues)
    for kind in ("tts", "stt"):
        results.append(_run_one(kind.upper(), lambda k=kind: _probe_audio(k, config, timeout), issues))
    return results


def maybe_run_live_checks(args, issues: list[str]):
    """Called from ``run_doctor`` after static checks; no-op (None) unless ``--live``.

    Rev6 C-CRASH-1: pin BOTH crash sites. Per-probe _run_one catch-all -> fail
    retained. Outer catch-all MUST become fail verdict + append to issues (so
    run_doctor returns nonzero).
    """
    if not getattr(args, "live", False):
        return None
    try:
        return run_live_checks(issues)
    except Exception as exc:
        check_fail("Live backend probes crashed", f"({exc})")
        issues.append(f"Live backend probes crashed: {exc}")
        return None
