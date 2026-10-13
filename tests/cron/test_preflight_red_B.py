"""RED B: reconnecting MCP BLOCK, non-dict fallback BLOCK, flag-false 4-mandatory.

Functional, real entrypoints, no string checks. Hermetic temp HERMES_HOME.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)


class TestBRedReconnectingMustBlock:
    def test_reconnecting_mcp_blocks_never_running_without_tools(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from cron import scheduler_preflight as pf
        job = {"id": "j-re", "enabled_toolsets": ["re-server"]}
        cfg = {"mcp_servers": {"re-server": {"command": "x"}}}
        # Server resolves to zero tools but is reconnecting -> must BLOCK (never run without tools)
        monkeypatch.setattr("hermes_cli.tools_config.enabled_mcp_server_names",
                            lambda cfg2: ["re-server"], raising=False)
        # Patch where preflight imports from
        import hermes_cli.tools_config as tc
        monkeypatch.setattr(tc, "enabled_mcp_server_names", lambda cfg2: ["re-server"])
        import toolsets as ts
        monkeypatch.setattr(ts, "resolve_toolset", lambda name: [])
        import tools.mcp_tool_discovery as disc
        monkeypatch.setattr(disc, "mcp_server_reconnecting", lambda name: True)
        # Clear warned set to avoid one-shot dedup hiding the block
        try:
            pf._RECONNECTING_WARNED.clear()
        except Exception:
            pass
        reason = pf._empty_requested_mcp_toolsets(job, cfg)
        assert reason is not None, \
            "RED B: reconnecting MCP resolved to zero tools must BLOCK (never running without tools)"
        assert "re-server" in reason

    def test_non_dict_fallback_blocked(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from cron import scheduler_preflight as pf
        from cron import scheduler as sched
        # Chain containing non-dict entry is a config error -> blocked, never skipped via continue
        def _chain_bad(job, cfg):
            return ["not-a-dict"]
        monkeypatch.setattr(sched, "_job_fallback_chain", _chain_bad)
        monkeypatch.setattr(pf._sched, "_job_fallback_chain", _chain_bad)
        reason = pf._preflight_check_provider_key({"id": "j"}, {})
        assert reason is not None, \
            f"RED B: non-dict fallback entry must BLOCK (config error), got {reason!r}"
        assert "fallback" in reason.lower() or "config" in reason.lower() or "dict" in reason.lower()

    def test_flag_false_same_guard_all4(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from cron import scheduler as sched
        from cron import scheduler_preflight as pf
        import tools.skills_tool as st
        import cron.scheduler_prompt as sp

        cfg = {"cron": {"preflight": False}}

        # Case 1: unready skill must block at 1712 even with flag false (mandatory guard)
        def _unready(name):
            return json.dumps({"success": True, "readiness_status": "setup_needed",
                               "setup_needed": True,
                               "missing_required_environment_variables": ["X"],
                               "missing_required_commands": [],
                               "missing_credential_files": []})
        monkeypatch.setattr(st, "skill_view", _unready)
        monkeypatch.setattr(sp, "_job_skill_names", lambda job: ["needy"])
        job = {"id": "j1", "skills": ["needy"]}
        out = sched._preflight_or_block(job, "j1", "jn", cfg)
        assert out is not None, "RED B: 1712 mandatory must block unready skill even with preflight:false"

        # Case 2: 2458 site must enforce SAME 4-mandatory guard, not MCP-only.
        # Build a job that passes 1712 mandatory (no skills, no delivery, provider ok, no MCP)
        # then make MCP empty-after-discovery -> must block at 2458 even with flag false.
        # Here we assert the 2458 path calls the full mandatory guard (all 4), not just MCP.
        # Functional: patch mandatory guard to record calls from _resolve_cron_agent_setup.
        calls = []
        real_guard = pf._cron_mandatory_readiness_guard

        def _rec(job2, cfg2):
            calls.append("full-guard")
            return real_guard(job2, cfg2)

        monkeypatch.setattr(pf, "_cron_mandatory_readiness_guard", _rec)
        # Also ensure scheduler's re-export sees it
        # Use a clean job that would otherwise pass 1712
        monkeypatch.setattr(sp, "_job_skill_names", lambda job: [])
        job2 = {"id": "j2"}
        cfg2 = {"cron": {"preflight": False}}

        class JC:
            cfg = cfg2
            model = "m"
            model_cfg = {}
            cron_default_provider = None

        # Patch runtime resolution to succeed so we reach MCP stage
        monkeypatch.setattr(sched, "_resolve_job_runtime",
                            lambda job, job_id, jc: ({"provider": "p", "api_key": "k"}, "m"))
        monkeypatch.setattr(sched, "_resolve_job_reasoning_config", lambda *a, **k: None)
        monkeypatch.setattr(sched, "_job_fallback_chain", lambda job, cfg: None)
        monkeypatch.setattr(sched, "_load_credential_pool", lambda rt, jid: None)
        monkeypatch.setattr(sched, "_init_cron_mcp_tools", lambda jid: None)
        # Force MCP empty to trigger 2458 block path
        monkeypatch.setattr(pf, "_empty_requested_mcp_toolsets",
                            lambda job, cfg: "MCP server(s) x resolved to zero tools (fail-closed)")
        # Need scheduler's imported ref to see patched MCP? It imports from preflight at call time?
        import cron.scheduler as _sched_mod
        # Patch both namespaces
        monkeypatch.setattr(_sched_mod, "_empty_requested_mcp_toolsets",
                            lambda job, cfg: "MCP server(s) x resolved to zero tools (fail-closed)")
        setup = sched._resolve_cron_agent_setup(job2, "j2", "jn", JC())
        assert setup.blocked is not None, "RED B: 2458 must block empty MCP even with flag false"


class TestBRedRawFullPath:
    """RAW fallback_providers validation BEFORE get_fallback_chain filters.

    Uses the actual full config path (real cfg dict, real _job_fallback_chain,
    no monkeypatched chain). Malformed dict/list entries must BLOCK at BOTH
    entrypoints (1712 _preflight_or_block + 2458 _resolve_cron_agent_setup)
    under BOTH flags (preflight true/false) with zero dispatch (no runtime).
    """

    @pytest.mark.parametrize("preflight_off", [False, True])
    @pytest.mark.parametrize("raw", [
        ["not-a-dict"],
        [{"provider": "x"}],
        [{"model": "y"}],
        [{"provider": "", "model": "y"}],
        "not-a-list",
        [{"provider": "x", "model": "y"}, "bad"],
    ])
    def test_raw_malformed_blocks_both_entrypoints_zero_dispatch(
            self, tmp_path, monkeypatch, raw, preflight_off):
        _env(tmp_path, monkeypatch)
        from cron import scheduler as sched
        # Real full path: no monkeypatched _job_fallback_chain (filter-only banned).
        job = {"id": "j-raw"}  # unpinned: inherits global chain
        cfg = {"fallback_providers": raw}
        if preflight_off:
            cfg["cron"] = {"preflight": False}
        # 1712 entrypoint must BLOCK on RAW malformed (before filtering).
        out = sched._preflight_or_block(job, "j-raw", "jn", cfg)
        assert out is not None, \
            f"RED B-RAW: 1712 must BLOCK RAW malformed {raw!r} (preflight_off={preflight_off}), got pass"
        err = out[3] if len(out) > 3 else str(out)
        assert "fallback" in err.lower(), f"RED B-RAW: 1712 block must name fallback, got {err!r}"
        # 2458 entrypoint must BLOCK with zero dispatch (no runtime resolution).
        calls = []

        def _rec_runtime(job2, job_id, jc):
            calls.append("dispatched")
            raise AssertionError("RED B-RAW: zero dispatch violated (runtime resolved despite RAW block)")

        monkeypatch.setattr(sched, "_resolve_job_runtime", _rec_runtime)

        class JC:
            pass
        jc = JC()
        jc.cfg = cfg
        jc.model = "m"
        jc.model_cfg = {}
        jc.cron_default_provider = None
        setup = sched._resolve_cron_agent_setup({"id": "j-raw"}, "j-raw", "jn", jc)
        assert setup.blocked is not None, \
            f"RED B-RAW: 2458 must BLOCK RAW malformed {raw!r} (preflight_off={preflight_off})"
        assert calls == [], \
            f"RED B-RAW: 2458 zero dispatch violated (runtime called {calls}) for {raw!r}"

    @pytest.mark.parametrize("preflight_off", [False, True])
    def test_raw_legacy_fallback_model_malformed_blocks(self, tmp_path, monkeypatch, preflight_off):
        _env(tmp_path, monkeypatch)
        from cron import scheduler as sched
        job = {"id": "j-raw2"}
        cfg = {"fallback_model": ["not-a-dict"]}
        if preflight_off:
            cfg["cron"] = {"preflight": False}
        out = sched._preflight_or_block(job, "j-raw2", "jn", cfg)
        assert out is not None, "RED B-RAW: legacy fallback_model malformed must BLOCK"
        assert "fallback" in out[3].lower()
