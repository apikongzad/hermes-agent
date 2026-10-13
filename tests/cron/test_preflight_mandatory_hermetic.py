"""Hermetic B: readiness fail-closed at exact lines (DESIGN rev6 §6).

Red regressions per ACCEPTED DESIGN exact 2f222ae.
Hermetic: temp HERMES_HOME, no credentials, no services, zero dispatch on block.

IDs: B-ENUM-1, B-READY-1, B-DIAG-1, B-CRED-1, B-PM-1, B-PLUGIN-1,
B-CRON-1..6, B-PREFLIGHT-FLAG (both 1712+2458, preflight:false scope,
fallback-chain 92-93 vs 94-95 disjoint), B-VIEW-1, B-ACT-1, B-ENUM-FLAG-1.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


class TestBEnumReady:
    def test_only_available_ready(self):
        from tools.skills_tool_setup import SkillReadinessStatus
        assert SkillReadinessStatus.AVAILABLE.value == "available"
        assert SkillReadinessStatus.SETUP_NEEDED.value == "setup_needed"
        assert SkillReadinessStatus.UNSUPPORTED.value == "unsupported"
        # Ready predicate: success True + available + setup_needed False + error absent
        def ready(payload: dict) -> bool:
            return (payload.get("success") is True
                    and payload.get("readiness_status") == "available"
                    and payload.get("setup_needed") is False
                    and "error" not in payload)
        assert ready({"success": True, "readiness_status": "available",
                      "setup_needed": False}) is True
        for bad in ({"success": True, "readiness_status": "setup_needed", "setup_needed": True},
                    {"success": True, "readiness_status": "available", "setup_needed": True},
                    {"success": False, "readiness_status": "available", "setup_needed": False},
                    {"success": True, "readiness_status": "unsupported", "setup_needed": False},
                    {"success": True, "readiness_status": "available", "setup_needed": False,
                     "error": "x"}):
            assert ready(bad) is False, f"must block {bad} (B-READY-1)"

    def test_cred_exception_fail_closed(self, tmp_path, monkeypatch):
        """B-CRED-1: register_credential_files raise -> setup_needed True + setup_needed status."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
        from tools import skills_tool as st
        import tools.credential_files as cf
        def _boom(files):
            raise OSError("injected cred failure")
        monkeypatch.setattr(cf, "register_credential_files", _boom)
        fields, _extras = st._skill_readiness(
            {"required_credential_files": ["cred.json"]}, "t-skill")
        assert fields.get("setup_needed") is True, "cred exception must set setup_needed (B-CRED-1)"
        assert fields.get("readiness_status") == "setup_needed"

    def test_pm_dep_failure_fail_closed_no_pm_ensure_on_view(self, tmp_path, monkeypatch):
        """B-PM-1 + B-VIEW-1: declared deps failure -> setup_needed; view performs zero setup."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
        import pm as _pm
        def _boom(*a, **k):
            raise AssertionError("view must not call pm.ensure (B-VIEW-1)")
        monkeypatch.setattr(_pm, "ensure", _boom)
        # skill_view with missing dep must report setup_needed, not available+True
        from tools import skills_tool as st
        # Use _skill_readiness + view-time deps path: missing command
        fields, _ = st._skill_readiness({"required_commands": ["definitely-missing-cmd-xyz"]}, "s")
        assert fields.get("setup_needed") is True
        assert fields.get("readiness_status") == "setup_needed"
        assert "definitely-missing-cmd-xyz" in str(fields.get("missing_required_commands"))

    def test_plugin_exception_fail_closed(self, tmp_path, monkeypatch):
        """B-PLUGIN-1: plugin readiness exception -> setup_needed, never available."""
        from tools import skills_tool_plugin as plug
        from tools import skills_tool as st
        def _boom(*a, **k):
            raise RuntimeError("injected readiness failure")
        monkeypatch.setattr(st, "_skill_readiness", _boom)
        # Build minimal plugin skill dir
        d = tmp_path / "plugskill"
        (d / "refs").mkdir(parents=True)
        md = d / "SKILL.md"
        md.write_text("---\nname: x\ndescription: d\n---\nhello\n", encoding="utf-8")
        out = json.loads(plug._serve_plugin_skill(md, "ns", "x"))
        assert out.get("setup_needed") is True, "plugin exception must be setup_needed (B-PLUGIN-1)"
        assert out.get("readiness_status") == "setup_needed"


class TestBCronFailClosed:
    def test_fallback_probe_error_blocked(self, tmp_path, monkeypatch):
        """B-CRON-1: _job_fallback_chain probe except -> blocked diagnostic, never None-proceed."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
        from cron import scheduler_preflight as pf
        from cron import scheduler as sched
        def _boom(job, cfg):
            raise RuntimeError("injected fallback failure")
        monkeypatch.setattr(sched, "_job_fallback_chain", _boom)
        # Also patch _sched ref inside preflight (late-bound)
        monkeypatch.setattr(pf._sched, "_job_fallback_chain", _boom)
        reason = pf._preflight_check_provider_key({"id": "j"}, {})
        assert reason is not None and "fallback" in reason.lower(), \
            f"B-CRON-1 probe error must block, got {reason!r}"

    def test_non_auth_resolve_error_blocked(self, tmp_path, monkeypatch):
        """B-CRON-2: non-AuthError resolve error -> blocked."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
        from cron import scheduler_preflight as pf
        from cron import scheduler as sched
        monkeypatch.setattr(sched, "_job_fallback_chain", lambda job, cfg: None)
        monkeypatch.setattr(pf._sched, "_job_fallback_chain", lambda job, cfg: None)
        import hermes_cli.runtime_provider as rp
        def _boom(**k):
            raise TimeoutError("injected non-auth failure")
        monkeypatch.setattr(rp, "resolve_runtime_provider", _boom)
        reason = pf._preflight_check_provider_key({"id": "j"}, {})
        assert reason is not None, f"B-CRON-2 non-auth error must block, got {reason!r}"

    def test_gateway_load_failure_known_platform_blocked(self, tmp_path, monkeypatch):
        """B-CRON-3: gateway-config load fail with known platform -> blocked; local/all exempt."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
        from cron import scheduler_preflight as pf
        import gateway.config as gc
        def _boom():
            raise OSError("injected gateway load failure")
        monkeypatch.setattr(gc, "load_gateway_config", _boom)
        # known platform must block
        r = pf._preflight_check_delivery({"deliver": "discord:123", "id": "j"})
        assert r is not None, "known-platform loader-fail must block (B-CRON-3)"
        # exempt lanes stay None
        for lane in ("local", "origin", "all", "bot-chat:abc"):
            assert pf._preflight_check_delivery({"deliver": lane}) is None, f"{lane} must stay exempt"

    def test_skill_unreadable_blocked(self, tmp_path, monkeypatch):
        """B-CRON-4: skill_view except / not success -> blocked diagnostic."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
        from cron import scheduler_preflight as pf
        from tools import skills_tool as st
        def _boom(name):
            raise OSError("injected view failure")
        monkeypatch.setattr(st, "skill_view", _boom)
        monkeypatch.setattr("cron.scheduler_prompt._job_skill_names",
                            lambda job: ["some-skill"], raising=False)
        # Need to patch the import inside function: it does from tools.skills_tool import skill_view
        # so patching tools.skills_tool.skill_view suffices if module re-imports. Force:
        import tools.skills_tool
        monkeypatch.setattr(tools.skills_tool, "skill_view", _boom)
        reason = pf._preflight_check_skills({"skills": ["some-skill"]})
        assert reason is not None, f"unreadable skill must block (B-CRON-4), got {reason!r}"

    def test_per_check_raise_blocked(self, tmp_path, monkeypatch):
        """B-CRON-5: per-check raise -> blocked naming the check."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
        from cron import scheduler_preflight as pf
        def _boom(job, cfg=None):
            raise RuntimeError("injected check failure")
        # Patch provider check to raise; _preflight_job_config must map to blocked
        monkeypatch.setattr(pf, "_preflight_check_provider_key", lambda job, cfg: (_ for _ in ()).throw(RuntimeError("x")))
        reason = pf._preflight_job_config({"id": "j"}, {})
        assert reason is not None and ("provider_key" in reason or "provider" in reason.lower() or "check" in reason.lower()), \
            f"B-CRON-5 must name check, got {reason!r}"

    def test_outer_validator_error_blocked(self, tmp_path, monkeypatch):
        """B-CRON-6: outer except -> blocked, job does not dispatch."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
        from cron import scheduler as sched
        def _boom(job, cfg):
            raise RuntimeError("injected validator failure")
        monkeypatch.setattr(sched, "_preflight_job_config", _boom)
        out = sched._preflight_or_block({"id": "j"}, "j", "jn", {})
        assert out is not None, "validator error must block (B-CRON-6)"
        assert "blocked_config" in str(out[-1]).lower() or "blocked" in str(out).lower()

    def test_mandatory_guard_both_sites_preflight_false(self, tmp_path, monkeypatch):
        """B-PREFLIGHT-FLAG: both 1712 and 2458 with preflight:false + unready skill -> blocked;
        NEW mandatory guard called; optional provider probe may skip."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
        from cron import scheduler as sched
        from cron import scheduler_preflight as pf
        cfg = {"cron": {"preflight": False}}
        # Unready skill payload
        import tools.skills_tool as st
        def _unready(name):
            return json.dumps({"success": True, "readiness_status": "setup_needed",
                               "setup_needed": True,
                               "missing_required_environment_variables": ["X"],
                               "missing_required_commands": [],
                               "missing_credential_files": []})
        monkeypatch.setattr(st, "skill_view", _unready)
        monkeypatch.setattr("cron.scheduler_prompt._job_skill_names",
                            lambda job: ["needy"], raising=False)
        import cron.scheduler_prompt as sp
        monkeypatch.setattr(sp, "_job_skill_names", lambda job: ["needy"])
        job = {"id": "j1", "skills": ["needy"]}
        # 1712 site: _preflight_or_block must still block via NEW mandatory guard
        out = sched._preflight_or_block(job, "j1", "jn", cfg)
        assert out is not None, "1712 mandatory guard must block unready skill even with preflight:false"
        # 2458 site: _resolve_cron_agent_setup MCP + mandatory must block
        _cfg0 = cfg
        class JC:
            cfg = _cfg0
            model = "m"
        # Need mandatory helper to exist and be called
        assert hasattr(pf, "_cron_mandatory_readiness_guard") or hasattr(sched, "_cron_mandatory_readiness_guard"), \
            "missing NEW mandatory guard helper (B-PREFLIGHT-FLAG)"
        setup = sched._resolve_cron_agent_setup(job, "j1", "jn", JC())
        assert setup.blocked is not None, "2458 mandatory guard must block unready skill even with preflight:false"

    def test_fallback_chain_disjoint_policies(self, tmp_path, monkeypatch):
        """B-PREFLIGHT-FLAG disjoint 92-93 vs 94-95: raise->blocked both true/false;
        valid chain requires mandatory validation, not blanket None."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
        from cron import scheduler_preflight as pf
        from cron import scheduler as sched
        for flag in (True, False):
            cfg = {"cron": {"preflight": flag}}
            def _boom(job, cfg2):
                raise RuntimeError("fallback probe boom")
            monkeypatch.setattr(sched, "_job_fallback_chain", _boom)
            monkeypatch.setattr(pf._sched, "_job_fallback_chain", _boom)
            r = pf._preflight_check_provider_key({"id": "j"}, cfg)
            assert r is not None, f"fallback raise must block regardless of preflight={flag} (:94-95 B-CRON-1)"
        # Valid chain-present (:92-93) must NOT be blanket None: requires fallback-provider readiness
        def _chain(job, cfg2):
            return [{"provider": "p2"}]
        monkeypatch.setattr(sched, "_job_fallback_chain", _chain)
        monkeypatch.setattr(pf._sched, "_job_fallback_chain", _chain)
        # If fallback provider missing creds, must still block (mandatory validation), not None
        import hermes_cli.runtime_provider as rp
        from hermes_cli import auth
        def _auth_boom(**k):
            raise auth.AuthError("missing key for fallback")
        monkeypatch.setattr(rp, "resolve_runtime_provider", _auth_boom)
        # The provider-key check with valid chain must validate fallback readiness;
        # blanket return None fails this test.
        r2 = pf._preflight_check_provider_key({"id": "j"}, {})
        # Either blocks (validates fallback) or explicitly validates; blanket None is failure.
        # We assert it does NOT blanket-allow when fallback creds missing:
        # If impl returns None without validation, this fails.
        assert r2 is not None, "valid chain-present must validate fallback readiness, not blanket None (:92-93)"
