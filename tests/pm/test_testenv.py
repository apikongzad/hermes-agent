"""PM test environment defaults must cover unconditional test imports.

The vault-key storage/CLI suites import keyring unconditionally (strict, no
skip guard) while [keychain] stays out of [all] by lazy-opt-in policy. CI
passes keychain explicitly in its test-environment extras; the local default
in pm.testenv must carry the same extras or collection fails outside CI.
Provisioning must go through PM's side-environment operation, never raw
pip/uv.
"""

from __future__ import annotations

from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_defaults_cover_keychain_opt_in_extra():
    import tomllib

    from pm import extras
    from pm.testenv import DEFAULT_TEST_EXTRAS

    assert set(DEFAULT_TEST_EXTRAS) >= {"all", "fal", "keychain"}
    assert tuple(DEFAULT_TEST_EXTRAS) == ("all", "fal", "keychain")

    metadata = tomllib.loads((_repo_root() / "pyproject.toml").read_text(encoding="utf-8-sig"))
    optional = metadata["project"]["optional-dependencies"]
    assert "keychain" in optional
    assert "fal" in optional
    assert extras.ANCHORS["keychain"] == "keyring"
    # Lazy-opt-in policy: [keychain] stays out of [all], so the testenv
    # default is the only local path that provides the anchor.
    assert not [spec for spec in optional["all"] if "keychain" in spec]

    workflow = (_repo_root() / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert '"keychain"' in workflow, "CI test-environment extras must include keychain"


def test_ensure_testenv_provisions_side_environment_through_pm(tmp_path, monkeypatch):
    import subprocess

    import pytest

    import pm
    from pm.testenv import DEFAULT_TEST_EXTRAS, GROUPS, ensure_testenv, testenv_root

    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: pytest.fail("testenv must not shell out to pip/uv")
    )
    monkeypatch.setattr(
        subprocess, "check_output", lambda *args, **kwargs: pytest.fail("testenv must not shell out to pip/uv")
    )
    monkeypatch.setattr(
        subprocess, "Popen", lambda *args, **kwargs: pytest.fail("testenv must not shell out to pip/uv")
    )

    calls: dict[str, object] = {}

    def fake_ensure(name, project, *, extras=(), groups=(), root=None, explicit=False, **kwargs):
        calls["name"] = name
        calls["project"] = Path(project)
        calls["extras"] = list(extras)
        calls["groups"] = list(groups)
        calls["root"] = root
        calls["explicit"] = explicit
        return tmp_path / "bin" / "python"

    monkeypatch.setattr(pm, "ensure_project_environment", fake_ensure)

    python = ensure_testenv(tmp_path)
    assert python == tmp_path / "bin" / "python"
    assert calls["name"] == "test-environment"
    assert calls["project"] == tmp_path
    assert calls["extras"] == sorted(set(DEFAULT_TEST_EXTRAS))
    assert "keychain" in calls["extras"]
    assert calls["groups"] == list(GROUPS)
    assert calls["root"] == testenv_root(tmp_path)
    assert calls["explicit"] is True


def test_ensure_testenv_explicit_extras_override_defaults(tmp_path, monkeypatch):
    import pm
    from pm.testenv import ensure_testenv, testenv_root

    seen: dict[str, object] = {}

    def fake_ensure(name, project, *, extras=(), groups=(), root=None, explicit=False, **kwargs):
        seen["extras"] = list(extras)
        return tmp_path / "bin" / "python"

    monkeypatch.setattr(pm, "ensure_project_environment", fake_ensure)

    assert ensure_testenv(tmp_path, ["all"]) == tmp_path / "bin" / "python"
    assert seen["extras"] == ["all"]
    assert testenv_root(tmp_path).name == "test-environment"
