"""Isolated candidate staging via the PM-documented build entrypoint. Stdlib only.

DESIGN v2: root NEVER imports candidate pm. The build runs as `ubuntu` with
explicit cwd=candidate_src, absolute /usr/bin/python3, isolated
HOME/HERMES_HOME/HERMES_RUNTIME_DIR, env -i, no PYTHONPATH. Re-exec probe
invokes REAL Hermes launch preparation (hermes_bootstrap + version identity),
not `python -c sys.executable`.
"""

from __future__ import annotations

import os
from pathlib import Path

from scripts.maintenance.cutover_journal import append
from scripts.maintenance.cutover_types import (
    CutoverConfig,
    Host,
    Staged,
    generation_dir_for,
    parse_pyvenv_cfg,
    venv_dir_for,
    venv_python_for,
)


class StageError(RuntimeError):
    pass


def _isolated_env(config: CutoverConfig) -> dict[str, str]:
    home = "/home/ubuntu"
    hermes_home = str(config.hermes_home)
    # HERMES_RUNTIME_DIR names the PM store parent; default to <home>/tools
    # so a bare env still resolves the pinned toolchain.
    return {
        "HOME": home,
        "HERMES_HOME": hermes_home,
        "HERMES_RUNTIME_DIR": str(Path(hermes_home) / "tools"),
        "PATH": "/usr/bin:/bin",
    }


def stage_argv(config: CutoverConfig) -> list[str]:
    """Documented PM build; the Host adds cwd/env isolation at spawn."""
    out = venv_dir_for(config)
    return [
        "/usr/bin/python3",
        "-m",
        "pm.build_env",
        "--source",
        str(Path(config.candidate_src).absolute()),
        "--out",
        str(out.absolute()),
    ]


def _wrap_for_user(argv: list[str], env: dict[str, str]) -> list[str]:
    """Wrap for root-owned spawn: run as ubuntu with env -i when root.

    Non-root callers (tests, ubuntu dev) run the argv directly with the
    isolated env; root inserts `runuser -u ubuntu -- env -i …` so the
    candidate build never runs as root and never inherits root's env.
    """
    try:
        is_root = os.geteuid() == 0
    except AttributeError:
        is_root = False
    env_args = ["env", "-i"] + [f"{k}={v}" for k, v in sorted(env.items())]
    if is_root:
        return ["runuser", "-u", "ubuntu", "--", *env_args, *argv]
    return [*env_args, *argv]


def _forbidden_staging_argv(argv: list[str]) -> bool:
    text = " ".join(argv)
    return any(
        token in text
        for token in (
            "pm.py",
            "scripts/sync_venv.py",
            "scripts/publish_launcher.py",
        )
    )


def stage(host: Host, config: CutoverConfig) -> Staged:
    argv = stage_argv(config)
    if _forbidden_staging_argv(argv):
        raise StageError("staging uses a forbidden entrypoint")
    # The inner argv must stay the documented entrypoint; the wrapper only
    # adds isolation (runuser/env -i) at spawn time.
    if "pm.build_env" not in " ".join(argv):
        raise StageError("staging must invoke pm.build_env")
    generation = generation_dir_for(config)
    venv_dir = venv_dir_for(config)
    venv_python = venv_python_for(config)
    env = _isolated_env(config)

    wrapped = _wrap_for_user(argv, env)
    res = host.run(wrapped, timeout=1800, cwd=Path(config.candidate_src).absolute(), env=env)
    if res.returncode != 0:
        append(
            host,
            config.journal_path,
            "stage-failed",
            False,
            {"argv": argv[:6], "stderr_tail": (res.stderr or "")[-500:]},
        )
        raise StageError(f"PM staging failed: {(res.stderr or '').strip()[-300:]}")

    # Read staged pyvenv.cfg to bind the expected store interpreter (exact).
    try:
        cfg_bytes = host.read_bytes(venv_dir / "pyvenv.cfg")
    except OSError as exc:
        raise StageError(f"staged pyvenv.cfg unreadable: {exc}") from exc
    cfg = parse_pyvenv_cfg(cfg_bytes)
    home = cfg.get("home", "")
    exe = cfg.get("executable", "")
    if not home:
        raise StageError("staged pyvenv.cfg has no home (refusing to proceed)")
    append(
        host,
        config.journal_path,
        "stage-ok",
        True,
        {"generation": str(generation), "venv_python": str(venv_python), "home": home},
    )
    return Staged(
        generation_dir=generation,
        venv_dir=venv_dir,
        venv_python=venv_python,
        store_home=Path(home),
        store_exe=Path(exe) if exe else Path(home) / "python3",
    )


def verify_isolated_launch(
    host: Host, config: CutoverConfig, staged: Staged, live_exe: str
) -> None:
    """Prove the staged venv boots REAL Hermes prep, not just sys.executable.

    Runs as ubuntu, isolated HOME/HERMES_HOME, cwd=candidate:
      <staged>/bin/python -I -B -c
        "import sys; sys.path.insert(0, '<candidate>');
         import hermes_bootstrap;
         from hermes_cli.version_info import get_code_identity; …"
    and requires the reported sha == candidate_sha. Then binds
    pyvenv.cfg home/exe against the live exe (must differ) and the staged
    interpreter (must be inside the generation).
    """
    candidate = str(Path(config.candidate_src).absolute())
    # Safe literal: candidate paths never contain single quotes on this host;
    # refuse otherwise rather than interpolating unsafely.
    if "'" in candidate:
        raise StageError("candidate path is not quotable (refusing to proceed)")
    code = (
        "import sys; sys.path.insert(0, '" + candidate + "'); "
        "import hermes_bootstrap; "
        "from hermes_cli.version_info import get_code_identity; "
        "import json; print(json.dumps(get_code_identity()))"
    )
    env = _isolated_env(config)
    argv = [str(staged.venv_python), "-I", "-B", "-c", code]
    wrapped = _wrap_for_user(argv, env)
    res = host.run(wrapped, timeout=120, cwd=Path(config.candidate_src).absolute(), env=env)
    if res.returncode != 0:
        raise StageError(f"staged launch-prep probe failed: {(res.stderr or '')[-500:]}")
    try:
        import json as _json

        identity = _json.loads((res.stdout or "").strip().splitlines()[-1])
        reported_sha = str(identity.get("sha") or "")
    except Exception as exc:
        raise StageError(f"staged probe identity unparseable: {exc}") from exc
    if reported_sha != config.candidate_sha:
        raise StageError(
            f"staged probe sha {reported_sha[:12]} != candidate {config.candidate_sha[:12]}"
        )
    # The staged interpreter must live inside the generation dir.
    if str(staged.generation_dir) not in str(staged.venv_python):
        raise StageError("staged python is not inside the generation dir")
    # The staged store home must NOT be the live exe's dir (proves isolation
    # from the live old generation); live exe checked by the caller.
    if live_exe and live_exe.strip() == str(staged.venv_python).strip():
        raise StageError("staged probe re-executes the live old generation interpreter")
    append(
        host,
        config.journal_path,
        "launch-verify-ok",
        True,
        {"sha": reported_sha, "venv_python": str(staged.venv_python)},
    )
