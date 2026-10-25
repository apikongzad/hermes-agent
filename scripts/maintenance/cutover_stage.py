"""Isolated candidate staging via the PM-documented build entrypoint. Stdlib only.

DESIGN v2: root NEVER imports candidate pm. The build runs as `ubuntu` with
explicit cwd=candidate_src, absolute /usr/bin/python3, isolated
HOME/HERMES_HOME/HERMES_RUNTIME_DIR, env -i, no PYTHONPATH. Re-exec probe
invokes REAL Hermes launch preparation (hermes_bootstrap + version identity),
not `python -c sys.executable`.
"""

from __future__ import annotations

import os
import subprocess
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


def probe_home_for(config: CutoverConfig) -> Path:
    """Isolated probe home: never the default production profile."""
    return (Path(config.generation_root).absolute()
            / f"probe-home-{config.candidate_sha[:12]}")


def _isolated_env(config: CutoverConfig) -> dict[str, str]:
    probe_home = str(probe_home_for(config))
    # Production toolchain is read-only via _unstamped_store borrowing;
    # the probe home itself is empty/isolated so the default profile
    # (/home/ubuntu/.hermes) is never HERMES_HOME here and never mutated.
    return {
        "HOME": probe_home,
        "HERMES_HOME": probe_home,
        "HERMES_RUNTIME_DIR": "/home/ubuntu/.hermes/tools",
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
    try:
        res = host.run(
            wrapped, timeout=1800,
            cwd=Path(config.candidate_src).absolute(), env=env,
        )
    except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        append(
            host,
            config.journal_path,
            "stage-failed",
            False,
            {"argv": argv[:6], "error": f"{type(exc).__name__}: {exc}"[-500:]},
        )
        raise StageError(f"PM staging transport failed: {exc}") from exc
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


def _launch_probe_code(candidate: str) -> str:
    return (
        "import sys, json\n"
        "_before={'exe': sys.executable, 'prefix': sys.prefix}\n"
        "sys.path.insert(0, '" + candidate + "')\n"
        "import hermes_bootstrap\n"
        "from hermes_cli.venv_sync import prepare_launch\n"
        "from hermes_cli.version_info import get_code_identity\n"
        "from pathlib import Path\n"
        "_root=Path('" + candidate + "')\n"
        "_relaunch=None\n"
        "_relaunch_error=None\n"
        "try:\n"
        " _relaunch=prepare_launch(_root, ['gateway', 'run'])\n"
        "except Exception as _exc:\n"
        " _relaunch_error=type(_exc).__name__ + ':' + str(_exc)[:300]\n"
        "_after={'exe': sys.executable, 'prefix': sys.prefix}\n"
        "_identity=get_code_identity()\n"
        "print(json.dumps({'sha': _identity.get('sha'), "
        "'short_sha': _identity.get('short_sha'), "
        "'version': _identity.get('version'), "
        "'source': _identity.get('source'), "
        "'before': _before, 'after': _after, "
        "'relaunch': str(_relaunch), "
        "'relaunch_error': _relaunch_error}))"
    )


def verify_isolated_launch(
    host: Host, config: CutoverConfig, staged: Staged, live_exe: str
) -> None:
    """Prove the staged venv boots REAL Hermes prep, not just sys.executable.

    Runs as ubuntu, isolated HOME/HERMES_HOME (never the default production
    profile), cwd=candidate:
      <staged>/bin/python -I -B -c "<probe>"
    The probe records sys.executable/sys.prefix BEFORE, imports
    hermes_bootstrap, calls hermes_cli.venv_sync.prepare_launch, records
    AFTER, then get_code_identity (sha/short_sha/version/source). The
    verifier requires sha==candidate, before==staged python,
    after==before (no mid-probe re-exec), and the prepare_launch call.
    """
    candidate = str(Path(config.candidate_src).absolute())
    if "'" in candidate:
        raise StageError("candidate path is not quotable (refusing to proceed)")
    code = _launch_probe_code(candidate)
    env = _isolated_env(config)
    if env.get("HERMES_HOME") == str(config.hermes_home):
        raise StageError("probe HERMES_HOME must be isolated (never production)")
    argv = [str(staged.venv_python), "-I", "-B", "-c", code]
    wrapped = _wrap_for_user(argv, env)
    try:
        res = host.run(
            wrapped, timeout=120,
            cwd=Path(config.candidate_src).absolute(), env=env,
        )
    except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        raise StageError(f"staged launch-prep probe transport failed: {exc}") from exc
    if res.returncode != 0:
        raise StageError(f"staged launch-prep probe failed: {(res.stderr or '')[-500:]}")
    try:
        import json as _json

        payload = _json.loads((res.stdout or "").strip().splitlines()[-1])
        reported_sha = str(payload.get("sha") or "")
        before = payload.get("before") or {}
        after = payload.get("after") or {}
    except Exception as exc:
        raise StageError(f"staged probe identity unparseable: {exc}") from exc
    if reported_sha != config.candidate_sha:
        raise StageError(
            f"staged probe sha {reported_sha[:12]} != candidate {config.candidate_sha[:12]}"
        )
    if "prepare_launch" not in code or "hermes_bootstrap" not in code:
        raise StageError("staged probe must exercise real Hermes launch prep")
    before_exe = str(before.get("exe") or "")
    after_exe = str(after.get("exe") or "")
    if not before_exe or not after_exe:
        raise StageError("staged probe must record sys.executable before/after")
    if not before.get("prefix") or not after.get("prefix"):
        raise StageError("staged probe must record sys.prefix before/after")
    try:
        same_interp = (
            Path(before_exe).resolve() == Path(staged.venv_python).resolve()
            or before_exe.strip() == str(staged.venv_python).strip()
        )
    except OSError:
        same_interp = before_exe.strip() == str(staged.venv_python).strip()
    if not same_interp:
        raise StageError("staged probe did not run in the staged interpreter")
    if after_exe != before_exe or (after.get("prefix") or "") != (before.get("prefix") or ""):
        raise StageError("staged probe re-execed mid-probe (before != after)")
    if payload.get("relaunch_error"):
        raise StageError(f"prepare_launch failed in probe: {payload.get('relaunch_error')}")
    if str(staged.generation_dir) not in str(staged.venv_python):
        raise StageError("staged python is not inside the generation dir")
    if live_exe and live_exe.strip() == str(staged.venv_python).strip():
        raise StageError("staged probe re-executes the live old generation interpreter")
    try:
        euid = os.geteuid()
        user = "root" if euid == 0 else "ubuntu"
    except AttributeError:
        user = "unknown"
    append(
        host,
        config.journal_path,
        "launch-verify-ok",
        True,
        {
            "sha": reported_sha,
            "venv_python": str(staged.venv_python),
            "user": user,
            "hermes_home": env.get("HERMES_HOME", ""),
            "before": before,
            "after": after,
            "relaunch": str(payload.get("relaunch") or ""),
        },
    )
