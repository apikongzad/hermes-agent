"""Isolated candidate staging via the PM-documented build entrypoint. Stdlib only."""

from __future__ import annotations

from pathlib import Path

from scripts.maintenance.cutover_journal import append
from scripts.maintenance.cutover_types import (
    CutoverConfig,
    Host,
    Staged,
    generation_dir_for,
    venv_dir_for,
    venv_python_for,
)


class StageError(RuntimeError):
    pass


# PM-documented preparation entrypoint. `python -m pm.build_env` is the CLI
# wrapper around pm.build_environment (see pm/build_env.py + tests/AGENTS.md).
# Never use invented entrypoints (pm.py, scripts/sync_venv.py,
# scripts/publish_launcher.py do not exist).
def stage_argv(config: CutoverConfig) -> list[str]:
    out = venv_dir_for(config)
    return [
        "python3",
        "-m",
        "pm.build_env",
        "--source",
        str(config.candidate_src),
        "--out",
        str(out),
    ]


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
    generation = generation_dir_for(config)
    venv_dir = venv_dir_for(config)
    venv_python = venv_python_for(config)

    res = host.run(argv, timeout=1800)
    if res.returncode != 0:
        append(
            host,
            config.journal_path,
            "stage-failed",
            False,
            {
                "argv": argv[:4],
                "stderr_tail": (res.stderr or "")[-500:],
            },
        )
        raise StageError(f"PM staging failed: {(res.stderr or '').strip()[-300:]}")

    append(
        host,
        config.journal_path,
        "stage-ok",
        True,
        {
            "generation": str(generation),
            "venv_python": str(venv_python),
        },
    )
    return Staged(generation_dir=generation, venv_dir=venv_dir, venv_python=venv_python)


def verify_isolated_launch(
    host: Host, config: CutoverConfig, staged: Staged, live_exe: str
) -> None:
    """Prove the staged interpreter does not re-exec to the live old generation."""
    probe = ["import sys", "print(sys.executable)", "print(sys.prefix)"]
    code = "; ".join(probe)
    res = host.run([str(staged.venv_python), "-c", code], timeout=60)
    if res.returncode != 0:
        raise StageError(
            f"staged interpreter probe failed: {(res.stderr or '')[-300:]}"
        )
    lines = (res.stdout or "").strip().splitlines()
    if not lines:
        raise StageError("staged interpreter probe printed nothing")
    reported_exe = lines[0].strip()
    reported_prefix = lines[1].strip() if len(lines) > 1 else ""
    generation_text = str(staged.generation_dir)
    if generation_text not in reported_exe and generation_text not in reported_prefix:
        raise StageError(
            f"staged probe re-executes outside the generation: exe={reported_exe!r} prefix={reported_prefix!r}"
        )
    if live_exe and reported_exe.strip() == live_exe.strip():
        raise StageError("staged probe re-executes the live old generation interpreter")
    append(
        host,
        config.journal_path,
        "launch-verify-ok",
        True,
        {
            "reported_exe": reported_exe,
            "reported_prefix": reported_prefix,
        },
    )
