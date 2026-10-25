"""Candidate systemd dropins: bind ExecStart/WorkingDirectory + explicit PATH.

The dropin sorts AFTER the existing zz-runtime-3.14.9.conf override
(lexicographic systemd ordering), binds the staged venv python directly
(HERMES_EXE never selects the interpreter: units hardcode ExecStart), and
saves/restores reversible bytes. Stdlib only.
"""

from __future__ import annotations

from pathlib import Path

from scripts.maintenance.cutover_types import (
    CutoverConfig,
    Host,
    Staged,
    candidate_dropin_path,
)


SYSTEM_PATH_TAIL = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def render_gateway_dropin(config: CutoverConfig, staged: Staged) -> str:
    staged_bin = str(staged.venv_dir / "bin")
    hermes_home = str(config.hermes_home)
    # Gateway WorkingDirectory is the default home per the live baseline.
    return (
        "[Service]\n"
        f"ExecStart={staged.venv_python} {config.candidate_src}/hermes_cli/main.py gateway run\n"
        f"WorkingDirectory={hermes_home}\n"
        f'Environment="PATH={staged_bin}:/home/ubuntu/.local/bin:{SYSTEM_PATH_TAIL}"\n'
        f'Environment="HERMES_HOME={hermes_home}"\n'
    )


def render_dashboard_dropin(config: CutoverConfig, staged: Staged) -> str:
    staged_bin = str(staged.venv_dir / "bin")
    hermes_home = str(config.hermes_home)
    # Dashboard WorkingDirectory is /home/ubuntu per the live baseline.
    return (
        "[Service]\n"
        f"ExecStart={staged.venv_python} {config.candidate_src}/hermes_cli/main.py "
        f"dashboard --port {config.dashboard_port} --host 127.0.0.1 --no-open --skip-build\n"
        "WorkingDirectory=/home/ubuntu\n"
        f'Environment="PATH={staged_bin}:/home/ubuntu/.local/bin:{SYSTEM_PATH_TAIL}"\n'
        f'Environment="HERMES_HOME={hermes_home}"\n'
    )


def write_candidate_dropins(
    host: Host, config: CutoverConfig, staged: Staged
) -> dict[str, bytes | None]:
    """Write zzz-candidate dropins; return prior bytes for reversible restore."""
    saved: dict[str, bytes | None] = {}
    for dropin_dir, render in (
        (config.gateway_dropin_dir, render_gateway_dropin),
        (config.dashboard_dropin_dir, render_dashboard_dropin),
    ):
        target = candidate_dropin_path(dropin_dir, config.candidate_dropin_name)
        try:
            prior = host.read_bytes(target)
        except FileNotFoundError:
            prior = None
        except OSError as exc:
            raise RuntimeError(f"cannot read existing dropin {target}: {exc}") from exc
        saved[str(target)] = prior
        body = render(config, staged)
        if "HERMES_EXE" in body:
            raise RuntimeError("dropin must not rely on HERMES_EXE")
        if (
            "ExecStart=" not in body
            or "WorkingDirectory=" not in body
            or "PATH=" not in body
        ):
            raise RuntimeError(
                "dropin must bind ExecStart + WorkingDirectory + explicit PATH"
            )
        host.write_bytes(target, body.encode("utf-8"))
    return saved


def remove_candidate_dropins(host: Host, config: CutoverConfig) -> None:
    for dropin_dir in (config.gateway_dropin_dir, config.dashboard_dropin_dir):
        target = candidate_dropin_path(dropin_dir, config.candidate_dropin_name)
        try:
            host.remove(target)
        except OSError as exc:
            raise RuntimeError(
                f"cannot remove candidate dropin {target}: {exc}"
            ) from exc
