"""Owner-scoped git for the root controller. Stdlib only.

DESIGN: systemd runs the controller as root with a minimal clean env (no
SUDO_UID, no user PATH). The live and candidate trees are owned by `ubuntu`,
so a bare `git -C <tree> …` as root fails closed with
`fatal: detected dubious ownership` and aborts the cutover pre-mutation.
Never work around this with `safe.directory=*` or any global root git
exception: root must not trust a mutable user tree.

Every git invocation in the controller therefore runs as the repo owner via
the trusted absolute spawn:

    /usr/sbin/runuser -u ubuntu -- /usr/bin/env -i HOME=/home/ubuntu
        PATH=/usr/bin:/bin GIT_CONFIG_NOSYSTEM=1 /usr/bin/git …

Non-root callers (tests, ubuntu dev) run the same inner argv through the
same absolute `/usr/bin/env -i` isolation without the runuser prefix, so no
ambient `GIT_*`/`PYTHON*`/`HOME` leaks in. Callers always pass an explicit
bounded `timeout` and an explicit `cwd` (the repo), and the inner argv always
uses the absolute `/usr/bin/git` with `-C <repo>`.

Covers all controller git routes: candidate/live `rev-parse HEAD` in
preflight, `check-ignore` for the web dist, `rev-parse HEAD` in health, and
`rev-parse`/`checkout --detach` in restore (which is already a no-op when
HEAD already equals parent, so untouched fleets never checkout).
"""

from __future__ import annotations

import os
from pathlib import Path

from scripts.maintenance.cutover_types import Host, RunResult

_RUNUSER = "/usr/sbin/runuser"
_ENV = "/usr/bin/env"
_GIT = "/usr/bin/git"
_OWNER = "ubuntu"
_OWNER_HOME = "/home/ubuntu"


def owner_git_env() -> dict[str, str]:
    """Explicit minimal env for owner git: no inherited config."""
    return {
        "HOME": _OWNER_HOME,
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def git_inner_argv(repo: Path | str, *git_args: str) -> list[str]:
    """Inner git argv with absolute binary and `-C <repo>`."""
    return [_GIT, "-C", str(Path(repo).absolute()), *git_args]


def wrap_owner_git(inner: list[str], env: dict[str, str]) -> list[str]:
    """Wrap inner git argv with owner isolation.

    Root inserts the absolute runuser prefix; non-root runs the same inner
    argv through absolute `env -i` so ambient config never leaks. Absolute
    paths are load-bearing: the isolated env carries `PATH=/usr/bin:/bin`
    (no `/usr/sbin`), so a bare `runuser` would raise `FileNotFoundError`
    before any live effect.
    """
    env_args = [_ENV, "-i"] + [f"{k}={v}" for k, v in sorted(env.items())]
    if _is_root():
        return [_RUNUSER, "-u", _OWNER, "--", *env_args, *inner]
    return [*env_args, *inner]


def run_owner_git(
    host: Host,
    repo: Path | str,
    git_args: list[str],
    timeout: int,
) -> RunResult:
    """Run git as the repo owner with explicit env, bounded timeout, and cwd.

    Never runs git as root directly; never inherits the caller env; never
    touches git `safe.directory` configuration.
    """
    repo_abs = Path(repo).absolute()
    env = owner_git_env()
    inner = git_inner_argv(repo_abs, *git_args)
    wrapped = wrap_owner_git(inner, env)
    return host.run(wrapped, timeout=int(timeout), cwd=repo_abs, env=env)
