"""Exact zzz-candidate.conf rendering. Stdlib only.

Implements gap addendum G3 sections 6.2/6.5 plus addendum 2.9 oracle:
in-place replacement only, empty-reset form, immutable mount python -I,
WorkingDirectory user-data dirs, EnvironmentFile empty reset, no forbidden
keys, no worktree/gen/.env/opt paths.
"""

KNOWN_GOOD_MOUNT = "/run/hermes-stock-activation/known-good-snap"
CANDIDATE_MOUNT = "/run/hermes-stock-activation/candidate-snap"

GATEWAY_WD = "/home/ubuntu/.hermes"
DASHBOARD_WD = "/home/ubuntu"

GATEWAY_UNIT = "hermes-gateway.service"
DASHBOARD_UNIT = "hermes-dashboard.service"

GATEWAY_CANDIDATE_PATH = (
    "/etc/systemd/system/hermes-gateway.service.d/zzz-candidate.conf"
)
DASHBOARD_CANDIDATE_PATH = (
    "/etc/systemd/system/hermes-dashboard.service.d/zzz-candidate.conf"
)

TARGET_SHA = "daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06"
KNOWN_GOOD_SHA = "1d9a377fa00ce0e663e274e16b63c75e36233b9e"

FORBIDDEN_LOADER_KEYS = (
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "PYTHONEXECUTABLE",
    "PYTHONSAFEPATH",
    "PYTHONNOUSERSITE",
    "PYTHONINSPECT",
)

VENV_OLD = "/home/ubuntu/.hermes/hermes-agent/venv"
WORKTREE_PATH = (
    "/home/ubuntu/worktrees/worktrees/hermes-upstream-integrate-20261025"
)
GEN_KNOWN_GOOD = "gen-1d9a377fa00c"
ENV_FILE_PATH = "/home/ubuntu/.hermes/.env"


def gateway_exec(mount):
    return (
        f"{mount}/venv/bin/python3 -I "
        f"{mount}/source/hermes_cli/main.py gateway run"
    )


def dashboard_exec(mount):
    return (
        f"{mount}/venv/bin/python3 -I "
        f"{mount}/source/hermes_cli/main.py "
        "dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build"
    )


KNOWN_GOOD_GATEWAY_EXEC = (
    "/run/hermes-stock-activation/known-good-snap/venv/bin/python3 -I "
    "/run/hermes-stock-activation/known-good-snap/source/hermes_cli/main.py "
    "gateway run"
)
KNOWN_GOOD_DASHBOARD_EXEC = (
    "/run/hermes-stock-activation/known-good-snap/venv/bin/python3 -I "
    "/run/hermes-stock-activation/known-good-snap/source/hermes_cli/main.py "
    "dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build"
)
CANDIDATE_GATEWAY_EXEC = (
    "/run/hermes-stock-activation/candidate-snap/venv/bin/python3 -I "
    "/run/hermes-stock-activation/candidate-snap/source/hermes_cli/main.py "
    "gateway run"
)
CANDIDATE_DASHBOARD_EXEC = (
    "/run/hermes-stock-activation/candidate-snap/venv/bin/python3 -I "
    "/run/hermes-stock-activation/candidate-snap/source/hermes_cli/main.py "
    "dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build"
)


def render_gateway_dropin(mount):
    lines = [
        "[Service]",
        "ExecStart=",
        f"ExecStart={gateway_exec(mount)}",
        "ExecStop=",
        "ExecStopPost=",
        f"WorkingDirectory={GATEWAY_WD}",
        "EnvironmentFile=",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_dashboard_dropin(mount):
    lines = [
        "[Service]",
        "ExecStart=",
        f"ExecStart={dashboard_exec(mount)}",
        "ExecStop=",
        "ExecStopPost=",
        f"WorkingDirectory={DASHBOARD_WD}",
        "EnvironmentFile=",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def dropin_for(unit, mount):
    if unit == GATEWAY_UNIT:
        return render_gateway_dropin(mount)
    if unit == DASHBOARD_UNIT:
        return render_dashboard_dropin(mount)
    raise ValueError("unknown unit")


def validate_dropin_bytes(data, mount, working_dir):
    """Fail-closed validation of rendered bytes. Returns True or raises."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("dropin type")
    text = bytes(data).decode("utf-8")
    if "[Service]" not in text:
        raise ValueError("missing Service")
    # Empty resets required.
    for needle in ("ExecStart=\n", "ExecStop=\n", "ExecStopPost=\n",
                   "EnvironmentFile=\n"):
        if needle not in text:
            raise ValueError("missing reset " + needle.strip())
    if f"ExecStart={mount}/venv/bin/python3 -I " not in text:
        raise ValueError("ExecStart not snapshot python -I")
    if f"WorkingDirectory={working_dir}" not in text:
        raise ValueError("WorkingDirectory")
    # Forbidden content must never appear.
    for bad in (WORKTREE_PATH, GEN_KNOWN_GOOD, VENV_OLD, ENV_FILE_PATH,
                "/opt/hermes-maintenance", "cutover_"):
        if bad in text:
            raise ValueError("forbidden content " + bad)
    for key in FORBIDDEN_LOADER_KEYS:
        if key + "=" in text:
            raise ValueError("forbidden loader " + key)
    if "PYTHONPATH" in text:
        raise ValueError("PYTHONPATH")
    # No second drop-in, no stacked ExecStart without reset.
    if text.count("ExecStart=") != 2:
        raise ValueError("ExecStart count")
    return True
