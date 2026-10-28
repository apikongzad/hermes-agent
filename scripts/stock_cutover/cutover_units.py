"""Exact zzz-candidate.conf rendering. Stdlib only.

Implements gap addendum G3 sections 6.2/6.5 plus addendum 2.9 oracle:
in-place replacement only, empty-reset form, immutable mount python -I,
WorkingDirectory user-data dirs, EnvironmentFile empty reset, no forbidden
keys, no worktree/gen/.env/opt paths.
"""

KNOWN_GOOD_MOUNT = "/run/hermes-stock-activation/known-good-snap"
CANDIDATE_MOUNT = "/run/hermes-stock-activation/candidate-snap"
# Systemd-escaped mount unit names (systemd-escape -p --suffix=mount <Where>).
# Raw strings so literal backslash-x2d escapes survive Python parsing.
# Single backslash only (repr shows \\, bytes contain one 0x5c).
KNOWN_GOOD_MOUNT_UNIT = r"run-hermes\x2dstock\x2dactivation-known\x2dgood\x2dsnap.mount"
CANDIDATE_MOUNT_UNIT = r"run-hermes\x2dstock\x2dactivation-candidate\x2dsnap.mount"

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


def _unit_requires_after_lines():
    # Boot hard dependency: gateway/dashboard must not start when either
    # backing mount failed. Mount Before= alone does not block gateway
    # boot (WantedBy enables mount but does not hard-require for gateway);
    # Requires+After in the dropin makes the prereq effective. Both mounts
    # required (fail-closed: services cannot start invalid images).
    return [
        "[Unit]",
        f"Requires={KNOWN_GOOD_MOUNT_UNIT} {CANDIDATE_MOUNT_UNIT}",
        f"After={KNOWN_GOOD_MOUNT_UNIT} {CANDIDATE_MOUNT_UNIT}",
        "",
    ]


def render_gateway_dropin(mount):
    lines = _unit_requires_after_lines() + [
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
    lines = _unit_requires_after_lines() + [
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
    if "[Unit]" not in text:
        raise ValueError("missing Unit (Requires+After mount prereq required)")
    # [Unit] Requires+After both escaped mounts (hard prereq, not Before-only).
    # Line-exact, not substring: separate Requires=/After= lines required.
    _unit_lines = []
    _in_unit = False
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            _in_unit = (s == "[Unit]")
            continue
        if _in_unit and s:
            _unit_lines.append(s)
    _req = [v for v in _unit_lines if v.startswith("Requires=")]
    _aft = [v for v in _unit_lines if v.startswith("After=")]
    if len(_req) != 1 or KNOWN_GOOD_MOUNT_UNIT not in _req[0] or CANDIDATE_MOUNT_UNIT not in _req[0]:
        raise ValueError("dropin Requires both mounts required")
    if len(_aft) != 1 or KNOWN_GOOD_MOUNT_UNIT not in _aft[0] or CANDIDATE_MOUNT_UNIT not in _aft[0]:
        raise ValueError("dropin After both mounts required")
    # Only-named-override contract: [Unit] may contain only Requires/After,
    # [Service] only the named Exec/WD/EnvironmentFile keys. No broad scope,
    # no Condition, no OnFailure in dropins (no loop), no Restart.
    for ln in _unit_lines:
        if not (ln.startswith("Requires=") or ln.startswith("After=")):
            raise ValueError("dropin Unit only-named-override: " + ln[:60])
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("Condition"):
            raise ValueError("dropin Condition forbidden: " + s)
        if s.startswith("OnFailure="):
            raise ValueError("dropin OnFailure forbidden")
        if s.startswith("Restart="):
            raise ValueError("dropin Restart forbidden")
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
