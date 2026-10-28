"""Recovery supervision. Stdlib only.

The external operator is the recovery launcher: each argv exits, no daemon.
Interruption recovery re-reads the journal plus physical state and re-enters
the 5s fence before any publish/restore/start. Journal never deleted.
A second start while identity ambiguous is forbidden.

Supervision is owned by systemd: the cutover oneshot carries
OnFailure to the recover service, and a timer re-invokes recovery after
interruption. Unit text is verified code, not merely a path.
"""

RECOVERY_DIR = "/var/lib/hermes-stock-activation/recovery"
JOURNAL_PATH = "/var/lib/hermes-stock-activation/journal"
RECOVERY_PROGRAM = "/var/lib/hermes-stock-activation/recovery/cli.py"
RECOVERY_MODE = 0o500
RECOVERY_DIR_MODE = 0o500
JOURNAL_MODE = 0o600

CUTOVER_SERVICE_NAME = "hermes-stock-cutover.service"
RECOVER_SERVICE_NAME = "hermes-stock-cutover-recover.service"
RECOVER_TIMER_NAME = "hermes-stock-cutover-recover.timer"

PYTHON_BIN = "/usr/bin/python3.12"

# Fixed recovery argv: python -I recovery program, no worktree, no restart.
RECOVERY_ARGV = [PYTHON_BIN, "-I", RECOVERY_PROGRAM, "recover"]
APPLY_ARGV = [PYTHON_BIN, "-I", RECOVERY_PROGRAM, "apply"]


def cutover_service_unit():
    return (
        "[Unit]\n"
        "Description=Hermes stock cutover transaction (oneshot, external root)\n"
        "After=network.target\n"
        "OnFailure=hermes-stock-cutover-recover.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=no\n"
        f"ExecStart={PYTHON_BIN} -I {RECOVERY_PROGRAM} apply\n"
        "NoNewPrivileges=yes\n"
        "PrivateTmp=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def recover_service_unit():
    return (
        "[Unit]\n"
        "Description=Hermes stock cutover recovery (fence re-verify, no second start while ambiguous)\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=no\n"
        f"ExecStart={PYTHON_BIN} -I {RECOVERY_PROGRAM} recover\n"
        "NoNewPrivileges=yes\n"
        "PrivateTmp=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def recover_timer_unit():
    return (
        "[Unit]\n"
        "Description=Re-enter cutover fence after interruption\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=1min\n"
        "OnUnitInactiveSec=1min\n"
        "Unit=hermes-stock-cutover-recover.service\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def validate_supervision(cutover_text, recover_text, timer_text):
    if not all(isinstance(t, str) for t in (cutover_text, recover_text, timer_text)):
        raise ValueError("unit type")
    # Cutover must own recovery via OnFailure, not via restart.
    if "OnFailure=hermes-stock-cutover-recover.service" not in cutover_text:
        raise ValueError("missing OnFailure")
    if "Type=oneshot" not in cutover_text or "Type=oneshot" not in recover_text:
        raise ValueError("oneshot required")
    for bad in ("Restart=always", "Restart=on-failure", "systemctl restart",
                "/home/ubuntu/worktrees", "gen-1d9a377fa00c",
                "/home/ubuntu/.hermes/hermes-agent/venv",
                "cutover_.py", "/opt/hermes-maintenance"):
        if bad in cutover_text or bad in recover_text:
            raise ValueError("forbidden in supervision: " + bad)
    # Fixed interpreter, -I, recovery path outside user trees.
    for t in (cutover_text, recover_text):
        if f"{PYTHON_BIN} -I {RECOVERY_PROGRAM}" not in t:
            raise ValueError("recovery ExecStart")
    if "Unit=hermes-stock-cutover-recover.service" not in timer_text:
        raise ValueError("timer unit")
    # No kill/signal directives.
    for bad in ("KillSignal", "ExecStop=", "kill ", "killpg", "SIGKILL"):
        if bad in timer_text:
            raise ValueError("timer forbidden " + bad)
    return True
