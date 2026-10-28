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

# §10 exact mount templates (designed text, NOT installed by worker).
KNOWN_GOOD_IMAGE = "/var/lib/hermes-stock-activation/backing/known-good.squashfs"
CANDIDATE_IMAGE = "/var/lib/hermes-stock-activation/backing/candidate.squashfs"
KNOWN_GOOD_MOUNT = "/run/hermes-stock-activation/known-good-snap"
CANDIDATE_MOUNT = "/run/hermes-stock-activation/candidate-snap"
KNOWN_GOOD_MOUNT_UNIT = "hermes-stock-known-good-snap.mount"
CANDIDATE_MOUNT_UNIT = "hermes-stock-candidate-snap.mount"
GATEWAY_UNIT = "hermes-gateway.service"
DASHBOARD_UNIT = "hermes-dashboard.service"

PYTHON_BIN = "/usr/bin/python3.12"

# Fixed recovery argv: python -I recovery program, no worktree, no restart.
RECOVERY_ARGV = [PYTHON_BIN, "-I", RECOVERY_PROGRAM, "recover"]
APPLY_ARGV = [PYTHON_BIN, "-I", RECOVERY_PROGRAM, "apply"]


def _mount_deps_after():
    return (f"After=network.target {KNOWN_GOOD_MOUNT_UNIT} "
            f"{CANDIDATE_MOUNT_UNIT}")


def _mount_deps_requires():
    return (f"Requires={KNOWN_GOOD_MOUNT_UNIT} "
            f"{CANDIDATE_MOUNT_UNIT}")


def cutover_service_unit():
    # §10 exact: root-owned 0644 uid 0 (install metadata, not text),
    # program 0500 uid 0, dir 0500 uid 0, interpreter fixed
    # /usr/bin/python3.12 -I, Type oneshot, RemainAfterExit no,
    # Restart=no explicit, NoNewPrivileges, PrivateTmp, timeouts.
    # Mount deps: After+Requires both mounts, Conditions for both snaps
    # + both backing images. OnFailure recover (no loop elsewhere).
    # No systemctl restart argv; only stop/show/sleep5/daemon-reload/
    # show/start via G3 launcher in the program, never in units.
    return (
        "[Unit]\n"
        "Description=Hermes stock cutover transaction (oneshot, external root)\n"
        f"{_mount_deps_after()}\n"
        f"{_mount_deps_requires()}\n"
        f"ConditionPathIsMountPoint={KNOWN_GOOD_MOUNT}\n"
        f"ConditionPathIsMountPoint={CANDIDATE_MOUNT}\n"
        f"ConditionPathExists={KNOWN_GOOD_IMAGE}\n"
        f"ConditionPathExists={CANDIDATE_IMAGE}\n"
        "OnFailure=hermes-stock-cutover-recover.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=no\n"
        "Restart=no\n"
        f"ExecStart={PYTHON_BIN} -I {RECOVERY_PROGRAM} apply\n"
        "NoNewPrivileges=yes\n"
        "PrivateTmp=yes\n"
        "TimeoutStartSec=300\n"
        "TimeoutStopSec=30\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def recover_service_unit():
    # §10 exact: same mount deps/conditions as cutover, no OnFailure
    # (no OnFailure loop), ExecStart recover. Same hardening.
    return (
        "[Unit]\n"
        "Description=Hermes stock cutover recovery (fence re-verify, no second start while ambiguous)\n"
        f"{_mount_deps_after()}\n"
        f"{_mount_deps_requires()}\n"
        f"ConditionPathIsMountPoint={KNOWN_GOOD_MOUNT}\n"
        f"ConditionPathIsMountPoint={CANDIDATE_MOUNT}\n"
        f"ConditionPathExists={KNOWN_GOOD_IMAGE}\n"
        f"ConditionPathExists={CANDIDATE_IMAGE}\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=no\n"
        "Restart=no\n"
        f"ExecStart={PYTHON_BIN} -I {RECOVERY_PROGRAM} recover\n"
        "NoNewPrivileges=yes\n"
        "PrivateTmp=yes\n"
        "TimeoutStartSec=300\n"
        "TimeoutStopSec=30\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def recover_timer_unit():
    # §10 exact: OnBoot 1min, OnUnitInactive 1min, Persistent false
    # (no catch-up loop), Accuracy 15s. No kill/signal, no Exec.
    return (
        "[Unit]\n"
        "Description=Re-enter cutover fence after interruption\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=1min\n"
        "OnUnitInactiveSec=1min\n"
        "Unit=hermes-stock-cutover-recover.service\n"
        "Persistent=false\n"
        "AccuracySec=15s\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def known_good_mount_unit():
    # §10 exact squashfs read-only mount: What backing image, Where snap,
    # Type squashfs, Options ro,nosuid,nodev (flag word 7, no rw/noexec/
    # remount/bind). Before cutover/recover/gateway/dashboard so /run
    # mounts recreate read-only BEFORE any service ExecStart. If mount/
    # verify fails, cutover/recover conditions fail and transaction
    # refuses/recovers per §2.3-§2.5, never fake future-reboot success.
    return (
        "[Unit]\n"
        "Description=Hermes stock known-good squashfs (read-only)\n"
        f"ConditionPathExists={KNOWN_GOOD_IMAGE}\n"
        f"Before={CUTOVER_SERVICE_NAME} {RECOVER_SERVICE_NAME} "
        f"{GATEWAY_UNIT} {DASHBOARD_UNIT}\n"
        "\n"
        "[Mount]\n"
        f"What={KNOWN_GOOD_IMAGE}\n"
        f"Where={KNOWN_GOOD_MOUNT}\n"
        "Type=squashfs\n"
        "Options=ro,nosuid,nodev\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def candidate_mount_unit():
    return (
        "[Unit]\n"
        "Description=Hermes stock candidate squashfs (read-only)\n"
        f"ConditionPathExists={CANDIDATE_IMAGE}\n"
        f"Before={CUTOVER_SERVICE_NAME} {RECOVER_SERVICE_NAME} "
        f"{GATEWAY_UNIT} {DASHBOARD_UNIT}\n"
        "\n"
        "[Mount]\n"
        f"What={CANDIDATE_IMAGE}\n"
        f"Where={CANDIDATE_MOUNT}\n"
        "Type=squashfs\n"
        "Options=ro,nosuid,nodev\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def validate_supervision(cutover_text, recover_text, timer_text):
    if not all(isinstance(t, str) for t in (cutover_text, recover_text, timer_text)):
        raise ValueError("unit type")
    # Cutover must own recovery via OnFailure, not via restart.
    if "OnFailure=hermes-stock-cutover-recover.service" not in cutover_text:
        raise ValueError("missing OnFailure")
    # Recover must NOT carry OnFailure (no OnFailure loop).
    if "OnFailure=" in recover_text:
        raise ValueError("recover must not have OnFailure")
    if "Type=oneshot" not in cutover_text or "Type=oneshot" not in recover_text:
        raise ValueError("oneshot required")
    for bad in ("Restart=always", "Restart=on-failure", "systemctl restart",
                "/home/ubuntu/worktrees", "gen-1d9a377fa00c",
                "/home/ubuntu/.hermes/hermes-agent/venv",
                "cutover_.py", "/opt/hermes-maintenance"):
        if bad in cutover_text or bad in recover_text:
            raise ValueError("forbidden in supervision: " + bad)
    # Explicit Restart=no (no Restart=), hardening + timeouts.
    for t in (cutover_text, recover_text):
        if "Restart=no" not in t:
            raise ValueError("Restart=no required")
        if "RemainAfterExit=no" not in t:
            raise ValueError("RemainAfterExit=no required")
        if "NoNewPrivileges=yes" not in t:
            raise ValueError("NoNewPrivileges required")
        if "PrivateTmp=yes" not in t:
            raise ValueError("PrivateTmp required")
        if "TimeoutStartSec=300" not in t:
            raise ValueError("TimeoutStartSec required")
        if "TimeoutStopSec=30" not in t:
            raise ValueError("TimeoutStopSec required")
        # Mount deps: After+Requires both mounts, Conditions both snaps+images.
        if KNOWN_GOOD_MOUNT_UNIT not in t or CANDIDATE_MOUNT_UNIT not in t:
            raise ValueError("mount deps required")
        if f"ConditionPathIsMountPoint={KNOWN_GOOD_MOUNT}" not in t:
            raise ValueError("ConditionPathIsMountPoint required")
        if f"ConditionPathIsMountPoint={CANDIDATE_MOUNT}" not in t:
            raise ValueError("ConditionPathIsMountPoint required")
        if f"ConditionPathExists={KNOWN_GOOD_IMAGE}" not in t:
            raise ValueError("ConditionPathExists required")
        if f"ConditionPathExists={CANDIDATE_IMAGE}" not in t:
            raise ValueError("ConditionPathExists required")
    # Fixed interpreter, -I, recovery path outside user trees.
    for t in (cutover_text, recover_text):
        if f"{PYTHON_BIN} -I {RECOVERY_PROGRAM}" not in t:
            raise ValueError("recovery ExecStart")
    if "Unit=hermes-stock-cutover-recover.service" not in timer_text:
        raise ValueError("timer unit")
    if "OnBootSec=1min" not in timer_text:
        raise ValueError("timer OnBootSec")
    if "OnUnitInactiveSec=1min" not in timer_text:
        raise ValueError("timer OnUnitInactiveSec")
    if "Persistent=false" not in timer_text:
        raise ValueError("timer Persistent=false required")
    if "AccuracySec=15s" not in timer_text:
        raise ValueError("timer AccuracySec required")
    # No kill/signal directives, no restart in timer.
    for bad in ("KillSignal", "ExecStop=", "kill ", "killpg", "SIGKILL",
                "Restart="):
        if bad in timer_text:
            raise ValueError("timer forbidden " + bad)
    return True


def validate_mount_units(known_good_text, candidate_text):
    for text, img, mnt in ((known_good_text, KNOWN_GOOD_IMAGE, KNOWN_GOOD_MOUNT),
                           (candidate_text, CANDIDATE_IMAGE, CANDIDATE_MOUNT)):
        if not isinstance(text, str):
            raise ValueError("mount unit type")
        if f"What={img}" not in text:
            raise ValueError("mount What")
        if f"Where={mnt}" not in text:
            raise ValueError("mount Where")
        if "Type=squashfs" not in text:
            raise ValueError("mount Type squashfs")
        if "Options=ro,nosuid,nodev" not in text:
            raise ValueError("mount Options ro,nosuid,nodev")
        # No rw/noexec/remount/bind (flag word 7 only).
        for bad in ("rw", "noexec", "remount", "bind", "erofs", "ext4"):
            # Exact token check on Options line to avoid false positives
            # (e.g., "Description" contains "ro" substring).
            for line in text.splitlines():
                if line.strip().startswith("Options="):
                    opts = line.split("=", 1)[1].split(",")
                    if bad in [o.strip() for o in opts]:
                        raise ValueError("mount forbidden option " + bad)
        if f"ConditionPathExists={img}" not in text:
            raise ValueError("mount ConditionPathExists")
        for svc in (CUTOVER_SERVICE_NAME, RECOVER_SERVICE_NAME,
                    GATEWAY_UNIT, DASHBOARD_UNIT):
            if svc not in text:
                raise ValueError("mount Before " + svc)
        if "WantedBy=multi-user.target" not in text:
            raise ValueError("mount WantedBy")
        for bad in ("/home/ubuntu/worktrees", "gen-1d9a377fa00c",
                    "/home/ubuntu/.hermes/hermes-agent/venv",
                    "cutover_.py", "/opt/hermes-maintenance",
                    "systemctl restart", "Restart="):
            if bad in text:
                raise ValueError("mount forbidden " + bad)
    return True
