"""Recovery supervision. Stdlib only.

The external operator is the recovery launcher: each argv exits, no daemon.
Interruption recovery re-reads the journal plus physical state and re-enters
the 5s fence before any publish/restore/start. Journal never deleted.
A second start while identity ambiguous is forbidden.

Supervision is owned by systemd: the cutover oneshot carries
OnFailure to the recover service, and a timer re-invokes recovery after
interruption. Unit text is verified code, not merely a path.

Fail-closed semantics (reviewer-requested, narrow addendum to §10):
Condition*=skip-with-success is FORBIDDEN here. A missing mount or image
must FAIL the cutover unit (Assert*=failed, OnFailure fires) rather than
skip with exit 0 and a false success claim. The recover unit itself carries
NO mount Requires/Condition/Assert so it can always ExecStart and emit a
stopped-unresolved receipt after reading physical state, even when mounts
or images are broken. Mount units use AssertPathExists (fail, not skip)
and correct systemd-escaped names so systemd-analyze verify passes offline.
Boot ordering (mount Before cutover/recover/gateway/dashboard) plus cutover
Requires+Assert ensures services cannot start invalid images, while recover
stays independent and always able to report.
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
# Systemd-escaped mount names (systemd-escape -p --suffix=mount <Where>).
# Custom short names FAIL systemd-analyze verify (Where mismatch). Use raw
# strings so the literal backslash-x2d escapes survive Python parsing.
KNOWN_GOOD_MOUNT_UNIT = r"run-hermes\x2dstock\x2dactivation-known\x2dgood\x2dsnap.mount"
CANDIDATE_MOUNT_UNIT = r"run-hermes\x2dstock\x2dactivation-candidate\x2dsnap.mount"
GATEWAY_UNIT = "hermes-gateway.service"
DASHBOARD_UNIT = "hermes-dashboard.service"

PYTHON_BIN = "/usr/bin/python3.12"

# Fixed recovery argv: python -I recovery program, no worktree, no restart.
RECOVERY_ARGV = [PYTHON_BIN, "-I", RECOVERY_PROGRAM, "recover"]
APPLY_ARGV = [PYTHON_BIN, "-I", RECOVERY_PROGRAM, "apply"]


def _cutover_after():
    return (f"After=network.target {KNOWN_GOOD_MOUNT_UNIT} "
            f"{CANDIDATE_MOUNT_UNIT}")


def _cutover_requires():
    return (f"Requires={KNOWN_GOOD_MOUNT_UNIT} "
            f"{CANDIDATE_MOUNT_UNIT}")


def _recover_after():
    # Recover stays independent: ordered after network only, NO mount
    # After/Requires/Condition/Assert. Mount units still carry
    # Before=recover for boot ordering, but recover never blocks on mounts
    # so it can always ExecStart and emit a receipt. After alone would not
    # block either, but omitting mount deps entirely is the clearest
    # independence contract and avoids any Assert on recovery itself that
    # would prevent the receipt.
    return "After=network.target"


def cutover_service_unit():
    # §10 exact + narrow fail-closed addendum: root-owned 0644 uid 0
    # (install metadata, not text), program 0500 uid 0, dir 0500 uid 0,
    # interpreter fixed /usr/bin/python3.12 -I, Type oneshot,
    # RemainAfterExit no, Restart=no explicit, NoNewPrivileges, PrivateTmp,
    # timeouts. Mount deps: After+Requires both escaped mounts, Assert (NOT
    # Condition) for both snaps + both backing images so missing prereq
    # FAILS (failed + OnFailure) instead of skipping with success.
    # OnFailure recover (no loop elsewhere). No systemctl restart argv;
    # only stop/show/sleep5/daemon-reload/show/start via G3 launcher in the
    # program, never in units.
    return (
        "[Unit]\n"
        "Description=Hermes stock cutover transaction (oneshot, external root)\n"
        f"{_cutover_after()}\n"
        f"{_cutover_requires()}\n"
        f"AssertPathIsMountPoint={KNOWN_GOOD_MOUNT}\n"
        f"AssertPathIsMountPoint={CANDIDATE_MOUNT}\n"
        f"AssertPathExists={KNOWN_GOOD_IMAGE}\n"
        f"AssertPathExists={CANDIDATE_IMAGE}\n"
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
    # §10 exact + narrow fail-closed addendum: NO mount Requires/Condition/
    # Assert here (unlike cutover). Recover must ExecStart even when mounts
    # or images are broken so the program can read journal + physical state
    # (show/file_info/digest) and emit a stopped-unresolved receipt, never
    # a false success and never a second start while ambiguous. An Assert
    # on recovery itself would prevent that receipt, so it is forbidden.
    # Boot ordering still holds via mount Before=recover; independence is
    # via absence of Requires/Assert here. No OnFailure (no loop).
    # Same hardening/timeouts as cutover.
    return (
        "[Unit]\n"
        "Description=Hermes stock cutover recovery (fence re-verify, no second start while ambiguous)\n"
        f"{_recover_after()}\n"
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
    # §10 exact + narrow fail-closed addendum: squashfs read-only mount:
    # What backing image, Where snap, Type squashfs, Options ro,nosuid,nodev
    # (flag word 7, no rw/noexec/remount/bind). Before cutover/recover/
    # gateway/dashboard so /run mounts recreate read-only BEFORE any service
    # ExecStart. AssertPathExists (NOT Condition) so a missing image FAILS
    # the mount instead of skipping with success; cutover then fails via
    # Requires+Assert and OnFailure fires recover, which itself stays
    # independent and emits an unresolved receipt per §2.3-§2.5, never a
    # fake future-reboot success. Unit filename must be the systemd-escaped
    # KNOWN_GOOD_MOUNT_UNIT or systemd-analyze verify refuses.
    return (
        "[Unit]\n"
        "Description=Hermes stock known-good squashfs (read-only)\n"
        f"AssertPathExists={KNOWN_GOOD_IMAGE}\n"
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
    # Same fail-closed contract as known-good: Assert, not Condition.
    return (
        "[Unit]\n"
        "Description=Hermes stock candidate squashfs (read-only)\n"
        f"AssertPathExists={CANDIDATE_IMAGE}\n"
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


def unit_template_sha():
    # Deterministic binding of the rendered unit templates for the external
    # REVIEWED pin (operator mints after exact review, code never hardcodes
    # its own hash). Concatenates the five rendered texts in fixed order.
    import hashlib as _hl
    blob = (
        cutover_service_unit()
        + "\n---recover---\n" + recover_service_unit()
        + "\n---timer---\n" + recover_timer_unit()
        + "\n---kg---\n" + known_good_mount_unit()
        + "\n---cd---\n" + candidate_mount_unit()
    ).encode("utf-8")
    return _hl.sha256(blob).hexdigest()


def unit_filenames():
    # Exact filenames for offline systemd-analyze verify (no install).
    # Mount filenames must equal the escaped unit names or verify refuses
    # with Where mismatch.
    return {
        CUTOVER_SERVICE_NAME: cutover_service_unit(),
        RECOVER_SERVICE_NAME: recover_service_unit(),
        RECOVER_TIMER_NAME: recover_timer_unit(),
        KNOWN_GOOD_MOUNT_UNIT: known_good_mount_unit(),
        CANDIDATE_MOUNT_UNIT: candidate_mount_unit(),
    }


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
    # Condition* is FORBIDDEN in supervision: skip-with-success would hide
    # a missing mount/image as exit 0 with no OnFailure and no receipt.
    # Fail-closed uses Assert* (failed + OnFailure) for cutover and NO
    # mount gate at all for recover (so recover can emit the receipt).
    for t in (cutover_text, recover_text):
        for line in t.splitlines():
            s = line.strip()
            if s.startswith("Condition"):
                raise ValueError("Condition forbidden, use Assert or no gate: " + s)
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
    # Cutover: After+Requires both escaped mounts, Assert both snaps+images.
    if KNOWN_GOOD_MOUNT_UNIT not in cutover_text or CANDIDATE_MOUNT_UNIT not in cutover_text:
        raise ValueError("cutover mount deps required")
    _req_ok = False
    for line in cutover_text.splitlines():
        s = line.strip()
        if s.startswith("Requires="):
            if KNOWN_GOOD_MOUNT_UNIT in s and CANDIDATE_MOUNT_UNIT in s:
                _req_ok = True
    if not _req_ok:
        raise ValueError("cutover Requires both mounts required")
    if f"AssertPathIsMountPoint={KNOWN_GOOD_MOUNT}" not in cutover_text:
        raise ValueError("cutover AssertPathIsMountPoint known-good required")
    if f"AssertPathIsMountPoint={CANDIDATE_MOUNT}" not in cutover_text:
        raise ValueError("cutover AssertPathIsMountPoint candidate required")
    if f"AssertPathExists={KNOWN_GOOD_IMAGE}" not in cutover_text:
        raise ValueError("cutover AssertPathExists known-good required")
    if f"AssertPathExists={CANDIDATE_IMAGE}" not in cutover_text:
        raise ValueError("cutover AssertPathExists candidate required")
    # Recover: independent. NO Requires, NO Assert, NO Condition on mounts/
    # images so a broken mount cannot block the receipt. An Assert on
    # recovery itself would prevent ExecStart and hide physical state.
    if "Requires=" in recover_text:
        raise ValueError("recover must not have Requires (must stay runnable when mounts broken)")
    if "Assert" in recover_text:
        raise ValueError("recover must not have Assert (would prevent receipt)")
    if KNOWN_GOOD_MOUNT_UNIT in recover_text or CANDIDATE_MOUNT_UNIT in recover_text:
        raise ValueError("recover must not reference mount units (independent)")
    if KNOWN_GOOD_MOUNT in recover_text or CANDIDATE_MOUNT in recover_text:
        raise ValueError("recover must not gate on snap paths")
    if KNOWN_GOOD_IMAGE in recover_text or CANDIDATE_IMAGE in recover_text:
        raise ValueError("recover must not gate on image paths")
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
        for line in text.splitlines():
            if line.strip().startswith("Condition"):
                raise ValueError("mount Condition forbidden, use Assert: " + line.strip())
        if f"AssertPathExists={img}" not in text:
            raise ValueError("mount AssertPathExists required")
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
