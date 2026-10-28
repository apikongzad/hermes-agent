"""Pins and legal states for hermetic external operator."""

TARGET_SHA = "daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06"
KNOWN_GOOD_SHA = "1d9a377fa00ce0e663e274e16b63c75e36233b9e"
REFUSED_SHA = "1c12738cfeecc78570b3a4ba3797a49de59cfdfe"

GATEWAY_RUNTIME_SHA256 = "2a495ff333ffdc6b0b61aeab46718ad135e1bd107754b634b82c0445d68cc9eb"
GATEWAY_RUNTIME_SIZE = 74
DASHBOARD_RUNTIME_SHA256 = "aa6d8c52fae720306ded7c9b4b037b33efa48026837484a3b487d9f4a647ffed"
DASHBOARD_RUNTIME_SIZE = 124

DESIGN_BASE_SHA256 = "70fc9debac3bdf25b2a52d6413a8bc42e03d00fd38a925faf33b98e7a39c18c9"
DESIGN_ADDENDUM_SHA256 = "ba9791ac89a15b2820f8d9cd8686ef67ef903833bab2eaf62c592da75bbab9fd"

JOURNAL_DIR = "/var/lib/hermes-stock-activation"
BACKING_DIR = "/var/lib/hermes-stock-activation/backing"
KNOWN_GOOD_SNAPSHOT = "/var/lib/hermes-stock-activation/backing/known-good-snap"
CANDIDATE_SNAPSHOT = "/var/lib/hermes-stock-activation/backing/candidate-snap"

GATEWAY_RUNTIME_PATH = "/etc/systemd/system/hermes-gateway.service.d/zz-runtime-3.14.9.conf"
DASHBOARD_RUNTIME_PATH = "/etc/systemd/system/hermes-dashboard.service.d/zz-runtime-3.14.9.conf"
GATEWAY_CANDIDATE_PATH = "/etc/systemd/system/hermes-gateway.service.d/zzz-candidate.conf"
DASHBOARD_CANDIDATE_PATH = "/etc/systemd/system/hermes-dashboard.service.d/zzz-candidate.conf"

WORKTREE_PATH = "/home/ubuntu/worktrees/worktrees/hermes-upstream-integrate-20261025"
GEN_KNOWN_GOOD = "gen-1d9a377fa00c"
GEN_CANDIDATE = "gen-daec3cd4c6d3"
CANDIDATE_INPUT_PATH = "/home/ubuntu/.hermes/runtime/stock-candidates/daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06"

ENV_FILE_PATH = "/home/ubuntu/.hermes/.env"
VENV_OLD = "/home/ubuntu/.hermes/hermes-agent/venv"

GATEWAY_WD = "/home/ubuntu/.hermes"
DASHBOARD_WD = "/home/ubuntu"

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

LEGAL_STATES = (
    "observed",
    "dropins-read",
    "target-bound",
    "known-good-frozen",
    "backup-verified",
    "candidate-materialized",
    "stop-fenced",
    "units-published",
    "reloaded",
    "restarted",
    "health-verified",
    "committed",
    "rolling-back",
    "rolled-back",
    "durable-state-unknown",
    "stopped-unresolved",
    "blocked-unread",
)

LEGAL_NEXT = {
    "observed": ("dropins-read", "blocked-unread", "stopped-unresolved"),
    "dropins-read": ("target-bound", "blocked-unread", "stopped-unresolved"),
    "target-bound": ("known-good-frozen", "stopped-unresolved"),
    "known-good-frozen": ("backup-verified", "durable-state-unknown", "stopped-unresolved"),
    "backup-verified": ("candidate-materialized", "stopped-unresolved"),
    "candidate-materialized": ("stop-fenced", "durable-state-unknown", "stopped-unresolved"),
    "stop-fenced": ("units-published", "rolling-back", "stopped-unresolved", "durable-state-unknown"),
    "units-published": ("reloaded", "rolling-back", "durable-state-unknown"),
    "reloaded": ("restarted", "rolling-back", "durable-state-unknown"),
    "restarted": ("health-verified", "rolling-back", "durable-state-unknown", "stopped-unresolved"),
    "health-verified": ("committed", "rolling-back"),
    "committed": (),
    "rolling-back": ("rolled-back", "durable-state-unknown", "stopped-unresolved"),
    "rolled-back": (),
    "durable-state-unknown": ("stop-fenced", "stopped-unresolved"),
    "stopped-unresolved": (),
    "blocked-unread": (),
}


def is_legal_transition(frm, to):
    return to in LEGAL_NEXT.get(frm, ())
