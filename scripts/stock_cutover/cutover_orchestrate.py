"""Production cutover orchestrator. Stdlib only.

Implements accepted addendum single order with exact unit bytes, fence,
health, rollback. No systemctl restart. No kill. No .env read. No worktree
start. Journal never deleted. Fsync OSError -> durable-state-unknown.
"""

TARGET_SHA = "daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06"
KNOWN_GOOD_SHA = "1d9a377fa00ce0e663e274e16b63c75e36233b9e"
REFUSED_SHA = "1c12738cfeecc78570b3a4ba3797a49de59cfdfe"

GATEWAY_RUNTIME_PATH = (
    "/etc/systemd/system/hermes-gateway.service.d/zz-runtime-3.14.9.conf"
)
DASHBOARD_RUNTIME_PATH = (
    "/etc/systemd/system/hermes-dashboard.service.d/zz-runtime-3.14.9.conf"
)
GATEWAY_RUNTIME_SHA256 = (
    "2a495ff333ffdc6b0b61aeab46718ad135e1bd107754b634b82c0445d68cc9eb"
)
DASHBOARD_RUNTIME_SHA256 = (
    "aa6d8c52fae720306ded7c9b4b03733efa48036a4b038d497b9f4a647ffed"
)
GATEWAY_RUNTIME_SIZE = 74
DASHBOARD_RUNTIME_SIZE = 124

JOURNAL_DIR = "/var/lib/hermes-stock-activation"
BACKING_DIR = "/var/lib/hermes-stock-activation/backing"
KNOWN_GOOD_SNAPSHOT = "/run/hermes-stock-activation/known-good-snap"
CANDIDATE_SNAPSHOT = "/run/hermes-stock-activation/candidate-snap"

GATEWAY_CANDIDATE_PATH = (
    "/etc/systemd/system/hermes-gateway.service.d/zzz-candidate.conf"
)
DASHBOARD_CANDIDATE_PATH = (
    "/etc/systemd/system/hermes-dashboard.service.d/zzz-candidate.conf"
)
GATEWAY_UNIT = "hermes-gateway.service"
DASHBOARD_UNIT = "hermes-dashboard.service"
BOTH = [GATEWAY_UNIT, DASHBOARD_UNIT]
WORKTREE_PATH = (
    "/home/ubuntu/worktrees/worktrees/hermes-upstream-integrate-20261025"
)
GEN_KNOWN_GOOD = "gen-1d9a377fa00c"
VENV_OLD = "/home/ubuntu/.hermes/hermes-agent/venv"
ENV_FILE_PATH = "/home/ubuntu/.hermes/.env"
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


def _gateway_exec(mount):
    return (
        f"{mount}/venv/bin/python3 -I "
        f"{mount}/source/hermes_cli/main.py gateway run"
    )


def _dashboard_exec(mount):
    return (
        f"{mount}/venv/bin/python3 -I "
        f"{mount}/source/hermes_cli/main.py "
        "dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build"
    )


def _render_gateway_dropin(mount):
    lines = [
        "[Service]",
        "ExecStart=",
        f"ExecStart={_gateway_exec(mount)}",
        "ExecStop=",
        "ExecStopPost=",
        f"WorkingDirectory={GATEWAY_WD}",
        "EnvironmentFile=",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _render_dashboard_dropin(mount):
    lines = [
        "[Service]",
        "ExecStart=",
        f"ExecStart={_dashboard_exec(mount)}",
        "ExecStop=",
        "ExecStopPost=",
        f"WorkingDirectory={DASHBOARD_WD}",
        "EnvironmentFile=",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _validate_dropin_bytes(data, mount, working_dir):
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("dropin type")
    text = bytes(data).decode("utf-8")
    if "[Service]" not in text:
        raise ValueError("missing Service")
    for needle in ("ExecStart=\n", "ExecStop=\n", "ExecStopPost=\n",
                   "EnvironmentFile=\n"):
        if needle not in text:
            raise ValueError("missing reset " + needle.strip())
    if f"ExecStart={mount}/venv/bin/python3 -I " not in text:
        raise ValueError("ExecStart not snapshot python -I")
    if f"WorkingDirectory={working_dir}" not in text:
        raise ValueError("WorkingDirectory")
    for bad in (WORKTREE_PATH, GEN_KNOWN_GOOD, VENV_OLD, ENV_FILE_PATH,
                "/opt/hermes-maintenance", "cutover_"):
        if bad in text:
            raise ValueError("forbidden content " + bad)
    for key in FORBIDDEN_LOADER_KEYS:
        if key + "=" in text:
            raise ValueError("forbidden loader " + key)
    if "PYTHONPATH" in text:
        raise ValueError("PYTHONPATH")
    if text.count("ExecStart=") != 2:
        raise ValueError("ExecStart count")
    return True

DASHBOARD_URL = "http://127.0.0.1:9119/api/health"
GATEWAY_REQUEST_BYTES = b'{"verb":"identify","id":1,"protocol":1}\n'

HAPPY = [
    "observed", "dropins-read", "target-bound", "known-good-frozen",
    "backup-verified", "candidate-materialized", "stop-fenced",
    "units-published", "reloaded", "restarted",
    "health-verified", "committed",
]

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


class _ProcIdentityUnknown(Exception):
    pass


class Request:
    def __init__(self, target_sha):
        if not isinstance(target_sha, str) or not target_sha:
            raise ValueError("target_sha")
        self.target_sha = target_sha


class Receipt:
    def __init__(self, state, journal, reason=None):
        self.state = state
        self.journal = list(journal)
        self.reason = reason


def _split_result(result):
    if not isinstance(result, str):
        return str(result), None
    if ":" in result:
        state, reason = result.split(":", 1)
        return state.strip(), (reason.strip() or None)
    return result, None


def _journal_states(host):
    raw = host.journal_load()
    out = []
    for e in raw:
        if isinstance(e, str):
            out.append(e)
        elif isinstance(e, dict):
            for k in ("state", "event", "step", "name"):
                if k in e and isinstance(e[k], str):
                    out.append(e[k])
                    break
        else:
            try:
                out.append(str(e))
            except Exception:
                pass
    return out


def _append(host, state):
    host.journal_append(state)
    host.journal_load()


def _inactive(u):
    if isinstance(u, dict):
        active = u.get("ActiveState", u.get("active_state", u.get("active")))
        pid = u.get("MainPID", u.get("main_pid", u.get("MainPid")))
        nrest = u.get("NRestarts", u.get("n_restarts", u.get("NRestarts")))
        return active, pid, nrest
    active = getattr(u, "ActiveState", getattr(u, "active", None))
    pid = getattr(u, "MainPID", getattr(u, "main_pid", None))
    nrest = getattr(u, "NRestarts", getattr(u, "n_restarts", None))
    return active, pid, nrest


def _fence(host):
    try:
        host.stop_units(BOTH)
        a0 = host.show_unit(GATEWAY_UNIT)
        b0 = host.show_unit(DASHBOARD_UNIT)
    except OSError:
        return False
    ag0, ap0, an0 = _inactive(a0)
    bg0, bp0, bn0 = _inactive(b0)
    if ag0 != "inactive" or ap0 != 0:
        return False
    if bg0 != "inactive" or bp0 != 0:
        return False
    try:
        t0 = host.now()
        host.sleep_secs(5)
        t1 = host.now()
    except OSError:
        return False
    if t1 - t0 < 5:
        return False
    try:
        a1 = host.show_unit(GATEWAY_UNIT)
        b1 = host.show_unit(DASHBOARD_UNIT)
    except OSError:
        return False
    ag1, ap1, an1 = _inactive(a1)
    bg1, bp1, bn1 = _inactive(b1)
    if ag1 != "inactive" or ap1 != 0:
        return False
    if bg1 != "inactive" or bp1 != 0:
        return False
    if an1 != an0 or bn1 != bn0:
        return False
    return True


def _unit_field(u, *names):
    if isinstance(u, dict):
        for n in names:
            if n in u:
                return u[n]
        return None
    for n in names:
        if hasattr(n, n):
            pass
    for n in names:
        if hasattr(u, n):
            return getattr(u, n)
    return None


def _check_denial(host, path):
    try:
        d = host.denial_probe(path)
    except OSError:
        return False
    if isinstance(d, dict):
        get = d.get
    else:
        get = lambda k, default=None: getattr(d, k, default)
    for k in ("kernel_enforced", "write_denied", "rename_denied",
              "hardlink_denied", "second_write_denied",
              "second_rename_denied", "second_hardlink_denied"):
        v = get(k) if isinstance(d, dict) else getattr(d, k, None)
        if v is not True:
            return False
    return True


def _check_python(host, py_path, snapshot):
    try:
        p = host.python_probe(py_path)
    except OSError:
        return False
    if isinstance(p, dict):
        def g(k, default=None):
            return p.get(k, default)
    else:
        def g(k, default=None):
            return getattr(p, k, default)
    if g("isolated") != 1:
        return False
    if g("ignore_environment") != 1:
        return False
    if g("safe_path") is not True:
        return False
    if g("no_site") != 0:
        return False
    if not g("import_ok"):
        return False
    origin = g("sitecustomize_origin")
    if origin is not None and not (isinstance(origin, str) and origin.startswith(snapshot)):
        return False
    if g("sys_path_has_cwd") is not False:
        return False
    vv = g("pyvenv_version")
    if vv != "3.14.9" and vv != (3, 14, 9):
        return False
    return True


def _check_digest(host):
    try:
        r = host.digest_record()
    except OSError:
        return False
    if isinstance(r, dict):
        def g(k, default=None):
            return r.get(k, default)
    else:
        def g(k, default=None):
            return getattr(r, k, default)
    signed = g("signed", None)
    if signed is None:
        return False
    if signed:
        return False
    owner = g("owner_uid", g("owner", None))
    if owner != 0:
        return False
    for k in ("outside_snapshot", "outside_uid1001"):
        v = g(k, "MISSING")
        if v == "MISSING":
            continue
        if not v:
            return False
    return True


def _parent_dir(path):
    if "/" in path:
        return path.rsplit("/", 1)[0] or "/"
    return "."


def _publish_snapshot(host, snapshot_str):
    gw_body = _render_gateway_dropin(snapshot_str)
    db_body = _render_dashboard_dropin(snapshot_str)
    _validate_dropin_bytes(gw_body, snapshot_str, GATEWAY_WD)
    _validate_dropin_bytes(db_body, snapshot_str, DASHBOARD_WD)
    for dest, body in ((GATEWAY_CANDIDATE_PATH, gw_body),
                       (DASHBOARD_CANDIDATE_PATH, db_body)):
        parent = _parent_dir(dest)
        if dest == GATEWAY_CANDIDATE_PATH:
            tmp = "/etc/systemd/system/hermes-gateway.service.d/.zzz-candidate.conf.tmp"
        else:
            tmp = parent + "/.zzz-candidate.conf.tmp"
        host.write_temp(tmp, body)
        host.file_fsync(tmp)
        host.rename_path(tmp, dest)
        host.dir_fsync(parent)


def _identity_ok(host, snapshot_str, worktree_path):
    for unit in BOTH:
        try:
            u = host.show_unit(unit)
        except OSError:
            raise _ProcIdentityUnknown
        pid = _unit_field(u, "MainPID", "main_pid", "MainPid", "pid")
        try:
            ident = host.proc_identity(pid)
        except OSError:
            raise _ProcIdentityUnknown
        if ident is None:
            raise _ProcIdentityUnknown
        if isinstance(ident, dict):
            exe = ident.get("exe", "") or ""
            cmd = ident.get("cmdline", "") or ""
            if isinstance(cmd, (list, tuple)):
                cmd = " ".join(cmd)
        else:
            exe = getattr(ident, "exe", "") or ""
            cmd = getattr(ident, "cmdline", "") or ""
            if isinstance(cmd, (list, tuple)):
                cmd = " ".join(cmd)
        exe_s, cmd_s = str(exe), str(cmd)
        if snapshot_str not in exe_s or snapshot_str not in cmd_s:
            return False
        if worktree_path and (worktree_path in exe_s or worktree_path in cmd_s):
            return False
        if GEN_KNOWN_GOOD in exe_s or GEN_KNOWN_GOOD in cmd_s:
            return False
    return True


def _forbidden_loader_present(host):
    forbidden = FORBIDDEN_LOADER_KEYS
    try:
        forbidden_set = set(forbidden)
    except TypeError:
        return False
    for unit in BOTH:
        try:
            u = host.show_unit(unit)
        except OSError:
            raise _ProcIdentityUnknown
        pid = _unit_field(u, "MainPID", "main_pid", "MainPid", "pid")
        try:
            ident = host.proc_identity(pid)
        except OSError:
            raise _ProcIdentityUnknown
        if ident is None:
            raise _ProcIdentityUnknown
        if isinstance(ident, dict):
            keys = ident.get("environ_keys", ident.get("environ", []))
        else:
            keys = getattr(ident, "environ_keys", getattr(ident, "environ", []))
        if not keys:
            continue
        try:
            for k in keys:
                name = k if isinstance(k, str) else str(k)
                if name in forbidden_set:
                    return True
        except TypeError:
            continue
    return False


def dashboard_ok(status, content_type, body):
    if status != 200:
        return False
    ctype = (content_type or "").lower()
    if "application/json" not in ctype:
        return False
    if not isinstance(body, dict):
        return False
    return body.get("ok") is True


def gateway_ok(response, peer_pid, peer_uid, expected_pid):
    if not isinstance(response, dict):
        return False
    if response.get("ok") is not True:
        return False
    result = response.get("result")
    if not isinstance(result, dict):
        return False
    if result.get("protocol") != 1:
        return False
    if result.get("pid") != expected_pid:
        return False
    if peer_pid != expected_pid:
        return False
    if peer_uid != 1001:
        return False
    return True


def _health_ok(host):
    try:
        resp = host.dashboard_fetch(DASHBOARD_URL, {})
    except OSError:
        return False
    if not isinstance(resp, dict):
        return False
    if not dashboard_ok(resp.get("status"), resp.get("content_type"), resp.get("body")):
        return False
    try:
        gw = host.gateway_talk(GATEWAY_REQUEST_BYTES)
    except OSError:
        return False
    if not isinstance(gw, dict):
        return False
    try:
        expected = _unit_field(host.show_unit(GATEWAY_UNIT), "MainPID", "main_pid", "MainPid")
    except OSError:
        return False
    return bool(gateway_ok(gw.get("response"), gw.get("peer_pid"), gw.get("peer_uid"), expected))


def _do_reload_checks(host):
    try:
        host.reload_manager()
        gu = host.show_unit(GATEWAY_UNIT)
        du = host.show_unit(DASHBOARD_UNIT)
    except OSError:
        return ("stopped-unresolved", "reload-unreadable")
    for u in (gu, du):
        ef = _unit_field(u, "EnvironmentFiles", "environment_files", "env_files")
        if ef:
            return ("stopped-unresolved", "missing-loader-evidence")
        for attr in ("ExecStop", "ExecStopPost", "exec_stop", "exec_stop_post"):
            v = _unit_field(u, attr)
            if v is None:
                continue
            s = str(v) if not isinstance(v, list) else " ".join(str(x) for x in v)
            if VENV_OLD in s:
                return ("no-start", "execstop-venv")
    return ("ok", "")


def _rollback(host, candidate_snapshot, known_good_snapshot, worktree_path):
    if not _fence(host):
        return "fence-failed"
    try:
        ki = host.file_info(known_good_snapshot)
    except OSError:
        return "stopped-unresolved"
    if isinstance(ki, dict):
        exists = ki.get("exists", True)
        w = ki.get("writable_by_1001", ki.get("writable_by_uid1001", False))
    else:
        exists = getattr(ki, "exists", True)
        w = getattr(ki, "writable_by_1001", False)
    if exists is False:
        return "stopped-unresolved"
    if w:
        return "stopped-unresolved"
    prefix = "/run/hermes-stock-activation/"
    if not isinstance(known_good_snapshot, str) or not known_good_snapshot.startswith(prefix):
        return "stopped-unresolved"
    if worktree_path and worktree_path in known_good_snapshot:
        return "stopped-unresolved"
    if GEN_KNOWN_GOOD in known_good_snapshot:
        return "stopped-unresolved"
    uid = ki.get("uid") if isinstance(ki, dict) else getattr(ki, "uid", None)
    if uid != 0:
        return "stopped-unresolved"
    try:
        if not _check_denial(host, known_good_snapshot):
            return "stopped-unresolved"
    except OSError:
        return "stopped-unresolved"
    try:
        _publish_snapshot(host, known_good_snapshot)
    except OSError:
        _append(host, "durable-state-unknown: rollback-publish indeterminate")
        return "durable-state-unknown"
    try:
        _append(host, "rolling-back")
    except OSError:
        return "durable-state-unknown"
    try:
        host.reload_manager()
        host.start_units(BOTH)
    except OSError:
        return "stopped-unresolved"
    try:
        ident_ok = _identity_ok(host, known_good_snapshot, worktree_path)
        forbidden = _forbidden_loader_present(host)
    except _ProcIdentityUnknown:
        return "stopped-unresolved"
    if not ident_ok or forbidden:
        return "stopped-unresolved"
    if not _health_ok(host):
        return "stopped-unresolved"
    _append(host, "rolled-back")
    return "rolled-back"


def _orchestrate_impl(host, target_sha=None):
    if target_sha is None:
        target_sha = TARGET_SHA
    states = _journal_states(host)
    if states:
        _last_base = states[-1].split(":")[0].strip() if isinstance(states[-1], str) else states[-1]
        if _last_base == "rolling-back":
            return "stopped-unresolved"
    if states and states[-1] == "committed":
        return "committed"
    for s in states:
        if isinstance(s, str) and s.startswith("durable-state-unknown"):
            return s
    for i, s in enumerate(states):
        base = s.split(":")[0].strip() if isinstance(s, str) else s
        if base in ("refused", "blocked-unread", "rolled-back", "stopped-unresolved"):
            continue
        if base in HAPPY:
            continue
        if base in ("stop-fenced", "units-published", "reloaded", "restarted"):
            continue
        return "stopped-unresolved"
    happy_seen = []
    for s in states:
        base = s.split(":")[0].strip() if isinstance(s, str) else s
        if base in HAPPY:
            happy_seen.append(base)
    for idx, val in enumerate(happy_seen):
        if idx >= len(HAPPY) or HAPPY[idx] != val:
            return "stopped-unresolved"
    if target_sha != TARGET_SHA:
        return "refused"
    try:
        jdi = host.journal_dir_info()
        if isinstance(jdi, dict):
            pw = jdi.get("parent_writable_by_1001", False)
        else:
            pw = getattr(jdi, "parent_writable_by_1001", False)
        if pw:
            return "stopped-unresolved: parent writable"
    except OSError:
        return "stopped-unresolved"
    last = states[-1].split(":")[0].strip() if states else None
    try:
        gi = host.file_info(GATEWAY_RUNTIME_PATH)
        di = host.file_info(DASHBOARD_RUNTIME_PATH)
    except PermissionError:
        _append(host, "blocked-unread")
        return "blocked-unread"
    except OSError:
        _append(host, "blocked-unread")
        return "blocked-unread"

    def _info_ok(info, want_sha, want_size):
        if isinstance(info, dict):
            sha = info.get("sha256", info.get("sha", ""))
            sz = info.get("size", info.get("length", None))
        else:
            sha = getattr(info, "sha256", getattr(info, "sha", ""))
            sz = getattr(info, "size", getattr(info, "length", None))
        if sha != want_sha:
            return False
        if want_size is not None and sz != want_size:
            return False
        return True

    if not _info_ok(gi, GATEWAY_RUNTIME_SHA256, 74):
        _append(host, "blocked-unread")
        return "blocked-unread"
    if not _info_ok(di, DASHBOARD_RUNTIME_SHA256, 124):
        _append(host, "blocked-unread")
        return "blocked-unread"
    cur = _journal_states(host)
    if not cur:
        _append(host, "observed")
        cur = _journal_states(host)
    cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] == "observed":
        try:
            host.dropin_names(GATEWAY_UNIT)
            host.dropin_names(DASHBOARD_UNIT)
        except OSError:
            _append(host, "blocked-unread")
            return "blocked-unread"
        _append(host, "dropins-read")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] == "dropins-read":
        _append(host, "target-bound")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] == "restarted":
        try:
            ident_ok = _identity_ok(host, CANDIDATE_SNAPSHOT, WORKTREE_PATH)
            forbidden = _forbidden_loader_present(host)
        except _ProcIdentityUnknown:
            return "stopped-unresolved"
        if not ident_ok:
            return _rollback(host, CANDIDATE_SNAPSHOT, KNOWN_GOOD_SNAPSHOT, WORKTREE_PATH)
        if forbidden:
            return _rollback(host, CANDIDATE_SNAPSHOT, KNOWN_GOOD_SNAPSHOT, WORKTREE_PATH)
        if not _health_ok(host):
            return _rollback(host, CANDIDATE_SNAPSHOT, KNOWN_GOOD_SNAPSHOT, WORKTREE_PATH)
        _append(host, "health-verified")
        _append(host, "committed")
        return "committed"
    if "known-good-frozen" not in cur_bases:
        try:
            tmp = BACKING_DIR + "/.known-good.tmp"
            host.write_temp(tmp, b"known-good")
            host.file_fsync(tmp)
            host.rename_path(tmp, BACKING_DIR + "/known-good-frozen-marker")
            host.dir_fsync(BACKING_DIR)
        except OSError:
            _append(host, "durable-state-unknown: indeterminate")
            return "durable-state-unknown: indeterminate"
        _append(host, "known-good-frozen")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if "backup-verified" not in cur_bases:
        try:
            ok = host.backup_ok()
        except OSError:
            ok = False
        if not ok:
            return cur_bases[-1] if cur_bases else "known-good-frozen"
        _append(host, "backup-verified")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if "candidate-materialized" not in cur_bases:
        try:
            tmp = BACKING_DIR + "/.candidate.tmp"
            host.write_temp(tmp, CANDIDATE_SNAPSHOT.encode())
            host.file_fsync(tmp)
            host.rename_path(tmp, BACKING_DIR + "/candidate-materialized-marker")
            host.dir_fsync(BACKING_DIR)
        except OSError:
            _append(host, "durable-state-unknown: candidate indeterminate")
            return "durable-state-unknown: indeterminate"
        if not _check_denial(host, CANDIDATE_SNAPSHOT):
            return cur_bases[-1] if cur_bases else "backup-verified"
        py_path = CANDIDATE_SNAPSHOT + "/venv/bin/python3"
        if not _check_python(host, py_path, CANDIDATE_SNAPSHOT):
            return cur_bases[-1] if cur_bases else "backup-verified"
        if not _check_digest(host):
            return cur_bases[-1] if cur_bases else "backup-verified"
        try:
            g_drop = host.dropin_names(GATEWAY_UNIT)
            d_drop = host.dropin_names(DASHBOARD_UNIT)
        except OSError:
            return cur_bases[-1] if cur_bases else "backup-verified"
        if "zzz-extra.conf" in list(g_drop or []) or "zzz-extra.conf" in list(d_drop or []):
            return cur_bases[-1] if cur_bases else "backup-verified"
        _append(host, "candidate-materialized")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] in ("candidate-materialized", "stop-fenced"):
        if not _fence(host):
            return "fence-failed"
        if cur_bases[-1] != "stop-fenced":
            _append(host, "stop-fenced")
            cur = _journal_states(host)
            cur_bases = [c.split(":")[0].strip() for c in cur]
        # Preserve prior unit bytes as journal evidence (read-only).
        try:
            _gw_prior = host.read_bytes(GATEWAY_CANDIDATE_PATH)
            _db_prior = host.read_bytes(DASHBOARD_CANDIDATE_PATH)
        except OSError:
            _gw_prior, _db_prior = b"", b""
        # Evidence only; never started. (Journal stores state; bytes stay
        # in host for parent audit via readback, not as start source.)
        _ = (_gw_prior, _db_prior)
        try:
            _publish_snapshot(host, CANDIDATE_SNAPSHOT)
        except OSError:
            _append(host, "durable-state-unknown: publish indeterminate")
            return "durable-state-unknown: indeterminate"
        _append(host, "units-published")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] == "units-published":
        if last == "units-published":
            if not _fence(host):
                return "fence-failed"
        res, _reason = _do_reload_checks(host)
        if res == "stopped-unresolved":
            return "stopped-unresolved: missing-loader-evidence"
        if res == "no-start":
            return "stopped-unresolved"
        _append(host, "reloaded")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] == "reloaded":
        try:
            host.start_units(BOTH)
        except OSError:
            return "stopped-unresolved"
        _append(host, "restarted")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] == "restarted":
        try:
            ident_ok = _identity_ok(host, CANDIDATE_SNAPSHOT, WORKTREE_PATH)
            forbidden = _forbidden_loader_present(host)
        except _ProcIdentityUnknown:
            return "stopped-unresolved"
        if not ident_ok:
            return _rollback(host, CANDIDATE_SNAPSHOT, KNOWN_GOOD_SNAPSHOT, WORKTREE_PATH)
        if forbidden:
            return _rollback(host, CANDIDATE_SNAPSHOT, KNOWN_GOOD_SNAPSHOT, WORKTREE_PATH)
        if not _health_ok(host):
            return _rollback(host, CANDIDATE_SNAPSHOT, KNOWN_GOOD_SNAPSHOT, WORKTREE_PATH)
        _append(host, "health-verified")
        _append(host, "committed")
        return "committed"
    if cur_bases and cur_bases[-1] == "health-verified":
        _append(host, "committed")
        return "committed"
    return cur_bases[-1] if cur_bases else "stopped-unresolved"


def orchestrate(host, request=None, target_sha=None):
    if isinstance(request, Request):
        target_sha = request.target_sha
    elif isinstance(request, str) and target_sha is None:
        target_sha = request
    elif request is not None:
        raise TypeError("orchestrate expects Request or target_sha str")
    result = _orchestrate_impl(host, target_sha)
    if isinstance(result, Receipt):
        return result
    state, reason = _split_result(result)
    journal = list(host.journal_load())
    return Receipt(state, journal, reason)


def run(host, *a, **kw):
    return orchestrate(host, *a, **kw)


def main(host, *a, **kw):
    return orchestrate(host, *a, **kw)


def activate(host, *a, **kw):
    return orchestrate(host, *a, **kw)
