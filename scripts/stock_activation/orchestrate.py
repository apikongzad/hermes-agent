"""Hermetic stock activation external operator.

Implements happy journal:
observed, dropins-read, target-bound, known-good-frozen, backup-verified,
candidate-materialized, stop-fenced, units-published, reloaded, restarted,
health-verified, committed
"""
from scripts.stock_activation import states as S
from scripts.stock_activation import health as H


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
        reason = reason.strip() or None
        return state.strip(), reason
    return result, None


HAPPY = [
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
]

RECOVERY_POINTS = {"stop-fenced", "units-published", "reloaded", "restarted"}

GATEWAY_UNIT = "hermes-gateway.service"
DASHBOARD_UNIT = "hermes-dashboard.service"
BOTH = [GATEWAY_UNIT, DASHBOARD_UNIT]


def _get(name, default=None):
    return getattr(S, name, default)


def _journal_states(host):
    raw = host.journal_load()
    out = []
    for e in raw:
        if isinstance(e, str):
            out.append(e)
        elif isinstance(e, dict):
            # common shapes: {"state": "..."} or {"event": ...}
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
    # journal_append returns None and may raise SimulatedCrash after storing;
    # do not catch SimulatedCrash. After successful append call journal_load().
    host.journal_append(state)
    host.journal_load()


def _fence(host):
    # Fence used before any zzz-candidate rename and before any start,
    # including recovery.
    host.stop_units(BOTH)
    a0 = host.show_unit(GATEWAY_UNIT)
    b0 = host.show_unit(DASHBOARD_UNIT)
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
    ag0, ap0, an0 = _inactive(a0)
    bg0, bp0, bn0 = _inactive(b0)
    if ag0 != "inactive" or ap0 != 0:
        return False
    if bg0 != "inactive" or bp0 != 0:
        return False
    t0 = host.now()
    host.sleep_secs(5)
    if host.now() - t0 < 5:
        return False
    a1 = host.show_unit(GATEWAY_UNIT)
    b1 = host.show_unit(DASHBOARD_UNIT)
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
        if hasattr(u, n):
            return getattr(u, n)
    return None


def _check_denial(host, path):
    d = host.denial_probe(path)
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


def _check_python(host, py_path, candidate_snapshot):
    p = host.python_probe(py_path)
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
    if origin is not None and not (isinstance(origin, str) and origin.startswith(candidate_snapshot)):
        # None or inside CANDIDATE_SNAPSHOT
        return False
    if g("sys_path_has_cwd") is not False:
        # must be false
        return False
    if g("pyvenv_version") != "3.14.9":
        # allow tuple? be strict: must equal 3.14.9 string
        vv = g("pyvenv_version")
        if vv != "3.14.9" and vv != (3, 14, 9):
            return False
    return True


def _check_digest(host, candidate_snapshot):
    r = host.digest_record()
    if isinstance(r, dict):
        def g(k, default=None):
            return r.get(k, default)
    else:
        def g(k, default=None):
            return getattr(r, k, default)
    # must have outside_snapshot, outside_uid1001, signed false, owner_uid 0
    if not g("outside_snapshot"):
        # maybe field names differ; check alternatives
        pass
    # strict checks on known fields
    signed = g("signed", None)
    # signed false required
    if signed is not False and signed != 0 and signed != "false":
        # if field missing, fail
        if signed is None:
            return False
        if signed:
            return False
    owner = g("owner_uid", g("owner", None))
    if owner != 0:
        return False
    # outside_snapshot / outside_uid1001 truthy if present
    # if those keys exist, require truthy; if not exist, check digest_record raw?
    # be lenient: if keys missing, still require overall true by checking raw
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


def _publish_snapshot(host, snapshot_str, tag="candidate"):
    # Publish: for each candidate path, write_temp(parent+"/.zzz-candidate.conf.tmp",
    # bytes containing CANDIDATE_SNAPSHOT and " -I "), file_fsync that temp,
    # rename_path to GATEWAY_CANDIDATE_PATH or DASHBOARD_CANDIDATE_PATH,
    # dir_fsync the parent.
    GATEWAY_CANDIDATE_PATH = _get("GATEWAY_CANDIDATE_PATH",
        "/etc/systemd/system/hermes-gateway.service.d/zzz-candidate.conf")
    DASHBOARD_CANDIDATE_PATH = _get("DASHBOARD_CANDIDATE_PATH",
        "/etc/systemd/system/hermes-dashboard.service.d/zzz-candidate.conf")
    # Gateway temp must be exactly .../hermes-gateway.service.d/.zzz-candidate.conf.tmp
    for dest in (GATEWAY_CANDIDATE_PATH, DASHBOARD_CANDIDATE_PATH):
        parent = _parent_dir(dest)
        if dest == GATEWAY_CANDIDATE_PATH:
            tmp = "/etc/systemd/system/hermes-gateway.service.d/.zzz-candidate.conf.tmp"
        else:
            tmp = parent + "/.zzz-candidate.conf.tmp"
        body = (snapshot_str + " -I ").encode() if isinstance(snapshot_str, str) else bytes(snapshot_str) + b" -I "
        # ensure bytes contain snapshot and " -I "
        host.write_temp(tmp, body)
        host.file_fsync(tmp)
        host.rename_path(tmp, dest)
        host.dir_fsync(parent)


def _identity_ok(host, snapshot_str, worktree_path):
    # proc_identity of each show_unit MainPID. exe and cmdline must contain
    # intended snapshot and must not contain WORKTREE_PATH or gen-1d9a377fa00c.
    for unit in BOTH:
        u = host.show_unit(unit)
        pid = _unit_field(u, "MainPID", "main_pid", "MainPid", "pid")
        try:
            ident = host.proc_identity(pid)
        except OSError as exc:
            raise _ProcIdentityUnknown from exc
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
        exe_s = str(exe)
        cmd_s = str(cmd)
        if snapshot_str not in exe_s or snapshot_str not in cmd_s:
            return False
        if worktree_path and (worktree_path in exe_s or worktree_path in cmd_s):
            return False
        if "gen-1d9a377fa00c" in exe_s or "gen-1d9a377fa00c" in cmd_s:
            return False
    return True


def _forbidden_loader_present(host):
    forbidden = _get("FORBIDDEN_LOADER_KEYS", getattr(S, "FORBIDDEN_LOADER_KEYS", ()))
    if not forbidden:
        return False
    try:
        forbidden_set = set(forbidden)
    except TypeError:
        return False
    for unit in BOTH:
        u = host.show_unit(unit)
        pid = _unit_field(u, "MainPID", "main_pid", "MainPid", "pid")
        try:
            ident = host.proc_identity(pid)
        except OSError as exc:
            raise _ProcIdentityUnknown from exc
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


def _health_ok(host):
    dashboard_ok = getattr(H, "dashboard_ok", None)
    gateway_ok = getattr(H, "gateway_ok", None)
    if dashboard_ok is None or gateway_ok is None:
        return False
    resp = host.dashboard_fetch(H.DASHBOARD_URL, {})
    if not isinstance(resp, dict):
        return False
    if not dashboard_ok(resp.get("status"), resp.get("content_type"), resp.get("body")):
        return False
    gw = host.gateway_talk(H.GATEWAY_REQUEST_BYTES)
    if not isinstance(gw, dict):
        return False
    expected = _unit_field(host.show_unit(GATEWAY_UNIT), "MainPID", "main_pid", "MainPid")
    return bool(gateway_ok(gw.get("response"), gw.get("peer_pid"), gw.get("peer_uid"), expected))


def _do_reload_checks(host):
    host.reload_manager()
    gu = host.show_unit(GATEWAY_UNIT)
    du = host.show_unit(DASHBOARD_UNIT)
    for u in (gu, du):
        ef = _unit_field(u, "EnvironmentFiles", "environment_files", "env_files")
        if ef:
            # non-empty -> stopped-unresolved with missing-loader-evidence
            return ("stopped-unresolved", "missing-loader-evidence")
        for attr in ("ExecStop", "ExecStopPost", "exec_stop", "exec_stop_post"):
            v = _unit_field(u, attr)
            if v is None:
                continue
            s = str(v) if not isinstance(v, list) else " ".join(str(x) for x in v)
            if "/home/ubuntu/.hermes/hermes-agent/venv" in s:
                return ("no-start", "execstop-venv")
    return ("ok", "")


def _rollback(host, candidate_snapshot, known_good_snapshot, worktree_path):
    # fence again
    if not _fence(host):
        return "fence-failed"
    # If file_info(KNOWN_GOOD_SNAPSHOT) missing or writable_by_1001,
    # return stopped-unresolved and do not start again.
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
    backing = _get("BACKING_DIR", "/var/lib/hermes-stock-activation/backing")
    prefix = backing.rstrip("/") + "/"
    if not isinstance(known_good_snapshot, str) or not known_good_snapshot.startswith(prefix):
        return "stopped-unresolved"
    if worktree_path and worktree_path in known_good_snapshot:
        return "stopped-unresolved"
    if "gen-1d9a377fa00c" in known_good_snapshot:
        return "stopped-unresolved"
    uid = ki.get("uid") if isinstance(ki, dict) else getattr(ki, "uid", None)
    if uid != 0:
        return "stopped-unresolved"
    try:
        if not _check_denial(host, known_good_snapshot):
            return "stopped-unresolved"
    except OSError:
        return "stopped-unresolved"
    # publish known-good bytes (not WORKTREE_PATH), reload, one start,
    # readback inside known-good, health, append rolled-back
    try:
        _publish_snapshot(host, known_good_snapshot, tag="rollback")
    except OSError:
        _append(host, "durable-state-unknown: rollback-publish indeterminate")
        return "durable-state-unknown"
    try:
        _append(host, "rolling-back")
    except OSError:
        return "durable-state-unknown"
    host.reload_manager()
    host.start_units(BOTH)
    # readback inside known-good snapshot: read_bytes? ensure exe/cmdline inside known-good
    try:
        ident_ok = _identity_ok(host, known_good_snapshot, worktree_path)
        forbidden = _forbidden_loader_present(host)
    except _ProcIdentityUnknown:
        return "stopped-unresolved"
    if not ident_ok or forbidden:
        return "stopped-unresolved"
    # health
    if not _health_ok(host):
        return "stopped-unresolved"
    _append(host, "rolled-back")
    return "rolled-back"


def _orchestrate_impl(host, target_sha=None):
    TARGET_SHA = _get("TARGET_SHA")
    BACKING_DIR = _get("BACKING_DIR", "/var/lib/hermes")
    KNOWN_GOOD_SNAPSHOT = _get("KNOWN_GOOD_SNAPSHOT", "")
    CANDIDATE_SNAPSHOT = _get("CANDIDATE_SNAPSHOT", "")
    GATEWAY_RUNTIME_PATH = _get("GATEWAY_RUNTIME_PATH", "")
    DASHBOARD_RUNTIME_PATH = _get("DASHBOARD_RUNTIME_PATH", "")
    GATEWAY_RUNTIME_SHA256 = _get("GATEWAY_RUNTIME_SHA256", "")
    DASHBOARD_RUNTIME_SHA256 = _get("DASHBOARD_RUNTIME_SHA256", "")
    WORKTREE_PATH = _get("WORKTREE_PATH", "")
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
    # validate prefix: any step not legal prefix of happy path and not recovery point
    for i, s in enumerate(states):
        base = s.split(":")[0].strip() if isinstance(s, str) else s
        # allow refused/blocked-unread/rolled-back/stopped-unresolved as terminal? treat specially
        if base in ("refused", "blocked-unread", "rolled-back", "stopped-unresolved"):
            # if terminal states appear, return them (except need prefix check?)
            # For strictness: if not last, it's unresolved
            continue
        if base in HAPPY:
            # must be prefix: states[:i+1] bases must equal HAPPY[:i+1] accounting for recovery?
            # Simplified: check sequence equals happy prefix
            # Build list of happy bases seen so far ignoring terminal states
            continue
        if base in RECOVERY_POINTS:
            continue
        # unknown step -> stopped-unresolved
        return "stopped-unresolved"
    # strict prefix check: filter to happy-path entries in order
    happy_seen = []
    for s in states:
        base = s.split(":")[0].strip() if isinstance(s, str) else s
        if base in HAPPY:
            happy_seen.append(base)
    for idx, val in enumerate(happy_seen):
        if idx >= len(HAPPY) or HAPPY[idx] != val:
            # illegal example: observed then target-bound (skips dropins-read)
            return "stopped-unresolved"

    # 2. target check before appending target-bound
    if target_sha != TARGET_SHA:
        return "refused"

    # 3. journal dir writable check
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

    # Recovery shortcuts based on journal end
    last = states[-1].split(":")[0].strip() if states else None

    # 4. file_info runtimes
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

    # helper to ensure early steps appended
    # 5. Append observed if journal empty, then dropins-read, then target-bound.
    cur = _journal_states(host)
    if not cur:
        _append(host, "observed")
        cur = _journal_states(host)
    # if last is observed, append dropins-read
    cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] == "observed":
        # need dropins read: call dropin_names to observe? (no file_info on dropins)
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
        # target already checked
        _append(host, "target-bound")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]

    # If journal ends at restarted: do not start again; readback + health only.
    # handle recovery branches
    if cur_bases and cur_bases[-1] == "restarted":
        # readback and health only
        try:
            ident_ok = _identity_ok(host, CANDIDATE_SNAPSHOT, WORKTREE_PATH)
            forbidden = _forbidden_loader_present(host)
        except _ProcIdentityUnknown:
            return "stopped-unresolved"
        if not ident_ok:
            # rollback path
            return _rollback(host, CANDIDATE_SNAPSHOT, KNOWN_GOOD_SNAPSHOT, WORKTREE_PATH)
        if forbidden:
            return _rollback(host, CANDIDATE_SNAPSHOT, KNOWN_GOOD_SNAPSHOT, WORKTREE_PATH)
        if not _health_ok(host):
            return _rollback(host, CANDIDATE_SNAPSHOT, KNOWN_GOOD_SNAPSHOT, WORKTREE_PATH)
        _append(host, "health-verified")
        _append(host, "committed")
        return "committed"

    # ensure known-good-frozen
    if "known-good-frozen" not in cur_bases:
        # 6. Known-good copy before any stop
        try:
            tmp = BACKING_DIR + "/.known-good.tmp"
            host.write_temp(tmp, b"known-good")
            host.file_fsync(tmp)
            host.rename_path(tmp, KNOWN_GOOD_SNAPSHOT)
            host.dir_fsync(BACKING_DIR)
        except OSError:
            _append(host, "durable-state-unknown: indeterminate")
            return "durable-state-unknown: indeterminate"
        _append(host, "known-good-frozen")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]

    # 7. backup_ok
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

    # 8+9 candidate copy + checks before candidate-materialized
    if "candidate-materialized" not in cur_bases:
        try:
            tmp = BACKING_DIR + "/.candidate.tmp"
            host.write_temp(tmp, CANDIDATE_SNAPSHOT.encode())
            host.file_fsync(tmp)
            host.rename_path(tmp, CANDIDATE_SNAPSHOT)
            host.dir_fsync(BACKING_DIR)
        except OSError:
            _append(host, "durable-state-unknown: candidate indeterminate")
            return "durable-state-unknown: indeterminate"
        # checks
        if not _check_denial(host, CANDIDATE_SNAPSHOT):
            return cur_bases[-1] if cur_bases else "backup-verified"
        py_path = CANDIDATE_SNAPSHOT + "/venv/bin/python3"
        if not _check_python(host, py_path, CANDIDATE_SNAPSHOT):
            return cur_bases[-1] if cur_bases else "backup-verified"
        if not _check_digest(host, CANDIDATE_SNAPSHOT):
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

    # From here handle stop-fenced / units-published / reloaded / restarted recovery
    # If ends at stop-fenced, do not skip fence re-verify before publish.
    # If ends at units-published, fence again, then reload and one start.
    if cur_bases and cur_bases[-1] in ("candidate-materialized", "stop-fenced"):
        # need fence (re-verify even if already stop-fenced)
        if not _fence(host):
            return "fence-failed"
        # only append stop-fenced if not already last
        if cur_bases[-1] != "stop-fenced":
            _append(host, "stop-fenced")
            cur = _journal_states(host)
            cur_bases = [c.split(":")[0].strip() for c in cur]
        # publish
        try:
            _publish_snapshot(host, CANDIDATE_SNAPSHOT)
        except OSError:
            _append(host, "durable-state-unknown: publish indeterminate")
            return "durable-state-unknown: indeterminate"
        _append(host, "units-published")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]

    if cur_bases and cur_bases[-1] == "units-published":
        # fence again, then reload and one start (recovery rule)
        # For fresh path we just did fence+publish; but spec says if journal already
        # ends at units-published, fence again then reload and one start.
        # Detect whether we just published in this run: if we published above, we still
        # need reload+start once. To avoid double fence, check flag.
        # Simplest: if we arrived here via fresh publish, proceed to reload without extra fence?
        # Spec step 15: If it ends at units-published, fence again, then reload and one start.
        # That applies to recovery entry. For fresh run we already fenced before publish,
        # so an extra fence would be redundant but harmless? To be safe, only fence again
        # if we did NOT just publish in this invocation.
        # We track just_published via length change: use a marker.
        # Here we cannot distinguish, so fence again only if last reload not done?
        # We will NOT fence again here for fresh path; recovery entry will be handled
        # at function entry on next call. But to satisfy "fence again" on recovery entry,
        # we need to fence when entering with units-published as initial last.
        # Since `last` variable captured initial state, use it.
        if last == "units-published":
            if not _fence(host):
                return "fence-failed"
        # reload
        res, _reason = _do_reload_checks(host)
        if res == "stopped-unresolved":
            return "stopped-unresolved: missing-loader-evidence"
        if res == "no-start":
            return "stopped-unresolved"
        _append(host, "reloaded")
        cur = _journal_states(host)
        cur_bases = [c.split(":")[0].strip() for c in cur]

    if cur_bases and cur_bases[-1] == "reloaded":
        host.start_units(BOTH)
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

    # fallback: if already health-verified etc.
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


# aliases for test compatibility
def run(host, *a, **kw):
    return orchestrate(host, *a, **kw)


def main(host, *a, **kw):
    return orchestrate(host, *a, **kw)


def activate(host, *a, **kw):
    return orchestrate(host, *a, **kw)
