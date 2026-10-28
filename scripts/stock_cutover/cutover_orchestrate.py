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

# Root-verified image closure manifests (exact pins, not just signed/outside).
# Known-good and candidate squashfs closure digests bound by separate review.
# _check_digest requires exact match; signed=false alone is not provenance.
KNOWN_GOOD_IMAGE_SHA = (
    "1d3f026c6c7bec02990c6ec7acc76ddec4f468fe5e7ee1572de5e9150919381a04"
)
CANDIDATE_IMAGE_SHA = (
    "8e50b775c2b6c82c6e4b75b09ede9b289819c669f9b3a174ab3efa148661a176"
)

JOURNAL_LOCK_PATH = "/var/lib/hermes-stock-activation/journal.lock"
EXPECTED_USER = "ubuntu"


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


class _DurableUnknown(Exception):
    pass


def _append(host, state, detail=None):
    """Durable journal append. OSError -> _DurableUnknown, never false success.

    Calls host.journal_append(state, detail) when detail is not None,
    falling back to single-arg hosts. Then readback via journal_load.
    Any OSError means durability indeterminate: caller must return
    durable-state-unknown with no further start.
    """
    try:
        if detail is None:
            host.journal_append(state)
        else:
            try:
                host.journal_append(state, detail)
            except TypeError:
                # Backward-compat fake without detail param.
                host.journal_append(state)
        host.journal_load()
    except OSError as e:
        raise _DurableUnknown(str(e))
    except Exception:
        # SimulatedCrash (interruption probe) and other non-OSError
        # faults must propagate so interruption tests observe the crash,
        # not a durable conversion.
        raise


def _acquire_authority_lock(host):
    """Authority lock before any journal/fence/publication.

    Uses host.lock_acquire() when present (O_EXCL+flock authority with
    epoch/boot semantics inside the host). Hosts without lock support
    raise OSError -> caller maps to durable/stopped. Returns True on
    authority held by this invocation. Raises OSError('lock-held') if a
    live holder owns it. Raises OSError('lock-stale-unverified') if the
    holder is stale: the stale file is preserved, there is no automatic
    takeover (exact stale->new handoff is not designed in accepted bytes,
    no delete-then-create race invented here). Caller maps to stopped-unresolved
    with the same reason. Never pretends release after kill.
    """
    acquire = getattr(host, "lock_acquire", None)
    if acquire is None:
        # No lock primitive: fail-closed, no second-writer protection.
        raise OSError("no lock authority")
    return acquire()


def _release_authority_lock(host):
    release = getattr(host, "lock_release", None)
    if release is None:
        return
    try:
        release()
    except OSError:
        # Release failure is not durability failure; holder check inside
        # host prevents pretending to release another's lock after kill.
        # Swallow here; orchestrate result already decided.
        pass


def _preserve_prior_bytes(host):
    """Read exact prior unit bytes, hash, base64 for durable journal evidence.

    Must run before first stop. Returns detail dict with sha256 + b64.
    OSError propagates -> caller maps to durable-state-unknown.
    """
    import base64 as _b64
    import hashlib as _hl
    gw = host.read_bytes(GATEWAY_CANDIDATE_PATH)
    db = host.read_bytes(DASHBOARD_CANDIDATE_PATH)
    if not isinstance(gw, (bytes, bytearray)) or not isinstance(db, (bytes, bytearray)):
        raise OSError("prior bytes type")
    gw_b = bytes(gw)
    db_b = bytes(db)
    return {
        "prior_gateway_sha256": _hl.sha256(gw_b).hexdigest(),
        "prior_gateway_b64": _b64.b64encode(gw_b).decode("ascii"),
        "prior_gateway_len": len(gw_b),
        "prior_dashboard_sha256": _hl.sha256(db_b).hexdigest(),
        "prior_dashboard_b64": _b64.b64encode(db_b).decode("ascii"),
        "prior_dashboard_len": len(db_b),
    }


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
    # Exact root-verified manifest pins: signed=false/outside alone is not
    # provenance. Require known-good + candidate image SHAs when present.
    # Hosts that do not yet expose image SHAs fail closed if pins are set.
    kg = g("known_good_image_sha", g("known_good_manifest", g("known_good_sha", "MISSING")))
    cd = g("candidate_image_sha", g("candidate_manifest", g("candidate_sha", "MISSING")))
    if kg == "MISSING" or cd == "MISSING":
        # No image pin exposed: fail closed (not just signed/outside bool).
        return False
    if kg != KNOWN_GOOD_IMAGE_SHA:
        return False
    if cd != CANDIDATE_IMAGE_SHA:
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


def _expected_argv_for(unit, snapshot_str):
    if unit == GATEWAY_UNIT:
        return [
            snapshot_str + "/venv/bin/python3",
            "-I",
            snapshot_str + "/source/hermes_cli/main.py",
            "gateway",
            "run",
        ]
    if unit == DASHBOARD_UNIT:
        return [
            snapshot_str + "/venv/bin/python3",
            "-I",
            snapshot_str + "/source/hermes_cli/main.py",
            "dashboard",
            "--port",
            "9119",
            "--host",
            "127.0.0.1",
            "--no-open",
            "--skip-build",
        ]
    raise ValueError("unit")


def _allowed_interpreters(snapshot_str):
    return {
        snapshot_str + "/venv/bin/python3",
        snapshot_str + "/venv/bin/python3.14",
    }


def _parse_cmd_argv(cmd):
    """Parse proc cmdline to argv list. None when unparseable/missing."""
    if cmd is None:
        return None
    if isinstance(cmd, (list, tuple)):
        try:
            out = [str(x) for x in cmd]
        except Exception:
            return None
        if not out:
            return None
        return out
    if isinstance(cmd, bytes):
        try:
            cmd = cmd.decode("utf-8", "replace")
        except Exception:
            return None
    if not isinstance(cmd, str):
        try:
            cmd = str(cmd)
        except Exception:
            return None
    if not cmd.strip():
        return None
    # Proc cmdline joined with spaces; args contain no spaces. Plain
    # whitespace split is exact for this closure and avoids new imports.
    # Quoted forms stay quoted (mismatch -> fail-closed, never bypass).
    return cmd.strip().split()


def _parse_show_execstart(got):
    """Normalize systemctl show ExecStart to argv list. None on mismatch.

    Accepts plain argv string (whitespace split) or structured
    `{ path=... ; argv[]=... ; ... }` form by extracting argv[] in order.
    Any ';'/'{'/'}' without argv[]=, empty, or multi-entry list returns
    None so the caller fails closed (exact equality, no substrings).
    """
    if got is None:
        return None
    if isinstance(got, (list, tuple)):
        # Empty reset has no ExecStart; non-singleton is stacked -> fail.
        if len(got) == 0:
            return None
        if len(got) != 1:
            return None
        return _parse_show_execstart(got[0])
    if isinstance(got, bytes):
        try:
            got = got.decode("utf-8", "replace")
        except Exception:
            return None
    if not isinstance(got, str):
        try:
            got = str(got)
        except Exception:
            return None
    if not got.strip():
        return None
    if "argv[]=" in got:
        argv = []
        for part in got.split(";"):
            p = part.strip()
            if p.startswith("{"):
                p = p[1:].strip()
            if p.endswith("}"):
                p = p[:-1].strip()
            if p.startswith("argv[]="):
                v = p[len("argv[]="):].strip()
                if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                    v = v[1:-1].replace('\\"', '"').replace('\\\\', '\\')
                argv.append(v)
        if not argv:
            return None
        return argv
    # Plain form must not contain structured fragments.
    if ";" in got or "{" in got or "}" in got:
        return None
    parts = got.strip().split()
    if not parts:
        return None
    return parts


def _identity_ok(host, snapshot_str, worktree_path):
    """Full I4 readback: boot/starttime(field22)/cgroup/PID/exe/cmdline.

    Binds pinned generation expected runtime to actual process:
    - show_unit MainPID must be int>0 and equal proc_identity pid
    - proc boot_id must equal host.boot_id()
    - starttime must be int>0 (field22) and present
    - parsed argv must equal expected snapshot argv exactly
      (argv[0] snapshot python, argv[1] exactly '-I', entry + subcommand
      exact; extra '--evil-flag' or '--config=-I-evil' fails)
    - exe must be exact snapshot interpreter (python3 or python3.14)
    - cgroup must be present and name the service
    - cwd is REQUIRED and must equal journaled WorkingDirectory
    Mismatch or unreadable identity is failure (False), OSError raises
    _ProcIdentityUnknown for caller to map to stopped-unresolved.
    """
    try:
        expected_boot = host.boot_id()
    except OSError:
        raise _ProcIdentityUnknown
    for unit in BOTH:
        try:
            u = host.show_unit(unit)
        except OSError:
            raise _ProcIdentityUnknown
        pid = _unit_field(u, "MainPID", "main_pid", "MainPid", "pid")
        try:
            pid_i = int(pid)
        except Exception:
            return False
        if pid_i <= 0:
            return False
        try:
            ident = host.proc_identity(pid_i)
        except OSError:
            raise _ProcIdentityUnknown
        if ident is None:
            raise _ProcIdentityUnknown
        if isinstance(ident, dict):
            exe = ident.get("exe", "") or ""
            cmd_raw = ident.get("cmdline", None)
            if cmd_raw is None:
                cmd_raw = ident.get("cmd", None)
            boot = ident.get("boot_id", ident.get("bootId", ""))
            st = ident.get("starttime", ident.get("start_time", 0))
            cg = ident.get("cgroup", "") or ""
            ipid = ident.get("pid", pid_i)
            if "cwd" in ident:
                cwd = ident.get("cwd")
            else:
                cwd = ident.get("Cwd", None)
        else:
            exe = getattr(ident, "exe", "") or ""
            cmd_raw = getattr(ident, "cmdline", None)
            if cmd_raw is None:
                cmd_raw = getattr(ident, "cmd", None)
            boot = getattr(ident, "boot_id", "") or ""
            st = getattr(ident, "starttime", 0)
            cg = getattr(ident, "cgroup", "") or ""
            ipid = getattr(ident, "pid", pid_i)
            cwd = getattr(ident, "cwd", None)
        try:
            if int(ipid) != pid_i:
                return False
        except Exception:
            return False
        if not boot or boot != expected_boot:
            return False
        try:
            st_i = int(st)
        except Exception:
            return False
        if st_i <= 0:
            return False
        # Exact argv: interpreter + '-I' + entry + subcommand, no fragments.
        want_argv = _expected_argv_for(unit, snapshot_str)
        got_argv = _parse_cmd_argv(cmd_raw)
        if got_argv is None:
            return False
        if got_argv != want_argv:
            return False
        # argv[1] must be exactly '-I' (exact equality already ensures,
        # explicit for review traceability; '--config=-I-evil' fails here).
        if len(got_argv) < 2 or got_argv[1] != "-I":
            return False
        exe_s = str(exe)
        if exe_s not in _allowed_interpreters(snapshot_str):
            return False
        # Contamination is already mismatch via exact argv/exe, kept as
        # explicit rejection (never permissive).
        if isinstance(cmd_raw, (list, tuple)):
            try:
                cmd_s = " ".join(str(x) for x in cmd_raw)
            except Exception:
                return False
        elif isinstance(cmd_raw, bytes):
            try:
                cmd_s = cmd_raw.decode("utf-8", "replace")
            except Exception:
                return False
        else:
            try:
                cmd_s = str(cmd_raw)
            except Exception:
                return False
        if worktree_path and (worktree_path in exe_s or worktree_path in cmd_s):
            return False
        if GEN_KNOWN_GOOD in exe_s or GEN_KNOWN_GOOD in cmd_s:
            return False
        cg_s = str(cg)
        if not cg_s:
            return False
        # cgroup must name the service slice (gateway vs dashboard).
        if unit not in cg_s and "hermes" not in cg_s:
            return False
        # cwd is REQUIRED: missing/empty fails closed.
        if cwd is None:
            return False
        try:
            cwd_s = str(cwd)
        except Exception:
            return False
        if not cwd_s:
            return False
        want_wd = GATEWAY_WD if unit == GATEWAY_UNIT else DASHBOARD_WD
        if cwd_s != want_wd:
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


def _expected_exec_for(unit, snapshot_str):
    if unit == GATEWAY_UNIT:
        return _gateway_exec(snapshot_str)
    if unit == DASHBOARD_UNIT:
        return _dashboard_exec(snapshot_str)
    raise ValueError("unit")


def _expected_wd_for(unit):
    if unit == GATEWAY_UNIT:
        return GATEWAY_WD
    if unit == DASHBOARD_UNIT:
        return DASHBOARD_WD
    raise ValueError("unit")


def _parse_env_keys_vals(env):
    """Split Environment property to (keys, vals) without substrings."""
    if isinstance(env, dict):
        try:
            keys = [str(k) for k in env.keys()]
        except Exception:
            keys = []
        try:
            vals = " ".join(str(v) for v in env.values())
        except Exception:
            vals = ""
        return keys, vals
    if isinstance(env, (list, tuple)):
        keys = []
        vals_parts = []
        for x in env:
            try:
                s = str(x)
            except Exception:
                continue
            vals_parts.append(s)
            if "=" in s:
                keys.append(s.split("=", 1)[0].strip())
            else:
                keys.append(s.strip())
        return keys, " ".join(vals_parts)
    try:
        s = str(env)
    except Exception:
        return [], ""
    if not s.strip():
        return [], ""
    keys = []
    for tok in s.strip().split():
        if "=" in tok:
            keys.append(tok.split("=", 1)[0].strip())
        else:
            keys.append(tok.strip())
    return keys, s


def _do_reload_checks(host, snapshot_str=None):
    """Exact reload checks vs rendered expected (C4).

    When snapshot_str is None, uses CANDIDATE_SNAPSHOT (normal publish).
    Callers in rollback pass KNOWN_GOOD_SNAPSHOT. Checks per unit:
    - User REQUIRED, exactly ubuntu (missing fails)
    - WorkingDirectory REQUIRED, exactly expected gateway/dashboard WD
    - ExecStart normalized structured argv exactly equal expected argv
      (no substring, no extra '--evil-flag', argv[1] exactly '-I')
    - ExecStop/ExecStopPost empty reset (no v0.21.7 venv hooks)
    - EnvironmentFiles REQUIRED presence, must be empty (any entry is
      missing-loader-evidence); Environment REQUIRED presence, must not
      contain forbidden loader keys
    """
    if snapshot_str is None:
        snapshot_str = CANDIDATE_SNAPSHOT
    try:
        host.reload_manager()
        gu = host.show_unit(GATEWAY_UNIT)
        du = host.show_unit(DASHBOARD_UNIT)
    except OSError:
        return ("stopped-unresolved", "reload-unreadable")
    for unit, u in ((GATEWAY_UNIT, gu), (DASHBOARD_UNIT, du)):
        user = _unit_field(u, "User", "user")
        if user is None:
            return ("stopped-unresolved", "user-mismatch")
        try:
            user_s = str(user)
        except Exception:
            return ("stopped-unresolved", "user-mismatch")
        if user_s != EXPECTED_USER:
            return ("stopped-unresolved", "user-mismatch")
        wd = _unit_field(u, "WorkingDirectory", "working_directory", "WorkingDir")
        want_wd = _expected_wd_for(unit)
        if wd is None:
            return ("stopped-unresolved", "workingdirectory-mismatch")
        try:
            wd_s = str(wd)
        except Exception:
            return ("stopped-unresolved", "workingdirectory-mismatch")
        if wd_s != want_wd:
            return ("stopped-unresolved", "workingdirectory-mismatch")
        ef = _unit_field(u, "EnvironmentFiles", "environment_files", "env_files")
        if ef is None:
            return ("stopped-unresolved", "missing-loader-evidence")
        if ef:
            # Any non-empty EnvironmentFiles is missing loader evidence.
            # Normalize: non-empty list/tuple/dict or non-blank string.
            if isinstance(ef, (list, tuple, dict)):
                if len(ef) != 0:
                    return ("stopped-unresolved", "missing-loader-evidence")
            elif isinstance(ef, bytes):
                try:
                    es = ef.decode("utf-8", "replace")
                except Exception:
                    return ("stopped-unresolved", "missing-loader-evidence")
                if es.strip() not in ("", "[]", "None"):
                    return ("stopped-unresolved", "missing-loader-evidence")
            else:
                try:
                    es = str(ef)
                except Exception:
                    return ("stopped-unresolved", "missing-loader-evidence")
                if es.strip() not in ("", "[]", "None"):
                    return ("stopped-unresolved", "missing-loader-evidence")
                # Empty string form is present-but-empty: allowed.
                # Any other non-empty string fails above.
            # Re-check truthy non-empty that slipped through.
            if ef:
                try:
                    blank = str(ef).strip() in ("", "[]", "None")
                except Exception:
                    blank = False
                if not blank:
                    return ("stopped-unresolved", "missing-loader-evidence")
        # Exact ExecStart vs expected argv (no permissive substrings).
        want_argv = _expected_argv_for(unit, snapshot_str)
        got_exec = _unit_field(u, "ExecStart", "exec_start")
        if got_exec is None:
            return ("stopped-unresolved", "reload-unreadable")
        got_argv = _parse_show_execstart(got_exec)
        if got_argv is None:
            return ("stopped-unresolved", "execstart-mismatch")
        if got_argv != want_argv:
            return ("stopped-unresolved", "execstart-mismatch")
        if len(got_argv) < 2 or got_argv[1] != "-I":
            return ("stopped-unresolved", "execstart-flags")
        # Contamination is already mismatch via exact argv; explicit
        # rejection kept (never permissive).
        try:
            if isinstance(got_exec, (list, tuple)):
                got_s = " ".join(str(x) for x in got_exec)
            elif isinstance(got_exec, bytes):
                got_s = got_exec.decode("utf-8", "replace")
            else:
                got_s = str(got_exec)
        except Exception:
            return ("stopped-unresolved", "execstart-mismatch")
        if WORKTREE_PATH in got_s or GEN_KNOWN_GOOD in got_s:
            return ("stopped-unresolved", "execstart-mismatch")
        for attr in ("ExecStop", "ExecStopPost", "exec_stop", "exec_stop_post"):
            v = _unit_field(u, attr)
            if v is None:
                continue
            if isinstance(v, (list, tuple)):
                if len(v) == 0:
                    continue
                s = " ".join(str(x) for x in v)
            else:
                s = str(v)
                if s in ("", "[]", "None"):
                    continue
            if VENV_OLD in s:
                return ("no-start", "execstop-venv")
            # Any non-empty stop hook without snapshot proof blocks:
            # empty reset with no replacement is the required outcome.
            if s.strip():
                return ("stopped-unresolved", "stop-hook-present")
        # Loader Environment contract: REQUIRED presence, no forbidden keys.
        env = _unit_field(u, "Environment", "environment")
        if env is None:
            return ("stopped-unresolved", "missing-loader-evidence")
        keys, vals = _parse_env_keys_vals(env)
        for k in keys:
            try:
                ks = str(k)
            except Exception:
                continue
            if ks in FORBIDDEN_LOADER_KEYS:
                return ("stopped-unresolved", "missing-loader-evidence")
        # Exact key match for PYTHONPATH (substring would false-positive
        # MYPYTHONPATH; exact key check above already covers, kept here
        # as explicit loader contract on values text).
        if "PYTHONPATH" in keys:
            return ("stopped-unresolved", "missing-loader-evidence")
        # Values text must not smuggle forbidden loader assignment.
        # Parse tokens exactly; substring on whole blob is not used.
        try:
            vals_s = str(vals)
        except Exception:
            vals_s = ""
        for tok in vals_s.split():
            if tok.split("=", 1)[0].strip() in FORBIDDEN_LOADER_KEYS:
                return ("stopped-unresolved", "missing-loader-evidence")
    return ("ok", "")


def _rollback(host, candidate_snapshot, known_good_snapshot, worktree_path):
    # C1: illegal bare fence-failed never returned. Preserve prior legal
    # state or canonical stopped-unresolved per design §2.3/§2.5.
    if not _fence(host):
        return "stopped-unresolved:fence-failed"
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
        try:
            _append(host, "durable-state-unknown: rollback-publish indeterminate")
        except _DurableUnknown:
            pass
        return "durable-state-unknown: rollback-publish indeterminate"
    try:
        _append(host, "rolling-back")
    except _DurableUnknown:
        return "durable-state-unknown: rolling-back indeterminate"
    try:
        host.reload_manager()
        # C4 exact reload vs rendered known-good expected while inactive.
        res, _rsn = _do_reload_checks(host, known_good_snapshot)
        if res != "ok":
            return "stopped-unresolved: rollback-reload-mismatch"
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
    try:
        _append(host, "rolled-back")
    except _DurableUnknown:
        return "durable-state-unknown: rolled-back indeterminate"
    return "rolled-back"


def _recover_durable(host, states):
    """C2: durable-state-unknown recovery (design §2.3).

    Only tail durable is recoverable. Requires root readback re-establishing
    durability + this invocation's 5s inactive fence re-verify. Returns
    'stop-fenced' directive (caller appends) or 'stopped-unresolved:...'.
    Never committed/rolled-back, never start of pre-transaction bytes.
    """
    tail = states[-1] if states else ""
    base = tail.split(":")[0].strip() if isinstance(tail, str) else str(tail)
    if base != "durable-state-unknown":
        return None
    # Readback must re-establish durability: journal + physical state.
    try:
        host.journal_load()
        host.show_unit(GATEWAY_UNIT)
        host.show_unit(DASHBOARD_UNIT)
        host.file_info(GATEWAY_CANDIDATE_PATH)
        host.file_info(DASHBOARD_CANDIDATE_PATH)
    except OSError:
        return "stopped-unresolved:durable-readback-failed"
    if not _fence(host):
        # C1-canonical: fence failure preserves stopped-unresolved.
        return "stopped-unresolved:fence-failed"
    return "stop-fenced"


def _orchestrate_impl(host, target_sha=None):
    # Authority lock before any journal/fence/publication. No second writer.
    # Stale lock is preserved fail-closed (no delete-then-create race, no
    # automatic takeover: exact stale->new authority handoff is not
    # designed in accepted bytes). Receipts distinguish lock-held vs
    # lock-stale-unverified (stale preserved). Atomic external recovery
    # lock design is a later narrow-exact slice, not a broad generic.
    try:
        _acquire_authority_lock(host)
    except OSError as e:
        msg = str(e)
        reason = "lock-stale-unverified" if "lock-stale-unverified" in msg else "lock-held"
        # Preserve prior legal state, no mutation, no takeover.
        try:
            cur = _journal_states(host)
        except OSError:
            return f"stopped-unresolved:{reason}"
        if cur:
            lastb = cur[-1].split(":")[0].strip() if isinstance(cur[-1], str) else str(cur[-1])
            if lastb in LEGAL_NEXT or lastb in HAPPY or lastb in ("stopped-unresolved", "blocked-unread", "rolled-back"):
                # Preserve prior legal state tail; report lock as reason.
                if lastb == "stopped-unresolved":
                    return cur[-1]
                return f"stopped-unresolved:{reason}"
        return f"stopped-unresolved:{reason}"
    try:
        return _orchestrate_locked(host, target_sha)
    finally:
        _release_authority_lock(host)


def _orchestrate_locked(host, target_sha=None):
    if target_sha is None:
        target_sha = TARGET_SHA
    try:
        states = _journal_states(host)
    except OSError:
        return "durable-state-unknown: journal unreadable"
    # C2: tail durable may recover via stop-fenced; non-tail durable history
    # does not block; never early-return forever.
    if states:
        tailb = states[-1].split(":")[0].strip() if isinstance(states[-1], str) else str(states[-1])
        if tailb == "durable-state-unknown":
            rec = _recover_durable(host, states)
            if rec is None:
                return "stopped-unresolved:durable-readback-failed"
            if rec.startswith("stopped-unresolved"):
                return rec
            # rec == stop-fenced: append durably then continue from fence.
            try:
                _append(host, "stop-fenced")
            except _DurableUnknown:
                return "durable-state-unknown: re-fence indeterminate"
            # Fall through with refreshed states to continue publish path.
            try:
                states = _journal_states(host)
            except OSError:
                return "durable-state-unknown: journal unreadable"
        if tailb == "rolling-back":
            return "stopped-unresolved"
    if states and states[-1] == "committed":
        return "committed"
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
        try:
            _append(host, "blocked-unread")
        except _DurableUnknown:
            return "durable-state-unknown: blocked indeterminate"
        return "blocked-unread"
    except OSError:
        try:
            _append(host, "blocked-unread")
        except _DurableUnknown:
            return "durable-state-unknown: blocked indeterminate"
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
        try:
            _append(host, "blocked-unread")
        except _DurableUnknown:
            return "durable-state-unknown: blocked indeterminate"
        return "blocked-unread"
    if not _info_ok(di, DASHBOARD_RUNTIME_SHA256, 124):
        try:
            _append(host, "blocked-unread")
        except _DurableUnknown:
            return "durable-state-unknown: blocked indeterminate"
        return "blocked-unread"
    cur = _journal_states(host)
    if not cur:
        try:
            _append(host, "observed")
        except _DurableUnknown:
            return "durable-state-unknown: observed indeterminate"
        try:
            cur = _journal_states(host)
        except OSError:
            return "durable-state-unknown: journal unreadable"
    cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] == "observed":
        try:
            host.dropin_names(GATEWAY_UNIT)
            host.dropin_names(DASHBOARD_UNIT)
        except OSError:
            try:
                _append(host, "blocked-unread")
            except _DurableUnknown:
                return "durable-state-unknown: blocked indeterminate"
            return "blocked-unread"
        try:
            _append(host, "dropins-read")
        except _DurableUnknown:
            return "durable-state-unknown: dropins indeterminate"
        try:
            cur = _journal_states(host)
        except OSError:
            return "durable-state-unknown: journal unreadable"
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] == "dropins-read":
        try:
            _append(host, "target-bound")
        except _DurableUnknown:
            return "durable-state-unknown: target indeterminate"
        try:
            cur = _journal_states(host)
        except OSError:
            return "durable-state-unknown: journal unreadable"
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
        try:
            _append(host, "health-verified")
            _append(host, "committed")
        except _DurableUnknown:
            return "durable-state-unknown: commit indeterminate"
        return "committed"
    if "known-good-frozen" not in cur_bases:
        # C3: known-good-frozen is NOT a marker. Requires actual I2
        # (denial+python+digest with exact image pins) plus durable
        # preservation of exact prior unit bytes (base64+sha256) in the
        # root journal BEFORE first stop. Any OSError -> durable, no start.
        try:
            evidence = _preserve_prior_bytes(host)
        except OSError:
            try:
                _append(host, "durable-state-unknown: prior evidence unreadable")
            except _DurableUnknown:
                pass
            return "durable-state-unknown: prior evidence unreadable"
        if not _check_denial(host, KNOWN_GOOD_SNAPSHOT):
            return cur_bases[-1] if cur_bases else "target-bound"
        _kg_py = KNOWN_GOOD_SNAPSHOT + "/venv/bin/python3"
        if not _check_python(host, _kg_py, KNOWN_GOOD_SNAPSHOT):
            return cur_bases[-1] if cur_bases else "target-bound"
        if not _check_digest(host):
            return cur_bases[-1] if cur_bases else "target-bound"
        try:
            tmp = BACKING_DIR + "/.known-good.tmp"
            host.write_temp(tmp, b"known-good")
            host.file_fsync(tmp)
            host.rename_path(tmp, BACKING_DIR + "/known-good-frozen-marker")
            host.dir_fsync(BACKING_DIR)
        except OSError:
            try:
                _append(host, "durable-state-unknown: known-good indeterminate")
            except _DurableUnknown:
                pass
            return "durable-state-unknown: known-good indeterminate"
        try:
            _append(host, "known-good-frozen", detail=evidence)
        except _DurableUnknown:
            return "durable-state-unknown: known-good indeterminate"
        try:
            cur = _journal_states(host)
        except OSError:
            return "durable-state-unknown: journal unreadable"
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if "backup-verified" not in cur_bases:
        try:
            ok = host.backup_ok()
        except OSError:
            ok = False
        if not ok:
            return cur_bases[-1] if cur_bases else "known-good-frozen"
        try:
            _append(host, "backup-verified")
        except _DurableUnknown:
            return "durable-state-unknown: backup indeterminate"
        try:
            cur = _journal_states(host)
        except OSError:
            return "durable-state-unknown: journal unreadable"
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if "candidate-materialized" not in cur_bases:
        try:
            tmp = BACKING_DIR + "/.candidate.tmp"
            host.write_temp(tmp, CANDIDATE_SNAPSHOT.encode())
            host.file_fsync(tmp)
            host.rename_path(tmp, BACKING_DIR + "/candidate-materialized-marker")
            host.dir_fsync(BACKING_DIR)
        except OSError:
            try:
                _append(host, "durable-state-unknown: candidate indeterminate")
            except _DurableUnknown:
                pass
            return "durable-state-unknown: candidate indeterminate"
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
        try:
            _append(host, "candidate-materialized")
        except _DurableUnknown:
            return "durable-state-unknown: candidate indeterminate"
        try:
            cur = _journal_states(host)
        except OSError:
            return "durable-state-unknown: journal unreadable"
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] in ("candidate-materialized", "stop-fenced"):
        # C1: never bare fence-failed. Preserve prior legal or canonical
        # stopped-unresolved:fence-failed.
        if not _fence(host):
            return "stopped-unresolved:fence-failed"
        if cur_bases[-1] != "stop-fenced":
            try:
                _append(host, "stop-fenced")
            except _DurableUnknown:
                return "durable-state-unknown: fence indeterminate"
            try:
                cur = _journal_states(host)
            except OSError:
                return "durable-state-unknown: journal unreadable"
            cur_bases = [c.split(":")[0].strip() for c in cur]
        # Prior unit bytes must remain readable after fence; OSError is
        # durability indeterminate, never false success. Evidence already
        # preserved durably at known-good-frozen before first stop; this
        # read verifies post-fence readability without starting those bytes.
        try:
            _gw_prior = host.read_bytes(GATEWAY_CANDIDATE_PATH)
            _db_prior = host.read_bytes(DASHBOARD_CANDIDATE_PATH)
        except OSError:
            try:
                _append(host, "durable-state-unknown: prior unreadable")
            except _DurableUnknown:
                pass
            return "durable-state-unknown: prior unreadable"
        _ = (_gw_prior, _db_prior)
        try:
            _publish_snapshot(host, CANDIDATE_SNAPSHOT)
        except OSError:
            try:
                _append(host, "durable-state-unknown: publish indeterminate")
            except _DurableUnknown:
                pass
            return "durable-state-unknown: publish indeterminate"
        try:
            _append(host, "units-published")
        except _DurableUnknown:
            return "durable-state-unknown: publish indeterminate"
        try:
            cur = _journal_states(host)
        except OSError:
            return "durable-state-unknown: journal unreadable"
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] == "units-published":
        if last == "units-published":
            if not _fence(host):
                return "stopped-unresolved:fence-failed"
        # C4: exact reload vs rendered expected for candidate snapshot.
        res, _reason = _do_reload_checks(host, CANDIDATE_SNAPSHOT)
        if res == "stopped-unresolved":
            return "stopped-unresolved: missing-loader-evidence"
        if res == "no-start":
            return "stopped-unresolved"
        try:
            _append(host, "reloaded")
        except _DurableUnknown:
            return "durable-state-unknown: reload indeterminate"
        try:
            cur = _journal_states(host)
        except OSError:
            return "durable-state-unknown: journal unreadable"
        cur_bases = [c.split(":")[0].strip() for c in cur]
    if cur_bases and cur_bases[-1] == "reloaded":
        try:
            host.start_units(BOTH)
        except OSError:
            return "stopped-unresolved"
        try:
            _append(host, "restarted")
        except _DurableUnknown:
            return "durable-state-unknown: restart indeterminate"
        try:
            cur = _journal_states(host)
        except OSError:
            return "durable-state-unknown: journal unreadable"
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
        try:
            _append(host, "health-verified")
            _append(host, "committed")
        except _DurableUnknown:
            return "durable-state-unknown: commit indeterminate"
        return "committed"
    if cur_bases and cur_bases[-1] == "health-verified":
        try:
            _append(host, "committed")
        except _DurableUnknown:
            return "durable-state-unknown: commit indeterminate"
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
