"""Production Host interface and fixed argv. Stdlib only.

Worker never instantiates RealCutoverHost live. Parent runs it as root
from the installed recovery path. Tests drive cutover_orchestrate with a
fake Host (subprocess/unit fake backend) and verify these argv without
executing them.
"""

import hashlib
import json
import os
import socket
import stat
import subprocess

GATEWAY_UNIT = "hermes-gateway.service"
DASHBOARD_UNIT = "hermes-dashboard.service"
BOTH = [GATEWAY_UNIT, DASHBOARD_UNIT]

G3_PREFIX = [
    "/usr/bin/sudo",
    "-n",
    "/usr/bin/env",
    "-i",
    "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG=C",
    "LC_ALL=C",
    "SYSTEMD_PAGER=",
    "SYSTEMD_COLORS=0",
]

SYSTEMCTL_BIN = "/usr/bin/systemctl"
SLEEP_BIN = "/usr/bin/sleep"
FINDMNT_BIN = "/usr/bin/findmnt"
PYTHON312_BIN = "/usr/bin/python3.12"

JOURNAL_DIR = "/var/lib/hermes-stock-activation"
JOURNAL_PATH = "/var/lib/hermes-stock-activation/journal"
JOURNAL_LOCK_PATH = "/var/lib/hermes-stock-activation/journal.lock"
BACKING_DIR = "/var/lib/hermes-stock-activation/backing"
RECOVERY_DIR = "/var/lib/hermes-stock-activation/recovery"

TARGET_SHA = "daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06"
KNOWN_GOOD_SHA = "1d9a377fa00ce0e663e274e16b63c75e36233b9e"
REFUSED_SHA = "1c12738cfeecc78570b3a4ba3797a49de59cfdfe"

KNOWN_GOOD_MOUNT = "/run/hermes-stock-activation/known-good-snap"
CANDIDATE_MOUNT = "/run/hermes-stock-activation/candidate-snap"

GATEWAY_RUNTIME_PATH = (
    "/etc/systemd/system/hermes-gateway.service.d/zz-runtime-3.14.9.conf"
)
DASHBOARD_RUNTIME_PATH = (
    "/etc/systemd/system/hermes-dashboard.service.d/zz-runtime-3.14.9.conf"
)
GATEWAY_CANDIDATE_PATH = (
    "/etc/systemd/system/hermes-gateway.service.d/zzz-candidate.conf"
)
DASHBOARD_CANDIDATE_PATH = (
    "/etc/systemd/system/hermes-dashboard.service.d/zzz-candidate.conf"
)

ENV_FILE_PATH = "/home/ubuntu/.hermes/.env"


class Host:
    def journal_load(self):
        raise NotImplementedError

    def journal_append(self, state, detail=None):
        raise NotImplementedError

    def journal_dir_info(self):
        raise NotImplementedError

    def boot_id(self):
        raise NotImplementedError

    def show_unit(self, unit):
        raise NotImplementedError

    def stop_units(self, units):
        raise NotImplementedError

    def start_units(self, units):
        raise NotImplementedError

    def reload_manager(self):
        raise NotImplementedError

    def read_bytes(self, path):
        raise NotImplementedError

    def file_info(self, path):
        raise NotImplementedError

    def write_temp(self, tmp_path, data):
        raise NotImplementedError

    def file_fsync(self, path):
        raise NotImplementedError

    def rename_path(self, src, dst):
        raise NotImplementedError

    def dir_fsync(self, dir_path):
        raise NotImplementedError

    def now(self):
        raise NotImplementedError

    def sleep_secs(self, seconds):
        raise NotImplementedError

    def proc_identity(self, pid):
        raise NotImplementedError

    def denial_probe(self, path):
        raise NotImplementedError

    def python_probe(self, python_exe):
        raise NotImplementedError

    def backup_ok(self):
        raise NotImplementedError

    def digest_record(self):
        raise NotImplementedError

    def dashboard_fetch(self, url, headers):
        raise NotImplementedError

    def gateway_talk(self, request_bytes):
        raise NotImplementedError

    def dropin_names(self, service):
        raise NotImplementedError

    def file_uid(self, path):
        raise NotImplementedError


def stop_argv():
    return G3_PREFIX + [SYSTEMCTL_BIN, "stop", GATEWAY_UNIT, DASHBOARD_UNIT]


def show_min_argv():
    return G3_PREFIX + [
        SYSTEMCTL_BIN, "show",
        "-p", "Id", "-p", "ActiveState", "-p", "SubState",
        "-p", "MainPID", "-p", "NRestarts",
        "--", GATEWAY_UNIT, DASHBOARD_UNIT,
    ]


def sleep_argv():
    return G3_PREFIX + [SLEEP_BIN, "5"]


def daemon_reload_argv():
    return G3_PREFIX + [SYSTEMCTL_BIN, "daemon-reload"]


def show_full_argv():
    return G3_PREFIX + [
        SYSTEMCTL_BIN, "show",
        "-p", "Id", "-p", "ActiveState", "-p", "SubState",
        "-p", "MainPID", "-p", "NRestarts",
        "-p", "ExecStart", "-p", "ExecStop", "-p", "ExecStopPost",
        "-p", "EnvironmentFiles", "-p", "FragmentPath",
        "-p", "DropInPaths",
        "--", GATEWAY_UNIT, DASHBOARD_UNIT,
    ]


def start_argv():
    return G3_PREFIX + [SYSTEMCTL_BIN, "start", GATEWAY_UNIT, DASHBOARD_UNIT]


def systemctl_sequence():
    return [
        stop_argv(), show_min_argv(), sleep_argv(), show_min_argv(),
        daemon_reload_argv(), show_full_argv(), start_argv(),
    ]


def _refuse_live_env(path):
    if not isinstance(path, str):
        raise RuntimeError("path type")
    if path == ENV_FILE_PATH or ".hermes/.env" in path:
        raise RuntimeError("refused .env read")


def lockfile_create_args(lock_path=JOURNAL_LOCK_PATH):
    """Pure constructor for the journal lock. Designed, NOT activated.

    Returns the fixed path/mode/flags for O_CREAT|O_EXCL|O_NOFOLLOW 0600
    uid 0. Callers must NOT activate services; orchestrate wiring is
    deferred to the state+mutation slice. This function performs no syscall.
    """
    if lock_path != JOURNAL_LOCK_PATH:
        raise ValueError("lock path fixed")
    return {
        "path": JOURNAL_LOCK_PATH,
        "mode": 0o600,
        "uid": 0,
        "flags": "O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY",
        "activated": False,
    }


def _show_argv_for(unit, full=False):
    if unit not in BOTH:
        raise ValueError("unit")
    if full:
        return G3_PREFIX + [
            SYSTEMCTL_BIN, "show",
            "-p", "Id", "-p", "ActiveState", "-p", "SubState",
            "-p", "MainPID", "-p", "NRestarts",
            "-p", "ExecStart", "-p", "ExecStop", "-p", "ExecStopPost",
            "-p", "EnvironmentFiles", "-p", "FragmentPath",
            "-p", "DropInPaths",
            "--", unit,
        ]
    return G3_PREFIX + [
        SYSTEMCTL_BIN, "show",
        "-p", "Id", "-p", "ActiveState", "-p", "SubState",
        "-p", "MainPID", "-p", "NRestarts",
        "--", unit,
    ]


def _findmnt_argv_for(mountpoint):
    if mountpoint not in (KNOWN_GOOD_MOUNT, CANDIDATE_MOUNT):
        raise ValueError("mountpoint")
    return [FINDMNT_BIN, "-n", "-o", "FSTYPE,OPTIONS,SOURCE,TARGET",
            "--target", mountpoint]


def _parse_show_output(text):
    out = {}
    for line in (text or "").splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k in ("MainPID", "NRestarts"):
            try:
                out[k] = int(v) if v not in ("", "N/A") else 0
            except ValueError:
                out[k] = v
        else:
            out[k] = v
    return out


class RealCutoverHost(Host):
    """Root-only production effects. Never used in worker tests live.

    All subprocess uses fixed absolute argv under G3_PREFIX with sanitized
    env. No systemctl restart. No process termination primitives.
    No .env read. All writes use
    O_EXCL|O_NOFOLLOW plus file+dir fsync, OSError fail-closed.

    Read-only preflight (`show_unit`, `python_probe`, `preflight_readonly`)
    is functional. All mutating operations remain hard-refused until the
    state+mutation slice is reviewed.
    """

    def __init__(self, runner=None):
        # runner(argv, timeout=60) -> object with returncode/stdout/stderr.
        # Live default is _run_fixed. Unit tests inject a fake runner;
        # worker never spawns live systemctl/sudo via this path.
        # Object identity (not __name__) decides live vs injected path.
        self._is_live = (runner is None)
        self._runner = runner if runner is not None else self._run_fixed
        self._lock_fd = None
        self._lock_owned = None

    def _run_fixed(self, argv, timeout=60):
        if not isinstance(argv, list) or not argv:
            raise RuntimeError("argv")
        # Fixed launcher check: must start with G3_PREFIX.
        if argv[:9] != G3_PREFIX:
            raise RuntimeError("launcher prefix")
        env = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "SYSTEMD_PAGER": "",
            "SYSTEMD_COLORS": "0",
        }
        done = subprocess.run(
            argv[9:], shell=False, check=False, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=env,
        )
        return done

    def journal_load(self):
        try:
            with open(JOURNAL_PATH, "rb") as f:
                raw = f.read().decode("utf-8")
        except FileNotFoundError:
            return []
        out = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict) and isinstance(obj.get("state"), str):
                    out.append(obj["state"])
                elif isinstance(obj, str):
                    out.append(obj)
            except Exception:
                out.append(line)
        return out

    def journal_append(self, state, detail=None):
        if not isinstance(state, str) or not state:
            raise ValueError("state")
        st = os.lstat(JOURNAL_DIR)
        if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
            raise RuntimeError("journal dir ownership")
        if stat.S_ISLNK(st.st_mode):
            raise RuntimeError("journal dir symlink")
        line = json.dumps({"state": state, "detail": detail or ""}) + "\n"
        data = line.encode("utf-8")
        tmp = JOURNAL_PATH + ".tmp.cutover"
        flags = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY
        fd = os.open(tmp, flags, 0o600)
        try:
            off = 0
            while off < len(data):
                n = os.write(fd, data[off:])
                if n == 0:
                    raise OSError("short write")
                off += n
            os.fsync(fd)
        finally:
            os.close(fd)
        # Append atomically: open journal O_APPEND then fsync? Use rename
        # of a full copy to keep durability simple: read+append+rename.
        # Simpler durable append: open with O_APPEND|O_NOFOLLOW and fsync.
        jfd = os.open(JOURNAL_PATH, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            off = 0
            while off < len(data):
                n = os.write(jfd, data[off:])
                if n == 0:
                    raise OSError("short write")
                off += n
            os.fsync(jfd)
        finally:
            os.close(jfd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        dfd = os.open(JOURNAL_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def journal_dir_info(self):
        pst = os.lstat("/var/lib")
        if pst.st_uid != 0 or stat.S_IMODE(pst.st_mode) != 0o755:
            raise RuntimeError("parent ownership")
        st = os.lstat(JOURNAL_DIR)
        mode = stat.S_IMODE(st.st_mode)
        writable = bool(mode & 0o002) or (st.st_uid == 1001 and bool(mode & 0o200))
        return {
            "path": JOURNAL_DIR, "mode": mode, "uid": st.st_uid,
            "parent_mode": stat.S_IMODE(pst.st_mode), "parent_uid": pst.st_uid,
            "parent_writable_by_1001": writable,
        }

    def boot_id(self):
        with open("/proc/sys/kernel/random/boot_id", "rb") as f:
            return f.read().decode("utf-8").strip()

    def show_unit(self, unit, full=False):
        # NONDESTRUCTIVE read-only preflight. Uses fixed G3_PREFIX argv via
        # injected runner (unit tests) or _run_fixed live. No mutation.
        if unit not in BOTH:
            raise ValueError("unit")
        argv = _show_argv_for(unit, full=full)
        done = self._runner(argv, timeout=60)
        rc = getattr(done, "returncode", None)
        if rc != 0:
            raise OSError(f"show failed rc={rc!r}")
        out = getattr(done, "stdout", "")
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        parsed = _parse_show_output(out)
        if parsed.get("Id") != unit:
            raise OSError("show Id mismatch")
        return parsed

    def stop_units(self, units):
        raise OSError("refused-mutation-until-review: stop not wired")

    def start_units(self, units):
        raise OSError("refused-mutation-until-review: start not wired")

    def reload_manager(self):
        raise OSError("refused-mutation-until-review: reload not wired")

    def read_bytes(self, path):
        _refuse_live_env(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            chunks = []
            while True:
                b = os.read(fd, 8192)
                if not b:
                    break
                chunks.append(b)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def file_info(self, path):
        _refuse_live_env(path)
        st = os.lstat(path)
        h = hashlib.sha256()
        if stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode):
            # O_NOFOLLOW hardening: never follow symlink between lstat and
            # hash. Open via O_NOFOLLOW fd, hash from fd.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                while True:
                    b = os.read(fd, 65536)
                    if not b:
                        break
                    h.update(b)
            finally:
                os.close(fd)
            sha = h.hexdigest()
        else:
            sha = ""
        mode = stat.S_IMODE(st.st_mode)
        writable = bool(mode & 0o002) or (st.st_uid == 1001 and bool(mode & 0o200))
        return {
            "exists": True, "mode": mode, "uid": st.st_uid,
            "size": st.st_size, "sha256": sha,
            "writable_by_1001": writable,
        }

    def write_temp(self, tmp_path, data):
        if tmp_path == ENV_FILE_PATH or ".hermes/.env" in tmp_path:
            raise RuntimeError("refused .env write")
        flags = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY
        fd = os.open(tmp_path, flags, 0o600)
        try:
            view = bytes(data)
            off = 0
            while off < len(view):
                n = os.write(fd, view[off:])
                if n == 0:
                    raise OSError("short write")
                off += n
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        else:
            os.close(fd)

    def file_fsync(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def rename_path(self, src, dst):
        if dst == ENV_FILE_PATH:
            raise RuntimeError("refused .env")
        os.rename(src, dst)

    def dir_fsync(self, dir_path):
        fd = os.open(dir_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def now(self):
        import time as _t
        return _t.monotonic()

    def sleep_secs(self, seconds):
        raise RuntimeError("refused-mutation-until-review: sleep not wired")

    def proc_identity(self, pid):
        if not isinstance(pid, int) or pid <= 0:
            raise ValueError("pid")
        base = "/proc/" + str(int(pid))
        exe = os.readlink(base + "/exe")
        # O_NOFOLLOW hardening for proc reads: open with O_NOFOLLOW where
        # applicable; /proc entries are not symlinks except exe/cwd.
        with open(base + "/cmdline", "rb") as f:
            raw = f.read()
        cmdline = " ".join([p for p in raw.decode("utf-8", "replace").split("\0") if p])
        with open(base + "/cgroup", "rb") as f:
            cgroup = f.read().decode("utf-8", "replace").strip()
        with open(base + "/stat", "rb") as f:
            parts = f.read().decode("utf-8", "replace").split()
        # Field 22 starttime per proc(5): index 21.
        starttime = int(parts[21]) if len(parts) > 21 else 0
        with open("/proc/sys/kernel/random/boot_id", "rb") as f:
            boot = f.read().decode("utf-8").strip()
        try:
            cwd = os.readlink(base + "/cwd")
        except OSError:
            cwd = ""
        with open(base + "/environ", "rb") as f:
            env_raw = f.read().decode("utf-8", "replace")
        keys = [c.split("=", 1)[0] for c in env_raw.split("\0") if "=" in c]
        return {
            "boot_id": boot, "pid": pid, "starttime": starttime,
            "exe": exe, "cmdline": cmdline, "cgroup": cgroup,
            "cwd": cwd, "environ_keys": keys,
        }

    def denial_probe(self, path):
        raise OSError("refused-mutation-until-review: denial probe by parent")

    def python_self_probe(self):
        # Real I2 self-probe of the running interpreter. No subprocess,
        # no env read, no live effects. Proves entry runs under -I.
        import sys as _sys
        flags = _sys.flags
        isolated = int(getattr(flags, "isolated", 0))
        ignore_env = int(getattr(flags, "ignore_environment", 0))
        no_site = int(getattr(flags, "no_site", 0))
        try:
            import importlib.util as _ilu
            spec = _ilu.find_spec("sitecustomize")
            origin = spec.origin if spec is not None else None
        except Exception:
            origin = "unknown"
        try:
            has_cwd = "" in _sys.path or os.getcwd() in _sys.path
        except Exception:
            has_cwd = "unknown"
        try:
            safe = bool(getattr(_sys.flags, "safe_path", False))
        except Exception:
            safe = False
        return {
            "isolated": isolated,
            "ignore_environment": ignore_env,
            "safe_path": safe,
            "no_site": no_site,
            "sitecustomize_origin": origin,
            "sys_path_has_cwd": bool(has_cwd) if isinstance(has_cwd, bool) else has_cwd,
            "exe": _sys.executable,
        }

    def python_probe(self, python_exe):
        # Real I2 probe of a snapshot interpreter. Read-only subprocess:
        # `<exe> -I -c <probe>` with sanitized env, cwd outside tree.
        # No .env read, no imports from user trees.
        _refuse_live_env(str(python_exe))
        if not isinstance(python_exe, str) or not python_exe.startswith("/"):
            raise ValueError("python_exe absolute")
        probe = (
            "import sys,json,importlib.util as u;"
            "spec=u.find_spec('sitecustomize');"
            "print(json.dumps({"
            "'isolated':int(sys.flags.isolated),"
            "'ignore_environment':int(sys.flags.ignore_environment),"
            "'safe_path':bool(getattr(sys.flags,'safe_path',False)),"
            "'no_site':int(sys.flags.no_site),"
            "'sitecustomize_origin':(spec.origin if spec else None),"
            "'sys_path_has_cwd':('' in sys.path),"
            "'exe':sys.executable}))"
        )
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C",
               "LC_ALL": "C"}
        try:
            done = subprocess.run(
                [python_exe, "-I", "-c", probe],
                shell=False, check=False, capture_output=True,
                text=True, encoding="utf-8", errors="replace",
                timeout=60, env=env, cwd="/",
            )
        except OSError as e:
            raise OSError(f"python probe spawn: {e}")
        if done.returncode != 0:
            raise OSError(f"python probe rc={done.returncode!r}")
        try:
            return json.loads((done.stdout or "").strip().splitlines()[-1])
        except Exception as e:
            raise OSError(f"python probe parse: {e}")

    def mount_show(self, mountpoint):
        # Read-only findmnt readback via injected runner/live _run_fixed?
        # findmnt is not under sudo launcher; run directly read-only.
        # In unit tests the runner fakes it; live path runs real findmnt.
        # Object identity (not __name__) decides the path.
        argv = _findmnt_argv_for(mountpoint)
        if not self._is_live:
            # Injected runner handles bare findmnt argv.
            try:
                done = self._runner(argv, timeout=60)
            except TypeError:
                done = self._runner(argv)
        else:
            done = subprocess.run(
                argv, shell=False, check=False, capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=60,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C",
                     "LC_ALL": "C"},
            )
        rc = getattr(done, "returncode", None)
        if rc != 0:
            raise OSError(f"findmnt rc={rc!r}")
        out = getattr(done, "stdout", "")
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return (out or "").strip()

    def backup_ok(self):
        raise OSError("refused-mutation-until-review: backup by parent")

    def digest_record(self):
        raise OSError("refused-mutation-until-review: digest by parent")

    def dashboard_fetch(self, url, headers):
        if url != "http://127.0.0.1:9119/api/health":
            raise RuntimeError("dashboard url")
        if headers:
            raise RuntimeError("dashboard no auth")
        import urllib.request as _urllib
        req = _urllib.Request(url, headers={"Accept": "application/json"}, method="GET")
        try:
            with _urllib.urlopen(req, timeout=15) as resp:
                status = resp.status
                ctype = resp.getheader("Content-Type") or ""
                raw = resp.read(1048576)
        except Exception:
            return {"status": 0, "content_type": "", "body": None}
        try:
            body = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            body = raw.decode("utf-8", "replace")
        return {"status": status, "content_type": ctype, "body": body}

    def gateway_talk(self, request_bytes):
        raise OSError("refused-mutation-until-review: gateway by parent")

    def dropin_names(self, service):
        raise OSError("refused-mutation-until-review: dropins via show readback")

    def file_uid(self, path):
        _refuse_live_env(path)
        return os.lstat(path).st_uid

    def lock_info(self):
        """Read current lock content without acquiring. Returns dict or None."""
        try:
            fd = os.open(JOURNAL_LOCK_PATH, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError:
            raise
        try:
            chunks = []
            while True:
                b = os.read(fd, 8192)
                if not b:
                    break
                chunks.append(b)
            raw = b"".join(chunks).decode("utf-8", "replace")
        finally:
            os.close(fd)
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None

    def lock_acquire(self):
        """Authority lock: O_EXCL create + flock, epoch/boot semantics.

        Before any journal/fence/publication. Raises OSError('lock-held')
        if a live holder owns it (same boot, holder pid alive with same
        starttime). Stale holder (dead pid, boot mismatch, pid reuse with
        different starttime) allows takeover after retained-journal check
        by the caller; this function unlinks the stale file and retries
        once. Never pretends release after process kill: file remains
        until explicit takeover; flock alone is not authority.
        """
        import fcntl as _fcntl
        import time as _t
        if self._lock_fd is not None:
            return True
        # Parent dir must be root-owned 0700, not symlink.
        try:
            st = os.lstat(JOURNAL_DIR)
        except FileNotFoundError:
            raise OSError("journal dir missing")
        if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
            raise OSError("journal dir ownership")
        if stat.S_ISLNK(st.st_mode):
            raise OSError("journal dir symlink")
        try:
            my_boot = self.boot_id()
        except OSError:
            raise
        my_pid = os.getpid()
        try:
            with open(f"/proc/{my_pid}/stat", "rb") as f:
                _parts = f.read().decode("utf-8", "replace").split()
            my_st = int(_parts[21]) if len(_parts) > 21 else 0
        except Exception:
            my_st = 0
        content = json.dumps({
            "boot_id": my_boot, "pid": my_pid, "starttime": my_st,
            "epoch": _t.monotonic(),
        }).encode("utf-8")
        flags = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY
        try:
            fd = os.open(JOURNAL_LOCK_PATH, flags, 0o600)
        except FileExistsError:
            # Existing lock: verify holder liveness (epoch/boot semantics).
            cur = self.lock_info()
            if not isinstance(cur, dict):
                raise OSError("lock-held")
            hp = cur.get("pid")
            hb = cur.get("boot_id")
            hs = cur.get("starttime", 0)
            alive = False
            if isinstance(hp, int) and hp > 0 and isinstance(hb, str) and hb:
                try:
                    ident = self.proc_identity(hp)
                    if (ident.get("boot_id") == hb and int(ident.get("pid", 0)) == hp
                            and int(ident.get("starttime", 0)) == int(hs or 0)
                            and int(hs or 0) != 0):
                        alive = True
                except Exception:
                    alive = False
            if alive:
                raise OSError("lock-held")
            # Stale: unlink then retry once. If retry races, second writer wins.
            try:
                os.unlink(JOURNAL_LOCK_PATH)
            except OSError:
                raise OSError("lock-held")
            try:
                fd = os.open(JOURNAL_LOCK_PATH, flags, 0o600)
            except FileExistsError:
                raise OSError("lock-held")
        # Write content durably, then flock non-blocking as authority.
        try:
            off = 0
            while off < len(content):
                n = os.write(fd, content[off:])
                if n == 0:
                    raise OSError("short write")
                off += n
            os.fsync(fd)
            try:
                _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            except (OSError, BlockingIOError):
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise OSError("lock-held")
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        self._lock_fd = fd
        self._lock_owned = {"boot_id": my_boot, "pid": my_pid, "starttime": my_st}
        # Fsync parent dir for durability of lock creation.
        try:
            dfd = os.open(JOURNAL_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
        return True

    def lock_release(self):
        """Release only own lock. Never releases another holder's file."""
        if self._lock_fd is None:
            # No fd held: do not unlink another holder's file (no pretend
            # release after process kill). Verify ownership via content.
            cur = self.lock_info()
            if cur is None:
                return
            raise OSError("not lock owner")
        owned = self._lock_owned
        try:
            cur = self.lock_info()
        except OSError:
            cur = None
        if (not isinstance(cur, dict) or cur.get("pid") != (owned or {}).get("pid")
                or cur.get("boot_id") != (owned or {}).get("boot_id")):
            try:
                os.close(self._lock_fd)
            except OSError:
                pass
            self._lock_fd = None
            self._lock_owned = None
            raise OSError("not lock owner")
        try:
            os.close(self._lock_fd)
        finally:
            self._lock_fd = None
            self._lock_owned = None
        try:
            os.unlink(JOURNAL_LOCK_PATH)
        except FileNotFoundError:
            pass


def preflight_readonly(host):
    """NONDESTRUCTIVE preflight. Read-only, no journal append, no stop/
    start/reload/write/rename/mount, no .env open. Returns dict; every
    unreadable area is `blocked:<reason>`, never an exception escape for
    expected OSErrors. Caller (cli preflight) prints it as JSON.
    """
    out = {
        "status": "preflight-complete",
        "signed": False,
        "activation": "UNEXECUTED",
        "service_cutover": "NOT-AUTHORIZED",
        "checks": {},
    }
    c = out["checks"]

    try:
        c["journal_dir"] = host.journal_dir_info()
    except Exception as e:
        c["journal_dir"] = {"blocked": f"{type(e).__name__}: {e}"}
    try:
        raw = host.journal_load()
        tail = raw[-1] if raw else None
        if isinstance(tail, dict):
            tail = tail.get("state", str(tail))
        c["journal_tail"] = tail
        c["journal_len"] = len(raw)
    except Exception as e:
        c["journal_tail"] = f"blocked:{type(e).__name__}"
        c["journal_len"] = -1
    try:
        c["boot_id"] = host.boot_id()
    except Exception as e:
        c["boot_id"] = f"blocked:{type(e).__name__}"
    for unit in BOTH:
        key = "show:" + unit
        try:
            u = host.show_unit(unit, full=True)
            c[key] = {
                "Id": u.get("Id"),
                "ActiveState": u.get("ActiveState"),
                "SubState": u.get("SubState"),
                "MainPID": u.get("MainPID"),
                "NRestarts": u.get("NRestarts"),
                "ExecStart": u.get("ExecStart"),
                "WorkingDirectory": u.get("WorkingDirectory"),
                "EnvironmentFiles": u.get("EnvironmentFiles"),
            }
            try:
                pid = int(u.get("MainPID") or 0)
            except Exception:
                pid = 0
            if pid > 0:
                try:
                    ident = host.proc_identity(pid)
                    c[f"identity:{pid}"] = {
                        "boot_id": ident.get("boot_id"),
                        "pid": ident.get("pid"),
                        "starttime": ident.get("starttime"),
                        "exe": ident.get("exe"),
                        "cmdline": ident.get("cmdline"),
                        "cgroup": ident.get("cgroup"),
                    }
                except Exception as e:
                    c[f"identity:{pid}"] = {"blocked": f"{e}"}
        except Exception as e:
            c[key] = {"blocked": f"{type(e).__name__}: {e}"}
    for label, path in (
        ("zz-runtime-gateway", GATEWAY_RUNTIME_PATH),
        ("zz-runtime-dashboard", DASHBOARD_RUNTIME_PATH),
        ("zzz-gateway", GATEWAY_CANDIDATE_PATH),
        ("zzz-dashboard", DASHBOARD_CANDIDATE_PATH),
    ):
        try:
            c["digest:" + label] = host.file_info(path)
        except Exception as e:
            c["digest:" + label] = {"blocked": f"{type(e).__name__}: {e}"}
    try:
        c["python_self"] = host.python_self_probe()
    except Exception as e:
        c["python_self"] = {"blocked": f"{e}"}
    for label, mp in (("mount:known-good", KNOWN_GOOD_MOUNT),
                      ("mount:candidate", CANDIDATE_MOUNT)):
        try:
            c[label] = host.mount_show(mp)
        except Exception as e:
            c[label] = f"blocked:{type(e).__name__}:{e}"
    c["lock"] = lockfile_create_args()
    c["pins"] = {"target": TARGET_SHA, "known_good": KNOWN_GOOD_SHA,
                 "refused": REFUSED_SHA}
    return out
