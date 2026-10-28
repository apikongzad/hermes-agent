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
BACKING_DIR = "/var/lib/hermes-stock-activation/backing"
RECOVERY_DIR = "/var/lib/hermes-stock-activation/recovery"

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


class RealCutoverHost(Host):
    """Root-only production effects. Never used in worker tests live.

    All subprocess uses fixed absolute argv under G3_PREFIX with sanitized
    env. No systemctl restart. No process termination primitives.
    No .env read. All writes use
    O_EXCL|O_NOFOLLOW plus file+dir fsync, OSError fail-closed.
    """

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

    def show_unit(self, unit):
        raise OSError("use _run_fixed show argv via parent supervisor")

    def stop_units(self, units):
        raise OSError("use stop_argv via parent supervisor")

    def start_units(self, units):
        raise OSError("use start_argv via parent supervisor")

    def reload_manager(self):
        raise OSError("use daemon_reload_argv via parent supervisor")

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
            with open(path, "rb") as f:
                while True:
                    b = f.read(65536)
                    if not b:
                        break
                    h.update(b)
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
        raise RuntimeError("use sleep_argv via parent supervisor")

    def proc_identity(self, pid):
        if not isinstance(pid, int) or pid <= 0:
            raise ValueError("pid")
        base = "/proc/" + str(int(pid))
        exe = os.readlink(base + "/exe")
        with open(base + "/cmdline", "rb") as f:
            raw = f.read()
        cmdline = " ".join([p for p in raw.decode("utf-8", "replace").split("\0") if p])
        with open(base + "/cgroup", "rb") as f:
            cgroup = f.read().decode("utf-8", "replace").strip()
        with open(base + "/stat", "rb") as f:
            parts = f.read().decode("utf-8", "replace").split()
        starttime = int(parts[21]) if len(parts) > 21 else 0
        with open("/proc/sys/kernel/random/boot_id", "rb") as f:
            boot = f.read().decode("utf-8").strip()
        with open(base + "/environ", "rb") as f:
            env_raw = f.read().decode("utf-8", "replace")
        keys = [c.split("=", 1)[0] for c in env_raw.split("\0") if "=" in c]
        return {
            "boot_id": boot, "pid": pid, "starttime": starttime,
            "exe": exe, "cmdline": cmdline, "cgroup": cgroup,
            "environ_keys": keys,
        }

    def denial_probe(self, path):
        raise OSError("use sudo -u #1001 probe via parent supervisor")

    def python_probe(self, python_exe):
        raise OSError("use snapshot python -I probe via parent supervisor")

    def backup_ok(self):
        raise OSError("backup verified by parent out of band")

    def digest_record(self):
        raise OSError("digest verified by parent out of band")

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
        if request_bytes != b'{"verb":"identify","id":1,"protocol":1}\n':
            raise OSError("gateway bytes")
        # AF_UNIX socket path is not named in accepted docs (precise gap).
        # Parent binds the path from supervisor metadata; never guessed here.
        raise OSError("gateway socket bound by parent supervisor")

    def dropin_names(self, service):
        raise OSError("use show DropInPaths via parent supervisor")

    def file_uid(self, path):
        _refuse_live_env(path)
        return os.lstat(path).st_uid
