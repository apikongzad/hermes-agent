"""Hermetic closure export boundary. Stdlib only."""

import hashlib
import os
import stat

from scripts.stock_activation.host import Host

TOOLS_ROOT = "/home/ubuntu/.hermes/tools"
_INTERPRETER_DIR_HEX = "707974686f6e2d332e31342e392b32303236313032312d6c696e75782d61726d3634"
INTERPRETER_DIR_NAME = bytes.fromhex(_INTERPRETER_DIR_HEX).decode("ascii")
INTERPRETER_PREFIX = os.path.join(TOOLS_ROOT, INTERPRETER_DIR_NAME)

LIVE_LIB = "/var/lib/hermes-stock-activation"
LIVE_RUN = "/run/hermes-stock-activation"
HERMES_HOME = "/home/ubuntu/.hermes"
STOCK_CLONE = "/home/ubuntu/.hermes/hermes-agent"

KNOWN_GOOD_REPO = "/home/ubuntu/.hermes/hermes-agent"
KNOWN_GOOD_SHA = "1d9a377fa00ce0e663e274e16b63c75e36233b9e"
KNOWN_GOOD_VENV_SRC = "/home/ubuntu/.hermes/runtime/cutover-generations/gen-1d9a377fa00c/venv"
KNOWN_GOOD_DEPS_SRC = "/home/ubuntu/.hermes/installs/fb097378e0b9d4af/environments/3db97cb527a04c959b19c09c3c48bf7c/venv"
CANDIDATE_REPO = "/home/ubuntu/.hermes/runtime/stock-candidates/daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06"
CANDIDATE_SHA = "daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06"
CANDIDATE_VENV_SRC = "/home/ubuntu/.hermes/runtime/cutover-generations/gen-daec3cd4c6d3/venv"

KNOWN_GOOD_IMAGE = "/var/lib/hermes-stock-activation/backing/known-good.squashfs"
CANDIDATE_IMAGE = "/var/lib/hermes-stock-activation/backing/candidate.squashfs"
KNOWN_GOOD_MOUNT = "/run/hermes-stock-activation/known-good-snap"
CANDIDATE_MOUNT = "/run/hermes-stock-activation/candidate-snap"

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
MKSQUASHFS_BIN = "/usr/bin/mksquashfs"
LOSETUP_BIN = "/usr/sbin/losetup"
MOUNT_BIN = "/usr/bin/mount"
FINDMNT_BIN = "/usr/bin/findmnt"
GIT_BIN = "/usr/bin/git"
TAR_BIN = "/usr/bin/tar"
RSYNC_BIN = "/usr/bin/rsync"
LN_BIN = "/usr/bin/ln"
UNSQUASHFS_BIN = "/usr/bin/unsquashfs"
PYTHON312_BIN = "/usr/bin/python3.12"
INSTALL_BIN = "/usr/bin/install"

GATEWAY_UNIT = "hermes-gateway.service"
DASHBOARD_UNIT = "hermes-dashboard.service"

PYTHON_LINK_TARGET = "../../interpreter/bin/python3.14"
PYTHON_LINK_NAMES = ("python", "python3", "python3.14")


class SandboxRefused(RuntimeError):
    pass


def _is_under(path, prefix):
    if path == prefix:
        return True
    return path.startswith(prefix + "/")


def _is_live_path(path):
    n = os.path.normpath(path)
    for prefix in (
        LIVE_LIB,
        LIVE_RUN,
        STOCK_CLONE,
        HERMES_HOME + "/hermes-agent",
        HERMES_HOME + "/runtime",
        HERMES_HOME + "/installs",
        HERMES_HOME + "/tools",
    ):
        if _is_under(n, prefix):
            return True
    if n == HERMES_HOME:
        return True
    if n == HERMES_HOME + "/.env":
        return True
    return False


class SandboxHost(Host):
    def __init__(self, sandbox_root):
        if not isinstance(sandbox_root, str):
            raise SandboxRefused("root type")
        if not os.path.isabs(sandbox_root):
            raise SandboxRefused("root not absolute")
        norm = os.path.normpath(sandbox_root)
        if _is_live_path(norm):
            raise SandboxRefused("live root")
        self._root = norm

    def _check(self, path):
        if not isinstance(path, str):
            raise SandboxRefused("path type")
        cand = os.path.normpath(path)
        if not os.path.isabs(cand):
            raise SandboxRefused("not absolute")
        if _is_live_path(cand):
            raise SandboxRefused("live")
        if cand != self._root and not cand.startswith(self._root + "/"):
            raise SandboxRefused("outside")
        rel = os.path.relpath(cand, self._root)
        if rel.startswith(".."):
            raise SandboxRefused("outside")
        cur = self._root
        if cand == self._root:
            try:
                st = os.lstat(cur)
            except OSError:
                raise SandboxRefused("missing root")
            if stat.S_ISLNK(st.st_mode):
                raise SandboxRefused("symlink ancestor")
            return cand
        parts = rel.split(os.sep)
        for comp in parts[:-1]:
            if comp in ("", ".", ".."):
                raise SandboxRefused("component")
            cur = cur + "/" + comp
            try:
                st = os.lstat(cur)
            except FileNotFoundError:
                raise SandboxRefused("missing ancestor")
            except NotADirectoryError:
                raise SandboxRefused("not a directory")
            if stat.S_ISLNK(st.st_mode):
                raise SandboxRefused("symlink ancestor")
        last = parts[-1]
        if last in ("", ".", ".."):
            raise SandboxRefused("component")
        return cand

    def file_uid(self, path):
        cand = self._check(path)
        st = os.lstat(cand)
        return st.st_uid

    def journal_load(self):
        raise RuntimeError("sandbox-refuse")

    def journal_append(self, state, detail=None):
        raise RuntimeError("sandbox-refuse")

    def journal_dir_info(self):
        raise RuntimeError("sandbox-refuse")

    def boot_id(self):
        raise RuntimeError("sandbox-refuse")

    def show_unit(self, unit):
        raise RuntimeError("sandbox-refuse")

    def stop_units(self, units):
        raise RuntimeError("sandbox-refuse")

    def start_units(self, units):
        raise RuntimeError("sandbox-refuse")

    def reload_manager(self):
        raise RuntimeError("sandbox-refuse")

    def read_bytes(self, path):
        raise RuntimeError("sandbox-refuse")

    def file_info(self, path):
        raise RuntimeError("sandbox-refuse")

    def write_temp(self, tmp_path, data):
        raise RuntimeError("sandbox-refuse")

    def file_fsync(self, path):
        raise RuntimeError("sandbox-refuse")

    def rename_path(self, src, dst):
        raise RuntimeError("sandbox-refuse")

    def dir_fsync(self, dir_path):
        raise RuntimeError("sandbox-refuse")

    def now(self):
        raise RuntimeError("sandbox-refuse")

    def sleep_secs(self, seconds):
        raise RuntimeError("sandbox-refuse")

    def proc_identity(self, pid):
        raise RuntimeError("sandbox-refuse")

    def denial_probe(self, path):
        raise RuntimeError("sandbox-refuse")

    def python_probe(self, python_exe):
        raise RuntimeError("sandbox-refuse")

    def backup_ok(self):
        raise RuntimeError("sandbox-refuse")

    def digest_record(self):
        raise RuntimeError("sandbox-refuse")

    def dashboard_fetch(self, url, headers):
        raise RuntimeError("sandbox-refuse")

    def gateway_talk(self, request_bytes):
        raise RuntimeError("sandbox-refuse")

    def dropin_names(self, service):
        raise RuntimeError("sandbox-refuse")


def mksquashfs_argv(staged, image_tmp):
    return [
        MKSQUASHFS_BIN,
        staged,
        image_tmp,
        "-comp",
        "xz",
        "-b",
        "131072",
        "-reproducible",
        "-mkfs-time",
        "0",
        "-all-root",
        "-no-xattrs",
        "-no-hardlinks",
        "-no-exports",
        "-no-recovery",
        "-no-progress",
        "-noappend",
    ]


def losetup_argv(final_image):
    return [
        LOSETUP_BIN,
        "--find",
        "--show",
        "--read-only",
        "--nooverlap",
        "--",
        final_image,
    ]


def mount_argv(loopdev, mountpoint):
    return [
        MOUNT_BIN,
        "-n",
        "-t",
        "squashfs",
        "-o",
        "ro,nosuid,nodev",
        loopdev,
        mountpoint,
    ]


def findmnt_argv(mountpoint):
    return [
        FINDMNT_BIN,
        "-n",
        "-o",
        "FSTYPE,OPTIONS,SOURCE,TARGET",
        "--target",
        mountpoint,
    ]


def stop_argv():
    return G3_PREFIX + [SYSTEMCTL_BIN, "stop", GATEWAY_UNIT, DASHBOARD_UNIT]


def show_min_argv():
    return G3_PREFIX + [
        SYSTEMCTL_BIN,
        "show",
        "-p",
        "Id",
        "-p",
        "ActiveState",
        "-p",
        "SubState",
        "-p",
        "MainPID",
        "-p",
        "NRestarts",
        "--",
        GATEWAY_UNIT,
        DASHBOARD_UNIT,
    ]


def sleep_argv():
    return G3_PREFIX + [SLEEP_BIN, "5"]


def daemon_reload_argv():
    return G3_PREFIX + [SYSTEMCTL_BIN, "daemon-reload"]


def show_full_argv():
    return G3_PREFIX + [
        SYSTEMCTL_BIN,
        "show",
        "-p",
        "Id",
        "-p",
        "ActiveState",
        "-p",
        "SubState",
        "-p",
        "MainPID",
        "-p",
        "NRestarts",
        "-p",
        "ExecStart",
        "-p",
        "ExecStop",
        "-p",
        "ExecStopPost",
        "-p",
        "EnvironmentFiles",
        "-p",
        "FragmentPath",
        "-p",
        "DropInPaths",
        "--",
        GATEWAY_UNIT,
        DASHBOARD_UNIT,
    ]


def start_argv():
    return G3_PREFIX + [SYSTEMCTL_BIN, "start", GATEWAY_UNIT, DASHBOARD_UNIT]


def systemctl_sequence():
    return [
        stop_argv(),
        show_min_argv(),
        sleep_argv(),
        show_min_argv(),
        daemon_reload_argv(),
        show_full_argv(),
        start_argv(),
    ]


def exec_start_gateway(mount):
    return f"{mount}/venv/bin/python3 -I {mount}/source/hermes_cli/main.py gateway run"


def exec_start_dashboard(mount):
    return (
        f"{mount}/venv/bin/python3 -I {mount}/source/hermes_cli/main.py "
        "dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build"
    )


KNOWN_GOOD_GATEWAY_EXEC = (
    "/run/hermes-stock-activation/known-good-snap/venv/bin/python3 -I "
    "/run/hermes-stock-activation/known-good-snap/source/hermes_cli/main.py gateway run"
)
KNOWN_GOOD_DASHBOARD_EXEC = (
    "/run/hermes-stock-activation/known-good-snap/venv/bin/python3 -I "
    "/run/hermes-stock-activation/known-good-snap/source/hermes_cli/main.py "
    "dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build"
)
CANDIDATE_GATEWAY_EXEC = (
    "/run/hermes-stock-activation/candidate-snap/venv/bin/python3 -I "
    "/run/hermes-stock-activation/candidate-snap/source/hermes_cli/main.py gateway run"
)
CANDIDATE_DASHBOARD_EXEC = (
    "/run/hermes-stock-activation/candidate-snap/venv/bin/python3 -I "
    "/run/hermes-stock-activation/candidate-snap/source/hermes_cli/main.py "
    "dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build"
)


def install_argv(path, mode_str):
    return [INSTALL_BIN, "-d", "-o", "0", "-g", "0", "-m", mode_str, path]


def generate_nonce():
    with open("/dev/urandom", "rb") as f:
        data = f.read(16)
    if len(data) != 16:
        raise SandboxRefused("urandom short")
    return data.hex()


def is_predictable_nonce(nonce):
    if not isinstance(nonce, str):
        return True
    if len(nonce) != 32:
        return True
    low = nonce.lower()
    for c in low:
        if c not in "0123456789abcdef":
            return True
    if len(set(low)) < 5:
        return True
    bad = {
        "0" * 32,
        "1" * 32,
        "f" * 32,
        "a" * 32,
        "0123456789abcdef0123456789abcdef",
        "fedcba9876543210fedcba9876543210",
        "deadbeefdeadbeefdeadbeefdeadbeef",
        "cafebabecafebabecafebabecafebabe",
    }
    if low in bad:
        return True
    return False


def validate_nonce(nonce):
    if is_predictable_nonce(nonce):
        raise SandboxRefused("predictable nonce")
    return nonce


def plan_dir(path, required_mode_oct, nonce=None):
    if nonce is not None:
        validate_nonce(nonce)
    if not isinstance(path, str) or not os.path.isabs(path):
        raise SandboxRefused("path")
    if _is_live_path(path):
        pass
    parent = os.path.dirname(os.path.normpath(path))
    try:
        pst = os.lstat(parent)
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISLNK(pst.st_mode):
            raise SandboxRefused("parent symlink")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if parent == "/var/lib":
            raise SandboxRefused("parent")
        mode_str = f"{required_mode_oct:04o}"
        return install_argv(path, mode_str)
    if stat.S_ISLNK(st.st_mode):
        raise SandboxRefused("symlink present")
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid == 0 and st.st_gid == 0 and mode == required_mode_oct:
        return None
    raise SandboxRefused("mode mismatch")


def live_install_plan(nonce):
    validate_nonce(nonce)
    out = []
    for p, m in [
        (LIVE_LIB, 0o700),
        (LIVE_LIB + "/backing", 0o700),
        (LIVE_LIB + "/backing/staging/" + nonce, 0o700),
        (LIVE_RUN, 0o755),
        (KNOWN_GOOD_MOUNT, 0o755),
        (CANDIDATE_MOUNT, 0o755),
    ]:
        argv = plan_dir(p, m, nonce=nonce)
        if argv is not None:
            out.append(argv)
    return out


def git_archive_argv(repo, sha, output):
    return [
        GIT_BIN,
        "-C",
        repo,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "archive",
        "--format=tar",
        "--output=" + output,
        sha,
    ]


def git_operator_argv(repo, sha, output):
    return G3_PREFIX + [
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_CONFIG_SYSTEM=/dev/null",
        "GIT_CONFIG_NOSYSTEM=1",
        GIT_BIN,
        "-C",
        repo,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "archive",
        "--format=tar",
        "--output=" + output,
        sha,
    ]


def tar_extract_argv(staging_source, tar_path):
    return [
        TAR_BIN,
        "-C",
        staging_source,
        "--no-same-owner",
        "--no-same-permissions",
        "-xf",
        tar_path,
    ]


def rsync_argv(src, dst):
    s = src.rstrip("/") + "/"
    d = dst.rstrip("/") + "/"
    return [
        RSYNC_BIN,
        "-a",
        "--fsync",
        "--numeric-ids",
        "--exclude=.git",
        "--exclude=.env",
        "--exclude=.envrc",
        "--exclude=__pycache__",
        "--exclude=*.pyc",
        "--exclude=.leases",
        "--",
        s,
        d,
    ]


def python_symlink_argv(bin_dir, name):
    return [LN_BIN, "-sfn", PYTHON_LINK_TARGET, os.path.join(bin_dir, name)]


def unsquashfs_argv(image, dest):
    return [UNSQUASHFS_BIN, "-no-xattrs", "-d", dest, image]


WALK_PROGRAM = (
    "import os, sys\n"
    "root=sys.argv[1]\n"
    "import stat as _st\n"
    "for dirpath, dirnames, filenames in os.walk(root, followlinks=False):\n"
    "    for _n in filenames:\n"
    "        _p=os.path.join(dirpath, _n)\n"
    "        _s=os.lstat(_p)\n"
    "        if _st.S_ISLNK(_s.st_mode):\n"
    "            continue\n"
    "        _fd=os.open(_p, os.O_RDONLY|os.O_NOFOLLOW)\n"
    "        try:\n"
    "            os.fsync(_fd)\n"
    "        finally:\n"
    "            os.close(_fd)\n"
    "    _d=os.open(dirpath, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\n"
    "    try:\n"
    "        os.fsync(_d)\n"
    "    finally:\n"
    "        os.close(_d)\n"
)


def fsync_walker_argv(root):
    return [PYTHON312_BIN, "-I", "-c", WALK_PROGRAM, root]


def known_good_plan():
    return {
        "kind": "known-good",
        "repo": KNOWN_GOOD_REPO,
        "sha": KNOWN_GOOD_SHA,
        "venv_src": KNOWN_GOOD_VENV_SRC,
        "interpreter_src": INTERPRETER_PREFIX,
        "deps_src": KNOWN_GOOD_DEPS_SRC,
        "image": KNOWN_GOOD_IMAGE,
        "mount": KNOWN_GOOD_MOUNT,
        "gateway_exec": KNOWN_GOOD_GATEWAY_EXEC,
        "dashboard_exec": KNOWN_GOOD_DASHBOARD_EXEC,
    }


def candidate_plan():
    return {
        "kind": "candidate",
        "repo": CANDIDATE_REPO,
        "sha": CANDIDATE_SHA,
        "venv_src": CANDIDATE_VENV_SRC,
        "interpreter_src": INTERPRETER_PREFIX,
        "deps_src": None,
        "image": CANDIDATE_IMAGE,
        "mount": CANDIDATE_MOUNT,
        "gateway_exec": CANDIDATE_GATEWAY_EXEC,
        "dashboard_exec": CANDIDATE_DASHBOARD_EXEC,
    }


_ALLOWED_BASENAMES = {"git", "tar", "rsync", "python3.12", "sha256sum", "mksquashfs", "unsquashfs", "ln"}
_BLOCKED_BASENAMES = {"sudo", "mount", "umount", "losetup", "systemctl", "install"}


def _check_runner_argv(argv, sandbox_root, source_repo=None):
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        raise SandboxRefused("argv")
    prog = argv[0]
    base = os.path.basename(prog)
    if base in _BLOCKED_BASENAMES:
        raise SandboxRefused("blocked")
    if base not in _ALLOWED_BASENAMES:
        raise SandboxRefused("not allowed")
    if base == "git":
        if "archive" not in argv:
            raise SandboxRefused("git only archive")
        out = None
        for a in argv:
            if a.startswith("--output="):
                out = a[len("--output="):]
        if out is None:
            raise SandboxRefused("no output")
        if not os.path.isabs(out) or not _is_under(os.path.normpath(out), os.path.normpath(sandbox_root)):
            raise SandboxRefused("output outside")
        return
    for a in argv[1:]:
        if a.startswith("-") or a.startswith("GIT_") or "=" in a and a.split("=")[0].isupper():
            continue
        if a in ("--",):
            continue
        if os.path.isabs(a):
            n = os.path.normpath(a)
            if _is_under(n, os.path.normpath(sandbox_root)):
                continue
            if base in ("tar", "rsync", "ln", "python3.12", "sha256sum", "mksquashfs", "unsquashfs"):
                if os.path.exists(a):
                    raise SandboxRefused("path outside")
                else:
                    parent = os.path.dirname(n)
                    if not _is_under(parent, os.path.normpath(sandbox_root)):
                        raise SandboxRefused("path outside")
                    continue
            raise SandboxRefused("path outside")


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(65536)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _copy_tree(src, dst):
    os.makedirs(dst, exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(src, topdown=True, followlinks=False):
        rel = os.path.relpath(dirpath, src)
        if rel == ".":
            dest_dir = dst
        else:
            dest_dir = os.path.join(dst, rel)
            os.makedirs(dest_dir, exist_ok=True)
            try:
                st = os.lstat(dirpath)
            except OSError:
                pass
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                dirnames.remove(d)
                continue
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(full)
                dest = os.path.join(dest_dir, d)
                try:
                    os.symlink(target, dest)
                except FileExistsError:
                    pass
                dirnames.remove(d)
        for n in filenames:
            full = os.path.join(dirpath, n)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                continue
            dest = os.path.join(dest_dir, n)
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(full)
                try:
                    if os.path.lexists(dest):
                        os.unlink(dest)
                    os.symlink(target, dest)
                except FileExistsError:
                    pass
            elif stat.S_ISREG(st.st_mode):
                with open(full, "rb") as rf, open(dest, "wb") as wf:
                    while True:
                        b = rf.read(65536)
                        if not b:
                            break
                        wf.write(b)
            else:
                raise SandboxRefused("special in src")


def _deny_tree(root):
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        for name in list(dirnames) + list(filenames):
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                continue
            if stat.S_ISFIFO(st.st_mode) or stat.S_ISSOCK(st.st_mode):
                raise SandboxRefused("fifo/socket")
            if stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
                raise SandboxRefused("device")
        rel_dir = os.path.relpath(dirpath, root)
        parts = [] if rel_dir == "." else rel_dir.split(os.sep)
        for comp in parts:
            if comp in (".git", ".env", ".envrc", "__pycache__", ".leases"):
                raise SandboxRefused("denylist " + comp)
            if comp.endswith(".pyc"):
                raise SandboxRefused("denylist pyc")
            if comp in ("state.db", "state.db-wal", "state.db-shm"):
                raise SandboxRefused("denylist state")
        for name in filenames:
            if name in ("state.db", "state.db-wal", "state.db-shm"):
                raise SandboxRefused("denylist state")
            if name.endswith(".pyc"):
                raise SandboxRefused("denylist pyc")
            if name in (".env", ".envrc", ".leases"):
                raise SandboxRefused("denylist " + name)
            if name == ".git":
                raise SandboxRefused("denylist .git")
        for name in dirnames:
            if name in (".git", ".env", ".envrc", "__pycache__", ".leases"):
                raise SandboxRefused("denylist " + name)
            if name.endswith(".pyc"):
                raise SandboxRefused("denylist pyc")


def _handle_symlinks(staging_root, venv_bins):
    for dirpath, dirnames, filenames in os.walk(staging_root, topdown=True, followlinks=False):
        for name in list(dirnames) + list(filenames):
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                continue
            if not stat.S_ISLNK(st.st_mode):
                continue
            target = os.readlink(full)
            parent = os.path.dirname(full)
            is_python_name = name in PYTHON_LINK_NAMES and parent in venv_bins
            if is_python_name:
                continue
            if os.path.isabs(target):
                raise SandboxRefused("abs symlink")
            dest_norm = os.path.normpath(os.path.join(parent, target))
            if _is_under(dest_norm, os.path.normpath(staging_root)):
                continue
            raise SandboxRefused("outside symlink")


def _secure_write(path, data):
    parent = os.path.dirname(path)
    try:
        orig_st = os.lstat(path)
        mode = stat.S_IMODE(orig_st.st_mode)
    except FileNotFoundError:
        mode = 0o644
    tmp = path + ".tmp." + os.urandom(4).hex()
    flags = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY
    fd = os.open(tmp, flags, mode)
    try:
        view = bytes(data)
        off = 0
        while off < len(view):
            n = os.write(fd, view[off:])
            if n == 0:
                raise OSError("short write")
            off += n
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, path)
    dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _rewrite_text_files(staging_root, mount_source, finder_prefix):
    for dirpath, dirnames, filenames in os.walk(staging_root, followlinks=False):
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_nlink > 1:
                raise SandboxRefused("hardlink")
            if os.path.basename(full) == "sitecustomize.py":
                raise SandboxRefused("sitecustomize")
            try:
                with open(full, "rb") as f:
                    data = f.read()
            except OSError:
                raise
            if b"sitecustomize" in data:
                raise SandboxRefused("sitecustomize content")
            changed = False
            new_data = data
            if name == "pyvenv.cfg":
                lines = new_data.split(b"\n")
                out_lines = []
                for line in lines:
                    s = line.strip()
                    if s.startswith(b"home"):
                        parts = line.split(b"=", 1)
                        if len(parts) == 2:
                            new_home = (mount_source.replace("/source", "/interpreter/bin")).encode()
                            out_lines.append(b"home = " + new_home)
                            changed = True
                            continue
                    out_lines.append(line)
                new_data = b"\n".join(out_lines)
            if finder_prefix.encode() in new_data:
                new_data = new_data.replace(finder_prefix.encode(), mount_source.encode())
                changed = True
            if changed:
                if mount_source.replace("/source", "/interpreter/bin").encode() not in new_data and b"home" in data:
                    pass
                _secure_write(full, new_data)


def _check_no_staging_absolute(staging_root, staging_norm, mount):
    import re

    pat = re.compile(rb"(?<![\w.\-])/[\w.\-]+(?:/[\w.\-]+)+")
    for dirpath, dirnames, filenames in os.walk(staging_root, followlinks=False):
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            with open(full, "rb") as f:
                data = f.read()
            if staging_norm.encode() in data:
                raise SandboxRefused("staging absolute remains")
            for m in pat.finditer(data):
                hit = m.group(0).decode("utf-8", errors="ignore")
                if hit.startswith(mount + "/"):
                    continue
                if hit.startswith("/run/hermes-stock-activation/"):
                    if hit.startswith(mount + "/"):
                        continue
                    raise SandboxRefused("absolute remains " + hit)
                if hit.startswith(("/home/", "/tmp/", "/var/", "/opt/", "/etc/", "/run/")):
                    raise SandboxRefused("absolute remains " + hit)
                if hit.startswith("/usr/") or hit.startswith("/bin/") or hit.startswith("/sbin/"):
                    if b"home" in data.lower() or b"finder" in data.lower():
                        raise SandboxRefused("absolute remains " + hit)
                    continue


def _build_manifest(staging_root, image_roots):
    entries = []
    for base in image_roots:
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            for name in list(dirnames) + list(filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, staging_root)
                try:
                    st = os.lstat(full)
                except FileNotFoundError:
                    continue
                mode = f"{stat.S_IMODE(st.st_mode):04o}"
                if stat.S_ISLNK(st.st_mode):
                    target = os.readlink(full)
                    entries.append((rel, "symlink", mode, "-", target))
                elif stat.S_ISDIR(st.st_mode):
                    entries.append((rel, "dir", mode, "-", "-"))
                elif stat.S_ISREG(st.st_mode):
                    h = _sha256_file(full)
                    entries.append((rel, "file", mode, h, "-"))
                else:
                    raise SandboxRefused("special manifest")
    entries.sort(key=lambda e: e[0])
    lines = []
    for rel, typ, mode, h, tgt in entries:
        lines.append(f"{rel} {typ} {mode} {h} {tgt}")
    text = "\n".join(lines) + ("\n" if lines else "")
    digest = hashlib.sha256(text.encode()).hexdigest()
    return text, digest


def export_sandbox_closure(host, runner, sandbox_root, *, kind, source_repo, source_sha, venv_src, interpreter_src, deps_src=None, finder_prefix):
    if not hasattr(host, "file_uid") or not callable(host.file_uid):
        raise SandboxRefused("missing file_uid")
    try:
        uid = host.file_uid(sandbox_root)
    except RuntimeError:
        raise
    except Exception as e:
        raise SandboxRefused(str(e))
    if isinstance(uid, bool) or not isinstance(uid, int):
        raise SandboxRefused("file_uid not int")
    if not isinstance(sandbox_root, str) or not os.path.isabs(sandbox_root):
        raise SandboxRefused("root")
    sroot = os.path.normpath(sandbox_root)
    if _is_live_path(sroot):
        raise SandboxRefused("live root")
    if kind not in ("known-good", "candidate"):
        raise SandboxRefused("kind")
    if kind == "candidate" and deps_src is not None:
        raise SandboxRefused("candidate no deps")
    if kind == "known-good" and deps_src is None:
        raise SandboxRefused("known-good needs deps")
    mount = KNOWN_GOOD_MOUNT if kind == "known-good" else CANDIDATE_MOUNT
    mount_source = mount + "/source"
    nonce = generate_nonce()
    if is_predictable_nonce(nonce):
        raise SandboxRefused("predictable nonce")
    staging_parent = os.path.join(sroot, "staging")
    os.makedirs(staging_parent, exist_ok=True)
    staging_root = os.path.join(staging_parent, nonce)
    if os.path.lexists(staging_root):
        raise SandboxRefused("staging exists")
    os.makedirs(staging_root, exist_ok=True)
    source_dir = os.path.join(staging_root, "source")
    os.makedirs(source_dir, exist_ok=True)

    def _run(argv):
        _check_runner_argv(argv, sroot, source_repo=source_repo)
        if hasattr(runner, "run"):
            try:
                return runner.run(argv, {"PATH": "/usr/bin:/bin"})
            except TypeError:
                return runner.run(argv)
        else:
            return runner(argv)

    tar1 = os.path.join(staging_root, "repo-1.tar")
    tar2 = os.path.join(staging_root, "repo-2.tar")
    if os.path.lexists(tar1) or os.path.lexists(tar2):
        raise SandboxRefused("tar exists")
    _run(git_archive_argv(source_repo, source_sha, tar1))
    _run(git_archive_argv(source_repo, source_sha, tar2))
    h1 = _sha256_file(tar1)
    h2 = _sha256_file(tar2)
    if h1 != h2:
        raise SandboxRefused("archive hash mismatch")
    _run(tar_extract_argv(source_dir, tar1))
    _deny_tree(source_dir)
    venv_dst = os.path.join(staging_root, "venv")
    interp_dst = os.path.join(staging_root, "interpreter")
    _copy_tree(venv_src, venv_dst)
    _copy_tree(interpreter_src, interp_dst)
    deps_dst = None
    if deps_src is not None:
        deps_dst = os.path.join(staging_root, "deps")
        _copy_tree(deps_src, deps_dst)
    image_roots = [source_dir, venv_dst, interp_dst] + ([deps_dst] if deps_dst else [])
    for r in image_roots:
        _deny_tree(r)
    venv_bins = set()
    for base in ([venv_dst] + ([deps_dst] if deps_dst else [])):
        b = os.path.join(base, "bin")
        if os.path.isdir(b):
            venv_bins.add(b)
    _handle_symlinks(staging_root, venv_bins)
    for b in list(venv_bins):
        for n in PYTHON_LINK_NAMES:
            link = os.path.join(b, n)
            try:
                st = os.lstat(link)
                is_link = stat.S_ISLNK(st.st_mode)
            except FileNotFoundError:
                is_link = False
            target_now = os.readlink(link) if is_link else None
            if target_now == PYTHON_LINK_TARGET:
                continue
            if os.path.lexists(link):
                os.unlink(link)
            os.symlink(PYTHON_LINK_TARGET, link)
    try:
        _rewrite_text_files(staging_root, mount_source, finder_prefix)
    except OSError as e:
        return {"status": "durable-state-unknown", "success": False, "rollback_clean": False, "error": str(e)}
    try:
        _check_no_staging_absolute(staging_root, staging_root, mount)
    except SandboxRefused:
        raise
    for r in image_roots:
        for dirpath, dirnames, filenames in os.walk(r, followlinks=False):
            for n in filenames:
                fp = os.path.join(dirpath, n)
                try:
                    st = os.lstat(fp)
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                    raise SandboxRefused("hardlink")
                if n == "sitecustomize.py":
                    raise SandboxRefused("sitecustomize")
    manifest_text, digest = _build_manifest(staging_root, image_roots)
    digest_file = os.path.join(sroot, f"export-{kind}.digest.json")
    import json as _json

    try:
        live_uid = host.file_uid(os.path.dirname(digest_file))
        _ = live_uid
    except Exception:
        pass
    try:
        payload = _json.dumps({"manifest": manifest_text, "digest": digest, "signed": False, "kind": kind}, sort_keys=True, indent=2).encode()
        _secure_write(digest_file, payload)
    except OSError as e:
        return {"status": "durable-state-unknown", "success": False, "rollback_clean": False, "error": str(e)}
    try:
        d_uid = host.file_uid(digest_file)
        live_published = (d_uid == 0)
    except Exception:
        live_published = False
    _run(fsync_walker_argv(staging_root))
    return {
        "status": "sandbox-exported",
        "success": True,
        "digest": digest,
        "manifest": manifest_text,
        "digest_file": digest_file,
        "signed": False,
        "live_published": live_published,
        "rollback_clean": True,
    }
