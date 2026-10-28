"""Hermetic fixture OS adapter. No live effects.

Filesystem operations are confined to fixture_root. Subprocess execution
is confined to an injected transport; the default refuses to spawn.
Closure export and provisioning remain unspecified (inert).
"""

import os
import stat
import subprocess

_FORBIDDEN = (
    "/home/ubuntu/.hermes/.env",
    "/var/lib/hermes-stock-activation",
    "/var/lib/hermes-cutover",
    "/etc/systemd",
    "/opt",
    "/home/ubuntu/worktrees/worktrees/hermes-upstream-integrate-20261025",
    "/home/ubuntu/.hermes/runtime",
)


class OsAdapterRefused(RuntimeError):
    pass


class PublishResult:
    def __init__(self, state, final_exists):
        self.state = state  # "published" or "durable-state-unknown"
        self.final_exists = final_exists
        self.success = state == "published"
        self.rollback_clean = False


class FilesystemAdapter:
    def __init__(self, fixture_root, opener=None, fsync_file=None, fsync_dir=None):
        self.fixture_root = fixture_root
        self._opener = opener or os.open
        self._fsync_file = fsync_file or os.fsync
        self._fsync_dir = fsync_dir or os.fsync

    def _forbidden_check(self, path):
        if not isinstance(path, str):
            raise OsAdapterRefused("path type")
        for forb in _FORBIDDEN:
            if forb in path:
                raise OsAdapterRefused("forbidden")

    def _lexical(self, path):
        # No syscalls here. Returns normalized absolute candidate or raises.
        self._forbidden_check(path)
        if not isinstance(self.fixture_root, str):
            raise OsAdapterRefused("fixture root type")
        root = os.path.normpath(self.fixture_root)
        if not os.path.isabs(root):
            raise OsAdapterRefused("fixture root not absolute")
        if path == "":
            raise OsAdapterRefused("empty path")
        if os.path.isabs(path):
            norm = os.path.normpath(path)
            if norm == root:
                return root
            if not path.startswith(root + "/"):
                # Even if normpath collapses back under root, raw prefix
                # mismatch means traversal/escape attempt.
                raise OsAdapterRefused("outside")
            rest_raw = path[len(root) + 1:]
            if rest_raw == "":
                return root
            parts = rest_raw.split("/")
            for comp in parts:
                if comp == "" or comp == "." or comp == "..":
                    raise OsAdapterRefused("component")
            candidate = os.path.normpath(path)
            if candidate != root and not candidate.startswith(root + "/"):
                raise OsAdapterRefused("outside")
            return candidate
        # relative path: join lexically under root
        parts = path.split("/")
        for comp in parts:
            if comp == "" or comp == "." or comp == "..":
                raise OsAdapterRefused("component")
        candidate = os.path.normpath(os.path.join(root, path))
        if candidate != root and not candidate.startswith(root + "/"):
            raise OsAdapterRefused("outside")
        return candidate

    def _walk_no_symlink(self, prefixes):
        for prefix in prefixes:
            try:
                st = os.lstat(prefix)
            except FileNotFoundError:
                continue
            except NotADirectoryError:
                raise OsAdapterRefused("not a directory")
            if stat.S_ISLNK(st.st_mode):
                raise OsAdapterRefused("symlink")

    def _prefixes(self, candidate, root):
        if candidate == root:
            return [root]
        rel = candidate[len(root) + 1:]
        comps = rel.split("/")
        prefixes = [root]
        cur = root
        for comp in comps:
            cur = cur + "/" + comp
            prefixes.append(cur)
        return prefixes

    def _resolve(self, path):
        candidate = self._lexical(path)
        root = os.path.normpath(self.fixture_root)
        prefixes = self._prefixes(candidate, root)
        self._walk_no_symlink(prefixes)
        return candidate

    def write_temp(self, path, data: bytes):
        resolved = self._resolve(path)
        flags = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY
        fd = self._opener(resolved, flags, 0o600)
        try:
            view = bytes(data)
            total = 0
            while total < len(view):
                n = os.write(fd, view[total:])
                if n == 0:
                    raise OSError("short write")
                total += n
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        else:
            os.close(fd)

    def file_fsync(self, path):
        resolved = self._resolve(path)
        fd = self._opener(resolved, os.O_RDWR | os.O_NOFOLLOW)
        try:
            self._fsync_file(fd)
        finally:
            os.close(fd)

    def dir_fsync(self, path):
        resolved = self._resolve(path)
        flag_dir = getattr(os, "O_DIRECTORY", 0)
        fd = self._opener(resolved, os.O_RDONLY | flag_dir | os.O_NOFOLLOW)
        try:
            self._fsync_dir(fd)
        finally:
            os.close(fd)

    def rename_path(self, src, dst):
        s = self._resolve(src)
        d = self._resolve(dst)
        os.rename(s, d)

    def read_bytes(self, path):
        resolved = self._resolve(path)
        fd = self._opener(resolved, os.O_RDONLY | os.O_NOFOLLOW)
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

    def file_uid(self, path):
        resolved = self._resolve(path)
        st = os.lstat(resolved)
        return st.st_uid

    def file_info(self, path):
        self._forbidden_check(path)
        candidate = self._lexical(path)
        root = os.path.normpath(self.fixture_root)
        prefixes = self._prefixes(candidate, root)
        # Check all parents for symlinks, but allow final to be reported.
        parents = prefixes[:-1] if len(prefixes) > 1 else prefixes
        # If candidate == root, prefixes == [root], parents == [root];
        # lstat below will report root itself.
        if candidate != root:
            self._walk_no_symlink(parents)
        else:
            self._walk_no_symlink(parents)
            # fall through to lstat root
        try:
            st = os.lstat(candidate)
        except FileNotFoundError:
            return {"exists": False, "is_symlink": False, "kernel_enforced": False}
        except NotADirectoryError:
            raise OsAdapterRefused("not a directory")
        is_link = stat.S_ISLNK(st.st_mode)
        return {
            "exists": True,
            "is_symlink": is_link,
            "kernel_enforced": False,
            "mode": stat.S_IMODE(st.st_mode),
            "size": st.st_size,
        }

    def publish_sequence(self, src_bytes, tmp_name, final_name):
        try:
            self.write_temp(tmp_name, src_bytes)
            self.file_fsync(tmp_name)
            self.rename_path(tmp_name, final_name)
            resolved_final = self._resolve(final_name)
            parent = os.path.dirname(resolved_final)
            if parent == "":
                raise OsAdapterRefused("parent")
            self.dir_fsync(parent)
        except OSError:
            try:
                try:
                    resolved = self._resolve(final_name)
                except OsAdapterRefused:
                    final_exists = False
                else:
                    try:
                        os.lstat(resolved)
                        final_exists = True
                    except FileNotFoundError:
                        final_exists = False
                    except OSError:
                        final_exists = False
            except Exception:
                final_exists = False
            return PublishResult("durable-state-unknown", final_exists)
        return PublishResult("published", True)


class RefuseTransport:
    def run(self, argv, env):
        raise OsAdapterRefused("spawn refused")


class RealFixtureTransport:
    def __init__(self, fixture_root):
        self.fixture_root = fixture_root

    def run(self, argv, env):
        if not isinstance(argv, list) or not argv or not all(
            isinstance(x, str) for x in argv
        ):
            raise OsAdapterRefused("argv")
        if not isinstance(env, dict) or env != {"PATH": "/usr/bin:/bin"}:
            raise OsAdapterRefused("env")
        prog = argv[0]
        if not isinstance(prog, str) or not os.path.isabs(prog):
            raise OsAdapterRefused("absolute")
        if os.path.basename(prog) in (
            "systemctl",
            "mount",
            "umount",
            "sudo",
            "git",
            "hermes",
        ):
            raise OsAdapterRefused("blocked basename")
        for forb in _FORBIDDEN:
            if forb in prog:
                raise OsAdapterRefused("forbidden")
        if not isinstance(self.fixture_root, str):
            raise OsAdapterRefused("fixture root type")
        root = os.path.normpath(self.fixture_root)
        if not os.path.isabs(root):
            raise OsAdapterRefused("fixture root not absolute")
        cand = os.path.normpath(prog)
        if cand != root and not cand.startswith(root + "/"):
            raise OsAdapterRefused("outside")
        try:
            st = os.lstat(cand)
        except FileNotFoundError:
            raise OsAdapterRefused("missing")
        except NotADirectoryError:
            raise OsAdapterRefused("not a directory")
        if stat.S_ISLNK(st.st_mode):
            raise OsAdapterRefused("symlink")
        if not stat.S_ISREG(st.st_mode):
            raise OsAdapterRefused("not regular")
        # Refuse symlinked parents up to fixture root.
        parent_dir = os.path.dirname(cand)
        # Build parent prefixes from root to parent_dir.
        if cand != root:
            if parent_dir == root:
                parent_prefixes = [root]
            elif parent_dir.startswith(root + "/"):
                rel = parent_dir[len(root) + 1:]
                cur = root
                parent_prefixes = [root]
                for comp in rel.split("/"):
                    cur = cur + "/" + comp
                    parent_prefixes.append(cur)
            else:
                raise OsAdapterRefused("outside")
            for prefix in parent_prefixes:
                try:
                    pst = os.lstat(prefix)
                except FileNotFoundError:
                    raise OsAdapterRefused("missing parent")
                if stat.S_ISLNK(pst.st_mode):
                    raise OsAdapterRefused("symlink parent")
        return subprocess.run(
            argv,
            shell=False,
            env=env,
            cwd=self.fixture_root,
            timeout=5,
            capture_output=True,
            check=False,
        )


class SubprocessBoundary:
    def __init__(self, transport=None, fixture_root=None):
        self.transport = transport if transport is not None else RefuseTransport()
        self.fixture_root = fixture_root

    def run(self, argv, env=None):
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(x, str) for x in argv)
        ):
            raise OsAdapterRefused("argv")
        if os.path.basename(argv[0]) in (
            "systemctl",
            "mount",
            "umount",
            "sudo",
            "git",
            "hermes",
        ):
            raise OsAdapterRefused("blocked basename")
        eff_env = env if env is not None else {"PATH": "/usr/bin:/bin"}
        return self.transport.run(argv, eff_env)


def export_closure(*args, **kwargs):
    return {"status": "CLOSURE_ENUMERATION_UNSPECIFIED", "copied": 0, "git_invoked": False}


def provisioning_recipe():
    return {
        "status": "INERT",
        "executed": False,
        "journal_dir": "/var/lib/hermes-stock-activation",
        "mode": 0o700,
        "uid": 0,
        "parent": "/var/lib",
        "parent_mode": 0o755,
        "parent_uid": 0,
        "target_sha": "daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06",
        "known_good_sha": "1d9a377fa00ce0e663e274e16b63c75e36233b9e",
        "mount_argv": None,
        "systemctl_argv": None,
        "closure_file_set": None,
    }
