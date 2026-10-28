import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts.stock_activation import closure_boundary as cb
from scripts.stock_activation.host import Host, LiveRootHost


class RealRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, env=None):
        self.calls.append((list(argv), dict(env) if isinstance(env, dict) else env))
        eff = env if isinstance(env, dict) else {"PATH": "/usr/bin:/bin"}
        return subprocess.run(argv, env=eff, capture_output=True, check=False)


class CountingRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, env=None):
        self.calls.append((list(argv), env))
        raise AssertionError("should not be called")


def run_cmd(argv, cwd=None, env=None):
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, check=False)


def git_env():
    e = dict(os.environ)
    e["GIT_CONFIG_GLOBAL"] = "/dev/null"
    e["GIT_CONFIG_SYSTEM"] = "/dev/null"
    e["GIT_CONFIG_NOSYSTEM"] = "1"
    return e


def init_repo(repo_dir, files, symlinks=None):
    os.makedirs(repo_dir, exist_ok=True)
    run_cmd(["/usr/bin/git", "init", "-q"], cwd=repo_dir)
    run_cmd(["/usr/bin/git", "config", "user.email", "t@t"], cwd=repo_dir)
    run_cmd(["/usr/bin/git", "config", "user.name", "t"], cwd=repo_dir)
    for rel, content in files.items():
        full = os.path.join(repo_dir, rel)
        os.makedirs(os.path.dirname(full) or repo_dir, exist_ok=True)
        with open(full, "wb") as f:
            f.write(content if isinstance(content, bytes) else content.encode())
    if symlinks:
        for rel, target in symlinks.items():
            full = os.path.join(repo_dir, rel)
            os.makedirs(os.path.dirname(full) or repo_dir, exist_ok=True)
            if os.path.lexists(full):
                os.unlink(full)
            os.symlink(target, full)
    run_cmd(["/usr/bin/git", "add", "-f", "-A"], cwd=repo_dir)
    r = run_cmd(["/usr/bin/git", "commit", "-qm", "init"], cwd=repo_dir)
    assert r.returncode == 0, r.stderr
    r = run_cmd(["/usr/bin/git", "rev-parse", "HEAD"], cwd=repo_dir)
    return r.stdout.strip()


FIXTURE_NONCE = "fixture-nonce-459595"
FINDER_ORIG = "/tmp/finder-orig-459595"


def make_venv_fixture(base, home_val=FINDER_ORIG):
    bin_d = os.path.join(base, "bin")
    os.makedirs(bin_d, exist_ok=True)
    for n in ("python", "python3", "python3.14"):
        p = os.path.join(bin_d, n)
        if os.path.lexists(p):
            os.unlink(p)
        os.symlink("/usr/bin/python3.12", p)
    with open(os.path.join(base, "pyvenv.cfg"), "w") as f:
        f.write(f"home = {home_val}\ninclude-system-site-packages = false\nversion = 3.12\n")


def make_interp_fixture(base):
    bin_d = os.path.join(base, "bin")
    os.makedirs(bin_d, exist_ok=True)
    with open(os.path.join(bin_d, "python3.14"), "w") as f:
        f.write("fake-interp")
    os.chmod(os.path.join(bin_d, "python3.14"), 0o755)


def make_main_py(nonce=FIXTURE_NONCE):
    return f"print({nonce!r})\nprint(__file__)\n"


class TestExactArgv(unittest.TestCase):
    def test_mksquashfs(self):
        argv = cb.mksquashfs_argv("/tmp/staged", "/tmp/img.tmp")
        self.assertEqual(argv, ["/usr/bin/mksquashfs", "/tmp/staged", "/tmp/img.tmp", "-comp", "xz", "-b", "131072", "-reproducible", "-mkfs-time", "0", "-all-root", "-no-xattrs", "-no-hardlinks", "-no-exports", "-no-recovery", "-no-progress", "-noappend"])

    def test_losetup(self):
        argv = cb.losetup_argv("/var/lib/hermes-stock-activation/backing/known-good.squashfs")
        self.assertEqual(argv, ["/usr/sbin/losetup", "--find", "--show", "--read-only", "--nooverlap", "--", "/var/lib/hermes-stock-activation/backing/known-good.squashfs"])
        joined = " ".join(argv)
        self.assertNotIn("/dev/loop0", joined)

    def test_mount(self):
        argv = cb.mount_argv("/dev/loop9", "/run/hermes-stock-activation/known-good-snap")
        self.assertEqual(argv, ["/usr/bin/mount", "-n", "-t", "squashfs", "-o", "ro,nosuid,nodev", "/dev/loop9", "/run/hermes-stock-activation/known-good-snap"])
        self.assertEqual(argv[5], "ro,nosuid,nodev")
        for bad in ("noexec", "rw", "remount", "bind"):
            self.assertNotIn(bad, argv[5].split(","))
            for el in argv:
                if el == "ro,nosuid,nodev":
                    continue
                self.assertNotEqual(el, bad)
        self.assertEqual(len(argv), 8)

    def test_findmnt(self):
        argv = cb.findmnt_argv("/run/hermes-stock-activation/known-good-snap")
        self.assertEqual(argv, ["/usr/bin/findmnt", "-n", "-o", "FSTYPE,OPTIONS,SOURCE,TARGET", "--target", "/run/hermes-stock-activation/known-good-snap"])

    def test_images_mounts(self):
        self.assertEqual(cb.KNOWN_GOOD_IMAGE, "/var/lib/hermes-stock-activation/backing/known-good.squashfs")
        self.assertEqual(cb.CANDIDATE_IMAGE, "/var/lib/hermes-stock-activation/backing/candidate.squashfs")
        self.assertEqual(cb.KNOWN_GOOD_MOUNT, "/run/hermes-stock-activation/known-good-snap")
        self.assertEqual(cb.CANDIDATE_MOUNT, "/run/hermes-stock-activation/candidate-snap")

    def test_g3_systemctl(self):
        seq = cb.systemctl_sequence()
        self.assertEqual(len(seq), 7)
        for argv in seq:
            self.assertEqual(argv[:9], cb.G3_PREFIX)
            self.assertEqual(argv[0], "/usr/bin/sudo")
            self.assertEqual(argv[1], "-n")
            joined = " ".join(argv)
            self.assertNotIn("PYTHONPATH", joined)
            self.assertNotIn("restart", joined)
            self.assertNotIn("restart", " ".join(argv).lower().replace("nrestarts", ""))
            # ensure NRestarts present where expected but no lowercase restart element
            for el in argv:
                self.assertNotIn("restart", el)
        self.assertEqual(seq[0][9:], ["/usr/bin/systemctl", "stop", "hermes-gateway.service", "hermes-dashboard.service"])
        self.assertIn("show", seq[1])
        self.assertIn("5", seq[2])
        self.assertEqual(seq[1], seq[3])
        self.assertEqual(seq[4], cb.G3_PREFIX + ["/usr/bin/systemctl", "daemon-reload"])
        self.assertIn("ExecStart", " ".join(seq[5]))
        self.assertIn("EnvironmentFiles", " ".join(seq[5]))
        self.assertEqual(seq[6][9:], ["/usr/bin/systemctl", "start", "hermes-gateway.service", "hermes-dashboard.service"])
        # order stop, show, sleep, show, daemon-reload, show-full, start
        self.assertEqual(seq[0][10], "stop")
        self.assertEqual(seq[1][10], "show")
        self.assertTrue(seq[2][9].endswith("sleep"))
        self.assertEqual(seq[4][10], "daemon-reload")
        self.assertEqual(seq[6][10], "start")

    def test_exec_start(self):
        self.assertEqual(cb.exec_start_gateway(cb.KNOWN_GOOD_MOUNT), cb.KNOWN_GOOD_GATEWAY_EXEC)
        self.assertEqual(cb.exec_start_dashboard(cb.KNOWN_GOOD_MOUNT), cb.KNOWN_GOOD_DASHBOARD_EXEC)
        self.assertEqual(cb.KNOWN_GOOD_GATEWAY_EXEC, "/run/hermes-stock-activation/known-good-snap/venv/bin/python3 -I /run/hermes-stock-activation/known-good-snap/source/hermes_cli/main.py gateway run")
        self.assertEqual(cb.KNOWN_GOOD_DASHBOARD_EXEC, "/run/hermes-stock-activation/known-good-snap/venv/bin/python3 -I /run/hermes-stock-activation/known-good-snap/source/hermes_cli/main.py dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build")
        self.assertEqual(cb.CANDIDATE_GATEWAY_EXEC, "/run/hermes-stock-activation/candidate-snap/venv/bin/python3 -I /run/hermes-stock-activation/candidate-snap/source/hermes_cli/main.py gateway run")

    def test_install(self):
        self.assertEqual(cb.install_argv("/var/lib/hermes-stock-activation", "0700"), ["/usr/bin/install", "-d", "-o", "0", "-g", "0", "-m", "0700", "/var/lib/hermes-stock-activation"])
        self.assertEqual(cb.install_argv("/run/hermes-stock-activation/known-good-snap", "0755"), ["/usr/bin/install", "-d", "-o", "0", "-g", "0", "-m", "0755", "/run/hermes-stock-activation/known-good-snap"])

    def test_archive_tar_rsync_ln_unsquashfs(self):
        ga = cb.git_archive_argv("/repo", "abc123", "/tmp/out.tar")
        self.assertEqual(ga, ["/usr/bin/git", "-C", "/repo", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "archive", "--format=tar", "--output=/tmp/out.tar", "abc123"])
        op = cb.git_operator_argv("/repo", "abc123", "/tmp/out.tar")
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", op)
        self.assertIn("GIT_CONFIG_SYSTEM=/dev/null", op)
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", op)
        ta = cb.tar_extract_argv("/tmp/staging/source", "/tmp/a.tar")
        self.assertEqual(ta, ["/usr/bin/tar", "-C", "/tmp/staging/source", "--no-same-owner", "--no-same-permissions", "-xf", "/tmp/a.tar"])
        ra = cb.rsync_argv("/src", "/dst")
        self.assertEqual(ra, ["/usr/bin/rsync", "-a", "--fsync", "--numeric-ids", "--exclude=.git", "--exclude=.env", "--exclude=.envrc", "--exclude=__pycache__", "--exclude=*.pyc", "--exclude=.leases", "--", "/src/", "/dst/"])
        la = cb.python_symlink_argv("/tmp/venv/bin", "python")
        self.assertEqual(la, ["/usr/bin/ln", "-sfn", "../../interpreter/bin/python3.14", "/tmp/venv/bin/python"])
        ua = cb.unsquashfs_argv("/tmp/img", "/tmp/dest")
        self.assertEqual(ua, ["/usr/bin/unsquashfs", "-no-xattrs", "-d", "/tmp/dest", "/tmp/img"])

    def test_hex_decode(self):
        self.assertEqual(cb._INTERPRETER_DIR_HEX, "707974686f6e2d332e31342e392b32303236313032312d6c696e75782d61726d3634")
        self.assertEqual(cb.INTERPRETER_DIR_NAME, "python-3.14.9+20261021-linux-arm64")
        self.assertEqual(cb.INTERPRETER_PREFIX, "/home/ubuntu/.hermes/tools/python-3.14.9+20261021-linux-arm64")

    def test_pins(self):
        self.assertEqual(cb.KNOWN_GOOD_REPO, "/home/ubuntu/.hermes/hermes-agent")
        self.assertEqual(cb.KNOWN_GOOD_SHA, "1d9a377fa00ce0e663e274e16b63c75e36233b9e")
        self.assertEqual(cb.KNOWN_GOOD_VENV_SRC, "/home/ubuntu/.hermes/runtime/cutover-generations/gen-1d9a377fa00c/venv")
        self.assertEqual(cb.KNOWN_GOOD_DEPS_SRC, "/home/ubuntu/.hermes/installs/fb097378e0b9d4af/environments/3db97cb527a04c959b19c09c3c48bf7c/venv")
        self.assertEqual(cb.CANDIDATE_REPO, "/home/ubuntu/.hermes/runtime/stock-candidates/daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06")
        self.assertEqual(cb.CANDIDATE_SHA, "daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06")
        self.assertEqual(cb.CANDIDATE_VENV_SRC, "/home/ubuntu/.hermes/runtime/cutover-generations/gen-daec3cd4c6d3/venv")

    def test_candidate_no_deps_known_good_has_deps(self):
        kg = cb.known_good_plan()
        cd = cb.candidate_plan()
        self.assertIsNotNone(kg["deps_src"])
        self.assertIsNone(cd["deps_src"])


class TestHost(unittest.TestCase):
    def test_live_file_uid(self):
        h = LiveRootHost()
        with self.assertRaises(RuntimeError) as cm:
            h.file_uid("/tmp/x")
        self.assertIn("ACTIVATION_NOT_AUTHORIZED", str(cm.exception))

    def test_host_base(self):
        h = Host()
        with self.assertRaises(NotImplementedError):
            h.file_uid("/tmp/x")

    def test_sandbox_temp_allowed(self):
        self.assertTrue(issubclass(cb.SandboxHost, Host))
        with tempfile.TemporaryDirectory() as td:
            sandbox = os.path.join(td, "sandbox")
            os.makedirs(sandbox)
            host = cb.SandboxHost(sandbox)
            uid = host.file_uid(sandbox)
            self.assertIsInstance(uid, int)
            self.assertNotIsInstance(uid, bool)
            self.assertFalse(cb._is_live_path(sandbox))
            self.assertFalse(cb._is_live_path("/home/ubuntu/.hermes/cache/scratch/abc-459595"))
            for p in (
                "/var/lib/hermes-stock-activation",
                "/var/lib/hermes-stock-activation/backing/staging/x",
                "/run/hermes-stock-activation",
                "/run/hermes-stock-activation/known-good-snap",
                "/home/ubuntu/.hermes",
                "/home/ubuntu/.hermes/.env",
                "/home/ubuntu/.hermes/hermes-agent",
                "/home/ubuntu/.hermes/hermes-agent/venv",
                "/home/ubuntu/.hermes/runtime",
                "/home/ubuntu/.hermes/runtime/cutover-generations/gen-1d9a377fa00c/venv",
                "/home/ubuntu/.hermes/installs",
                "/home/ubuntu/.hermes/installs/fb097378e0b9d4af/environments/3db97cb527a04c959b19c09c3c48bf7c/venv",
                "/home/ubuntu/.hermes/tools",
                "/home/ubuntu/.hermes/tools/python-3.14.9+20261021-linux-arm64",
            ):
                self.assertTrue(cb._is_live_path(p), msg=p)
            with self.assertRaises(cb.SandboxRefused):
                cb.SandboxHost("/home/ubuntu/.hermes/hermes-agent")

    def test_exporter_missing_file_uid_zero_calls(self):
        class Empty:
            pass
        runner = CountingRunner()
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "sandbox")
            os.makedirs(root)
            with self.assertRaises(Exception):
                cb.export_sandbox_closure(Empty(), runner, root, kind="known-good", source_repo="/tmp/r", source_sha="abc", venv_src="/tmp/v", interpreter_src="/tmp/i", deps_src="/tmp/d", finder_prefix="/tmp/f")
            self.assertEqual(runner.calls, [])


class TestPlanner(unittest.TestCase):
    def test_foreign_dir(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "foreign")
            os.makedirs(d)
            os.chmod(d, 0o755)
            st_before = os.lstat(d)
            mode_before = stat.S_IMODE(st_before.st_mode)
            # require 0700 but has 0755 -> refuse
            with self.assertRaises(Exception):
                cb.plan_dir(d, 0o700)
            st_after = os.lstat(d)
            self.assertEqual(stat.S_IMODE(st_after.st_mode), mode_before)
            # no install executed: plan_dir is pure, no runner involved

    def test_predictable_nonce(self):
        with self.assertRaises(Exception):
            cb.validate_nonce("0" * 32)
        with self.assertRaises(Exception):
            cb.validate_nonce("a" * 32)
        with self.assertRaises(Exception):
            cb.plan_dir("/tmp/whatever/staging/" + "0" * 32, 0o700, nonce="0" * 32)


def build_fixture(tmpbase, extra_files=None, symlinks=None, with_deps=False):
    repo = os.path.join(tmpbase, "repo")
    files = {
        "hermes_cli/main.py": make_main_py(),
        "credential_note.txt": "credential allowed\n",
        "app.conf": f"finder={FINDER_ORIG}\n",
    }
    if extra_files:
        files.update(extra_files)
    sha = init_repo(repo, files, symlinks)
    venv_src = os.path.join(tmpbase, "venvsrc")
    make_venv_fixture(venv_src)
    interp_src = os.path.join(tmpbase, "interpsrc")
    make_interp_fixture(interp_src)
    deps_src = None
    if with_deps:
        deps_src = os.path.join(tmpbase, "depssrc")
        make_venv_fixture(deps_src)
    return repo, sha, venv_src, interp_src, deps_src


class TestExport(unittest.TestCase):
    def test_success_known_good(self):
        with tempfile.TemporaryDirectory() as td:
            sandbox = os.path.join(td, "sandbox")
            os.makedirs(sandbox)
            host = cb.SandboxHost(sandbox)
            repo, sha, venv_src, interp_src, deps_src = build_fixture(os.path.join(td, "fix"), with_deps=True)
            runner = RealRunner()
            res = cb.export_sandbox_closure(host, runner, sandbox, kind="known-good", source_repo=repo, source_sha=sha, venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src, finder_prefix=FINDER_ORIG)
            self.assertEqual(res["status"], "sandbox-exported")
            self.assertFalse(res["signed"])
            self.assertFalse(res["live_published"])
            # digest outside image trees, inside sandbox
            df = res["digest_file"]
            self.assertTrue(df.startswith(sandbox + "/"))
            staging_parent = os.path.join(sandbox, "staging")
            # find staging_root: the subdir containing source
            found = [os.path.join(staging_parent, n) for n in os.listdir(staging_parent)]
            self.assertTrue(len(found) >= 1)
            for sr in found:
                self.assertNotEqual(os.path.commonpath([df, sr]), sr)
            # no .git component in export
            for sr in found:
                src = os.path.join(sr, "source")
                if os.path.isdir(src):
                    for dp, dn, fn in os.walk(src):
                        self.assertNotIn(".git", dn)
                        self.assertNotIn(".git", fn)
            # run python3 -I on exported main
            exp_main = None
            for sr in found:
                cand = os.path.join(sr, "source", "hermes_cli", "main.py")
                if os.path.exists(cand):
                    exp_main = cand
                    break
            self.assertIsNotNone(exp_main)
            r = subprocess.run(["/usr/bin/python3", "-I", exp_main], capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(FIXTURE_NONCE, r.stdout)
            self.assertIn(exp_main, r.stdout)
            # no .git in stdout path? __file__ under export
            self.assertTrue(exp_main.startswith(sandbox + "/"))
            # digest file content signed false
            with open(df) as f:
                payload = json.load(f)
            self.assertFalse(payload["signed"])
            # no sitecustomize
            for sr in found:
                for dp, dn, fn in os.walk(sr):
                    self.assertNotIn("sitecustomize.py", fn)
            # live not created
            self.assertFalse(os.path.exists("/var/lib/hermes-stock-activation/backing/staging"))
            self.assertFalse(os.path.exists("/run/hermes-stock-activation/known-good-snap/venv"))
            # check pyvenv rewritten to mount, not staging
            for sr in found:
                for dp, dn, fn in os.walk(sr):
                    if "pyvenv.cfg" in fn:
                        with open(os.path.join(dp, "pyvenv.cfg")) as f:
                            txt = f.read()
                        self.assertIn(cb.KNOWN_GOOD_MOUNT + "/interpreter/bin", txt)
                        self.assertNotIn(sr, txt)
            # check finder rewritten to mount/source
            for sr in found:
                cfg = os.path.join(sr, "source", "app.conf")
                if os.path.exists(cfg):
                    with open(cfg) as f:
                        txt = f.read()
                    self.assertIn(cb.KNOWN_GOOD_MOUNT + "/source", txt)
                    self.assertNotIn(FINDER_ORIG, txt)
            # walker actually executed
            walker_calls = [c for c, e in runner.calls if c[0] == "/usr/bin/python3.12"]
            self.assertTrue(len(walker_calls) >= 1)
            # also directly execute walker on temp tree
            for sr in found:
                argv = cb.fsync_walker_argv(sr)
                self.assertEqual(argv[0], "/usr/bin/python3.12")
                self.assertEqual(argv[1], "-I")
                self.assertEqual(argv[2], "-c")
                self.assertIn("followlinks", argv[3])
                self.assertIn("O_NOFOLLOW", argv[3])
                self.assertIn("O_RDONLY", argv[3])
                self.assertIn("O_DIRECTORY", argv[3])
                self.assertIn("fsync", argv[3])
                r2 = subprocess.run(argv, capture_output=True, text=True, check=False)
                self.assertEqual(r2.returncode, 0, r2.stderr)

    def test_unequal_hash_refuse_before_extract(self):
        class UnequalRunner:
            def __init__(self):
                self.calls = []
                self.n = 0

            def run(self, argv, env=None):
                self.calls.append(list(argv))
                if argv[0] == "/usr/bin/git":
                    out = None
                    for a in argv:
                        if a.startswith("--output="):
                            out = a[len("--output="):]
                    assert out is not None
                    self.n += 1
                    with open(out, "wb") as f:
                        f.write(f"content-{self.n}".encode())
                    return subprocess.CompletedProcess(argv, 0, b"", b"")
                if argv[0] == "/usr/bin/tar":
                    raise AssertionError("tar should not be called on hash mismatch")
                return subprocess.CompletedProcess(argv, 0, b"", b"")

        with tempfile.TemporaryDirectory() as td:
            sandbox = os.path.join(td, "sandbox")
            os.makedirs(sandbox)
            host = cb.SandboxHost(sandbox)
            repo, sha, venv_src, interp_src, deps_src = build_fixture(os.path.join(td, "fix"), with_deps=True)
            runner = UnequalRunner()
            with self.assertRaises(Exception):
                cb.export_sandbox_closure(host, runner, sandbox, kind="known-good", source_repo=repo, source_sha=sha, venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src, finder_prefix=FINDER_ORIG)
            for c in runner.calls:
                self.assertNotEqual(c[0], "/usr/bin/tar")

    def test_tracked_env_refuses(self):
        with tempfile.TemporaryDirectory() as td:
            sandbox = os.path.join(td, "sandbox")
            os.makedirs(sandbox)
            host = cb.SandboxHost(sandbox)
            repo, sha, venv_src, interp_src, deps_src = build_fixture(os.path.join(td, "fix"), extra_files={".env": "SECRET=1\n"}, with_deps=True)
            runner = RealRunner()
            with self.assertRaises(Exception):
                cb.export_sandbox_closure(host, runner, sandbox, kind="known-good", source_repo=repo, source_sha=sha, venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src, finder_prefix=FINDER_ORIG)

    def test_env_example_allows(self):
        with tempfile.TemporaryDirectory() as td:
            sandbox = os.path.join(td, "sandbox")
            os.makedirs(sandbox)
            host = cb.SandboxHost(sandbox)
            repo, sha, venv_src, interp_src, deps_src = build_fixture(os.path.join(td, "fix"), extra_files={".env.example": "EXAMPLE=1\n"}, with_deps=True)
            runner = RealRunner()
            res = cb.export_sandbox_closure(host, runner, sandbox, kind="known-good", source_repo=repo, source_sha=sha, venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src, finder_prefix=FINDER_ORIG)
            self.assertEqual(res["status"], "sandbox-exported")

    def test_bad_abs_symlink_refuses(self):
        with tempfile.TemporaryDirectory() as td:
            sandbox = os.path.join(td, "sandbox")
            os.makedirs(sandbox)
            host = cb.SandboxHost(sandbox)
            repo, sha, venv_src, interp_src, deps_src = build_fixture(os.path.join(td, "fix"), symlinks={"evil-link": "/etc/passwd"}, with_deps=True)
            runner = RealRunner()
            with self.assertRaises(Exception):
                cb.export_sandbox_closure(host, runner, sandbox, kind="known-good", source_repo=repo, source_sha=sha, venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src, finder_prefix=FINDER_ORIG)

    def test_remaining_absolute_refuses(self):
        with tempfile.TemporaryDirectory() as td:
            sandbox = os.path.join(td, "sandbox")
            os.makedirs(sandbox)
            host = cb.SandboxHost(sandbox)
            repo, sha, venv_src, interp_src, deps_src = build_fixture(os.path.join(td, "fix"), extra_files={"evil.conf": f"path=/opt/secret-abs-459595\nfinder={FINDER_ORIG}\n"}, with_deps=True)
            runner = RealRunner()
            with self.assertRaises(Exception):
                cb.export_sandbox_closure(host, runner, sandbox, kind="known-good", source_repo=repo, source_sha=sha, venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src, finder_prefix=FINDER_ORIG)

    def test_fsync_oserror(self):
        with tempfile.TemporaryDirectory() as td:
            sandbox = os.path.join(td, "sandbox")
            os.makedirs(sandbox)
            host = cb.SandboxHost(sandbox)
            repo, sha, venv_src, interp_src, deps_src = build_fixture(os.path.join(td, "fix"), with_deps=True)
            runner = RealRunner()
            with mock.patch("os.fsync", side_effect=OSError("injected")):
                res = cb.export_sandbox_closure(host, runner, sandbox, kind="known-good", source_repo=repo, source_sha=sha, venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src, finder_prefix=FINDER_ORIG)
            self.assertEqual(res["status"], "durable-state-unknown")
            self.assertFalse(res.get("rollback_clean", True))

    def test_no_sitecustomize(self):
        with tempfile.TemporaryDirectory() as td:
            sandbox = os.path.join(td, "sandbox")
            os.makedirs(sandbox)
            host = cb.SandboxHost(sandbox)
            repo, sha, venv_src, interp_src, deps_src = build_fixture(os.path.join(td, "fix"), with_deps=True)
            runner = RealRunner()
            res = cb.export_sandbox_closure(host, runner, sandbox, kind="known-good", source_repo=repo, source_sha=sha, venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src, finder_prefix=FINDER_ORIG)
            self.assertEqual(res["status"], "sandbox-exported")
            for dp, dn, fn in os.walk(sandbox):
                self.assertNotIn("sitecustomize.py", fn)


class TestExisting(unittest.TestCase):
    def test_export_closure_stub(self):
        import sys as _sys
        from scripts.stock_activation.os_adapter import export_closure, provisioning_recipe
        try:
            r = export_closure()
            self.assertEqual(r["status"], "CLOSURE_ENUMERATION_UNSPECIFIED")
            pr = provisioning_recipe()
            self.assertFalse(pr["executed"])
        finally:
            _sys.modules.pop("scripts.stock_activation.os_adapter", None)

    def test_cli_apply(self):
        from scripts.stock_activation.cli import main
        self.assertEqual(main(["apply"]), 2)

    def test_ledger(self):
        from scripts.stock_activation.ledger import LEDGER
        for row in LEDGER:
            self.assertEqual(row["stage_only"], "UNEXECUTED")
            self.assertFalse(row["id"].startswith("C"))
        ids = {r["id"] for r in LEDGER}
        for c in ("C1", "C2", "C3", "C4"):
            self.assertNotIn(c, ids)


class TestReadonly(unittest.TestCase):
    def test_git_archive_known_good(self):
        repo = "/home/ubuntu/.hermes/hermes-agent"
        sha = "1d9a377fa00ce0e663e274e16b63c75e36233b9e"
        before = run_cmd(["/usr/bin/git", "status", "--porcelain"], cwd=repo)
        with tempfile.TemporaryDirectory() as td:
            a1 = os.path.join(td, "a1.tar")
            a2 = os.path.join(td, "a2.tar")
            for out in (a1, a2):
                r = subprocess.run(["/usr/bin/git", "-C", repo, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "archive", "--format=tar", "--output=" + out, sha], capture_output=True, check=False)
                self.assertEqual(r.returncode, 0, r.stderr)
            def sha256(p):
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    while True:
                        b = f.read(65536)
                        if not b:
                            break
                        h.update(b)
                return h.hexdigest()
            self.assertEqual(sha256(a1), sha256(a2))
            src = os.path.join(td, "source")
            os.makedirs(src)
            r = subprocess.run(["/usr/bin/tar", "-C", src, "--no-same-owner", "--no-same-permissions", "-xf", a1], capture_output=True, check=False)
            self.assertEqual(r.returncode, 0)
            for dp, dn, fn in os.walk(src):
                self.assertNotIn(".git", dn)
            target = os.path.join(src, "hermes_cli", "main.py")
            self.assertTrue(os.path.exists(target))
            with open(target, "rb") as f:
                got = f.read()
            r = run_cmd(["/usr/bin/git", "-C", repo, "show", sha + ":hermes_cli/main.py"])
            self.assertEqual(got, r.stdout.encode() if isinstance(r.stdout, str) else r.stdout)
        after = run_cmd(["/usr/bin/git", "status", "--porcelain"], cwd=repo)
        self.assertEqual(before.stdout, after.stdout)


def _snapshot_live_path(path):
    """Read-only snapshot of a live path without opening private content.

    Only lstat(target) + listdir(parent) are used; never open/read files
    inside the mount. Permission-denied is recorded explicitly as
    unknown-permission, not as absent, so pre-existing provisioned state
    from prior reviewed proof is preserved and proven unchanged.
    """
    import errno as _errno

    norm = os.path.normpath(path)
    snap = {"path": norm}
    try:
        st = os.lstat(norm)
        snap["lstat"] = {
            "mode": stat.S_IMODE(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "size": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "ino": st.st_ino,
            "dev": st.st_dev,
            "nlink": st.st_nlink,
            "islink": bool(stat.S_ISLNK(st.st_mode)),
            "isdir": bool(stat.S_ISDIR(st.st_mode)),
        }
        snap["lexists"] = True
        snap["lstat_error"] = None
    except OSError as e:
        snap["lstat"] = None
        snap["lstat_error"] = e.errno
        if e.errno in (_errno.EACCES, _errno.EPERM):
            snap["lexists"] = "unknown-permission"
        elif e.errno == _errno.ENOENT:
            snap["lexists"] = False
        else:
            snap["lexists"] = f"unknown-errno-{e.errno}"
    try:
        parent = os.path.dirname(norm)
        snap["parent_entries"] = sorted(os.listdir(parent))
        snap["parent_error"] = None
    except OSError as e:
        snap["parent_entries"] = None
        snap["parent_error"] = e.errno
    return snap


class TestSquashfs(unittest.TestCase):
    def test_mksquashfs_unsquashfs(self):
        # Live may pre-exist from prior reviewed proof (loop20/21).
        # Never delete live to make fixture green; snapshot and prove
        # unchanged. Fresh (absence) is covered by isolated temp img
        # below, not by asserting absence of real authority paths.
        live_paths = (
            "/var/lib/hermes-stock-activation/backing/staging",
            "/run/hermes-stock-activation/known-good-snap",
        )
        before = {p: _snapshot_live_path(p) for p in live_paths}
        with tempfile.TemporaryDirectory() as td:
            staged = os.path.join(td, "staged")
            os.makedirs(os.path.join(staged, "source", "hermes_cli"))
            with open(os.path.join(staged, "source", "hermes_cli", "main.py"), "w") as f:
                f.write("print(1)\n")
            with open(os.path.join(staged, "hello.txt"), "w") as f:
                f.write("hi\n")
            img = os.path.join(td, "img.squashfs")
            self.assertFalse(os.path.exists(img))
            argv = cb.mksquashfs_argv(staged, img)
            r = subprocess.run(argv, capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 0, "mksquashfs failed: " + r.stderr)
            self.assertTrue(os.path.exists(img))
            dest = os.path.join(td, "verify")
            uargv = cb.unsquashfs_argv(img, dest)
            self.assertEqual(uargv[:3], ["/usr/bin/unsquashfs", "-no-xattrs", "-d"])
            r2 = subprocess.run(uargv, capture_output=True, text=True, check=False)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            def manifest(root):
                out = []
                for dp, dn, fn in os.walk(root):
                    for n in dn + fn:
                        full = os.path.join(dp, n)
                        rel = os.path.relpath(full, root)
                        st = os.lstat(full)
                        if stat.S_ISLNK(st.st_mode):
                            out.append((rel, "link", os.readlink(full)))
                        elif stat.S_ISREG(st.st_mode):
                            with open(full, "rb") as _f:
                                h = hashlib.sha256(_f.read()).hexdigest()
                            out.append((rel, "file", h))
                        else:
                            out.append((rel, "dir", ""))
                return sorted(out)
            self.assertEqual(manifest(staged), manifest(dest))
            # No host mutation: isolated mksquashfs/unsquashfs must leave
            # pre-existing live state byte-identical (metadata/state).
            # Do not open root-private content; parent metadata readback
            # above is sufficient, unknown-permission stays explicit.
            after = {p: _snapshot_live_path(p) for p in live_paths}
            for p in live_paths:
                self.assertEqual(before[p], after[p], msg=f"live mutated: {p}")


if __name__ == "__main__":
    unittest.main()
