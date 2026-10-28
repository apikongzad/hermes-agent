import contextlib
import inspect
import io
import os
import stat
import sys
import tempfile
import unittest


def _load_os_adapter():
    from scripts.stock_activation import os_adapter as m

    return m


class OsAdapterTests(unittest.TestCase):
    def test_00_cli_does_not_require_os_adapter(self):
        # Confirm os_adapter not required by cli before importing it.
        self.assertNotIn("scripts.stock_activation.os_adapter", sys.modules)
        from scripts.stock_activation import cli

        src = inspect.getsource(cli)
        self.assertNotIn("os_adapter", src)
        self.assertEqual(cli.main([]), 2)
        self.assertEqual(cli.main(["--apply"]), 2)
        self.assertNotIn("scripts.stock_activation.os_adapter", sys.modules)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["--self-check"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06", out)
        self.assertIn("1d9a377fa00ce0e663e274e16b63c75e36233b9e", out)

    def test_01_real_write_fsync_rename_dir_fsync(self):
        m = _load_os_adapter()
        with tempfile.TemporaryDirectory() as root:
            ad = m.FilesystemAdapter(root)
            tmp = os.path.join(root, "tmp1")
            final = os.path.join(root, "final1")
            data = b"hello-fixture-bytes"
            ad.write_temp(tmp, data)
            # mode 0o600, not symlink
            st = os.lstat(tmp)
            self.assertFalse(stat.S_ISLNK(st.st_mode))
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
            ad.file_fsync(tmp)
            ad.rename_path(tmp, final)
            ad.dir_fsync(root)
            # independent read-back via os.open
            fd = os.open(final, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                got = b""
                while True:
                    chunk = os.read(fd, 8192)
                    if not chunk:
                        break
                    got += chunk
            finally:
                os.close(fd)
            self.assertEqual(got, data)
            st2 = os.lstat(final)
            self.assertFalse(stat.S_ISLNK(st2.st_mode))
            # tmp no longer exists
            self.assertFalse(os.path.lexists(tmp))
            # existing file must fail, not truncate
            with self.assertRaises(OSError):
                ad.write_temp(final, b"new")

    def test_02_publish_file_fsync_oserror(self):
        m = _load_os_adapter()

        def boom(fd):
            raise OSError("injected file fsync fail")

        with tempfile.TemporaryDirectory() as root:
            ad = m.FilesystemAdapter(root, fsync_file=boom)
            tmp = os.path.join(root, "t")
            final = os.path.join(root, "f")
            res = ad.publish_sequence(b"abc", tmp, final)
            self.assertEqual(res.state, "durable-state-unknown")
            self.assertFalse(res.success)
            self.assertFalse(res.final_exists)
            self.assertFalse(os.path.lexists(final))

    def test_03_publish_dir_fsync_oserror_after_rename(self):
        m = _load_os_adapter()

        def boom_dir(fd):
            raise OSError("injected dir fsync fail")

        with tempfile.TemporaryDirectory() as root:
            ad = m.FilesystemAdapter(root, fsync_dir=boom_dir)
            tmp = os.path.join(root, "t2")
            final = os.path.join(root, "f2")
            res = ad.publish_sequence(b"xyz-data", tmp, final)
            self.assertEqual(res.state, "durable-state-unknown")
            self.assertFalse(res.success)
            self.assertFalse(res.rollback_clean)
            self.assertTrue(res.final_exists)
            self.assertTrue(os.path.lexists(final))
            # final content intact
            fd = os.open(final, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                got = b""
                while True:
                    c = os.read(fd, 8192)
                    if not c:
                        break
                    got += c
            finally:
                os.close(fd)
            self.assertEqual(got, b"xyz-data")

    def test_04_symlink_final_not_followed(self):
        m = _load_os_adapter()
        with tempfile.TemporaryDirectory() as root:
            ad = m.FilesystemAdapter(root)
            real = os.path.join(root, "real")
            ad.write_temp(real, b"real-bytes")
            link = os.path.join(root, "link")
            os.symlink(real, link)
            with self.assertRaises(m.OsAdapterRefused):
                ad.write_temp(link, b"evil")
            with self.assertRaises(m.OsAdapterRefused):
                ad.file_fsync(link)
            # target untouched
            self.assertEqual(ad.read_bytes(real), b"real-bytes")
            # symlink parent also refused
            subdir_link = os.path.join(root, "dirlink")
            os.mkdir(os.path.join(root, "d"))
            os.symlink(os.path.join(root, "d"), subdir_link)
            with self.assertRaises(m.OsAdapterRefused):
                ad.write_temp(os.path.join(subdir_link, "x"), b"y")

    def test_05_outside_paths_refused_before_syscall(self):
        m = _load_os_adapter()
        with tempfile.TemporaryDirectory() as root:
            calls = []

            def bad_opener(*a, **kw):
                calls.append(1)
                raise AssertionError("opener must not be called")

            ad = m.FilesystemAdapter(root, opener=bad_opener)
            outsiders = [
                "/home/ubuntu/.hermes/.env",
                "/var/lib/hermes-stock-activation",
                "/var/lib/hermes-stock-activation/journal",
                "/var/lib/hermes-cutover",
                "/etc/systemd/system.conf",
                "/opt/thing",
                "/home/ubuntu/worktrees/worktrees/hermes-upstream-integrate-20261025/x",
                "/home/ubuntu/.hermes/runtime/y",
                "/etc/passwd",
                "/tmp/definitely-outside-stock-test",
            ]
            for p in outsiders:
                with self.assertRaises(m.OsAdapterRefused, msg=p):
                    ad.write_temp(p, b"x")
                with self.assertRaises(m.OsAdapterRefused, msg=p):
                    ad.file_fsync(p)
                with self.assertRaises(m.OsAdapterRefused, msg=p):
                    ad.read_bytes(p)
                with self.assertRaises(m.OsAdapterRefused, msg=p):
                    ad.dir_fsync(p)
                with self.assertRaises(m.OsAdapterRefused, msg=p):
                    ad.file_info(p)
            # traversal attempts
            for p in [
                os.path.join(root, "..", "escape"),
                os.path.join(root, ".", "x"),
                root + "/a/../b",
            ]:
                with self.assertRaises(m.OsAdapterRefused, msg=p):
                    ad.write_temp(p, b"x")
            self.assertEqual(calls, [])

    def test_06_default_boundary_blocks_before_transport(self):
        m = _load_os_adapter()

        class Recorder:
            def __init__(self):
                self.calls = []

            def run(self, argv, env):
                self.calls.append((list(argv), dict(env)))
                raise AssertionError("must not reach transport")

        rec = Recorder()
        b = m.SubprocessBoundary(transport=rec, fixture_root="/tmp")
        for name in ("systemctl", "mount", "umount", "sudo", "git", "hermes"):
            with self.assertRaises(m.OsAdapterRefused, msg=name):
                b.run(["/usr/bin/" + name, "arg"], {"PATH": "/usr/bin:/bin"})
            with self.assertRaises(m.OsAdapterRefused, msg=name):
                b.run([name], {"PATH": "/usr/bin:/bin"})
        self.assertEqual(rec.calls, [])
        # default transport refuses without spawn
        d = m.SubprocessBoundary()
        with self.assertRaises(m.OsAdapterRefused):
            d.run(["/bin/echo", "hi"])
        with self.assertRaises(m.OsAdapterRefused):
            d.run(["systemctl", "status"])
        # bad argv shapes refused
        with self.assertRaises(m.OsAdapterRefused):
            d.run("not-a-list")
        with self.assertRaises(m.OsAdapterRefused):
            d.run([])
        with self.assertRaises(m.OsAdapterRefused):
            d.run([123])

    def test_07_real_fixture_transport_runs_nonce(self):
        m = _load_os_adapter()
        with tempfile.TemporaryDirectory() as root:
            script = os.path.join(root, "nonce-script")
            with open(script, "w") as f:
                f.write("#!/bin/sh\necho nonce-987654321\n")
            os.chmod(script, 0o755)
            t = m.RealFixtureTransport(root)
            cp = t.run([script], {"PATH": "/usr/bin:/bin"})
            self.assertIn("nonce-987654321", cp.stdout.decode())
            # blocked basenames are not spawned even if file exists
            for blocked in ("git", "systemctl", "mount", "sudo", "hermes", "umount"):
                p = os.path.join(root, blocked)
                with open(p, "w") as f:
                    f.write("#!/bin/sh\necho SHOULD-NOT-RUN\n")
                os.chmod(p, 0o755)
                with self.assertRaises(m.OsAdapterRefused, msg=blocked):
                    t.run([p], {"PATH": "/usr/bin:/bin"})
            # wrong env refused
            with self.assertRaises(m.OsAdapterRefused):
                t.run([script], {"PATH": "/usr/bin:/bin:/extra"})
            # outside absolute refused
            with self.assertRaises(m.OsAdapterRefused):
                t.run(["/bin/echo", "hi"], {"PATH": "/usr/bin:/bin"})
            # relative refused
            with self.assertRaises(m.OsAdapterRefused):
                t.run(["nonce-script"], {"PATH": "/usr/bin:/bin"})

    def test_08_export_closure_copies_zero_and_ignores_path(self):
        m = _load_os_adapter()
        with tempfile.TemporaryDirectory() as root:
            marker = os.path.join(root, "keep")
            with open(marker, "wb") as f:
                f.write(b"data")
            before = sorted(os.listdir(root))
            res = m.export_closure(root)
            self.assertEqual(
                res,
                {
                    "status": "CLOSURE_ENUMERATION_UNSPECIFIED",
                    "copied": 0,
                    "git_invoked": False,
                },
            )
            self.assertEqual(sorted(os.listdir(root)), before)
            # ignores any path argument, still pure
            res2 = m.export_closure("/nonexistent/path/that/must/be/ignored")
            self.assertEqual(res2, res)
            self.assertEqual(sorted(os.listdir(root)), before)
            res3 = m.export_closure()
            self.assertEqual(res3, res)
            # pure return: no subprocess, no spawn, no filesystem calls
            src = inspect.getsource(m.export_closure)
            self.assertIn("return", src)
            self.assertNotIn("subprocess", src)
            self.assertNotIn("Popen", src)
            self.assertNotIn("os.", src)
            self.assertNotIn("open(", src)

    def test_09_provisioning_recipe_inert(self):
        m = _load_os_adapter()
        with tempfile.TemporaryDirectory() as root:
            before_list = sorted(os.listdir(root))
            before_stat = os.stat(root)
            before_mtime = (before_stat.st_mtime_ns, before_stat.st_ctime_ns)

            class Counting:
                def __init__(self):
                    self.n = 0

                def run(self, argv, env):
                    self.n += 1
                    raise AssertionError("must not be called")

            c = Counting()
            res = m.provisioning_recipe()
            self.assertEqual(
                res,
                {
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
                },
            )
            self.assertEqual(c.n, 0)
            self.assertEqual(sorted(os.listdir(root)), before_list)
            after_stat = os.stat(root)
            self.assertEqual(
                (after_stat.st_mtime_ns, after_stat.st_ctime_ns), before_mtime
            )

    def test_10_file_info_0555_not_kernel_enforced(self):
        m = _load_os_adapter()
        with tempfile.TemporaryDirectory() as root:
            ad = m.FilesystemAdapter(root)
            p = os.path.join(root, "f0555")
            ad.write_temp(p, b"mode-test")
            os.chmod(p, 0o555)
            info = ad.file_info(p)
            self.assertTrue(info["exists"])
            self.assertFalse(info["is_symlink"])
            self.assertFalse(info["kernel_enforced"])
            self.assertIn("kernel_enforced", info)
            # missing returns exists false
            missing = ad.file_info(os.path.join(root, "does-not-exist"))
            self.assertEqual(
                missing,
                {"exists": False, "is_symlink": False, "kernel_enforced": False},
            )


if __name__ == "__main__":
    unittest.main()
