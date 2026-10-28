"""Host argv and supervision tests. No live spawn. Stdlib unittest only."""
import unittest

from scripts.stock_cutover import cutover_host as H
from scripts.stock_cutover import cutover_recovery as R


class TestFixedArgv(unittest.TestCase):
    def test_g3_prefix_exact(self):
        self.assertEqual(H.G3_PREFIX, [
            "/usr/bin/sudo", "-n", "/usr/bin/env", "-i",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=C", "LC_ALL=C",
            "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0",
        ])

    def test_no_restart_anywhere(self):
        seq = H.systemctl_sequence()
        self.assertEqual(len(seq), 7)
        for argv in seq:
            self.assertEqual(argv[:9], H.G3_PREFIX)
            for el in argv:
                self.assertNotEqual(el, "restart")
            joined = " ".join(argv).lower().replace("nrestarts", "")
            self.assertNotIn("restart", joined)
            self.assertNotIn("PYTHONPATH", " ".join(argv))
        self.assertEqual(seq[0][9:], ["/usr/bin/systemctl", "stop",
                                     "hermes-gateway.service",
                                     "hermes-dashboard.service"])
        self.assertEqual(seq[4], H.G3_PREFIX + ["/usr/bin/systemctl", "daemon-reload"])
        self.assertEqual(seq[6][9:], ["/usr/bin/systemctl", "start",
                                      "hermes-gateway.service",
                                      "hermes-dashboard.service"])
        self.assertTrue(seq[2][9].endswith("sleep"))

    def test_mount_constants(self):
        self.assertEqual(H.KNOWN_GOOD_MOUNT, "/run/hermes-stock-activation/known-good-snap")
        self.assertEqual(H.CANDIDATE_MOUNT, "/run/hermes-stock-activation/candidate-snap")
        self.assertEqual(H.JOURNAL_PATH, "/var/lib/hermes-stock-activation/journal")
        self.assertEqual(H.BACKING_DIR, "/var/lib/hermes-stock-activation/backing")

    def test_no_env_read_in_code(self):
        import pathlib
        src = pathlib.Path("scripts/stock_cutover/cutover_host.py").read_bytes().decode()
        # Refusal constant exists but no open of .env path.
        for line in src.splitlines():
            if "open(" in line and ".env" in line:
                self.fail("live .env open: " + line)
        self.assertIn(".hermes/.env", src)


class FakeRunner:
    """Injected command runner. No live spawn. Records argv.

    Fixed-argv only: G3 systemctl/sleep/show, bare findmnt, sudo -u #1001
    denial probe. Enforces allowlist via H._is_allowed_fixed_argv, no
    restart, no arbitrary commands. Returns happy rc0 by default;
    configurable rc/text/errno for negative tests.
    """

    def __init__(self, show_text=None, findmnt_text="", denial_errno=30,
                 rc_map=None):
        self.calls = []
        self.show_text = show_text
        self.findmnt_text = findmnt_text
        self.denial_errno = denial_errno
        self.rc_map = dict(rc_map or {})

    def __call__(self, argv, timeout=60):
        self.calls.append(list(argv))
        import subprocess as _sp
        if not H._is_allowed_fixed_argv(argv):
            raise AssertionError(f"not allowlisted: {argv!r}")
        for el in argv:
            assert el != "restart", "restart forbidden"
        assert "PYTHONPATH" not in " ".join(argv)
        # Denial probe (sudo -u #1001 ...).
        if argv[0] == "/usr/bin/sudo" and "-u" in argv:
            return _sp.CompletedProcess(argv, 0, f"{self.denial_errno}\n", "")
        # Bare findmnt.
        if argv[0] == "/usr/bin/findmnt":
            return _sp.CompletedProcess(argv, 0, self.findmnt_text, "")
        # G3 systemctl/sleep/show.
        if argv[:9] == H.G3_PREFIX:
            tail = argv[9:]
            key = " ".join(tail)
            if key in self.rc_map:
                rc = self.rc_map[key]
                return _sp.CompletedProcess(argv, rc, "", "")
            if "show" in argv:
                unit = argv[-1]
                if self.show_text is not None:
                    text = self.show_text
                else:
                    text = (
                        f"Id={unit}\nActiveState=inactive\nSubState=dead\n"
                        "MainPID=0\nNRestarts=0\nExecStart=test\n"
                    )
                return _sp.CompletedProcess(argv, 0, text, "")
            # stop/start/reload/sleep fixed success.
            return _sp.CompletedProcess(argv, 0, "", "")
        raise AssertionError(f"unexpected argv: {argv!r}")


class TestReadAdapter(unittest.TestCase):
    def test_show_via_injected_runner_no_live(self):
        runner = FakeRunner()
        h = H.RealCutoverHost(runner=runner)
        u = h.show_unit("hermes-gateway.service")
        self.assertEqual(u["Id"], "hermes-gateway.service")
        self.assertEqual(u["ActiveState"], "inactive")
        self.assertEqual(u["MainPID"], 0)
        self.assertEqual(len(runner.calls), 1)
        argv = runner.calls[0]
        self.assertEqual(argv[:9], H.G3_PREFIX)
        self.assertIn("show", argv)
        self.assertNotIn("restart", " ".join(argv).lower().replace("nrestarts", ""))
        for el in argv:
            self.assertNotEqual(el, "restart")

    def test_show_full_parses_execstart(self):
        text = ("Id=hermes-gateway.service\nActiveState=active\nSubState=running\n"
                "MainPID=590001\nNRestarts=0\nExecStart=/run/x/venv/bin/python3 -I /run/x/source/hermes_cli/main.py gateway run\n")
        runner = FakeRunner(show_text=text)
        h = H.RealCutoverHost(runner=runner)
        u = h.show_unit("hermes-gateway.service", full=True)
        self.assertEqual(u["MainPID"], 590001)
        self.assertIn("python3 -I", u["ExecStart"])

    def test_python_self_probe_real_isolated(self):
        import subprocess
        # Real probe under -I must show isolated=1; without -I it is 0.
        # This runs real interpreters, no live host mutation.
        code = ("import sys;"
                "sys.path.insert(0,'.');"
                "from scripts.stock_cutover.cutover_host import RealCutoverHost;"
                "import json as j;"
                "print(j.dumps(RealCutoverHost().python_self_probe()))")
        cp_i = subprocess.run(["/usr/bin/python3", "-I", "-c", code],
                              capture_output=True, text=True, check=False,
                              cwd=".",
                              env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertEqual(cp_i.returncode, 0, cp_i.stderr)
        import json as _j
        got = _j.loads(cp_i.stdout.strip().splitlines()[-1])
        self.assertEqual(got["isolated"], 1)
        self.assertEqual(got["ignore_environment"], 1)
        self.assertIn("sitecustomize_origin", got)
        self.assertIn("sys_path_has_cwd", got)

    def test_python_probe_real_snapshot_exe(self):
        h = H.RealCutoverHost(runner=FakeRunner())
        got = h.python_probe("/usr/bin/python3.12")
        self.assertEqual(got["isolated"], 1)
        self.assertEqual(got["ignore_environment"], 1)
        self.assertFalse(got["sys_path_has_cwd"])
        # Real fields (not hardcoded True): system python has no adjacent
        # hermes_cli/pyvenv.cfg, so False/None proves real discovery.
        self.assertIn("import_ok", got)
        self.assertIn("pyvenv_version", got)
        self.assertEqual(got["import_ok"], False)
        self.assertTrue(got["pyvenv_version"] is None
                        or isinstance(got["pyvenv_version"], str))
        self.assertIn("safe_path", got)
        self.assertIn("sitecustomize_origin", got)
        self.assertIn("exe", got)

    def test_python_probe_real_snapshot_valid(self):
        import os as _os
        import shutil as _sh
        import tempfile as _tf
        h = H.RealCutoverHost(runner=FakeRunner())
        d = _tf.mkdtemp(prefix="snap-valid-", dir="/tmp")
        try:
            snap = _os.path.join(d, "snap")
            venvbin = _os.path.join(snap, "venv", "bin")
            srccli = _os.path.join(snap, "source", "hermes_cli")
            _os.makedirs(venvbin)
            _os.makedirs(srccli)
            _os.symlink("/usr/bin/python3.12",
                        _os.path.join(venvbin, "python3"))
            with open(_os.path.join(srccli, "__init__.py"), "w") as f:
                f.write("# pkg\n")
            with open(_os.path.join(srccli, "main.py"), "w") as f:
                f.write("x=1\n")
            with open(_os.path.join(snap, "venv", "pyvenv.cfg"), "w") as f:
                f.write("home = /usr\nversion = 3.14.9\n")
            got = h.python_probe(_os.path.join(venvbin, "python3"))
            self.assertEqual(got["isolated"], 1)
            self.assertEqual(got["import_ok"], True)
            self.assertEqual(got["pyvenv_version"], "3.14.9")
            self.assertFalse(got["sys_path_has_cwd"])
        finally:
            _sh.rmtree(d, ignore_errors=True)

    def test_show_full_requests_user_wd_env(self):
        full = H.show_full_argv()
        joined = " ".join(full)
        for prop in ("User", "WorkingDirectory", "Environment",
                     "EnvironmentFiles", "ExecStart"):
            self.assertIn(prop, joined)
        # No restart element.
        for el in full:
            self.assertNotEqual(el, "restart")
        # Per-unit full argv also carries the three REQUIRED properties.
        for unit in H.BOTH:
            argv = H._show_argv_for(unit, full=True)
            js = " ".join(argv)
            self.assertIn("-p", js)
            self.assertIn("User", js)
            self.assertIn("WorkingDirectory", js)
            self.assertIn("Environment", js)

    def test_stop_start_reload_sleep_fixed_argv(self):
        runner = FakeRunner()
        h = H.RealCutoverHost(runner=runner)
        h.stop_units(H.BOTH)
        h.start_units(H.BOTH)
        h.reload_manager()
        h.sleep_secs(5)
        self.assertEqual(runner.calls[0], H.stop_argv())
        self.assertEqual(runner.calls[1], H.start_argv())
        self.assertEqual(runner.calls[2], H.daemon_reload_argv())
        self.assertEqual(runner.calls[3], H.sleep_argv())
        for argv in runner.calls:
            self.assertTrue(H._is_allowed_fixed_argv(argv))
            self.assertNotIn("restart", " ".join(argv).lower().replace("nrestarts", ""))
            for el in argv:
                self.assertNotEqual(el, "restart")
        # Arbitrary units rejected, no execution.
        n = len(runner.calls)
        with self.assertRaises(ValueError):
            h.stop_units(["hermes-gateway.service"])
        with self.assertRaises(ValueError):
            h.start_units(["evil.service", "hermes-dashboard.service"])
        with self.assertRaises(ValueError):
            h.sleep_secs(4)
        self.assertEqual(len(runner.calls), n)
        # Zero extra: exactly 4 invocations for the happy shape.
        self.assertEqual(len(runner.calls), 4)

    def test_sleep_oserror_not_runtimeerror(self):
        runner = FakeRunner(rc_map={" ".join(H.sleep_argv()[9:]): 1})
        h = H.RealCutoverHost(runner=runner)
        with self.assertRaises(OSError):
            h.sleep_secs(5)
        # Must be OSError, not RuntimeError branch.
        try:
            h.sleep_secs(5)
        except OSError:
            pass
        except RuntimeError:
            self.fail("sleep must be OSError, not RuntimeError")
        except Exception as e:
            self.fail(f"sleep wrong type: {type(e).__name__}")

    def test_stop_start_oserror_on_rc(self):
        runner = FakeRunner(rc_map={" ".join(H.stop_argv()[9:]): 1})
        h = H.RealCutoverHost(runner=runner)
        with self.assertRaises(OSError):
            h.stop_units(H.BOTH)
        runner2 = FakeRunner(rc_map={" ".join(H.start_argv()[9:]): 1})
        h2 = H.RealCutoverHost(runner=runner2)
        with self.assertRaises(OSError):
            h2.start_units(H.BOTH)
        runner3 = FakeRunner(rc_map={" ".join(H.daemon_reload_argv()[9:]): 1})
        h3 = H.RealCutoverHost(runner=runner3)
        with self.assertRaises(OSError):
            h3.reload_manager()

    def test_denial_probe_strict_erofs(self):
        runner = FakeRunner(denial_errno=30)
        h = H.RealCutoverHost(runner=runner)
        d = h.denial_probe(H.KNOWN_GOOD_MOUNT)
        for k in ("kernel_enforced", "write_denied", "rename_denied",
                  "hardlink_denied", "second_write_denied",
                  "second_rename_denied", "second_hardlink_denied"):
            self.assertTrue(d[k] is True, k)
        # Three ops, one errno each, fixed sudo -u #1001 -I snippet.
        self.assertEqual(len(runner.calls), 3)
        for argv in runner.calls:
            self.assertTrue(H._is_allowed_fixed_argv(argv))
            self.assertEqual(argv[0], "/usr/bin/sudo")
            self.assertIn("-I", argv)
            self.assertIn(H.KNOWN_GOOD_MOUNT, argv)
        # Non-EROFS fails closed (False, no commit), not True.
        runner2 = FakeRunner(denial_errno=0)
        h2 = H.RealCutoverHost(runner=runner2)
        d2 = h2.denial_probe(H.CANDIDATE_MOUNT)
        self.assertFalse(d2["kernel_enforced"])
        self.assertFalse(d2["write_denied"])
        # Bad mount rejected, no execution.
        with self.assertRaises(ValueError):
            h.denial_probe("/tmp/evil")
        # Vendored snippet has no user-tree imports, no .env, no /home.
        self.assertNotIn("import scripts", H._DENIAL_PROBE_CODE)
        self.assertNotIn("from scripts", H._DENIAL_PROBE_CODE)
        self.assertNotIn("/home", H._DENIAL_PROBE_CODE)
        self.assertNotIn(".env", H._DENIAL_PROBE_CODE)

    def test_backup_digest_fail_closed_worker(self):
        # Worker is not root and has no /var/lib images: must fail closed,
        # never stub True. backup_ok False or OSError; digest OSError.
        h = H.RealCutoverHost(runner=FakeRunner(
            findmnt_text="squashfs ro /dev/loop20 /run/hermes-stock-activation/known-good-snap"))
        try:
            ok = h.backup_ok()
        except OSError:
            ok = False
        self.assertFalse(ok)
        with self.assertRaises(OSError):
            h.digest_record()

    def test_backup_measures_not_caller_true(self):
        import os as _os
        import tempfile as _tf
        import shutil as _sh
        import hashlib as _hl
        d = _tf.mkdtemp(prefix="cutover-backup-", dir="/tmp")
        try:
            img = _os.path.join(d, "known-good.squashfs")
            with open(img, "wb") as f:
                f.write(b"test-image-bytes")
            digest = _hl.sha256(b"test-image-bytes").hexdigest()
            # Temp file is uid !=0 in worker, so backup must be False
            # even with matching hash (proves uid/mode/hash all checked,
            # not caller True).
            runner = FakeRunner(
                findmnt_text="squashfs ro /dev/loop9 /run/hermes-stock-activation/known-good-snap")
            h = H.RealCutoverHost(runner=runner, known_good_image=img)
            # Pin is fixed production 1d3f...; temp hash differs, so False.
            self.assertNotEqual(digest, H.KNOWN_GOOD_IMAGE_SHA)
            try:
                ok = h.backup_ok()
            except OSError:
                ok = False
            self.assertFalse(ok)
            # Even if pin matched, uid !=0 still False (not caller True).
            orig = H.KNOWN_GOOD_IMAGE_SHA
            try:
                H.KNOWN_GOOD_IMAGE_SHA = digest
                try:
                    ok2 = h.backup_ok()
                except OSError:
                    ok2 = False
                # Temp mode is 644, not 0400, and uid !=0, so still False.
                self.assertFalse(ok2)
            finally:
                H.KNOWN_GOOD_IMAGE_SHA = orig
        finally:
            _sh.rmtree(d, ignore_errors=True)

    def test_dropin_names_scope(self):
        base = ("Id=hermes-gateway.service\nActiveState=inactive\nSubState=dead\n"
                "MainPID=0\nNRestarts=0\nExecStart=test\n"
                "DropInPaths=/etc/systemd/system/hermes-gateway.service.d/10-user-bus.conf "
                "/etc/systemd/system/hermes-gateway.service.d/zz-runtime-3.14.9.conf "
                "/etc/systemd/system/hermes-gateway.service.d/zzz-candidate.conf\n")
        runner = FakeRunner(show_text=base)
        h = H.RealCutoverHost(runner=runner)
        names = h.dropin_names("hermes-gateway.service")
        self.assertEqual(names, ["10-user-bus.conf", "zz-runtime-3.14.9.conf",
                                 "zzz-candidate.conf"])
        # Outside scope rejected.
        evil = base.replace(
            "/etc/systemd/system/hermes-gateway.service.d/zzz-candidate.conf",
            "/tmp/evil.conf")
        runner2 = FakeRunner(show_text=evil)
        h2 = H.RealCutoverHost(runner=runner2)
        with self.assertRaises(OSError):
            h2.dropin_names("hermes-gateway.service")
        # Missing DropInPaths fails closed, never drops checks.
        runner3 = FakeRunner(show_text="Id=hermes-gateway.service\nActiveState=inactive\n")
        h3 = H.RealCutoverHost(runner=runner3)
        with self.assertRaises(OSError):
            h3.dropin_names("hermes-gateway.service")
        with self.assertRaises(ValueError):
            h.dropin_names("evil.service")

    def test_gateway_missing_socket_gap_not_fake(self):
        import tempfile as _tf
        import os as _os
        d = _tf.mkdtemp(prefix="gw-missing-", dir="/tmp")
        try:
            miss = _os.path.join(d, "gateway.sock")
            ptr = _os.path.join(d, "gateway.sock.path")
            h = H.RealCutoverHost(runner=FakeRunner(), gateway_sock=miss,
                                  gateway_pointer=ptr)
            with self.assertRaises(OSError) as cm:
                h.gateway_talk(H.GATEWAY_REQUEST_BYTES)
            self.assertIn("gateway-unsupported", str(cm.exception))
            # Wrong request bytes rejected, no fake.
            with self.assertRaises(ValueError):
                h.gateway_talk(b'{"verb":"identify","id":1,"protocol":2}\n')
        finally:
            import shutil as _sh
            _sh.rmtree(d, ignore_errors=True)

    def test_gateway_real_socket_fake_protocol_negative(self):
        import socket as _sock
        import threading as _th
        import tempfile as _tf
        import os as _os
        import json as _j
        d = _tf.mkdtemp(prefix="gw-real-", dir="/tmp")
        try:
            path = _os.path.join(d, "gateway.sock")
            # Fake server speaks wrong protocol (ok False), real peercred.
            def _serve_once():
                srv = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
                try:
                    srv.bind(path)
                    srv.listen(1)
                    srv.settimeout(5)
                    conn, _ = srv.accept()
                    with conn:
                        conn.settimeout(5)
                        data = b""
                        while b"\n" not in data:
                            chunk = conn.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                        bad = _j.dumps({"ok": False, "protocol": 99,
                                        "result": {"protocol": 99, "pid": 0}}).encode() + b"\n"
                        conn.sendall(bad)
                finally:
                    try:
                        srv.close()
                    except OSError:
                        pass
            t = _th.Thread(target=_serve_once, daemon=True)
            t.start()
            import time as _t
            for _ in range(50):
                if _os.path.exists(path):
                    break
                _t.sleep(0.02)
            h = H.RealCutoverHost(runner=FakeRunner(), gateway_sock=path,
                                  gateway_pointer=path + ".ptr")
            got = h.gateway_talk(H.GATEWAY_REQUEST_BYTES)
            # Real response (ok False), real peercred (not faked to 1001).
            self.assertIsInstance(got, dict)
            self.assertIn("response", got)
            self.assertIn("peer_pid", got)
            self.assertIn("peer_uid", got)
            self.assertFalse(got["response"].get("ok") is True)
            # Must not fake pid/uid to 1001/New pid: peer is this test proc.
            self.assertEqual(got["peer_pid"], _os.getpid())
            # gateway_ok contract would fail (protocol 99, ok False) -> no commit.
            from scripts.stock_cutover import cutover_orchestrate as C
            self.assertFalse(C.gateway_ok(got["response"], got["peer_pid"],
                                          got["peer_uid"], 590001))
            t.join(timeout=5)
        finally:
            import shutil as _sh
            _sh.rmtree(d, ignore_errors=True)

    def test_preflight_reports_cwd(self):
        runner = FakeRunner(
            findmnt_text="squashfs ro /dev/loop20 /run/hermes-stock-activation/known-good-snap")
        h = H.RealCutoverHost(runner=runner)
        h.journal_dir_info = lambda: {"path": H.JOURNAL_DIR, "mode": 0o700,
                                      "uid": 0, "parent_mode": 0o755,
                                      "parent_uid": 0,
                                      "parent_writable_by_1001": False}
        h.journal_load = list
        h.boot_id = lambda: "a7d3326c-test-boot-id"
        h.proc_identity = lambda pid: {"boot_id": "a7d3326c-test-boot-id",
                                       "pid": pid, "starttime": 1,
                                       "exe": "x", "cmdline": "y",
                                       "cgroup": "z", "cwd": "/home/ubuntu/.hermes",
                                       "environ_keys": ["HOME"]}
        h.file_info = lambda p: {"exists": True, "mode": 0o600, "uid": 0,
                                 "size": 1, "sha256": "00" * 32,
                                 "writable_by_1001": False}
        _res = H.preflight_readonly(h)
        # show is inactive MainPID 0, so no identity; force active to check cwd.
        text = ("Id=hermes-gateway.service\nActiveState=active\nSubState=running\n"
                "MainPID=590001\nNRestarts=0\nExecStart=test\n")
        runner2 = FakeRunner(show_text=text,
            findmnt_text="squashfs ro /dev/loop20 /run/x")
        h2 = H.RealCutoverHost(runner=runner2)
        h2.journal_dir_info = h.journal_dir_info
        h2.journal_load = list
        h2.boot_id = h.boot_id
        h2.proc_identity = h.proc_identity
        h2.file_info = h.file_info
        res2 = H.preflight_readonly(h2)
        self.assertIn("identity:590001", res2["checks"])
        self.assertEqual(res2["checks"]["identity:590001"]["cwd"],
                         "/home/ubuntu/.hermes")

    def test_preflight_readonly_no_mutation(self):
        runner = FakeRunner(
            findmnt_text="squashfs ro /dev/loop20 /run/hermes-stock-activation/known-good-snap")
        h = H.RealCutoverHost(runner=runner)
        # Stub filesystem-touching reads to stay hermetic (no /var/lib).
        h.journal_dir_info = lambda: {"path": H.JOURNAL_DIR, "mode": 0o700,
                                      "uid": 0, "parent_mode": 0o755,
                                      "parent_uid": 0,
                                      "parent_writable_by_1001": False}
        h.journal_load = list
        h.boot_id = lambda: "a7d3326c-test-boot-id"
        h.proc_identity = lambda pid: {"boot_id": "a7d3326c-test-boot-id",
                                       "pid": pid, "starttime": 1,
                                       "exe": "x", "cmdline": "y",
                                       "cgroup": "z"}
        h.file_info = lambda p: {"exists": True, "mode": 0o600, "uid": 0,
                                 "size": 1, "sha256": "00" * 32,
                                 "writable_by_1001": False}
        res = H.preflight_readonly(h)
        self.assertEqual(res["status"], "preflight-complete")
        self.assertFalse(res["signed"])
        self.assertEqual(res["service_cutover"], "NOT-AUTHORIZED")
        self.assertIn("show:hermes-gateway.service", res["checks"])
        self.assertIn("python_self", res["checks"])
        self.assertIn("pins", res["checks"])
        self.assertEqual(res["checks"]["pins"]["target"], H.TARGET_SHA)
        # No mutation argv recorded beyond show/findmnt.
        for argv in runner.calls:
            self.assertNotIn("stop", argv)
            self.assertNotIn("start", argv)
            self.assertNotIn("restart", " ".join(argv).lower().replace("nrestarts", ""))

    def test_lock_constructor_not_activated(self):
        args = H.lockfile_create_args()
        self.assertEqual(args["path"], "/var/lib/hermes-stock-activation/journal.lock")
        self.assertEqual(args["mode"], 0o600)
        self.assertFalse(args["activated"])
        with self.assertRaises(ValueError):
            H.lockfile_create_args("/tmp/evil.lock")


class TestSupervision(unittest.TestCase):
    def test_units_verified(self):
        cut = R.cutover_service_unit()
        rec = R.recover_service_unit()
        tim = R.recover_timer_unit()
        self.assertTrue(R.validate_supervision(cut, rec, tim))
        self.assertIn("OnFailure=hermes-stock-cutover-recover.service", cut)
        self.assertIn("Type=oneshot", cut)
        self.assertIn("Type=oneshot", rec)
        self.assertIn("/usr/bin/python3.12 -I /var/lib/hermes-stock-activation/recovery/cli.py", cut)
        self.assertIn("/usr/bin/python3.12 -I /var/lib/hermes-stock-activation/recovery/cli.py", rec)
        self.assertIn("Unit=hermes-stock-cutover-recover.service", tim)
        for bad in ("Restart=always", "systemctl restart", "/home/ubuntu/worktrees",
                    "gen-1d9a377fa00c", "/home/ubuntu/.hermes/hermes-agent/venv"):
            self.assertNotIn(bad, cut)
            self.assertNotIn(bad, rec)

    def test_recovery_argv_fixed(self):
        self.assertEqual(R.RECOVERY_ARGV,
                         ["/usr/bin/python3.12", "-I",
                          "/var/lib/hermes-stock-activation/recovery/cli.py", "recover"])
        self.assertEqual(R.APPLY_ARGV,
                         ["/usr/bin/python3.12", "-I",
                          "/var/lib/hermes-stock-activation/recovery/cli.py", "apply"])


class TestRunnerIdentityObject(unittest.TestCase):
    def test_object_identity_not_name(self):
        # Injected runner named _run_fixed must still be treated as injected,
        # not live. Old name-based check would misclassify.
        import subprocess as _sp
        def _run_fixed(argv, timeout=60):
            self.assertEqual(argv[0], "/usr/bin/findmnt")
            return _sp.CompletedProcess(argv, 0, "squashfs ro /dev/loop9 /run/x", "")
        _run_fixed.__name__ = "_run_fixed"
        h = H.RealCutoverHost(runner=_run_fixed)
        self.assertFalse(h._is_live)
        out = h.mount_show(H.KNOWN_GOOD_MOUNT)
        self.assertIn("squashfs", out)
        # Live host uses object identity (is_live True).
        h2 = H.RealCutoverHost(runner=None)
        self.assertTrue(h2._is_live)

    def test_proc_identity_full_fields(self):
        import os as _os
        h = H.RealCutoverHost(runner=FakeRunner())
        ident = h.proc_identity(_os.getpid())
        for k in ("boot_id", "pid", "starttime", "exe", "cmdline", "cgroup", "cwd"):
            self.assertIn(k, ident)
        self.assertEqual(ident["pid"], _os.getpid())
        self.assertGreater(int(ident["starttime"]), 0)
        self.assertTrue(ident["boot_id"])
        self.assertTrue(ident["exe"])
        # cwd must be real dir (readlink /proc/self/cwd).
        self.assertTrue(ident["cwd"].startswith("/"))

    def test_file_info_o_nofollow_no_follow(self):
        import os as _os
        import tempfile as _tf
        h = H.RealCutoverHost(runner=FakeRunner())
        d = _tf.mkdtemp(prefix="cutover-nofollow-", dir="/tmp")
        try:
            real = _os.path.join(d, "real.conf")
            with open(real, "wb") as f:
                f.write(b"real-bytes")
            link = _os.path.join(d, "link.conf")
            _os.symlink(real, link)
            info_link = h.file_info(link)
            # Symlink must not be hashed as target (sha empty, no follow).
            self.assertEqual(info_link["sha256"], "")
            info_real = h.file_info(real)
            self.assertEqual(len(info_real["sha256"]), 64)
        finally:
            import shutil as _sh
            _sh.rmtree(d, ignore_errors=True)

    def test_lock_info_none_when_absent(self):
        h = H.RealCutoverHost(runner=FakeRunner())
        # No /var/lib/.../journal.lock in worker (no root); must be None or OSError.
        try:
            info = h.lock_info()
        except OSError:
            info = None
        self.assertTrue(info is None or isinstance(info, dict))


if __name__ == "__main__":
    unittest.main()
