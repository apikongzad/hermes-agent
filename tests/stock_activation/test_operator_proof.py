import errno
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest


def _load_op():
    from scripts.stock_activation import operator_proof as m
    return m


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _make_prep(tmpdir, manifest_text, extra=None):
    prep_path = os.path.join(tmpdir, "known-good.prep.json")
    payload = {
        "kind": "known-good",
        "source_sha": "abc",
        "archive_sha256": "def",
        "manifest": manifest_text,
        "manifest_sha256": _sha(manifest_text.encode()),
        "image_sha256": "imgs",
        "image_bytes": 123,
        "image_path": os.path.join(tmpdir, "known-good.squashfs"),
        "web_dist": "omitted-unverified",
    }
    if extra:
        payload.update(extra)
    with open(prep_path, "w") as f:
        json.dump(payload, f)
    return prep_path


class FakeStat:
    def __init__(self, mode, uid, gid=0, size=0):
        self.st_mode = mode
        self.st_uid = uid
        self.st_gid = gid
        self.st_size = size


class FakeResult:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeHost:
    def __init__(self, fixture_root):
        self.fixture_root = fixture_root
        self.live = {}  # path -> {"data": bytes, "mode": int, "uid": int}
        self.run_log = []
        self.chmod_calls = []
        self.fsync_fail = False
        self.denial = {"write": errno.EROFS, "rename": errno.EROFS, "link": errno.EROFS}
        self.findmnt_output = None
        self.losetup_device = "/dev/loop7"
        self.cli_rc = 0
        self.web_rc = 0
        self.write_temp_calls = []
        self.loop_to_image = {}

    def lstat(self, path):
        if path in self.live:
            e = self.live[path]
            return FakeStat(0o100000 | e["mode"], e["uid"], 0, len(e.get("data", b"")))
        # real fs for fixture
        return os.lstat(path)

    def read_bytes(self, path):
        if path in self.live:
            return self.live[path]["data"]
        with open(path, "rb") as f:
            return f.read()

    def sha256_file(self, path):
        return _sha(self.read_bytes(path))

    def write_temp(self, path, data):
        self.write_temp_calls.append(path)
        if path in self.live:
            raise OSError(errno.EEXIST, "exists")
        try:
            os.lstat(path)
            raise OSError(errno.EEXIST, "exists")
        except FileNotFoundError:
            pass
        self.live[path] = {"data": bytes(data), "mode": 0o600, "uid": 0}

    def file_fsync(self, path):
        if self.fsync_fail:
            raise OSError("injected fsync fail")

    def rename_path(self, src, dst):
        if src not in self.live:
            # real fs rename
            os.rename(src, dst)
            return
        if dst in self.live:
            raise OSError("dst exists")
        self.live[dst] = self.live.pop(src)
        # simulate live final perms after copy
        self.live[dst]["mode"] = 0o600
        self.live[dst]["uid"] = 0

    def dir_fsync(self, path):
        if self.fsync_fail:
            raise OSError("injected dir fsync fail")

    def run(self, argv, env):
        assert isinstance(argv, list) and argv
        assert all(isinstance(x, str) for x in argv)
        self.run_log.append(list(argv))
        prog = argv[0]
        base = os.path.basename(prog)
        assert base not in ("systemctl", "git", "sudo"), base
        assert "/opt" not in prog, prog
        assert "systemctl" not in argv[0]
        if argv[:3] == ["/usr/bin/install", "-d", "-o"]:
            return FakeResult(0, b"", b"")
        if argv[0] == "/usr/sbin/losetup" and "-d" in argv:
            return FakeResult(0, b"", b"")
        if argv[0] == "/usr/sbin/losetup" and "--list" in argv:
            loopdev = argv[-1]
            img = self.loop_to_image.get(loopdev)
            if img is None:
                # derive from previous --find call if available
                for logged in reversed(self.run_log):
                    if logged[0] == "/usr/sbin/losetup" and "--find" in logged:
                        img = logged[-1]
                        break
                if img is None:
                    from scripts.stock_activation import operator_proof as _op
                    img = _op.KNOWN_GOOD_DEST
            return FakeResult(0, f"1 {img}\n".encode(), b"")
        if argv[0] == "/usr/sbin/losetup":
            # --find --show --read-only --nooverlap -- <image>
            img = argv[-1] if argv[-1].startswith("/") else None
            if img is not None:
                self.loop_to_image[self.losetup_device] = img
            return FakeResult(0, (self.losetup_device + "\n").encode(), b"")
        if argv[0] == "/usr/bin/mount":
            return FakeResult(0, b"", b"")
        if argv[0] == "/usr/bin/findmnt":
            out = self.findmnt_output
            if out is None:
                # default RO squashfs with loop
                out = f"squashfs ro,nosuid,nodev {self.losetup_device} {argv[-1]}\n"
            if isinstance(out, str):
                out = out.encode()
            return FakeResult(0, out, b"")
        if argv[0] == "/usr/bin/umount":
            return FakeResult(0, b"", b"")
        # proof python
        if "main.py" in argv[0] or (len(argv) > 2 and "main.py" in str(argv)):
            if "dashboard" in argv:
                return FakeResult(self.web_rc, b"", b"")
            return FakeResult(self.cli_rc, b"", b"")
        # python proof binary path like /run/.../venv/bin/python3
        if argv[0].endswith("/venv/bin/python3"):
            if "dashboard" in argv:
                return FakeResult(self.web_rc, b"", b"")
            return FakeResult(self.cli_rc, b"", b"")
        return FakeResult(0, b"", b"")

    def denial_probe(self, path, op):
        return self.denial.get(op, errno.EROFS)

    def file_uid(self, path):
        if path in self.live:
            return self.live[path]["uid"]
        return os.lstat(path).st_uid


class OperatorProofTests(unittest.TestCase):
    def test_inventory_uid_equals_lstat(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            img = os.path.join(td, "a.squashfs")
            with open(img, "wb") as f:
                f.write(b"imgbytes")
            manifest = f"source/a file 0644 {_sha(b'x')} -\n"
            prep = _make_prep(td, manifest)
            inv = m.inventory_closure(prep, img)
            self.assertEqual(inv["status"], "inventoried")
            self.assertEqual(inv["copied"], 0)
            self.assertFalse(inv["git_invoked"])
            self.assertFalse(inv["signed"])
            self.assertFalse(inv.get("signed"))
            st = os.lstat(prep)
            self.assertEqual(inv["file_uid"], st.st_uid)
            # never hardcoded 0 when file exists and owner is not root
            # (in CI container uid may be 0; only assert equality)
            self.assertEqual(inv["file_uid"], os.lstat(prep).st_uid)
            self.assertEqual(inv["file_gid"], os.lstat(prep).st_gid)
            # missing lstat => None, never 0
            inv2 = m.inventory_closure(prep, os.path.join(td, "missing.img"))
            self.assertIsNone(inv2["image_uid"])
            self.assertIsNone(inv2["image_gid"])
            self.assertNotEqual(inv2["image_uid"], 0)

    def test_inventory_denied_env_refuses(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            manifest = (
                "source/a file 0644 abc -\n"
                "source/.env file 0644 abc -\n"
            )
            prep = _make_prep(td, manifest)
            inv = m.inventory_closure(prep)
            self.assertEqual(inv["status"], "inventory-refused")
            self.assertEqual(inv["copied"], 0)
            hits = inv.get("denylist_hits", inv.get("hits", []))
            self.assertTrue(any(".env" in h for h in hits))

    def test_inventory_counts_and_venv_and_interpreter(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            manifest = (
                "source/a file 0644 abc -\n"
                "venv/bin/python3 symlink - ../../interpreter/bin/python3.14\n"
                "interpreter/bin/python3.14 file 0755 abc -\n"
                "deps/x file 0644 abc -\n"
            )
            prep = _make_prep(td, manifest)
            inv = m.inventory_closure(prep)
            self.assertEqual(inv["status"], "inventoried")
            self.assertEqual(inv["counts"]["source"], 1)
            self.assertEqual(inv["counts"]["venv"], 1)
            self.assertEqual(inv["counts"]["interpreter"], 1)
            self.assertEqual(inv["counts"]["deps"], 1)
            self.assertEqual(inv["interpreter_file_count"], 1)
            vt = inv.get("venv_python_targets", {})
            self.assertTrue(any("python3" in k for k in vt))

    def test_plan_argv_equals_closure_boundary(self):
        m = _load_op()
        from scripts.stock_activation import closure_boundary as cb
        self.assertEqual(m.losetup_argv("/x.img"), cb.losetup_argv("/x.img"))
        self.assertEqual(m.mount_argv("/dev/loop1", "/mp"), cb.mount_argv("/dev/loop1", "/mp"))
        self.assertEqual(m.findmnt_argv("/mp"), cb.findmnt_argv("/mp"))
        # literals
        self.assertEqual(m.losetup_argv("/x"), ["/usr/sbin/losetup", "--find", "--show", "--read-only", "--nooverlap", "--", "/x"])
        self.assertEqual(m.mount_argv("L", "M"), ["/usr/bin/mount", "-n", "-t", "squashfs", "-o", "ro,nosuid,nodev", "L", "M"])
        self.assertEqual(m.findmnt_argv("M"), ["/usr/bin/findmnt", "-n", "-o", "FSTYPE,OPTIONS,SOURCE,TARGET", "--target", "M"])
        self.assertEqual(m.umount_argv("M"), ["/usr/bin/umount", "--", "M"])
        self.assertEqual(m.losetup_detach_argv("L"), ["/usr/sbin/losetup", "-d", "L"])
        self.assertEqual(m.install_dir_argv("/p", "0700"), ["/usr/bin/install", "-d", "-o", "0", "-g", "0", "-m", "0700", "/p"])
        self.assertEqual(m.PROOF_ENV, {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})

    def test_plan_no_systemctl_git_signed_gates(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(b"img")
            h = _sha(b"img")
            recs = [{"kind": "known-good", "image_path": src, "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            res = m.plan(recs, {"known-good": 9120})
            self.assertEqual(res["status"], "manifest-ready")
            man = res["manifest"]
            self.assertFalse(man["signed"])
            for g, v in man["gates"].items():
                self.assertEqual(v, "UNEXECUTED")
            self.assertEqual(man["activation"], "UNEXECUTED")
            self.assertEqual(man["service_cutover"], "NOT_AUTHORIZED")
            for c in res["commands"]:
                joined = " ".join(c)
                self.assertNotIn("systemctl", joined)
                self.assertNotIn("git", joined)
                self.assertNotIn("sudo", joined)
                self.assertNotIn("/opt", joined)

    def test_sha_mismatch_writes_no_destination(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(b"real")
            recs = [{"kind": "known-good", "image_path": src, "prep_path": os.path.join(td, "p.json"), "expected_sha256": "0" * 64}]
            man = m.build_portable_manifest(recs)
            self.assertEqual(man["status"], "manifest-refused")
            self.assertEqual(man["images"], [])
            host = FakeHost(td)
            res = m.apply(host, recs, {"known-good": 9120})
            self.assertEqual(res["status"], "manifest-refused")
            self.assertEqual(host.write_temp_calls, [])
            self.assertEqual(host.run_log, [])

    def test_fsync_oserror_durable_unknown_no_mount(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            data = b"imgdata"
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(data)
            h = _sha(data)
            recs = [{"kind": "known-good", "image_path": src, "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            host = FakeHost(td)
            host.fsync_fail = True
            res = m.apply(host, recs, {"known-good": 9120})
            self.assertEqual(res["status"], "durable-state-unknown")
            for c in host.run_log:
                self.assertNotEqual(c[0], "/usr/bin/mount")

    def test_foreign_owner_refuses_no_chmod(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            data = b"img2"
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(data)
            h = _sha(data)
            recs = [{"kind": "known-good", "image_path": src, "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            host = FakeHost(td)
            host.live[m.KNOWN_GOOD_DEST] = {"data": data, "mode": 0o400, "uid": 1001}
            host.findmnt_output = f"squashfs ro,nosuid,nodev /dev/loop7 {m.KNOWN_GOOD_MOUNT}\n"
            res = m.apply(host, recs, {"known-good": 9120})
            self.assertIn(res["status"], ("refused", "failed", "manifest-refused"))
            for c in host.run_log:
                self.assertNotIn("chmod", " ".join(c).lower())
            self.assertEqual(host.chmod_calls, [])

    def test_erofs_marks_observation(self):
        m = _load_op()
        ev = {"executed": True, "write_errno": 30, "rename_errno": 30, "link_errno": 30, "backing_writable_by_1001": False}
        self.assertTrue(m._immutable_from_evidence(ev))
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(b"z")
            h = _sha(b"z")
            recs = [{"kind": "known-good", "image_path": src, "prep_path": os.path.join(td, "p.json"), "expected_sha256": h,
                     "evidence": dict(ev)}]
            man = m.build_portable_manifest(recs)
            self.assertTrue(man["images"][0]["kernel_immutable"])

    def test_immutable_true_without_erofs_does_not(self):
        m = _load_op()
        ev = {"executed": True, "kernel_immutable": True, "immutable": True}
        self.assertFalse(m._immutable_from_evidence(ev))
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(b"z")
            h = _sha(b"z")
            recs = [{"kind": "known-good", "image_path": src, "prep_path": os.path.join(td, "p.json"), "expected_sha256": h,
                     "evidence": dict(ev)}]
            man = m.build_portable_manifest(recs)
            self.assertFalse(man["images"][0]["kernel_immutable"])
            self.assertFalse(man["kernel_immutable"])
            for v in man["gates"].values():
                self.assertEqual(v, "UNEXECUTED")

    def test_eacces_0555_does_not_set_immutable(self):
        m = _load_op()
        ev = {"executed": True, "write_errno": 13, "rename_errno": 13, "link_errno": 13, "backing_writable_by_1001": True}
        self.assertFalse(m._immutable_from_evidence(ev))
        with tempfile.TemporaryDirectory() as td:
            data = b"img3"
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(data)
            h = _sha(data)
            recs = [{"kind": "known-good", "image_path": src, "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            host = FakeHost(td)
            host.denial = {"write": 13, "rename": 13, "link": 13}
            res = m.apply(host, recs, {"known-good": 9120})
            self.assertEqual(res["status"], "applied")
            self.assertFalse(res["kernel_immutable"])

    def test_recover_leaves_journal(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            journal = os.path.join(td, "journal.json")
            with open(journal, "w") as f:
                f.write("{}")
            host = FakeHost(td)
            host.findmnt_output = ""
            # not mounted
            m.recover(host, [m.KNOWN_GOOD_MOUNT])
            self.assertTrue(os.path.exists(journal))
            # mounted case also leaves journal
            host2 = FakeHost(td)
            host2.findmnt_output = f"squashfs ro,nosuid,nodev /dev/loop9 {m.KNOWN_GOOD_MOUNT}\n"
            m.recover(host2, [m.KNOWN_GOOD_MOUNT])
            self.assertTrue(os.path.exists(journal))
            # umount + detach called
            kinds = [c[0] for c in host2.run_log]
            self.assertIn("/usr/bin/umount", kinds)
            self.assertIn("/usr/sbin/losetup", kinds)

    def test_idempotent_no_mount_twice(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            data = b"idem"
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(data)
            h = _sha(data)
            recs = [{"kind": "known-good", "image_path": src, "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            host = FakeHost(td)
            res1 = m.apply(host, recs, {"known-good": 9120})
            self.assertEqual(res1["status"], "applied")
            # fix perms to idempotent state
            host.live[m.KNOWN_GOOD_DEST]["mode"] = 0o400
            host.live[m.KNOWN_GOOD_DEST]["uid"] = 0
            host.findmnt_output = f"squashfs ro,nosuid,nodev /dev/loop7 {m.KNOWN_GOOD_MOUNT}\n"
            n_mount_before = sum(1 for c in host.run_log if c[0] == "/usr/bin/mount")
            n_loop_before = sum(1 for c in host.run_log if c[0] == "/usr/sbin/losetup" and "-d" not in c)
            m.apply(host, recs, {"known-good": 9120})
            n_mount_after = sum(1 for c in host.run_log if c[0] == "/usr/bin/mount")
            n_loop_after = sum(1 for c in host.run_log if c[0] == "/usr/sbin/losetup" and "-d" not in c)
            self.assertEqual(n_mount_after, n_mount_before)
            self.assertEqual(n_loop_after, n_loop_before)

    def test_rw_bind_findmnt_fails(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            data = b"rwtest"
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(data)
            h = _sha(data)
            recs = [{"kind": "known-good", "image_path": src, "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            host = FakeHost(td)
            host.findmnt_output = f"squashfs rw,relatime /dev/loop7 {m.KNOWN_GOOD_MOUNT}\n"
            res = m.apply(host, recs, {"known-good": 9120})
            self.assertEqual(res["status"], "failed")
            host2 = FakeHost(td)
            host2.findmnt_output = f"squashfs ro,bind /dev/loop7 {m.KNOWN_GOOD_MOUNT}\n"
            res2 = m.apply(host2, recs, {"known-good": 9120})
            self.assertEqual(res2["status"], "failed")

    def test_cli_apply_recover_no_execute_exits_3(self):
        m = _load_op()
        self.assertEqual(m.main(["apply"]), 3)
        self.assertEqual(m.main(["recover", "/x"]), 3)
        self.assertFalse(os.path.exists("/var/lib/hermes-stock-activation"))

    def test_export_closure_unspecified_and_cli(self):
        from scripts.stock_activation import os_adapter as oa
        from scripts.stock_activation import cli
        r = oa.export_closure()
        self.assertEqual(r["status"], "CLOSURE_ENUMERATION_UNSPECIFIED")
        self.assertEqual(r["copied"], 0)
        self.assertFalse(r["git_invoked"])
        self.assertEqual(cli.main(["apply"]), 2)

    def test_web_proof_refuses_9119(self):
        m = _load_op()
        with self.assertRaises(ValueError):
            m.web_proof_argv("/mp", 9119)
        with self.assertRaises(ValueError):
            m.web_proof_argv("/mp", 4096)
        argv = m.web_proof_argv("/mp", 9120)
        self.assertIn("127.0.0.1", argv)
        self.assertIn("9120", argv)

    def test_file_uid_adapter(self):
        from scripts.stock_activation import os_adapter as oa
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "f")
            with open(p, "wb") as f:
                f.write(b"hi")
            ad = oa.FilesystemAdapter(td)
            self.assertEqual(ad.file_uid(p), os.lstat(p).st_uid)

    def test_file_uid_of_rejects_bool(self):
        m = _load_op()
        with self.assertRaises(TypeError):
            m.file_uid_of(True)

    def test_gates_bare_true_not_enough(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(b"b")
            h = _sha(b"b")
            recs = [{"kind": "known-good", "image_path": src, "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            man = m.build_portable_manifest(recs, evidence={"executed": True})
            for v in man["gates"].values():
                self.assertEqual(v, "UNEXECUTED")
            self.assertFalse(man["kernel_immutable"])

    def test_plan_manifest_out_forbidden(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(b"b")
            h = _sha(b"b")
            recs = [{"kind": "known-good", "image_path": src, "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            res = m.plan(recs, {"known-good": 9120}, manifest_out="/var/lib/hermes-stock-activation/out.json")
            self.assertEqual(res["status"], "manifest-refused")

    def test_plan_exits_0_even_refused(self):
        m = _load_op()
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = m.main(["plan"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["status"], "manifest-refused")

    def test_recover_ambiguous(self):
        m = _load_op()
        host = FakeHost(tempfile.gettempdir())
        host.findmnt_output = "squashfs ro /dev/loop1 /mp\nsquashfs ro /dev/loop2 /mp\n"
        res = m.recover(host, ["/mp"])
        self.assertEqual(res["status"], "stopped-unresolved")
        # no detach by guessing
        detach_calls = [c for c in host.run_log if c[0] == "/usr/sbin/losetup" and "-d" in c]
        self.assertEqual(detach_calls, [])

    def test_apply_requires_host_methods(self):
        m = _load_op()
        class Bare:
            pass
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(b"x")
            recs = [{"kind": "known-good", "image_path": src, "prep_path": "p", "expected_sha256": _sha(b"x")}]
            res = m.apply(Bare(), recs, {})
            self.assertEqual(res["status"], "refused")

    def test_proof_home_refuses_live_home_and_env_component(self):
        m = _load_op()
        for bad in ("/home/ubuntu", "/home/ubuntu/",
                    "/home/ubuntu/.hermes", "/home/ubuntu/sub/dir",
                    "/home/ubuntu//sub"):
            self.assertTrue(m._proof_home_refused(bad), bad)
        for bad in ("/tmp/x/.env", "/tmp/.env/y", "/a/.env",
                    "/a/b/.env/c"):
            self.assertTrue(m._proof_home_refused(bad), bad)
        self.assertFalse(
            m._proof_home_refused("/var/lib/hermes-stock-activation/proof-home"))
        self.assertFalse(m._proof_home_refused("/tmp/my.env/file"))
        self.assertFalse(m._proof_home_refused("/tmp/.env2/file"))

    def test_immutable_requires_exact_false_backing(self):
        m = _load_op()
        base = {"executed": True, "write_errno": errno.EROFS,
                "rename_errno": errno.EROFS, "link_errno": errno.EROFS}
        good = dict(base, backing_writable_by_1001=False)
        self.assertTrue(m._immutable_from_evidence(good))
        for bad_val in (1, 0, True, None, "false"):
            ev = dict(base, backing_writable_by_1001=bad_val)
            self.assertFalse(m._immutable_from_evidence(ev), repr(bad_val))


class LiveEntrypointTests(unittest.TestCase):
    def test_apply_execute_live_calls_apply_not_4(self):
        m = _load_op()
        # live factory must exist in this file (stdlib only, no scripts.stock_activation import)
        self.assertTrue(hasattr(m, "LiveProofHost"), "LiveProofHost missing")
        self.assertTrue(hasattr(m, "_make_live_host"), "host factory missing")
        import os as _os
        orig_geteuid = _os.geteuid
        orig_ok = m._live_file_ok
        orig_factory = m._make_live_host
        orig_apply = m.apply
        orig_ensure = getattr(m, "_ensure_live_proof_home", None)
        called = {}
        fake_host = FakeHost(tempfile.gettempdir())
        # health fetch stub so WEB gate could be evaluated without live net
        fake_host.health_fetch = lambda url: {"status": 200, "content_type": "application/json", "body": {"ok": True}}
        def fake_apply(host, records, ports, execute_commands=True, proof_home=None):
            called["yes"] = True
            self.assertIs(host, fake_host)
            return {"status": "applied", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": m._gates_unexecuted(), "images": []}
        try:
            _os.geteuid = lambda: 0
            m._live_file_ok = lambda: (True, "")
            m._make_live_host = lambda: fake_host
            m.apply = fake_apply
            if orig_ensure is not None:
                m._ensure_live_proof_home = lambda path=None: path
            with tempfile.TemporaryDirectory() as td:
                src = os.path.join(td, "k.squashfs")
                with open(src, "wb") as f:
                    f.write(b"x")
                h = _sha(b"x")
                rc = m.main(["apply", "--execute-live",
                             "--prep", os.path.join(td, "p.json"),
                             "--image", src,
                             "--expected-sha", h,
                             "--kind", "known-good",
                             "--port", "9120"])
                self.assertTrue(called.get("yes"), "apply not called")
                self.assertNotEqual(rc, 4)
        finally:
            _os.geteuid = orig_geteuid
            m._live_file_ok = orig_ok
            m._make_live_host = orig_factory
            m.apply = orig_apply
            if orig_ensure is not None:
                m._ensure_live_proof_home = orig_ensure

    def test_missing_execute_live_returns_3_no_host(self):
        m = _load_op()
        self.assertTrue(hasattr(m, "_make_live_host"), "host factory missing")
        orig_factory = m._make_live_host
        constructed = []
        def boom():
            constructed.append(1)
            raise AssertionError("live host must not be constructed without --execute-live")
        try:
            m._make_live_host = boom
            self.assertEqual(m.main(["apply"]), 3)
            self.assertEqual(constructed, [])
            self.assertEqual(m.main(["recover", "/x"]), 3)
            self.assertEqual(constructed, [])
        finally:
            m._make_live_host = orig_factory


class ExecutedGatesTests(unittest.TestCase):
    def test_successful_fixture_apply_marks_only_performed(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            data = b"gate-performed"
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(data)
            h = _sha(data)
            recs = [{"kind": "known-good", "image_path": src,
                     "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            host = FakeHost(td)
            # fixture performs EROFS denials, cli ok, web argv ok, but no health_fetch
            # and digest mode will be 0600 (not 0400) so those gates stay UNEXECUTED
            res = m.apply(host, recs, {"known-good": 9120})
            self.assertEqual(res["status"], "applied")
            g = res["gates"]
            # actually performed in this invocation
            self.assertEqual(g["PROVISION"], "EXECUTED")
            self.assertEqual(g["MOUNT"], "EXECUTED")
            self.assertEqual(g["A1"], "EXECUTED")
            self.assertEqual(g["C2"], "EXECUTED")
            self.assertEqual(g["CLI_PROOF"], "EXECUTED")
            # not performed: no health_fetch success, no 0400 digest
            self.assertEqual(g["WEB_PROOF"], "UNEXECUTED")
            self.assertEqual(g["DIGEST"], "UNEXECUTED")
            self.assertEqual(res["activation"], "UNEXECUTED")
            self.assertEqual(res["service_cutover"], "NOT_AUTHORIZED")

    def test_caller_evidence_errno13_does_not_mark_A1(self):
        m = _load_op()
        ev = {"executed": True, "write_errno": 13, "rename_errno": 13,
              "link_errno": 13, "backing_writable_by_1001": False}
        self.assertFalse(m._immutable_from_evidence(ev))
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(b"z13")
            h = _sha(b"z13")
            recs = [{"kind": "known-good", "image_path": src,
                     "prep_path": os.path.join(td, "p.json"), "expected_sha256": h,
                     "evidence": dict(ev)}]
            man = m.build_portable_manifest(recs)
            self.assertFalse(man["images"][0]["kernel_immutable"])
            self.assertFalse(man["kernel_immutable"])
            self.assertEqual(man["gates"]["A1"], "UNEXECUTED")
            self.assertEqual(man["gates"]["C2"], "UNEXECUTED")
            # caller evidence must never mark these
            for k in ("CLI_PROOF", "WEB_PROOF", "MOUNT", "PROVISION", "DIGEST"):
                self.assertEqual(man["gates"][k], "UNEXECUTED")
        # live apply with EACCES denials must not mark A1/C2 either
        with tempfile.TemporaryDirectory() as td:
            data = b"img-eacces-gate"
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(data)
            h = _sha(data)
            recs = [{"kind": "known-good", "image_path": src,
                     "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            host = FakeHost(td)
            host.denial = {"write": 13, "rename": 13, "link": 13}
            res = m.apply(host, recs, {"known-good": 9120})
            self.assertEqual(res["status"], "applied")
            self.assertFalse(res["kernel_immutable"])
            self.assertEqual(res["gates"]["A1"], "UNEXECUTED")
            self.assertEqual(res["gates"]["C2"], "UNEXECUTED")


class OwnedWebProofTests(unittest.TestCase):
    def test_start_web_before_health_before_stop_and_no_blocking_run(self):
        m = _load_op()
        self.assertTrue(hasattr(m, "LiveProofHost"))
        self.assertTrue(hasattr(m.LiveProofHost, "start_web"))
        self.assertTrue(hasattr(m.LiveProofHost, "stop_web"))
        with tempfile.TemporaryDirectory() as td:
            data = b"owned-web-proof"
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(data)
            h = _sha(data)
            recs = [{"kind": "known-good", "image_path": src,
                     "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            # Legitimate symbolic proof-home: never created on real FS.
            # Real scratch files (src/prep) stay under provided TMPDIR (td).
            proof_home = m.PROOF_HOME_LIVE_DEFAULT
            self.assertEqual(
                proof_home, "/var/lib/hermes-stock-activation/proof-home",
                f"unexpected live default: {proof_home!r}",
            )
            self.assertFalse(
                m._proof_home_refused(proof_home),
                f"legitimate proof_home refused: {proof_home!r}",
            )
            order = []
            blocking_calls = []

            class OwnedFake(FakeHost):
                def run(self, argv, env):
                    if any("dashboard" in str(x) for x in argv):
                        blocking_calls.append(list(argv))
                        raise AssertionError("blocking run() must not be used for dashboard argv")
                    return super().run(argv, env)

                def start_web(self, argv, env):
                    order.append("start_web")
                    assert env.get("HOME") == proof_home, env
                    assert env.get("HERMES_HOME") == proof_home, env
                    assert any("dashboard" in str(x) for x in argv)
                    order_env = dict(env)

                    class Handle:
                        def poll(self):
                            return None

                        def wait(self, timeout=None):
                            return 0

                    self._handle = Handle()
                    self._start_env = order_env
                    return self._handle

                def health_fetch(self, url):
                    order.append("health_fetch")
                    return {"status": 200, "content_type": "application/json",
                            "body": {"ok": True}}

                def stop_web(self, handle):
                    order.append("stop_web")
                    assert handle is self._handle
                    return True

            import unittest.mock as _mock
            with _mock.patch.object(
                m, "_proof_home_refused", wraps=m._proof_home_refused
            ) as _spy:
                host = OwnedFake(td)
                res = m.apply(host, recs, {"known-good": 9120}, proof_home=proof_home)
            self.assertEqual(res["status"], "applied", f"unexpected response: {res!r}")
            _evaluated = [
                c for c in _spy.call_args_list if c.args and c.args[0] == proof_home
            ]
            self.assertTrue(
                _evaluated,
                f"guard never evaluated legitimate proof_home {proof_home!r}: "
                f"calls={_spy.call_args_list!r} response={res!r}",
            )
            self.assertEqual(
                order, ["start_web", "health_fetch", "stop_web"],
                f"order={order!r} response={res!r}",
            )
            self.assertEqual(
                blocking_calls, [],
                f"blocking run used for dashboard: {blocking_calls!r} response={res!r}",
            )
            run_cmds = [" ".join(c) for c in host.run_log]
            self.assertTrue(
                any("--help" in c for c in run_cmds),
                f"missing cli proof: {run_cmds!r} response={res!r}",
            )
            self.assertFalse(
                any("dashboard" in c for c in run_cmds),
                f"dashboard via blocking run: {run_cmds!r} response={res!r}",
            )
            self.assertEqual(
                res["gates"]["WEB_PROOF"], "EXECUTED",
                f"unexpected gates: {res['gates']!r} response={res!r}",
            )
            self.assertEqual(
                host._start_env.get("HOME"), proof_home,
                f"start_env={host._start_env!r} response={res!r}",
            )
            self.assertEqual(
                host._start_env.get("HERMES_HOME"), proof_home,
                f"start_env={host._start_env!r} response={res!r}",
            )

    def test_proof_home_refused(self):
        m = _load_op()
        with tempfile.TemporaryDirectory() as td:
            data = b"refuse-home"
            src = os.path.join(td, "k.squashfs")
            with open(src, "wb") as f:
                f.write(data)
            h = _sha(data)
            recs = [{"kind": "known-good", "image_path": src,
                     "prep_path": os.path.join(td, "p.json"), "expected_sha256": h}]
            for bad in ("/home/ubuntu", "/home/ubuntu/.hermes",
                        "/tmp/x/.env", "/tmp/.env/y"):
                host = FakeHost(td)
                res = m.apply(host, recs, {"known-good": 9120}, proof_home=bad)
                self.assertEqual(res["status"], "refused", f"bad={bad!r} response={res!r}")
                self.assertEqual(host.run_log, [], f"bad={bad!r} response={res!r}")
                for g in res["gates"].values():
                    self.assertEqual(g, "UNEXECUTED", f"bad={bad!r} response={res!r}")


def tearDownModule():
    import sys as _sys
    for _mod in list(_sys.modules.keys()):
        if _mod == "scripts.stock_activation.os_adapter":
            del _sys.modules[_mod]


if __name__ == "__main__":
    unittest.main()
