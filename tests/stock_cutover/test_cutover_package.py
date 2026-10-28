"""Cutover package exporter + CLI refusal tests. Home scratch only, no /tmp."""
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest


def _home_scratch(prefix):
    home = os.path.expanduser("~")
    assert os.path.isabs(home) and not home.startswith("/tmp"), home
    base = os.path.join(home, "cutover-pkg-tests")
    os.makedirs(base, mode=0o700, exist_ok=True)
    d = tempfile.mkdtemp(prefix=prefix, dir=base)
    assert not os.path.normpath(d).startswith("/tmp"), d
    return d


def _sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(65536)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _load():
    from scripts.stock_cutover import cutover_package as e
    return e


class PackageTests(unittest.TestCase):
    def test_export_no_git_manifest(self):
        e = _load()
        scratch = _home_scratch("export-")
        dest = os.path.join(scratch, "pkg")
        res = e.export_cutover_package(dest)
        self.assertEqual(res["status"], "cutover-exported")
        self.assertTrue(res["success"])
        self.assertFalse(res["signed"])
        for dp, dn, fn in os.walk(dest, followlinks=False):
            self.assertNotIn(".git", dn)
            self.assertNotIn(".git", fn)
            for n in dn + fn:
                self.assertFalse(n.endswith(".pyc"))
        for rel in e.PACKAGE_FILES:
            p = os.path.join(dest, rel)
            self.assertTrue(os.path.isfile(p), p)
            self.assertFalse(os.path.islink(p), p)
        man = os.path.join(dest, "MANIFEST.json")
        with open(man, "rb") as f:
            payload = json.loads(f.read().decode())
        self.assertFalse(payload["signed"])
        self.assertEqual(payload["service_cutover"], "NOT-AUTHORIZED")
        self.assertEqual(payload["expected_uid"], 0)
        self.assertIn("journal and rollback bytes never deleted", payload["retention"])

    def test_closure_stdlib_no_userpath_no_kill(self):
        import ast
        e = _load()
        for rel in e.PACKAGE_FILES:
            src = os.path.join(os.path.dirname(os.path.abspath(e.__file__)), rel)
            with open(src, "rb") as f:
                data = f.read()
            self.assertTrue(e._verify_closure_bytes(data, rel))
            tree = ast.parse(data.decode())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        self.assertFalse(a.name.startswith("scripts"))
                if isinstance(node, ast.ImportFrom):
                    self.assertIsNotNone(node.module)
                    self.assertFalse(str(node.module).startswith("scripts"))

    def test_exported_cli_plan_no_root(self):
        e = _load()
        scratch = _home_scratch("cli-")
        dest = os.path.join(scratch, "pkg")
        e.export_cutover_package(dest)
        entry = os.path.join(dest, "cli.py")
        for argv in (["/usr/bin/python3", "-I", entry, "plan"],
                      ["/usr/bin/python3", entry, "plan"]):
            cp = subprocess.run(argv, capture_output=True, text=True, check=False,
                                cwd=scratch, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            self.assertEqual(cp.returncode, 0, cp.stderr)
            data = json.loads(cp.stdout)
            self.assertEqual(data["status"], "manifest-ready")
            self.assertFalse(data["signed"])
            self.assertEqual(data["service_cutover"], "NOT-AUTHORIZED")

    def test_exported_cli_refuses_live(self):
        e = _load()
        scratch = _home_scratch("refuse-")
        dest = os.path.join(scratch, "pkg")
        e.export_cutover_package(dest)
        entry = os.path.join(dest, "cli.py")
        for use_i in (True, False):
            argv = ["/usr/bin/python3"] + (["-I"] if use_i else []) + [entry, "apply"]
            cp = subprocess.run(argv, capture_output=True, text=True, check=False,
                                cwd=scratch, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            self.assertEqual(cp.returncode, 3, (use_i, cp.stdout, cp.stderr))
            argv2 = ["/usr/bin/python3"] + (["-I"] if use_i else []) + [entry, "recover"]
            cp2 = subprocess.run(argv2, capture_output=True, text=True, check=False,
                                 cwd=scratch, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            self.assertEqual(cp2.returncode, 3, (use_i, cp2.stdout, cp2.stderr))

    def test_no_tmp_live_dest_refused(self):
        e = _load()
        with self.assertRaises(ValueError):
            e.export_cutover_package("/tmp/cutover-x")
        for bad in ("/var/lib/hermes-stock-activation/recovery",
                    "/run/hermes-stock-activation",
                    "/home/ubuntu/.hermes/runtime/x",
                    "/etc/foo", "/opt/foo"):
            with self.assertRaises(ValueError, msg=bad):
                e.export_cutover_package(bad)

    def test_exported_preflight_no_git_readonly(self):
        e = _load()
        scratch = _home_scratch("preflight-")
        dest = os.path.join(scratch, "pkg")
        e.export_cutover_package(dest)
        entry = os.path.join(dest, "cli.py")
        self.assertFalse(os.path.lexists(os.path.join(dest, ".git")))
        cp = subprocess.run(["/usr/bin/python3", "-I", entry, "preflight"],
                            capture_output=True, text=True, check=False,
                            cwd=scratch,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertEqual(cp.returncode, 0, (cp.stdout, cp.stderr))
        data = json.loads(cp.stdout)
        self.assertEqual(data["status"], "preflight-complete")
        self.assertFalse(data["signed"])
        self.assertEqual(data["service_cutover"], "NOT-AUTHORIZED")
        self.assertIn("checks", data)
        self.assertIn("python_self", data["checks"])
        # Entry ran under -I: isolated + ignore_environment must be 1.
        self.assertEqual(data["checks"]["python_self"]["isolated"], 1)
        self.assertEqual(data["checks"]["python_self"]["ignore_environment"], 1)

    def test_adversarial_sibling_before_import_not_executed(self):
        e = _load()
        scratch = _home_scratch("advers-")
        dest = os.path.join(scratch, "pkg")
        e.export_cutover_package(dest)
        marker = os.path.join(scratch, "SIBLING_EXECUTED")
        # Overwrite a sibling post-export with code that would write the
        # marker on import. Verification-before-import must refuse BEFORE
        # any import, so the marker must never appear.
        evil = (f"import os\nopen({marker!r}, 'w').write('pwned')\nVALUE = 1\n")
        with open(os.path.join(dest, "cutover_host.py"), "wb") as f:
            f.write(evil.encode())
        entry = os.path.join(dest, "cli.py")
        self.assertFalse(os.path.exists(marker))
        cp = subprocess.run(["/usr/bin/python3", "-I", entry, "preflight"],
                            capture_output=True, text=True, check=False,
                            cwd=scratch,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertNotEqual(cp.returncode, 0, (cp.stdout, cp.stderr))
        self.assertFalse(os.path.exists(marker),
                         "adversarial sibling executed despite hash mismatch")
        # Sanity: clean export has no marker either; plan still works
        # (plan never imports siblings).
        cp2 = subprocess.run(["/usr/bin/python3", "-I", entry, "plan"],
                             capture_output=True, text=True, check=False,
                             cwd=scratch,
                             env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertEqual(cp2.returncode, 0, cp2.stderr)
        self.assertFalse(os.path.exists(marker))

    def test_manifest_parent_commands(self):
        e = _load()
        scratch = _home_scratch("parent-")
        dest = os.path.join(scratch, "pkg")
        e.export_cutover_package(dest)
        with open(os.path.join(dest, "README.parent.md"), "rb") as f:
            readme = f.read().decode()
        self.assertIn("UNSIGNED", readme)
        self.assertIn("must verify REVIEWED", readme)
        self.assertIn("/var/lib/hermes-stock-activation/recovery", readme)
        self.assertIn("0500", readme)
        self.assertIn("0400", readme)
        self.assertIn("--execute-live", readme)
        self.assertIn("/usr/bin/python3 -I /var/lib/hermes-stock-activation/recovery/cli.py plan", readme)
        self.assertIn("/usr/bin/install -d -o 0 -g 0 -m 0500", readme)

    def test_preflight_manifest_trust_not_trusted(self):
        e = _load()
        scratch = _home_scratch("trust-")
        dest = os.path.join(scratch, "pkg")
        e.export_cutover_package(dest)
        entry = os.path.join(dest, "cli.py")
        cp = subprocess.run(["/usr/bin/python3", "-I", entry, "preflight"],
                            capture_output=True, text=True, check=False,
                            cwd=scratch,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertEqual(cp.returncode, 0, (cp.stdout, cp.stderr))
        data = json.loads(cp.stdout)
        self.assertEqual(data["service_cutover"], "NOT-AUTHORIZED")
        self.assertEqual(data.get("manifest_trust"), "self-consistent-only-not-trusted")
        self.assertIn("root_live_enforced", data)
        # Not root in worker, so not enforced, but still NOT-AUTHORIZED.
        self.assertFalse(data["root_live_enforced"])

    def test_verify_o_nofollow_symlink_refused(self):
        import sys as _sys
        _sys.path.insert(0, ".")
        try:
            from scripts.stock_cutover import cli as _cli
            e = _load()
            scratch = _home_scratch("nofollow-")
            dest = os.path.join(scratch, "pkg")
            e.export_cutover_package(dest)
            # Replace sibling with symlink -> must refuse, not follow.
            target = os.path.join(dest, "cutover_host.py")
            os.unlink(target)
            os.symlink("/etc/hostname", target)
            ok, reason, _ = _cli._verify_export_dir(dest)
            self.assertFalse(ok)
            self.assertIn("symlink", reason)
        finally:
            try:
                _sys.path.remove(".")
            except ValueError:
                pass


if __name__ == "__main__":
    unittest.main()
