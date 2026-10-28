"""Portable proof package exporter tests. Home scratch only, no /tmp.

All temp dirs are created under HOME (user scratch), never /tmp.
No sudo/install/mount/service ops. No .env read.
"""
import ast
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
    assert isinstance(home, str) and os.path.isabs(home), home
    # Never /tmp.
    assert not home.startswith("/tmp"), home
    base = os.path.join(home, "proof-pkg-tests")
    os.makedirs(base, mode=0o700, exist_ok=True)
    d = tempfile.mkdtemp(prefix=prefix, dir=base)
    assert os.path.isabs(d)
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


def _load_exporter():
    from scripts.stock_activation import proof_package as e
    return e


def _snapshot_live_path(path):
    """Read-only snapshot without opening private content.

    Only lstat(target) + listdir(parent). Permission-denied is recorded
    explicitly as unknown-permission, not as absent.
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


class ProofPackageTests(unittest.TestCase):
    def test_export_creates_no_git_manifest_modes(self):
        e = _load_exporter()
        scratch = _home_scratch("export-")
        dest = os.path.join(scratch, "pkg")
        res = e.export_proof_package(dest)
        self.assertEqual(res["status"], "proof-exported")
        self.assertTrue(res["success"])
        self.assertFalse(res["signed"])
        self.assertEqual(res["activation"], "UNEXECUTED")
        self.assertEqual(res["install_prefix"], "/var/lib/hermes-stock-activation/recovery")
        # No .git anywhere.
        for dp, dn, fn in os.walk(dest, followlinks=False):
            self.assertNotIn(".git", dn)
            self.assertNotIn(".git", fn)
            for n in dn + fn:
                self.assertFalse(n.endswith(".pyc"))
        # Files exist.
        entry = os.path.join(dest, "operator_proof.py")
        man = os.path.join(dest, "MANIFEST.json")
        readme = os.path.join(dest, "README.parent.md")
        for p in (entry, man, readme):
            self.assertTrue(os.path.isfile(p), p)
            self.assertFalse(os.path.islink(p), p)
        # Source verbatim.
        src = os.path.join(os.path.dirname(os.path.abspath(e.__file__)), "operator_proof.py")
        with open(src, "rb") as f:
            src_bytes = f.read()
        with open(entry, "rb") as f:
            got = f.read()
        self.assertEqual(got, src_bytes)
        self.assertEqual(res["entry_sha256"], hashlib.sha256(src_bytes).hexdigest())
        # Manifest external: hashes match, signed false.
        with open(man, "rb") as f:
            payload = json.loads(f.read().decode("utf-8"))
        self.assertFalse(payload["signed"])
        self.assertEqual(payload["install_prefix"], "/var/lib/hermes-stock-activation/recovery")
        self.assertEqual(payload["expected_uid"], 0)
        self.assertEqual(payload["expected_gid"], 0)
        self.assertEqual(payload["expected_dir_mode"], "0500")
        by_rel = {x["rel"]: x for x in payload["files"]}
        self.assertEqual(by_rel["operator_proof.py"]["mode"], "0500")
        self.assertEqual(by_rel["operator_proof.py"]["sha256"], res["entry_sha256"])
        self.assertEqual(by_rel["README.parent.md"]["mode"], "0400")
        # manifest text canonical.
        self.assertIn("operator_proof.py file 0500", payload["manifest"])
        self.assertEqual(payload["manifest_sha256"], res["manifest_sha256"])
        self.assertEqual(payload["manifest_sha256"], hashlib.sha256(payload["manifest"].encode()).hexdigest())
        self.assertEqual(payload["template_sha256"], res["template_sha256"])
        self.assertEqual(payload["source_sha256"], res["entry_sha256"])

    def test_closure_stdlib_only_refuses_mutable(self):
        e = _load_exporter()
        with self.assertRaises(ValueError):
            e._verify_closure_bytes(b"import scripts.stock_activation.host\n")
        with self.assertRaises(ValueError):
            e._verify_closure_bytes(b"from scripts.stock_activation import host\n")
        with self.assertRaises(ValueError):
            e._verify_closure_bytes(b"from . import host\n")
        # Allowed stdlib passes.
        e._verify_closure_bytes(b"import os\nimport sys\n")
        # Real source passes.
        src = os.path.join(os.path.dirname(os.path.abspath(e.__file__)), "operator_proof.py")
        with open(src, "rb") as f:
            data = f.read()
        self.assertTrue(e._verify_closure_bytes(data))
        # AST check: no scripts imports.
        tree = ast.parse(data.decode("utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertFalse(a.name.startswith("scripts"))
            if isinstance(node, ast.ImportFrom):
                self.assertIsNotNone(node.module)
                self.assertFalse(str(node.module).startswith("scripts"))

    def test_exported_cli_plan_deterministic_no_root(self):
        e = _load_exporter()
        scratch = _home_scratch("cli-")
        dest = os.path.join(scratch, "pkg")
        res = e.export_proof_package(dest)
        entry = res["entry"]
        # plan with no records: deterministic manifest-refused, exit 0.
        for argv in (["/usr/bin/python3", "-I", entry, "plan"],
                     ["/usr/bin/python3", entry, "plan"]):
            cp = subprocess.run(argv, capture_output=True, text=True, check=False,
                                cwd=scratch, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            self.assertEqual(cp.returncode, 0, cp.stderr)
            data = json.loads(cp.stdout)
            self.assertEqual(data["status"], "manifest-refused")
            self.assertFalse(data["manifest"]["signed"])
            self.assertEqual(data["manifest"]["activation"], "UNEXECUTED")
            for g in data["manifest"]["gates"].values():
                self.assertEqual(g, "UNEXECUTED")
        # plan with two dummy images (home scratch, small bytes).
        img1 = os.path.join(scratch, "a.squashfs")
        img2 = os.path.join(scratch, "b.squashfs")
        with open(img1, "wb") as f:
            f.write(b"img-one")
        with open(img2, "wb") as f:
            f.write(b"img-two")
        h1 = _sha_file(img1)
        h2 = _sha_file(img2)
        prep1 = os.path.join(scratch, "a.prep.json")
        prep2 = os.path.join(scratch, "b.prep.json")
        for p in (prep1, prep2):
            with open(p, "w") as f:
                f.write("{}")
        argv = ["/usr/bin/python3", "-I", entry, "plan",
                "--prep", prep1, "--image", img1, "--expected-sha", h1, "--kind", "known-good", "--port", "9120",
                "--prep", prep2, "--image", img2, "--expected-sha", h2, "--kind", "candidate", "--port", "9121"]
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        cp = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=scratch, env=env)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        data = json.loads(cp.stdout)
        self.assertEqual(data["status"], "manifest-ready", cp.stdout[:2000])
        self.assertFalse(data["manifest"]["signed"])
        self.assertEqual(data["manifest"]["activation"], "UNEXECUTED")
        self.assertEqual(data["manifest"]["service_cutover"], "NOT_AUTHORIZED")
        for c in data["commands"]:
            joined = " ".join(c)
            self.assertNotIn("systemctl", joined)
            self.assertNotIn("sudo", joined)
            # git must not appear as command (GIT_CONFIG_* env is ok, but no git argv).
            self.assertFalse(c[0].endswith("/git") and "archive" in joined)
            self.assertNotIn("/opt", joined)
        # -I present in proof argv.
        found_i = any("-I" in c for c in data["commands"])
        self.assertTrue(found_i)

    def test_exported_cli_refuses_live_deterministic(self):
        e = _load_exporter()
        # Live may pre-exist from prior reviewed proof. Never delete live;
        # snapshot metadata/state and prove unchanged. Fresh (absence) is
        # covered by isolated home-scratch export, not by asserting absence
        # of real authority paths. No private content opened.
        live_paths = (
            "/var/lib/hermes-stock-activation",
            "/run/hermes-stock-activation",
        )
        before = {p: _snapshot_live_path(p) for p in live_paths}
        scratch = _home_scratch("refuse-")
        dest = os.path.join(scratch, "pkg")
        # Isolated fresh fixture: dest must not pre-exist in home scratch.
        self.assertFalse(os.path.lexists(dest))
        res = e.export_proof_package(dest)
        entry = res["entry"]
        for use_i in (True, False):
            argv = ["/usr/bin/python3"]
            if use_i:
                argv.append("-I")
            argv += [entry, "apply"]
            cp = subprocess.run(argv, capture_output=True, text=True, check=False,
                                cwd=scratch, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            self.assertEqual(cp.returncode, 3, (use_i, cp.stdout, cp.stderr))
            argv2 = ["/usr/bin/python3"]
            if use_i:
                argv2.append("-I")
            argv2 += [entry, "recover", "/x"]
            cp2 = subprocess.run(argv2, capture_output=True, text=True, check=False,
                                 cwd=scratch, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            self.assertEqual(cp2.returncode, 3, (use_i, cp2.stdout, cp2.stderr))
        # Must not have mutated live paths (refusal leaves state identical).
        after = {p: _snapshot_live_path(p) for p in live_paths}
        for p in live_paths:
            self.assertEqual(before[p], after[p], msg=f"live mutated: {p}")

    def test_imports_bind_package_dir_pythonpath_isolation(self):
        e = _load_exporter()
        scratch = _home_scratch("bind-")
        dest = os.path.join(scratch, "pkg")
        res = e.export_proof_package(dest)
        entry = res["entry"]
        # Evil dir with shadowing operator_proof.py and json.py.
        evil = os.path.join(scratch, "evil")
        os.makedirs(evil, exist_ok=True)
        with open(os.path.join(evil, "operator_proof.py"), "w") as f:
            f.write("MARKER_EVIL = True\n")
        with open(os.path.join(evil, "json.py"), "w") as f:
            f.write("raise ImportError('evil json')\n")
        # With -I, PYTHONPATH is ignored: plan still works, __file__ binds to export.
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "PYTHONPATH": evil}
        cp = subprocess.run(["/usr/bin/python3", "-I", entry, "plan"],
                            capture_output=True, text=True, check=False, cwd=scratch, env=env)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        data = json.loads(cp.stdout)
        self.assertEqual(data["status"], "manifest-refused")
        # __file__ binds to package directory even with evil PYTHONPATH.
        probe = (
            "import importlib.util as _u, sys as _s;"
            f"_s.path = [p for p in _s.path if p not in ('', {evil!r})];"
            f"spec=_u.spec_from_file_location('exported_op', {entry!r});"
            "m=_u.module_from_spec(spec);spec.loader.exec_module(m);"
            "print(m.__file__)"
        )
        cp2 = subprocess.run(["/usr/bin/python3", "-I", "-c", probe],
                             capture_output=True, text=True, check=False, cwd=scratch, env=env)
        self.assertEqual(cp2.returncode, 0, cp2.stderr)
        self.assertEqual(cp2.stdout.strip(), entry)
        self.assertTrue(cp2.stdout.strip().startswith(dest + "/"))
        self.assertNotIn(evil, cp2.stdout.strip())
        # Script handling: run as script path with -I works (already covered),
        # and package file location via runpy also works.
        runpy_prog = f"import runpy,sys; sys.argv=[{entry!r},'plan']; runpy.run_path({entry!r}, run_name='__main__')"
        cp3 = subprocess.run(["/usr/bin/python3", "-I", "-c",
                              runpy_prog],
                             capture_output=True, text=True, check=False, cwd=scratch, env=env)
        # runpy path prints JSON to stdout; exit 0 via SystemExit(0)? main returns 0 but runpy doesn't exit.
        # At least it must not import evil and must not crash.
        self.assertEqual(cp3.returncode, 0, cp3.stderr)
        self.assertIn("manifest-refused", cp3.stdout)

    def test_manifest_unsigned_no_trust_parent_commands(self):
        e = _load_exporter()
        scratch = _home_scratch("parent-")
        dest = os.path.join(scratch, "pkg")
        e.export_proof_package(dest)
        with open(os.path.join(dest, "MANIFEST.json"), "rb") as f:
            payload = json.loads(f.read().decode("utf-8"))
        self.assertFalse(payload["signed"])
        with open(os.path.join(dest, "README.parent.md"), "rb") as f:
            readme = f.read().decode("utf-8")
        # Must state unsigned self-hash provides no trust.
        self.assertIn("UNSIGNED", readme)
        self.assertIn("provides NO trust", readme)
        self.assertIn("must verify REVIEWED", readme)
        self.assertIn("signed=false", readme.lower().replace(" ", ""))
        # Must contain verified image paths + digests (exact strings from exporter).
        self.assertIn(e.KNOWN_GOOD_IMAGE, readme)
        self.assertIn(e.KNOWN_GOOD_SHA, readme)
        self.assertIn(e.CANDIDATE_IMAGE, readme)
        self.assertIn(e.CANDIDATE_SHA, readme)
        self.assertIn(e.KNOWN_GOOD_PREP, readme)
        self.assertIn(e.CANDIDATE_PREP, readme)
        # Must contain exact parent install prefix + modes.
        self.assertIn("/var/lib/hermes-stock-activation/recovery", readme)
        self.assertIn("0500", readme)
        self.assertIn("0400", readme)
        # Must contain actual CLI flags inspected (not invented).
        for flag in ("--prep", "--image", "--expected-sha", "--kind", "--port", "--execute-live"):
            self.assertIn(flag, readme)
        # Must use python -I with absolute recovery path.
        self.assertIn("/usr/bin/python3 -I /var/lib/hermes-stock-activation/recovery/operator_proof.py plan", readme)
        # Must document refusal ports and deterministic gates.
        self.assertIn("9120", readme)
        self.assertIn("9121", readme)
        # Must use /usr/bin/install with -o 0 -g 0 (actual recorded vector style).
        self.assertIn("/usr/bin/install -d -o 0 -g 0 -m 0500", readme)
        # Must not authorize live execution.
        self.assertIn("does not", readme)
        self.assertIn("NOT part of this export", readme)

    def test_no_tmp_and_live_dest_refused(self):
        e = _load_exporter()
        # /tmp dest refused.
        with self.assertRaises(ValueError):
            e.export_proof_package("/tmp/proof-pkg-x")
        # Live dests refused.
        for bad in ("/var/lib/hermes-stock-activation/recovery",
                    "/run/hermes-stock-activation",
                    "/home/ubuntu/.hermes/runtime/x",
                    "/etc/foo",
                    "/opt/foo"):
            with self.assertRaises(ValueError, msg=bad):
                e.export_proof_package(bad)
        # Home scratch accepted (already covered); ensure not /tmp.
        scratch = _home_scratch("notmp-")
        self.assertFalse(os.path.normpath(scratch).startswith("/tmp"))
        dest = os.path.join(scratch, "pkg")
        self.assertFalse(os.path.normpath(dest).startswith("/tmp"))
        res = e.export_proof_package(dest)
        self.assertFalse(os.path.normpath(res["dest_dir"]).startswith("/tmp"))

    def test_source_template_hashes_external(self):
        e = _load_exporter()
        scratch = _home_scratch("hashes-")
        dest = os.path.join(scratch, "pkg")
        res = e.export_proof_package(dest)
        src = os.path.join(os.path.dirname(os.path.abspath(e.__file__)), "operator_proof.py")
        with open(src, "rb") as f:
            src_bytes = f.read()
        self.assertEqual(hashlib.sha256(src_bytes).hexdigest(), res["entry_sha256"])
        with open(os.path.join(dest, "MANIFEST.json"), "rb") as f:
            payload = json.loads(f.read().decode("utf-8"))
        self.assertEqual(payload["source_sha256"], res["entry_sha256"])
        self.assertEqual(payload["template_sha256"], res["template_sha256"])
        # Template hash is stable placeholder-based (not filled copy).
        self.assertEqual(res["template_sha256"], e._readme_template_hash())
        # Manifest text hash matches.
        self.assertEqual(hashlib.sha256(payload["manifest"].encode()).hexdigest(),
                         payload["manifest_sha256"])


if __name__ == "__main__":
    unittest.main()
