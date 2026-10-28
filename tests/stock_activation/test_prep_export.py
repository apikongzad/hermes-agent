"""Behavioral prep export tests. Fixture-only, no live reads."""

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest


def run_cmd(argv, cwd=None, env=None):
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, check=False)


def init_repo(repo_dir, files, symlinks=None):
    os.makedirs(repo_dir, exist_ok=True)
    run_cmd(["/usr/bin/git", "init", "-q"], cwd=repo_dir)
    run_cmd(["/usr/bin/git", "config", "user.email", "t@t"], cwd=repo_dir)
    run_cmd(["/usr/bin/git", "config", "user.name", "t"], cwd=repo_dir)
    for rel, content in files.items():
        full = os.path.join(repo_dir, rel)
        os.makedirs(os.path.dirname(full) or repo_dir, exist_ok=True)
        with open(full, "wb") as f:
            f.write(content.encode() if isinstance(content, str) else content)
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


FIXTURE_NONCE = "fixture-nonce-prep-c040"
FINDER_ORIG = "/tmp/finder-orig-prep-c040"
MOUNT_KNOWN = "/run/hermes-stock-activation/known-good-snap"
MOUNT_CAND = "/run/hermes-stock-activation/candidate-snap"


def make_venv(base, home_val=FINDER_ORIG):
    bin_d = os.path.join(base, "bin")
    os.makedirs(bin_d, exist_ok=True)
    for n in ("python", "python3", "python3.14"):
        p = os.path.join(bin_d, n)
        if os.path.lexists(p):
            os.unlink(p)
        os.symlink("/usr/bin/python3.12", p)
    with open(os.path.join(base, "pyvenv.cfg"), "w") as f:
        f.write(f"home = {home_val}\ninclude-system-site-packages = false\nversion = 3.12\n")


def make_interp(base):
    bin_d = os.path.join(base, "bin")
    os.makedirs(bin_d, exist_ok=True)
    with open(os.path.join(bin_d, "python3.14"), "w") as f:
        f.write("fake-interp")
    os.chmod(os.path.join(bin_d, "python3.14"), 0o755)


class RealRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, env=None):
        eff = env if isinstance(env, dict) else {"PATH": "/usr/bin:/bin"}
        self.calls.append((list(argv), dict(eff)))
        return subprocess.run(argv, env=eff, capture_output=True, check=False)


class UnequalRunner:
    def __init__(self):
        self.calls = []
        self.n = 0

    def run(self, argv, env=None):
        self.calls.append(list(argv))
        eff = env if isinstance(env, dict) else {"PATH": "/usr/bin:/bin"}
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
            raise AssertionError("tar must not run on hash mismatch")
        return subprocess.run(argv, env=eff, capture_output=True, check=False)


def build_basic(tmpbase, extra_files=None, with_deps=True, home_val=FINDER_ORIG):
    repo = os.path.join(tmpbase, "repo")
    files = {
        "hermes_cli/main.py": f"print({FIXTURE_NONCE!r})\nprint(__file__)\n",
        "app.conf": f"finder={FINDER_ORIG}\n",
    }
    if extra_files:
        files.update(extra_files)
    sha = init_repo(repo, files)
    venv_src = os.path.join(tmpbase, "venvsrc")
    make_venv(venv_src, home_val=home_val)
    interp_src = os.path.join(tmpbase, "interpsrc")
    make_interp(interp_src)
    deps_src = None
    if with_deps:
        deps_src = os.path.join(tmpbase, "depssrc")
        make_venv(deps_src, home_val=home_val)
    return repo, sha, venv_src, interp_src, deps_src


def make_stage(tmpbase, mode=0o755):
    stage = os.path.join(tmpbase, "stage")
    os.makedirs(stage, exist_ok=True)
    os.chmod(stage, mode)
    return stage


def find_staging_root(stage):
    parent = os.path.join(stage, "staging")
    assert os.path.isdir(parent)
    subs = [os.path.join(parent, n) for n in os.listdir(parent)]
    assert len(subs) >= 1
    # Return the one containing source.
    for s in subs:
        if os.path.isdir(os.path.join(s, "source")):
            return s
    return subs[0]


def list_images(stage):
    out = []
    for n in os.listdir(stage):
        if n.endswith(".squashfs"):
            out.append(os.path.join(stage, n))
    return out


class TestRefusals(unittest.TestCase):
    def test_live_protected_refused_zero_images(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            # Non-existent protected paths must refuse and not be created.
            for protected in (
                "/var/lib/hermes-stock-activation",
                "/run/hermes-stock-activation",
                "/var/lib/hermes-stock-activation/backing/staging/nope-c040",
            ):
                self.assertFalse(os.path.lexists(protected))
                res = export_prep_closure(
                    protected, kind="known-good", source_repo=repo, source_sha=sha,
                    venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                    finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
                )
                self.assertEqual(res["status"], "prep-refused")
                self.assertFalse(res["success"])
                self.assertFalse(os.path.lexists(protected))
            # Existing stage under source_repo is protected (extra_forbidden).
            stage_inside = os.path.join(repo, "stage-inside")
            os.makedirs(stage_inside, exist_ok=True)
            os.chmod(stage_inside, 0o755)
            res = export_prep_closure(
                stage_inside, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-refused")
            self.assertEqual(list_images(stage_inside), [])

    def test_symlink_and_mode_refused(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            real_stage = make_stage(os.path.join(td, "real"))
            link = os.path.join(td, "link-stage")
            os.symlink(real_stage, link)
            res = export_prep_closure(
                link, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-refused")
            # Writable by group/other refused.
            bad = make_stage(os.path.join(td, "bad"), mode=0o777)
            # Ensure actually writable bits set (umask 077 may have cleared? chmod forces).
            os.chmod(bad, 0o777)
            res2 = export_prep_closure(
                bad, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res2["status"], "prep-refused")
            self.assertEqual(list_images(bad), [])

    def test_deps_kind_validation(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            stage = make_stage(os.path.join(td, "s"))
            # known-good without deps refused
            r1 = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=None,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(r1["status"], "prep-refused")
            self.assertFalse(r1["success"])
            # candidate with deps refused
            r2 = export_prep_closure(
                stage, kind="candidate", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_CAND,
            )
            self.assertEqual(r2["status"], "prep-refused")
            self.assertEqual(list_images(stage), [])

    def test_git_hash_mismatch_refuses_before_extract(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            stage = make_stage(os.path.join(td, "s"))
            runner = UnequalRunner()
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN, runner=runner,
            )
            self.assertEqual(res["status"], "prep-refused")
            for c in runner.calls:
                self.assertNotEqual(c[0], "/usr/bin/tar")
            self.assertEqual(list_images(stage), [])


class TestCopyExcludes(unittest.TestCase):
    def test_env_auth_config_not_copied_library_sessions_kept(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            fix = os.path.join(td, "fix")
            repo = os.path.join(fix, "repo")
            files = {
                "hermes_cli/main.py": "print(1)\n",
                "sessions/user-data.txt": "user\n",
            }
            sha = init_repo(repo, files)
            venv_src = os.path.join(fix, "venvsrc")
            make_venv(venv_src)
            # .env / auth / config in venv must be excluded via rsync, not refused.
            with open(os.path.join(venv_src, ".env"), "w") as f:
                f.write("SECRET=1\n")
            with open(os.path.join(venv_src, ".envrc"), "w") as f:
                f.write("x\n")
            # Library sessions path must be preserved.
            lib_sess = os.path.join(venv_src, "lib", "python3.12", "site-packages", "mypkg", "sessions")
            os.makedirs(lib_sess, exist_ok=True)
            with open(os.path.join(lib_sess, "keep.txt"), "w") as f:
                f.write("keep\n")
            # User sessions in venv (not under site-packages) must go.
            user_sess = os.path.join(venv_src, "sessions")
            os.makedirs(user_sess, exist_ok=True)
            with open(os.path.join(user_sess, "drop.txt"), "w") as f:
                f.write("drop\n")
            # Also plant auth/config in venv to ensure rsync excludes them.
            with open(os.path.join(venv_src, "auth.json"), "w") as f:
                f.write("{}")
            with open(os.path.join(venv_src, "config.yaml"), "w") as f:
                f.write("x")
            interp_src = os.path.join(fix, "interpsrc")
            make_interp(interp_src)
            deps_src = os.path.join(fix, "depssrc")
            make_venv(deps_src)
            stage = make_stage(os.path.join(td, "s"))
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-staged")
            sr = find_staging_root(stage)
            # .env, auth, config absent everywhere.
            for dp, dn, fn in os.walk(sr):
                self.assertNotIn(".env", fn)
                self.assertNotIn("auth.json", fn)
                self.assertNotIn("config.yaml", fn)
                self.assertNotIn(".env", dn)
            # User sessions absent.
            self.assertFalse(os.path.exists(os.path.join(sr, "source", "sessions")))
            self.assertFalse(os.path.exists(os.path.join(sr, "venv", "sessions")))
            # Library sessions kept.
            keep = os.path.join(sr, "venv", "lib", "python3.12", "site-packages", "mypkg", "sessions", "keep.txt")
            self.assertTrue(os.path.exists(keep))
            with open(keep) as f:
                self.assertEqual(f.read(), "keep\n")

    def test_pyc_and_pycache_excluded(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            fix = os.path.join(td, "fix")
            repo, sha, venv_src, interp_src, deps_src = build_basic(fix)
            # Plant pycache in venv (rsync excludes) rather than tracked source.
            pcd = os.path.join(venv_src, "lib", "__pycache__")
            os.makedirs(pcd, exist_ok=True)
            with open(os.path.join(pcd, "cached.pyc"), "w") as f:
                f.write("fake")
            with open(os.path.join(venv_src, "mod.pyc"), "w") as f:
                f.write("fake2")
            with open(os.path.join(venv_src, "ok.py"), "w") as f:
                f.write("x=1\n")
            stage = make_stage(os.path.join(td, "s"))
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-staged")
            sr = find_staging_root(stage)
            for dp, dn, fn in os.walk(sr):
                self.assertNotIn("__pycache__", dn)
                for n in fn:
                    self.assertFalse(n.endswith(".pyc"), msg=os.path.join(dp, n))
            self.assertTrue(os.path.exists(os.path.join(sr, "venv", "ok.py")))


class TestRewrites(unittest.TestCase):
    def test_python_symlinks_and_pyvenv(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            stage = make_stage(os.path.join(td, "s"))
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-staged")
            sr = find_staging_root(stage)
            for base in ("venv", "deps"):
                for n in ("python", "python3", "python3.14"):
                    link = os.path.join(sr, base, "bin", n)
                    self.assertTrue(os.path.islink(link), msg=link)
                    self.assertEqual(os.readlink(link), "../../interpreter/bin/python3.14")
            for base in ("venv", "deps"):
                cfg = os.path.join(sr, base, "pyvenv.cfg")
                with open(cfg) as f:
                    txt = f.read()
                self.assertIn(MOUNT_KNOWN + "/interpreter/bin", txt)
                self.assertNotIn(sr, txt)
                self.assertNotIn(FINDER_ORIG, txt)

    def test_finder_rewritten_only_in_targets(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            extra = {
                "__editable___hermes_agent_0_0_0_finder.py": f"p = '{FINDER_ORIG}/x'\n",
                "pkg/mod.pth": f"{FINDER_ORIG}/site\n",
                "hermes_agent-0.0.0.dist-info/direct_url.json": f'{{"url": "file://{FINDER_ORIG}"}}\n',
                "other.conf": f"still {FINDER_ORIG} here\n",
            }
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"), extra_files=extra)
            stage = make_stage(os.path.join(td, "s"))
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-staged")
            sr = find_staging_root(stage)
            mount_src = MOUNT_KNOWN + "/source"
            for rel in (
                "__editable___hermes_agent_0_0_0_finder.py",
                "pkg/mod.pth",
                "hermes_agent-0.0.0.dist-info/direct_url.json",
            ):
                with open(os.path.join(sr, "source", rel), "rb") as f:
                    data = f.read()
                self.assertIn(mount_src.encode(), data)
                self.assertNotIn(FINDER_ORIG.encode(), data)
            with open(os.path.join(sr, "source", "other.conf"), "rb") as f:
                other = f.read()
            self.assertIn(FINDER_ORIG.encode(), other)
            self.assertNotIn(mount_src.encode(), other)

    def test_so_residual_gate(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            extra = {
                "lib/fake.so": "binary \x00 /home/ubuntu/secret-blob-c040 \x00 end\n",
                "__editable___hermes_agent_0_0_0_finder.py": f"p='{FINDER_ORIG}'\n",
            }
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"), extra_files=extra)
            stage = make_stage(os.path.join(td, "s"))
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-staged")
            self.assertEqual(res["design_absolute_gate"], "residual-embedded")
            self.assertTrue(len(res["residual_embedded_paths"]) >= 1)
            joined = "\n".join(res["residual_embedded_paths"])
            self.assertIn("fake.so", joined)
            sr = find_staging_root(stage)
            with open(os.path.join(sr, "source", "lib", "fake.so"), "rb") as f:
                data = f.read()
            self.assertIn(b"/home/ubuntu", data)


class TestArgvAndImages(unittest.TestCase):
    def test_mksquashfs_argv_and_outputs(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            stage = make_stage(os.path.join(td, "s"))
            runner = RealRunner()
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN, runner=runner,
            )
            self.assertEqual(res["status"], "prep-staged")
            # Find mksquashfs call.
            mk = [c for c, e in runner.calls if os.path.basename(c[0]) == "mksquashfs"]
            self.assertEqual(len(mk), 1)
            argv = mk[0]
            # Recorded vector must be exact.
            self.assertEqual(argv[0], "/usr/bin/mksquashfs")
            self.assertEqual(argv[3:], ["-comp", "xz", "-b", "131072", "-reproducible", "-mkfs-time", "0", "-all-root", "-no-xattrs", "-no-hardlinks", "-no-exports", "-no-recovery", "-no-progress", "-noappend"])
            staged = argv[1]
            image_tmp = argv[2]
            self.assertTrue(staged.startswith(stage + "/"))
            self.assertTrue(image_tmp.startswith(stage + "/"))
            self.assertEqual(os.path.dirname(image_tmp), stage)
            self.assertNotIn("/var/lib", " ".join(argv))
            # Output stays under stage_root.
            for c, e in runner.calls:
                for a in c[1:]:
                    if a.startswith("--output="):
                        out = a[len("--output="):]
                        self.assertTrue(out.startswith(stage + "/"))
                # git/tar/rsync/mksquashfs/unsquashfs env PATH only.
                if os.path.basename(c[0]) in ("git", "tar", "rsync", "mksquashfs", "unsquashfs"):
                    self.assertIn("PATH", e)
                    # No GIT_* leaking except explicit GIT_CONFIG on git.
                    for k in e:
                        if k.startswith("GIT_") and os.path.basename(c[0]) != "git":
                            self.fail(f"GIT env on non-git: {k}")
            # No forbidden basenames.
            for c, e in runner.calls:
                base = os.path.basename(c[0])
                self.assertNotIn(base, ("sudo", "mount", "umount", "losetup", "systemctl", "install"))
            # Image and prep.json exist under stage.
            self.assertTrue(os.path.exists(res["image_path"]))
            self.assertTrue(res["image_path"].startswith(stage + "/"))
            self.assertTrue(os.path.exists(res["digest_file"]))
            self.assertEqual(stat.S_IMODE(os.lstat(res["digest_file"]).st_mode), 0o644)
            # Flags.
            self.assertFalse(res["signed"])
            self.assertFalse(res["live_published"])
            self.assertFalse(res["kernel_immutable"])
            self.assertFalse(res["mount_executed"])
            self.assertEqual(res["activation"], "UNEXECUTED")

    def test_tiny_roundtrip_if_available(self):
        import shutil as _sh
        if not os.path.exists("/usr/bin/mksquashfs"):
            self.skipTest("no mksquashfs")
        with tempfile.TemporaryDirectory() as td:
            staged = os.path.join(td, "staged")
            os.makedirs(os.path.join(staged, "source"))
            with open(os.path.join(staged, "source", "a.txt"), "w") as f:
                f.write("hi-c040\n")
            img = os.path.join(td, "img.squashfs")
            argv = ["/usr/bin/mksquashfs", staged, img, "-comp", "xz", "-b", "131072", "-reproducible", "-mkfs-time", "0", "-all-root", "-no-xattrs", "-no-hardlinks", "-no-exports", "-no-recovery", "-no-progress", "-noappend"]
            r = subprocess.run(argv, capture_output=True, check=False)
            self.assertEqual(r.returncode, 0, r.stderr.decode()[:1000])
            dest = os.path.join(td, "verify")
            r2 = subprocess.run(["/usr/bin/unsquashfs", "-no-xattrs", "-d", dest, img], capture_output=True, check=False)
            self.assertEqual(r2.returncode, 0, r2.stderr.decode()[:1000])
            with open(os.path.join(dest, "source", "a.txt")) as f:
                self.assertEqual(f.read(), "hi-c040\n")


class TestContracts(unittest.TestCase):
    def test_export_closure_stub_and_cli(self):
        from scripts.stock_activation.os_adapter import export_closure
        res = export_closure()
        self.assertEqual(res, {"status": "CLOSURE_ENUMERATION_UNSPECIFIED", "copied": 0, "git_invoked": False})
        res2 = export_closure("/ignored/path")
        self.assertEqual(res2, res)
        from scripts.stock_activation.cli import main
        self.assertEqual(main(["apply"]), 2)
        self.assertEqual(main([]), 2)
        self.assertEqual(main(["--self-check", "extra"]), 0)


if __name__ == "__main__":
    unittest.main()
