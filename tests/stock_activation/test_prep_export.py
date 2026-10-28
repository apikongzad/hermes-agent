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


class _RefuseRunner:
    """Injected backend that must never be called for refused stages."""

    def __init__(self):
        self.calls = []

    def run(self, argv, env=None):
        self.calls.append(list(argv))
        raise AssertionError("backend must not run for refused stage")


class TestRefusals(unittest.TestCase):
    def test_live_protected_refused_zero_images(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            # Live may pre-exist from prior reviewed proof. Never delete live;
            # snapshot metadata/state and prove unchanged before/after.
            # Fresh (absence) is covered by isolated missing-stage fixture
            # below, not by asserting absence of real authority paths.
            # Injected backend must stay unused for refused stages.
            for protected in (
                "/var/lib/hermes-stock-activation",
                "/run/hermes-stock-activation",
                "/var/lib/hermes-stock-activation/backing/staging/nope-c040",
            ):
                before = _snapshot_live_path(protected)
                runner = _RefuseRunner()
                res = export_prep_closure(
                    protected, kind="known-good", source_repo=repo, source_sha=sha,
                    venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                    finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
                    runner=runner,
                )
                self.assertEqual(res["status"], "prep-refused")
                self.assertFalse(res["success"])
                self.assertIsNone(res["image_path"])
                self.assertIsNone(res["image_sha256"])
                self.assertEqual(runner.calls, [])
                after = _snapshot_live_path(protected)
                self.assertEqual(before, after, msg=f"live mutated: {protected}")
            # Isolated absence fixture: non-existent temp stage must refuse
            # and not be created (fresh case without real authority).
            missing = os.path.join(td, "missing-stage-c040")
            self.assertFalse(os.path.lexists(missing))
            runner2 = _RefuseRunner()
            res_missing = export_prep_closure(
                missing, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
                runner=runner2,
            )
            self.assertEqual(res_missing["status"], "prep-refused")
            self.assertFalse(res_missing["success"])
            self.assertFalse(os.path.lexists(missing))
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


class TestWebDistVerifyRealNode(unittest.TestCase):
    def test_verify_with_real_node(self):
        import shutil
        from scripts.stock_activation.prep_export import _verify_web_dist_with_node
        node = shutil.which("node")
        self.assertIsNotNone(node)
        # _find_node probes /opt/node24/bin etc via os.path.exists; those metadata
        # checks only pass home_io_guard when their dir is on PATH (guard allows
        # PATH-entry stats, then realpath would otherwise trip on the hermes
        # tools symlink). Prepend real node dirs so verification uses real node.
        _orig_path = os.environ.get("PATH", "")
        _extra = os.pathsep.join([os.path.dirname(node), "/opt/node24/bin", "/opt/node/bin", "/usr/bin"])
        os.environ["PATH"] = _extra + os.pathsep + _orig_path
        try:
            with tempfile.TemporaryDirectory() as td:
                src = os.path.join(td, "src")
                os.makedirs(os.path.join(src, "scripts", "build"))
                repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
                # Copy worktree freshness (do not edit) + its import dep so sourceHash can import.
                shutil.copy(
                    os.path.join(repo_root, "scripts", "build", "freshness.mjs"),
                    os.path.join(src, "scripts", "build", "freshness.mjs"),
                )
                shutil.copy(
                    os.path.join(repo_root, "scripts", "build", "frontend-common.mjs"),
                    os.path.join(src, "scripts", "build", "frontend-common.mjs"),
                )
                # Minimal web inputs so sourceHash covers real files (missing also deterministic).
                for p in ("web", "apps/shared"):
                    d = os.path.join(src, p)
                    os.makedirs(d, exist_ok=True)
                    with open(os.path.join(d, "dummy.txt"), "w") as f:
                        f.write("dummy\n")
                for rel, content in (
                    ("package.json", "{}"),
                    ("package-lock.json", "{}"),
                    (".npmrc", "x\n"),
                    ("pm/lock.json", "{}"),
                    ("scripts/generate-icons.mjs", "x\n"),
                    ("scripts/generate_icons.py", "x\n"),
                    ("assets/dummy.txt", "dummy\n"),
                    ("pyproject.toml", "x\n"),
                    ("uv.lock", "x\n"),
                ):
                    full = os.path.join(src, rel)
                    os.makedirs(os.path.dirname(full) or src, exist_ok=True)
                    if not os.path.exists(full):
                        with open(full, "w") as f:
                            f.write(content)
                dist = os.path.join(td, "dist")
                os.makedirs(dist)
                with open(os.path.join(dist, "index.html"), "w") as f:
                    f.write("<html>hi-c040</html>\n")
                with open(os.path.join(dist, "app.js"), "w") as f:
                    f.write("console.log(1)\n")
                # sourceHash via node importing the copied freshness.mjs (same way freshness does).
                src_js = os.path.join(td, "calc-source.mjs")
                with open(src_js, "w") as f:
                    f.write(
                        "import {join} from 'node:path';\n"
                        "const src = process.argv[2];\n"
                        "const mod = await import('file://' + join(src, 'scripts/build/freshness.mjs'));\n"
                        "console.log(mod.sourceHash(src, 'web'));\n"
                    )
                r = subprocess.run([node, src_js, src], capture_output=True, text=True, check=False)
                self.assertEqual(r.returncode, 0, r.stderr[:2000])
                source_hash = r.stdout.strip()
                self.assertTrue(len(source_hash) == 64)
                # outputHash via node with freshness-identical treeHash (same skip/contents/walk).
                out_js = os.path.join(td, "calc-output.mjs")
                with open(out_js, "w") as f:
                    f.write(
                        "import {createHash} from 'node:crypto';\n"
                        "import {existsSync, readFileSync, readdirSync, statSync} from 'node:fs';\n"
                        "import {join} from 'node:path';\n"
                        "const out = process.argv[2];\n"
                        "const receiptName='hermes-build.json';\n"
                        "const osMetadata = name => {\n"
                        "  const base = name.split('/').pop()\n"
                        "  return base === '.DS_Store' || base === '.localized'\n"
                        "    || base === 'Thumbs.db' || base === 'Desktop.ini' || base.startsWith('._')\n"
                        "};\n"
                        "function skipOut(name){ return name===receiptName || name==='.hermes-product'; }\n"
                        "function contents(name){ return !name.split('/').includes('node_modules') && !name.startsWith('native/'); }\n"
                        "function walkTree(root, inputs, skip, onEntry) {\n"
                        "  function visit(name) {\n"
                        "    if (osMetadata(name) || skip(name)) return\n"
                        "    const file = join(root, name)\n"
                        "    if (!existsSync(file)) return onEntry(name, 'missing')\n"
                        "    if (!statSync(file).isDirectory()) return onEntry(name, 'file')\n"
                        "    onEntry(name, 'directory')\n"
                        "    for (const child of readdirSync(file).sort()) visit(`${name}/${child}`)\n"
                        "  }\n"
                        "  for (const input of inputs) visit(input)\n"
                        "}\n"
                        "function treeHash(root, inputs, skip, contentsFn = () => true) {\n"
                        "  const hash = createHash('sha256')\n"
                        "  walkTree(root, inputs, skip, (name, kind) => {\n"
                        "    hash.update(name.replaceAll('\\\\', '/')).update('\\0')\n"
                        "    if (kind === 'file') hash.update(contentsFn(name) ? readFileSync(join(root, name)) : 'file').update('\\0')\n"
                        "    else hash.update(`${kind}\\0`)\n"
                        "  })\n"
                        "  return hash.digest('hex')\n"
                        "}\n"
                        "console.log(treeHash(out, readdirSync(out).sort(), skipOut, contents));\n"
                    )
                r2 = subprocess.run([node, out_js, dist], capture_output=True, text=True, check=False)
                self.assertEqual(r2.returncode, 0, r2.stderr[:2000])
                output_hash = r2.stdout.strip()
                self.assertTrue(len(output_hash) == 64)
                receipt = {"schema": 1, "product": "web", "inputs": {"sourceHash": source_hash}, "outputHash": output_hash}
                with open(os.path.join(dist, "hermes-build.json"), "w") as f:
                    f.write(json.dumps(receipt) + "\n")
                self.assertTrue(_verify_web_dist_with_node(src, dist))
                # One-byte dist tamper must fail closed.
                with open(os.path.join(dist, "app.js"), "ab") as f:
                    f.write(b"x")
                self.assertFalse(_verify_web_dist_with_node(src, dist))
        finally:
            os.environ["PATH"] = _orig_path


class TestDeniedArchiveExclusion(unittest.TestCase):
    def test_tracked_envrc_authjson_excluded_not_refused(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            fix = os.path.join(td, "fix")
            repo = os.path.join(fix, "repo")
            files = {
                "hermes_cli/main.py": f"print({FIXTURE_NONCE!r})\n",
                ".envrc": "export FIXTURE_C040=1\n",
                "auth.json": '{"token": "fixture"}\n',
                "nested/config.yaml": "x: 1\n",
                "nested/.env": "SECRET=1\n",
            }
            sha = init_repo(repo, files)
            venv_src = os.path.join(fix, "venvsrc")
            make_venv(venv_src)
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
            for rel in (".envrc", "auth.json", "nested/config.yaml", "nested/.env"):
                self.assertFalse(os.path.lexists(os.path.join(sr, "source", rel)), msg=rel)
            excl = res.get("excluded_denylist", [])
            self.assertEqual(excl, sorted(excl))
            self.assertTrue(any(p.endswith(".envrc") for p in excl), msg=str(excl))
            self.assertTrue(any(p.endswith("auth.json") for p in excl), msg=str(excl))
            self.assertTrue(any(p.endswith("config.yaml") for p in excl), msg=str(excl))
            # venv fifo must still be tested separately; source itself is clean here.

    def test_fifo_in_venv_still_refuses(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            os.mkfifo(os.path.join(venv_src, "fifo-c040"))
            stage = make_stage(os.path.join(td, "s"))
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-refused")
            self.assertEqual(list_images(stage), [])


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


class TestImageModes(unittest.TestCase):
    """Canonical mode contract: service uid 1001 must traverse/read while immutable.

    Root cause: staging preserved 0700/0600/0711 via rsync -a; mksquashfs
    -all-root fixes ownership only, not modes, so squashfs-root blocked uid
    1001 (EACCES 13, not EROFS 30). Fix normalizes in user staging before
    manifest+SquashFS: dirs 0555, files 0444 (non-exec) / 0555 (exec, based
    on actual x bits), no writable bits. Fixture-only, no live/mount/sudo.
    """

    def _make_restrictive(self, venv_src):
        # Simulate real 0700 home tree: dirs 0700, files 0600, exec 0711.
        for dp, dn, fn in os.walk(venv_src, followlinks=False):
            try:
                os.chmod(dp, 0o700)
            except OSError:
                pass
            for n in fn:
                fp = os.path.join(dp, n)
                try:
                    st = os.lstat(fp)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue
                try:
                    if st.st_mode & 0o111:
                        os.chmod(fp, 0o711)
                    else:
                        os.chmod(fp, 0o600)
                except OSError:
                    pass

    def _assert_canonical_tree(self, root):
        for dp, dn, fn in os.walk(root, followlinks=False):
            st = os.lstat(dp)
            if not stat.S_ISLNK(st.st_mode):
                mode = stat.S_IMODE(st.st_mode)
                self.assertEqual(mode, 0o555, msg=f"dir {dp} mode {oct(mode)}")
                self.assertEqual(mode & 0o222, 0, msg=f"dir writable {dp}")
                self.assertEqual(mode & 0o444, 0o444, msg=f"dir not readable {dp}")
                self.assertEqual(mode & 0o111, 0o111, msg=f"dir not traversable {dp}")
            for n in fn:
                fp = os.path.join(dp, n)
                try:
                    st = os.lstat(fp)
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                mode = stat.S_IMODE(st.st_mode)
                self.assertIn(mode, (0o444, 0o555), msg=f"file {fp} mode {oct(mode)}")
                self.assertEqual(mode & 0o222, 0, msg=f"file writable {fp}")
                self.assertEqual(mode & 0o444, 0o444, msg=f"file not readable {fp}")

    def _parse_manifest(self, text):
        entries = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            parts = line.split(None, 4)
            self.assertEqual(len(parts), 5, msg=f"manifest must be 5-field rel typ mode sha target: {raw!r}")
            rel, typ, mode, sha, target = parts
            entries.append((rel, typ, mode, sha, target))
        return entries

    def test_dirs_555_files_444_no_writable(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            self._make_restrictive(venv_src)
            self._make_restrictive(deps_src)
            stage = make_stage(os.path.join(td, "s"))
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-staged")
            self.assertFalse(res["signed"])
            self.assertFalse(res["live_published"])
            self.assertFalse(res["kernel_immutable"])
            self.assertEqual(res["activation"], "UNEXECUTED")
            sr = find_staging_root(stage)
            self._assert_canonical_tree(sr)
            # No legacy restrictive modes remain.
            for dp, dn, fn in os.walk(sr, followlinks=False):
                for n in fn:
                    fp = os.path.join(dp, n)
                    try:
                        st = os.lstat(fp)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISLNK(st.st_mode):
                        continue
                    mode = stat.S_IMODE(st.st_mode)
                    self.assertNotIn(mode, (0o700, 0o600, 0o711, 0o755, 0o644),
                                     msg=f"legacy mode remains {fp} {oct(mode)}")

    def test_exec_preserved_not_blanket_stripped(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            fix = os.path.join(td, "fix")
            repo, sha, venv_src, interp_src, deps_src = build_basic(fix)
            # Executable script (0755) and fake lib .so (0755) must stay exec (0555).
            script = os.path.join(venv_src, "bin", "tool.sh")
            with open(script, "w") as f:
                f.write("#!/bin/sh\necho tool\n")
            os.chmod(script, 0o755)
            lib = os.path.join(venv_src, "lib", "libfake.so")
            os.makedirs(os.path.dirname(lib), exist_ok=True)
            with open(lib, "wb") as f:
                f.write(b"\x7fELF fake\n")
            os.chmod(lib, 0o755)
            plain = os.path.join(venv_src, "plain.txt")
            with open(plain, "w") as f:
                f.write("plain\n")
            os.chmod(plain, 0o644)
            # Also restrictive 0711 exec to prove any-x -> 0555.
            legacy_exec = os.path.join(venv_src, "legacy.bin")
            with open(legacy_exec, "w") as f:
                f.write("bin\n")
            os.chmod(legacy_exec, 0o711)
            stage = make_stage(os.path.join(td, "s"))
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-staged")
            sr = find_staging_root(stage)
            self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(sr, "venv", "bin", "tool.sh")).st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(sr, "venv", "lib", "libfake.so")).st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(sr, "venv", "legacy.bin")).st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(sr, "venv", "plain.txt")).st_mode), 0o444)
            # Manifest records exec vs non-exec distinctly.
            entries = {r: (t, m) for r, t, m, h, tgt in self._parse_manifest(res["manifest"])}
            self.assertEqual(entries["venv/bin/tool.sh"][1], "0555")
            self.assertEqual(entries["venv/lib/libfake.so"][1], "0555")
            self.assertEqual(entries["venv/plain.txt"][1], "0444")

    def test_manifest_records_canonical_modes_sorted(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            self._make_restrictive(venv_src)
            stage = make_stage(os.path.join(td, "s"))
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-staged")
            entries = self._parse_manifest(res["manifest"])
            rels = [r for r, _, _, _, _ in entries]
            self.assertEqual(rels, sorted(rels))
            for rel, typ, mode, sha_h, tgt in entries:
                if typ == "dir":
                    self.assertEqual(mode, "0555", msg=rel)
                    self.assertEqual(sha_h, "-")
                    self.assertEqual(tgt, "-")
                elif typ == "file":
                    self.assertIn(mode, ("0444", "0555"), msg=rel)
                    self.assertEqual(len(sha_h), 64, msg=rel)
                    self.assertEqual(tgt, "-")
                elif typ == "symlink":
                    self.assertEqual(mode, "-")
                    self.assertEqual(sha_h, "-")
                    self.assertTrue(tgt, msg=rel)
                else:
                    self.fail(f"unknown type {typ}")
            # Manifest sha matches text.
            self.assertEqual(res["manifest_sha256"], hashlib.sha256(res["manifest"].encode()).hexdigest())
            # Verify dir round-trips same manifest (modes preserved via umask 022).
            vdir = os.path.join(stage, "verify-known-good")
            self.assertTrue(os.path.isdir(vdir))
            self._assert_canonical_tree(vdir)
            # Staging and verify manifests use same canonical modes (hash equality
            # already enforced by export; here just ensure verify tree canonical).

    def test_unpriv_1001_readable_mode_bits_and_conditional_actual(self):
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            self._make_restrictive(venv_src)
            stage = make_stage(os.path.join(td, "s"))
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-staged")
            sr = find_staging_root(stage)
            # Safe mode-bit proof uid 1001 can traverse/read: o+r and o+x set.
            for dp, dn, fn in os.walk(sr, followlinks=False):
                dmode = stat.S_IMODE(os.lstat(dp).st_mode)
                self.assertTrue(dmode & 0o004 and dmode & 0o001, msg=f"dir blocks 1001 {dp} {oct(dmode)}")
                for n in fn:
                    fp = os.path.join(dp, n)
                    try:
                        st = os.lstat(fp)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISLNK(st.st_mode):
                        continue
                    fmode = stat.S_IMODE(st.st_mode)
                    self.assertTrue(fmode & 0o004, msg=f"file blocks 1001 {fp} {oct(fmode)}")
                    if fmode == 0o555:
                        self.assertTrue(fmode & 0o001, msg=f"exec blocks 1001 {fp}")
            # Conditional actual unpriv read when running as root: fork, setuid
            # 1001, try listdir+open. Fixture-only, no live paths.
            if os.geteuid() == 0:
                probe_rel = os.path.join("venv", "pyvenv.cfg")
                probe = os.path.join(sr, probe_rel)
                self.assertTrue(os.path.exists(probe))
                pid = os.fork()
                if pid == 0:
                    try:
                        try:
                            os.setgid(1001)
                        except OSError:
                            pass
                        os.setuid(1001)
                        os.listdir(sr)
                        os.listdir(os.path.join(sr, "venv", "bin"))
                        with open(probe, "rb") as f:
                            data = f.read()
                        if not data:
                            os._exit(2)
                        os._exit(0)
                    except Exception:
                        os._exit(1)
                else:
                    _, status = os.waitpid(pid, 0)
                    # If setuid user missing or sandbox blocks, child exits non-zero;
                    # only assert when child could run (exit 0/1 from read, not signal).
                    if os.WIFEXITED(status):
                        code = os.WEXITSTATUS(status)
                        # 0 proves actual 1001 read; 1 is read failure (must not happen
                        # with canonical modes); allow skip only if setuid itself failed
                        # (child would still exit 1, but mode bits above already prove).
                        # To stay safe, require 0 when root can setuid to 1001.
                        # If environment lacks uid 1001 support, this still works
                        # (setuid to numeric id needs no passwd entry).
                        self.assertEqual(code, 0, msg="actual uid 1001 read failed despite 0444/0555")
                    else:
                        self.fail("unpriv probe child did not exit")

    def test_image_ll_canonical_if_available(self):
        import shutil as _sh
        if not os.path.exists("/usr/bin/mksquashfs") or not os.path.exists("/usr/bin/unsquashfs"):
            self.skipTest("no squashfs tools")
        if _sh.which("unsquashfs") is None:
            self.skipTest("no unsquashfs")
        from scripts.stock_activation.prep_export import export_prep_closure
        with tempfile.TemporaryDirectory() as td:
            repo, sha, venv_src, interp_src, deps_src = build_basic(os.path.join(td, "fix"))
            self._make_restrictive(venv_src)
            stage = make_stage(os.path.join(td, "s"))
            res = export_prep_closure(
                stage, kind="known-good", source_repo=repo, source_sha=sha,
                venv_src=venv_src, interpreter_src=interp_src, deps_src=deps_src,
                finder_prefixes=[FINDER_ORIG], mount_prefix=MOUNT_KNOWN,
            )
            self.assertEqual(res["status"], "prep-staged")
            img = res["image_path"]
            self.assertTrue(os.path.exists(img))
            cp = subprocess.run(["/usr/bin/unsquashfs", "-ll", img], capture_output=True, text=True, check=False)
            self.assertEqual(cp.returncode, 0, cp.stderr[:1000])
            out = cp.stdout
            # Image must be root-owned (all-root) but world-readable, not 0700/0600.
            self.assertIn("root/root", out)
            self.assertNotIn("drwx------", out, msg="squashfs-root still 0700, blocks 1001")
            self.assertNotIn("-rw-------", out)
            # Canonical perms present.
            self.assertIn("dr-xr-xr-x", out)
            self.assertTrue("-r--r--r--" in out or "-r-xr-xr-x" in out)


if __name__ == "__main__":
    unittest.main()
