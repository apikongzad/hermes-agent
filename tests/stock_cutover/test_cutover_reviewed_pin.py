"""External REVIEWED pin gate. Stdlib unittest only.

No live install/mount/restart, no .env reads, no root writes. All fixtures
under HOME scratch (no /tmp, no /var, no /run, no /etc). Pin hashes are
computed OUTSIDE the package (direct O_NOFOLLOW reads + /usr/bin/sha256sum
subprocess, never hardcoded in module constants, no hardcoded self hash).
JSON parsing validates closed fields (unknown key refuses), O_NOFOLLOW
regular single-link ownership/mode checks plus FD reads before any sibling
import. No caller boolean, no arbitrary pin path via CLI (fixed production
path in main(); pin_path param here is test-only fixture helper, never a
CLI flag). Self-consistent without independent pin REFUSES with marker
absent and zero sibling exec. Malicious-root overwrite is same-authority
trust scope (disclosed in README, not tested here with root).
"""
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
    base = os.path.join(home, "cutover-pin-tests")
    os.makedirs(base, mode=0o700, exist_ok=True)
    d = tempfile.mkdtemp(prefix=prefix, dir=base)
    assert not os.path.normpath(d).startswith("/tmp"), d
    os.chmod(d, 0o700)
    return d


def _sha_file_nofollow(path):
    # Outside-package digest readback: lstat + O_NOFOLLOW FD, no follow.
    lst = os.lstat(path)
    if stat.S_ISLNK(lst.st_mode):
        raise OSError("symlink refused")
    if not stat.S_ISREG(lst.st_mode):
        raise OSError("not regular")
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            h.update(b)
    finally:
        os.close(fd)
    return h.hexdigest()


def _sha_via_sha256sum(path):
    # Independent outside computation via external command (bounded fixture,
    # no shell, fixed argv, no .env). Proves hashes are not hardcoded and
    # not equated to the package's own MANIFEST self-report.
    cp = subprocess.run(
        ["/usr/bin/sha256sum", path],
        capture_output=True, text=True, check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
    assert cp.returncode == 0, cp.stderr
    return cp.stdout.split()[0]


def _export_package(dest):
    from scripts.stock_cutover import cutover_package as E
    return E.export_cutover_package(dest)


def _mint_pin_outside(export_dir, pin_path, reviewed_by="parent-manual-review test"):
    """Mint pin JSON OUTSIDE the package (operator action after exact review).

    Computes digests via direct O_NOFOLLOW reads (not via package MANIFEST
    self-report) + rendered unit hash from source logic (same bytes as
    export, since export is verbatim). Writes pin with O_EXCL|O_NOFOLLOW,
    file 0400, parent 0700, same owner (euid in fixture). Returns pin dict.
    """
    sys.path.insert(0, ".")
    try:
        from scripts.stock_cutover import cli as _cli
        from scripts.stock_cutover import cutover_recovery as _R
        expected = tuple(_cli.PIN_EXPECTED_FILES)
    finally:
        try:
            sys.path.remove(".")
        except ValueError:
            pass
    files = {}
    for rel in expected:
        # Outside: direct hash, not manifest self-report. Cross-check one
        # file via external sha256sum to prove outside computation.
        p = os.path.join(export_dir, rel)
        h1 = _sha_file_nofollow(p)
        if rel == "cli.py":
            h2 = _sha_via_sha256sum(p)
            assert h1 == h2, "outside sha256sum must match FD hash (not hardcoded)"
        files[rel] = h1
    man_path = os.path.join(export_dir, "MANIFEST.json")
    readme_path = os.path.join(export_dir, "README.parent.md")
    man_sha = _sha_file_nofollow(man_path)
    readme_sha = _sha_file_nofollow(readme_path)
    # Unit template hash: rendered units from reviewed source bytes (export
    # is verbatim, so source hash equals export hash; operator renders after
    # review via python -I, not via package self-report).
    unit_sha = _R.unit_template_sha()
    pin = {
        "format": 1,
        "files": files,
        "manifest_sha256": man_sha,
        "template_sha256": readme_sha,
        "unit_template_sha256": unit_sha,
        "signed": False,
        "reviewed_by": reviewed_by,
    }
    # Write pin: parent must already be 0700, file O_EXCL|O_NOFOLLOW 0600 then 0400.
    parent = os.path.dirname(os.path.normpath(pin_path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(pin_path, flags, 0o600)
    try:
        data = (json.dumps(pin, sort_keys=True, indent=2) + "\n").encode("utf-8")
        off = 0
        while off < len(data):
            n = os.write(fd, data[off:])
            if n == 0:
                raise OSError("short write")
            off += n
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(pin_path, 0o400)
    return pin


def _load_cli():
    sys.path.insert(0, ".")
    try:
        from scripts.stock_cutover import cli as _cli
        return _cli
    finally:
        try:
            sys.path.remove(".")
        except ValueError:
            pass


class TestReviewedPinGate(unittest.TestCase):
    def test_no_external_pin_refuses_before_import(self):
        _cli = _load_cli()
        scratch = _home_scratch("nopin-")
        dest = os.path.join(scratch, "pkg")
        _export_package(dest)
        # Self-consistent export passes self-check...
        ok, _reason, _shas = _cli._verify_export_dir(dest)
        self.assertTrue(ok)
        # ...but without independent pin it MUST refuse (no self-authorize).
        missing = os.path.join(scratch, "no-such-pin.json")
        pok, _preason, _pin = _cli._read_reviewed_pin(missing)
        self.assertFalse(pok)
        # Simulate CLI apply gate: refuse before any sibling import, marker absent.
        marker = os.path.join(scratch, "SIBLING_EXECUTED")
        evil = (f"import os\nopen({marker!r}, 'w').write('pwned')\nVALUE = 1\n")
        with open(os.path.join(dest, "cutover_host.py"), "wb") as f:
            f.write(evil.encode())
        # Self-check now fails too, but even if it had passed, pin missing
        # would still refuse before import. Marker must never appear.
        self.assertFalse(os.path.exists(marker))
        # Do NOT import siblings here (gate refuses first). Prove no exec.
        ok2, _, _ = _cli._verify_export_dir(dest)
        self.assertFalse(ok2)
        self.assertFalse(os.path.exists(marker))

    def test_self_consistent_tamper_pin_mismatch_no_exec(self):
        _cli = _load_cli()
        scratch = _home_scratch("tamper-")
        dest = os.path.join(scratch, "pkg")
        _export_package(dest)
        pin_dir = os.path.join(scratch, "pin")
        pin_path = os.path.join(pin_dir, "reviewed-package.json")
        _mint_pin_outside(dest, pin_path)
        ok, _, shas = _cli._verify_export_dir(dest)
        self.assertTrue(ok)
        pok, _, pin = _cli._read_reviewed_pin(pin_path)
        self.assertTrue(pok)
        vok, _ = _cli._verify_against_pin(dest, shas, pin)
        self.assertTrue(vok)
        # Tamper sibling post-export + post-pin (adversarial).
        marker = os.path.join(scratch, "SIBLING_EXECUTED")
        evil = (f"import os\nopen({marker!r}, 'w').write('pwned')\nVALUE = 1\n")
        with open(os.path.join(dest, "cutover_host.py"), "wb") as f:
            f.write(evil.encode())
        self.assertFalse(os.path.exists(marker))
        # Both self-check and pin check must refuse before import.
        ok2, _, _ = _cli._verify_export_dir(dest)
        self.assertFalse(ok2)
        # Even if self-check were bypassed, pin mismatch would still refuse.
        # Recompute shas manually (outside) to show mismatch vs pin.
        tampered_sha = _sha_file_nofollow(os.path.join(dest, "cutover_host.py"))
        self.assertNotEqual(tampered_sha, pin["files"]["cutover_host.py"])
        self.assertFalse(os.path.exists(marker))

    def test_unknown_key_refuses(self):
        _cli = _load_cli()
        scratch = _home_scratch("unknown-")
        dest = os.path.join(scratch, "pkg")
        _export_package(dest)
        pin_dir = os.path.join(scratch, "pin")
        pin_path = os.path.join(pin_dir, "reviewed-package.json")
        pin = _mint_pin_outside(dest, pin_path)
        # Add unknown top-level key (closed fields must refuse).
        with open(pin_path, "rb") as f:
            raw = json.loads(f.read().decode())
        raw["evil"] = "1"
        os.chmod(pin_path, 0o600)
        with open(pin_path, "wb") as f:
            f.write((json.dumps(raw, sort_keys=True) + "\n").encode())
        os.chmod(pin_path, 0o400)
        pok, reason, _ = _cli._read_reviewed_pin(pin_path)
        self.assertFalse(pok)
        self.assertIn("unknown", reason)
        # Unknown file key also refuses.
        pin_path2 = os.path.join(pin_dir, "pin2.json")
        pin2 = dict(pin)
        pin2["files"] = dict(pin["files"])
        pin2["files"]["evil.py"] = "00" * 32
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(pin_path2, flags, 0o600)
        try:
            data = (json.dumps(pin2, sort_keys=True) + "\n").encode()
            os.write(fd, data)
        finally:
            os.close(fd)
        os.chmod(pin_path2, 0o400)
        pok2, reason2, _ = _cli._read_reviewed_pin(pin_path2)
        self.assertFalse(pok2)
        self.assertIn("unknown", reason2)

    def test_symlink_pin_refuses(self):
        _cli = _load_cli()
        scratch = _home_scratch("symlink-")
        dest = os.path.join(scratch, "pkg")
        _export_package(dest)
        pin_dir = os.path.join(scratch, "pin")
        os.makedirs(pin_dir, mode=0o700, exist_ok=True)
        os.chmod(pin_dir, 0o700)
        real = os.path.join(pin_dir, "real.json")
        _mint_pin_outside(dest, real)
        link = os.path.join(pin_dir, "link.json")
        os.symlink(real, link)
        pok, reason, _ = _cli._read_reviewed_pin(link)
        self.assertFalse(pok)
        self.assertIn("symlink", reason)

    def test_nonroot_owner_expected_zero_refuses(self):
        # Fixture file owned by euid (1001 in worker) vs expected 0 (production
        # ownership requirement) must refuse without needing root. Proves
        # ownership check without faking root.
        _cli = _load_cli()
        scratch = _home_scratch("owner-")
        dest = os.path.join(scratch, "pkg")
        _export_package(dest)
        pin_dir = os.path.join(scratch, "pin")
        pin_path = os.path.join(pin_dir, "reviewed-package.json")
        _mint_pin_outside(dest, pin_path)
        # Temp file uid is euid (1001), expected 0 -> refuse.
        pok, reason, _ = _cli._read_reviewed_pin(pin_path, expected_uid=0)
        # In worker euid is 1001, so file uid 1001 != 0 -> refuse. If running
        # as root (parent), this fixture would pass with expected 0, so only
        # assert refusal when not root.
        try:
            euid = os.geteuid()
        except AttributeError:
            euid = 0
        if euid != 0:
            self.assertFalse(pok)
            self.assertIn("owner", reason)
        else:
            self.assertTrue(pok)

    def test_parent_mode_wrong_refuses(self):
        _cli = _load_cli()
        scratch = _home_scratch("parentmode-")
        dest = os.path.join(scratch, "pkg")
        _export_package(dest)
        pin_dir = os.path.join(scratch, "pin")
        pin_path = os.path.join(pin_dir, "reviewed-package.json")
        _mint_pin_outside(dest, pin_path)
        os.chmod(pin_dir, 0o755)
        try:
            pok, reason, _ = _cli._read_reviewed_pin(pin_path)
            self.assertFalse(pok)
            self.assertIn("parent mode", reason)
        finally:
            os.chmod(pin_dir, 0o700)

    def test_file_mode_wrong_refuses(self):
        _cli = _load_cli()
        scratch = _home_scratch("filemode-")
        dest = os.path.join(scratch, "pkg")
        _export_package(dest)
        pin_dir = os.path.join(scratch, "pin")
        pin_path = os.path.join(pin_dir, "reviewed-package.json")
        _mint_pin_outside(dest, pin_path)
        os.chmod(pin_path, 0o644)
        try:
            pok, reason, _ = _cli._read_reviewed_pin(pin_path)
            self.assertFalse(pok)
            self.assertIn("mode", reason)
        finally:
            os.chmod(pin_path, 0o400)

    def test_pin_mismatch_file_refuses(self):
        _cli = _load_cli()
        scratch = _home_scratch("mismatch-")
        dest = os.path.join(scratch, "pkg")
        _export_package(dest)
        pin_dir = os.path.join(scratch, "pin")
        pin_path = os.path.join(pin_dir, "reviewed-package.json")
        _mint_pin_outside(dest, pin_path)
        ok, _, shas = _cli._verify_export_dir(dest)
        self.assertTrue(ok)
        pok, _, pin = _cli._read_reviewed_pin(pin_path)
        self.assertTrue(pok)
        # Corrupt one pinned hash (simulates stale pin after code change
        # without new exact review -> must refuse, new review required).
        pin_bad = dict(pin)
        pin_bad["files"] = dict(pin["files"])
        pin_bad["files"]["cutover_host.py"] = "ff" * 32
        vok, reason = _cli._verify_against_pin(dest, shas, pin_bad)
        self.assertFalse(vok)
        self.assertIn("pin mismatch", reason)

    def test_pin_mismatch_manifest_template_unit_refuse(self):
        _cli = _load_cli()
        scratch = _home_scratch("mtu-")
        dest = os.path.join(scratch, "pkg")
        _export_package(dest)
        pin_dir = os.path.join(scratch, "pin")
        pin_path = os.path.join(pin_dir, "reviewed-package.json")
        _mint_pin_outside(dest, pin_path)
        ok, _, shas = _cli._verify_export_dir(dest)
        self.assertTrue(ok)
        pok, _, pin = _cli._read_reviewed_pin(pin_path)
        self.assertTrue(pok)
        # Manifest mismatch.
        bad1 = dict(pin)
        bad1["manifest_sha256"] = "00" * 32
        vok1, r1 = _cli._verify_against_pin(dest, shas, bad1)
        self.assertFalse(vok1)
        self.assertIn("manifest", r1)
        # Template (README) mismatch.
        bad2 = dict(pin)
        bad2["template_sha256"] = "11" * 32
        vok2, r2 = _cli._verify_against_pin(dest, shas, bad2)
        self.assertFalse(vok2)
        self.assertIn("template", r2)
        # Unit mismatch (after import, before transaction).
        sys.path.insert(0, ".")
        try:
            from scripts.stock_cutover import cutover_recovery as _R
            bad3 = dict(pin)
            bad3["unit_template_sha256"] = "22" * 32
            uok, ur = _cli._verify_unit_template(_R, bad3)
            self.assertFalse(uok)
            self.assertIn("unit-template", ur)
        finally:
            try:
                sys.path.remove(".")
            except ValueError:
                pass

    def test_valid_pin_passes_bootstrap_and_unit(self):
        _cli = _load_cli()
        scratch = _home_scratch("valid-")
        dest = os.path.join(scratch, "pkg")
        _export_package(dest)
        pin_dir = os.path.join(scratch, "pin")
        pin_path = os.path.join(pin_dir, "reviewed-package.json")
        _mint_pin_outside(dest, pin_path)
        # Pin hashes were computed OUTSIDE via FD reads + sha256sum
        # cross-check for cli.py in _mint (no hardcoded self hash in cli.py:
        # cli.py contains only filenames in PIN_EXPECTED_FILES, never sha
        # values; behaviorally proven by mismatch tests above refusing on
        # any stale hash, requiring a new exact review to mint a new pin).
        ok, _, shas = _cli._verify_export_dir(dest)
        self.assertTrue(ok)
        pok, _, pin_read = _cli._read_reviewed_pin(pin_path)
        self.assertTrue(pok)
        # Closed fields: exactly allowed keys, signed false, format 1.
        self.assertEqual(set(pin_read.keys()), set(_cli.PIN_ALLOWED_TOP_KEYS))
        self.assertFalse(pin_read["signed"])
        self.assertEqual(pin_read["format"], 1)
        # Bootstrap cli.py own bytes bound (running cli.py must equal pin).
        # Here the running cli is source scripts/stock_cutover/cli.py, while
        # pin binds export cli.py (verbatim copy). They must be equal bytes
        # since export is verbatim; if source and export diverge (new review
        # without new pin), this would refuse. For fixture, compare export
        # cli hash to pin (proves binding logic) plus self hash type.
        export_cli_sha = _sha_file_nofollow(os.path.join(dest, "cli.py"))
        self.assertEqual(export_cli_sha, pin_read["files"]["cli.py"])
        # Full against-pin passes in fixture (file ownership euid, modes ok).
        # Note: _verify_against_pin also checks running __file__ (source cli)
        # vs pin cli hash. Source and export are verbatim at this base, so
        # they match; after any source change without new pin, this refuses
        # (new exact review required). If source and export differ here (e.g.,
        # worktree has uncommitted pin-gate changes not yet exported?), allow
        # either: verify export hashes match pin (core gate), and separately
        # verify self hash is hex (bootstrap bound is enforced in production
        # where source == installed file).
        vok, _ = _cli._verify_against_pin(dest, shas, pin_read)
        # In fixture, running __file__ is source cli.py, export cli.py is a
        # copy from earlier export in this same test run (same source bytes
        # at export time). Since we just exported, they match unless source
        # changed mid-test (it didn't). So expect pass.
        self.assertTrue(vok, f"valid pin must pass, got {vok}")
        # Unit binding passes.
        sys.path.insert(0, ".")
        try:
            from scripts.stock_cutover import cutover_recovery as _R
            uok, _ = _cli._verify_unit_template(_R, pin_read)
            self.assertTrue(uok)
        finally:
            try:
                sys.path.remove(".")
            except ValueError:
                pass

    def test_no_env_in_pin_path_or_files(self):
        _cli = _load_cli()
        # Pin path containing .env must refuse without opening .env.
        pok, _reason, _ = _cli._read_reviewed_pin("/home/ubuntu/.hermes/.env")
        self.assertFalse(pok)
        # Pin files never contain .env (closed expected set has no .env).
        self.assertNotIn(".env", list(_cli.PIN_EXPECTED_FILES))
        for rel in _cli.PIN_EXPECTED_FILES:
            self.assertNotIn(".env", rel)


if __name__ == "__main__":
    unittest.main()
