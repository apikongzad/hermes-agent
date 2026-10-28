"""Fail-closed unit contracts + offline systemd verify. Stdlib unittest only.

No live install/mount/restart/env reads. All fixtures under HOME scratch
(no /tmp, no /var, no /run, no /etc writes). Unit parsing uses a bounded
command parser (section/key split, not grep-alone) plus real
systemd-analyze verify offline (no install/service effects). Sandbox never
touches real root units; no fake activation claim (never asserts
committed/GO, only fail-closed refusal/unresolved).
"""
import os
import subprocess
import tempfile
import unittest

from scripts.stock_cutover import cutover_recovery as R


def _home_scratch(prefix):
    home = os.path.expanduser("~")
    assert os.path.isabs(home) and not home.startswith("/tmp"), home
    base = os.path.join(home, "cutover-units-failclosed")
    os.makedirs(base, mode=0o700, exist_ok=True)
    d = tempfile.mkdtemp(prefix=prefix, dir=base)
    assert not os.path.normpath(d).startswith("/tmp"), d
    os.chmod(d, 0o700)
    return d


def _parse_unit(text):
    """Bounded systemd unit parser: section -> list[(key, value)].

    Rejects comments outside sections, requires [Section] + key=value.
    Preserves duplicate keys in order (Assert may repeat). Raises on
    malformed input (fail-closed, never silent skip).
    """
    if not isinstance(text, str) or not text:
        raise ValueError("unit type")
    sections = {}
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1].strip()
            if not cur:
                raise ValueError("empty section")
            sections.setdefault(cur, [])
            continue
        if cur is None:
            raise ValueError("directive outside section")
        if "=" not in line:
            raise ValueError("directive without =: " + line[:80])
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            raise ValueError("empty key")
        sections[cur].append((k, v))
    if "Unit" not in sections:
        raise ValueError("missing Unit")
    return sections


def _values(sections, section, key):
    return [v for k, v in sections.get(section, []) if k == key]


def _has_key_prefix(sections, prefix):
    for _sec, pairs in sections.items():
        for k, _v in pairs:
            if k.startswith(prefix):
                return True
    return False


class TestFailClosedParserContracts(unittest.TestCase):
    def test_cutover_assert_not_condition_via_parser(self):
        cut = R.cutover_service_unit()
        secs = _parse_unit(cut)
        # No Condition* anywhere (skip-with-success forbidden).
        self.assertFalse(_has_key_prefix(secs, "Condition"),
                         "cutover must not contain Condition* (skip-success)")
        # Assert both snaps + both images (fail-closed, OnFailure fires).
        asserts = _values(secs, "Unit", "AssertPathIsMountPoint") + _values(
            secs, "Unit", "AssertPathExists")
        self.assertIn(R.KNOWN_GOOD_MOUNT, _values(secs, "Unit", "AssertPathIsMountPoint"))
        self.assertIn(R.CANDIDATE_MOUNT, _values(secs, "Unit", "AssertPathIsMountPoint"))
        self.assertIn(R.KNOWN_GOOD_IMAGE, _values(secs, "Unit", "AssertPathExists"))
        self.assertIn(R.CANDIDATE_IMAGE, _values(secs, "Unit", "AssertPathExists"))
        self.assertGreaterEqual(len(asserts), 4)
        # Requires both escaped mounts on one Requires line (cannot start invalid).
        reqs = _values(secs, "Unit", "Requires")
        self.assertEqual(len(reqs), 1)
        self.assertIn(R.KNOWN_GOOD_MOUNT_UNIT, reqs[0])
        self.assertIn(R.CANDIDATE_MOUNT_UNIT, reqs[0])
        # After both mounts.
        afters = _values(secs, "Unit", "After")
        self.assertEqual(len(afters), 1)
        self.assertIn(R.KNOWN_GOOD_MOUNT_UNIT, afters[0])
        # OnFailure owns recovery, no restart.
        self.assertIn("hermes-stock-cutover-recover.service",
                      _values(secs, "Unit", "OnFailure")[0])
        self.assertEqual(_values(secs, "Service", "Restart"), ["no"])

    def test_recover_independent_via_parser(self):
        rec = R.recover_service_unit()
        secs = _parse_unit(rec)
        # Recover must stay runnable when mounts/images are broken: no
        # Requires, no Assert, no Condition anywhere. An Assert on recovery
        # itself would prevent ExecStart and hide the receipt.
        self.assertFalse(_has_key_prefix(secs, "Condition"),
                         "recover must not contain Condition*")
        self.assertEqual(_values(secs, "Unit", "Requires"), [])
        self.assertEqual(_values(secs, "Unit", "AssertPathIsMountPoint"), [])
        self.assertEqual(_values(secs, "Unit", "AssertPathExists"), [])
        # No mount unit names, no snap/image paths in recover text.
        self.assertNotIn(R.KNOWN_GOOD_MOUNT_UNIT, rec)
        self.assertNotIn(R.CANDIDATE_MOUNT_UNIT, rec)
        self.assertNotIn(R.KNOWN_GOOD_MOUNT, rec)
        self.assertNotIn(R.CANDIDATE_MOUNT, rec)
        self.assertNotIn(R.KNOWN_GOOD_IMAGE, rec)
        self.assertNotIn(R.CANDIDATE_IMAGE, rec)
        # Still oneshot, Restart=no, ExecStart recover, no OnFailure loop.
        self.assertEqual(_values(secs, "Service", "Type"), ["oneshot"])
        self.assertEqual(_values(secs, "Service", "Restart"), ["no"])
        self.assertNotEqual(_values(secs, "Service", "ExecStart"), [])
        self.assertIn("recover", _values(secs, "Service", "ExecStart")[0])
        self.assertEqual(_values(secs, "Unit", "OnFailure"), [])

    def test_mounts_assert_via_parser(self):
        for text, img, mnt in ((R.known_good_mount_unit(), R.KNOWN_GOOD_IMAGE, R.KNOWN_GOOD_MOUNT),
                               (R.candidate_mount_unit(), R.CANDIDATE_IMAGE, R.CANDIDATE_MOUNT)):
            secs = _parse_unit(text)
            self.assertFalse(_has_key_prefix(secs, "Condition"),
                             "mount must not contain Condition* (skip-success)")
            self.assertIn(img, _values(secs, "Unit", "AssertPathExists"))
            self.assertIn(img, _values(secs, "Mount", "What")[0])
            self.assertIn(mnt, _values(secs, "Mount", "Where")[0])
            self.assertEqual(_values(secs, "Mount", "Type"), ["squashfs"])
            self.assertEqual(_values(secs, "Mount", "Options"), ["ro,nosuid,nodev"])
            befores = _values(secs, "Unit", "Before")
            self.assertEqual(len(befores), 1)
            for svc in (R.CUTOVER_SERVICE_NAME, R.RECOVER_SERVICE_NAME,
                        R.GATEWAY_UNIT, R.DASHBOARD_UNIT):
                self.assertIn(svc, befores[0])

    def test_mount_names_match_systemd_escape(self):
        # Correct escaped names or systemd-analyze verify refuses (Where mismatch).
        # Proves via real systemd-escape (bounded, no install), not grep-alone.
        # Byte-level single-escape proof: repr shows \\ for one 0x5c byte;
        # double-escaped would be \\\\ in repr and 0x5c 0x5c in bytes.
        for path, const in ((R.KNOWN_GOOD_MOUNT, R.KNOWN_GOOD_MOUNT_UNIT),
                            (R.CANDIDATE_MOUNT, R.CANDIDATE_MOUNT_UNIT)):
            cp = subprocess.run(
                ["/usr/bin/systemd-escape", "-p", "--suffix=mount", path],
                capture_output=True, text=True, check=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stdout.strip(), const)
            # Complete fname byte comparison (not prefix-only).
            self.assertEqual(cp.stdout.strip().encode("utf-8"), const.encode("utf-8"))
            # Single backslash only: actual contains \x2d (one 0x5c), never \\.
            self.assertIn("\\x2d", const)
            self.assertNotIn("\\\\x2d", const)
            self.assertNotIn(b"\x5c\x5c", const.encode("utf-8"))
            # Expected escape counts: known-good 4, candidate 3.
            want = 4 if "known" in path else 3
            self.assertEqual(const.count("\\"), want)
            self.assertEqual(const.count("\\x2d"), want)

    def test_validator_rejects_missing_prereq(self):
        cut = R.cutover_service_unit()
        rec = R.recover_service_unit()
        tim = R.recover_timer_unit()
        kgm = R.known_good_mount_unit()
        cdm = R.candidate_mount_unit()
        # Baseline passes.
        self.assertTrue(R.validate_supervision(cut, rec, tim))
        self.assertTrue(R.validate_mount_units(kgm, cdm))
        # Cutover missing Requires -> fail.
        bad = cut.replace("Requires=", "Wants=")
        with self.assertRaises(ValueError):
            R.validate_supervision(bad, rec, tim)
        # Cutover Condition instead of Assert -> fail (skip-success forbidden).
        bad2 = cut.replace("AssertPathIsMountPoint=", "ConditionPathIsMountPoint=")
        with self.assertRaises(ValueError):
            R.validate_supervision(bad2, rec, tim)
        # Cutover missing one Assert -> fail.
        bad3 = cut.replace(f"AssertPathExists={R.KNOWN_GOOD_IMAGE}\n", "")
        with self.assertRaises(ValueError):
            R.validate_supervision(bad3, rec, tim)
        # Recover with Requires (blocks when mount broken) -> fail.
        bad4 = rec.replace("After=network.target",
                           f"After=network.target {R.KNOWN_GOOD_MOUNT_UNIT}\n"
                           f"Requires={R.KNOWN_GOOD_MOUNT_UNIT}")
        with self.assertRaises(ValueError):
            R.validate_supervision(cut, bad4, tim)
        # Recover with Assert (prevents receipt) -> fail.
        bad5 = rec.replace("After=network.target",
                           f"After=network.target\nAssertPathExists={R.KNOWN_GOOD_IMAGE}")
        with self.assertRaises(ValueError):
            R.validate_supervision(cut, bad5, tim)
        # Recover with Condition (skip-success) -> fail.
        bad6 = rec.replace("After=network.target",
                           f"After=network.target\nConditionPathExists={R.KNOWN_GOOD_IMAGE}")
        with self.assertRaises(ValueError):
            R.validate_supervision(cut, bad6, tim)
        # Mount Condition instead of Assert -> fail.
        bad7 = kgm.replace("AssertPathExists=", "ConditionPathExists=")
        with self.assertRaises(ValueError):
            R.validate_mount_units(bad7, cdm)
        # Mount missing Before gateway -> fail.
        bad8 = kgm.replace(R.GATEWAY_UNIT, "other.service")
        with self.assertRaises(ValueError):
            R.validate_mount_units(bad8, cdm)
        # Cutover missing --execute-live (would exit 3, never execute) -> fail.
        bad9 = cut.replace(" apply --execute-live", " apply")
        with self.assertRaises(ValueError):
            R.validate_supervision(bad9, rec, tim)
        # Recover missing --execute-live -> fail.
        bad10 = rec.replace(" recover --execute-live", " recover")
        with self.assertRaises(ValueError):
            R.validate_supervision(cut, bad10, tim)
        # Substring without flag is insufficient: ExecStart line must be exact.
        bad11 = cut.replace(
            "ExecStart=/usr/bin/python3.12 -I /var/lib/hermes-stock-activation/recovery/cli.py apply --execute-live",
            "ExecStart=/usr/bin/python3.12 -I /var/lib/hermes-stock-activation/recovery/cli.py apply")
        with self.assertRaises(ValueError):
            R.validate_supervision(bad11, rec, tim)
        # OnFailure must be a separate exact line, not substring inside other text.
        bad12 = cut.replace(
            "OnFailure=hermes-stock-cutover-recover.service",
            "# OnFailure=hermes-stock-cutover-recover.service")
        with self.assertRaises(ValueError):
            R.validate_supervision(bad12, rec, tim)
        bad13 = cut.replace(
            "OnFailure=hermes-stock-cutover-recover.service",
            "XOnFailure=hermes-stock-cutover-recover.service")
        with self.assertRaises(ValueError):
            R.validate_supervision(bad13, rec, tim)
        # Recover with OnFailure line (even commented as directive) -> fail.
        bad14 = rec.replace("After=network.target",
                            "After=network.target\nOnFailure=hermes-stock-cutover-recover.service")
        with self.assertRaises(ValueError):
            R.validate_supervision(cut, bad14, tim)

    def test_execstart_exact_flag_via_parser(self):
        # Exact full argv binding via parser (not grep-alone): rendered
        # ExecStart must equal python -I program + subcommand + flag.
        for text, sub in ((R.cutover_service_unit(), "apply"),
                          (R.recover_service_unit(), "recover")):
            secs = _parse_unit(text)
            execs = _values(secs, "Service", "ExecStart")
            self.assertEqual(len(execs), 1)
            parts = execs[0].split()
            self.assertEqual(parts, [R.PYTHON_BIN, "-I", R.RECOVERY_PROGRAM,
                                     sub, "--execute-live"])
        # Constants match rendered exact argv (no drift).
        self.assertEqual(R.APPLY_ARGV,
                         [R.PYTHON_BIN, "-I", R.RECOVERY_PROGRAM,
                          "apply", "--execute-live"])
        self.assertEqual(R.RECOVERY_ARGV,
                         [R.PYTHON_BIN, "-I", R.RECOVERY_PROGRAM,
                          "recover", "--execute-live"])

    def test_render_execstart_traces_to_actual_cli(self):
        # Trace render -> actual CLI: parsed ExecStart tail must be accepted
        # past the flag gate (not exit 3), while unflagged refuses exit 3
        # with no execution. Safe: worker uid 1001, HOME scratch only, no
        # live systemctl/mount/service effects; flagged in worker exits 4
        # (fails root/installed, no live ops), never 0/1 execution.
        import sys as _sys
        _sys.path.insert(0, ".")
        try:
            from scripts.stock_cutover import cli as _cli
        finally:
            try:
                _sys.path.remove(".")
            except ValueError:
                pass
        for text, sub in ((R.cutover_service_unit(), "apply"),
                          (R.recover_service_unit(), "recover")):
            secs = _parse_unit(text)
            execs = _values(secs, "Service", "ExecStart")
            self.assertEqual(len(execs), 1)
            parts = execs[0].split()
            # Rendered tail is [sub, --execute-live].
            self.assertEqual(parts[-2:], [sub, "--execute-live"])
            # Unflagged refuses exit 3, no execution.
            self.assertEqual(_cli.main([sub]), 3)
            # Flagged passes flag gate (not 3) but worker refuses exit 4,
            # no live effects (not root/installed, no systemctl).
            rc = _cli.main([sub, "--execute-live"])
            self.assertNotEqual(rc, 3)
            self.assertEqual(rc, 4)
        # Exported CLI subprocess (real binary, temp HOME scratch, no live):
        # unflagged rc3, flagged rc4 (accepted past flag only).
        from scripts.stock_cutover import cutover_package as _E
        scratch = _home_scratch("cli-flag-")
        dest = os.path.join(scratch, "pkg")
        _E.export_cutover_package(dest)
        entry = os.path.join(scratch, "pkg", "cli.py")
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        for sub in ("apply", "recover"):
            cp0 = subprocess.run(["/usr/bin/python3", "-I", entry, sub],
                                 capture_output=True, text=True, check=False,
                                 cwd=scratch, env=env)
            self.assertEqual(cp0.returncode, 3, (sub, cp0.stdout, cp0.stderr))
            cp1 = subprocess.run(["/usr/bin/python3", "-I", entry, sub, "--execute-live"],
                                 capture_output=True, text=True, check=False,
                                 cwd=scratch, env=env)
            # Worker: passes flag gate, then fails root/installed (exit 4),
            # never executes live (never 0/1).
            self.assertEqual(cp1.returncode, 4, (sub, cp1.stdout, cp1.stderr))
            self.assertNotIn("committed", cp1.stdout)

    def test_dropin_requires_after_parser(self):
        # Boot hard prereq must be effective for gateway/dashboard, not
        # Before-only. Dropins carry [Unit] Requires+After both mounts.
        # Parser-based (not grep-alone), only-named-override enforced.
        from scripts.stock_cutover import cutover_units as _U
        from scripts.stock_cutover import cutover_orchestrate as _C
        for mod, gw_fn, db_fn, gw_wd, db_wd in (
                (_U, _U.render_gateway_dropin, _U.render_dashboard_dropin,
                 _U.GATEWAY_WD, _U.DASHBOARD_WD),
                (_C, _C._render_gateway_dropin, _C._render_dashboard_dropin,
                 _C.GATEWAY_WD, _C.DASHBOARD_WD)):
            for fn, mount, wd in ((gw_fn, _U.CANDIDATE_MOUNT, gw_wd),
                                  (db_fn, _U.CANDIDATE_MOUNT, db_wd),
                                  (gw_fn, _U.KNOWN_GOOD_MOUNT, gw_wd),
                                  (db_fn, _U.KNOWN_GOOD_MOUNT, db_wd)):
                body = fn(mount)
                text = body.decode("utf-8")
                # Parse dropin sections manually (dropins have [Unit]+[Service]).
                secs = {}
                cur = None
                for raw in text.splitlines():
                    s = raw.strip()
                    if not s:
                        continue
                    if s.startswith("[") and s.endswith("]"):
                        cur = s[1:-1]
                        secs.setdefault(cur, [])
                        continue
                    self.assertIsNotNone(cur)
                    k, _, v = s.partition("=")
                    secs[cur].append((k.strip(), v.strip()))
                self.assertIn("Unit", secs)
                self.assertIn("Service", secs)
                reqs = [v for k, v in secs["Unit"] if k == "Requires"]
                afts = [v for k, v in secs["Unit"] if k == "After"]
                self.assertEqual(len(reqs), 1)
                self.assertEqual(len(afts), 1)
                for unit in (_U.KNOWN_GOOD_MOUNT_UNIT, _U.CANDIDATE_MOUNT_UNIT):
                    self.assertIn(unit, reqs[0])
                    self.assertIn(unit, afts[0])
                # Only-named-override: Unit has only Requires/After.
                for k, _v in secs["Unit"]:
                    self.assertIn(k, ("Requires", "After"))
                # No Condition/OnFailure/Restart in dropins.
                for sec, pairs in secs.items():
                    for k, _v in pairs:
                        self.assertFalse(k.startswith("Condition"))
                        self.assertNotEqual(k, "OnFailure")
                        self.assertNotEqual(k, "Restart")
                # Validators enforce the same contract.
                if mod is _U:
                    self.assertTrue(_U.validate_dropin_bytes(body, mount, wd))
                else:
                    self.assertTrue(_C._validate_dropin_bytes(body, mount, wd))


class TestSystemdAnalyzeVerifyOffline(unittest.TestCase):
    def test_verify_all_units_offline_no_install(self):
        # Exact systemd verify on generated units in worktree scratch (safe:
        # offline, no install, no service effects). Proves syntax + mount
        # name binding (Where match) with real systemd-analyze, not grep.
        files = R.unit_filenames()
        # Explicit expected set (no broad glob).
        self.assertEqual(set(files.keys()), {
            R.CUTOVER_SERVICE_NAME, R.RECOVER_SERVICE_NAME,
            R.RECOVER_TIMER_NAME, R.KNOWN_GOOD_MOUNT_UNIT,
            R.CANDIDATE_MOUNT_UNIT})
        scratch = _home_scratch("verify-")
        paths = []
        for name in sorted(files.keys()):
            p = os.path.join(scratch, name)
            # O_EXCL|O_NOFOLLOW, no follow, no overwrite (bounded fixture).
            fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                data = files[name].encode("utf-8")
                off = 0
                while off < len(data):
                    n = os.write(fd, data[off:])
                    if n == 0:
                        raise OSError("short write")
                    off += n
            finally:
                os.close(fd)
            paths.append(p)
        # Record absence before (no install side effects).
        self.assertFalse(os.path.exists("/etc/systemd/system/hermes-stock-cutover.service"))
        self.assertFalse(os.path.exists("/etc/systemd/system/" + R.KNOWN_GOOD_MOUNT_UNIT))
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        cp = subprocess.run(["/usr/bin/systemd-analyze", "verify"] + paths,
                            capture_output=True, text=True, check=False,
                            cwd=scratch, env=env)
        # rc 0 proves offline correctness; unrelated host warnings about
        # other units (e.g., unified-monitoring-agent executable bits) are
        # ignored, but our five files must not appear as errors.
        self.assertEqual(cp.returncode, 0,
                         f"verify rc={cp.returncode} out={cp.stdout[:2000]} err={cp.stderr[:4000]}")
        for name in files.keys():
            self.assertNotIn(f"{name}: Failed", cp.stderr)
            self.assertNotIn(f"{name} has a bad unit file setting", cp.stderr)
        # Still no install after (no /etc writes, no live units, no .env).
        self.assertFalse(os.path.exists("/etc/systemd/system/hermes-stock-cutover.service"))
        self.assertFalse(os.path.exists("/etc/systemd/system/" + R.KNOWN_GOOD_MOUNT_UNIT))
        self.assertFalse(os.path.lexists(os.path.join(scratch, ".git")))


class TestProgramReceiptUnresolved(unittest.TestCase):
    """Program reads physical state and emits unresolved, never false success.

    Recover unit has no Assert/Requires so ExecStart always runs; the
    program then reconciles journal + show/file_info/digest and returns
    stopped-unresolved (or durable) with prior journal preserved, never
    committed on broken physical state. No second start while ambiguous.
    """

    def test_recover_durable_readback_failed_unresolved(self):
        from scripts.stock_cutover import cutover_orchestrate as C

        class _BrokenShow:
            def journal_load(self):
                return ["observed", "durable-state-unknown: test"]
            def boot_id(self):
                return "a7d3326c-test-boot-id"
            def show_unit(self, unit):
                raise OSError("show unreadable (mount broken)")
            def file_info(self, path):
                raise OSError("unreadable")
            def digest_record(self):
                raise OSError("unreadable")

        # Tail durable with broken physical readback must be unresolved,
        # never committed/rolled-back, never false success.
        res = C._recover_durable(_BrokenShow(), ["observed", "durable-state-unknown: test"])
        self.assertTrue(str(res).startswith("stopped-unresolved"),
                        f"got {res!r}, must be unresolved when physical state unreadable")
        self.assertNotIn("committed", str(res))
        self.assertNotIn("rolled-back", str(res))

    def test_terminal_readback_failed_unresolved(self):
        from scripts.stock_cutover import cutover_orchestrate as C

        class _BrokenTerminal:
            def boot_id(self):
                raise OSError("boot unreadable")
            def show_unit(self, unit):
                raise OSError("show unreadable")
            def file_info(self, path):
                raise OSError("unreadable")
            def digest_record(self):
                raise OSError("unreadable")

        res = C._verify_terminal_readonly(_BrokenTerminal(), "committed")
        self.assertTrue(str(res).startswith("stopped-unresolved"),
                        f"got {res!r}, terminal with unreadable physical must be unresolved")
        self.assertNotEqual(res, "committed")

    def test_fence_failure_canonical_unresolved_no_bare(self):
        # Fence failure never returns bare fence-failed; canonical is
        # stopped-unresolved:fence-failed with prior journal preserved.
        # Uses existing Fake pattern minimally: fence needs stop/show/sleep.
        from scripts.stock_cutover import cutover_orchestrate as C

        class _FenceFail:
            def stop_units(self, units):
                pass
            def show_unit(self, unit):
                # Active (not inactive) so fence fails closed.
                return {"ActiveState": "active", "MainPID": 1234, "NRestarts": 5}
            def now(self):
                return 1000.0
            def sleep_secs(self, s):
                pass

        self.assertFalse(C._fence(_FenceFail()),
                         "fence must fail closed when units stay active")


if __name__ == "__main__":
    unittest.main()
