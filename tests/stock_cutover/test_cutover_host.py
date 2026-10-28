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


if __name__ == "__main__":
    unittest.main()
