"""Unit rendering tests. No live effects. Stdlib unittest only."""
import unittest

from scripts.stock_cutover import cutover_units as U


class TestCutoverUnits(unittest.TestCase):
    def test_gateway_exact(self):
        body = U.render_gateway_dropin(U.CANDIDATE_MOUNT)
        text = body.decode()
        self.assertIn("[Service]", text)
        self.assertIn("ExecStart=\n", text)
        self.assertIn("ExecStop=\n", text)
        self.assertIn("ExecStopPost=\n", text)
        self.assertIn("EnvironmentFile=\n", text)
        self.assertIn(U.CANDIDATE_GATEWAY_EXEC, text)
        self.assertIn("python3 -I ", text)
        self.assertIn("WorkingDirectory=/home/ubuntu/.hermes", text)
        self.assertNotIn(U.WORKTREE_PATH, text)
        self.assertNotIn(U.GEN_KNOWN_GOOD, text)
        self.assertNotIn(U.VENV_OLD, text)
        self.assertNotIn(U.ENV_FILE_PATH, text)
        self.assertNotIn("/opt", text)
        self.assertNotIn("PYTHONPATH", text)
        for k in U.FORBIDDEN_LOADER_KEYS:
            self.assertNotIn(k + "=", text)
        self.assertEqual(text.count("ExecStart="), 2)

    def test_dashboard_exact(self):
        body = U.render_dashboard_dropin(U.CANDIDATE_MOUNT)
        text = body.decode()
        self.assertIn(U.CANDIDATE_DASHBOARD_EXEC, text)
        self.assertIn("--port 9119", text)
        self.assertIn("--host 127.0.0.1", text)
        self.assertIn("WorkingDirectory=/home/ubuntu\n", text)
        self.assertIn("EnvironmentFile=\n", text)
        self.assertNotIn("9119/api/health", text)
        self.assertNotIn(U.WORKTREE_PATH, text)
        self.assertNotIn("Authorization", text)
        self.assertEqual(text.count("ExecStart="), 2)

    def test_known_good_mounts(self):
        self.assertEqual(U.KNOWN_GOOD_MOUNT, "/run/hermes-stock-activation/known-good-snap")
        self.assertEqual(U.CANDIDATE_MOUNT, "/run/hermes-stock-activation/candidate-snap")
        gw = U.render_gateway_dropin(U.KNOWN_GOOD_MOUNT)
        self.assertIn(U.KNOWN_GOOD_GATEWAY_EXEC, gw.decode())
        db = U.render_dashboard_dropin(U.KNOWN_GOOD_MOUNT)
        self.assertIn(U.KNOWN_GOOD_DASHBOARD_EXEC, db.decode())
        self.assertNotIn("gen-1d9a377fa00c", gw.decode())
        self.assertNotIn("gen-1d9a377fa00c", db.decode())

    def test_validate_rejects_forbidden(self):
        good = U.render_gateway_dropin(U.CANDIDATE_MOUNT)
        self.assertTrue(U.validate_dropin_bytes(good, U.CANDIDATE_MOUNT, U.GATEWAY_WD))
        bad = good.replace(b"EnvironmentFile=", b"EnvironmentFile=/home/ubuntu/.hermes/.env")
        with self.assertRaises(ValueError):
            U.validate_dropin_bytes(bad, U.CANDIDATE_MOUNT, U.GATEWAY_WD)
        bad2 = good + b'Environment="PYTHONPATH=/tmp"\n'
        with self.assertRaises(ValueError):
            U.validate_dropin_bytes(bad2, U.CANDIDATE_MOUNT, U.GATEWAY_WD)
        bad3 = good.replace(b"python3 -I", b"python3")
        with self.assertRaises(ValueError):
            U.validate_dropin_bytes(bad3, U.CANDIDATE_MOUNT, U.GATEWAY_WD)


if __name__ == "__main__":
    unittest.main()
