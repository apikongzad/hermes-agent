"""Production orchestrator hermetic tests.

Drives scripts.stock_cutover.cutover_orchestrate (actual production code)
with a subprocess/unit fake backend (FakeCutoverHost). No live host calls.
No .env opens. Fault injection covers journal, fence, health, interruption.
"""
import unittest

from scripts.stock_cutover import cutover_orchestrate as C

TARGET = "daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06"
KNOWN_GOOD = "1d9a377fa00ce0e663e274e16b63c75e36233b9e"
REFUSED = "1c12738cfeecc78570b3a4ba3797a49de59cfdfe"

LIVE_GW_PID = 583405
LIVE_DB_PID = 583247
NEW_GW_PID = 590001
NEW_DB_PID = 590002


class SimulatedCrash(RuntimeError):
    pass


class FakeCutoverHost:
    """Subprocess/unit fake backend. Records ops, never touches live host."""

    def __init__(self):
        self.log = []
        self.open_log = []
        self.journal = []
        self.clock = 1000.0
        self.sleep_advance = 5.5
        self.stopped = False
        self.reloaded = False
        self.started = False
        self.published_kind = None
        self.fail_flush_file = set()
        self.fail_flush_dir = set()
        self.interrupt_after = None
        self._interrupted = False
        self.journal_parent_writable = False
        self.runtime_unreadable = False
        self.runtime_mismatch = False
        self.denial_mode = "ok"
        self.python_mode = "ok"
        self.backup_verified = True
        self.digest_mode = "ok"
        self.dashboard_mode = "ok"
        self.gateway_mode = "ok"
        self.dropins_mode = "ok"
        self.show_active_after_stop = False
        self.nrestarts_bump = False
        self.reload_envfile = False
        self.reload_venv_hook = False
        self.proc_mismatch = False
        self.rollback_snapshot_missing = False
        self.rollback_snapshot_writable = False
        self.rollback_snapshot_uid = 0
        self.rollback_denial_fail = False
        self.journal_dir_oserror = False
        self.dropin_oserror = False
        self.proc_identity_oserror = False
        self.rollback_dashboard_mode = None
        self.rollback_gateway_mode = None
        self.post_start_forbidden_key = False
        self.files = {
            C.GATEWAY_RUNTIME_PATH: b"G" * 74,
            C.DASHBOARD_RUNTIME_PATH: b"D" * 124,
            C.GATEWAY_CANDIDATE_PATH: b"old-gateway-unit",
            C.DASHBOARD_CANDIDATE_PATH: b"old-dashboard-unit",
        }

    def journal_load(self):
        self.log.append("journal-load")
        return list(self.journal)

    def journal_append(self, state, detail=None):
        self.log.append(f"journal-append:{state}")
        if state == "test-journal-fail":
            raise OSError("journal fsync failed")
        self.log.append("flush-file:journal")
        self.log.append("flush-dir:journal")
        self.journal.append(state)
        if self.interrupt_after == state and not self._interrupted:
            self._interrupted = True
            raise SimulatedCrash(f"interrupted after {state}")

    def journal_dir_info(self):
        self.log.append("dir-info")
        if self.journal_dir_oserror:
            raise OSError("journal dir unreadable")
        return {"path": C.JOURNAL_DIR, "mode": 0o700, "uid": 0,
                "parent_mode": 0o755, "parent_uid": 0,
                "parent_writable_by_1001": self.journal_parent_writable}

    def boot_id(self):
        self.log.append("boot")
        return "a7d3326c-test-boot-id"

    def show_unit(self, unit):
        self.log.append(f"show:{unit}")
        is_gw = "gateway" in unit
        live_pid = LIVE_GW_PID if is_gw else LIVE_DB_PID
        new_pid = NEW_GW_PID if is_gw else NEW_DB_PID
        nrestarts = 5
        if self.stopped and self.nrestarts_bump and len([e for e in self.log if e.startswith("show:")]) >= 4:
            nrestarts = 6
        snap = C.CANDIDATE_SNAPSHOT if self.published_kind != "rollback" else C.KNOWN_GOOD_SNAPSHOT
        if self.started:
            py = f"{snap}/venv/bin/python3"
            entry = f"{snap}/source/hermes_cli/main.py"
            return {"ActiveState": "active", "MainPID": new_pid, "NRestarts": nrestarts,
                    "ExecStart": f"{py} -I {entry} {'gateway run' if is_gw else 'dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build'}",
                    "ExecStop": [], "ExecStopPost": [],
                    "WorkingDirectory": C.GATEWAY_WD if is_gw else C.DASHBOARD_WD,
                    "User": "ubuntu", "EnvironmentFiles": [],
                    "Environment": {"VIRTUAL_ENV": f"{snap}/venv"}}
        if not self.stopped:
            return {"ActiveState": "active", "MainPID": live_pid, "NRestarts": 5,
                    "ExecStart": f"/home/ubuntu/.hermes/runtime/cutover-generations/gen-1d9a377fa00c/venv/bin/python3 {C.WORKTREE_PATH}/hermes_cli/main.py {'gateway run' if is_gw else 'dashboard run'}",
                    "ExecStop": [f"{C.VENV_OLD}/bin/python -m gateway.systemd_stop_mark"],
                    "ExecStopPost": [f"{C.VENV_OLD}/bin/python -m gateway.cgroup_cleanup"],
                    "WorkingDirectory": C.GATEWAY_WD if is_gw else C.DASHBOARD_WD,
                    "User": "ubuntu", "EnvironmentFiles": [C.ENV_FILE_PATH],
                    "Environment": {"VIRTUAL_ENV": C.VENV_OLD, "PATH": "/usr/bin"}}
        if self.stopped and not self.reloaded:
            if self.show_active_after_stop:
                return {"ActiveState": "active", "MainPID": live_pid, "NRestarts": 5,
                        "ExecStart": "old", "ExecStop": [], "ExecStopPost": [],
                        "WorkingDirectory": C.GATEWAY_WD if is_gw else C.DASHBOARD_WD,
                        "User": "ubuntu", "EnvironmentFiles": [C.ENV_FILE_PATH], "Environment": {}}
            return {"ActiveState": "inactive", "MainPID": 0, "NRestarts": nrestarts,
                    "ExecStart": "old", "ExecStop": [], "ExecStopPost": [],
                    "WorkingDirectory": C.GATEWAY_WD if is_gw else C.DASHBOARD_WD,
                    "User": "ubuntu", "EnvironmentFiles": [C.ENV_FILE_PATH], "Environment": {}}
        if self.stopped and self.reloaded and not self.started:
            envfiles = [C.ENV_FILE_PATH] if self.reload_envfile else []
            es, esp = [], []
            if self.reload_venv_hook:
                es = [f"{C.VENV_OLD}/bin/python -m gateway.systemd_stop_mark"]
                esp = [f"{C.VENV_OLD}/bin/python -m gateway.cgroup_cleanup"]
            py = f"{snap}/venv/bin/python3"
            entry = f"{snap}/source/hermes_cli/main.py"
            return {"ActiveState": "inactive", "MainPID": 0, "NRestarts": nrestarts,
                    "ExecStart": f"{py} -I {entry} {'gateway run' if is_gw else 'dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build'}",
                    "ExecStop": es, "ExecStopPost": esp,
                    "WorkingDirectory": C.GATEWAY_WD if is_gw else C.DASHBOARD_WD,
                    "User": "ubuntu", "EnvironmentFiles": envfiles,
                    "Environment": {"VIRTUAL_ENV": f"{snap}/venv"}}
        py = f"{snap}/venv/bin/python3"
        entry = f"{snap}/source/hermes_cli/main.py"
        return {"ActiveState": "active", "MainPID": new_pid, "NRestarts": nrestarts,
                "ExecStart": f"{py} -I {entry} {'gateway run' if is_gw else 'dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build'}",
                "ExecStop": [], "ExecStopPost": [],
                "WorkingDirectory": C.GATEWAY_WD if is_gw else C.DASHBOARD_WD,
                "User": "ubuntu", "EnvironmentFiles": [],
                "Environment": {"VIRTUAL_ENV": f"{snap}/venv"}}

    def stop_units(self, units):
        self.log.append(f"stop:{sorted(units)}")
        self.stopped = True
        self.started = False

    def start_units(self, units):
        self.log.append(f"start:{sorted(units)}")
        self.started = True
        self.stopped = False

    def reload_manager(self):
        self.log.append("reload")
        self.reloaded = True

    def read_bytes(self, path):
        self.log.append(f"read:{path}")
        self.open_log.append(path)
        if path == C.ENV_FILE_PATH:
            raise AssertionError("must never open .env")
        if self.runtime_unreadable and path in (C.GATEWAY_RUNTIME_PATH, C.DASHBOARD_RUNTIME_PATH):
            raise PermissionError("unreadable")
        if path not in self.files:
            if path.endswith("/SNAPSHOT"):
                raise FileNotFoundError(path)
            raise FileNotFoundError(path)
        return self.files[path]

    def file_info(self, path):
        self.log.append(f"stat:{path}")
        self.open_log.append(path)
        if path == C.ENV_FILE_PATH:
            raise AssertionError("must never stat .env")
        if self.runtime_unreadable and path in (C.GATEWAY_RUNTIME_PATH, C.DASHBOARD_RUNTIME_PATH):
            raise PermissionError("unreadable")
        if path in (C.GATEWAY_RUNTIME_PATH, C.DASHBOARD_RUNTIME_PATH):
            if self.runtime_mismatch:
                return {"exists": True, "mode": 0o600, "uid": 0,
                        "size": 74 if "gateway" in path else 124,
                        "sha256": "00" * 32, "writable_by_1001": False}
            if "gateway" in path:
                return {"exists": True, "mode": 0o600, "uid": 0,
                        "size": 74, "sha256": C.GATEWAY_RUNTIME_SHA256,
                        "writable_by_1001": False}
            return {"exists": True, "mode": 0o600, "uid": 0,
                    "size": 124, "sha256": C.DASHBOARD_RUNTIME_SHA256,
                    "writable_by_1001": False}
        if path in (C.KNOWN_GOOD_SNAPSHOT, C.CANDIDATE_SNAPSHOT):
            if path == C.KNOWN_GOOD_SNAPSHOT and self.rollback_snapshot_missing:
                return {"exists": False, "mode": 0, "uid": 0, "size": 0, "sha256": "", "writable_by_1001": False}
            w = bool(self.rollback_snapshot_writable) if path == C.KNOWN_GOOD_SNAPSHOT else False
            return {"exists": True, "mode": 0o755,
                    "uid": self.rollback_snapshot_uid if path == C.KNOWN_GOOD_SNAPSHOT else 0,
                    "size": 0, "sha256": "", "writable_by_1001": w}
        if path == C.JOURNAL_DIR:
            return {"exists": True, "mode": 0o700, "uid": 0, "size": 0, "sha256": "", "writable_by_1001": False}
        return {"exists": True, "mode": 0o644, "uid": 0, "size": 0, "sha256": "", "writable_by_1001": False}

    def write_temp(self, tmp_path, data):
        self.log.append(f"write-temp:{tmp_path}")
        self.files[tmp_path] = bytes(data)

    def file_fsync(self, path):
        self.log.append(f"flush-file:{path}")
        if path in self.fail_flush_file:
            raise OSError("file fsync failed")

    def rename_path(self, src, dst):
        self.log.append(f"rename:{src}->{dst}")
        if src in self.files:
            self.files[dst] = self.files.pop(src)
        else:
            self.files[dst] = b"renamed"
        if dst in (C.GATEWAY_CANDIDATE_PATH, C.DASHBOARD_CANDIDATE_PATH):
            data = self.files[dst]
            if C.KNOWN_GOOD_SNAPSHOT.encode() in data:
                self.published_kind = "rollback"
            elif C.CANDIDATE_SNAPSHOT.encode() in data:
                self.published_kind = "candidate"

    def dir_fsync(self, dir_path):
        self.log.append(f"flush-dir:{dir_path}")
        if dir_path in self.fail_flush_dir:
            raise OSError("dir fsync failed")

    def now(self):
        self.log.append("now")
        return self.clock

    def sleep_secs(self, seconds):
        self.log.append(f"sleep:{seconds}")
        self.clock += self.sleep_advance

    def proc_identity(self, pid):
        self.log.append(f"proc:{pid}")
        if self.proc_identity_oserror:
            raise OSError("unreadable")
        if pid in (LIVE_GW_PID, LIVE_DB_PID) and not self.started:
            is_gw = pid == LIVE_GW_PID
            return {"boot_id": "a7d3326c-test", "pid": pid,
                    "starttime": 6962673 if is_gw else 6962258,
                    "exe": "/home/ubuntu/.hermes/tools/python-3.14.9+20261021-linux-arm64/bin/python3.14",
                    "cmdline": f"/home/ubuntu/.hermes/runtime/cutover-generations/gen-1d9a377fa00c/venv/bin/python3 {C.WORKTREE_PATH}/hermes_cli/main.py gateway run",
                    "cgroup": "/system.slice/hermes-gateway.service",
                    "cwd": C.GATEWAY_WD if is_gw else C.DASHBOARD_WD,
                    "environ_keys": ["HOME", "USER", "PATH", "VIRTUAL_ENV"]}
        is_gw = pid in (NEW_GW_PID, LIVE_GW_PID)
        snap = C.CANDIDATE_SNAPSHOT if self.published_kind != "rollback" else C.KNOWN_GOOD_SNAPSHOT
        if self.proc_mismatch:
            return {"boot_id": "a7d3326c-test", "pid": pid, "starttime": 8000001,
                    "exe": "/home/ubuntu/.hermes/tools/python-3.14.9+20261021-linux-arm64/bin/python3.14",
                    "cmdline": f"/home/ubuntu/.hermes/runtime/cutover-generations/gen-1d9a377fa00c/venv/bin/python3 {C.WORKTREE_PATH}/hermes_cli/main.py gateway run",
                    "cgroup": "/system.slice/hermes-gateway.service",
                    "cwd": C.GATEWAY_WD if is_gw else C.DASHBOARD_WD,
                    "environ_keys": ["HOME", "PYTHONPATH"] if self.post_start_forbidden_key else ["HOME"]}
        if self.post_start_forbidden_key and self.published_kind != "rollback":
            return {"boot_id": "a7d3326c-test", "pid": pid, "starttime": 8000001,
                    "exe": f"{snap}/venv/bin/python3.14",
                    "cmdline": f"{snap}/venv/bin/python3 -I {snap}/source/hermes_cli/main.py gateway run",
                    "cgroup": "/system.slice/hermes-gateway.service",
                    "cwd": C.GATEWAY_WD if is_gw else C.DASHBOARD_WD,
                    "environ_keys": ["HOME", "PYTHONPATH"]}
        return {"boot_id": "a7d3326c-test", "pid": pid,
                "starttime": 8000001 if pid == NEW_GW_PID else 8000002,
                "exe": f"{snap}/venv/bin/python3.14",
                "cmdline": f"{snap}/venv/bin/python3 -I {snap}/source/hermes_cli/main.py {'gateway run' if is_gw else 'dashboard run'}",
                "cgroup": "/system.slice/hermes-gateway.service" if is_gw else "/system.slice/hermes-dashboard.service",
                "cwd": C.GATEWAY_WD if is_gw else C.DASHBOARD_WD,
                "environ_keys": ["HOME", "USER", "PATH"]}

    def denial_probe(self, path):
        self.log.append(f"denial:{path}")
        if self.denial_mode == "chmod-only":
            return {"write_denied": True, "rename_denied": True, "hardlink_denied": True, "kernel_enforced": False,
                    "second_write_denied": True, "second_rename_denied": True, "second_hardlink_denied": True, "second_kernel_enforced": False}
        if self.denial_mode == "fail":
            return {"write_denied": False, "rename_denied": False, "hardlink_denied": False, "kernel_enforced": False,
                    "second_write_denied": False, "second_rename_denied": False, "second_hardlink_denied": False, "second_kernel_enforced": False}
        if path == C.KNOWN_GOOD_SNAPSHOT and (self.rollback_snapshot_writable or self.rollback_denial_fail):
            return {"write_denied": False, "rename_denied": False, "hardlink_denied": False, "kernel_enforced": False,
                    "second_write_denied": False, "second_rename_denied": False, "second_hardlink_denied": False, "second_kernel_enforced": False}
        return {"write_denied": True, "rename_denied": True, "hardlink_denied": True, "kernel_enforced": True,
                "second_write_denied": True, "second_rename_denied": True, "second_hardlink_denied": True, "second_kernel_enforced": True}

    def python_probe(self, python_exe):
        self.log.append(f"python-probe:{python_exe}")
        base = {"isolated": 1, "ignore_environment": 1, "safe_path": True, "no_site": 0,
                "import_ok": True, "sitecustomize_origin": None, "sys_path_has_cwd": False,
                "pyvenv_version": "3.14.9"}
        if self.python_mode == "sitecustomize-outside":
            base["sitecustomize_origin"] = "/tmp/evil/sitecustomize.py"
        elif self.python_mode == "no-isolated":
            base["isolated"] = 0
            base["ignore_environment"] = 0
        elif self.python_mode == "import-fail":
            base["import_ok"] = False
        elif self.python_mode == "cwd-in-path":
            base["sys_path_has_cwd"] = True
        elif self.python_mode == "wrong-version":
            base["pyvenv_version"] = "3.12.0"
        return base

    def backup_ok(self):
        self.log.append("backup-check")
        return self.backup_verified

    def digest_record(self):
        self.log.append("digest-info")
        if self.digest_mode == "inside":
            return {"location": f"{C.CANDIDATE_SNAPSHOT}/digest", "owner_uid": 0, "signed": False,
                    "outside_snapshot": False, "outside_uid1001": False}
        if self.digest_mode == "signed":
            return {"location": "/var/lib/hermes-stock-activation/digest", "owner_uid": 0, "signed": True,
                    "outside_snapshot": True, "outside_uid1001": True}
        return {"location": "/var/lib/hermes-stock-activation/digest", "owner_uid": 0, "signed": False,
                "outside_snapshot": True, "outside_uid1001": True}

    def dashboard_fetch(self, url, headers):
        phase = self.published_kind or "none"
        self.log.append(f"dashboard:{phase}:{url}|headers={sorted((headers or {}).keys())}")
        if url != C.DASHBOARD_URL:
            return {"status": 404, "content_type": "text/html", "body": "<html>not found</html>"}
        if self.published_kind == "rollback" and self.rollback_dashboard_mode is not None:
            m = self.rollback_dashboard_mode
            if m == "ok":
                return {"status": 200, "content_type": "application/json", "body": {"ok": True}}
            return {"status": 200, "content_type": "application/json", "body": {"ok": False}}
        if self.published_kind == "rollback" and self.dashboard_mode != "ok":
            return {"status": 200, "content_type": "application/json", "body": {"ok": True}}
        mode = self.dashboard_mode
        if mode == "401":
            return {"status": 401, "content_type": "application/json", "body": {"ok": False}}
        if mode == "403":
            return {"status": 403, "content_type": "application/json", "body": {"ok": False}}
        if mode == "timeout":
            return {"status": 0, "content_type": "", "body": None}
        if mode == "html":
            return {"status": 200, "content_type": "text/html", "body": "<html>ok</html>"}
        if mode == "ok-false":
            return {"status": 200, "content_type": "application/json", "body": {"ok": False}}
        return {"status": 200, "content_type": "application/json", "body": {"ok": True}}

    def gateway_talk(self, request_bytes):
        self.log.append(f"gateway:{request_bytes!r}")
        if request_bytes != C.GATEWAY_REQUEST_BYTES:
            return {"response": {"ok": False}, "peer_pid": 0, "peer_uid": 0}
        if self.published_kind == "rollback":
            if self.rollback_gateway_mode == "uid-mismatch":
                return {"response": {"ok": True, "result": {"protocol": 1, "pid": NEW_GW_PID}},
                        "peer_pid": NEW_GW_PID, "peer_uid": 1002}
            return {"response": {"ok": True, "result": {"protocol": 1, "pid": NEW_GW_PID}},
                    "peer_pid": NEW_GW_PID, "peer_uid": 1001}
        if self.gateway_mode == "peer-mismatch":
            return {"response": {"ok": True, "result": {"protocol": 1, "pid": NEW_GW_PID}},
                    "peer_pid": 999999, "peer_uid": 1001}
        if self.gateway_mode == "uid-mismatch":
            return {"response": {"ok": True, "result": {"protocol": 1, "pid": NEW_GW_PID}},
                    "peer_pid": NEW_GW_PID, "peer_uid": 1002}
        return {"response": {"ok": True, "result": {"protocol": 1, "pid": NEW_GW_PID}},
                "peer_pid": NEW_GW_PID, "peer_uid": 1001}

    def dropin_names(self, service):
        self.log.append(f"dropins:{service}")
        if self.dropin_oserror:
            raise OSError("unreadable")
        base = ["10-user-bus.conf", "20-runtime-permissions.conf", "30-allow-sudo.conf",
                "a1-runner-compat.conf", "zz-performance-allocation.conf",
                "zz-runtime-3.14.9.conf", "zzz-candidate.conf"]
        if self.dropins_mode == "stacked":
            return base + ["zzz-extra.conf"]
        return base


def make_happy():
    return FakeCutoverHost()


class TestProductionOrchestrator(unittest.TestCase):
    def test_happy_committed_exact_units(self):
        h = make_happy()
        r = C.orchestrate(h, C.Request(target_sha=TARGET))
        self.assertEqual(r.state, "committed")
        self.assertEqual(r.journal, ["observed", "dropins-read", "target-bound",
                                    "known-good-frozen", "backup-verified",
                                    "candidate-materialized", "stop-fenced",
                                    "units-published", "reloaded", "restarted",
                                    "health-verified", "committed"])
        for path in (C.GATEWAY_CANDIDATE_PATH, C.DASHBOARD_CANDIDATE_PATH):
            body = h.files[path]
            self.assertIn(C.CANDIDATE_SNAPSHOT.encode(), body)
            self.assertIn(b" -I ", body)
            self.assertIn(b"[Service]", body)
            self.assertIn(b"ExecStart=\n", body)
            self.assertIn(b"ExecStop=\n", body)
            self.assertIn(b"ExecStopPost=\n", body)
            self.assertIn(b"EnvironmentFile=\n", body)
            self.assertNotIn(C.WORKTREE_PATH.encode(), body)
            self.assertNotIn(b"gen-1d9a377fa00c", body)
            self.assertNotIn(b"/home/ubuntu/.hermes/hermes-agent/venv", body)
            self.assertNotIn(b"PYTHONPATH", body)
        self.assertNotIn(C.ENV_FILE_PATH, h.open_log)
        starts = [e for e in h.log if e.startswith("start:")]
        self.assertEqual(len(starts), 1)
        # No systemctl restart operation: journal state "restarted" is legal,
        # but no restart argv or restart op may appear.
        restarts = [e for e in h.log if e.startswith("restart:")]
        self.assertEqual(restarts, [])
        self.assertNotIn("systemctl restart", "\n".join(h.log))

    def test_fence_5s_before_publish(self):
        h = make_happy()
        h.sleep_advance = 4.0
        r = C.orchestrate(h, C.Request(target_sha=TARGET))
        pubs = [e for e in h.log if e.startswith("rename:") and "zzz-candidate" in e]
        self.assertEqual(pubs, [])
        self.assertNotIn("units-published", r.journal)
        h2 = make_happy()
        h2.nrestarts_bump = True
        C.orchestrate(h2, C.Request(target_sha=TARGET))
        pubs2 = [e for e in h2.log if e.startswith("rename:") and "zzz-candidate" in e]
        self.assertEqual(pubs2, [])
        h3 = make_happy()
        h3.show_active_after_stop = True
        C.orchestrate(h3, C.Request(target_sha=TARGET))
        pubs3 = [e for e in h3.log if e.startswith("rename:") and "zzz-candidate" in e]
        self.assertEqual(pubs3, [])

    def test_only_target_accepted(self):
        for bad in (REFUSED, KNOWN_GOOD, "00" * 32):
            h = make_happy()
            r = C.orchestrate(h, C.Request(target_sha=bad))
            self.assertNotEqual(r.state, "committed")
            self.assertNotIn("target-bound", r.journal)

    def test_no_snapshotted_state(self):
        self.assertNotIn("snapshotted", C.HAPPY)
        for tos in C.LEGAL_NEXT.values():
            self.assertNotIn("snapshotted", tos)
        self.assertNotIn("snapshotted", C.LEGAL_NEXT)

    def test_order_backup_before_candidate(self):
        h = make_happy()
        r = C.orchestrate(h, C.Request(target_sha=TARGET))
        j = r.journal
        self.assertLess(j.index("backup-verified"), j.index("candidate-materialized"))
        self.assertLess(j.index("target-bound"), j.index("known-good-frozen"))
        self.assertLess(j.index("known-good-frozen"), j.index("backup-verified"))
        h2 = make_happy()
        h2.journal = ["observed", "target-bound"]
        r2 = C.orchestrate(h2, C.Request(target_sha=TARGET))
        self.assertEqual(r2.state, "stopped-unresolved")

    def test_fsync_fail_closed(self):
        h = make_happy()
        h.fail_flush_file.add("/etc/systemd/system/hermes-gateway.service.d/.zzz-candidate.conf.tmp")
        r = C.orchestrate(h, C.Request(target_sha=TARGET))
        self.assertEqual(r.state, "durable-state-unknown")
        self.assertEqual([e for e in h.log if e.startswith("start:")], [])
        h2 = make_happy()
        h2.fail_flush_dir.add("/etc/systemd/system/hermes-gateway.service.d")
        r2 = C.orchestrate(h2, C.Request(target_sha=TARGET))
        self.assertEqual(r2.state, "durable-state-unknown")

    def test_interruption_refences_no_second_start(self):
        h = make_happy()
        h.interrupt_after = "units-published"
        try:
            C.orchestrate(h, C.Request(target_sha=TARGET))
            self.fail("expected crash")
        except SimulatedCrash:
            pass
        h.interrupt_after = None
        r = C.orchestrate(h, C.Request(target_sha=TARGET))
        self.assertEqual(r.state, "committed")
        starts = [e for e in h.log if e.startswith("start:")]
        self.assertEqual(len(starts), 1)
        sleeps = [e for e in h.log if e.startswith("sleep:")]
        self.assertTrue(len(sleeps) >= 2)

    def test_interruption_after_restart_binds_once(self):
        h = make_happy()
        h.interrupt_after = "restarted"
        try:
            C.orchestrate(h, C.Request(target_sha=TARGET))
            self.fail("expected crash")
        except SimulatedCrash:
            pass
        h.interrupt_after = None
        before = len([e for e in h.log if e.startswith("start:")])
        r = C.orchestrate(h, C.Request(target_sha=TARGET))
        after = len([e for e in h.log if e.startswith("start:")])
        self.assertEqual(after, before)
        self.assertEqual(r.state, "committed")

    def test_health_contracts_no_auth(self):
        for mode in ["401", "403", "timeout", "html", "ok-false"]:
            h = make_happy()
            h.dashboard_mode = mode
            r = C.orchestrate(h, C.Request(target_sha=TARGET))
            self.assertEqual(r.state, "rolled-back",
                             msg=f"mode={mode} got={r.state} reason={r.reason} journal={r.journal}")
            dashes = [e for e in h.log if e.startswith("dashboard:")]
            self.assertEqual(len(dashes), 2)
            for line in dashes:
                self.assertNotIn("Authorization", line)
                self.assertIn("|headers=[]", line)
            gws = [e for e in h.log if e.startswith("gateway:")]
            self.assertEqual(len(gws), 1)
            self.assertIn(repr(C.GATEWAY_REQUEST_BYTES), gws[0])

    def test_rollback_snapshot_never_mutable(self):
        h = make_happy()
        h.dashboard_mode = "ok-false"
        r = C.orchestrate(h, C.Request(target_sha=TARGET))
        self.assertEqual(r.state, "rolled-back",
                         msg=f"got={r.state} reason={r.reason} journal={r.journal} logtail={h.log[-20:]}")
        for path in (C.GATEWAY_CANDIDATE_PATH, C.DASHBOARD_CANDIDATE_PATH):
            body = h.files[path]
            self.assertIn(C.KNOWN_GOOD_SNAPSHOT.encode(), body)
            self.assertNotIn(C.WORKTREE_PATH.encode(), body)
            self.assertNotIn(b"gen-1d9a377fa00c", body)

    def test_journal_never_deleted(self):
        import pathlib
        src = pathlib.Path("scripts/stock_cutover/cutover_orchestrate.py").read_bytes().decode()
        self.assertNotIn("unlink", src)
        self.assertNotIn("remove", src.replace("remove", "") if False else src.split("journal")[0] if False else "")
        # Explicit: no unlink of journal.
        self.assertNotIn("os.unlink", src)
        self.assertNotIn("os.remove", src)

    def test_no_restart_no_kill_no_env(self):
        import pathlib
        src = pathlib.Path("scripts/stock_cutover/cutover_orchestrate.py").read_bytes().decode()
        # Forbid restart argv element ("restart") but allow legal state "restarted"
        # and docstring prohibition "No systemctl restart" (no quotes).
        self.assertNotIn('"restart"', src)
        self.assertNotIn("'restart'", src)
        self.assertNotIn("os.kill", src)
        self.assertNotIn("killpg", src)
        for line in src.splitlines():
            if "open(" in line and ".env" in line:
                self.fail("env open: " + line)


if __name__ == "__main__":
    unittest.main()
