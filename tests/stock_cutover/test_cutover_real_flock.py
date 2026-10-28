"""§10 real-fixture process tests. Stdlib unittest only.

Uses actual production entry points (RealCutoverHost + cutover_orchestrate)
with temp 0700 fixture roots (real O_NOFOLLOW files, real kernel flock,
real processes, real SIGKILL, real AF_UNIX peercred where noted). No live
systemctl/mount/root writes, no .env reads: unit ops via injected fixed
runner (no live effects), runtime digests stubbed happy (parent already
verified root readonly preflight), gateway happy stubbed except one real
socket negative test (existing). Exported CLI via subprocess temp HOME
scratch, no .git, adversarial sibling still refused.
"""
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from scripts.stock_cutover import cutover_host as H
from scripts.stock_cutover import cutover_orchestrate as C
from scripts.stock_cutover import cutover_recovery as R


def _home_scratch(prefix):
    home = os.path.expanduser("~")
    assert os.path.isabs(home) and not home.startswith("/tmp"), home
    base = os.path.join(home, "cutover-real-tests")
    os.makedirs(base, mode=0o700, exist_ok=True)
    d = tempfile.mkdtemp(prefix=prefix, dir=base)
    assert not os.path.normpath(d).startswith("/tmp"), d
    os.chmod(d, 0o700)
    return d


def _fixture_root(prefix):
    root = _home_scratch(prefix)
    jd = os.path.join(root, "journal")
    os.makedirs(jd, mode=0o700, exist_ok=False)
    os.chmod(jd, 0o700)
    bd = os.path.join(root, "backing")
    os.makedirs(bd, mode=0o700, exist_ok=False)
    dd = os.path.join(root, "dropins")
    os.makedirs(dd, mode=0o700, exist_ok=False)
    return root


def _write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        off = 0
        view = bytes(data)
        while off < len(view):
            n = os.write(fd, view[off:])
            if n == 0:
                raise OSError("short write")
            off += n
        os.fsync(fd)
    finally:
        os.close(fd)


def _append_log(path, line):
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass


def _read_lines(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [l.strip() for l in f.read().splitlines() if l.strip()]
    except FileNotFoundError:
        return []


class _FixtureRunner:
    """Injected fixed runner: no live systemctl/sudo/mount. Records
    stop/start/sleep/show to shared filesystem logs for cross-process
    verification. Returns canned happy show/findmnt/denial, exact argv
    shape, zero extra, no restart, no PYTHONPATH.
    """

    def __init__(self, fixture_root, starts_log=None, fences_log=None):
        self.calls = []
        self.root = fixture_root
        self.starts_log = starts_log or os.path.join(fixture_root, "starts.log")
        self.fences_log = fences_log or os.path.join(fixture_root, "fences.log")
        # In-memory state per process (stopped/reloaded/started/published).
        # Journal file (real) is the cross-process truth for resume;
        # runner state is per-process fence/start shape only.
        self._stopped = False
        self._reloaded = False
        self._started = False
        self._published = False

    def _show_text(self, unit):
        is_gw = "gateway" in unit
        # Published kind shared via filesystem for cross-process resume:
        # rollback publishes known-good snapshot, candidate publishes candidate.
        try:
            with open(os.path.join(self.root, "published_kind"), "r", encoding="utf-8") as f:
                pk = f.read().strip()
        except OSError:
            pk = "candidate" if (self._started or self._reloaded) else "none"
        if pk == "rollback":
            snap = C.KNOWN_GOOD_SNAPSHOT
        else:
            snap = C.CANDIDATE_SNAPSHOT
        py = f"{snap}/venv/bin/python3"
        entry = f"{snap}/source/hermes_cli/main.py"
        cand_exec = (f"{py} -I {entry} "
                     f"{'gateway run' if is_gw else 'dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build'}")
        wd = C.GATEWAY_WD if is_gw else C.DASHBOARD_WD
        if is_gw:
            drops = " ".join([
                f"/etc/systemd/system/{unit}.d/10-user-bus.conf",
                f"/etc/systemd/system/{unit}.d/20-runtime-permissions.conf",
                f"/etc/systemd/system/{unit}.d/30-allow-sudo.conf",
                f"/etc/systemd/system.control/{unit}.d/50-CPUQuota.conf",
                f"/etc/systemd/system.control/{unit}.d/50-MemoryHigh.conf",
                f"/etc/systemd/system.control/{unit}.d/50-MemoryMax.conf",
                f"/etc/systemd/system/{unit}.d/a1-runner-compat.conf",
                f"/etc/systemd/system/{unit}.d/zz-performance-allocation.conf",
                f"/etc/systemd/system/{unit}.d/zz-runtime-3.14.9.conf",
                f"/etc/systemd/system/{unit}.d/zzz-candidate.conf",
            ])
        else:
            drops = " ".join([
                f"/etc/systemd/system/{unit}.d/20-runtime-permissions.conf",
                f"/etc/systemd/system.control/{unit}.d/50-CPUQuota.conf",
                f"/etc/systemd/system.control/{unit}.d/50-MemoryHigh.conf",
                f"/etc/systemd/system.control/{unit}.d/50-MemoryMax.conf",
                f"/etc/systemd/system/{unit}.d/zz-loopback-binding.conf",
                f"/etc/systemd/system/{unit}.d/zz-runtime-3.14.9.conf",
                f"/etc/systemd/system/{unit}.d/zzz-candidate.conf",
            ])
        # In-memory flags first (same-process fence/start shape).
        if self._started:
            return (f"Id={unit}\nActiveState=active\nSubState=running\n"
                    f"MainPID={590001 if is_gw else 590002}\nNRestarts=5\n"
                    f"ExecStart={cand_exec}\nExecStop=\nExecStopPost=\n"
                    f"User=ubuntu\nWorkingDirectory={wd}\n"
                    f"Environment=VIRTUAL_ENV={snap}/venv\nEnvironmentFiles=\n"
                    f"FragmentPath=/etc/systemd/system/{unit}\nDropInPaths={drops}\n")
        if self._stopped and self._reloaded:
            return (f"Id={unit}\nActiveState=inactive\nSubState=dead\n"
                    f"MainPID=0\nNRestarts=5\n"
                    f"ExecStart={cand_exec}\nExecStop=\nExecStopPost=\n"
                    f"User=ubuntu\nWorkingDirectory={wd}\n"
                    f"Environment=VIRTUAL_ENV={snap}/venv\nEnvironmentFiles=\n"
                    f"FragmentPath=/etc/systemd/system/{unit}\nDropInPaths={drops}\n")
        if self._stopped:
            return (f"Id={unit}\nActiveState=inactive\nSubState=dead\n"
                    f"MainPID=0\nNRestarts=5\nExecStart=old\n"
                    f"ExecStop=\nExecStopPost=\n"
                    f"User=ubuntu\nWorkingDirectory={wd}\n"
                    f"Environment=VIRTUAL_ENV={snap}/venv\nEnvironmentFiles=\n"
                    f"FragmentPath=/etc/systemd/system/{unit}\nDropInPaths={drops}\n")
        # Initial in-memory (no fence/start yet in this process): reflect
        # cross-process physical state via shared filesystem logs (holder may
        # have stopped/started before SIGKILL). Journal file is the truth for
        # resume, but show must match physical: stopped (inactive) if stops>
        # starts, active NEW if starts>=stops>0, else live old.
        try:
            with open(os.path.join(self.root, "starts.log"), "r", encoding="utf-8") as _f:
                _starts = len([l for l in _f.read().splitlines() if l.strip() == "start"])
        except OSError:
            _starts = 0
        try:
            with open(os.path.join(self.root, "fences.log"), "r", encoding="utf-8") as _f:
                _stops = len([l for l in _f.read().splitlines() if l.strip() == "stop"])
        except OSError:
            _stops = 0
        if _starts >= 1 and _stops <= _starts:
            # Units active with published snapshot (candidate or rollback via pk file).
            return (f"Id={unit}\nActiveState=active\nSubState=running\n"
                    f"MainPID={590001 if is_gw else 590002}\nNRestarts=5\n"
                    f"ExecStart={cand_exec}\nExecStop=\nExecStopPost=\n"
                    f"User=ubuntu\nWorkingDirectory={wd}\n"
                    f"Environment=VIRTUAL_ENV={snap}/venv\nEnvironmentFiles=\n"
                    f"FragmentPath=/etc/systemd/system/{unit}\nDropInPaths={drops}\n")
        if _stops > _starts:
            return (f"Id={unit}\nActiveState=inactive\nSubState=dead\n"
                    f"MainPID=0\nNRestarts=5\nExecStart=old\n"
                    f"ExecStop=\nExecStopPost=\n"
                    f"User=ubuntu\nWorkingDirectory={wd}\n"
                    f"Environment=VIRTUAL_ENV={snap}/venv\nEnvironmentFiles=\n"
                    f"FragmentPath=/etc/systemd/system/{unit}\nDropInPaths={drops}\n")
        # Live active old (pre-fence).
        return (f"Id={unit}\nActiveState=active\nSubState=running\n"
                f"MainPID={583405 if is_gw else 583247}\nNRestarts=5\n"
                f"ExecStart=old-live\nExecStop=\nExecStopPost=\n"
                f"User=ubuntu\nWorkingDirectory={wd}\n"
                f"Environment=VIRTUAL_ENV=/tmp/old\nEnvironmentFiles=\n"
                f"FragmentPath=/etc/systemd/system/{unit}\nDropInPaths={drops}\n")

    def __call__(self, argv, timeout=60):
        self.calls.append(list(argv))
        import subprocess as _sp
        if not H._is_allowed_fixed_argv(argv):
            raise AssertionError(f"not allowlisted: {argv!r}")
        for el in argv:
            assert el != "restart"
        assert "PYTHONPATH" not in " ".join(argv)
        if argv[0] == "/usr/bin/sudo" and "-u" in argv:
            return _sp.CompletedProcess(argv, 0, "30\n", "")
        if argv[0] == "/usr/bin/findmnt":
            mp = argv[-1]
            return _sp.CompletedProcess(argv, 0, f"squashfs ro /dev/loop20 {mp}", "")
        if argv[:9] == H.G3_PREFIX:
            tail = argv[9:]
            if tail[0] == "/usr/bin/systemctl" and tail[1] == "stop":
                self._stopped = True
                self._started = False
                _append_log(self.fences_log, "stop")
                return _sp.CompletedProcess(argv, 0, "", "")
            if tail[0] == "/usr/bin/systemctl" and tail[1] == "start":
                self._started = True
                self._stopped = False
                _append_log(self.starts_log, "start")
                return _sp.CompletedProcess(argv, 0, "", "")
            if tail[0] == "/usr/bin/systemctl" and tail[1] == "daemon-reload":
                self._reloaded = True
                return _sp.CompletedProcess(argv, 0, "", "")
            if tail[0].endswith("sleep"):
                _append_log(self.fences_log, "sleep:5")
                return _sp.CompletedProcess(argv, 0, "", "")
            if "show" in argv:
                unit = argv[-1]
                if unit not in ("hermes-gateway.service", "hermes-dashboard.service"):
                    unit = "hermes-gateway.service"
                return _sp.CompletedProcess(argv, 0, self._show_text(unit), "")
        raise AssertionError(f"unexpected argv: {argv!r}")


def _real_dropins_for(service):
    # Real shapes: gateway 10, dashboard 7, with system.control prefix.
    if "gateway" in service:
        return [
            "/etc/systemd/system/hermes-gateway.service.d/10-user-bus.conf",
            "/etc/systemd/system/hermes-gateway.service.d/20-runtime-permissions.conf",
            "/etc/systemd/system/hermes-gateway.service.d/30-allow-sudo.conf",
            "/etc/systemd/system.control/hermes-gateway.service.d/50-CPUQuota.conf",
            "/etc/systemd/system.control/hermes-gateway.service.d/50-MemoryHigh.conf",
            "/etc/systemd/system.control/hermes-gateway.service.d/50-MemoryMax.conf",
            "/etc/systemd/system/hermes-gateway.service.d/a1-runner-compat.conf",
            "/etc/systemd/system/hermes-gateway.service.d/zz-performance-allocation.conf",
            "/etc/systemd/system/hermes-gateway.service.d/zz-runtime-3.14.9.conf",
            "/etc/systemd/system/hermes-gateway.service.d/zzz-candidate.conf",
        ]
    return [
        "/etc/systemd/system/hermes-dashboard.service.d/20-runtime-permissions.conf",
        "/etc/systemd/system.control/hermes-dashboard.service.d/50-CPUQuota.conf",
        "/etc/systemd/system.control/hermes-dashboard.service.d/50-MemoryHigh.conf",
        "/etc/systemd/system.control/hermes-dashboard.service.d/50-MemoryMax.conf",
        "/etc/systemd/system/hermes-dashboard.service.d/zz-loopback-binding.conf",
        "/etc/systemd/system/hermes-dashboard.service.d/zz-runtime-3.14.9.conf",
        "/etc/systemd/system/hermes-dashboard.service.d/zzz-candidate.conf",
    ]


def _make_real_host(fixture_root, runner=None, gateway_sock=None,
                     gateway_pointer=None, extra=None):
    jd = os.path.join(fixture_root, "journal")
    jp = os.path.join(jd, "journal")
    lp = os.path.join(jd, "journal.lock")
    if runner is None:
        runner = _FixtureRunner(fixture_root)
    host = H.RealCutoverHost(
        runner=runner,
        gateway_sock=gateway_sock or os.path.join(fixture_root, "gw.sock"),
        gateway_pointer=gateway_pointer or os.path.join(fixture_root, "gw.sock.ptr"),
        journal_dir=jd, journal_path=jp, journal_lock_path=lp)
    # Fake clock for fast 5s fence (no real 5s sleep in worker).
    host._fake_clock = [1000.0]

    def _fake_now():
        return host._fake_clock[0]

    def _fake_sleep(s):
        if s != 5:
            raise ValueError("sleep fixed 5")
        # Runner already recorded sleep:5 via G3 sleep argv; advance clock.
        host._fake_clock[0] += 5.5

    host.now = _fake_now
    # Wrap runner sleep to advance clock: runner.__call__ already logs
    # sleep:5, but need to advance clock. Patch sleep_secs to use fake.
    _orig_sleep = host.sleep_secs

    def _wrap_sleep(s):
        # Call runner path (records sleep:5, no live effects) then advance.
        # Use host._runner directly to avoid double clock logic.
        import subprocess as _sp
        argv = H.sleep_argv()
        done = host._runner(argv, timeout=60)
        rc = getattr(done, "returncode", None)
        if rc != 0:
            raise OSError(f"sleep failed rc={rc!r}")
        host._fake_clock[0] += 5.5

    host.sleep_secs = _wrap_sleep
    # Happy stubs for runtime-only areas (parent already verified root
    # readonly preflight; worker never touches live /var/lib or /etc
    # backing images). Real journal/lock/files remain real temp files.
    def _happy_file_info(path):
        # Real temp journal/lock/backing/dropins use real OS; production
        # runtime/digest/image paths stubbed happy (no live root reads).
        s = str(path)
        if s.startswith(fixture_root):
            return host.__class__.file_info(host, path)
        if path in (C.GATEWAY_RUNTIME_PATH, C.DASHBOARD_RUNTIME_PATH):
            is_gw = "gateway" in s
            return {"exists": True, "mode": 0o600, "uid": 0,
                    "size": 74 if is_gw else 124,
                    "sha256": (C.GATEWAY_RUNTIME_SHA256 if is_gw
                               else C.DASHBOARD_RUNTIME_SHA256),
                    "writable_by_1001": False}
        # Images/digests: exact pins, root-owned 0400 (measured, not caller True).
        if "backing" in s or "digest" in s:
            # Backing markers under temp fixture use real OS above (startswith fixture_root).
            # Production image/digest paths stubbed happy with exact pins.
            if "known-good" in s:
                pin = H.KNOWN_GOOD_IMAGE_SHA
            elif "candidate" in s:
                pin = H.CANDIDATE_IMAGE_SHA
            else:
                pin = H.KNOWN_GOOD_IMAGE_SHA
            return {"exists": True, "mode": 0o400, "uid": 0, "size": 1,
                    "sha256": pin, "writable_by_1001": False}
        # Known-good/candidate snapshots (/run/...): real OS (worker can stat
        # read-only mounts) or happy fallback.
        try:
            return host.__class__.file_info(host, path)
        except OSError:
            return {"exists": True, "mode": 0o755, "uid": 0, "size": 0,
                    "sha256": "", "writable_by_1001": False}

    host.file_info = _happy_file_info

    def _happy_read_bytes(path):
        s = str(path)
        if s.startswith(fixture_root):
            return host.__class__.read_bytes(host, path)
        # Prior bytes for /etc dropins: old unit bytes (not snapshot).
        return b"old-unit-bytes-prior"

    host.read_bytes = _happy_read_bytes

    def _happy_write_temp(tmp_path, data):
        s = str(tmp_path)
        if s.startswith(fixture_root):
            return host.__class__.write_temp(host, tmp_path, data)
        # Production tmp (worker cannot write live): redirect to temp
        # fixture with real O_EXCL|O_NOFOLLOW for hermetic test.
        if ".zzz-candidate.conf.tmp" in s:
            # Distinct gateway vs dashboard tmp to avoid collision.
            if "gateway" in s:
                alt = os.path.join(fixture_root, "dropins", "gateway-tmp.conf.tmp")
            else:
                alt = os.path.join(fixture_root, "dropins", "dashboard-tmp.conf.tmp")
            try:
                os.unlink(alt)
            except OSError:
                pass
            return host.__class__.write_temp(host, alt, data)
        if "backing" in s and s.endswith(".tmp"):
            base = os.path.basename(s)
            alt = os.path.join(fixture_root, "backing", base)
            try:
                os.unlink(alt)
            except OSError:
                pass
            return host.__class__.write_temp(host, alt, data)
        # Any other production tmp: refuse live write in worker test.
        raise OSError("refused live write in worker test")

    # Keep original for publication fault tests to wrap.
    host._real_write_temp = host.__class__.write_temp.__get__(host, host.__class__)
    host.write_temp = _happy_write_temp

    def _happy_rename(src, dst):
        ss, ds = str(src), str(dst)
        if ss.startswith(fixture_root) and ds.startswith(fixture_root):
            # Detect publish kind from data for cross-process show.
            try:
                _d = host.__class__.read_bytes(host, src)
            except OSError:
                _d = b""
            try:
                if C.KNOWN_GOOD_SNAPSHOT.encode() in bytes(_d):
                    with open(os.path.join(fixture_root, "published_kind"), "w", encoding="utf-8") as _f:
                        _f.write("rollback")
                elif C.CANDIDATE_SNAPSHOT.encode() in bytes(_d):
                    with open(os.path.join(fixture_root, "published_kind"), "w", encoding="utf-8") as _f:
                        _f.write("candidate")
            except OSError:
                pass
            return host.__class__.rename_path(host, src, dst)
        if "zzz-candidate" in ds and ".zzz-candidate.conf.tmp" in ss:
            # Publish: production tmp was redirected to temp gateway/dashboard
            # tmp by write_temp. Read alt for real data, write final published
            # files + published_kind, unlink alt. No live /etc writes.
            if "gateway" in ss or "gateway" in ds:
                alt = os.path.join(fixture_root, "dropins", "gateway-tmp.conf.tmp")
            else:
                alt = os.path.join(fixture_root, "dropins", "dashboard-tmp.conf.tmp")
            try:
                data = host.__class__.read_bytes(host, alt)
            except OSError:
                data = b"published-bytes"
            try:
                if C.KNOWN_GOOD_SNAPSHOT.encode() in bytes(data):
                    with open(os.path.join(fixture_root, "published_kind"), "w", encoding="utf-8") as _f:
                        _f.write("rollback")
                elif C.CANDIDATE_SNAPSHOT.encode() in bytes(data):
                    with open(os.path.join(fixture_root, "published_kind"), "w", encoding="utf-8") as _f:
                        _f.write("candidate")
            except OSError:
                pass
            if "gateway" in ds:
                final = os.path.join(fixture_root, "dropins", "gateway-published.conf")
            else:
                final = os.path.join(fixture_root, "dropins", "dashboard-published.conf")
            try:
                host.__class__.write_temp(host, final, data)
            except OSError:
                tmp2 = final + ".tmp2"
                try:
                    os.unlink(tmp2)
                except OSError:
                    pass
                host.__class__.write_temp(host, tmp2, data)
                host.__class__.rename_path(host, tmp2, final)
            try:
                os.unlink(alt)
            except OSError:
                pass
            return
        if "known-good-frozen-marker" in ds or "candidate-materialized-marker" in ds:
            # Backing markers: production tmp redirected to temp backing tmp.
            # Read alt tmp for real data, write temp marker, unlink tmp.
            base_tmp = os.path.basename(ss)
            alt_tmp = os.path.join(fixture_root, "backing", base_tmp)
            try:
                data = host.__class__.read_bytes(host, alt_tmp)
            except OSError:
                data = b"marker"
            base = os.path.basename(ds)
            alt = os.path.join(fixture_root, "backing", base)
            try:
                try:
                    os.unlink(alt)
                except OSError:
                    pass
                host.__class__.write_temp(host, alt, data)
            except OSError:
                pass
            try:
                os.unlink(alt_tmp)
            except OSError:
                pass
            return
        # Any other production rename: refuse live writes in worker test.
        if ss.startswith("/etc/") or ss.startswith("/var/lib/") or ss.startswith("/run/") \
                or ds.startswith("/etc/") or ds.startswith("/var/lib/") or ds.startswith("/run/"):
            raise OSError("refused live rename in worker test")
        return host.__class__.rename_path(host, src, dst)

    host.rename_path = _happy_rename

    def _happy_file_fsync(path):
        if str(path).startswith(fixture_root):
            return host.__class__.file_fsync(host, path)
        # Production /etc tmp fsync: no-op happy (real temp already fsynced).
        return

    host.file_fsync = _happy_file_fsync

    def _happy_dir_fsync(d):
        if str(d).startswith(fixture_root):
            return host.__class__.dir_fsync(host, d)
        return

    host.dir_fsync = _happy_dir_fsync
    if extra:
        for k, v in extra.items():
            setattr(host, k, v)
    return host, runner


class TestTwoContendersRealFlock(unittest.TestCase):
    def test_two_processes_one_holds_other_lock_held(self):
        import multiprocessing as _mp
        root = _fixture_root("contend-")
        jd = os.path.join(root, "journal")
        lp = os.path.join(jd, "journal.lock")
        jp = os.path.join(jd, "journal")
        # Parent acquires via real flock, retained FD.
        host_p, _ = _make_real_host(root)
        self.assertTrue(host_p.lock_acquire(target_sha=C.TARGET_SHA))
        # Lock file 0600, parent 0700, real O_NOFOLLOW, retained FD.
        st = os.lstat(lp)
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
        jdst = os.lstat(jd)
        self.assertEqual(stat.S_IMODE(jdst.st_mode), 0o700)
        # Child attempts same lock path: must get lock-held, zero mutation.
        def _child_try(lock_path, journal_dir, journal_path, q):
            try:
                h, _ = _make_real_host(os.path.dirname(journal_dir))
                # Re-point to same fixture (dirname is root).
                # _make_real_host expects fixture_root; journal_dir parent is root.
                # Ensure same paths (host already uses jd/jp/lp via root).
                h.lock_acquire(target_sha=C.TARGET_SHA)
                q.put(("acquired-unexpected", None))
            except OSError as e:
                q.put(("held" if "lock-held" in str(e) else f"other:{e}", str(e)))
            except Exception as e:
                q.put((f"exc:{type(e).__name__}", str(e)))

        # Use fork: child inherits parent FD (same description, already locked).
        # To test contention, child must use a NEW host (new FD, separate open)
        # after fork. Our _child_try creates new host, so new open -> EWOULDBLOCK.
        ctx = _mp.get_context("fork")
        q = ctx.Queue()
        # Need fixture root for child: root contains journal dir.
        # Child will create host via _make_real_host(root) (same temp paths).
        def _child_entry(q2):
            try:
                h2, _ = _make_real_host(root)
                h2.lock_acquire(target_sha=C.TARGET_SHA)
                q2.put("acquired-unexpected")
            except OSError as e:
                if "lock-held" in str(e):
                    q2.put("lock-held")
                else:
                    q2.put(f"other:{e}")
            except Exception as e:
                q2.put(f"exc:{e}")

        p = ctx.Process(target=_child_entry, args=(q,))
        p.start()
        p.join(timeout=10)
        self.assertFalse(p.is_alive(), "child hung")
        try:
            res = q.get_nowait()
        except Exception as e:
            self.fail(f"no child result: {e}")
        self.assertEqual(res, "lock-held")
        # Journal preserved (empty, no append without authority), lock retained
        # with parent owner, no deletion.
        self.assertFalse(os.path.lexists(jp) and os.path.getsize(jp) > 0 if os.path.lexists(jp) else False)
        cur = host_p.lock_info()
        self.assertIsInstance(cur, dict)
        self.assertEqual(cur.get("pid"), os.getpid())
        # Release by close only: retained file, never deleted.
        host_p.lock_release()
        self.assertTrue(os.path.lexists(lp))
        # Successor can now acquire (death/release vacates via FD close, no unlink).
        host2, _ = _make_real_host(root)
        self.assertTrue(host2.lock_acquire(target_sha=C.TARGET_SHA))
        host2.lock_release()
        self.assertTrue(os.path.lexists(lp))


class TestOwnerAndPublicationFsyncFault(unittest.TestCase):
    def test_owner_fsync_fault_durable_no_start(self):
        # Narrow interior fault: patch os.fsync (owner-record fsync inside
        # the REAL lock_acquire), not the whole method. Proves actual
        # owner-record EIO maps to durable-state-unknown with zero start,
        # lock file retained (no unlink), journal preserved, and clean
        # restore of os.fsync afterwards.
        root = _fixture_root("ownerfault-")
        host, runner = _make_real_host(root)
        jd = os.path.join(root, "journal")
        lp = os.path.join(jd, "journal.lock")
        jp = os.path.join(jd, "journal")
        import os as _os
        _orig_fsync = _os.fsync
        _calls = []

        def _fault_fsync(fd):
            # Targeted: fail the owner-record fsync inside lock_acquire.
            # First fsync during acquire is the owner write (SAME locked FD);
            # raising here must yield owner-fsync-failed -> durable, no start.
            _calls.append(int(fd) if isinstance(fd, int) else fd)
            raise OSError("injected owner EIO")

        _os.fsync = _fault_fsync
        try:
            r = C.orchestrate(host, C.Request(target_sha=C.TARGET_SHA))
        finally:
            # Clean state: restore real fsync even on failure.
            _os.fsync = _orig_fsync
        self.assertEqual(r.state, "durable-state-unknown")
        self.assertEqual([c for c in runner.calls if "start" in " ".join(c)], [])
        # Interior patch actually ran (owner fsync attempted, not stubbed away).
        self.assertGreaterEqual(len(_calls), 1)
        # Lock file retained (no unlink in any path), journal preserved
        # (empty, never deleted), fsync restored.
        self.assertTrue(os.path.lexists(lp), "lock retained, no unlink on fsync fault")
        self.assertTrue(_os.fsync is _orig_fsync, "fsync restored clean")
        if os.path.lexists(jp):
            # Prior legal tail preserved (empty here), never bare fence-failed.
            with open(jp, "rb") as f:
                raw = f.read().decode("utf-8", "replace")
            self.assertNotIn("fence-failed", raw)

    def test_publication_fsync_fault_durable_no_start(self):
        root = _fixture_root("pubfault-")
        host, runner = _make_real_host(root)
        # Happy stubs for denial/python/digest/dropins/backup/health/identity.
        host.denial_probe = lambda p: {"write_denied": True, "rename_denied": True,
                                       "hardlink_denied": True, "kernel_enforced": True,
                                       "second_write_denied": True, "second_rename_denied": True,
                                       "second_hardlink_denied": True, "second_kernel_enforced": True}
        host.python_probe = lambda e: {"isolated": 1, "ignore_environment": 1,
                                       "safe_path": True, "no_site": 0, "import_ok": True,
                                       "sitecustomize_origin": None, "sys_path_has_cwd": False,
                                       "pyvenv_version": "3.14.9"}
        host.backup_ok = lambda: True
        host.digest_record = lambda: {"location": "x", "owner_uid": 0, "owner": 0,
                                      "signed": False, "outside_snapshot": True,
                                      "outside_uid1001": True,
                                      "known_good_image_sha": H.KNOWN_GOOD_IMAGE_SHA,
                                      "candidate_image_sha": H.CANDIDATE_IMAGE_SHA,
                                      "known_good_manifest": H.KNOWN_GOOD_IMAGE_SHA,
                                      "candidate_manifest": H.CANDIDATE_IMAGE_SHA,
                                      "known_good_sha": H.KNOWN_GOOD_IMAGE_SHA,
                                      "candidate_sha": H.CANDIDATE_IMAGE_SHA}
        host.dropin_names = lambda s: _real_dropins_for(s)
        host.proc_identity = lambda pid: {"boot_id": host.boot_id(), "pid": pid,
                                          "starttime": 8000001 if pid == 590001 else 8000002,
                                          "exe": f"{C.CANDIDATE_SNAPSHOT}/venv/bin/python3.14",
                                          "cmdline": (f"{C.CANDIDATE_SNAPSHOT}/venv/bin/python3 -I "
                                                      f"{C.CANDIDATE_SNAPSHOT}/source/hermes_cli/main.py "
                                                      f"{'gateway run' if pid == 590001 else 'dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build'}"),
                                          "cgroup": "/system.slice/hermes-gateway.service" if pid == 590001 else "/system.slice/hermes-dashboard.service",
                                          "cwd": C.GATEWAY_WD if pid == 590001 else C.DASHBOARD_WD,
                                          "environ_keys": ["HOME"]}
        host.dashboard_fetch = lambda u, h: {"status": 200, "content_type": "application/json",
                                             "body": {"ok": True}}
        host.gateway_talk = lambda b: {"response": {"ok": True, "result": {"protocol": 1, "pid": 590001}},
                                       "peer_pid": 590001, "peer_uid": 1001}
        # Publication fault: file_fsync raises for publish tmp (real temp files).
        _orig_fsync = host.file_fsync

        def _fault_fsync(path):
            raise OSError("file fsync failed")

        host.file_fsync = _fault_fsync
        r = C.orchestrate(host, C.Request(target_sha=C.TARGET_SHA))
        self.assertEqual(r.state, "durable-state-unknown")
        starts = [c for c in runner.calls if len(c) > 10 and c[9:11] == ["/usr/bin/systemctl", "start"]]
        self.assertEqual(starts, [])


class TestHealthRollbackRealFixture(unittest.TestCase):
    def _happy_stubs(self, host, fixture_root, dashboard_mode="ok"):
        # dashboard_mode: "ok" always ok, "fail_once" candidate fail then rollback ok,
        # "fail_always" both fail (rollback fail -> stopped).
        host.denial_probe = lambda p: {"write_denied": True, "rename_denied": True,
                                       "hardlink_denied": True, "kernel_enforced": True,
                                       "second_write_denied": True, "second_rename_denied": True,
                                       "second_hardlink_denied": True, "second_kernel_enforced": True}
        host.python_probe = lambda e: {"isolated": 1, "ignore_environment": 1,
                                       "safe_path": True, "no_site": 0, "import_ok": True,
                                       "sitecustomize_origin": None, "sys_path_has_cwd": False,
                                       "pyvenv_version": "3.14.9"}
        host.backup_ok = lambda: True
        host.digest_record = lambda: {"location": "x", "owner_uid": 0, "owner": 0,
                                      "signed": False, "outside_snapshot": True,
                                      "outside_uid1001": True,
                                      "known_good_image_sha": H.KNOWN_GOOD_IMAGE_SHA,
                                      "candidate_image_sha": H.CANDIDATE_IMAGE_SHA,
                                      "known_good_manifest": H.KNOWN_GOOD_IMAGE_SHA,
                                      "candidate_manifest": H.CANDIDATE_IMAGE_SHA,
                                      "known_good_sha": H.KNOWN_GOOD_IMAGE_SHA,
                                      "candidate_sha": H.CANDIDATE_IMAGE_SHA}
        host.dropin_names = lambda s: _real_dropins_for(s)

        def _proc(pid):
            try:
                with open(os.path.join(fixture_root, "published_kind"), "r", encoding="utf-8") as _f:
                    pk = _f.read().strip()
            except OSError:
                pk = "candidate"
            snap = C.KNOWN_GOOD_SNAPSHOT if pk == "rollback" else C.CANDIDATE_SNAPSHOT
            # For rollback identity, exe must be known-good snapshot python.
            # For candidate, candidate snapshot.
            return {"boot_id": host.boot_id(), "pid": pid,
                    "starttime": 8000001 if pid == 590001 else 8000002,
                    "exe": f"{snap}/venv/bin/python3.14",
                    "cmdline": (f"{snap}/venv/bin/python3 -I "
                                f"{snap}/source/hermes_cli/main.py "
                                f"{'gateway run' if pid == 590001 else 'dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build'}"),
                    "cgroup": "/system.slice/hermes-gateway.service" if pid == 590001 else "/system.slice/hermes-dashboard.service",
                    "cwd": C.GATEWAY_WD if pid == 590001 else C.DASHBOARD_WD,
                    "environ_keys": ["HOME"]}

        host.proc_identity = _proc

        def _dash(u, h):
            if dashboard_mode == "ok":
                return {"status": 200, "content_type": "application/json", "body": {"ok": True}}
            if dashboard_mode == "fail_always":
                return {"status": 200, "content_type": "application/json", "body": {"ok": False}}
            # fail_once: candidate fails (published_kind candidate/none), rollback succeeds.
            try:
                with open(os.path.join(fixture_root, "published_kind"), "r", encoding="utf-8") as _f:
                    pk = _f.read().strip()
            except OSError:
                pk = "candidate"
            if pk == "rollback":
                return {"status": 200, "content_type": "application/json", "body": {"ok": True}}
            return {"status": 200, "content_type": "application/json", "body": {"ok": False}}

        host.dashboard_fetch = _dash
        host.gateway_talk = lambda b: {"response": {"ok": True, "result": {"protocol": 1, "pid": 590001}},
                                        "peer_pid": 590001, "peer_uid": 1001}

    def test_candidate_health_fail_rollback_verified(self):
        root = _fixture_root("healthfail-")
        host, _runner = _make_real_host(root)
        # Candidate fails, rollback succeeds (known-good I4+probes pass).
        self._happy_stubs(host, root, dashboard_mode="fail_once")
        r = C.orchestrate(host, C.Request(target_sha=C.TARGET_SHA))
        self.assertEqual(r.state, "rolled-back")
        self.assertIn("rolled-back", r.journal)
        self.assertIn("rolling-back", r.journal)

    def test_rollback_health_fail_stopped_no_further_start(self):
        root = _fixture_root("rollbackfail-")
        host, runner = _make_real_host(root)
        # Candidate fails and rollback also fails -> stopped, no further start.
        self._happy_stubs(host, root, dashboard_mode="fail_always")
        r = C.orchestrate(host, C.Request(target_sha=C.TARGET_SHA))
        self.assertEqual(r.state, "stopped-unresolved")
        self.assertNotIn("rolled-back", r.journal)
        starts = [c for c in runner.calls if len(c) > 10 and c[9:11] == ["/usr/bin/systemctl", "start"]]
        # Candidate start + rollback start = 2, no third start.
        self.assertEqual(len(starts), 2)


class TestThreeKillsRealSigkill(unittest.TestCase):
    def _run_holder(self, root, kill_after, ready_name):
        # Holder runs actual orchestrate with pause at kill_after state.
        ready = os.path.join(root, ready_name)

        def _holder():
            import time as _t
            host, _runner = _make_real_host(root)
            # Happy stubs (same as health happy, dashboard ok).
            host.denial_probe = lambda p: {"write_denied": True, "rename_denied": True,
                                           "hardlink_denied": True, "kernel_enforced": True,
                                           "second_write_denied": True, "second_rename_denied": True,
                                           "second_hardlink_denied": True, "second_kernel_enforced": True}
            host.python_probe = lambda e: {"isolated": 1, "ignore_environment": 1,
                                           "safe_path": True, "no_site": 0, "import_ok": True,
                                           "sitecustomize_origin": None, "sys_path_has_cwd": False,
                                           "pyvenv_version": "3.14.9"}
            host.backup_ok = lambda: True
            host.digest_record = lambda: {"location": "x", "owner_uid": 0, "owner": 0,
                                          "signed": False, "outside_snapshot": True,
                                          "outside_uid1001": True,
                                          "known_good_image_sha": H.KNOWN_GOOD_IMAGE_SHA,
                                          "candidate_image_sha": H.CANDIDATE_IMAGE_SHA,
                                          "known_good_manifest": H.KNOWN_GOOD_IMAGE_SHA,
                                          "candidate_manifest": H.CANDIDATE_IMAGE_SHA,
                                          "known_good_sha": H.KNOWN_GOOD_IMAGE_SHA,
                                          "candidate_sha": H.CANDIDATE_IMAGE_SHA}
            host.dropin_names = lambda s: _real_dropins_for(s)
            host.proc_identity = lambda pid: {"boot_id": host.boot_id(), "pid": pid,
                                              "starttime": 8000001 if pid == 590001 else 8000002,
                                              "exe": f"{C.CANDIDATE_SNAPSHOT}/venv/bin/python3.14",
                                              "cmdline": (f"{C.CANDIDATE_SNAPSHOT}/venv/bin/python3 -I "
                                                          f"{C.CANDIDATE_SNAPSHOT}/source/hermes_cli/main.py "
                                                          f"{'gateway run' if pid == 590001 else 'dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build'}"),
                                              "cgroup": "/system.slice/hermes-gateway.service" if pid == 590001 else "/system.slice/hermes-dashboard.service",
                                              "cwd": C.GATEWAY_WD if pid == 590001 else C.DASHBOARD_WD,
                                              "environ_keys": ["HOME"]}
            host.dashboard_fetch = lambda u, h: {"status": 200, "content_type": "application/json",
                                                 "body": {"ok": True}}
            host.gateway_talk = lambda b: {"response": {"ok": True, "result": {"protocol": 1, "pid": 590001}},
                                           "peer_pid": 590001, "peer_uid": 1001}
            _orig_append = host.journal_append

            def _pausing_append(state, detail=None):
                _orig_append(state, detail)
                if state == kill_after:
                    # Signal parent (real file), then hold lock via real sleep
                    # so parent can SIGKILL. Lock retained FD held whole time.
                    with open(ready, "w", encoding="utf-8") as f:
                        f.write("ready")
                    _t.sleep(30)

            host.journal_append = _pausing_append
            try:
                C.orchestrate(host, C.Request(target_sha=C.TARGET_SHA))
            except Exception:
                pass

        import multiprocessing as _mp
        ctx = _mp.get_context("fork")
        p = ctx.Process(target=_holder)
        p.start()
        # Wait for ready (holder reached kill point, holding lock).
        for _ in range(100):
            if os.path.exists(ready):
                break
            time.sleep(0.05)
        else:
            try:
                p.terminate()
            except Exception:
                pass
            p.join(timeout=5)
            self.fail(f"holder never reached {kill_after}")
        # SIGKILL holder (real death, FD close releases flock, no unlink).
        import signal as _sig
        try:
            os.kill(p.pid, _sig.SIGKILL)
        except ProcessLookupError:
            pass
        p.join(timeout=10)
        self.assertEqual(p.exitcode, -9)
        return root

    def _successor_commits(self, root):
        host, runner = _make_real_host(root)
        host.denial_probe = lambda p: {"write_denied": True, "rename_denied": True,
                                       "hardlink_denied": True, "kernel_enforced": True,
                                       "second_write_denied": True, "second_rename_denied": True,
                                       "second_hardlink_denied": True, "second_kernel_enforced": True}
        host.python_probe = lambda e: {"isolated": 1, "ignore_environment": 1,
                                       "safe_path": True, "no_site": 0, "import_ok": True,
                                       "sitecustomize_origin": None, "sys_path_has_cwd": False,
                                       "pyvenv_version": "3.14.9"}
        host.backup_ok = lambda: True
        host.digest_record = lambda: {"location": "x", "owner_uid": 0, "owner": 0,
                                      "signed": False, "outside_snapshot": True,
                                      "outside_uid1001": True,
                                      "known_good_image_sha": H.KNOWN_GOOD_IMAGE_SHA,
                                      "candidate_image_sha": H.CANDIDATE_IMAGE_SHA,
                                      "known_good_manifest": H.KNOWN_GOOD_IMAGE_SHA,
                                      "candidate_manifest": H.CANDIDATE_IMAGE_SHA,
                                      "known_good_sha": H.KNOWN_GOOD_IMAGE_SHA,
                                      "candidate_sha": H.CANDIDATE_IMAGE_SHA}
        host.dropin_names = lambda s: _real_dropins_for(s)
        host.proc_identity = lambda pid: {"boot_id": host.boot_id(), "pid": pid,
                                          "starttime": 8000001 if pid == 590001 else 8000002,
                                          "exe": f"{C.CANDIDATE_SNAPSHOT}/venv/bin/python3.14",
                                          "cmdline": (f"{C.CANDIDATE_SNAPSHOT}/venv/bin/python3 -I "
                                                      f"{C.CANDIDATE_SNAPSHOT}/source/hermes_cli/main.py "
                                                      f"{'gateway run' if pid == 590001 else 'dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build'}"),
                                          "cgroup": "/system.slice/hermes-gateway.service" if pid == 590001 else "/system.slice/hermes-dashboard.service",
                                          "cwd": C.GATEWAY_WD if pid == 590001 else C.DASHBOARD_WD,
                                          "environ_keys": ["HOME"]}
        host.dashboard_fetch = lambda u, h: {"status": 200, "content_type": "application/json",
                                             "body": {"ok": True}}
        host.gateway_talk = lambda b: {"response": {"ok": True, "result": {"protocol": 1, "pid": 590001}},
                                       "peer_pid": 590001, "peer_uid": 1001}
        r = C.orchestrate(host, C.Request(target_sha=C.TARGET_SHA))
        return r, runner, host

    def _assert_ledger(self, root, expect_committed=True):
        jd = os.path.join(root, "journal")
        jp = os.path.join(jd, "journal")
        lp = os.path.join(jd, "journal.lock")
        self.assertTrue(os.path.lexists(jp), "journal never deleted")
        self.assertTrue(os.path.lexists(lp), "lock retained, no unlink")
        with open(jp, "rb") as f:
            raw = f.read().decode("utf-8")
        states = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict) and isinstance(obj.get("state"), str):
                states.append(obj["state"])
        # Prior legal tail preserved, monotonic, no bare fence-failed, no snapshotted.
        self.assertNotIn("fence-failed", states)
        self.assertNotIn("snapshotted", states)
        if expect_committed:
            self.assertIn("committed", states)
            self.assertEqual(states[-1], "committed")
        # Lock owner is successor (not dead holder), journal_tail audit present.
        with open(lp, "rb") as f:
            owner = json.loads(f.read().decode("utf-8"))
        self.assertIn("boot_id", owner)
        self.assertIn("journal_tail_sha256", owner)
        self.assertIn("target_sha", owner)
        return states

    def test_kill_after_stop_fenced_successor_refences_single_start(self):
        root = _fixture_root("killfence-")
        self._run_holder(root, "stop-fenced", "ready_fence")
        r, _runner, _host = self._successor_commits(root)
        self.assertEqual(r.state, "committed")
        states = self._assert_ledger(root, True)
        self.assertIn("stop-fenced", states)
        starts = _read_lines(os.path.join(root, "starts.log"))
        fences = _read_lines(os.path.join(root, "fences.log"))
        # Holder fenced once before kill, successor re-fenced (stop-fenced never skips re-verify).
        stops = [l for l in fences if l == "stop"]
        self.assertGreaterEqual(len(stops), 2)
        self.assertEqual(len(starts), 1)

    def test_kill_after_publish_before_reload_successor_continues(self):
        root = _fixture_root("killpublish-")
        self._run_holder(root, "units-published", "ready_publish")
        r, _runner, _host = self._successor_commits(root)
        self.assertEqual(r.state, "committed")
        states = self._assert_ledger(root, True)
        self.assertIn("units-published", states)
        starts = _read_lines(os.path.join(root, "starts.log"))
        fences = _read_lines(os.path.join(root, "fences.log"))
        # Successor re-fenced before reload (last==units-published), single start.
        stops = [l for l in fences if l == "stop"]
        self.assertGreaterEqual(len(stops), 2)
        self.assertEqual(len(starts), 1)

    def test_kill_after_restart_before_health_no_second_start(self):
        root = _fixture_root("killrestart-")
        self._run_holder(root, "restarted", "ready_restart")
        r, _runner, _host = self._successor_commits(root)
        self.assertEqual(r.state, "committed")
        states = self._assert_ledger(root, True)
        self.assertIn("restarted", states)
        starts = _read_lines(os.path.join(root, "starts.log"))
        # Holder started once before kill, successor must not start again.
        self.assertEqual(len(starts), 1)


class TestExportedCliSubprocessTemp(unittest.TestCase):
    def test_export_no_git_preflight_apply_recover_subprocess(self):
        from scripts.stock_cutover import cutover_package as E
        scratch = _home_scratch("exportreal-")
        dest = os.path.join(scratch, "pkg")
        res = E.export_cutover_package(dest)
        self.assertEqual(res["status"], "cutover-exported")
        # No .git anywhere, no secrets.
        for dp, dn, fn in os.walk(scratch, followlinks=False):
            self.assertNotIn(".git", dn)
            self.assertNotIn(".git", fn)
        entry = os.path.join(dest, "cli.py")
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        cp = subprocess.run(["/usr/bin/python3", "-I", entry, "plan"],
                            capture_output=True, text=True, check=False,
                            cwd=scratch, env=env)
        self.assertEqual(cp.returncode, 0)
        data = json.loads(cp.stdout)
        self.assertEqual(data["service_cutover"], "NOT-AUTHORIZED")
        cp2 = subprocess.run(["/usr/bin/python3", "-I", entry, "preflight"],
                             capture_output=True, text=True, check=False,
                             cwd=scratch, env=env)
        self.assertEqual(cp2.returncode, 0)
        data2 = json.loads(cp2.stdout)
        self.assertEqual(data2["status"], "preflight-complete")
        self.assertEqual(data2["checks"]["python_self"]["isolated"], 1)
        # Apply/recover without flag refuse (3), with flag as non-root refuse (4), no live effects.
        for cmd in ("apply", "recover"):
            c0 = subprocess.run(["/usr/bin/python3", "-I", entry, cmd],
                                capture_output=True, text=True, check=False,
                                cwd=scratch, env=env)
            self.assertEqual(c0.returncode, 3)
            c1 = subprocess.run(["/usr/bin/python3", "-I", entry, cmd, "--execute-live"],
                                capture_output=True, text=True, check=False,
                                cwd=scratch, env=env)
            # Worker uid 1001, not root installed -> 4, never executes live.
            self.assertEqual(c1.returncode, 4)

    def test_adversarial_sibling_still_refused(self):
        from scripts.stock_cutover import cutover_package as E
        scratch = _home_scratch("adversreal-")
        dest = os.path.join(scratch, "pkg")
        E.export_cutover_package(dest)
        marker = os.path.join(scratch, "SIBLING_EXECUTED")
        evil = (f"import os\nopen({marker!r}, 'w').write('pwned')\nVALUE = 1\n")
        with open(os.path.join(dest, "cutover_host.py"), "wb") as f:
            f.write(evil.encode())
        entry = os.path.join(dest, "cli.py")
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        cp = subprocess.run(["/usr/bin/python3", "-I", entry, "preflight"],
                            capture_output=True, text=True, check=False,
                            cwd=scratch, env=env)
        self.assertNotEqual(cp.returncode, 0)
        self.assertFalse(os.path.exists(marker))


class TestExactUnitsRenderingOnly(unittest.TestCase):
    def test_cutover_recover_timer_mounts_exact_no_install(self):
        cut = R.cutover_service_unit()
        rec = R.recover_service_unit()
        tim = R.recover_timer_unit()
        kgm = R.known_good_mount_unit()
        cdm = R.candidate_mount_unit()
        self.assertTrue(R.validate_supervision(cut, rec, tim))
        self.assertTrue(R.validate_mount_units(kgm, cdm))
        # Fixed interpreter, -I, root package, no restart, timeouts.
        for t in (cut, rec):
            self.assertIn("/usr/bin/python3.12 -I /var/lib/hermes-stock-activation/recovery/cli.py", t)
            self.assertIn("Restart=no", t)
            self.assertIn("Type=oneshot", t)
            self.assertIn("RemainAfterExit=no", t)
            self.assertIn("NoNewPrivileges=yes", t)
            self.assertIn("PrivateTmp=yes", t)
            self.assertIn("TimeoutStartSec=300", t)
            self.assertIn("TimeoutStopSec=30", t)
        # Fail-closed narrow addendum: cutover Requires+Assert mounts (cannot
        # start invalid), recover independent (no Requires/Assert/Condition
        # so it can emit the receipt when mounts are broken). Condition*
        # is forbidden everywhere here (skip-with-success would hide failure).
        self.assertIn(R.KNOWN_GOOD_MOUNT_UNIT, cut)
        self.assertIn(R.CANDIDATE_MOUNT_UNIT, cut)
        self.assertIn("Requires=", cut)
        self.assertIn("AssertPathIsMountPoint=", cut)
        self.assertIn("AssertPathExists=", cut)
        self.assertNotIn("Condition", cut)
        self.assertNotIn(R.KNOWN_GOOD_MOUNT_UNIT, rec)
        self.assertNotIn(R.CANDIDATE_MOUNT_UNIT, rec)
        self.assertNotIn("Requires=", rec)
        self.assertNotIn("Assert", rec)
        self.assertNotIn("Condition", rec)
        self.assertIn("After=network.target", rec)
        self.assertIn("OnFailure=hermes-stock-cutover-recover.service", cut)
        self.assertNotIn("OnFailure=", rec)
        self.assertIn("Persistent=false", tim)
        self.assertIn("AccuracySec=15s", tim)
        self.assertIn("OnBootSec=1min", tim)
        self.assertIn("OnUnitInactiveSec=1min", tim)
        for m in (kgm, cdm):
            self.assertIn("Type=squashfs", m)
            self.assertIn("Options=ro,nosuid,nodev", m)
            self.assertIn("Before=", m)
            self.assertIn("hermes-stock-cutover.service", m)
            self.assertIn("hermes-gateway.service", m)
            self.assertIn("AssertPathExists=", m)
            self.assertNotIn("Condition", m)
        # Rendering only: no active writes/install/stop/start/mount in worker.
        # Verify no install side effects (no /etc writes, no live units).
        self.assertFalse(os.path.exists("/etc/systemd/system/hermes-stock-cutover.service"))
        self.assertFalse(os.path.exists("/etc/systemd/system/" + R.KNOWN_GOOD_MOUNT_UNIT))
        self.assertFalse(os.path.exists("/etc/systemd/system/" + R.CANDIDATE_MOUNT_UNIT))


if __name__ == "__main__":
    unittest.main()
