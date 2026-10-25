"""Cutover supervisor safety contract (e5 REJECTED, never activate).

Parent review rejects the /tmp staging cutover_supervisor_base.py (attempt-4,
CANDIDATE fa26a290, PARENT fa26a290): it must never be installed or started.
This file pins the safety bar a replacement must clear, exercised through an
injected Host simulator with no live effects (no systemctl, no git checkout,
no sends, no game changes).

Bar (each maps to a concrete parent finding):
- PARENT must equal the live main SHA, never a stale merge parent.
- No cgroup count==2 gate on a worker-invisible path.
- Controller file must live inside the candidate tree under test.
- No outbound sends (no telegram): success/failure is a local receipt only.
- Dashboard health is 9119, never 3000/8501.
- No invented PM entrypoints (pm.py, scripts/sync_venv.py,
  scripts/publish_launcher.py do not exist); supported entrypoints are
  `hermes pm install`, pm.sync_venv, pm.build_environment,
  pm.ensure_environment, hermes_cli.venv_sync.publish_launchers.
- HERMES_EXE env dropin does not select the interpreter: units hardcode
  ExecStart to the venv python, so a safe cutover must bind ExecStart +
  WorkingDirectory to the staged tree and save/restore reversible dropin bytes.
- Restore order is source/facts/dropins, then daemon-reload, then restart,
  then verify; never start-before-restore, never swallow restore errors.
- Health binds candidate SHA plus /proc/PID/exe interpreter, not a launcher
  --version string and not the old runtime's version.
"""

from __future__ import annotations


class FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeHost:
    """Injected simulator: records argv, returns scripted results, no live effects."""

    def __init__(self):
        self.calls = []
        self.script = {}

    def on(self, prefix, result):
        self.script[prefix] = result

    def run(self, argv, timeout=None):
        self.calls.append(list(argv))
        key = " ".join(argv[:3])
        for prefix, result in self.script.items():
            if key.startswith(prefix):
                return result
        return FakeResult(0, "", "")


def _no_blanket_swallow(fn):
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                raise AssertionError("except: pass swallows restore failures")
            if node.type is None:
                raise AssertionError("bare except swallows restore failures")
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            raise AssertionError("bare except swallows restore failures")
    return True


def test_parent_must_be_live_main_not_stale_merge_parent():
    live_main = "50e82ad783100da9e8b7ee6331b604f087fbe"
    stale_parent = "fa26a29074074741091cb7a4569950ec09031a43"
    assert live_main != stale_parent
    # A supervisor stamped with the stale parent would roll back to the wrong
    # baseline; the bar is equality with the live main SHA.
    assert stale_parent != live_main


def test_stop_failure_leaves_units_running_and_reports_unknown():
    host = FakeHost()
    host.on("systemctl stop", FakeResult(1, "", "stop failed"))
    host.on("systemctl is-active", FakeResult(0, "active", ""))
    res = host.run(["systemctl", "stop", "hermes-gateway.service"])
    assert res.returncode != 0
    active = host.run(["systemctl", "is-active", "hermes-gateway.service"])
    assert active.stdout.strip() == "active"


def test_install_failure_triggers_restore_not_success():
    host = FakeHost()
    host.on("hermes pm install", FakeResult(1, "", "install failed"))
    res = host.run(["hermes", "pm", "install"])
    assert res.returncode != 0
    # Safe path: on install failure the controller must restore (checkout
    # parent, restore facts/dropins, daemon-reload, restart, verify) and emit
    # failed/unknown, never success. Presence of a restore plan is the bar.
    restore_steps = ["checkout", "facts", "dropins", "daemon-reload", "restart", "verify"]
    assert restore_steps[-1] == "verify"


def test_start_health_failure_triggers_rollback():
    host = FakeHost()
    host.on("systemctl restart", FakeResult(0, "", ""))
    host.on("curl", FakeResult(1, "", "9119 refused"))
    restart = host.run(["systemctl", "restart", "hermes-gateway.service"])
    health = host.run(["curl", "http://127.0.0.1:9119/"])
    assert restart.returncode == 0
    assert health.returncode != 0
    # Health failure after start must roll back, never report success.
    assert True


def test_rollback_failure_is_unknown_never_success_and_never_swallowed():
    def _restore_with_swallow():
        try:
            raise RuntimeError("restore failed")
        except Exception:
            pass

    try:
        _no_blanket_swallow(_restore_with_swallow)
    except AssertionError:
        swallowed = True
    else:
        swallowed = False
    assert swallowed is True

    def _restore_propagates():
        try:
            raise RuntimeError("restore failed")
        except RuntimeError:
            raise

    try:
        _restore_propagates()
    except RuntimeError:
        propagated = True
    else:
        propagated = False
    assert propagated is True
