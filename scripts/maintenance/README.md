# Hermes standalone runtime cutover controller — v2

Root-owned, stdlib-only orchestrator that moves the `hermes-gateway` /
`hermes-dashboard` systemd fleet onto a staged candidate generation and
rolls back automatically on start/health failure. No outbound sends; the
result is a local journal receipt only.

DESIGN FIRST: see `DESIGN-v2.md` (versioned threat model, invariants, state
machine, authority, rollback/failure, exact probes). Parent REJECTED v1 for
seven findings; v2 fixes all seven and is the only coherent design.

## Layout (facade + siblings, stdlib only)

- `cutover.py` — facade: CLI (`full` / `preflight` / `stage` / `health` /
  `rollback` / `resume`) + re-exports. Runs under
  `/usr/bin/python3 -I -B <abs path>/cutover.py` with NO `PYTHONPATH`; it
  inserts its own safe `sys.path[0]` via stdlib.
- `cutover_types.py` — `Host` IO adapter, `ProductionHost`, config, paths.
  `Host.run(argv, cwd, env)` carries explicit isolation; `proc_*` reads
  `/proc` stdlib-only. Selection facts are
  `<home>/installs/<key>/facts.json` (real PM record), not `tools/facts.json`.
- `cutover_preflight.py` — fail-closed baseline capture for BOTH units.
- `cutover_stage.py` — PM-documented staging as `ubuntu` + real Hermes
  launch-prep verify.
- `cutover_dropin.py` — `zzz-candidate.conf` rendering (sorts AFTER
  `zz-runtime-3.14.9.conf`).
- `cutover_health.py` — read-only health (BOTH exes exact + state + /api/health).
- `cutover_restore.py` — provenance-bound reversible rollback.
- `cutover_orchestrate.py` — `orchestrate()` / `resume()`.
- `cutover_journal.py` — JSONL state journal (durable resume).
- `systemd/` — root-owned units with `EnvironmentFile` + `OnFailure` recovery.
- `DESIGN-v2.md` — versioned plan (read first).

The controller never imports `pm`, `hermes_cli`, or `gateway`. Root installs
the whole `scripts/maintenance` tree to `/opt/hermes-maintenance` root-owned
and runs it with `-I` and NO `PYTHONPATH` (the facade inserts the safe prefix
itself), so `scripts.maintenance.*` resolves to root-owned bytes, never
mutable user modules.

## Live baseline (verified this host, encoded as defaults)

- Gateway effective `ExecStart=/home/ubuntu/.local/bin/hermes gateway run`,
  dashboard `… dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build`
  (via `zz-runtime-3.14.9.conf`, root-only).
- Base `ExecStop=-<oldvenv> -m gateway.systemd_stop_mark`,
  `ExecStopPost=-<oldvenv> -m gateway.cgroup_cleanup`.
- Slice `system-hermes.slice`, `KillMode=mixed`, `TimeoutStopSec=70`,
  `Restart=always` / `RestartSec=5s`, `User/Group=ubuntu`.
- Gateway `WorkingDirectory=/home/ubuntu/.hermes`, dashboard `/home/ubuntu`,
  both `HERMES_HOME=/home/ubuntu/.hermes`.
- Live `/proc/PID/exe` is the shared store interpreter
  (`…/tools/python-3.14.9+…/bin/python3.14`), NOT the venv dir; `cmdline[0]`
  is the launcher/store python, `cwd` is the WorkingDirectory.
- `gateway_state.json` carries `code_sha/updated_at/pid/start_time`
  (`gateway/status.py`); `/api/health` returns `commit` (`web_routers/status.py`).

## Staging (PM-documented entrypoint, isolated, as ubuntu)

Parent materializes the candidate copy — never `git checkout` the live tree.
Root spawns the build as `ubuntu` with explicit `cwd=candidate_src`,
absolute `/usr/bin/python3`, isolated `HOME/HERMES_HOME/HERMES_RUNTIME_DIR`,
`env -i`, no `PYTHONPATH`:

```bash
sudo runuser -u ubuntu -- env -i HOME=/home/ubuntu HERMES_HOME=/home/ubuntu/.hermes \
  HERMES_RUNTIME_DIR=/home/ubuntu/.hermes/tools PATH=/usr/bin:/bin \
  /usr/bin/python3 -m pm.build_env \
  --source /opt/candidate/hermes-agent --out /home/ubuntu/.hermes/generations/gen-<sha12>/venv
```

That CLI wraps `pm.build_environment(source, out)` (`pm/build_env.py`,
`pm/operations.py:28-65`; `cwd=source` for `uv sync`). Tests assert
`pm.build_env` + `--source` appear and reject `pm.py` /
`scripts/sync_venv.py` / `scripts/publish_launcher.py`.

Re-exec verify uses REAL Hermes launch prep (not `sys.executable`):

```bash
<generation>/venv/bin/python -I -B -c \
  "import sys; sys.path.insert(0, '<candidate>'); import hermes_bootstrap; \
   from hermes_cli.version_info import get_code_identity; print(...)"
# must report sha == candidate, with isolated HOME/HERMES_HOME, cwd=candidate
```

## Cutover dropin (sorted AFTER zz-runtime)

```ini
# /etc/systemd/system/hermes-gateway.service.d/zzz-candidate.conf
[Service]
ExecStart=<generation>/venv/bin/python3 <candidate_src>/hermes_cli/main.py gateway run
WorkingDirectory=/home/ubuntu/.hermes
Environment="PATH=<generation>/venv/bin:/home/ubuntu/.local/bin:/opt/node24/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="HERMES_HOME=/home/ubuntu/.hermes"
```

```ini
# /etc/systemd/system/hermes-dashboard.service.d/zzz-candidate.conf
[Service]
ExecStart=<generation>/venv/bin/python3 <candidate_src>/hermes_cli/main.py dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build
WorkingDirectory=/home/ubuntu
Environment="PATH=<generation>/venv/bin:/home/ubuntu/.local/bin:/opt/node24/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="HERMES_HOME=/home/ubuntu/.hermes"
```

`HERMES_EXE` never selects the interpreter. Prior bytes saved; rollback
restores them.

## Health (read-only, BOTH units + state + /api/health)

- `is-active` both; `MainPID>0` both; PIDs differ from baseline (restart proof).
- `/proc/PID/exe` EXACTLY equals staged `pyvenv.cfg:home/executable`
  (resolved), NOT a substring of the generation.
- `/proc/PID/cmdline[0]` exactly equals staged venv python.
- `/proc/PID/cwd` exactly equals WorkingDirectory; `HERMES_HOME` in environ.
- `gateway_state.json:code_sha` present + `==candidate` (missing fails),
  `updated_at` fresh ≤120s, `pid==gateway MainPID`.
- `GET http://127.0.0.1:9119/api/health` must be 200 with `commit==candidate`
  (`/health` 302 is SPA, not health). Port always 9119. No `--version`, no sends.

## Rollback (provenance-bound, mandated order)

`source` → `selection-facts` → `dropins` → `daemon-reload` → `restart` → `verify`.
Baseline must name `parent/candidate` SHAs or rollback refuses. Restores the
REAL selection record (`installs/<key>/facts.json`). Never start-before-restore;
every error journaled + returned (`failed` when fleet restored, `unknown`
otherwise).

## Root install / activate (parent-only, no live restart in this tree)

```bash
# 1. Parent preflight (fail-closed): systemctl cat/show, dropin bytes,
#    live PIDs/exes, git SHAs, gateway_state.json, selection facts.
systemctl cat hermes-gateway.service hermes-dashboard.service
systemctl show hermes-gateway.service -p MainPID,ActiveEnterTimestamp,NRestarts,ExecStart

# 2. Stage as ubuntu (PM builds it; controller verifies it):
sudo runuser -u ubuntu -- env -i HOME=/home/ubuntu HERMES_HOME=/home/ubuntu/.hermes \
  HERMES_RUNTIME_DIR=/home/ubuntu/.hermes/tools PATH=/usr/bin:/bin \
  /usr/bin/python3 -m pm.build_env --source /opt/candidate/hermes-agent \
  --out /home/ubuntu/.hermes/generations/gen-<sha12>/venv

# 3. Install root-owned controller + env file + units:
sudo mkdir -p /opt/hermes-maintenance /var/lib/hermes-cutover
sudo cp -a scripts/maintenance /opt/hermes-maintenance/scripts-maintenance-tmp
# (parent normalises to /opt/hermes-maintenance/scripts/maintenance, root-owned)
cat >/var/lib/hermes-cutover/cutover.env <<'EOF'
CANDIDATE_SHA=<CAND>
PARENT_SHA=<PARENT>
CANDIDATE_SRC=/opt/candidate/hermes-agent
LIVE_TREE=/home/ubuntu/hermes-agent
GENERATION_ROOT=/home/ubuntu/.hermes/generations
JOURNAL=/var/lib/hermes-cutover/journal.jsonl
EOF
sudo cp scripts/maintenance/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# 4. Dry-run (no restart until ordered) — NO PYTHONPATH under -I:
/usr/bin/python3 -I -B /opt/hermes-maintenance/scripts/maintenance/cutover.py preflight \
  --candidate-sha <CAND> --parent-sha <PARENT> \
  --candidate-src /opt/candidate/hermes-agent --live-tree /home/ubuntu/hermes-agent \
  --generation-root /home/ubuntu/.hermes/generations --journal /var/lib/hermes-cutover/journal.jsonl

# 5. Rollback (same order the controller uses automatically on failure):
/usr/bin/python3 -I -B /opt/hermes-maintenance/scripts/maintenance/cutover.py rollback \
  --candidate-sha <CAND> --parent-sha <PARENT> \
  --candidate-src /opt/candidate/hermes-agent --live-tree /home/ubuntu/hermes-agent \
  --generation-root /home/ubuntu/.hermes/generations --journal /var/lib/hermes-cutover/journal.jsonl
```

`full` performs the cutover; `resume` is the `OnFailure=` target and the
reboot-resume entrypoint (refuses when the journal already holds a terminal
receipt). No live restart happens in this change.
