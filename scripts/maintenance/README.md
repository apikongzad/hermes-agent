# Hermes standalone runtime cutover controller

Root-owned, stdlib-only orchestrator that moves the `hermes-gateway` /
`hermes-dashboard` systemd fleet onto a staged candidate generation and
rolls back automatically on start/health failure. No outbound sends; the
result is a local journal receipt only.

## Layout (facade + siblings, stdlib only)

- `cutover.py` — facade: CLI (`full` / `preflight` / `stage` / `health` /
  `rollback` / `resume`) + re-exports.
- `cutover_types.py` — `Host` IO adapter, `ProductionHost`, config, paths.
- `cutover_preflight.py` — fail-closed baseline capture.
- `cutover_stage.py` — PM-documented staging + isolated-launch verify.
- `cutover_dropin.py` — `zzz-candidate.conf` rendering (sorts AFTER
  `zz-runtime-3.14.9.conf`).
- `cutover_health.py` — read-only health (SHA + `/proc/PID/exe` + 9119).
- `cutover_restore.py` — reversible rollback in mandated order.
- `cutover_orchestrate.py` — `orchestrate()` / `resume()`.
- `cutover_journal.py` — JSONL state journal (durable resume).
- `systemd/` — root-owned units with `OnFailure` recovery.

The controller never imports `pm`, `hermes_cli`, or `gateway`. Root installs
the whole `scripts/maintenance` tree to a root-owned prefix and runs it with
`PYTHONPATH` pointed there, so `scripts.maintenance.*` resolves to
root-owned bytes, never mutable user modules.

## Live baseline (captured by parent preflight, encoded as defaults)

- Gateway `ExecStart=/home/ubuntu/.local/bin/hermes gateway run`,
  dashboard `... dashboard --port 9119 --host 127.0.0.1 --no-open
  --skip-build` (effective, via `zz-runtime-3.14.9.conf`).
- Base `ExecStop=-<oldvenv> -m gateway.systemd_stop_mark`,
  `ExecStopPost=-<oldvenv> -m gateway.cgroup_cleanup`.
- Slice `system-hermes.slice`, `KillMode=mixed`, `TimeoutStopSec=70`,
  `Restart=always` / `RestartSec=5s`, `User=/Group=ubuntu`.
- Gateway `WorkingDirectory=~/.hermes`, dashboard `/home/ubuntu`,
  both `HERMES_HOME` default (`/home/ubuntu/.hermes`).
- Parent verifies: `systemctl cat/show` bytes, source archive bytes
  (19527 entries), live `50e82ad783`, live `/proc/PID/exe`; any failure is
  fail-closed. Protected root overrides are backed up at
  `/home/ubuntu/backups/hermes-upgrade-20261025-150042/protected-state-root.tar.gz`.

## Staging (PM-documented entrypoint, isolated durable generation)

Source the exact candidate from a copied tree/archive the parent
materializes — never `git checkout` the active live tree:

```bash
# Parent materializes the candidate copy, then stages an isolated generation:
python3 -m pm.build_env --source /opt/candidate/hermes-agent --out /home/ubuntu/.hermes/generations/gen-<sha12>/venv
```

That CLI is the wrapper around `pm.build_environment(source, out)`
(`pm/build_env.py`; see also `tests/AGENTS.md`). The controller runs
exactly that argv through the injected `Host` (tests assert the argv and
reject invented `pm.py` / `scripts/sync_venv.py` /
`scripts/publish_launcher.py`). `pm.ensure_environment` /
`pm.sync_venv` / `hermes pm install` /
`hermes_cli.venv_sync.publish_launchers` are the other supported
entrypoints; the controller does not invent new ones.

Isolated-launch verify (no re-exec to the live old generation):

```bash
<generation>/venv/bin/python3 -c 'import sys; print(sys.executable); print(sys.prefix)'
# must name the generation dir, never the live /proc/PID/exe target
```

User config/auth/skills/plugins stay at the default home
(`/home/ubuntu/.hermes`) for the final service; an isolated home is used
only inside tests (injected `Host`).

## Cutover dropin (sorted AFTER zz-runtime)

Systemd sorts dropins lexicographically; the candidate file is named
`zzz-candidate.conf` so it wins over `zz-runtime-3.14.9.conf`:

```ini
# /etc/systemd/system/hermes-gateway.service.d/zzz-candidate.conf
[Service]
ExecStart=<generation>/venv/bin/python3 <candidate_src>/hermes_cli/main.py gateway run
WorkingDirectory=/home/ubuntu/.hermes
Environment="PATH=<generation>/venv/bin:/home/ubuntu/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="HERMES_HOME=/home/ubuntu/.hermes"
```

```ini
# /etc/systemd/system/hermes-dashboard.service.d/zzz-candidate.conf
[Service]
ExecStart=<generation>/venv/bin/python3 <candidate_src>/hermes_cli/main.py dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build
WorkingDirectory=/home/ubuntu
Environment="PATH=<generation>/venv/bin:/home/ubuntu/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="HERMES_HOME=/home/ubuntu/.hermes"
```

`HERMES_EXE` never selects the interpreter (units hardcode `ExecStart`).
Prior bytes for the candidate name are saved in the journal; rollback
removes what was added and restores what was overwritten.

## Health (read-only, binds SHA + exe + 9119)

- `systemctl is-active` for both units.
- `systemctl show -p MainPID`, then `readlink /proc/<pid>/exe` must name
  the staged generation (not the live old interpreter).
- `git -C <candidate_src> rev-parse HEAD` must equal the candidate SHA;
  `gateway_state.json` `code_sha` (when present) must equal it too.
- `GET http://127.0.0.1:9119/health` must be 200/302. Port is always 9119,
  never 3000/8501. No `launcher --version` probe, no old-runtime version
  string, no writes, no sends.

## Rollback (mandated order, never swallowed)

`source` → `facts` → `dropins` → `daemon-reload` → `restart` → `verify`.
Never start-before-restore; every restore error is journaled and returned
(`failed` when the fleet is back, `unknown` when it is not) — never
`success`, never `except: pass` / bare `except`.

## Root install / activate (parent-only, no live restart yet)

```bash
# 1. Parent preflight (fail-closed): capture systemctl cat/show, dropin bytes,
#    archive bytes, live PID exe. Any failure aborts before mutation.
systemctl cat hermes-gateway.service hermes-dashboard.service
systemctl show hermes-gateway.service -p MainPID,ExecStart,WorkingDirectory,Environment
readlink /proc/$(systemctl show hermes-gateway.service -p MainPID --value)/exe
tar -tf /home/ubuntu/backups/hermes-upgrade-20261025-150042/protected-state-root.tar.gz | wc -l

# 2. Stage the candidate generation (PM builds it; controller verifies it):
python3 -m pm.build_env --source /opt/candidate/hermes-agent --out /home/ubuntu/.hermes/generations/gen-<sha12>/venv

# 3. Install the root-owned controller (preserves scripts/maintenance layout):
sudo mkdir -p /opt/hermes-maintenance
sudo cp -a scripts/maintenance /opt/hermes-maintenance/scripts-maintenance-tmp
# (parent normalises to /opt/hermes-maintenance/scripts/maintenance + root-owned systemd units)
sudo cp systemd/hermes-runtime-cutover.service systemd/hermes-runtime-cutover-recovery.service /etc/systemd/system/
sudo systemctl daemon-reload

# 4. Dry-run the orchestrator through the journal (no restart until ordered):
sudo PYTHONPATH=/opt/hermes-maintenance /usr/bin/python3 -I -B /opt/hermes-maintenance/scripts/maintenance/cutover.py preflight \
  --candidate-sha <CAND> --parent-sha <PARENT> \
  --candidate-src /opt/candidate/hermes-agent --live-tree /home/ubuntu/hermes-agent \
  --generation-root /home/ubuntu/.hermes/generations --journal /var/lib/hermes-cutover/journal.jsonl

# 5. Rollback (same order the controller uses automatically on failure):
sudo PYTHONPATH=/opt/hermes-maintenance /usr/bin/python3 -I -B /opt/hermes-maintenance/scripts/maintenance/cutover.py rollback \
  --candidate-sha <CAND> --parent-sha <PARENT> \
  --candidate-src /opt/candidate/hermes-agent --live-tree /home/ubuntu/hermes-agent \
  --generation-root /home/ubuntu/.hermes/generations --journal /var/lib/hermes-cutover/journal.jsonl
# then: sudo systemctl daemon-reload && sudo systemctl restart hermes-gateway.service hermes-dashboard.service
```

`full` performs the cutover; `resume` is the `OnFailure=` target and the
reboot-resume entrypoint (it refuses when the journal already holds a
terminal receipt). No live restart happens in this change.
