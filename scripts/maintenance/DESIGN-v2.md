# Hermes standalone runtime cutover — DESIGN v2 (parent-gated)

Status: DESIGN FIRST (required after repeated unsafe iterations). No cutover
implementation change lands without this document updated first. Parent owns
root read/copy/deploy; this tree only carries the verified controller + tests.

Version: v2 (2026-10-25). Supersedes the v1 speculative controller
(`be9628fa`, README + `cutover_*` as shipped) which parent REJECTS for the
seven findings in §1. All commands below were verified against real source in
this tree and actual isolated execution on this host (not FakeHost alone);
receipts live in §8.

## 1. Parent findings (v1 REJECT) → v2 answer

1. `stage runs bare python3 -m pm.build_env with no cwd/owner` and
   `root controller may import PM from wrong tree`.
   → v2 stage NEVER runs in the root controller interpreter. Root (stdlib
   only) spawns the build as `ubuntu` via `runuser -u ubuntu -- env -i …`
   with explicit `cwd=candidate_src`, absolute `/usr/bin/python3`,
   isolated `HOME=/home/ubuntu`, `HERMES_HOME=/home/ubuntu/.hermes`,
   `HERMES_RUNTIME_DIR=<store>`, and no `PYTHONPATH`. Verified:
   `pm/build_env.py:41-44` parses `--source/--out`; `pm/operations.py:28-65`
   requires `source/pyproject.toml` + `uv.lock` (frozen), `out` must not
   exist, `cwd=source` for `uv sync` (`pm/environment.py:395-441`);
   `managed_environment` resolves the pinned toolchain and strips `PYTHON*`
   (`pm/environment.py:250-271`). Root imports only stdlib (`cutover.py`
   facade); the child imports the CANDIDATE's `pm` via `cwd`, as `ubuntu`.
2. `health expects proc exe inside venv generation but PM venv symlinks
   actual exe to shared tool Python so fails correct launch`.
   → v2 NEVER substrings `generation` in `/proc/PID/exe`. Verified live:
   `exe=/home/ubuntu/.hermes/tools/python-3.14.9+…/bin/python3.14`
   (shared store interpreter), while `cmdline[0]=<venv>/bin/python`
   and `cwd=WorkingDirectory`. venv proof: `python3 -m venv` in
   `/tmp/opencode/probe` shows `bin/python3 -> /home/ubuntu/.local/bin/python3`
   → store `python3.14`; `sys.executable` names the venv, `/proc exe`
   names the store. v2 health asserts EXACT equality:
   `readlink(/proc/PID/exe) == canonical(store_python)` where
   `store_python` is the staged `pyvenv.cfg:executable` (resolved) AND the
   live `pm/lock.json:python=3.14.9+20261021`, PLUS `cmdline[0]` is the
   staged venv python, PLUS `cwd` and `HERMES_HOME/PATH` bindings match the
   dropin. References: `pm/environments.py:321-328` (`venv_python`),
   `pm/environment.py:370-379` (`uv venv --relocatable --python <pinned>`).
3. `only Gateway exe checked no Dashboard`.
   → v2 checks BOTH units (`hermes-gateway.service`,
   `hermes-dashboard.service`): `is-active`, `MainPID>0`, `NRestarts`,
   `ActiveEnterTimestamp`, `ExecStart`, per-PID `exe+cmdline+cwd+environ`,
   and start-time PID-reuse guard. Verified:
   `systemctl show -p MainPID,ActiveEnterTimestamp,NRestarts,ExecStart`
   returns live `gateway 15839/0/2026-10-25…`, `dashboard 15683/0/…`.
4. `missing stateSHA treated success fail-open`.
   → v2 is fail-CLOSED: `gateway_state.json:code_sha` MUST be present,
   40-hex, and equal `candidate_sha`; missing/unparseable/stale/mismatched
   is `ok=False`. Schema verified live: keys include `pid,kind,argv,
   start_time,hermes_home,gateway_state,updated_at,code_sha,code_version`
   (`gateway/status.py:826-832,799-814`); stamping via
   `hermes_cli/version_info.get_code_identity` (`version_info.py:308-332`);
   stale TTL 120s (`gateway/status.py:1206-1217`); live `code_sha=50e82ad…`
   equals live `HEAD`, `pid=15839` equals `MainPID`.
5. `/health9119 endpoint unverified`.
   → v2 probes the REAL dashboard contract, verified live:
   `GET http://127.0.0.1:9119/api/health` → `200
   {"ok":true,"version":"0.21.7","commit":"50e82ad…","auth_required":true}`
   (`hermes_cli/web_routers/status.py:119-130`); `/health` is a `302` SPA
   fallback, NOT health. v2 requires `200` on `/api/health` AND
   `commit==candidate_sha`. Port is always `9119`
   (`hermes_cli/subcommands/dashboard.py:18`); never `3000/8501`.
6. `rollback no baseline provenance bind`.
   → v2 binds every baseline to `(parent_sha,candidate_sha,live_HEAD,
   candidate_HEAD,live PIDs/starttimes,facts bytes,unit texts,dropin bytes)`
   and the journal records the same provenance on every receipt. Rollback
   refuses when `baseline.live_head != parent_sha` or
   `baseline.candidate_head != candidate_sha` (stale baseline), restores in
   the mandated order, and re-verifies. Facts restored are the REAL
   selection record `installs/<key>/facts.json`
   (`pm/environments.py:105-106`; live holds `venv.environment=
   …/environments/<uuid>/venv`), NOT `tools/facts.json` (which holds
   `python,uv,node…` only — verified live).
7. `CLI python -I ignores PYTHONPATH so documented command imports fail`.
   → Verified: `PYTHONPATH=/tmp/opencode python3 -I -c …` drops
   `PYTHONPATH` from `sys.path` (env still shows it). v2 install/run docs
   NEVER rely on `PYTHONPATH` under `-I`. Root-owned layout
   `/opt/hermes-maintenance/scripts/maintenance/cutover.py` is invoked as
   `/usr/bin/python3 -I -B <abs path> …` with NO `PYTHONPATH`; the facade
   inserts its own safe `sys.path[0]` (`/opt/hermes-maintenance`) via
   stdlib `pathlib` before importing siblings, and pops
   `PYTHONHOME/PYTHONPATH/VIRTUAL_ENV` like the real launcher
   (`hermes_cli/_launchers.py:39-72`).

## 2. Real launch chain (facts lock runtime generation)

- Build: `pm.build_environment(source,out,python,cache,…,frozen=True,
  explicit=True)` (`pm/client.py:287-302` → `pm/operations.py:28-65`).
  Fresh destination only; failure removes only this invocation's tree;
  `cwd=source`; env from `source_build_environment` (null on linux) +
  pinned `uv/python` (`pm/environment.py:250-271`).
- Selection: `install_state_dir(project)=<home>/installs/<key>` where
  `<key>=sha256(canonical(project))[:16]` (`pm/environments.py:20-38`);
  `runtime_facts_path=<state>/facts.json` holds
  `{stamp,extras,environment,resolved_lock}` (`pm/lock.py:269-279`);
  `selected_venv` reads it and requires
  `<state>/environments/.../pyvenv.cfg` (`pm/environments.py:275-319`).
  Generation dirs are `<state>/environments/<uuid>/venv` — NEVER
  `<home>/generations/gen-<sha>/venv` (v1 path was invented).
- Runtime: `runtime_command` = `[store_python,-I,-B,script]` (or
  `-I,-S,-B -c launcher` for resident) (`pm/runtime.py:259-271`);
  launchers exec `store_python -I -c bootstrap` which pops
  `PYTHONHOME/PYTHONPATH/VIRTUAL_ENV`, inserts `repo_root`, imports
  `hermes_bootstrap` (`hermes_cli/_launchers.py:39-72`,
  verified `.hermes/bin/hermes`). `hermes_bootstrap` + `activate_dependencies`
  select+lease the generation at boot (`pm/environments.py:453-517`).
- v2 staging therefore builds a SIDE generation via the candidate's own
  `pm` (as `ubuntu`, isolated, `cwd=candidate`) to
  `<generation_root>/gen-<sha12>/venv` (side root is parent-owned, NOT the
  live selection dir), then points the candidate dropins DIRECTLY at
  `<side>/bin/python <candidate>/hermes_cli/main.py …` (bypasses live
  selection by design — the cutover under test). Health binds the side
  `pyvenv.cfg` + `cmdline/cwd/env`, not the live selection.

## 3. Real service lifecycle + live dashboard endpoint

- Units (verified `systemctl cat/show`): base `ExecStart` names the OLD
  `…/hermes-agent/venv/bin/python -m hermes_cli.main …`; effective
  `ExecStart` (via `zz-runtime-3.14.9.conf`, root-only) is the launcher
  `/home/ubuntu/.local/bin/hermes gateway run` /
  `… dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build`.
  `WorkingDirectory` gateway `/home/ubuntu/.hermes`, dashboard `/home/ubuntu`;
  `HERMES_HOME=/home/ubuntu/.hermes`; `Restart=always/5s`;
  `TimeoutStopSec=70`; `KillMode=mixed`. Both `active`, `NRestarts=0`.
- Liveness ladder (v2, read-only): `is-active` both → `MainPID>0` both →
  `readlink exe == expected store python` both →
  `cmdline[0] == staged venv python` both → `cwd == WorkingDirectory` both
  → `HERMES_HOME` in `/proc/PID/environ` both → `NRestarts` +
  `ActiveEnterTimestamp` change vs baseline (proves restart happened) →
  `gateway_state.json` fresh + `code_sha==candidate` + `pid==gateway MainPID`
  → `/api/health commit==candidate` → `updated_at` fresh.
- Dashboard contract: `/api/health` (public, `dashboard_auth/public_paths.py:12`)
  is the ONLY health; `/health` 302 is SPA, `/api/status` 200 is portal
  (needs gateway state). Gateway HTTP `/health` lives behind
  `GATEWAY_HEALTH_URL` (`hermes_cli/web_server_gateway.py:39-64`), not 9119.

## 4. Threat model

- Mutable candidate tree: root MUST NOT `import pm/hermes_cli/gateway`
  from it; only `ubuntu` child with `cwd=candidate` may. Root controller is
  stdlib-only + `ProductionHost` (`subprocess/os/urllib/pathlib`).
- Env injection: `PYTHONPATH/VIRTUAL_ENV/PYTHONHOME/HOME/HERMES_HOME/
  HERMES_RUNTIME_DIR` are attacker-controlled under `sudo`/cron; v2 uses
  `env -i` + explicit allowlist, pops the three Python vars in-process like
  the launcher, and never trusts ambient `HOME`.
- PID reuse: bare `MainPID` equality is insufficient; v2 compares
  `ActiveEnterTimestamp` + `/proc start_time` + `gateway_state.start_time`.
- Stale baseline/journal: v2 refuses a baseline whose
  `live_HEAD != parent_sha` or `candidate_HEAD != candidate_sha`, and
  `resume` refuses when a terminal receipt exists.
- No sends: success/failure is a local JSONL receipt only; no telegram,
  no `hermes send`, no game/data mutation, no live restart except the
  orchestrated `daemon-reload + restart` (parent-ordered only).

## 5. Invariants (fail-closed)

- I1 `candidate_sha != parent_sha`, both 40-hex; `dashboard_port==9119`.
- I2 Controller file lives inside `candidate_src/scripts/maintenance/cutover.py`
  and contains `def orchestrate`.
- I3 `candidate_dropin_name > zz-runtime-3.14.9.conf` (lexicographic win).
- I4 Staging argv is EXACTLY the documented PM entrypoint
  (`pm.build_env --source <abs candidate> --out <abs side>/venv [--python <abs>]`)
  executed as `ubuntu` with `cwd=candidate`, isolated `HOME/HERMES_HOME/
  HERMES_RUNTIME_DIR`, `env -i`, absolute `/usr/bin/python3`; forbidden
  tokens (`pm.py`, `scripts/sync_venv.py`, `scripts/publish_launcher.py`,
  `HERMES_EXE`) abort.
- I5 `pyvenv.cfg:executable` (resolved) == live store python pin
  (`pm/lock.json:python`) == `/proc/PID/exe` (resolved) for BOTH units.
- I6 `gateway_state.json:code_sha` present + `==candidate_sha` +
  `updated_at` fresh (≤120s) + `pid==gateway MainPID`.
- I7 `/api/health:commit == candidate_sha`, HTTP 200.
- I8 Dropins bind `ExecStart+WorkingDirectory+PATH+HERMES_HOME`, never
  `HERMES_EXE`; prior bytes saved; name sorts after `zz-runtime`.
- I9 Restore order `source→facts→dropins→reload→restart→verify`, never
  start-before-restore; every error journaled + returned; `unknown` when
  restore itself fails, never `success`.
- I10 `-I` runs with NO `PYTHONPATH`; safe `sys.path` only.

## 6. State machine + authority + rollback/failure

- States: `preflight → staged → launch-verified → dropins-written →
  reloaded → restarted → healthy ⇒ success`; any step fail ⇒
  `rollback(source,facts,dropins,reload,restart,verify) ⇒ failed`
  (fleet restored) or `unknown` (restore failed/interrupted).
  `resume` (OnFailure/reboot) finishes or rolls back; refuses if terminal
  receipt exists.
- Authority: PARENT (human/root): materialize candidate copy, capture
  baseline (`systemctl cat/show`, `readlink exe`, `git rev-parse`,
  `gateway_state.json`, `facts.json`, dropin bytes), stage as `ubuntu`
  (via root `runuser`), install root-owned controller to
  `/opt/hermes-maintenance`, `daemon-reload/restart`, read/copy/deploy.
  ROOT controller: read-only probes + atomic dropin writes + ordered
  restore. UBUNTU child: `pm.build_env` + real launch-prep probe with
  isolated `HOME/HERMES_HOME`. No actor writes outside its boundary.
- Rollback: `_restore_source` (`git checkout --detach parent_sha` only if
  `HEAD != parent`), `_restore_facts` (atomic replace of
  `installs/<key>/facts.json` from baseline bytes), `_restore_dropins`
  (remove candidate, restore prior bytes), `daemon-reload`, `restart both`,
  `verify both + state + /api/health`. Provenance-checked (I1/I2/baseline
  HEAD bind) before any mutation.

## 7. Exact probes (v2, stdlib root boundary)

- Preflight: `systemctl cat <gw> <dash>` contains `ExecStart=`;
  `systemctl show <gw> -p MainPID` → `>0`;
  `readlink(/proc/<pid>/exe)` non-empty;
  `git -C <live> rev-parse HEAD == parent_sha`;
  `git -C <candidate> rev-parse HEAD == candidate_sha`;
  `candidate/.../cutover.py` contains `def orchestrate`;
  `facts.json` (selection) + `gateway_state.json` readable;
  dropin prior bytes captured.
- Stage (as ubuntu): `runuser -u ubuntu -- env -i HOME=… HERMES_HOME=…
  HERMES_RUNTIME_DIR=… /usr/bin/python3 -m pm.build_env --source <cand>
  --out <side>/venv` with `cwd=<cand>`, `timeout=1800`.
  Re-exec probe (REAL launch prep, not `python -c`): as `ubuntu`,
  `<side>/bin/python -I -B <candidate>/hermes_cli/main.py --help`
  (loads `hermes_bootstrap` + candidate deps; proves staged env boots
  Hermes) with isolated `HOME/HERMES_HOME`, `cwd=<cand>`; then
  `pyvenv.cfg` parse + `exe/cmdline/cwd` bind check.
- Health (both): `is-active`, `MainPID`, `NRestarts`,
  `ActiveEnterTimestamp` changed; `exe==store python` (exact resolve);
  `cmdline[0]==staged venv python`; `cwd==WorkingDirectory`;
  `HERMES_HOME` in environ; `gateway_state.json` I6;
  `GET /api/health` I7. Any miss ⇒ fail.
- CLI: `/usr/bin/python3 -I -B /opt/hermes-maintenance/scripts/maintenance/cutover.py
  <subcommand> …` with NO `PYTHONPATH`; facade inserts
  `/opt/hermes-maintenance` at `sys.path[0]` via stdlib.

## 8. Verified commands (this host, this tree)

- `python3 -m pm.build_env --help` → `--source/--out/--python/--cache…`
  (`pm/build_env.py`); `pm.client.build_environment(source,out,…)`.
- `PYTHONPATH=/tmp/opencode python3 -I -c …` → `sys.path` WITHOUT
  `/tmp/opencode` (proves I7 doc fix).
- `python3 -m venv /tmp/opencode/probe/venv1` → `bin/python3` symlink chain
  → store `python3.14`; child `sleep` → `/proc exe`=store, `cmdline[0]`=venv,
  `cwd`=launch dir (proves §1.2).
- `systemctl show hermes-gateway/-dashboard -p MainPID,ActiveEnterTimestamp,
  NRestarts,ExecStart` → `15839/15683`, `NRestarts=0`, launcher `ExecStart`
  (proves §3 ladder).
- `os.readlink(/proc/<MainPID>/exe)` → store `python3.14` both;
  `cmdline[0]` → store python bootstrap; `cwd` → `/home/ubuntu/.hermes`
  + `/home/ubuntu` (proves exe≠generation).
- `curl /api/health` → `200 {"commit":"50e82ad…"}`, `/health` → `302`
  (proves §1.5); `gateway_state.json:code_sha=50e82ad…==live HEAD`,
  `pid=15839==MainPID` (proves §1.4 schema).
- `install_key(/home/ubuntu/.hermes/hermes-agent)=5f0a1ff4045d044e`,
  `runtime_facts=…/installs/…/facts.json:{venv:{environment:…/environments/<uuid>/venv}}`
  vs `tools/facts.json:{python,uv,node…}` (proves §1.6 facts fix).
- `hermes_cli.version_info.get_code_identity()` in worktree →
  `sha=be9628fa…` (candidate), live dashboard `commit=50e82ad…` (parent).

Parent owns live `systemctl`, root-only dropins (`zz-runtime-3.14.9.conf`
permission-denied as `ubuntu`), and `/opt/hermes-maintenance` deploy.
This tree performs NO live restart/outbound/data mutation.
