# Stock Activation External Operator — Addendum

## Binding

This addendum is bound to base file
`docs/design/STOCK-ACTIVATION-EXTERNAL-OPERATOR.md` at base sha256
`70fc9debac3bdf25b2a52d6413a8bc42e03d00fd38a925faf33b98e7a39c18c9`
and base commit `ac3d03d991248e998d43693471dd6f6a06147c30`.

Its own sha256 is the later review binding.

A GO on this addendum would authorize only a later hermetic implementation
slice, not provisioning, install, restart, merge, or activation.
No live command in the addendum is authorized now.

Where the addendum and the base file conflict, the addendum controls.
Each superseded clause is named below. There is no second global
alternative and no second global rule. This addendum does not expand a new
controller framework. It keeps one minimal external root operator
transaction.

Owner facts below were already verified read-only on 2026-10-27.
Use these; do not re-probe secrets; do not invent substitutes.

## 1. Live fleet, leave untouched

- `hermes-gateway.service` active, `User=ubuntu` uid 1001,
  MainPID=583405, starttime=6962673, `Restart=always`, `RestartUSec=5s`,
  `WorkingDirectory=/home/ubuntu/.hermes`, NRestarts=0.
- ExecStart argv:
  `/home/ubuntu/.hermes/runtime/cutover-generations/gen-1d9a377fa00c/venv/bin/python3`
  `/home/ubuntu/worktrees/worktrees/hermes-upstream-integrate-20261025/hermes_cli/main.py`
  `gateway run`.
- ExecStop:
  `/home/ubuntu/.hermes/hermes-agent/venv/bin/python -m gateway.systemd_stop_mark ignore_errors=yes`.
- ExecStopPost:
  same venv python `-m gateway.cgroup_cleanup ignore_errors=yes`.
- `hermes-dashboard.service` active, MainPID=583247, starttime=6962258,
  `Restart=always`, `RestartUSec=5s`, `WorkingDirectory=/home/ubuntu`,
  `EnvironmentFile=/home/ubuntu/.hermes/.env` (do not read it),
  no ExecStop and no ExecStopPost.
- ExecStart argv: same generation python plus the same worktree
  `hermes_cli/main.py`
  `dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build`.
- Both processes still those PIDs. Old generation `gen-1d9a377fa00c`
  served from worktree SHA `1d9a377fa00ce0e663e274e16b63c75e36233b9e`.
  Do not checkout or mutate that worktree.
- Resolved interpreter exe for both PIDs is the CPython 3.14.9 prefix
  named by `pyvenv.cfg` home. The tools directory name was masked in one
  log; do not write the masked asterisk form. Write only: the
  `pyvenv.cfg` home path, read by the operator from both generation
  venvs, which is the uid-1001 tools prefix bin directory for CPython
  3.14.9. The exact directory spelling is the `pyvenv.cfg` home value,
  not a guessed date.

## 2. Verified drop-ins

Owner `sudo -n`, not privilege-blocked:

- `/etc/systemd/system/hermes-gateway.service.d/zz-runtime-3.14.9.conf`
  sha256
  `2a495ff333ffdc6b0b61aeab46718ad135e1bd107754b634b82c0445d68cc9eb`,
  74 bytes:
  ```
  [Service]
  ExecStart=
  ExecStart=/home/ubuntu/.local/bin/hermes gateway run
  ```
- `/etc/systemd/system/hermes-dashboard.service.d/zz-runtime-3.14.9.conf`
  sha256
  `aa6d8c52fae720306ded7c9b4b037b33efa48026837484a3b487d9f4a647ffed`,
  124 bytes:
  ```
  [Service]
  ExecStart=
  ExecStart=/home/ubuntu/.local/bin/hermes dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build
  ```

That empty-assignment line is the proven systemd list-reset form already
in those files. Require the same form for `ExecStop=` and
`ExecStopPost=` inside the later in-place `zzz-candidate.conf`
replacement. Do not invent a different reset syntax. If post-reload
`systemctl show`, while both units are inactive, still names
`/home/ubuntu/.hermes/hermes-agent/venv`, block. Do not leave stop hooks
on v0.21.7. If snapshot-bound stop modules cannot be proven inside the
snapshot, a successful empty reset with no replacement hook is the
required outcome, not a residual v0.21.7 hook. Dashboard has no stop
hooks today; do not add the v0.21.7 hooks.

`zz-runtime` files stay on disk and are not rewritten. I10 still allows
only in-place replacement of `zzz-candidate.conf`. Effective ExecStart
after reload must be the snapshot interpreter, not the `zz-runtime`
wrapper `/home/ubuntu/.local/bin/hermes`.

## 3. PIN, no generic reapproval

Activation target is exactly
`daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06`.

`git rev-parse upstream/main` in this worktree returned that SHA. Owner
directed this operational freeze. This supersedes base lines 29-31, 308,
421-423, and 484-485. Do not say "not daec3cd4 by assumption" and do not
require another generic user approval. Still refuse
`1c12738cfeecc78570b3a4ba3797a49de59cfdfe` and
`scripts/maintenance/cutover_*.py` as the launcher. Do not start
`/opt/hermes-maintenance` or `/opt/hermes-maintenance-next`.

Candidate tree exists at
`/home/ubuntu/.hermes/runtime/stock-candidates/daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06`,
detached HEAD that SHA, uid 1001. Generation `gen-daec3cd4c6d3` exists,
uid 1001, mode 0700. Neither is an execution root.

## 4. Interpreter contract

Verified on the live 3.14.9 interpreter with `python -I -c`, not a
service start:

- `sys.flags.isolated=1`, `ignore_environment=1`, `no_user_site=1`,
  `safe_path=True`, `no_site=0`.
- `python -I` does not disable `site.py`. `pyvenv.cfg` is therefore an
  execution input.
- Both generation `pyvenv.cfg` files say `version_info=3.14.9`,
  `include-system-site-packages=false`, `relocatable=true`, `uv=0.13.5`,
  `home=` the uid-1001 tools prefix bin directory.
  `relocatable=true` is not immutability. `home` outside the snapshot
  fails I2.
- A nested file exists at
  `venv/lib/python3.14/site-packages/opentelemetry/instrumentation/auto_instrumentation/sitecustomize.py`
  in both generations. That path is not automatically the `sitecustomize`
  import unless `find_spec("sitecustomize")` returns it. The check is the
  `find_spec` result, not a guess.
- Live gateway environ key names include `VIRTUAL_ENV` and do not
  include `PYTHONPATH`. `VIRTUAL_ENV` currently names
  `/home/ubuntu/.hermes/hermes-agent/venv` while ExecStart uses the
  generation venv. That mismatch is not trust.
- Dashboard environ key names include `HERMES_HOME` and do not include
  `PYTHON*` or `VIRTUAL_ENV`.

## 5. Health contracts

One contract each. No fallback.

### Dashboard

GET `http://127.0.0.1:9119/api/health` with no Authorization, no cookie,
no bearer. Do not read `.env` to obtain a token. Live result 2026-10-27:
HTTP 200, `application/json`, keys `auth_required`, `commit`,
`displayVersion`, `ok`, `version`, `ok=true`. `auth_required=true` in the
body describes other routes; this probe itself is public
(`PUBLIC_API_PATHS` contains `/api/health` in both the live tree and
the pinned candidate). A 401/403 is failure, not a cue to attach
credentials.

Deadline: 15.0 seconds. Source constant `DEFAULT_PROBE_TIMEOUT_MS =
15000` in `apps/desktop/electron/backend-probes.ts`, present in both the
live tree and the pinned candidate. Do not use
`HERMES_PROBE_TIMEOUT_MS` overrides. Timeout, non-200, HTML, or
`ok!=true` is health failure.

Do not use GET `/health`. Live GET `http://127.0.0.1:9119/health`
returned 200 `text/html`, not the contract.

Do not use `127.0.0.1:50185`. A GET there returned HTML. It is not the
gateway health contract. `api_server` port 8642 is not the live
listener.

JSON `commit` is not provenance. I4 process identity is provenance.
Record `commit` only as a non-authoritative observation.

### Gateway liveness

AF_UNIX control socket, not HTTP. Product text in
`gateway/control_socket.py`, both trees: a connectable socket with a
well-formed identify answer is liveness; never a TCP port; filesystem
ACLs are the auth boundary; one JSON line in, one out. Request bytes
exactly `{"verb":"identify","id":1,"protocol":1}` plus newline. Deadline
2.0 seconds (`_DEFAULT_CLIENT_TIMEOUT = 2.0` in both trees). Success:
response `ok==true`, `result.protocol==1`, `result.pid` equals the new
MainPID, and `SO_PEERCRED` pid equals MainPID and uid equals 1001. Do
not send `pause-for-update`. Do not trust code SHA fields in the
payload.

Live socket `/home/ubuntu/.hermes/gateway.sock` exists, not a symlink,
mode 0600, uid 1001. Its parent is uid-1001 writable, so a path connect
is not auth. Peer credentials are the auth. No pointer file was present.

This supersedes base I2 and section 6 health paragraphs that leave
flags, endpoint, auth, and deadline unbound (see B7).

## 6. Journal and recovery

- New root-owned directory `/var/lib/hermes-stock-activation` mode 0700
  uid 0, not created by this design.
- Parent `/var/lib` is uid 0 mode 0755 and is not writable by uid 1001.
  Ancestors `/` and `/var` are the same. uid 1001 cannot replace that
  directory.
- Journal file and the recovery program both live in that directory.
  Recovery program is not `/opt/hermes-maintenance`, not
  `cutover_*.py`, and not any uid-1001 path.
- Do not reuse `/var/lib/hermes-cutover`. It exists, root 0700, and
  holds prior controller journals plus `cutover.env`. Do not read
  `cutover.env`. Do not treat those journals as this transaction's
  journal.

## 7. Required single order

This supersedes base section 8 where it materializes the candidate
before backup. The state table order wins: backup-verified before
candidate-materialized. It also inserts the two missing gates. No
alternate order.

1. observed. Record boot id, `systemctl show`, MainPID, starttime, exe,
   cmdline, cgroup, unit bytes. Onward only dropins-read,
   blocked-unread, or stopped-unresolved.
2. dropins-read. Re-hash both `zz-runtime` files before any unit write.
   They must equal the two sha256 values above or the machine stops at
   blocked-unread. Owner `sudo -n` is verified, so missing privileges are
   not a blocker. The base "unread/UNVERIFIED" wording at lines 193-199,
   271-275, 412-415, and 479 is superseded as a privilege claim, not as
   a skip of the re-hash.
3. target-bound. Record
   `daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06`. No other SHA is legal for
   this transaction.
4. known-good-frozen, before any stop and before any unit publication.
   Root copies the currently executing closure into a backing directory
   under `/var/lib/hermes-stock-activation/backing`. Parent of that
   backing is root-owned and not writable by uid 1001. Expose it only as
   a kernel read-only mount (erofs, squashfs, or a read-only bind whose
   backing is not also writable). `chmod` is not immutability. Denial
   must hold for write, rename, and hardlink, including any second mount
   of the same backing. No writable alias and no hardlink from a
   uid-1001 tree. Contents: the argv interpreter, the resolved CPython
   prefix named by `pyvenv.cfg` home, `pyvenv.cfg`, the site-packages
   closure imported under `python -I`, and a copy of the entry tree at
   SHA `1d9a377fa00ce0e663e274e16b63c75e36233b9e`. Do not mutate the
   live worktree. This snapshot, not `gen-1d9a377fa00c` and not the
   worktree, is the only rollback execution root.
5. backup-verified. Full user-data backup fail-closed per I6, before
   candidate materialization. This supersedes base section 8 steps 4 and
   6, which currently materialize first.
6. candidate-materialized. Copy pinned SHA
   `daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06` plus the generation closure
   into a second kernel read-only snapshot with the same backing-parent
   rules. The uid-1001 candidate directory and `gen-daec3cd4c6d3` are
   inputs to the copy, not the execution root. Then run the I2 checks
   below. Any failure stops before publish.
7. stop-fenced, before any unit publication and before any unit restore.
   `systemctl stop` both units. Verify `ActiveState=inactive` and
   `MainPID=0` for both. Wait at least `RestartUSec=5s`. Re-verify both
   still inactive, `MainPID=0`, and NRestarts unchanged from the
   post-stop read. If either returns active or NRestarts increases, do
   not publish and do not restore. Manager stop is the fence; do not
   rely on killing the main process, because `Restart=always` would
   respawn it. Both units have `Restart=always` and `RestartUSec=5s`.
   This supersedes base section 8 steps 8-12 and the rollback paragraph
   at 456-460, which publish or restore without an inactive gate.
8. units-published only while stop-fenced. In-place
   `zzz-candidate.conf` only. File and directory fsync. OSError is
   durable-state-unknown. Do not start. ExecStart shape, both units:
   snapshot interpreter, then `-I`, then the snapshot copy of
   `hermes_cli/main.py`, then the existing arguments (`gateway run`, or
   `dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build`). No
   worktree path. No `/home/ubuntu/.local/bin/hermes`. No `PYTHONPATH`.
9. reloaded while still inactive. `systemctl show` must match the
   journal. If not, restore prior unit bytes while still inactive and do
   not start.
10. restarted by one explicit start, not by `Restart=`. Then I4 readback.
11. health-verified using only the two contracts above.
12. committed only after health-verified.

## 8. Rollback execution

While stop-fenced inactive, the only legal rollback start is one in-place zzz-candidate.conf whose ExecStart interpreter and entry are inside the pre-stop known-good snapshot. Preserve the pre-transaction unit bytes in the journal as evidence. Do not start those pre-transaction bytes: they name gen-1d9a377fa00c and the worktree. If the known-good snapshot is missing or writable, leave both units stopped and report stopped-unresolved. Do not git checkout the live worktree. Do not restore state.db.

## 9. Withdraw the stale denial

Base line 306 says the only onward state on unread is blocked-unread,
not snapshotted. `snapshotted` is not a legal state and not a legal
transition. That denial phrase is superseded and withdrawn. Do not add a
`snapshotted` state. Do not invent a transition into it.

## 10. I2 executable checks, all required, no alternative flag set

- Interpreter `argv[0]` and its resolved exe are inside the snapshot.
- `pyvenv.cfg` is beside that venv, `version_info=3.14.9`,
  `include-system-site-packages=false`, and `home` resolves inside the
  snapshot.
- `python -I` is argv, proven by the snapshot interpreter printing
  `isolated=1`, `ignore_environment=1`, `safe_path=True`, `no_site=0`.
  If `import hermes_cli.main` fails under `python -I` with a clean
  environment and a cwd outside the tree, activation is blocked.
- `sitecustomize`: `find_spec("sitecustomize")` under that `python -I`
  is None, or its origin is inside the snapshot. An outside origin
  blocks.
- `WorkingDirectory` is explicit: gateway `/home/ubuntu/.hermes`,
  dashboard `/home/ubuntu`. These are user-data directories, not code
  roots. The `python -I` probe must show cwd absent from `sys.path`.
  Post-start `/proc/PID/cwd` must equal the journaled
  `WorkingDirectory`.
- Loader keys absent from the unit and from the effective environ:
  `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONUSERBASE`,
  `PYTHONEXECUTABLE`, `PYTHONSAFEPATH`, `PYTHONNOUSERSITE`,
  `PYTHONINSPECT`. If `VIRTUAL_ENV` is set, it must name the snapshot
  venv, not `/home/ubuntu/.hermes/hermes-agent/venv`. Before publish,
  root may list key names only from the dashboard EnvironmentFile. Do
  not record values. If a forbidden loader key name is present, block.
  This design does not read that file.

## 11. Compact acceptance ledger

Every row Status UNEXECUTED. No "or" column and no second global rule.

| ID | Blocker | Supersedes | Required evidence | Status |
| B1 | rollback execution root is the pre-stop kernel read-only known-good snapshot; backing parent root-owned and not uid-1001 replaceable; no writable alias | base I5 and section 6 rollback source that still names mutable unit ExecStart paths | snapshot mount read-only; uid-1001 write/rename/hardlink denied on the mount and on a second mount; rollback ExecStart paths are inside that snapshot | UNEXECUTED |
| B2 | journal and recovery program root-owned outside user-replaceable directories | base section 5 journal with no path | path /var/lib/hermes-stock-activation, mode 0700 uid 0, parent not writable by uid 1001; recovery program in that directory; /opt not started | UNEXECUTED |
| B3 | Restart=always 5s fence | base section 8 publish/rollback without inactive | both units inactive, MainPID=0, still inactive after >=5s, NRestarts unchanged, before any unit publication or restore | UNEXECUTED |
| B4 | backup-verified before candidate-materialized | base section 8 steps 4 then 6 | journal order has backup-verified before candidate-materialized; no other order is legal | UNEXECUTED |
| B5 | snapshotted denial withdrawn | base line 306 phrase "not snapshotted" | document contains no legal snapshotted state or transition | UNEXECUTED |
| B6 | target pinned | base lines 29-31, 308, 421-423, 484-485 | only daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06; not 1c12738; no generic reapproval | UNEXECUTED |
| B7 | executable I2 and health contracts | base I2 and section 6 health paragraphs that leave flags, endpoint, auth, and deadline unbound | the checks and the two health contracts in this addendum, with no fallback endpoint | UNEXECUTED |

Base probes A1 through A13 remain UNEXECUTED. This addendum does not
execute them and does not mark any passed. No health is claimed. No
immutability is claimed. No unit was written.

## Review checklist
- BASE_FILE: docs/design/STOCK-ACTIVATION-EXTERNAL-OPERATOR.md
- BASE_SHA256: 70fc9debac3bdf25b2a52d6413a8bc42e03d00fd38a925faf33b98e7a39c18c9
- BASE_COMMIT: ac3d03d991248e998d43693471dd6f6a06147c30
- ADDENDUM_CONTROLS_ON_CONFLICT: yes
- TARGET_SHA: daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06
- KNOWN_GOOD_SHA: 1d9a377fa00ce0e663e274e16b63c75e36233b9e
- LIVE_GATEWAY_PID: 583405
- LIVE_DASHBOARD_PID: 583247
- A1_A13: UNEXECUTED
- B1: UNEXECUTED
- B2: UNEXECUTED
- B3: UNEXECUTED
- B4: UNEXECUTED
- B5: UNEXECUTED
- B6: UNEXECUTED
- B7: UNEXECUTED
- ACTIVATION: not authorized
