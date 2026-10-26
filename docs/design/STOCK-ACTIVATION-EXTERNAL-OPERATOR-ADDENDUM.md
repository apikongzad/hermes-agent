# Stock Activation External Operator — Addendum

## 1. Binding

This file replaces addendum sha256
`0820730235ee23115551dc3d1212594193f8aacf32fcb2dce4557cc5b72571ff`.
That hash is DESIGN_NO_GO. It is not controlling. Do not follow it.

This addendum is bound to base file
`docs/design/STOCK-ACTIVATION-EXTERNAL-OPERATOR.md`
at base sha256
`70fc9debac3bdf25b2a52d6413a8bc42e03d00fd38a925faf33b98e7a39c18c9`
and base commit `ac3d03d991248e998d43693471dd6f6a06147c30`.
The base file is not edited by this addendum.

Its own sha256 is the later review binding.

Where this addendum and the base conflict, this addendum controls.
Section 2 is the only procedure. Section 3 names every base operational
clause that must not be followed. There is no second procedure.

A GO on this addendum's own sha256 would authorize only a later hermetic
implementation slice. It would not authorize provisioning, install,
restart, merge, journal migration, or activation.
No live command in this addendum is authorized now.
This authoring does not authorize hermetic implementation.

Owner facts below were already verified read-only on 2026-10-27.
Use these. Do not re-probe secrets. Do not invent substitutes.

## 2. Effective contract

One procedure. No alternate order. No second rollback start.
No second health contract. No EnvironmentFile byte read.

### 2.1 Pins and live fleet

- TARGET_SHA: `daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06`
- KNOWN_GOOD_SHA: `1d9a377fa00ce0e663e274e16b63c75e36233b9e`
- Refuse `1c12738cfeecc78570b3a4ba3797a49de59cfdfe`.
- Refuse `scripts/maintenance/cutover_*.py` as the launcher.
- Do not start `/opt/hermes-maintenance` or `/opt/hermes-maintenance-next`.
- `hermes-gateway.service` stays untouched by this design.
  MainPID=583405. `Restart=always`. `RestartUSec=5s`.
  WorkingDirectory=/home/ubuntu/.hermes.
- `hermes-dashboard.service` stays untouched by this design.
  MainPID=583247. `Restart=always`. `RestartUSec=5s`.
  WorkingDirectory=/home/ubuntu.
  Live unit text names `EnvironmentFile=/home/ubuntu/.hermes/.env`.
  Do not open that file.
- Do not checkout or mutate the known-good worktree.
- Candidate tree at
  `/home/ubuntu/.hermes/runtime/stock-candidates/daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06`
  and generation `gen-daec3cd4c6d3` are copy inputs, not execution roots.

### 2.2 Closed facts that remain inputs

- Gateway `zz-runtime-3.14.9.conf` sha256
  `2a495ff333ffdc6b0b61aeab46718ad135e1bd107754b634b82c0445d68cc9eb`,
  74 bytes. Dashboard counterpart sha256
  `aa6d8c52fae720306ded7c9b4b037b33efa48026837484a3b487d9f4a647ffed`,
  124 bytes. Those files stay on disk and are not rewritten.
- Empty assignment is the proven systemd list-reset form.
  Use that same form for `ExecStart=`, `ExecStop=`, `ExecStopPost=`,
  and `EnvironmentFile=`.
- I10 allows only in-place replacement of `zzz-candidate.conf`.
- Journal directory: `/var/lib/hermes-stock-activation`, mode 0700, uid 0.
  Parent `/var/lib` is uid 0 mode 0755 and is not writable by uid 1001.
  Journal file and recovery program both live in that directory.
  Recovery program is not `/opt`, not `cutover_*.py`, and not a uid-1001 path.
  Do not reuse `/var/lib/hermes-cutover`. Do not read `cutover.env`.
- Backing parent is that same root-owned activation directory.
  Expose each snapshot only as a kernel read-only mount
  (erofs, squashfs, or a read-only bind whose backing is not also writable).
  `chmod` is not immutability. Denial must hold for write, rename, and
  hardlink, including any second mount of the same backing.
- `snapshotted` is not a legal state and not a legal transition.

### 2.3 Canonical journal

These names are the legal states. `known-good-frozen` and `stop-fenced`
are legal. They replace the base next-state cells at lines 308 and 310.
`snapshotted` is not legal. No other new state name is added.
`missing-loader-evidence` is a journal reason, not a state.

| State | Only legal next states |
|---|---|
| `observed` | `dropins-read`, `blocked-unread`, `stopped-unresolved` |
| `dropins-read` | `target-bound`, `blocked-unread`, `stopped-unresolved` |
| `target-bound` | `known-good-frozen`, `stopped-unresolved` |
| `known-good-frozen` | `backup-verified`, `durable-state-unknown`, `stopped-unresolved` |
| `backup-verified` | `candidate-materialized`, `stopped-unresolved` |
| `candidate-materialized` | `stop-fenced`, `durable-state-unknown`, `stopped-unresolved` |
| `stop-fenced` | `units-published`, `rolling-back`, `stopped-unresolved`, `durable-state-unknown` |
| `units-published` | `reloaded`, `rolling-back`, `durable-state-unknown` |
| `reloaded` | `restarted`, `rolling-back`, `durable-state-unknown` |
| `restarted` | `health-verified`, `rolling-back`, `durable-state-unknown`, `stopped-unresolved` |
| `health-verified` | `committed`, `rolling-back` |
| `committed` | terminal |
| `rolling-back` | `rolled-back`, `durable-state-unknown`, `stopped-unresolved` |
| `rolled-back` | terminal |
| `durable-state-unknown` | `stop-fenced` only after root readback re-establishes durability and this invocation has re-verified the 5s inactive fence; otherwise `stopped-unresolved`. Never `committed`. Never `rolled-back`. Never a start of pre-transaction bytes. |
| `stopped-unresolved` | terminal |
| `blocked-unread` | terminal |

`target-bound` does not go directly to `backup-verified`.
`candidate-materialized` does not go directly to `units-published`.
`backup-verified` still comes before `candidate-materialized`.
That order is closed and is not reopened.

Pre-fence abort does not stop the still-healthy live fleet.
Not proceeding before the fence is not a transition.
The journal stays at the last pre-fence state.
`stopped-unresolved` means services were left stopped because identity
could not be verified. It is not an instruction to stop a healthy fleet.

### 2.4 Single order

1. `observed`. Record boot id, `systemctl show`, MainPID, starttime, exe,
   cmdline, cgroup, and unit bytes.
2. `dropins-read`. Re-hash both `zz-runtime` files before any unit write.
   They must equal the two sha256 values above, or the machine stops at
   `blocked-unread`.
3. `target-bound`. Record `daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06`.
   No other SHA is legal for this transaction.
4. `known-good-frozen`, before any stop and before any unit publication.
   Root copies the currently executing closure into a backing directory
   under `/var/lib/hermes-stock-activation/backing`.
   This snapshot, not `gen-1d9a377fa00c` and not the worktree, is the only
   rollback execution root. Apply the snapshot-copy fsync rule in 2.6.
5. `backup-verified`. Full user-data backup, fail-closed, before candidate
   materialization.
6. `candidate-materialized`. Copy pinned SHA
   `daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06` plus the generation closure
   into a second kernel read-only snapshot with the same backing-parent
   rules and the same snapshot-copy fsync rule. Then run the I2 checks.
   Any failure stops before publish.
7. `stop-fenced`, before any unit publication and before any unit restore.
   Apply the fence rule in 2.5.
8. `units-published` only while this invocation is stop-fenced.
   In-place `zzz-candidate.conf` only. Unit file fsync and directory fsync
   per base I3. Do not start.
9. `reloaded` while both units are still inactive.
   `systemctl show` must match the journal. If not, do not start.
   A restore at this point is the snapshot rollback unit in 2.7,
   only after the fence is re-verified. It is not a start of
   pre-transaction bytes.
10. `restarted` by one explicit start, not by `Restart=`. Then I4 readback.
11. `health-verified` using only the two probe contracts in 2.8.
12. `committed` only after `health-verified`.

### 2.5 Fence

Before any unit publication, any unit-byte restore, or any start,
including interruption recovery and including rollback, this invocation
must:

1. `systemctl stop` both units.
2. Verify `ActiveState=inactive` and `MainPID=0` for both.
3. Wait at least `RestartUSec=5s`.
4. Re-verify both still inactive, `MainPID=0`, and `NRestarts` unchanged
   from the post-stop read.

If either unit returns active, or `NRestarts` increases, do not publish,
do not restore, and do not start.
Manager stop is the fence. Do not rely on killing the main process,
because `Restart=always` would respawn it.
A journal row that already says `stop-fenced` does not skip this
re-verify on a later invocation.

Interruption recovery reads the journal and the physical state.
It does not guess. It does not delete the journal.
It does not start a second restart while `MainPID` or `starttime`
cannot be bound to the intended bytes.
If the next action would publish, restore, or start, it re-enters this
fence first.

### 2.6 Snapshot-copy fsync

Both the known-good copy and the candidate copy use a temp file in the
root-owned backing parent, then file `fsync`, then rename, then
containing-directory `fsync`.

`OSError` from either `fsync` is `durable-state-unknown`.
Do not publish. Do not start. Do not claim that copy is an execution root.
If rename succeeded and directory `fsync` did not, the state is
indeterminate `durable-state-unknown`, not rollback-clean and not success.

Base I3 lines 246-249 remain in force for unit publication.
Base lines 360-363 remain in force for unit publish and unit rollback
`fsync`. Base line 318's durability definition remains and also binds
both snapshot copies. `ProductionHost.write_bytes` remains unfit.
Do not use it.

### 2.7 Rollback start

While this invocation is stop-fenced, the only legal rollback start is
one in-place `zzz-candidate.conf` whose `ExecStart` interpreter and entry
are inside the pre-stop known-good snapshot.

Preserve the pre-transaction unit bytes in the journal as evidence.
Do not write those bytes back as the started unit.
Do not start them. They name `gen-1d9a377fa00c` and the worktree.

`rolled-back` means all of the following:
- the stop-fence was held for the rollback publication and the rollback start
- snapshot `ExecStart` was published with file and directory `fsync`
- one explicit start occurred
- I4 `exe` and `cmdline` are inside the known-good snapshot
- I4 `exe` and `cmdline` do not contain the worktree path or
  `gen-1d9a377fa00c`
- health uses the two probe contracts in 2.8 against that snapshot identity

Byte-equality to pre-transaction unit copies is not the success predicate.

If the known-good snapshot is missing or writable, leave both units
stopped and report `stopped-unresolved`.
Do not `git checkout` the live worktree. Do not restore `state.db`.

`rolling-back` is legal only after this invocation's stop-fence re-verify.
Its only start is the snapshot `ExecStart` above.

### 2.8 Health contracts

Two contracts. No fallback endpoint. No changed constants.
The base word `authenticated` does not authorize an Authorization header,
a cookie, a bearer token, or a `.env` read on the dashboard probe.

Dashboard: GET `http://127.0.0.1:9119/api/health` with no Authorization,
no cookie, and no bearer. Do not read `.env` to obtain a token.
Deadline 15.0 seconds. Source constant `DEFAULT_PROBE_TIMEOUT_MS = 15000`.
Do not use `HERMES_PROBE_TIMEOUT_MS` overrides.
Success is HTTP 200, `application/json`, and `ok=true`.
A 401 or a 403 is failure, not a cue to attach credentials.
Timeout, non-200, HTML, or `ok!=true` is health failure.
Do not use GET `/health`. Do not use `127.0.0.1:50185`.
Do not use `api_server` port 8642.
JSON `commit` is not provenance.

Gateway: AF_UNIX identify, not HTTP.
Request bytes exactly `{"verb":"identify","id":1,"protocol":1}` plus newline.
Deadline 2.0 seconds.
Success: `ok==true`, `result.protocol==1`, `result.pid` equals the new
MainPID, and `SO_PEERCRED` pid equals MainPID and uid equals 1001.
Do not send `pause-for-update`. Do not trust code SHA fields in the payload.
Peer credentials are the socket auth boundary.
That boundary is not an Authorization header and not a `.env` token.

Rollback health uses these same two contracts against the snapshot identity.

### 2.9 EnvironmentFile oracle

One rule. Do not open `/home/ubuntu/.hermes/.env`.
Do not list key names from it. Do not record values from it.

Pre-start loader evidence is static unit text plus `systemctl show`
metadata only, while this invocation is stop-fenced and both units are
inactive:

- Dashboard `zzz-candidate.conf` contains `EnvironmentFile=` as an empty
  list-reset, the same form as `ExecStart=`.
- After reload, `systemctl show` EnvironmentFiles for the dashboard is
  empty or absent. If it still names `/home/ubuntu/.hermes/.env` or any
  file, do not start and do not open the file.
  Remain `stop-fenced`, or enter `stopped-unresolved` with journal reason
  `missing-loader-evidence`.
- Forbidden loader key names must be absent from `Environment=` lines in
  the unit text being published and from environment key names
  `systemctl show` reports without opening a file.
  Names: `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONUSERBASE`,
  `PYTHONEXECUTABLE`, `PYTHONSAFEPATH`, `PYTHONNOUSERSITE`, `PYTHONINSPECT`.
- If `VIRTUAL_ENV` is set in that unit text, it must name the snapshot
  venv, not `/home/ubuntu/.hermes/hermes-agent/venv`.
- If `systemctl show` cannot prove EnvironmentFile is unset, that is
  missing loader evidence. Block. Do not invent a file read.

Post-start `/proc/PID/environ` key-name observation is a failure detector
after start. It is not a pre-start oracle and not a reason to read `.env`.
A forbidden key after start is I2 failure and enters snapshot rollback
only through the fence. It does not authorize the start that already
happened.

### 2.10 What an implementer must not follow

An implementer follows section 2 only.
A base sentence named in section 3 is not a procedure.
The replaced addendum hash is not a procedure.

## 3. Exhaustive supersession

Search of the base for restore, restart, authenticated, EnvironmentFile,
fsync, rolling-back, and units-published added two further contradicting
procedures beyond the six review ranges: lines 19-21, and the
`rolling-back` next-state cells at lines 308, 309, and 318.
No other base sentence is a contradicting procedure.
Threat-model observations, updater non-use, and evidence preservation
stay in section 4.

| ID | Base lines | Do not follow | Single replacement | Status |
|---|---|---|---|---|
| S1 | 19-21, 255-259, 316-317, 342-346, 351-353, 457-458, 474-475, 512, 545-548 | Do not restore pre-transaction unit bytes into the started unit. Do not start those bytes. Do not treat byte-equality to those copies as `rolled-back`. Do not use the worktree or `gen-1d9a377fa00c` as the rollback execution root. | Section 2.7. One rollback start: snapshot `ExecStart` while stop-fenced. Pre-transaction bytes stay journal evidence. `rolled-back` matches snapshot `exe` and `cmdline`. | superseded |
| S2 | 310-313, 316-319, 322-330, 442-461, 509 | Do not publish, restore, or start from a legal-next cell or an interruption resume without this invocation's stop plus 5s inactive re-verify. | Section 2.5. The fence applies to normal publication, restore, rollback start, and interruption recovery. | superseded |
| S3 | 308, 309, 310, 318 | Do not use base line 308's next cell `backup-verified`. Do not use base line 310's next cell `units-published`. Do not use `rolling-back` from lines 308, 309, or 318 as a start of pre-transaction bytes. Line 308's SHA-assumption sentence stays superseded by the pin in section 4. Line 309's order `backup-verified` then `candidate-materialized` remains. | Section 2.3. `known-good-frozen` and `stop-fenced` are legal states with the next cells in that table. | superseded |
| S4 | 424-430 | Do not treat the supersession of base section 8 steps 4 and 6 as dropping snapshot-copy `fsync`. | Section 2.6 restates file `fsync`, directory `fsync`, `OSError` as `durable-state-unknown`, and rename-before-directory-fsync as indeterminate. Lines 246-249, 318, and 360-363 remain in force. | superseded |
| S5 | 314, 317, 334-339, 342-346, 452-454, 474 | Do not send dashboard credentials because the base says authenticated. A 401 or 403 is not a cue to attach a token. Base "unauthenticated response" is not a failure of the no-Authorization dashboard 200 contract. | Section 2.8. Dashboard probe has no Authorization. Gateway probe stays identify plus `SO_PEERCRED`. | superseded |
| S6 | replaced addendum hash `0820730235ee23115551dc3d1212594193f8aacf32fcb2dce4557cc5b72571ff` lines that both forbade and permitted opening the EnvironmentFile | Do not list key names from `/home/ubuntu/.hermes/.env`. Do not open it. | Section 2.9. Static unit directive and `systemctl show` metadata only. Missing proof blocks. Base lines 97 and 111-113 remain a prohibition. | superseded |

## 4. Remains in force

These are not reopened.

| Item | Disposition |
|---|---|
| Journal parent `/var/lib/hermes-stock-activation` mode 0700 uid 0; recovery program in that directory; not `/opt`; not `cutover_*.py` | remains |
| Backing parent kernel read-only mount; `chmod` is not immutability; second-mount and hardlink denial | remains |
| Materialize order: `backup-verified` before `candidate-materialized` | remains |
| SHA pin `daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06`; known-good `1d9a377fa00ce0e663e274e16b63c75e36233b9e`; refuse `1c12738cfeecc78570b3a4ba3797a49de59cfdfe`; supersedes base lines 29-31, 308 SHA sentence, 421-423, and 484-485; no generic reapproval | remains |
| `snapshotted` withdrawn; base line 306 phrase is not a legal state | remains |
| Dashboard GET `/api/health` no Authorization, 15.0s, `ok=true`; gateway identify, 2.0s, `result.pid` and `SO_PEERCRED`; no fallback endpoint | remains |
| Unit publication `fsync`: base I3 lines 246-249; file and directory `fsync`; `OSError` is `durable-state-unknown` | remains |
| Base lines 97 and 111-113: do not read `/home/ubuntu/.hermes/.env` | remains |
| Base lines 360-363 and the durability definition at line 318 | remains |
| Do not `git checkout` the live worktree. Do not restore `state.db`. | remains |
| `ProductionHost.write_bytes` unfit | remains |
| A1-A13 and B1-B7 | UNEXECUTED |

Preservation of pre-transaction unit bytes in the journal remains required
evidence. That preservation is not permission to start those bytes.

## 5. Acceptance ledger

Every row is UNEXECUTED. No probe is passed. No health is claimed.
No immutability is claimed. No unit was written.

| ID | Required evidence | Status |
|---|---|---|
| A1 | Kernel denies uid-1001 write, rename, and hardlink in the mounted snapshot and through a second mount | UNEXECUTED |
| A2 | ExecStart interpreter and entry are inside the snapshot; no worktree path; no `PYTHONPATH`; `sitecustomize` disposition proven or blocked | UNEXECUTED |
| A3 | Injected file `fsync` `OSError` and directory `fsync` `OSError` on publish yield `durable-state-unknown`; no restart; no success claim | UNEXECUTED |
| A4 | Interruption after publish re-enters the 5s inactive fence before any further publish, restore, or start; no second restart while identity is ambiguous; journal is not deleted | UNEXECUTED |
| A5 | Interruption after restart binds one readback; no duplicate restart while ambiguous | UNEXECUTED |
| A6 | Post-start boot id, MainPID, starttime, exe, cmdline, and cgroup match the journaled snapshot identity, or the result is declared failure | UNEXECUTED |
| A7 | After rollback, exe and cmdline are inside the known-good snapshot and do not contain the worktree path or `gen-1d9a377fa00c`. Byte-equality to pre-transaction unit copies is not the success predicate. | UNEXECUTED |
| A8 | User data is unchanged by the code path; backup is verified separately | UNEXECUTED |
| A9 | Both `zz-runtime` digests match section 2.2 before any unit write, or activation is blocked | UNEXECUTED |
| A10 | Read-only `hermes update --plan` still mismatches the live ExecStart tree; updater is not used | UNEXECUTED |
| A11 | Digest record is root-owned, outside the snapshot and outside uid-1001 trees, and is never called signed | UNEXECUTED |
| A12 | Pre-start `ExecStop` and `ExecStopPost` match journaled intent, or the transaction is blocked; no residual v0.21.7 hooks | UNEXECUTED |
| A13 | Only `zzz-candidate.conf` is replaced in place | UNEXECUTED |
| B1 | Rollback execution root is the pre-stop kernel read-only known-good snapshot. Rollback `ExecStart` paths are inside that snapshot. `rolled-back` is not byte-equality to pre-transaction unit copies. | UNEXECUTED |
| B2 | Journal and recovery program are root-owned at `/var/lib/hermes-stock-activation` mode 0700 uid 0. Parent is not writable by uid 1001. `/opt` is not started. | UNEXECUTED |
| B3 | Both units are inactive, MainPID=0, still inactive after at least 5s, and NRestarts is unchanged, before any publication, restore, or start, including interruption recovery. | UNEXECUTED |
| B4 | Journal order has `backup-verified` before `candidate-materialized`. No other order is legal. | UNEXECUTED |
| B5 | The document contains no legal `snapshotted` state or transition. | UNEXECUTED |
| B6 | The only target is `daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06`. `1c12738` is refused. No generic reapproval. | UNEXECUTED |
| B7 | I2 checks and the two health contracts in section 2.8, with no fallback endpoint. Dashboard health sends no Authorization. A 401 or 403 is failure. | UNEXECUTED |

## 6. Checklist

- BASE_FILE: docs/design/STOCK-ACTIVATION-EXTERNAL-OPERATOR.md
- BASE_SHA256: 70fc9debac3bdf25b2a52d6413a8bc42e03d00fd38a925faf33b98e7a39c18c9
- BASE_COMMIT: ac3d03d991248e998d43693471dd6f6a06147c30
- REPLACED_ADDENDUM_SHA256: 0820730235ee23115551dc3d1212594193f8aacf32fcb2dce4557cc5b72571ff
- REPLACED_ADDENDUM_VERDICT: DESIGN_NO_GO
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
- PROVISIONING: not authorized
- HERMETIC_IMPLEMENTATION: not authorized by this authoring
