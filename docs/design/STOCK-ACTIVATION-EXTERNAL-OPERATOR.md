# Stock activation via external root operator — design only

Base commit for this design: `1c12738cfeecc78570b3a4ba3797a49de59cfdfe`.
Review binding: the sha256 of this file, not HEAD alone.
This document is not an activation approval.
This document authorizes no provisioning, install, restart, drop-in write,
daemon-reload, merge, controller start, `hermes update`, plugin enable,
or state.db migration.

Decision reached by this document:

- Sibling-identity code at `1c12738cfeecc78570b3a4ba3797a49de59cfdfe`
  is not an activation approval.
- Stop controller patches. Do not extend `scripts/maintenance/cutover_*.py`
  as an activation path.
- Do not start the installed controller (`/opt/hermes-maintenance`,
  `/opt/hermes-maintenance-next`, or any staged copy).
- Do not run `hermes update` as this activation.
- The smallest later path is one external root operator transaction that
  binds a kernel-enforced read-only stock snapshot, with exact unit-byte
  rollback.
- No cryptographic signature is demanded or claimed. No genuine signature
  verifier exists in this scope. An independent root-owned digest of
  snapshot bytes and unit bytes, stored outside the snapshot and outside
  uid-1001 trees, is sufficient. That digest is never called signed.
  `signed=false` stays honest.

No live command in this document is to be executed by the design author.
The activation target SHA in this document is an owner input placeholder,
not `daec3cd4` by assumption and not `1c12738`. `daec3cd4` may be a
candidate input only after a separate review binds it.

## 1. Status

Design only. No code change. No live change.

- Worktree inspected for this design:
  source worktree
  `/home/ubuntu/worktrees/worktrees/stock-external-controller-compat`
  was reported clean at `1c12738cfeecc78570b3a4ba3797a49de59cfdfe`
  on `hermes/stock-external-controller-compat-20261026`.
- 81 cutover tests were reported passed on that tree under
  `/usr/bin/python3`. That pass does not close deployment and does not
  approve activation. Test success is a code-level signal only.
- Live facts cited in this document are parent-verified inputs dated
  2026-10-27, boot id prefix `a7d3326c`. They were not re-probed by the
  design author. Any needed fact absent below is marked UNVERIFIED.
- Content hash is the review binding: reviewers approve a specific sha256
  of `docs/design/STOCK-ACTIVATION-EXTERNAL-OPERATOR.md`, not HEAD alone
  and not a branch name. Any edit invalidates the review.
- A design GO, if ever given, would authorize only a later hermetic
  implementation slice, not root provisioning, not restart, not merge.

## 2. Assets and trust boundaries

Service user: `ubuntu`, uid 1001. Root operator: uid 0.

Same-UID writer (uid 1001) currently owns all of the following mutable
inputs and must be assumed able to mutate them after any check:

- Worktree
  `/home/ubuntu/worktrees/worktrees/hermes-upstream-integrate-20261025`,
  HEAD `1d9a377fa00ce0e663e274e16b63c75e36233b9e`, uid 1001, mode 0700.
- Candidate generation `gen-daec3cd4c6d3` and stock candidate tree
  `daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06`, uid 1001, mode 0700.
  Detached HEAD `daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06` was reported
  clean when checked. `chmod 0700` is not kernel immutability.
- Live generation `gen-1d9a377fa00c`, uid 1001, mode 0755.
- `~/.hermes` source, runtime, generations, and user data under uid 1001.
- Effective gateway ExecStart argv (live, read 2026-10-27):
  `/home/ubuntu/.hermes/runtime/cutover-generations/gen-1d9a377fa00c/venv/bin/python3`
  plus
  `/home/ubuntu/worktrees/worktrees/hermes-upstream-integrate-20261025/hermes_cli/main.py gateway run`.
- Effective dashboard ExecStart (live): same generation python plus the same
  worktree `hermes_cli/main.py dashboard --port 9119 --host 127.0.0.1 --no-open --skip-build`.
- Gateway `exe` resolves to
  `/home/ubuntu/.hermes/tools/python-3.14.9+20261021-linux-arm64/bin/python3.14`.
  Note: the date in the tools directory name was masked in one read as
  `202****1021`; treat the exact tools build id as UNVERIFIED beyond that
  prefix.
- Effective gateway environment keys readable in the allowed cat text:
  `HOME, USER, LOGNAME, PATH, VIRTUAL_ENV, HERMES_HOME,`
  `HERMES_SUPERVISED_CHILD, XDG_RUNTIME_DIR, DBUS_SESSION_BUS_ADDRESS`.
  No `PYTHONPATH` and no `sitecustomize` appeared in the cat text that the
  parent worker could read. `VIRTUAL_ENV` still names
  `/home/ubuntu/.hermes/hermes-agent/venv` while ExecStart uses the
  generation venv. That mismatch is evidence of a mixed install, not trust.
- Live gateway identity: `hermes-gateway.service` active, `User=ubuntu`
  (uid 1001), `MainPID=583405`, `starttime=6962673`,
  `cgroup=/system.slice/system-hermes.slice/hermes-gateway.service`,
  `cwd=/home/ubuntu/.hermes`, `Type=simple`, `Restart=always`,
  `KillMode=mixed`, `NoNewPrivileges=no`, `PrivateTmp=no`, `UMask=0077`.
- Live dashboard identity: `hermes-dashboard.service` active,
  `MainPID=583247`, `starttime=6962258`,
  `cgroup=/system.slice/hermes-dashboard.service`, `cwd=/home/ubuntu`,
  `NoNewPrivileges=yes`, `PrivateTmp=yes`, `KillMode=control-group`,
  `EnvironmentFile=/home/ubuntu/.hermes/.env` (do not read it).

Root operator is the only writer of the execution snapshot and unit bytes
in the proposed path. That is a future boundary, not a present claim.

Code snapshot versus user data:

- Code snapshot (future): a kernel-enforced read-only mount (read-only
  bind with immutable backing, erofs, or squashfs) containing only the
  interpreter and stock source bytes that ExecStart will execute.
- User data: `HERMES_HOME` state, `state.db`, logs, gateway sessions,
  `~/.hermes/.env`, and `EnvironmentFile` contents. User data is never
  part of the code snapshot and is never overwritten by the code
  transaction.
- `EnvironmentFile` and `.env` are not code trust. They are secrets and
  environment inputs. Their presence in the unit does not authenticate code.
  Do not read `/home/ubuntu/.hermes/.env` to evaluate this design.

ExecStop divergence (present, must be preserved in reasoning):

- `ExecStop` and `ExecStopPost` still point at
  `/home/ubuntu/.hermes/hermes-agent/venv/bin/python -m gateway.systemd_stop_mark`
  and `-m gateway.cgroup_cleanup`.
- That is a different install (`~/.local/bin/hermes` reports
  `Hermes Agent v0.21.7+166.g50e82ad`, install directory
  `/home/ubuntu/.hermes/hermes-agent`, HEAD `50e82ad783`, main ahead 1)
  than the live ExecStart generation venv + worktree.
- Stop hooks therefore do not prove start provenance. I9 covers this.

Unit bytes (present, live):

- Drop-in
  `/etc/systemd/system/hermes-gateway.service.d/zzz-candidate.conf`
  sha256 `cea239fa7125e562b490bfbad527543a77ad90b364adf5c6049e6eb41ae18103`,
  493 bytes, uid 0, mode 0644. It resets ExecStart and points at the
  uid-1001 worktree.
- Dashboard `zzz-candidate.conf` sha256
  `62d740cb06ed650fc8d40209410ad32522e14cdac5d8ff961581062d6a513bab`,
  535 bytes.
- Base gateway unit sha256
  `cf0df0aa00acb64000d4db59c48515661ddf846a537c77004db703d3e00bb2e0`.
  Base ExecStart is
  `/home/ubuntu/.hermes/hermes-agent/venv/bin/python -m hermes_cli.main gateway run`.
  Base dashboard ExecStart uses host `0.0.0.0`;
  `zz-loopback-binding.conf` resets it to `127.0.0.1` on the old venv;
  `zzz-candidate.conf` wins again.
- Gateway drop-ins also include `10-user-bus.conf`,
  `20-runtime-permissions.conf` (`NoNewPrivileges=true`),
  `30-allow-sudo.conf` (`NoNewPrivileges=false`, which is why effective
  `NoNewPrivileges=no`), CPU/memory control drop-ins,
  `a1-runner-compat.conf`, `zz-performance-allocation.conf`. This design
  does not change those.
- `/opt/hermes-maintenance` is uid 0, mode 0755, contains
  `cutover_manifest.py` (1691 bytes, sha256
  `3a2b9b5d621445e7c8b844e5583dc7c5fa92a9f7411649da75c888c29534946b`)
  and lacks `cutover_receipt.py`.
  `/opt/hermes-maintenance-next` contains `cutover_receipt.py` but its
  manifest is 1717 bytes, sha256
  `a628465e837115ddb3edc048b12bc28cc52620c75f4bddfbca52d78e954b8247`,
  not the former SHA. Neither install is `1c12738`. Do not start either.

## 3. Threat model

This transaction assumes an attacker, mistake, or race with uid-1001
write capability, plus ordinary operator and durability failures. Each
item below must be closed by an invariant or an explicit blocker; none
is assumed away.

1. Same-UID mutation after `chmod`: mode 0700/0755 does not prevent uid
   1001 from rewriting worktree files, generation venv files, or staged
   source between a hash check and a later `systemctl restart`.
2. Hash-then-open (TOCTOU): hashing a path then opening the same path
   later re-resolves symlinks, renames, and hardlinks. A digest of a path
   is not execution provenance without a kernel-immutable binding.
3. Symlink/hardlink substitution: a same-name hardlink or swapped symlink
   inside a uid-1001 tree can satisfy a prefix or name check while
   executing different bytes. The reported controller weakness is that
   `root_installed` provenance is a prefix check, not authority, and a
   same-name hardlink can still be accepted when candidate `lstat` is
   uncertain in a way the sibling gate does not cover as a signature.
   `signed=False` is the honest result.
4. Drop-in swap between check and restart: after the operator reads unit
   bytes, a root-compromised writer or a mistaken second operator could
   replace `zzz-candidate.conf` before `daemon-reload`/`restart`. Only an
   external journal plus pre-restart readback plus post-start identity
   readback narrows this; it does not eliminate a hostile-root case, which
   is out of scope and must be stated.
5. `fsync` failure reported as success: `ProductionHost.write_bytes`
   (`scripts/maintenance/cutover_types.py` lines 127–143) catches
   `OSError` from file `fsync` and directory `fsync` and passes. A failed
   `fsync` is therefore reported as success. Any reuse of that helper for
   unit publication would misreport durability.
6. Updater restarting a unit whose ExecStart the updater does not own:
   `hermes update` restarts service-managed gateways through systemd while
   live ExecStart points at a custom generation venv + worktree the updater
   did not install. See section 7.
7. Unread root-0600 drop-ins:
   `/etc/systemd/system/hermes-gateway.service.d/zz-runtime-3.14.9.conf`
   (uid 0, mode 0600, size 74) and the dashboard counterpart (uid 0, mode
   0600, size 124) returned Permission denied to `systemctl cat` for the
   parent worker. Their contents are UNVERIFIED and must stay a blocker.
   Later drop-ins can still be affected by unread directives. Do not invent
   their contents.
8. Interruption of the operator mid-transaction: power loss, kill, or SSH
   drop between snapshot, publish, reload, restart, and health check. The
   next invocation must recover from journal + physical state, never by
   guessing or by deleting the journal to retry.
9. Candidate-printed SHA as false trust anchor: any hash, version string,
   or receipt printed by the candidate process itself is self-attestation.
   It is not health and not provenance.
10. State.db rollback hazards: restoring an old `state.db` over live data,
    or running an old release on a `state.db` the new gateway has written,
    is unsupported per the stock candidate docs. Quick snapshots are not
    application-code rollback. Either direction can corrupt or strand user
    data. Code rollback must not touch user data.
11. Architectural NO-GO findings at `1c12738` (do not patch around them;
    they are the reason controller activation is refused):
    - `scripts/maintenance/cutover_dropin.py` lines 44 and 58 set
      ExecStart to `{staged.venv_python}` plus
      `{config.candidate_src}/hermes_cli/main.py`. `candidate_src` is
      user-mutable.
    - `scripts/maintenance/cutover_orchestrate.py` lines 184–188 call
      `systemctl restart` of both units after a path check. That is not an
      identity-bound start.
    - `scripts/maintenance/cutover_types.py` `ProductionHost.write_bytes`
      lines 127–143 as above.
    - Controller provenance `root_installed` is a prefix check, not
      authority. `signed=False` is honest.

## 4. Invariants

Each invariant has an ID. All must hold for the later transaction. If any
cannot be established, activation is blocked; the design does not permit
downgrading an invariant to an assumption.

- I1 — Execution inputs are kernel-enforced immutable (read-only mount,
  erofs, or squashfs). `chmod` is not immutability. The snapshot mount
  must deny writes by uid 1001 at the kernel level, including via
  same-UID rename, hardlink, and symlink tricks inside the mounted tree.
  Owner/mode bits alone do not satisfy I1. A read-only bind mount of a
  uid-1001 directory is not immutability if that directory or its backing
  remains writable. Denial must hold through any second mount of the same
  backing.
- I2 — ExecStart interpreter and script/module are both inside that
  snapshot. No uid-1001 worktree path appears in ExecStart. No
  `PYTHONPATH`. No `sitecustomize` outside the snapshot. `python -I` or an
  equivalent reviewed flag is required if the product entrypoint allows it;
  if the stock module entry cannot be proven to ignore user
  `sitecustomize`, that is a blocker, not an assumption.
- I3 — Unit publication fsyncs the file and the directory. `OSError` from
  either `fsync` is durable-state-unknown. Do not restart and do not claim
  rollback success after that. A helper that swallows `fsync` errors does
  not satisfy I3.
- I4 — Every start, including rollback, is followed by readback of boot
  id, `MainPID`, `starttime`, `exe`, `cmdline`, and `cgroup`. Mismatch or
  unreadable identity is failure. `systemctl restart` is an operator
  action, not a binding. Only the readback binds the new process to the
  intended bytes.
- I5 — Rollback restores the exact prior unit bytes, not a reconstructed
  drop-in. The operator preserves byte-identical copies of every affected
  unit file and drop-in before any write, and restores those bytes on
  rollback. Re-creating an equivalent drop-in from memory does not satisfy
  I5.
- I6 — User data is not overwritten by the code transaction. Code rollback
  does not restore `state.db`. A full user-data backup is fail-closed and
  stored separately before any restart. If that backup cannot be completed
  and verified, the transaction stops before publish. Quick snapshots that
  the updater takes on a best-effort basis do not satisfy I6.
- I7 — Owner digest is outside both trees, root-owned, and is not called a
  signature. The root operator records an unsigned digest (for example
  sha256) of snapshot bytes and final unit bytes in a root-owned location
  outside the snapshot and outside uid-1001 trees. The digest is a
  same-operator change-detection aid, not authentication. It is never
  described as signed. No signature verifier is claimed.
- I8 — Unread `zz-runtime` drop-ins are hashed by root before any unit
  write. Until root has read and recorded
  `zz-runtime-3.14.9.conf` (gateway, 0600/74) and its dashboard counterpart
  (0600/124), activation is blocked. Proceeding on guessed contents
  violates I8.
- I9 — Effective `systemctl show` `ExecStart`, `ExecStop`, `ExecStopPost`,
  `WorkingDirectory`, `User`, and environment keys match the journal before
  restart. Do not guess `ExecStop` reset syntax. If a drop-in cannot
  override `ExecStop`/`ExecStopPost` to the snapshot, activation is blocked
  rather than leaving stop hooks on v0.21.7 (`/home/ubuntu/.hermes/hermes-agent/venv`).
- I10 — This design does not change `NoNewPrivileges`, sudo, resource
  limits, or other existing drop-ins. Replacing `zzz-candidate.conf` in
  place is the smallest unit edit. A stacked extra drop-in is forbidden
  because it hides which ExecStart won. `10-user-bus.conf`,
  `20-runtime-permissions.conf`, `30-allow-sudo.conf`, CPU/memory controls,
  `a1-runner-compat.conf`, and `zz-performance-allocation.conf` stay
  untouched.
- I11 — Plugins are a later gate. Do not enable or install plugins in this
  transaction. Plugin surface changes provenance and health reasoning and
  needs its own review.
- I12 — The custom controller is not the launcher. `/opt` copies are not
  started. `1c12738` is not installed as activation authority. Identity
  checks from sibling code at `1c12738` remain advisory evidence only;
  they do not authorize a start and do not replace I4 readback.

## 5. State machine

The machine is an external operator journal, not an in-process
controller. The operator appends one durable journal line per transition
(root-owned, fsynced file + directory per I3) before acting, then verifies
physical state before appending the outcome. The journal is never deleted
to retry.

| State | Physical evidence required to claim it | Only legal next states |
|---|---|---|
| `observed` | Journal opened; boot id, `systemctl show` for both units, live `MainPID`/`starttime`/`exe`/`cmdline`/`cgroup`, unit/drop-in bytes + sha256 recorded (record live identity and unit bytes); unread 0600 drop-ins still block onward movement per I8 — the only onward state on unread is `blocked-unread`, not `snapshotted` | `dropins-read`, `blocked-unread` (if drop-ins unread/unreadable), `stopped-unresolved` (if observation itself shows mismatch/unreadable) |
| `dropins-read` | Root has hashed both 0600 files (gateway 0600/74 and dashboard counterpart 0600/124) recorded in journal per I8; if still unreadable, terminal `blocked-unread` | `target-bound`, `blocked-unread`, `stopped-unresolved` |
| `target-bound` | Owner placeholder target SHA bound by separate review and recorded in journal; not `daec3cd4` and not `1c12738` by assumption | `backup-verified`, `rolling-back` (abort before publish), `stopped-unresolved` |
| `backup-verified` | Full user-data backup completed and verified fail-closed per I6, stored separately; failure stops before publish | `candidate-materialized`, `rolling-back` (abort before publish), `stopped-unresolved` |
| `candidate-materialized` | Bound SHA bytes equal staged bytes in a kernel read-only snapshot whose backing is not also mounted writable; a read-only bind of a still-writable uid-1001 tree fails I1; mount flags show read-only; uid-1001 write attempt denied including via any second mount of the same backing (see acceptance probe); both interpreter and entry module inside snapshot; no worktree path, no `PYTHONPATH`, sitecustomize disposition proven or blocked per I2; snapshot byte digest recorded in root-owned location outside snapshot and outside uid-1001 trees; digest recorded as unsigned (`signed=false`) | `units-published`, `rolling-back` (abort before publish), `durable-state-unknown` (fsync/digest failure) |
| `units-published` | Exact prior unit bytes preserved; replacement `zzz-candidate.conf` bytes (in-place, no stacked drop-in per I10) written with file + directory fsync; post-write readback bytes equal intended bytes; `ExecStop`/`ExecStopPost` disposition resolved per I9 | `reloaded`, `rolling-back`, `durable-state-unknown` (any fsync error or readback mismatch) |
| `reloaded` | `daemon-reload` completed; post-reload `systemctl show` effective `ExecStart`/`ExecStop`/`ExecStopPost`/`WorkingDirectory`/`User`/environment keys equal journaled intent | `restarted`, `rolling-back`, `durable-state-unknown` |
| `restarted` | Restart issued once by operator; new `MainPID`/`starttime` read; `exe`/`cmdline`/`cgroup`/boot id read back per I4 | `health-verified`, `rolling-back`, `durable-state-unknown`, `stopped-unresolved` (identity unreadable) |
| `health-verified` | External bounded authenticated gateway/dashboard check passed from outside the candidate plus I4 provenance match; candidate-printed SHA not used as health | `committed`, `rolling-back` |
| `committed` | Terminal success only after `health-verified`; journal records final identity + unit digest; rollback bytes retained for the agreed retention | (terminal; no further transitions except a new separately authorized transaction) |
| `rolling-back` | Failure or health-unknown declared; exact prior unit bytes restored with file + directory fsync; reload + restart of prior identity attempted | `rolled-back`, `durable-state-unknown`, `stopped-unresolved` |
| `rolled-back` | Prior unit bytes byte-equal to pre-transaction copies; reloaded; restarted; I4 identity readback plus external health check against pre-stop identity both pass | (terminal for this transaction) |
| `durable-state-unknown` | File or directory `fsync` raised `OSError`, or post-write readback mismatched, or crash between rename and directory fsync | `rolling-back` (only after durability re-established by root readback), `stopped-unresolved`; never direct to `committed` or `rolled-back` |
| `stopped-unresolved` | Services left stopped because rollback identity could not be verified or identity is ambiguous; journal records last known physical bytes + identity; no further start attempted by this transaction | (terminal; requires new human-directed recovery, not silent retry) |
| `blocked-unread` | Unread 0600 drop-ins remain unreadable; activation blocked per I8 with no unit write performed; journal records the denial | (terminal; requires new human-directed recovery, not silent retry) |

Interruption rule: the next invocation reads the journal and the physical
unit bytes and process identity (`systemctl show`, `/proc`-independent
identity via systemd properties where possible, boot id, `MainPID`,
`starttime`, `exe`, `cmdline`, `cgroup`). It must not guess, must not
start a second restart while identity is ambiguous, and must not delete
the journal to retry. After rename but before successful directory fsync,
the state is `durable-state-unknown`, not success and not rollback-clean.
A second restart while `MainPID`/`starttime` cannot be bound to the
intended bytes is forbidden.

## 6. Failure and rollback

- Health unknown is failure. Timeout, unauthenticated response, partial
  response, or any check that cannot complete within its bound is treated
  as failed health, not as deferred success.
- Candidate health is external: process provenance per I4 plus a bounded
  authenticated gateway/dashboard check issued from outside the candidate
  (not from inside the candidate tree, not via candidate-provided tooling).
  A SHA printed by the candidate is not health. A log line claiming a
  version is not health.
- Rollback health is the same external check against the pre-stop
  identity: provenance readback must match the pre-transaction journal
  (`MainPID` will differ after restart; `exe`/`cmdline`/`cgroup`/unit bytes
  must match the prior known-good set, and `starttime`/boot id must be
  freshly bound), plus the bounded authenticated check must pass.
- If rollback identity cannot be verified, leave the services stopped and
  report `stopped-unresolved`. Do not attempt another restart to "fix" an
  ambiguous identity.
- Do not `git checkout` the live worktree as rollback. The live worktree
  is uid-1001 mutable and is not the rollback source. Rollback source is
  the byte-identical unit copies preserved by root plus the prior
  snapshot/install they pointed at.
- Code rollback does not restore user data. If user data was modified by
  the new release, restoring an old `state.db` over live data, or running
  the old release on a new `state.db`, is out of scope for this
  transaction and unsupported per the stock docs. Report the user-data
  condition separately; do not conflate code `rolled-back` with data
  recovery.
- Any `OSError` on file or directory `fsync` during publish or rollback
  moves the machine to `durable-state-unknown`. Do not restart and do not
  claim rollback success after that until root has re-established byte
  equality by readback.

## 7. Why the product updater is not this activation

Stock candidate docs (`website/docs/getting-started/updating.md` in
`daec3cd4`, same contract in upstream docs) describe `hermes update` as
the supported method for a managed source checkout. That method, as
documented and as planned on this host, does not satisfy this activation:

- `--plan` mismatch (read-only `hermes update --plan` from
  `~/.local/bin/hermes`, v0.21.7+166.g50e82ad at
  `/home/ubuntu/.hermes/hermes-agent` HEAD `50e82ad783`):
  `Install git (v0.21.7 @ 50e82ad7); it would restart gateway [default]
  pid 583405 — systemd @ 1d9a377f via systemctl restart.`
  That plan updates a different tree than the live ExecStart. Live
  ExecStart runs the generation venv plus the
  `hermes-upstream-integrate-20261025` worktree; the updater's install is
  `/home/ubuntu/.hermes/hermes-agent` at `50e82ad783`. Restarting pid
  583405 through that plan would restart a unit whose ExecStart the updater
  does not own.
- Best-effort snapshot: the updater takes a best-effort pre-update
  snapshot and continues if that snapshot fails. That continues-into-
  failure behavior violates I6 fail-closed backup and I3 durability.
- The updater git-updates the install checkout, can reset that checkout on
  syntax failure, and restarts service-managed gateways through systemd.
  It does not install an arbitrary staged tree, does not create a kernel
  read-only snapshot, and does not rewrite a custom `zzz-candidate.conf`.
- Rolling back an older release onto a `state.db` the new gateway has
  written is unsupported. Quick snapshots are not application-code
  rollback. Manual `hermes serve`/dashboard backends are left running; this
  host's units are custom and the plan still offered `systemctl restart`
  of the live pid.

`hermes update --backup --yes` would become the routine path only when
all of the following are true: live ExecStart is the updater's own
install; `--plan` names that same install (no cross-tree restart); snapshot
failure is fail-closed or separately accepted with a verified independent
backup; no active work is at risk; and the command runs outside the
gateway. That condition is false today. Do not recommend running it now.
`hermes update` also cannot activate the staged `daec3cd4` tree: the
updater updates its own checkout, it does not install an arbitrary staged
tree into a kernel-immutable snapshot and rebind units to it.

## 8. Smallest feasible later transaction (operator steps, not code)

No step below is authorized now. No step below is to be executed by the
design author. Root performs these later, in order, under a new
authorization, with the journal from section 5.

1. Root reads both unread drop-ins:
   `/etc/systemd/system/hermes-gateway.service.d/zz-runtime-3.14.9.conf`
   and the dashboard counterpart. Record bytes + sha256 in the journal.
   If either remains unreadable, stop. Activation stays blocked per I8.
2. Root records `observed`: boot id, `systemctl show` effective
   `ExecStart`/`ExecStop`/`ExecStopPost`/`WorkingDirectory`/`User`/
   environment keys for both units, live `MainPID`/`starttime`/`exe`/
   `cmdline`/`cgroup`, and sha256 of every unit file and drop-in. Preserve
   byte-identical rollback copies of all affected unit bytes.
3. Owner binds the activation target SHA by separate review (placeholder
   input, not `daec3cd4` by assumption, not `1c12738`). Journal records
   the bound SHA and the review pointer. Without this binding, stop.
4. Root materializes the bound SHA into a staging directory, verifies
   byte equality to the bound SHA, then exposes it as a kernel-enforced
   read-only mount (read-only mount with immutable backing, erofs, or
   squashfs). Prove uid-1001 write denial. Record the unsigned digest
   (`signed=false`) in a root-owned location outside the snapshot and
   outside uid-1001 trees per I7. On any `fsync` error, enter
   `durable-state-unknown` and stop before publish.
5. Root verifies I2 inside the snapshot: interpreter and entry module both
   inside; no worktree path; no `PYTHONPATH`; `sitecustomize` disposition
   proven or activation blocked; `python -I` or reviewed equivalent
   confirmed if the entrypoint allows it.
6. Root completes and verifies a full user-data backup, fail-closed and
   stored separately per I6. Quick/best-effort snapshots do not count. If
   backup verification fails, stop before publish.
7. Root resolves I9: confirm how `ExecStop`/`ExecStopPost` will be bound
   to the snapshot without guessing reset syntax. If the drop-in cannot
   express it, activation is blocked rather than leaving stop hooks on
   v0.21.7.
8. Root publishes units by replacing `zzz-candidate.conf` in place (no
   stacked extra drop-in per I10), leaving all other drop-ins untouched
   per I10 and plugins disabled per I11. File + directory fsync per I3;
   post-write readback must equal intent or enter
   `durable-state-unknown`.
9. Root runs `daemon-reload`, then verifies post-reload effective
   `systemctl show` matches journaled intent for both units.
10. Root performs a single restart, then reads back boot id, `MainPID`,
    `starttime`, `exe`, `cmdline`, `cgroup` per I4. Mismatch or unreadable
    identity is failure; do not issue a second restart while ambiguous.
11. Root performs the external bounded authenticated gateway/dashboard
    health check from outside the candidate. Candidate-printed SHAs are not
    health. Health unknown is failure and enters `rolling-back`.
12. On success, root enters `health-verified` then `committed`, retaining
    rollback bytes for the agreed retention. On any failure, root enters
    `rolling-back`: restore exact prior unit bytes (I5), reload, restart,
    and re-verify provenance + external health against pre-stop identity.
    If that cannot be verified, leave services stopped and report
    `stopped-unresolved`. Never `git checkout` the live worktree as
    rollback and never restore `state.db` as code rollback.

## 9. Provisioning boundary

Later root work (requires new authorization; none of it happens under
this design):

- Read and hash the two root-0600 `zz-runtime` drop-ins.
- Create, mount, and own the kernel read-only snapshot and its unsigned
  root-owned digest location.
- Preserve byte-identical rollback copies of unit files and drop-ins.
- Perform full user-data backup and verification to separate storage.
- Replace `zzz-candidate.conf` in place, `daemon-reload`, single restart,
  provenance readback, external health check, and if needed exact-byte
  rollback.

Remaining blockers today:

- Contents of the two unread 0600 drop-ins are UNVERIFIED (I8).
- `ExecStop`/`ExecStopPost` reset syntax to the snapshot is UNVERIFIED;
  guessing is forbidden (I9).
- `python -I` (or equivalent) applicability and `sitecustomize`
  suppression for the stock module entry are UNVERIFIED (I2).
- Activation target SHA is an unbound placeholder; `daec3cd4` needs a
  separate review before it can be an input (section 8, step 3).
- Exact tools-build id beyond the `python-3.14.9+20261021` prefix is
  UNVERIFIED where a read was masked; re-read by root is needed for the
  final provenance line, not for this design.
- Durability helper with swallowed `fsync` errors (`cutover_types.py`
  127–143) is unfit for unit publication (I3).

Explicitly unauthorized now: install, `daemon-reload`, restart, drop-in
write, `chmod`, controller start (`/opt` or staged copies),
`hermes update` (including `--backup --yes`), plugin enable/install,
`state.db` migration or restore, and any merge. A10 is a later read-only
`hermes update --plan` probe, still UNEXECUTED, and is not authorization
to run it now.

## 10. Acceptance matrix

Every probe is UNEXECUTED under this design. No probe is passed, no
health is claimed, no immutability is claimed.

| ID | Invariant | Probe | Expected result | Status |
|---|---|---|---|---|
| A1 | I1 ro snapshot | As uid 1001, attempt write/rename/hardlink inside the mounted snapshot and through any second mount of the same backing; a read-only bind mount of a uid-1001 directory whose backing remains writable fails I1 | Kernel denies in both mounts; bytes unchanged | UNEXECUTED |
| A2 | I2 confinement | Inspect effective ExecStart: both interpreter and entry under snapshot mount; check env for `PYTHONPATH` and `sitecustomize` disposition; confirm `python -I` or reviewed equivalent | No worktree path; no `PYTHONPATH`; no outside `sitecustomize` or documented blocker | UNEXECUTED |
| A3 | I3 durability | Publish path with injected file-`fsync` `OSError`; then directory-`fsync` `OSError` | State `durable-state-unknown`; no restart; no success claim | UNEXECUTED |
| A4 | I4/I5 publish-crash | Kill operator after publish before restart; re-invoke; read journal + unit bytes + identity | Resume without second restart while ambiguous; no journal deletion | UNEXECUTED |
| A5 | I4 restart-crash | Kill operator after restart before health; re-invoke; read back boot id, `MainPID`, `starttime`, `exe`, `cmdline`, `cgroup` | Single binding readback; no duplicate restart while ambiguous | UNEXECUTED |
| A6 | I4 identity | Post-restart readback of boot id, `MainPID`, `starttime`, `exe`, `cmdline`, `cgroup` vs journaled intent | Exact match or declared failure | UNEXECUTED |
| A7 | I5 rollback bytes | After rollback, byte-compare restored units to pre-transaction copies (sha256) | Byte-equal | UNEXECUTED |
| A8 | I6 user data | Compare user-data backup manifest and live `state.db`/data checksums before vs after code transaction | User data unchanged by code path; backup verified separately | UNEXECUTED |
| A9 | I8 unread drop-ins | Root read + sha256 of both 0600 `zz-runtime` files recorded in journal before any unit write | Both digests present or activation blocked | UNEXECUTED |
| A10 | Sec 7 updater | Re-run read-only `hermes update --plan` and compare named install vs effective ExecStart tree | Mismatch still true until unit shape changes; updater not used | UNEXECUTED |
| A11 | I7 digest honesty | Inspect digest record location/ownership and wording | Root-owned, outside snapshot and uid-1001 trees, never called signed; `signed=false` | UNEXECUTED |
| A12 | I9 stop hooks | Pre-restart `systemctl show` `ExecStop`/`ExecStopPost` vs journal; confirm no guessed reset syntax | Match intent or blocked; no residual v0.21.7 hooks by accident | UNEXECUTED |
| A13 | I10 minimal edit | Diff unit directory before/after: only `zzz-candidate.conf` replaced in place; no stacked drop-in; other drop-ins untouched | Minimal diff or blocked | UNEXECUTED |

## 11. Compatibility

- Live lazy imports must not see a checkout swap under the worktree. Do
  not `git checkout`, `git reset`, or otherwise mutate
  `hermes-upstream-integrate-20261025` (or any tree the running gateway
  imports from) underneath the running gateway. Stage a separate snapshot
  from the bound SHA instead.
- Schema: do not roll `state.db` backward or forward inside this
  transaction. Running an older release on a newer `state.db`, or
  restoring an older `state.db` over live data, is unsupported and out of
  scope. Code commit/rollback and user-data backup/restore are separate
  concerns; this transaction does the former's byte handling and only the
  latter's backup, never a data restore.
- Generations and venvs under uid 1001 (`gen-1d9a377fa00c`,
  `gen-daec3cd4c6d3`, `/home/ubuntu/.hermes/hermes-agent/venv`) remain
  mutable by the service user and therefore cannot serve as the execution
  root. The kernel read-only snapshot is the only execution root in the
  later path.

---

Smallest-path recommendation: keep the fleet as-is, stop controller
patches, leave `/opt` installs and the live units untouched, and treat the
single external root transaction in section 8 — read the two 0600
drop-ins, bind an owner-chosen target SHA by separate review, expose it as
a kernel read-only snapshot with I2 confinement, preserve exact unit-byte
rollback and a fail-closed user-data backup, replace `zzz-candidate.conf`
in place with fsynced durability, reload once, restart once with I4
readback and external health, else exact-byte rollback or
`stopped-unresolved` — as the only later activation route. Review of this
file's sha256 is the next gate, and a design GO would authorize only a
later hermetic implementation slice, not root provisioning.
