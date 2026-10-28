# Stock-cutover DESIGN-TO-CODE gap ledger (bounded)

Base: `0c3d327ebe94d1ed283b569dbbe0ff95e84e0a5a` (2026-10-28).
Scope: ONE read-only slice only — packaging + verification-before-import +
RealHost NONDESTRUCTIVE preflight. State+mutation deferred to next slice.
No new generic design. Accepted design bytes immutable (not edited here).

## 1. Canonical design (immutable, verified sha256)

- `STOCK-ACTIVATION-EXTERNAL-OPERATOR.md` sha256
  `70fc9debac3bdf25b2a52d6413a8bc42e03d00fd38a925faf33b98e7a39c18c9`
- `STOCK-ACTIVATION-EXTERNAL-OPERATOR-ADDENDUM.md` sha256
  `ba9791ac89a15b2820f8d9cd8686ef67ef903833bab2eaf62c592da75bbab9fd`
  controls on conflict. Single order §2.4, fence §2.5, fsync §2.6,
  rollback-start §2.7, health §2.8, oracle §2.9, I2 §2.11, I4 §2.12.
  Journal table §2.3 (no `snapshotted`, `known-good-frozen`+`stop-fenced`
  legal, `durable-state-unknown`→`stop-fenced` only after readback+fence).
- `STOCK-ACTIVATION-OS-SYSCALL-GAP.md` sha256
  `246567b90ba0d22bc2d45a122da23813c85a0cbd709aead116aabc04f870e3d7`
  (G1-G4 owner placeholders).
- `STOCK-ACTIVATION-OS-SYSCALL-GAP-ADDENDUM.md` (this task does not edit it)
  supplies G1 closure objects, G2 squashfs-only mount (flag word 7 =
  MS_RDONLY|MS_NOSUID|MS_NODEV, no rw/noexec/remount/bind), G3 sudo env -i
  launcher + 7-step stop/show/sleep/show/reload/show/start + snapshot
  ExecStart, G4 install/archive/rsync/fsync-walker/unsquashfs-verify.
  All rows A1-A13/B1-B7/C1-C4 UNEXECUTED. No mount/start authorized here.

Target pins (accepted addendum §2.1/§4 + gap addendum §4-§6):

- TARGET `daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06`, KNOWN-GOOD
  `1d9a377fa00ce0e663e274e16b63c75e36233b9e`, REFUSE
  `1c12738cfeecc78570b3a4ba3797a49de59cfdfe`.
- zz-runtime gateway sha256 `2a495ff3…cc9eb` 74B, dashboard `aa6d8c52…ffed`
  124B, both uid 0 mode 0600. Live gateway PID 583405 / dashboard 583247,
  boot prefix `a7d3326c`, Restart always, RestartUSec 5s.
- Mounts: known-good `/run/hermes-stock-activation/known-good-snap`,
  candidate `/run/hermes-stock-activation/candidate-snap`, images under
  `/var/lib/hermes-stock-activation/backing/*.squashfs` mode 0400 uid 0,
  parent `/run/hermes-stock-activation` 0755 uid 0. Squashfs-only; loops
  20/21 are parent-observed live facts, not worker-probed.
- Journal: `/var/lib/hermes-stock-activation` 0700 uid 0, parent `/var/lib`
  0755 uid 0 not writable by 1001, journal `0600`, recovery
  `/var/lib/hermes-stock-activation/recovery` 0500 uid 0, entry `cli.py`
  0500. Digest outside snapshot+uid1001, `signed=false` (never signed).

Source hashes at base (this ledger's input, not trust):

- `__init__.py` `44215dfd…3dac43`, `cli.py` `4627bd32…1479eed`,
  `cutover_host.py` `55645933…79db0880e4`,
  `cutover_orchestrate.py` `1421cad3…4bd754d942c4`,
  `cutover_package.py` `e115e2c3…1a272701d3dcb66c0b54`,
  `cutover_recovery.py` `f70a97e7…5d7ba77b1de34f07`,
  `cutover_units.py` `dbcbed0d…21cfc899f`.

## 2. Public entries → invariants / journal / syscall / acceptance

| Entry | Invariants | Journal | Syscall authority (this slice) | Acceptance |
|---|---|---|---|---|
| `cli plan` | none (manifest-ready, UNEXECUTED) | none | no root, no import, deterministic | A/B UNEXECUTED stays |
| `cli preflight` (NEW, read-only) | I2 (python-I + sitecustomize + cwd), I4 (boot/MainPID/starttime/exe/cmdline/cgroup/WD/User), I7 (digest outside, signed=false), I8 (zz-runtime re-hash), I10 (in-place only) | read-only: journal_dir_info + journal_load tail (no append) | `O_RDONLY\|O_NOFOLLOW` reads, `lstat`, `show --` via fixed launcher, `python -I` probe, `findmnt` readback; NO stop/start/reload/write/rename/mount/sudo-mut/.env open | C3-read + A2/A6/A9/A11-read partial; full A/B still UNEXECUTED |
| `cli apply/recover [--execute-live]` | all I1-I12 | full §2.3 machine | REFUSED here: exit 3 without flag; exit 4 if euid≠0 or not installed 0500; exit 1 `refused-live-not-authorized-here` even if root+installed until wiring reviewed | UNEXECUTED (no live mutation in worker) |
| `export_cutover_package(dest)` | I7-honesty (signed=false), denylist, stdlib-only closure, no .git | none (user scratch, HOME-only, no /tmp//var//run//etc//opt) | `O_CREAT\|O_EXCL\|O_NOFOLLOW` + file+dir fsync in scratch only | C1-packaging partial |
| `RealCutoverHost.show_unit` | I4/I9-read | none | fixed G3_PREFIX + `systemctl show` via injected runner in tests, `_run_fixed` live; parse only | A6/A12-read partial |
| `RealCutoverHost.proc_identity/boot_id/file_info/read_bytes/file_uid` | I4/I8-read | none | `/proc` + `O_NOFOLLOW` reads, `_refuse_live_env` (.env) | A6/A9-read partial |
| `RealCutoverHost.python_probe` | I2 | none | `python_exe -I -c` probe, no env, cwd outside tree; fail-closed | A2-read partial |
| `RealCutoverHost.{stop,start,reload,sleep,denial,backup,digest,gateway,dropins,write,rename}` | — | — | HARD REFUSAL (`OSError`/`RuntimeError`) until next review | UNEXECUTED |
| `orchestrate/run/main/activate` | full §2.3-§2.12 | full HAPPY + rolling-back/rolled-back/durable/stopped/blocked | DEFERRED (next slice owns state+mutation) | UNEXECUTED |
| `render/validate_dropin_bytes` | I2/I9/I10 exact bytes | none (pure) | none | A13-text partial |
| `cutover/recover service_unit + validate_supervision` | recovery launcher (oneshot, OnFailure, no restart) | none (text) | none | B2-text partial |
| `JOURNAL_LOCK_PATH + lockfile_create_args` (NEW, constructor only) | concurrency (no double start) | path `/var/lib/hermes-stock-activation/journal.lock` 0600 uid 0, `O_CREAT\|O_EXCL\|O_NOFOLLOW` | DESIGNED, NOT ACTIVATED (no service wiring) | deferred |

## 3. Twelve NO-GO findings (0c3d327) → disposition

1. `cli.py:83-91` live root always stub return 1 — KEPT as refusal for
   mutation in this slice; functional path is NEW `preflight` only.
   Mutation wiring deferred.
2. `cutover_host.py:304-313` show/stop/start/reload + `:423-433`
   denial/python/backup/digest + `:455-463` gateway/dropins all raise,
   `_run_fixed` unused — PARTIAL FIX: `show_unit` + `python_probe` +
   `preflight` now use fixed launcher/runner; stop/start/reload/sleep/
   denial/backup/digest-write/gateway/dropins-write stay refused.
3. Illegal `fence-failed` (`orchestrate:519,734,758`, not in LEGAL_NEXT) —
   DEFERRED. Next slice must return legal `stopped-unresolved:fence-failed`
   or journal tail, never bare `fence-failed`.
4. `durable-state-unknown:586,588` early return blocks §2.3 recovery
   (`durable→stop-fenced` after readback+fence) — DEFERRED. Next slice owns.
5. Prior unit bytes `739,747` read then discarded (`_ = …`), not journal
   evidence — DEFERRED. §2.7 keeps them as evidence only, never start
   source; next slice must persist hashes, not bytes, without starting them.
6. `_identity_ok:377,407` only exe/cmdline substring, no
   boot/starttime/cgroup/WD/User compare — PARTIAL: `preflight` records
   exact boot/MainPID/starttime/exe/cmdline/cgroup/WD/User; full
   `_identity_ok` fix deferred.
7. `_append:206,208` `OSError` uncaught (most callers), should be
   `durable-state-unknown`, no restart — DEFERRED. Preflight performs no
   append.
8. Rollback `known-good-frozen` is only backing marker
   (`backing/known-good-frozen-marker` = `b"known-good"`), no snapshot copy
   fsync §2.6 + no I2 proof — DEFERRED.
9. Image SHAs unpinned (no squashfs/manifest digest pin in orchestrate;
   `signed=false` alone is not provenance) — PARTIAL: preflight checks
   TARGET/KNOWN-GOOD pins + zz-runtime SHAs + squashfs-ro/findmnt readback;
   full image-manifest pin deferred.
10. No concurrent lock (double start / double publish possible) —
    PARTIAL: `JOURNAL_LOCK_PATH` + constructor designed, not activated.
    Next slice must wire `O_EXCL` acquire before fence/publish/start.
11. `_do_reload_checks:496,514` lacks exact User/WD/ExecStart vs journal,
    only EnvironmentFiles + ExecStop venv-substring — DEFERRED.
12. `cli._live_file_ok` checks self only, no sibling hash before import —
    FIXED: `preflight` (and future live entries) verify ALL siblings vs
    MANIFEST before import; adversarial sibling marker must NOT execute
    (test below).

Mislabel: `service_cutover=AUTHORIZED-BY-REVIEW` in `cli._plan_result`,
`cutover_package` payload/result/README/MANIFEST — FALSE (no receipt).
FIXED in this slice to `NOT-AUTHORIZED` until actual review receipt.

## 4. Accepted-design contradictions in implementation (must not follow code)

- C1: orchestrate `fence-failed` contradicts addendum §2.3 legal-next
  table (no such state). Design controls; code deferred.
- C2: orchestrate early `durable-state-unknown` return contradicts §2.3
  `durable→stop-fenced` recovery. Design controls; code deferred.
- C3: orchestrate marker-only `known-good-frozen` contradicts §2.4-step4 +
  §2.6 snapshot-copy fsync + §2.11 I2. Design controls; code deferred.
- C4: orchestrate `_do_reload_checks` subset contradicts §2.9 oracle +
  §2.12 stop-hook/User/WD/ExecStart match. Design controls; code deferred.
- C5: `AUTHORIZED-BY-REVIEW` string contradicts base §1 + addendum §6
  (`ACTIVATION: not authorized`, `HERMETIC_IMPLEMENTATION: not authorized
  by this authoring`). Design controls; fixed here to `NOT-AUTHORIZED`.
- No other base sentence is a contradicting procedure (§3 exhaustive).
  Threat-model, updater non-use, evidence preservation remain.

## 5. This slice (done) vs next slice (unmet)

DONE HERE: NOT-AUTHORIZED relabel; export no-.git + `python -I` entry;
verification-before-import (adversarial marker NOT executed);
RealHost read-only preflight (show via injected runner, real python-I
probe, boot/starttime/cgroup exact, zz-runtime/digest/readback, no .env);
mutations hard-refused; lockfile constructor designed-not-activated;
`test_closure_boundary:359-360` absence→before/after-unchanged (no delete
of pre-existing loops 20/21).
NEXT (state+mutation): C1-C4 fixes, full `_identity_ok`, `_append`
fail-closed, snapshot-copy fsync + I2, image-manifest pin + unsquashfs
recompute, lock wiring, exact reload checks, live journal/digest/root
wiring review. Do NOT claim goal complete.

## 6. Evidence (this slice)

- `PYTHONPATH=. /usr/bin/python3 -m unittest discover -s tests/stock_cutover`
  28 tests green (now +2 new: adversarial-before-import, show-via-runner).
- `tests/stock_activation` 147 tests green after closure-boundary fix
  (was 1 failure at `:360` asserting absence of pre-existing
  `/run/…/known-good-snap/venv`; now before/after unchanged).
- Live-entry proof: `/usr/bin/python3 -I <EXPORT>/cli.py plan` exit 0
  `manifest-ready/signed-false/NOT-AUTHORIZED`; `apply`/`recover` exit 3
  without flag; adversarial sibling overwritten post-export →
  `preflight` refuses, marker file absent.
- No sudo/mount/service mutation in worker; no `/var/lib` or `/run`
  writes; no `.env` opens; no design files edited.

## 7. Next slice (state/durability/evidence/lock, this commit)

- C1: no bare `fence-failed`; `_rollback` + publish/reload paths return
  `stopped-unresolved:fence-failed`, preserving prior legal journal or
  canonical terminal per §2.3/§2.5.
- C2: tail `durable-state-unknown` recovers via `_recover_durable`:
  journal+physical readback + this-invocation 5s fence re-verify, then
  `stop-fenced`; otherwise `stopped-unresolved`. No early-return-forever.
- C3: `known-good-frozen` is I2 (denial+python+digest with exact image
  pins) + snapshot-copy fsync + durable prior-bytes evidence
  (base64+sha256 via `_preserve_prior_bytes` in journal detail) before
  first stop. Marker-only removed.
- C4: `_do_reload_checks(snapshot)` exact User/WD/ExecStart vs rendered
  expected, empty stop-hook reset, no v0.21.7 hooks; `_identity_ok` full
  boot_id/starttime(field22)/cgroup/PID/exe/cmdline/cwd vs pinned
  generation + expected runtime.
- `_append` OSError -> `_DurableUnknown` -> `durable-state-unknown`, no
  false success, no further start. All append sites fail-closed.
- Image pins: `KNOWN_GOOD_IMAGE_SHA=1d3f026c…381a04`,
  `CANDIDATE_IMAGE_SHA=8e50b775…61a176`; `_check_digest` requires exact
  match, not just signed=false/outside.
- Lock: `JOURNAL_LOCK_PATH` O_EXCL+flock authority via
  `lock_acquire/lock_release/lock_info` with epoch/boot/pid/starttime;
  acquired before any journal/fence/publication; stale takeover only
  after retained-journal verification; no pretend release after kill.
- Preflight: O_NOFOLLOW fd hashes, `_is_root_live_dir` uid/mode/path
  enforcement when root live; `manifest_trust=self-consistent-only-
  not-trusted`; runner identity via object (`_is_live`), not `__name__`.
- CLI apply/recover stay `refused-live-not-authorized-here` (exit 1)
  until full review; no handoff break.
- Tests: `tests/stock_cutover` 62 green (was 37), `tests/stock_activation`
  147 green. No design bytes edited. RealHost mutations still refused:
  stop/start/reload/sleep/denial/backup/digest/gateway/dropins (see §2).

## 8. Exact-C4 review slice (this commit, NO live operations)

Base: `bfa2f623bdf20e3475000ebbeea2942f53f10c55`. No sudo/envread/mount/
service ops. No design bytes edited. Parent mounted-runtime proof already
both passed, service PIDs old unchanged (not touched here).

- C4-reload exact (review NO-GO `_do_reload_checks:718-719`): substring
  `want_exec in got_s` allowed `--evil-flag` — REMOVED. Now
  `_parse_show_execstart` normalizes actual `systemctl show` ExecStart
  (plain argv split or structured `{ path=; argv[]=; }` extraction, single
  entry only, no `;`/`{`/`}` fragments) and requires equality exact to
  `_expected_argv_for(unit,snapshot)`; `argv[1]` must be exactly `-I`
  (`--config=-I-evil` fails). `WORKTREE/GEN` contamination kept as explicit
  rejection only. Verified by `reload_extra_flag`, `reload_evil_I`,
  `parse_helpers_exact`, `structured_show_accepted` (all zero-start except
  structured which commits).
- C4-reload REQUIRED presence (review `697-702`): `User`/`WD`/`Environment`
  missing previously passed — now REQUIRED. `User` must be exactly
  `ubuntu`, `WD` exactly expected gateway/dashboard, `EnvironmentFiles`
  must be present and empty, `Environment` must be present with exact-key
  loader contract (no `FORBIDDEN_LOADER_KEYS`, `PYTHONPATH` exact-key, not
  substring). `show_full_argv` + `_show_argv_for(full)` now request `-p
  User -p WorkingDirectory -p Environment` (were missing at `165-174`,
  `212-224`); `preflight_readonly` also records `User`/`Environment`.
  Verified by `missing_user/wd/environment`, `evil_environment` (all
  `stopped-unresolved:missing-loader-evidence`, zero `start:`).
- C4-identity exact (review `_identity_ok:555`): any `-I` substring
  permitted `--config=-I-evil` — REMOVED. Now `_parse_cmd_argv` + exact
  `_expected_argv_for` equality, `argv[1]` exactly `-I`, `exe` in exact
  allowed snapshot interpreters (`.../venv/bin/python3` or `python3.14`);
  extra `--evil-flag` fails. `cwd` missing previously passed (`is not
  None` guard) — now REQUIRED: `None`/empty fails closed, else exact
  `GATEWAY_WD`/`DASHBOARD_WD`. Verified by `identity_cwd_missing`,
  `identity_evil_I`, `identity_extra_flag` (all `stopped-unresolved`, no
  commit; post-start so start log exists, never second commit).
- `_unit_field:361` dead `hasattr(n,n)` loop — REMOVED.
- Probe real fields (review `575-585` vs `399-417`): `python_probe`
  lacked `import_ok`/`pyvenv_version` so `_check_python` real success was
  impossible — FIXED to return real values from isolated runtime: `import_ok`
  via snapshot-source `hermes_cli`/`hermes_cli.main` `find_spec` (no exec,
  no hardcode), `pyvenv_version` via adjacent `venv/pyvenv.cfg` `version =`
  parse (or `None`), `sys_path_has_cwd` via `''` or `getcwd()` in path.
  System `/usr/bin/python3.12` correctly returns `False`/`None` (not
  snapshot); temp snapshot with `source/hermes_cli` + `pyvenv.cfg 3.14.9`
  returns `True`/`3.14.9`. Verified by `python_probe_real_snapshot_exe`
  (fields present) + `python_probe_real_snapshot_valid`.
- Lock stale order (review `755-758` before `884-910`): stale `unlink`
  before retained-journal verify introduced a race and destroyed authority
  too early — REMOVED. `RealCutoverHost.lock_acquire` now preserves stale
  file and raises `OSError('lock-stale-unverified')` fail-closed; fake
  mirrors (no takeover). Orchestrate maps to `stopped-unresolved`, zero
  start, file byte-preserved. Exact stale->new atomic transition is
  UNDERSPECIFIED in accepted bytes (no same-UID handoff defined) — this
  slice does NOT invent one. DESIGN GAP recorded here; stale recovery stays
  fail-closed until design defines the handoff. Verified by
  `lock_stale_preserved_no_takeover` (replaces old `reauthorizes` which
  asserted takeover). Live-holder `lock-held` still blocked with no journal
  mutation.
- No regression: C1 (no bare `fence-failed`), C2 (tail-durable recovery),
  C3 (I2 + prior-bytes evidence + image pins `1d3f026c…`/`8e50b775…`)
  unchanged and green. 9 mutating RealHost stubs still hard-refused
  (stop/start/reload/sleep/denial/backup/digest/gateway/dropins);
  `cli apply/recover` still `refused-live-not-authorized-here` (exit 1);
  next wiring after review.
- Tests: `tests/stock_cutover` 75 green (62 + 13 new: 11 orchestrate +
  2 host/probe+show), `tests/stock_activation` 147 green. C4 NOT claimed
  `all closed`: reload+identity+probe closed and verified above; lock stale
  handoff OPEN as design gap by intent.

## 9. REALHOST wiring slice (this commit, no live execution by worker)

Base: `bd50700d7eb1a882939fe7641c89c47f64dc49fe`. No sudo/mount/service
ops by worker. No design bytes edited. No scope expansion.

- stop/start/reload/sleep implemented via existing `G3_PREFIX` + fixed
  helpers (`stop_argv/start_argv/daemon_reload_argv/sleep_argv`).
  Strict allowlist (`_is_allowed_fixed_argv`, exact equality, named units
  only, no arbitrary commands, no `restart`, no `PYTHONPATH`). `sleep`
  is `OSError` on failure (not `RuntimeError`), `seconds==5` only.
  Worker never runs live; tests use injected runner and assert exact
  argv shape + zero extra.
- denial probe actual strict: vendored exact `_DENIAL_PROBE_CODE` closure
  from reviewed proof (os,sys,errno only, `-I`, no user-tree imports, no
  `.env`). One errno per owned readonly mount (`write/rename/link` via
  `sudo -n -u #1001 python3.12 -I`), each must be `EROFS (30)`.
  Returns 7-key dict for `_check_denial`; mismatch is `False` (no
  commit), spawn/parse failure is `OSError` (fail-closed).
- `backup_ok` measured (not caller `True`): root-owned mount/kernel-ro
  (`mount_show` must be squashfs+ro, no rw/bind) + exact known-good
  image digest (`file_info` uid 0, mode 0400, sha256==`1d3f026c…381a04`).
  Mismatch is `False`, unreadable is `OSError`.
- `digest_record` measured: root-owned image+digest files, `O_NOFOLLOW`
  reads via `file_info`, `signed=False`, outside snapshot/uid1001 by
  path prefix, actual measured `known_good_image_sha==1d3f026c…` and
  `candidate_image_sha==8e50b775…61a176` from real root backing.
  Missing/unreadable is `OSError` (fail-closed, no stub `True`).
- `dropin_names` from `systemctl show DropInPaths` (full show via
  runner), enforce exact scope (`/etc/systemd/system/<service>.d/`,
  `.conf` only, no `..`, no outside prefix). Missing/scope violation is
  `OSError`; fixtures carry complete legit 7-basename contract, no
  dropped checks.
- `gateway_talk` REAL existing gateway identity contract (AF_UNIX
  `identify` v1, one JSON line in/out, `SO_PEERCRED` pid/uid boundary).
  Readonly runtime discovery (`$HERMES_HOME/gateway.sock` else
  `gateway.sock.path` pointer, `O_NOFOLLOW`, bounded, no `.env`).
  No invented port/protocol (9119 is dashboard/web, not gateway; actual
  gateway endpoint verified separately). Request bytes exact
  `{"verb":"identify","id":1,"protocol":1}` + newline; deadline 2.0s.
  Unsupported/missing/malformed is `OSError('gateway-unsupported: …')`
  precise gap, never faked pid/uid. Worker tests use temp AF_UNIX
  socket + fake-protocol negative (real peercred, `ok False` fails
  `gateway_ok`, no commit).
- Preflight reports `cwd` (actual `/proc/<pid>/cwd` readlink) +
  `environ_keys` (names only, no values).
- Stale lock still preserved fail-closed, no automatic takeover
  (authority not designed). Receipts separate `lock-held` (live holder)
  vs `lock-stale-unverified` (stale preserved). Atomic external
  recovery lock design is later narrow-exact, not broad generic.
- `cli apply/recover` remain disabled (`exit 3` without flag, `exit 4`
  if not root/installed, `exit 1 refused-live-not-authorized-here`
  even if root+installed) until review package + external supervisor
  ready. All mutating methods implemented but worker executes none
  live (injected runner + temp socket/files only).
- Tests: `tests/stock_cutover` 87 green (75 + 12 new: 10 host + 2
  realhost-orchestrate shape), `tests/stock_activation` 147 green.
  New: stop/start/reload/sleep fixed argv + `OSError` + zero extra;
  denial strict EROFS + vendored closure hygiene; backup/digest
  fail-closed + measurement (not caller `True`); dropin scope;
  gateway missing-gap + real-socket fake-protocol negative (real
  peercred, no fake 1001); preflight cwd; realhost orchestrate happy
  shape via functional `RealHost` + fake fixed runner (not separate
  `FakeHost` only); lock stale reason separate. No broad glob.
- Remaining exact gate (parent owns production activation after GO):
  independent review of this wiring + review package digests +
  external supervisor (`cutover/recover` oneshot + timer) readiness +
  actual gateway endpoint support verification + narrow-exact atomic
  recovery lock design. No stub `True`, no fake protocol.
