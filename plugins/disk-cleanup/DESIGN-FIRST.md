# DESIGN-FIRST rev2: report-only sweep, zero writes (no runtime change)

> **Status: DESIGN ONLY — no runtime implementation in this commit.**
> Rev 2 revises `8761fcfb` after independent review returned **NO-GO**.
> Per order: **design only, on the design branch, commit docs only, no
> runtime code or host changes.**
>
> - **PR1 BLOCKED — DO NOT MERGE:** `apikongzad/hermes-agent#1`
>   (`hermes/hermes-repair-all` → `main`). It stays OPEN and unmerged until
>   a future implementation lands and is re-reviewed. This commit does **not**
>   supersede, close, or fix PR1.
> - **Rereviewed commits:** `46ad80b1` (FAILED, multiple HIGH TOCTOU after
>   2 passes) and `8761fcfb` (**NO-GO**, this revision's basis). Reasons for
>   the `8761fcfb` NO-GO are listed in §1 and closed by §§2–8 below; none
>   are closed by prose alone — each needs a future implementation diff +
>   adversarial tests + fresh review.
> - **What this commit does:** revises this markdown file only. No `.py`/`.ts`
>   edits, no test edits, no config/lockfile edits, no `utils.atomic_replace`
>   or `atomic_json_write` edits, no commands run against live state, no
>   secrets or log dumps included.
> - **No anticipatory GO:** nothing in this file pre-authorizes deletion,
>   quarantine, rename, log/state writes, or a future broker. Any mutation
>   authority needs a distinct design + implementation + provisioning review.

---

## 0. Scope declaration

### In scope for this design

- **Design A (normative, initial slice):** a **report-only sweep with zero
  writes** for `plugins/disk-cleanup/disk_cleanup.py`. Enumerate + classify
  + return an in-memory report. Delete nothing, write nothing, create
  nothing. Ingress-anchor definition (openat2 vs held walking) is part of
  this scope because even reads need a safe anchor.
- **Design B (separate):** plugin/skill readiness gate — fail-closed
  throughout, with the actual fail-open sites named (§9).
- **Design C (separate):** `hermes doctor --live` browser-backend health —
  actual per-backend oracle, no implicit install, errors fail-closed (§10).

### Explicitly out of scope (independent review only, not this deliverable)

- Any deletion, quarantine, rename, temp-file, mkdir, log-append,
  registry-write, or state-write privilege in the initial slice (see §4:
  **none granted**).
- Future privileged broker (distinct UID, root-0700 store, trusted unnamed
  socketpair, distinct peer — see §6). Separate review/provisioning, not
  this deliverable.
- `utils.atomic_replace` / `atomic_json_write` global changes: **forbidden**
  in the initial slice (see §4).
- Dependency and desktop items (must not ride along, need their own review):
  `katex` / `braces` / `postcss-selector-parser` / `tinypool` / `undici` /
  `vitest` / `js-yaml` / `brace-expansion` / `yaml` / `source-map-js` pins,
  Electron `40.x → 44.x`, `simple-git 3.x → 4.x` + `GIT_`-prefix guard +
  `GITHUB_TOKEN`, clipboard-image `nativeImage.toPNG` validation,
  anything in `apps/desktop/*` not named above.

A future implementation PR for Design A MUST NOT bundle Design B/C fixes or
any out-of-scope item without separate sign-off.

---

## 1. Verdicts being designed around

After two incremental hardening passes (`7a04146`, `76594d9`), rereview of
`46ad80b1` still reported multiple HIGH TOCTOU races: every fix reintroduced
the same primitive — **check-then-use on a pathname whose parent or leaf an
adversary can swap between check and use.**

Rev 1 (`8761fcfb`) correctly stopped incremental patching but itself drew
**NO-GO** for the following load-bearing reasons. Rev 2 closes each by
narrowing the initial slice to zero writes and by pinning the anchor,
broker, B, and C definitions below:

- **R1 — same-UID dirfd overclaim.** Rev 1 described a "pinned dirfd" +
  `fstat` + `*at` sequence as if it conferred exclusive mutation authority.
  Under the same-UID model it does not: the adversary can rename/swap/
  symlink any component at any time, and `dirfd` + dirent re-check is **not
  an atomic check**. No `unlinkat`/`renameat`/`mkdirat` authority can be
  derived from it in the initial slice. Closed by §§2–5 (zero mutation
  authority).
- **R2 — residual mutation privileges.** Rev 1 kept `mkdirat`/`O_TMPFILE`/
  `O_CREAT|O_EXCL` temps, `cleanup.log` bound append, `.bak` rotation as "a
  second COMMIT", quarantine `renameat`, and a "report-only **until**"
  framing that read as an anticipatory GO. Closed by §4 (explicit forbidden
  list, `--apply` absent-or-refuse, no anticipatory GO).
- **R3 — ingress anchor under-specified.** Rev 1 said
  `O_DIRECTORY|O_NOFOLLOW` per root without requiring `openat2`
  `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS` or held component-by-component
  walking, without reject-uncertain, and without never-path-reopen. Closed
  by §3.
- **R4 — uncertain/post-commit handling implied writes.** Rev 1 defined
  PREPARE/COMMIT/FSYNC/INDETERMINATE with `.bak`/log commits and a shared
  `utils` change surface. Closed by §§3–4 (all-uncertain → close/rollback,
  durable-state-unknown, never pathname retry; no `.bak`/log commit; no
  `utils` changes).
- **R5 — future broker read as pre-approved.** Rev 1 did not isolate the
  broker clearly enough. Closed by §6 (distinct UID, root-0700, unnamed
  socketpair, distinct peer; separate provisioning/review; not this
  deliverable).
- **R6 — Design B named the refusal exception but not the actual fail-open
  sites.** `tools/skills_tool_plugin.py` `except Exception → AVAILABLE` and
  the `cron/scheduler_preflight.py` + `cron/scheduler.py` skip-on-error
  chain were not pinned to entrypoints. Closed by §9.
- **R7 — Design C allowed version/import/PATH/other-backend and unknown→skip
  readings, left `--live` install scope and static/live/fix distinction
  loose, and had no per-backend acceptance matrix.** Closed by §10.

### Finding catalog (read-path restatement — implementation MUST prove each)

- **F1 — parent/state-dir symlink, preexisting read outside.** If
  `$HERMES_HOME/disk-cleanup` (or any ancestor at ingress time) is or
  becomes a symlink/junction, reads intended for protected state land
  outside the protected roots.
- **F2 — quick-delete temp victim unchecked.** The current sweep deletes
  temp candidates without re-binding each victim to a pinned directory at
  unlink time. **Initial slice: no victim is deleted at all (§4).**
- **F3 — load tracked/`.bak` lstat/read race.** `is_symlink()` (lstat)
  followed by `open()`/`read()` leaves a window where a regular file is
  replaced by a symlink. **Initial slice: single-anchor bound read or
  refuse; no `.bak` commit.**
- **F4 — `mkdir → mkstemp` parent swap; temp symlink installed.**
  **Initial slice: no `mkdir`, no `mkstemp`, no temp, no install (§4).**
- **F5 — `cleanup.log` follows link.** Audit log opened by pathname with
  errors suppressed redirects the trail. **Initial slice: no log file
  writes at all (§4).**
- **F6 — pathname `dir fsync` can sync the wrong dir; failure-after-commit
  needs indeterminate.** **Initial slice: no commit, no dir fsync by
  pathname, no durability claim beyond what bound fds prove; any
  verification/fsync question that cannot be answered from held fds is
  reported `durable-state-unknown`, never retried by pathname (§§3–4).**

---

## 2. Threat model

- **Adversary: same-UID actor.** A malicious or compromised skill, plugin,
  hook, prior agent turn, or user shell running as the same UID — able to
  create/swap symlinks, rename directories, and race every syscall gap
  inside `$HERMES_HOME` and `/tmp`. No root, no other-UID, no kernel
  attacker. Same-UID races are in scope; cross-UID DAC is not the defense.
- **No exclusive mutation authority in a same-UID writable directory.**
  This is load-bearing: holding a `dirfd` does **not** lock the directory,
  pinning `(st_dev, st_ino)` does **not** prevent mutation, re-`fstat()`
  before use does **not** close the race, and `dirfd` +
  `fstatat(AT_SYMLINK_NOFOLLOW)` + `unlinkat` on the "same" dirfd is **not
  an atomic check-then-delete**. The kernel provides no atomic
  check-dirent-and-unlink via `dirfd` alone. Any design that claims deletion
  authority from a held `dirfd` under same-UID fails this model. Hence §4:
  the initial slice claims **zero** mutation authority.
- **Protected roots:** exactly `$HERMES_HOME` and `/tmp/hermes-*` (with the
  macOS `/private/tmp` alias resolved once at ingress). Everything else —
  including `/mnt/*`, `~`, `/tmp` siblings, and the repo tree — is outside.
- **Trust boundaries (read-only slice):**
  1. **Ingress boundary** — pathname → bound descriptor. The ONLY place a
     pathname is resolved. Everything after it operates on descriptors or
     refuses. See §3.
  2. **No commit boundary in the initial slice.** There is no temp → final
     rename, no linearization point, no durability orbit. Any text in a
     future diff introducing one fails the §11 checklist.
  3. **No deletion boundary in the initial slice.** Pathname strings NEVER
     confer delete authority, and neither does a held `dirfd` under
     same-UID. There is nothing to grant yet.
  4. **No audit-file boundary in the initial slice.** There is no
     `cleanup.log` write to defend; diagnostics are in-memory return values
     (§4). A future audit store needs its own design.
- **Non-goals:** cross-UID hardening, encrypted-at-rest state, quota/DoS
  policy, Windows-junction parity beyond "refuse unless proven safe",
  general plugin sandboxing.

---

## 3. Normative primitives (apply to every path below, including reads)

1. **Ingress anchor via `openat2` or held component walking — nothing
   weaker.**
   - Preferred: `openat2(anchor_fd, path,
     RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` (plus `RESOLVE_NO_XDEV` where
     the platform supports it) to bind each protected root and the
     `disk-cleanup/` child in one kernel-checked step.
   - Fallback where `openat2` is unavailable: held component-by-component
     walking — open the parent with
     `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, `fstat` it (`S_ISDIR`,
     expected `st_dev`/`st_ino`/ownership where pinned), then
     `openat(parent_fd, next_component, O_DIRECTORY | O_NOFOLLOW |
     O_CLOEXEC)` **while holding the parent fd open**, verifying each level
     before descending. Never release the parent before the child is bound.
   - **Reject on uncertain or symlink ancestors.** `ELOOP`, mount/XDEV
     escape, `st_dev`/`st_ino` mismatch, non-directory, wrong
     ownership/mode surprise, or any error where safe binding cannot be
     proven → fail-closed refuse. A symlink at any ingress component
     (preexisting or swapped in) → refuse before any read.
   - **Never path-reopen.** After ingress, never re-resolve the same
     directory by name: no second `open(path)`, no `Path.resolve()` /
     `exists()` / `is_symlink()`-then-`open()` split on state paths, no
     pathname dir-fsync, no pathname retry on uncertain. Reads use
     `openat(anchor_fd, name, O_RDONLY | O_NOFOLLOW)` + immediate
     `fstat(fd)` verify (regular file, `nlink == 1` expected); `ELOOP` →
     refuse.
   - On Windows (`O_DIRECTORY`/`O_NOFOLLOW`/`openat2` absent), refuse the
     anchored path fail-closed unless a followup review explicitly approves
     a Windows-specific binding primitive. Silent downgrade to pathname
     behavior fails this design.
2. **Held descriptors only; no `*at`-implies-mutation reading.** `*at`
   helpers in the initial slice are read-only (`openat` `O_RDONLY`,
   `fstatat` `AT_SYMLINK_NOFOLLOW` for classification). Bare
   `open(path)` / `os.remove` / `Path.unlink` / `Path.rename` /
   `shutil.*` / `mkstemp` on attacker-reachable names are prohibited.
3. **Schema-valid is classification input, never deletion authority.**
   A `tracked.json` entry that validates against the schema is still just a
   **candidate description**. Validity NEVER authorizes deletion, quarantine,
   rename, or tracking-registry mutation in the initial slice (there is no
   authority to authorize — §4).
4. **All-uncertain → close, rollback, report; never pathname-retry.**
   On any uncertain outcome (anchor mismatch, `ELOOP`, I/O error, race
   signal, schema parse failure, clock/age ambiguity): close all held fds,
   drop in-memory derived state (rollback, no partial reuse), and report
   the verification/durability question as **`durable-state-unknown`**
   with a distinct typed reason. MUST NOT retry the same name via pathname,
   MUST NOT fall back to `Path.exists()`/`resolve()` classification,
   MUST NOT claim success or clean failure when durability/identity is
   unknown. There is no `.bak` or log commit to fall back to in the initial
   slice.
5. **Fail-closed diagnostics, in memory.** No `contextlib.suppress(OSError)`
   on the ingress/read path that hides a refusal. Errors surface in the
   returned report (typed reason + what was refused + what was not touched).

---

## 4. Initial slice: report-only sweep, zero writes

The initial implementation slice exposes **one** behavior: given an anchored
read of `tracked.json` (or a refuse verdict), return what *would* be
deleted under current policy without touching anything.

- **Allowed syscalls (exhaustive):** `openat2` / `openat(O_RDONLY|
  O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY where dirs)` on the ingress chain,
  `fstat`/`fstatat(AT_SYMLINK_NOFOLLOW)`, `read`/`close`, `getattr`-class
  stat of already-open fds, directory listing via an already-open dirfd
  (`getdents`/`fdopendir` equivalent) for enumeration. Nothing else on
  state paths.
- **Forbidden in the initial slice (non-exhaustive but binding):**
  `mkdir` / `mkdirat` (even `parents=True`, even "ensure state dir"),
  `mkstemp` / `O_TMPFILE` / `O_CREAT` / `O_EXCL` temps, `write` to any state
  path, `renameat` / `linkat` / `os.replace` / `Path.replace`, `unlinkat` /
  `unlink` / `rmdir` / `rmtree`, `fsync`/`fdatasync` on state (reads need
  none), `cleanup.log` append/create, `tracked.json` / `.bak` create/write/
  rotate, quarantine directory create/rename, tracking-registry mutation,
  `chmod`/`fchmod`/`chown` on state, `symlink`/`readlink`-driven repair.
  `grep` for any of these on state paths in the implementation diff (outside
  test fixtures) fails the §11 checklist.
- **No `.bak` / log commit.** There is no second COMMIT, no `.bak` rotation
  (never `shutil.copy`/temp+replace onto `.bak`), no `cleanup.log` commit
  record. Corrupt state reads as `corrupt-untrusted` in the report; it is
  never quarantined, renamed, overwritten, or "restored from backup" in
  this slice.
- **No shared-helper changes.** `utils.atomic_replace`,
  `utils.atomic_json_write`, `atomic_roundtrip_yaml_save`, and any global
  atomic-write helper stay untouched. A local symlink-safe writer is not
  introduced in this slice either — there is nothing to write.
- **`--apply` absent or always-refuse.** The initial slice exposes **no**
  `--apply` (or `--force`/`--delete`/`--commit`) flag. If CLI plumbing
  requires the flag name to exist, it MUST hard-refuse: non-zero exit,
  `"report-only slice: mutation not implemented"`, zero side effects. A
  flag that silently no-ops to success, or that mutates, fails this design.
- **Report shape (in-memory only):** `{ candidates, refused, corrupt,
  durable_state_unknown, touched: [] }` where `touched` is always empty and
  asserted empty in tests. `candidates` carry policy reasons (age/category/
  size) and the anchored identity they were classified from; `refused`
  carries the §3 reason. Callers may print/log via their own channel; the
  sweep itself persists nothing.
- **No anticipatory GO.** Phrases like "deletion returns after review" grant
  nothing. The next slice (if any) needs its own design + diff + adversarial
  tests + independent sign-off.

---

## 5. Deletion / quarantine / rename / log / state authority: NONE

Until a *separate* reviewed design explicitly grants it (not this file),
there is **no** deletion authority, no quarantine authority, no rename
authority, no log-append authority, and no state-write authority to reason
about. This file therefore defines **no** per-victim `unlinkat` protocol,
no "four ordered steps with no gaps", no protected-dir data tables as
deletion policy — those belong to a future design IF one is commissioned.
Reviewers of the initial slice check for absence (§11), not for correctness
of a protocol that must not exist yet.

Protected top-level names (`logs/`, `memories/`, `sessions/`, `cron/`,
`cache/`, `skills/`, `plugins/`, `disk-cleanup/`, `workspace/`,
`projects/`, `plans/`, `home/`, `kanban/`, …) are classification context
for the report (a candidate under one is reported `refused-protected`),
not an enforced deletion policy — enforcement implies an unlink path that
does not exist in this slice.

---

## 6. Future broker (NOT this deliverable, NO GO implied)

A same-UID in-process sweeper can never hold exclusive mutation authority
(§2). IF mutation is ever wanted, one candidate shape is a **privileged
broker**, sketched here only to keep it out of the initial slice:

- Runs as a **distinct UID** from the agent/skill surface (not same-UID);
  state directory owned by that UID (or root) with mode **0700**;
  agent side holds no write fd to the store.
- Speaks to the agent over a **trusted unnamed `socketpair`** (or a
  distinct authenticated peer channel with credential passing, e.g.
  `SCM_CREDENTIALS`/`SCM_RIGHTS` fd-passing of result fds — never bare
  pathnames as authority).
- Provisions its UID, home, unit/socket activation, and upgrade/rollback
  via OS-level packaging (systemd unit, macOS launchd, or equivalent) —
  **separate provisioning review**, plus its own threat model (broker
  compromise, fd-passing confused deputy, DoS/quota, audit durability).

This paragraph authorizes nothing. Broker design, provisioning, identity,
and audit durability each need their own review. Citing this section as a
GO for any `unlink`/`rename`/`mkdir`/log write in the initial slice fails
review.

---

## 7. Per-finding closure sketch (READ path only — no mutation proofs)

- **F1:** ingress pins roots + `disk-cleanup/` child via §3 (`openat2`
  `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS` or held walking). Preexisting
  symlink, uncertain ancestor, or XDEV escape → fail-closed refuse before
  any read. No `mkdir(parents=True)` on an unbound chain (no `mkdir` at
  all in this slice).
- **F2:** closed by absence — sweeps report only; no victim is deleted from
  a pathname OR from a dirfd. Any `unlinkat` reachable from sweep paths
  fails §11.
- **F3:** no `is_symlink()`-then-`open()` split. Single
  `openat(…, O_NOFOLLOW)` + `fstat(fd)`; `ELOOP` → refuse + close +
  `durable-state-unknown` where identity was the question. `.bak` is not
  loaded as a fallback authority; at most it is reported as a second
  candidate input, never committed.
- **F4:** no `mkdir`-then-`mkstemp(name)` pair — no `mkdir`, no `mkstemp`,
  no temp, no rename install. No attacker-chosen pathname is ever promoted
  into a state slot.
- **F5:** `cleanup.log` is not opened, created, appended, or suppressed in
  this slice. No `_log()` write path exists on sweep/read code. Diagnostics
  are return values.
- **F6:** no pathname `dir_fsync`; no commit whose post-fsync failure needs
  grading. Any durability/verification question unanswerable from held fds
  → `durable-state-unknown` terminal report, never success, never blind
  pathname retry.

---

## 8. Migration, rollback, acceptance (read-only slice)

- **Migration (existing homes):** current `tracked.json` / `.bak` /
  `cleanup.log` are UNTRUSTED input. The new code reads each via the §3
  bound-read primitive, schema-validates as classification input, and
  reports `corrupt-untrusted` / `refused-symlink` / `refused-escape` as
  appropriate. It **never quarantines** (no `quarantine/<ts>/` rename), never
  rewrites, never deletes legacy files. No silent auto-repair.
- **Rollback:** there is no format change and no write, so rollback = stop
  running the new reader. Rollback MUST NOT restore or perform deletions
  (there are none). Downgrade readers see the files exactly as before
  because nothing was written.
- **Acceptance tests (adversarial, real races — mandatory):**
  - Same-UID swapper thread/process hammering each read gap (parent swap,
    leaf swap, log-path swap attempts, anchor swap) during every read/sweep;
    tests MUST use real concurrency (no mocks, no single-threaded lstat
    stubs) and assert refuse/`durable-state-unknown`/report-only.
  - Each of F1–F6 gets a dedicated race test asserting fail-closed /
    `durable-state-unknown` / report-only behavior. No commit-path
    durability test exists in this slice (nothing commits); instead assert
    the negative: **zero mutating syscalls** (seccomp-style fd-trace or
    `strace`-equivalent assertion that no `mkdir`/`open(O_CREAT)`/
    `rename`/`unlink`/`fsync`-on-state occurred) plus `touched == []`.
  - Protected-root escape tests: symlinked state dir, `/mnt/*` candidates,
    `/tmp` non-`hermes-*` candidates, project-tree candidates — all MUST be
    refused and reported, none written.
  - `--apply` tests: flag absent, or present-but-always-refuses with
    non-zero exit and zero side effects (assert mtime/inode census of the
    state dir unchanged).
  - Flakiness guard: race tests run with bounded iterations and fail on ANY
    escape or ANY write, not on statistical sampling.

---

## 9. Design B (separate): plugin/skill readiness — no fail-open exception

Actual fail-open sites this design closes (all must become fail-closed; any
remaining carve-out fails review):

- `tools/skills_tool_plugin.py::_serve_plugin_skill` — `except Exception`
  around `_shared_readiness` currently synthesizes `AVAILABLE`
  (`setup_needed: False`). That is fail-open: a readiness-probe crash
  activates the skill.
- `cron/scheduler_preflight.py::_preflight_check_skills` — `except
  Exception: continue` and `not success → continue` skip failed skill views
  (fail-open to `_build_job_prompt`'s skip handling).
- `cron/scheduler_preflight.py::_preflight_job_config` — per-check
  `except Exception: continue` fails open.
- `cron/scheduler_preflight.py::_preflight_check_provider_key` —
  `except Exception: return None` and non-`AuthError` → `None` fail open.
- `cron/scheduler_preflight.py::_preflight_check_delivery` — gateway-config
  load failure → `return None` (fail-open `skip`).
- `cron/scheduler.py::_preflight_or_block` — outer `except Exception →
  _pf_reason = None` fails open ("validator must never take down a runnable
  job" is the wrong default when the validator itself is broken).

Normative rules:

- Readiness (`required_commands` actual `PATH` discovery via `shutil.which`
  on validated basenames, per-view recheck; required env/credential checks;
  `TERMINAL_ENV` backend note) is fail-closed throughout. Only `ready` can
  activate. Every other verdict — `blocked-missing-cmd`,
  `blocked-refused`, `blocked-error`, `blocked-timeout`,
  `blocked-unconfigured`, `blocked-unknown` — blocks load, blocks plugin
  enable, blocks cron dispatch, and blocks dependent-service enablement,
  uniformly across CLI, gateway, TUI/Desktop, and cron surfaces.
- **The `TerminalPolicyRefusal` fail-open exception is REJECTED.**
  `tools/terminal_scope.py::TerminalPolicyRefusal` /
  `TerminalPolicyUnavailable` is a denial signal, not a skip signal: it MUST
  resolve to blocked/disabled with the same surface as any other readiness
  failure, never to "allow and continue". Any `except
  TerminalPolicyRefusal: allow` (or `except Exception: AVAILABLE` /
  `continue` / `return None` that swallows it) fails this design.
- Refusal, error, timeout, unconfigured, and unknown are all fail-closed.
  "Unconfigured" never activates; "unknown" (unrecognized backend, missing
  probe, unparseable frontmatter gate) never activates. A skill whose
  readiness cannot be proven ready is not ready.
- Shared readiness gate for bundled + catalog + plugin skills (one code
  path, one verdict vocabulary above), with per-view recheck so
  `PATH`/policy changes between views cannot latch a stale ready.
- **Actual-entrypoint tests (mandatory, no mocked interiors):** tests drive
  the real `skill_view` / `_serve_plugin_skill` /
  `_preflight_check_skills` / `_preflight_job_config` / `_preflight_or_block`
  entrypoints with real faults — `PATH` without the command, invalid
  `required_commands` declaration, refusal scope installed, probe raising,
  probe timing out, unconfigured credential store, unknown backend string —
  and assert blocked verdicts plus no activation/scheduling/service-enable
  side effect. Tests that patch the readiness helper to return ready, or
  that assert only the helper in isolation, do not satisfy this design.

---

## 10. Design C (separate): `doctor --live` browser health — real, per-backend, no implicit install

Failure mode being closed: version-string-only / bare-import / PATH-presence
checks producing a pass, unknown backends skipping instead of failing, and
`--live` mutating the host.

- **Version / import / PATH / other-backend success MUST NOT produce PASS.**
  None of these proves the configured backend works: a version string, a
  bare `import playwright` / `import browser_harness`, a `shutil.which` /
  `_find_cli() is not None` / `_find_agent_browser(validate=False)` PATH
  hit, or a successful probe of a *different* backend than the configured
  one. PASS requires the §10 oracle for the *configured* backend only.
- **Probe the CONFIGURED backend; unknown → broken, not skip.**
  Read `browser.backend` (`off` / `browser-use` / agent-browser / unset
  default / unknown string) via the real key (`get_browser_backend`).
  `off` → `skip` (never enables dependent services). Unset default → probe
  in the documented default order, but PASS requires the probed backend's
  own oracle to pass. Explicit `browser-use` MUST NOT fall back to
  agent-browser (and vice versa). **Unknown configured value → `broken`
  (fail-closed), never `skip`.** Configured-but-broken (binary missing,
  `--version` non-zero, probe timeout, Chromium executable missing, version
  mismatch, unexpected output) → `broken`, never silently unconfigured.
- **Actual-backend oracle: bounded launch operation, reaped child.**
  The oracle executes the exact binary/entrypoint the tool spawns:
  bounded `--version` subprocess (`1s ≤ timeout ≤ 15s`, output cap ~80–4k
  chars, `capture_output`, `check=False`, explicit `wait`/reap, no daemon
  start, no `pm.ensure`) or a bounded real launch (`about:blank` open +
  close with the same budgets and guaranteed `close()`/reap in `finally`).
  A bare import or a PATH hit without this exec proves nothing. The launch
  owns the full lifecycle and always cleans up (no zombies, no lingering
  browser/daemon).
- **Entire `--live` path: no install, no download, no mutation — including
  static-doctor / doctor-fix distinction.** `doctor --live` never calls
  `pm.ensure`, never downloads Chromium/browsers, never mutates browser
  state. Static `doctor` (no `--live`) performs no live probes and never
  enables dependent services on live results; `doctor --live` performs
  probes and reports but enables nothing by itself; `doctor fix` (explicit
  repair command) is the only path that may mutate, and only what the user
  asked to fix. Conflating these (e.g. a `--live` probe that ensures,
  installs, or flips service enablement) fails this design.
- **Errors are `fail`, never `warn`/`pass`/`skip`.** Probe exceptions
  (timeout, `FileNotFound`, non-zero exit, unexpected output, HTTP 401/403/
  5xx on keyed probes, missing key for a *configured* provider) → `fail`
  with a remediation line. Downgrading a configured-but-broken backend to
  `warn` (or dressing a crash as "backend downtime skipped") fails this
  design. `warn` is reserved for explicitly-documented degraded-but-usable
  states, never for a failed oracle. `skip` is reserved for unconfigured /
  `off` / provider-not-implemented, never for an error.
- **Precise acceptance tests per configured backend (mandatory, no implicit
  services):** a matrix over `browser.backend ∈ {off, browser-use,
  agent-browser, unset, unknown-string}` × `{binary missing, --version
  non-zero, --version timeout, Chromium missing, playwright missing,
  harness-ok-but-agent-browser-configured (and reverse)}` asserting the
  exact `pass | fail | skip` per cell (unknown → fail; other-backend-only
  success → fail; version/import/PATH-only → fail), asserting no
  `pm.ensure`/download/service-enable/file-write occurred on any `--live`
  path (mock the install seam to explode if called), asserting bounded
  budgets (timeout + output cap) and child reap (no zombie/daemon), and
  asserting static-doctor vs `--live` vs `fix` behavior stays distinct.
  Tests that assert "all backends pass" from a single shared stub do not
  satisfy this design.

---

## 11. Reviewer checklist (all must be YES before any implementation PR)

1. Implementation diff touches docs + tests only for the initial slice
   contract, and on state paths uses only §3 reads via the §3 anchor;
   `grep` for `mkdir`, `mkstemp`, `O_TMPFILE`, `O_CREAT`, `renameat`,
   `linkat`, `os.replace`, `Path.replace`, `unlinkat`, `os.remove`,
   `Path.unlink`, `rmdir`, `rmtree`, `shutil.*`, `fsync`, `cleanup.log`,
   `quarantine`, `atomic_replace`, `atomic_json_write` on state paths
   returns only test fixtures asserting absence.
2. No `.bak` / log commit path exists; corrupt state is reported, never
   quarantined/rewritten/restored.
3. Sweeps are report-only with `touched == []` asserted; `--apply` is absent
   or always-refuses with non-zero exit and zero side effects (mtime/inode
   census unchanged).
4. Ingress uses `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` or held
   component walking; uncertain/symlink/XDEV → refuse; no path reopen or
   pathname retry anywhere; schema-valid never confers authority.
5. All-uncertain outcomes close fds, roll back in-memory state, and report
   `durable-state-unknown` distinctly — never success, never clean failure,
   never silent suppress.
6. `utils.atomic_replace` and friends are untouched (diff empty).
7. Future broker (if mentioned in code comments) is clearly marked
   not-implemented / separate-review; nothing cites §6 as authority for a
   write.
8. Designs B and C are implemented (or explicitly deferred) WITHOUT the
   `except Exception → AVAILABLE` / skip-on-error carve-outs, WITHOUT
   version/import/PATH/other-backend passes, WITHOUT unknown→skip, WITHOUT
   implicit installs, and WITH actual-entrypoint / per-backend acceptance
   tests. `TerminalPolicyRefusal` resolves to blocked everywhere.
9. Out-of-scope dependency/desktop items are absent from the filesystem
   implementation diff (or split into their own PRs).
10. PR1 remains untouched/OPEN until 1–9 hold on the implementation branch.
    This design grants no GO by itself.

---

## Record

- Rereviewed commit `46ad80b1c85036394d701c54af26287e34eaea86`
  (branch `hermes/hermes-repair-all`, PR1). Verdict: BLOCKED, multiple HIGH
  TOCTOU, no merge.
- Revised commit `8761fcfb1a1ca3ca70442e66ed17186a794fa4eb`
  (branch `hermes/hermes-repair-design`, file
  `plugins/disk-cleanup/DESIGN-FIRST.md`). Verdict: **NO-GO** per §1
  (R1–R7: dirfd overclaim, residual mutation privileges, under-specified
  anchor, commit-implying indeterminate handling, broker ambiguity,
  unnamed fail-open sites, loose doctor oracle). No merge authority drawn
  from it.
- This design rev (branch `hermes/hermes-repair-design`, file
  `plugins/disk-cleanup/DESIGN-FIRST.md`, no runtime changes) narrows the
  initial slice to zero writes, pins the `openat2`/held-walking anchor,
  isolates the broker as a separate deliverable, and pins the actual B/C
  fail-open sites and oracles. It neither closes nor supersedes PR1.
- Next step (separate, after design sign-off): implementation branch +
  adversarial tests per §§8–10 + fresh rereview. Mutation authority stays
  **nonexistent** (not merely "report-only until") until that review
  explicitly grants it — and this file does not pre-grant it.
