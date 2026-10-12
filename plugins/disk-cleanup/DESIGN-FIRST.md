# DESIGN-FIRST: filesystem atomicity + readiness/doctor scope (no runtime change)

> **Status: DESIGN ONLY — no runtime implementation in this commit.**
> Independent rereview of `46ad80b1` FAILED with multiple HIGH TOCTOU findings
> after 2 incremental patch passes. Per order: **STOP incremental filesystem
> patching. Design first, on a separate branch/commit, no live mutations.**
>
> - **PR1 BLOCKED — DO NOT MERGE:** `apikongzad/hermes-agent#1`
>   (`hermes/hermes-repair-all` → `main`, title
>   "fix(repair-all): audited dep pins, doctor scope, disk-cleanup atomic,
>   browser probe, skills commands"). It stays OPEN and unmerged until this
>   design is independently reviewed AND a later implementation lands and is
>   re-reviewed. This commit does **not** supersede, close, or fix PR1.
> - **Canonical followup (design track):** branch `hermes/hermes-repair-design`
>   on the managed worktree. This file is the first commit on that track.
> - **What this commit does:** adds this markdown file only. No `.py`/`.ts`
>   edits, no test edits, no config/lockfile edits, no commands run against
>   live state, no secrets or log dumps included.

---

## 0. Scope declaration

### In scope for this design

- **Design A (normative):** TOCTOU-safe atomic persistence + deletion authority
  for `plugins/disk-cleanup/disk_cleanup.py` and the shared
  `utils.atomic_json_write` / `atomic_replace` path it rides on, including
  `tracked.json`, `tracked.json.bak`, temp files, and `cleanup.log`.
- **Design B (separate):** plugin/skill readiness gate — fail-closed throughout,
  explicitly covering the `TerminalPolicyRefusal` fail-open exception.
- **Design C (separate):** `hermes doctor --live` browser-backend health —
  backend-specific actual health, no implicit install, exception = fail-closed.

### Explicitly out of scope (independent review only)

Dependency and desktop fixes MUST NOT ride along with the filesystem fix and
are accepted only by their own independent review:

- `katex` / `braces` / `postcss-selector-parser` / `tinypool` / `undici` /
  `vitest` / `js-yaml` / `brace-expansion` / `yaml` / `source-map-js` pins and
  overrides (root + website).
- Electron `40.x → 44.x` runtime bump (desktop-only).
- `simple-git 3.x → 4.x` migration + `GIT_`-prefix env guard + `GITHUB_TOKEN`
  preservation.
- Clipboard-image `nativeImage.toPNG` size validation.
- Anything in `apps/desktop/*` not named above.

A future implementation PR for Design A MUST NOT bundle Design B/C fixes or
any out-of-scope item without separate sign-off.

---

## 1. Verdict being designed around

After two incremental hardening passes (`7a04146`, `76594d9`), independent
rereview of `46ad80b1` still reports multiple HIGH TOCTOU races. Patching
one pathname check at a time cannot converge because every fix reintroduces
the same primitive: **check-then-use on a pathname whose parent or leaf an
adversary can swap between the check and the use.** Hence this design-first
reset.

### Finding catalog (must all be closed by the implementation, none by docs)

- **F1 — parent/state-dir symlink, preexisting read/write outside.**
  If `$HERMES_HOME/disk-cleanup` (or any ancestor at ingress time) is or
  becomes a symlink/junction, reads and writes intended for protected state
  land outside the protected roots.
- **F2 — quick-delete temp victim unchecked.**
  The quick/deep sweep deletes temp candidates without re-binding each
  victim to a pinned directory at unlink time; a swapped-in symlink or
  renamed path turns a benign unlink into an outside-tree delete.
- **F3 — load tracked/`.bak` lstat/read race.**
  `is_symlink()` (lstat) followed by `open()`/`read()` leaves a window where
  a regular file is replaced by a symlink (or vice versa); the read then
  follows the link.
- **F4 — `mkdir → mkstemp` parent swap; temp symlink installed.**
  Creating the parent with `mkdir(parents=True)` and then creating the temp
  inside it by name allows a parent swap between the two calls. A temp path
  that is itself a symlink can then be atomically installed via rename,
  promoting attacker content into the state file slot.
- **F5 — `cleanup.log` follows link.**
  The audit log is opened in append mode by pathname with errors suppressed;
  a symlinked `cleanup.log` redirects the audit trail and hides the attack.
- **F6 — pathname `dir fsync` can sync the wrong dir; failure-after-commit
  needs an indeterminate result.**
  `fsync(pathname-of-parent)` re-resolves the parent at sync time and may
  sync an attacker-swapped directory. Worse, when the rename has committed
  but the subsequent fsync fails, reporting plain success (durability lie)
  or plain failure (caller retries into a duplicated/ambiguous state) are
  both wrong: the result is **indeterminate** and must be surfaced as such.

---

## 2. Threat model

- **Adversary: same-UID actor.** A malicious or compromised skill, plugin,
  hook, prior agent turn, or user shell running as the same UID — able to
  create/swap symlinks, rename directories, and race every syscall gap
  inside `$HERMES_HOME` and `/tmp`. No root, no other-UID, no kernel
  attacker. This is the load-bearing assumption: same-UID races are in
  scope, cross-UID DAC is not the defense.
- **Protected roots:** exactly `$HERMES_HOME` and `/tmp/hermes-*` (with the
  macOS `/private/tmp` alias resolved once at ingress). Everything else —
  including `/mnt/*`, `~`, `/tmp` siblings, and the repo tree — is outside.
- **Trust boundaries:**
  1. **Ingress boundary** — pathname → bound descriptor. The ONLY place a
     pathname is resolved. Everything after it operates on descriptors.
  2. **Commit boundary** — temp → final rename. The single linearization
     point; durability (fsync) and reporting orbit it.
  3. **Deletion boundary** — no deletion authority exists except via a
     bound directory descriptor + verified dirent (see §5). Pathname
     strings NEVER confer delete authority.
  4. **Audit boundary** — `cleanup.log` is a security record, not a
     debug convenience. If it cannot be bound safely, the operation aborts
     (fail-closed); it is never skipped silently.
- **Non-goals for this design:** cross-UID hardening, encrypted-at-rest
  state, quota/DoS policy, Windows-junction parity beyond "refuse unless
  proven safe", general sandboxing of plugins.

---

## 3. Normative primitives (apply to every path below)

1. **Ingress via `dirfd` with `O_DIRECTORY | O_NOFOLLOW`.**
   Open each protected root (and the `disk-cleanup/` child) with
   `O_DIRECTORY | O_NOFOLLOW` (plus `O_CLOEXEC`), then `fstat()` the fd and
   pin `(st_dev, st_ino)`. Re-`fstat()` before each use phase; on mismatch,
   abort. Never re-resolve the same directory by name.
2. **`*at` operations only after ingress.**
   All file work uses `openat` / `mkdirat` / `unlinkat` / `renameat` /
   `fstatat(AT_SYMLINK_NOFOLLOW)` relative to a pinned dirfd, with
   `O_NOFOLLOW` (files) and `O_CREAT | O_EXCL` (temps). Bare
   `open(path)` / `os.remove(path)` / `Path.rename(path)` on
   attacker-reachable names is prohibited by this design.
3. **Bound file descriptors.**
   A file is "bound" only when it was opened via `openat(dirfd, name,
   O_NOFOLLOW|…)` and immediately verified with `fstat(fd)` (regular file,
   nlink == 1 expected, uid/ownership as required). Reads, writes, fsyncs,
   and renames act on the fd / `renameat` pair, never on a re-looked-up
   name.
4. **No path-based deletion authority.**
   A string path is NEVER sufficient to delete. Deletion requires: pinned
   parent dirfd + `fstatat(name, AT_SYMLINK_NOFOLLOW)` proving non-symlink
   regular file (or explicitly-authorized empty-dir case) + `unlinkat`
   against the same dirfd without releasing it in between. Any gap that
   lets the parent be swapped invalidates the authorization.
5. **State machine with an explicit INDETERMINATE terminal state.**
   `PREPARE → COMMIT → FSYNC → { DURABLE | INDETERMINATE | FAILED-BEFORE-COMMIT }`.
   Failure after the rename commits is INDETERMINATE (see §4), never
   reported as success or as a clean failure.
6. **Fail-closed logging.**
   Audit-log open failure, symlink detection, or ownership surprise aborts
   the enclosing mutation and surfaces. `contextlib.suppress(OSError)` on
   the audit path is forbidden.
7. **Report-only cleanup until separate review.**
   Under this design, sweep paths (`quick`/`deep`/session-end hooks) run in
   **report-only mode**: enumerate + classify + log what WOULD be deleted,
   delete nothing. Actual unlinking returns only in a later implementation
   review that proves §5 per-victim. This is intentional containment, not a
   permanent product decision.

---

## 4. State machine: prepare / commit / fsync / indeterminate

```
PREPARE  : create temp via openat(pinned_dirfd, O_TMPFILE or
           O_CREAT|O_EXCL|O_NOFOLLOW|O_RDWR, 0o600) -> write bytes ->
           fstat(fd) verify -> fsync(fd).
COMMIT   : link/rename temp into place via renameat(pinned_dirfd, tmpname,
           pinned_dirfd, finalname)  [or linkat for O_TMPFILE].
           COMMIT is the single linearization point.
FSYNC    : fsync(file fd if still open) then fsync(pinned_dirfd).
           The dir fsync acts on the ALREADY-OPEN dirfd, never on a
           re-resolved pathname (closes F6's wrong-dir sync).
```

Outcomes:

| Case | Result | Caller-visible contract |
|---|---|---|
| Fail in PREPARE (incl. temp symlink / parent mismatch) | `FAILED-BEFORE-COMMIT` | State file untouched; safe to retry. |
| COMMIT ok, both fsyncs ok | `DURABLE` | Entry survives power loss (POSIX). |
| COMMIT ok, any fsync fails | **`INDETERMINATE`** | Rename happened; durability unknown. MUST surface distinctly (typed error, metric, log). Caller MUST NOT report success, MUST NOT blindly retry the same rename (could duplicate side effects), MUST run the recovery read-verify path. |
| COMMIT itself fails | `FAILED-BEFORE-COMMIT` | Temp unlinked via dirfd; safe to retry. |

Notes:

- Pathname `dir_fsync(parent_path)` helpers are BANNED in the new code;
  the only allowed dir sync is `fsync(pinned_dirfd)`.
- On Windows (`O_DIRECTORY`/`O_NOFOLLOW` absent), the implementation MUST
  refuse the durable path (fail-closed) rather than silently degrading to
  pathname behavior, unless the followup review explicitly approves a
  Windows-specific binding primitive.
- `.bak` rotation is a second COMMIT with the same machine (prepare new
  `.bak` from the bound current fd, commit, fsync, report indeterminate on
  post-commit failure) — never `shutil.copy`/rename by pathname.

---

## 5. Deletion authority (report-only for now)

Until the followup implementation review, there is NO deletion authority to
grant: sweeps report only. When deletion is re-enabled, each victim MUST
independently pass, in order, with no gaps:

1. Parent is a pinned dirfd (re-`fstat`ed, dev/ino match).
2. `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)` shows an allowed type
   (regular file for file victims; empty-dir check via bound fd for dir
   victims) and allowed location (still under a protected root).
3. `unlinkat(dirfd, name, 0)` on the SAME dirfd with no intervening yield
   that could swap the parent.
4. Dir fsync on the same dirfd; post-unlink fsync failure is likewise
   INDETERMINATE (may-or-may-not-be-deleted) and must be reported as such,
   with a re-list verify step — never auto-retried as a blind second
   unlink of the same name.

Protected top-level state dirs (`logs/`, `memories/`, `sessions/`, `cron/`,
`cache/`, `skills/`, `plugins/`, `disk-cleanup/` itself), user project
trees (`workspace/`, `projects/`, `plans/`, `home/`), and `kanban/` remain
never-delete even when empty; a tracked directory under a protected top
level ages out its files but the directory itself is never removed. These
lists stay data (reviewed in the implementation diff), not prose.

---

## 6. Per-finding closure sketch (implementation MUST prove each)

- **F1:** ingress pins both roots + `disk-cleanup/` dirfd with
  `O_DIRECTORY|O_NOFOLLOW` + dev/ino pinning. Preexisting symlink at any
  ingress component → fail-closed before any read/write. No
  `mkdir(parents=True)` on an unbound chain.
- **F2:** covered by §5 — no victim is deleted from a pathname; report-only
  until the per-victim bound-unlink proof exists.
- **F3:** no `is_symlink()`-then-`open()` split. Single `openat(…,
  O_NOFOLLOW)` + `fstat(fd)`; `ELOOP` → fail-closed. `.bak` load uses the
  same primitive; `O_NOFOLLOW`-absent platforms fail closed.
- **F4:** no `mkdir`-then-`mkstemp(name)` pair. Temp is `O_TMPFILE` (or
  `O_CREAT|O_EXCL|O_NOFOLLOW` via `openat` on the pinned dirfd) and is
  never a pathname the adversary chose; rename installs only a bound fd.
- **F5:** `cleanup.log` opens via `openat(pinned_dirfd, "cleanup.log",
  O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW)` + `fstat` verify; symlink/swap →
  abort the operation with a surfaced error, not a suppressed skip. The
  log is part of the commit record (what was attempted, what was
  indeterminate), not best-effort.
- **F6:** dir sync only on the pinned dirfd; post-commit fsync failure →
  INDETERMINATE terminal state with recovery/verify, per §4.

---

## 7. Migration, rollback, acceptance

- **Migration (existing homes):** current `tracked.json` / `.bak` /
  `cleanup.log` are UNTRUSTED input. On first run under the new code:
  ingress-pin, load each via the bound-read primitive, schema-validate,
  quarantine anything failing validation (rename to `quarantine/<ts>/`
  via `renameat` on pinned fds, log the quarantine), never execute
  deletions derived from unvalidated state. No silent auto-delete of
  legacy files.
- **Rollback:** the design adds no irreversible format change; legacy
  readers see either the old or the new file atomically (rename
  linearization). Rollback = stop writing new format + keep quarantine
  dir for inspection. Rollback MUST NOT restore deletions already
  performed (there are none in report-only mode).
- **Acceptance tests (adversarial, real races — mandatory):**
  - Same-UID swapper thread/process hammering each gap (parent swap,
    leaf swap, log swap, temp swap) during every operation; tests MUST
    use real concurrency (no mocks, no single-threaded lstat stubs).
  - Each of F1–F6 gets a dedicated race test asserting fail-closed /
    indeterminate / report-only behavior, plus a clean-path durability
    test (fsync-failure injection asserting INDETERMINATE, not success).
  - Protected-root escape tests: symlinked state dir, `/mnt/*` victims,
    `/tmp` non-`hermes-*` victims, project-tree victims — all MUST be
    refused and logged.
  - Flakiness guard: race tests run with bounded iterations and fail on
    ANY escape, not on statistical sampling.

---

## Design B (separate): plugin/skill readiness — no fail-open exception

- Readiness (`required_commands` discovery via `PATH`, per-view recheck) is
  fail-closed throughout. Missing/unexecutable required command → setup
  blocked with actionable copy; the skill/plugin MUST NOT load, enable
  services, or partially activate.
- **The `TerminalPolicyRefusal` fail-open exception is REJECTED.**
  A policy refusal is a denial signal, not a skip signal: it MUST resolve
  to blocked/disabled with the same surface as any other readiness
  failure, never to "allow and continue". Any implementation that keeps a
  `except TerminalPolicyRefusal: allow` carve-out fails this design.
- Shared readiness gate for bundled + catalog skills (one code path, one
  verdict vocabulary: `ready | blocked-missing-cmd | blocked-refused |
  unconfigured`), with per-view recheck so `PATH`/policy changes between
  views cannot latch a stale ready.

---

## Design C (separate): `doctor --live` browser health — real, per-backend, no implicit install

- Version-string-only checks are INSUFFICIENT and MUST NOT produce a pass
  for any backend (closes the "version-only false pass all backends"
  failure mode).
- Health is **backend-specific and actual**: probe the CONFIGURED backend
  (`harness` vs `agent-browser`) by executing its real entrypoint/version
  or bounded launch probe; assert the result belongs to that backend.
  A bare `import playwright` succeeding proves nothing about the
  configured backend and MUST NOT gate service enablement.
- **No implicit install/ensure.** `doctor --live` never downloads,
  installs, or mutates browser state. Unconfigured browser → `skip`
  (never enables dependent services). Configured-but-broken (exec fails,
  probe times out, version mismatch) → `broken` (fail-closed), never
  silently treated as unconfigured.
- Exceptions during the probe (timeout, `FileNotFound`, non-zero exit,
  unexpected output) are fail-closed `broken`, with bounded probe budgets
  (timeout + output cap). "All backends pass" requires EACH configured
  backend to pass its own real probe.

---

## Reviewer checklist (all must be YES before any implementation PR)

1. Every post-ingress operation in the implementation diff uses a pinned
   dirfd + `*at`/`O_NOFOLLOW`; `grep` for bare `open(.*path`,
   `os.remove`, `Path.unlink`, `shutil.*`, `mkstemp(.*name` on state paths
   returns only test fixtures.
2. Post-commit fsync failure surfaces INDETERMINATE (distinct type/metric),
   never success.
3. Sweeps are report-only (no `unlinkat` reachable from sweep paths) until
   the followup review explicitly re-enables deletion.
4. Audit-log open is bound + fail-closed; no suppression on that path.
5. Migration quarantines untrusted state; rollback is deletion-free.
6. Race tests are real-concurrency adversarial per F1–F6, not mocked.
7. Designs B and C are implemented (or explicitly deferred) WITHOUT the
   `TerminalPolicyRefusal` fail-open carve-out, WITHOUT version-only
   passes, and WITHOUT implicit browser installs.
8. Out-of-scope dependency/desktop items are absent from the filesystem
   implementation diff (or split into their own PRs).
9. PR1 remains untouched/OPEN until 1–8 hold on the implementation branch.

---

## Record

- Rereviewed commit: `46ad80b1c85036394d701c54af26287e34eaea86`
  (branch `hermes/hermes-repair-all`, PR1). Verdict: BLOCKED, multiple HIGH
  TOCTOU, no merge.
- This design commit: branch `hermes/hermes-repair-design`, file
  `plugins/disk-cleanup/DESIGN-FIRST.md`, no runtime changes. It neither
  closes nor supersedes PR1.
- Next step (separate, after design sign-off): implementation branch +
  adversarial tests + fresh rereview. Deletion authority stays report-only
  until that review explicitly grants it.
