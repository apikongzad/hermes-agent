# DESIGN-FIRST rev4: report-only sweep, zero writes (no runtime change)

> **Status: DESIGN ONLY — no runtime implementation in this commit.**
> Rev4 revises `6128da1` (rev3) fixing the EXACT remaining contradictions
> named below, with no scope expansion.
> Rev3 enumerated entrypoints/lines but left three contradictions:
> (A) two anchor policies (`/`-anchored walk vs `openat2` from
> inherited-or-`/` allowing `/`-relative escape to project/`/mnt`/non-`hermes-`
> temp even when lexically valid); (B) invented `blocked-*` readiness vocabulary
> plus an imaginary "early-hint vs dispatch-time gates still block" claim with
> no new helper and no pinned `1712`/`2458` split; (C) a generic 5×6 matrix
> that judged each backend by the other backend's deps (browser-use by
> Chromium, agent-browser by Python playwright), allowed `--version` reasoning,
> and pinned only `_run_one` while leaving `maybe_run_live_checks:326-327`
> `check_warn` unpinned.
> Rev4 is the implementable contract: one allowed-root policy for both bind
> paths (§3), actual `available`/`setup_needed`/`unsupported` enum + ready
> predicate + new mandatory guard at both dispatch sites (§6), and a
> backend-specific prerequisite oracle with no version-pass and an explicit
> `326-327 → check_fail` pin (§7).
> Per order: **design only, on the design branch, commit docs only, no
> runtime code or host changes.**
>
> - **PR1 BLOCKED — DO NOT MERGE:** `apikongzad/hermes-agent#1`
>   (`hermes/hermes-repair-all` → `main`). OPEN and unmerged until a future
>   implementation lands and is re-reviewed. This commit does **not**
>   supersede, close, or fix PR1.
> - **Rereviewed commits:** `46ad80b1` (FAILED, HIGH TOCTOU), `8761fcfb`
>   (NO-GO R1–R7), `f1e7b5c7` (**NO-GO**, generic `--apply`-only framing),
>   `6128da1` (**NO-GO**, this revision's basis: dual anchor policies,
>   invented readiness enum + imaginary early-hint, generic 5×6 with
>   cross-backend deps + version-pass residue + unpinned `326-327`).
> - **What this commit does:** revises this markdown file only. No `.py`/`.ts`
>   edits, no test edits, no config/lockfile edits, no `utils` edits, no
>   commands against live state, no secrets or log dumps.
> - **No anticipatory GO:** nothing here pre-authorizes deletion, quarantine,
>   rename, log/state writes, broker, install, or `doctor fix`. Mutation
>   authority needs a distinct design + diff + tests + review.

---

## 0. Scope

### In scope

- **Design A (normative, initial slice):** report-only sweep, **zero writes**,
  for the exact entrypoints in §2. Ingress anchor (§3) is in scope because
  even reads need a safe anchor.
- **Design B (separate):** readiness gate fail-closed at the exact lines in §6.
- **Design C (separate):** `hermes doctor --live` per-backend oracle at the
  exact lines in §7.

### Out of scope (independent review only)

- Any deletion/quarantine/rename/temp/mkdir/log/registry/state privilege in
  the initial slice (§4: **none granted**).
- Future privileged broker (§5, separate review/provisioning).
- `utils.atomic_replace` / `atomic_json_write` / `atomic_roundtrip_yaml_save`
  global changes: **forbidden** in the initial slice.
- Dependency/desktop items (`katex`/`braces`/`postcss-selector-parser`/
  `tinypool`/`undici`/`vitest`/`js-yaml`/`brace-expansion`/`yaml`/
  `source-map-js`, Electron `40.x→44.x`, `simple-git 3.x→4.x` + `GIT_` guard +
  `GITHUB_TOKEN`, clipboard `nativeImage.toPNG`, anything in `apps/desktop/*`).

A future Design-A implementation PR MUST NOT bundle B/C or out-of-scope
items without separate sign-off.

---

## 1. Why rev2 was NO-GO (each closed by the cited rev3 section and retained in rev4, proved by diff+tests+review, never by prose)

- **R1 — entrypoints unnamed.** Rev2 said "sweep" and a nonexistent
  `--apply` flag. It never enumerated `quick`, `_delete_item`,
  `_sweep_empty_dirs`, `save_tracked`, `_log`, `track`, `forget`, hooks
  `post_tool_call`/`on_session_end`, slash `quick`/`deep`/`track`/`forget`.
  Closed by §2.
- **R2 — implicit writes unaddressed.** Rev2 forbade `mkdir`/`rename` in the
  abstract while leaving `_log()` bound-append, `guess_category()` git-spawn,
  and hook/slash auto-wire live. Closed by §§2,4.
- **R3 — anchor origin unspecified.** Rev2 said "`openat2` or held walking"
  without saying where the anchor fd comes from, allowing multi-component
  `open()`, `Path.resolve()`, and the `/tmp→/private/tmp` alias relaxation.
  Closed by §3.
- **R4 — metadata as authority + JSON names unvalidated.** Rev2 left mode/stat
  and schema-valid as implicit authority and left `tracked.json` path strings
  unvalidated. Closed by §§3–4.
- **R5 — tests were hammer-only with skip.** Rev2 allowed "hammer each gap"
  and silent skip when the tracer was absent, with no per-boundary barrier
  and no fixed read-only syscall profile. Closed by §8.
- **R6 — Design B lines unnamed.** Rev2 named two sites loosely, omitting
  `skills_tool.py:439-444`, `skills_tool.py:617-641`, `skills_tool_plugin.py:
  164-172`, every `cron/scheduler_preflight.py` fail-open line, the
  `cron/scheduler.py:1719-1722` outer fail-open, and the `cron.preflight:false`
  bypass. Closed by §6.
- **R7 — Design C oracle disjunctive + matrix empty.** Rev2 allowed
  "`--version` OR launch" and left `get_browser_backend` exception→`""`,
  the 5×6 matrix, the static-path install ban, and the `fix` separation
  unpinned. Closed by §7.

---

## 2. Design A: exact mutation entrypoints and required rev4 wiring

All paths read at `6128da1`. The initial slice wires **every** row to
refusal/report-only. Leaving any row live fails review. There is **no**
`--apply`/`--force`/`--delete`/`--commit` flag in
`plugins/disk-cleanup/disk_cleanup.py` (596 lines) or
`plugins/disk-cleanup/__init__.py` (236 lines) — acceptance MUST exercise the
real rows below, never an invented flag.

| ID | Entrypoint (file:line) | Current mutation (must be removed/disabled in initial slice) | Rev4 wiring |
|---|---|---|---|
| A-E1 | `disk_cleanup.py:438-469` `quick()` | calls `_delete_item` (459), `_sweep_empty_dirs` (466), `save_tracked` (467), `_log` (447,451,454,468) | enumerate only via §3 bound reads; return in-memory `{candidates, refused, corrupt, durable_state_unknown, touched: []}`; zero calls to E2–E7; `touched` always `[]` |
| A-E2 | `disk_cleanup.py:403-415` `_delete_item(item)` | `p.unlink()` (408), `shutil.rmtree(p)` (410), `_log` (412,414) | MUST NOT be reachable from `quick`, hooks, or slash in initial slice; any reachable `unlink`/`rmtree` fails §9; keep function only if dead or deleted — never called |
| A-E3 | `disk_cleanup.py:479-497` `_sweep_empty_dirs(hermes_home)` | `dirpath.rmdir()` (491), `_log` (493) | MUST NOT be called in initial slice; `_subdirs` (`472-476`) enumeration only via held dirfd, no `rmdir` |
| A-E4 | `disk_cleanup.py:218-265` `save_tracked(tracked)` | `mkdir` (239), `mkstemp` via `_atomic_bytes_no_follow` (260,265), `os.replace` (inside `122-150`), `fsync`+`_strict_fsync_dir` (77-92), `_log` (245,253) | MUST NOT be called in initial slice; `track`/`forget`/`quick` paths that call it fail §9 |
| A-E5 | `disk_cleanup.py:59-66` `_log(message)` | `mkdir(parents=True)` (63), `open(log_file,"a")`+`write` (65-66), suppressed `OSError` (61) | MUST NOT exist on any sweep/read/track/forget/hook/slash path in initial slice; diagnostics are in-memory return values only; grep for `_log(` on those paths must be empty outside fixtures asserting absence |
| A-E6 | `disk_cleanup.py:336-364` `track(path_str,category)` | `Path.resolve()` (343), `save_tracked` (360), `_log` (339,345,349,352,361), `print` (363) | refuse-or-report-only: validate name per §3, return verdict, zero writes, zero `_log`, zero `save_tracked`; `print` only via slash return string, never as side channel |
| A-E7 | `disk_cleanup.py:367-376` `forget(path_str)` | `Path.resolve()` (369,371), `save_tracked` (374), `_log` (375) | same as E6: verdict only, zero writes |
| A-H1 | `__init__.py:97-119` `_on_post_tool_call` | calls `dg.guess_category` (116, spawns git per §4) + `dg.track` (117, writes) | initial slice: MUST NOT call `track`/`save_tracked`/`_log`; may compute classification via §3 bound read and record in-memory candidate only; invoked in acceptance even on anchor failure, asserting zero writes |
| A-H2 | `__init__.py:122-138` `_on_session_end` | calls `dg.quick()` (132, deletes) + `dg._log` (137) | initial slice: MUST NOT call `quick`-mutating path nor `_log`; may call report-only enumeration; invoked in acceptance even when `had_tracks` true/false and even on refusal, asserting zero writes |
| A-S1 | `__init__.py:215` slash `quick` (`_SUBCOMMANDS:212-218`, `_handle_slash:221-228`, `_fmt_summary:159-164`) | `dg.quick()` mutates | report-only enumeration + format; zero writes |
| A-S2 | `__init__.py:182-190` slash `deep` (`_cmd_deep`) | `dg.quick()` (184) then `dg.dry_run()` (185) | report-only both phases; zero writes; MUST NOT delete then list |
| A-S3 | `__init__.py:193-201` slash `track` (`_cmd_track`) | `dg.track` (199, writes) | verdict string only; zero writes |
| A-S4 | `__init__.py:204-209` slash `forget` (`_cmd_forget`) | `dg.forget` (207, writes) | verdict string only; zero writes |

Supporting rows that MUST also be dead in the initial slice (same grep gate):

- `disk_cleanup.py:183-215` `load_tracked()` — `mkdir` (193), `.bak` fallback
  read (203-211), `_log` (195,205,210,214): replaced by §3 bound-read-or-refuse
  single-file read, no `mkdir`, no `.bak` authority, no `_log`.
- `disk_cleanup.py:122-150` `_atomic_bytes_no_follow` (`mkstemp` 136,
  `os.replace` 145, `fsync` 144, `_strict_fsync_dir` 146), `disk_cleanup.py:
  77-92` `_strict_fsync_dir` (`os.open` 88, `fsync` 90): no callers in slice.
- `disk_cleanup.py:423-435` `dry_run()`, `disk_cleanup.py:379-386`
  `_live_items(log_stale=True→_log)`, `disk_cleanup.py:500-526` `status()`/
  `format_status()`: read-only via §3 anchor; `log_stale` MUST NOT call `_log`.
- `disk_cleanup.py:575-596` `guess_category()` + `disk_cleanup.py:533-572`
  `_git_tracks`/`_inside_git_worktree` (git spawn via
  `hermes_cli.source_check._git_ok`, `533-548`, gated at `551-572`): **no git
  spawn in the initial slice** — classification is name/age/policy only (§4).
- `__init__.py:78-94` `_on_pre_tool_call` snapshot (`Path.exists` 87): read-only;
  MUST NOT create/track/write.
- `__init__.py:231-236` `register(ctx)` (`pre_tool_call`/`post_tool_call`/
  `on_session_end`, `disk-cleanup` command): wires the report-only handlers
  above; no additional hook may call E2–E7.

**Acceptance IDs:** `A-E1`…`A-S4` each have a zero-write test invoking the
exact function/hook/slash named (see §8). A test exercising only a nonexistent
`--apply` flag satisfies nothing.

---

## 3. Read anchor (normative — applies to every read, including report-only)

Rev3 contradiction fixed here: rev3 defined TWO policies — a `/`-anchored
single-basename walk (A-ANCHOR-1/2) AND an `openat2(anchor_fd, path)` that
still accepted the inherited-or-`/` fd with a "validated relative chain"
(A-ANCHOR-3). An implementer following rev3 literally could bind
`openat2("/", "mnt/x")` or `openat2("/", "projects/y")` with lexically-valid
components and pass review. Rev4 defines ONE policy below. `/` is a
bootstrap locator only, never an operation anchor.

**A-ROOTS-1 — explicit allowed roots (from old `is_safe_path`,
`disk_cleanup.py:32-56`).** The ONLY roots the bootstrap may select are:

- `R_HERMES_HOME`: `$HERMES_HOME` (covers the report-only state
  `$HERMES_HOME/disk-cleanup/tracked.json` + allowed ephemeral cache/temp
  owned by this plugin under `$HERMES_HOME`; `get_hermes_home()` is the
  locator input, never a JSON string);
- `R_HERMES_TMP`: `/tmp/hermes-*` (first path component under the resolved
  `/tmp` root starts with `hermes-`; the `/tmp→/private/tmp` alias is
  resolved once at bootstrap by comparing resolved roots, never per-open).

Everything else is refused EVEN WHEN LEXICALLY VALID (no absolute, no `..`,
no empty, no NUL is not enough): project trees (`projects/`, `workspace/`,
`plans/`, `home/`), `/mnt/*`, `/tmp` non-`hermes-*`, outside-`R_HERMES_TMP`
temp, and any absolute path outside the selected root. There is no third
root and no per-call root invention.

**A-ROOTS-2 — bootstrap `/` only to locate, then retain selected-root FD +
fixed rootID.** Open `/` once (`os.open("/", O_DIRECTORY | O_NOFOLLOW |
O_CLOEXEC)`) and walk ONLY single validated basenames from `/` toward the
explicit allowed root named above (each step `openat(parent_fd, name,
O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` + `fstat` + hold-parent).
On arrival `fstat` the selected root and record `rootID = (st_dev, st_ino)`.
Retain the selected-root FD open for the whole operation. Every later bind
re-validates `fstat(selectedRootFD) == rootID`; mismatch → refuse
(`A-REFUSE-1`). The `/` FD is closed after selection and MUST NOT be used
as an operation anchor. No opening `$HERMES_HOME`, `disk-cleanup/`,
`tracked.json`, or any candidate by a multi-component pathname. No
`open(path)`, `Path(path).open()`, `Path.exists()/stat()/read_text()` on
state paths.

**A-BIND-1 — ONE bind policy for component-walk AND `openat2`.**
`tracked.json` carries ONLY `{rootID, relative}`: `rootID` names
`R_HERMES_HOME` or `R_HERMES_TMP`, `relative` is validated components (reject
absolute via `os.path.isabs`, reject `..`, reject empty, reject NUL; each
basename validated before use). Both bind paths start from
`selectedRootFD`, NEVER from `/`:

- (a) component-walk: each descent step opens exactly one validated basename
  with `openat(selectedRootFD-or-held-child, name, O_RDONLY | O_DIRECTORY |
  O_NOFOLLOW | O_CLOEXEC)` (files: without `O_DIRECTORY` but still
  `O_NOFOLLOW`), then `fstat(child)` (`S_ISDIR`/`S_ISREG` as appropriate)
  while **holding the parent fd open**. Never release-then-reopen.
  `ELOOP` → refuse.
- (b) `openat2`: `openat2(selectedRootFD, relative, RESOLVE_BENEATH |
  RESOLVE_NO_SYMLINKS)` (plus `RESOLVE_NO_XDEV` where supported) in one
  kernel-checked step with the SAME per-basename validation and the SAME
  `rootID` + refuse table as (a). `openat2` starting from `/`, from an
  unretained fd, or with an unchecked chain fails §9.

(a) and (b) are interchangeable implementations of the same policy, paired
in acceptance (§8 A-PAIR-1). Neither relaxes the other.

**A-ANCHOR-4 — bans (each fails §9 if present on state paths outside
fixtures asserting absence).** `Path.resolve()` / `os.path.realpath()` /
`Path.exists()/is_symlink()-then-open()` splits (current `disk_cleanup.py:
39,53,72,107,194,197,203,207,308,325,343,369,371,383,570,580`); multi-component
`os.open(str(p))` / `open()` (current `88,109,136` pattern + `65,201,209`);
`Path("/tmp").resolve()` alias relaxation + `relative_to(hermes_home)` +
`parts[0].startswith("hermes-")` as a per-open check (current `32-56`
`is_safe_path` — replaced by A-ROOTS-1/2 bootstrap + rootID); `mkdir(
parents=True)` unbound-chain creation (current `63,193,239`); pathname
`dir_fsync` (`77-92` reopen by name); `readlink`-driven repair; `openat2`
from `/` or from a non-retained fd; silent Windows downgrade to pathname
behavior (refuse fail-closed where `O_DIRECTORY`/`O_NOFOLLOW`/`openat2`
absent).

**A-REFUSE-1 — reject uncertain.** `ELOOP`, `st_dev`/`st_ino`/mode/ownership
surprise, non-directory, mount/XDEV escape, I/O error, `rootID` mismatch,
or any error where safe binding cannot be proven → fail-closed refuse
before any read. Symlink at any ingress component (preexisting or swapped
in) → refuse. Never path-reopen, never `Path.resolve()` retry, never
`exists()` fallback.

**A-JSON-1 — `tracked.json` names are untrusted input.** Each `path` string
in the JSON array is converted to `{rootID, relative}` and validated per
A-BIND-1 (reject absolute, reject `..`, reject empty, reject NUL), then
bound via (a) exact held-component path or (b) `openat2` from
`selectedRootFD` with `RESOLVE_BENEATH|NO_SYMLINKS`. A candidate that does
not name `R_HERMES_HOME`/`R_HERMES_TMP` (project, `/mnt/*`, `/tmp`
non-`hermes-*`, outside temp) is refused even when lexically valid. No
candidate string is ever `open()`ed/`stat()`ed/`unlink()`ed by name. Schema
validation is classification input only (§4). Report-only grants no
deletion authority (§4 A-NONE-1).

---

## 4. Classification without authority; implicit writes removed

**A-AUTH-1 — schema-valid ≠ authority.** A JSON entry that validates is a
*candidate description* for the in-memory report. It never authorizes
deletion, quarantine, rename, tracking-registry mutation, or `.bak`/log commit
(there is no authority to authorize in this slice).

**A-AUTH-2 — metadata uncertain, never security authority.** `stat`/`lstat`
mode bits (`_mode_of_regular_file`, `disk_cleanup.py:153-166`),
`_default_new_mode()` umask sampling (`169-180`), `st_size`/`st_mtime` age,
`nlink` counts, and `fstat` identity are *report hints*. They MUST NOT gate a
write/delete/replace decision, MUST NOT select temp names, and MUST NOT prove
"same file". Any future diff branching a mutation on metadata fails §9.

**A-NOIMPLICIT-1 — no `_log` on slice paths** (`disk_cleanup.py:59-66` removed
from reachability per §2 A-E5; `_live_items(log_stale)` `379-386`,
`quick` log lines `447,451,454,468`, `_sweep_empty_dirs` `493`,
`track/forget/load/save` log lines all dead). Diagnostics are typed return
values `{candidates, refused, corrupt, durable_state_unknown, touched: []}`.

**A-NOIMPLICIT-2 — no `guess_category` git spawn in slice.**
`disk_cleanup.py:533-548` `_git_tracks` (`_git_ok([...,"ls-files",
"--error-unmatch",...], timeout=5)`), `551-572` `_inside_git_worktree`
(`.git` probes + `_git_tracks`), and `575-596` `guess_category` branches
calling them are **out of the slice**. Initial classification uses only
anchored names/ages/policy tables (`ALLOWED_CATEGORIES 268-269`,
`_EMPTY_DIR_PROTECTED_TOP_LEVEL 272-280`, `_NEVER_TRACK_TOP_LEVEL 287-299`,
`_is_auto_delete 389-390`, `_prompt_group 393-400`). Zero `subprocess`/git
spawns on read paths; the §8 syscall profile asserts it (including no
`.git/index` writes, which even read-only `ls-files` can cause).

**A-NONE-1 — authority NONE.** No deletion, quarantine, rename, log-append,
state-write, `chmod`/`chown`, `symlink`/`readlink`-repair authority exists
until a separate reviewed design grants it. §2 tables + §9 check absence, not
correctness of a protocol that must not exist.

---

## 5. Future broker (NOT this deliverable, NO GO implied)

Same-UID in-process code can never hold exclusive mutation authority (§1 R1).
IF mutation is ever wanted, the candidate shape is a distinct-UID broker with
root-0700 store, trusted unnamed `socketpair` (or `SCM_CREDENTIALS`/
`SCM_RIGHTS` fd-passing, never bare pathnames), OS-level
packaging/provisioning (systemd/launchd), and its own threat model (broker
compromise, confused deputy, quota/DoS, audit durability). This paragraph
authorizes nothing; citing it for any `unlink`/`rename`/`mkdir`/log write in
the initial slice fails review.

---

## 6. Design B: readiness fail-closed at exact lines

Rev3 contradiction fixed here: rev3 invented a new readiness vocabulary
(`blocked-missing-cmd`, `blocked-refused`, …) as if it were
`readiness_status`, and claimed `cron.preflight:false` "disables only the
early hint" while unnamed "dispatch-time gates still block" — no such
always-on gate exists. Rev4 uses the ACTUAL enum, defines ONE ready
predicate, keeps `blocked_config` as a cron diagnostic (not a readiness
value), and requires a NEW mandatory helper invoked regardless of the flag
at BOTH dispatch sites.

**B-ENUM-1 — actual enum, no new values.** The only `readiness_status`
values are `tools/skills_tool_setup.py:19-22` `SkillReadinessStatus`:
`AVAILABLE="available"`, `SETUP_NEEDED="setup_needed"`,
`UNSUPPORTED="unsupported"`. Produced at `tools/skills_tool.py:450`
(`SETUP_NEEDED if setup_needed else AVAILABLE`) and `:590` /
`tools/skills_tool_plugin.py:140-141` (`UNSUPPORTED` for platform mismatch).
No `blocked-error`/`blocked-missing-cmd`/other `readiness_status` value is
introduced. `success` (`skill_view` `:644`, `_fail` = `success:False` via
`tools/skills_tool_plugin.py:29-30`, `tool_error(success=False)` via
`tools/registry.py:1022-1025`), `setup_needed` / `setup_skipped`
(`:455`), and `error` are separate fields — never folded into the enum.

**B-READY-1 — ready predicate (activation).** A skill is READY iff ALL hold
on the CURRENT view payload: `success is True` AND
`readiness_status == "available"` AND `setup_needed is False` AND `error`
absent. Every other combination blocks skill load, plugin enable, cron
dispatch, and dependent-service enablement, uniformly across
CLI/gateway/TUI/Desktop/cron. `UNSUPPORTED` never activates (platform
mismatch, `:590`). `SETUP_NEEDED` never activates (missing env/commands/
cred-files, `:426-449`). `success:False` (disabled, unreadable, `_fail`,
`tool_error`) never activates. Missing/unknown fields → not ready
(fail-closed). Per-view recheck (no latched ready).
`TerminalPolicyRefusal`/`TerminalPolicyUnavailable` is a denial signal →
not ready, never allow/skip.

**B-DIAG-1 — `blocked-error` is a cron diagnostic for `setup_needed`,
not a readiness value and not activatable.** When the skill payload reports
`setup_needed` (including exception paths below that MUST set
`setup_needed=True` + `readiness_status="setup_needed"`), cron maps it to a
`[blocked_config]` diagnostic reason (`cron/scheduler_preflight.py:24-25`
`BLOCKED_CONFIG_MARKER`, emitted by `cron/scheduler.py:1728-1752`
`_blocked_config_result`) naming the missing items via
`_SKILL_MISSING_FIELDS` (`scheduler_preflight.py:296-300`). The diagnostic
blocks dispatch; it never makes the skill activatable and never appears as
`readiness_status`. `UNSUPPORTED` maps to the same blocked diagnostic (never
ready), but its label is the platform verdict, not `setup_needed`.

| ID | Fail-open line (read at current HEAD) | Required fail-closed wiring (actual-enum vocabulary) |
|---|---|---|
| B-CRED-1 | `tools/skills_tool.py:439-444` `register_credential_files` wrapped in `try/except → debug` leaving `missing_cred_files=[]`, `setup_needed` unchanged | exception → `setup_needed=True`, `readiness_status="setup_needed"` (B-ENUM-1), activation blocked per B-READY-1; surfaced in preflight `missing_credential_files` label via B-DIAG-1 |
| B-PM-1 | `tools/skills_tool.py:616-641` `pm.ensure(dep)` fail → `deps_note` string only, result still `success:True` + `readiness_status="available"` | declared-`deps` failure MUST also set `setup_needed=True` + `readiness_status="setup_needed"` (or `blocked-missing-cmd`-equivalent TEXT in `deps_note` + blocked diagnostic when the dep provides a `required_commands` binary); content MUST NOT report `success:True`+`"available"`+`setup_needed:False` while deps failed |
| B-PLUGIN-1 | `tools/skills_tool_plugin.py:161-172` `except Exception → readiness_status="available"/setup_needed:False/setup_skipped:False` | exception → `setup_needed=True` + `readiness_status="setup_needed"` with the same vocabulary as local skills; shared `_skill_readiness` path (`:162-163`), one verdict table (B-ENUM-1) |
| B-CRON-1 | `cron/scheduler_preflight.py:91-95` `_job_fallback_chain` probe `except → None` | probe error → blocked diagnostic naming the check (fail-closed); never "no fallback chain, proceed" |
| B-CRON-2 | `cron/scheduler_preflight.py:120-121` non-`AuthError` `except → None` | non-auth resolve error → blocked diagnostic (real path does not get to reinterpret it as runnable) |
| B-CRON-3 | `cron/scheduler_preflight.py:275-279` gateway-config load `except → None` (fail-open skip) | load failure → blocked diagnostic for known-platform lanes; `local`/`origin`/`all`/bot-chat lanes stay exempt (no config load) |
| B-CRON-4 | `cron/scheduler_preflight.py:314-317` `skill_view` `except → continue` / `not success → continue` | unreadable/missing/unready skill → blocked diagnostic via `_SKILL_MISSING_FIELDS` labels (296-300) evaluated under B-READY-1; fall-through to `_build_job_prompt` skip handling is removed for the blocking path |
| B-CRON-5 | `cron/scheduler_preflight.py:399-403` `_preflight_job_config` per-check `except → continue` | check raise → blocked diagnostic naming the check (`provider_key`/`skills`/`delivery`) |
| B-CRON-6 | `cron/scheduler.py:1697-1725` `_preflight_or_block`, esp. `1719-1722` outer `except → _pf_reason=None` ("validator must never take down a runnable job") | validator error → blocked diagnostic; job does not dispatch |
| B-PREFLIGHT-FLAG | `cron/scheduler_preflight.py:80-83` `_cron_preflight_enabled` (`cron.preflight` literally `False` disables) + `cron/scheduler.py:1712` gate + `cron/scheduler.py:2458` gate (`_empty_requested_mcp_toolsets`) | `cron.preflight:false` disables ONLY the OPTIONAL provider-key probe (`_preflight_check_provider_key`, `:86-122`, transient/auth-fallback sensitive). It MUST NOT bypass mandatory readiness. Implementation MUST ADD a NEW helper — e.g. `_cron_mandatory_readiness_guard(job, cfg) -> Optional[str]` wrapping the B-READY-1 skill check (`_preflight_check_skills`) + mandatory delivery check (`_preflight_check_delivery` unknown-platform part) fail-closed on raise — and invoke it UNCONDITIONALLY at BOTH dispatch sites regardless of `_cron_preflight_enabled`: (i) inside `_preflight_or_block` (`scheduler.py:1710-1722`, before/around the flag gate), and (ii) inside `_resolve_cron_agent_setup` (`scheduler.py:2441-2462`, alongside `_empty_requested_mcp_toolsets` at `:2458-2461` which is likewise gated today and must also run its mandatory part regardless). An implementation where `false` dispatches a B-READY-1-unready skill/key/delivery, or one that cites an imaginary "dispatch-time `_skill_readiness` gate already blocks" without the new call, fails review |
| B-VIEW-1 | `tools/skills_tool.py:613-641` view-time `pm.ensure` (read-only `skill_view` mutates host) | read-only view performs zero setup: no `pm.ensure`, no `pm.ensure_import`, no download; missing deps → `setup_needed` verdict + `deps_note` remedy, install only via explicit `hermes pm install` + reload. Same ban covers `skills_list` and plugin-serve paths |
| B-ACT-1 | deployment/activation seam (skill load, plugin enable, cron dispatch, dependent-service enable) | activation requires B-READY-1 on the current view; every other status blocks with no side effect (no scheduling, no service enable, no tool registration for that skill) |

**Acceptance IDs:** `B-ENUM-1`, `B-READY-1`, `B-DIAG-1`, `B-CRED-1`,
`B-PM-1`, `B-PLUGIN-1`, `B-CRON-1`…`B-CRON-6`, `B-PREFLIGHT-FLAG`
(both `1712` and `2458` exercised with `cron.preflight:false` + unready
skill, asserting the NEW mandatory guard blocks while the optional
provider probe skips), `B-VIEW-1`, `B-ACT-1` — each driven through the real
entrypoint (`skill_view`/`_serve_plugin_skill`/`_preflight_check_skills`/
`_preflight_job_config`/`_preflight_or_block`/`_resolve_cron_agent_setup`)
with real faults (PATH without command, invalid `required_commands`,
refusal scope, raising probe, timeout, unconfigured store, unknown backend,
`cron.preflight:false`), asserting actual-enum verdicts + `success` +
`setup_needed` + zero activation/scheduling/service-enable side effects.
Helper-only or patched-ready tests satisfy nothing.

---

## 7. Design C: `doctor --live` real per-backend oracle

Rev3 contradiction fixed here: rev3's generic 5×6 matrix judged each backend
by the OTHER backend's deps (browser-use by Chromium, agent-browser by
Python playwright), left `--version` as a PASS-adjacent probe, let unset
pass via the non-launched backend, and pinned only `_run_one:274-284` while
leaving the outer `maybe_run_live_checks:326-327` `check_warn` unpinned.
Rev4 REPLACES the 5×6 with the ordered backend-specific decision below.
Failure mode remains: version-string/bare-import/PATH-presence/other-backend
success producing PASS, unknown→skip, `--live` mutating host,
static/live/fix conflated.

**C-DECIDE-1 — ordered decision (config → selection → selected-backend
prerequisites → launch; irrelevant deps ignored).**

1. Config parse failure → `fail`. `get_browser_backend()`
   (`tools/browser_use_cli.py:219-223`, reads `_read_browser_cfg()`
   `:194-202`; YAML-1.1 unquoted `off` as `False` → `"off"`, else
   lowercased `str`, `""` = unset) raising or returning a malformed
   non-string → `fail` (fail-closed), never unset-default. Doctor's
   `_configured_backend_key()` (`hermes_cli/doctor_live.py:73-79`)
   `except → ""` becomes `except → fail` (probe error).
2. Selection via the EXACT resolver: `off` → `skip` (never enables
   dependents); explicit `"browser-use"` / `"agent-browser"` → that backend
   only (no fallback); unset `""` → the EXPLICIT default-selection
   algorithm grounded in `is_browser_use_cli_mode()`
   (`tools/browser_use_cli.py:251-259`: explicit key wins, else legacy
   cloud config or `_find_cli() is not None` selects browser-use, else the
   built-in/agent-browser path) — the same order `_probe_configured_backend`
   (`hermes_cli/doctor_live.py:129-178`) implements (harness first, then
   agent-browser). Unset has no second resolver; citing a different default
   order fails review. Unknown string → `fail` (fail-closed), never `skip`.
3. Selected backend's ACTUAL required deps only; irrelevant deps IGNORED
   (never fail, never pass):
   - `browser-use` selected → requires ONLY the configured backend's own
     `browser_harness` operation: `_find_cli()`
     (`tools/browser_use_cli.py:292-297`, `[sys.executable, "-m",
     "browser_harness.run"]` when `importlib.util.find_spec(
     "browser_harness")` resolves) runnable via the launch oracle below.
     Chromium-executable missing (`hermes_cli/browser_runtime.py:10-16`),
     Python `playwright` missing, `agent-browser` binary missing are
     IRRELEVANT → ignored.
   - `agent-browser` selected → requires ONLY `_find_agent_browser(
     validate=False)` (`tools/browser_tool_install.py:60-91`, PM exact
     binary then PATH/Homebrew, never exec/install) PLUS
     `chromium_executable()` (`hermes_cli/browser_runtime.py:10-16`, PM
     `chromium` or `AGENT_BROWSER_EXECUTABLE_PATH` override) runnable via
     the launch oracle below. Python `playwright` importable/missing and
     `browser_harness` present/missing are IRRELEVANT → ignored.
     **Agent-browser does NOT require Python playwright** (rev3 col (e) was
     wrong); **browser-use does NOT require local Chromium** (rev3 col (d)
     was wrong).
4. PASS requires the actual LAUNCH oracle (C-ORACLE-2) for the SELECTED
   backend only. A pass from the non-selected backend is `fail` per
   C-ORACLE-1. `skip` is reserved for `off` and genuinely-none-configured
   unset (absent key, no backend runnable, no error beyond absence — e.g.
   local-audio provider); never for configured-but-broken, missing-dep-for-
   configured, or unset-where-the-default-oracle-errored (→ `fail` with
   remediation).

**C-ORACLE-1 — REMOVE every version-OR-launch disjunct.** No `pass` from a
version string, bare `import playwright`/`browser_harness`, `shutil.which`/
`_find_cli() is not None` (`tools/browser_use_cli.py:292-297`)/
`_find_agent_browser(validate=False)` (`tools/browser_tool_install.py:60-91`)/
`chromium_executable() is not None` (`hermes_cli/browser_runtime.py:10-16`)
PATH hit, or a probe of a *different* backend than selected. Current
disjuncts that MUST NOT confer PASS: `hermes_cli/doctor_live.py:55-61`
`_browser_use_ready`, `64-70` `_agent_browser_ready`, `82-95`
`_browser_available` (`or`), `98-126` `_harness_version_probe` standalone
PASS, `129-178` `_probe_configured_backend` version-subprocess PASS,
`181-207` `_launch_browser_probe` fallback-to-other-backend. A `--version`
exec is at most a bounded liveness pre-check inside the launch oracle; **a
version string alone NEVER confers PASS.**

**C-ORACLE-2 — launch oracle (the only PASS path).** Launch the EXACT
binary/entrypoint the tool spawns for the SELECTED backend (predetermined:
`[sys.executable, "-m", "browser_harness.run"]` for browser-use;
`_find_agent_browser` binary + `chromium_executable()` for agent-browser),
open `about:blank`, evaluate a KNOWN-DOM assertion, close, reap. Bounded:
`1s ≤ timeout ≤ 15s` (clamp `doctor.live_probe_timeout`,
`hermes_cli/doctor_live.py:293-296`), output cap 80–4k chars,
`capture_output`, `check=False`, explicit `wait`/reap, `close()` in
`finally` (no zombies, no lingering browser/daemon, no `pm.ensure`). The
playwright launch path (`hermes_cli/doctor_live.py:194-207`) survives ONLY
as the agent-browser-selected backend's own launch mechanism when that
backend drives via playwright — never as a pass for an explicitly-configured
`browser-use` backend and never because "playwright imports".

**C-BACKEND-1 — selected backend decisive; exception is broken.**
Configured-but-broken (binary missing, `--version` non-zero/timeout,
Chromium missing for agent-browser, harness missing for browser-use,
unexpected output, resolver/config exception) → `fail` (`broken`),
fail-closed, never `unconfigured`/`skip`. Unknown string → `fail`, never
`skip`. `off` → `skip`.

Audio/keyed probes keep their existing contract (`_KEYED_PROBES 21-24`,
`_AUDIO_PROBES 27-31`, `_keyed_probe 225-231`, `_probe_audio 241-256`):
missing key for an *unconfigured* provider → `skip`; missing key for a
*configured* provider → `fail`; HTTP 401/403/5xx → `fail`; timeout/
`FileNotFound`/non-zero/unexpected → `fail`, never `warn`. `warn` only for
explicitly-documented degraded-but-usable states.

**C-LIVE-1 — entire `--live` path is non-mutating, static path is
non-downloading.** `doctor --live` (`hermes_cli/doctor.py:189-192`
after `DOCTOR_CHECKS 112-129`, `hermes_cli/doctor_live.py:287-328`)
never calls `pm.ensure`/`ensure_import`, never downloads Chromium/browsers,
never mutates browser state, never enables dependent services. Static `doctor`
(no `--live`) performs no live probes.

**C-CRASH-1 — pin BOTH crash sites (not only `_run_one`).**
`_run_one` (`hermes_cli/doctor_live.py:274-284`) per-probe catch-all →
`fail` is retained. ADDITIONALLY the outer
`maybe_run_live_checks:326-327` catch-all (`except Exception` → currently
`check_warn("Live backend probes crashed", …)` + `return None`, swallowing
the crash into exit-0 via `hermes_cli/doctor.py:190-194`
`warn_on_error` + `run_doctor` return) MUST become `check_fail` + append to
`issues` (so `run_doctor` returns nonzero) — explicitly pin `:326-327`,
not only `:274-284`. Any implementation leaving `check_warn`/`return None`
at `:326-327` fails review.

**C-FIX-1 — `doctor fix` is separate, human-approved, scoped.** Only
`hermes doctor --fix` (`should_fix`, e.g. `hermes_cli/doctor_tools.py:320-343`
`_check_agent_browser` `pm.ensure` iff `should_fix`, `397-410`
`_check_node_and_browser`) may mutate, and only what the user asked to fix.
`--live` MUST NOT imply `--fix`; `--fix` MUST NOT ride along with `--live`
unless explicitly passed. No anticipatory permission: documenting a fix does
not authorize a probe to fix.

**Acceptance IDs:** `C-DECIDE-1` (ordered steps asserted with real
`browser.backend` values incl. `False`-as-`off`, malformed, unknown),
`C-ORACLE-1/2` (no version/import/PATH/other-backend PASS; launch-only
PASS with known-DOM eval + bounded reap), `C-BACKEND-1`
(backend-specific prereqs; irrelevant-missing-dep tests: browser-use PASS
with Chromium/playwright/agent-browser absent; agent-browser PASS with
harness/playwright absent and FAIL without Chromium), `C-LIVE-1`,
`C-CRASH-1` (outer `:326-327` crash → `check_fail` + `issues` + nonzero
exit, plus per-probe `_run_one` crashes → `fail`), `C-FIX-1` — asserting
exact `pass|fail|skip` per backend-specific prerequisite, zero
`pm.ensure`/download/service-enable/file-write on any `--live` path,
bounded budgets + child reap, and static-vs-live-vs-fix distinction.
Single-stub "all backends pass" tests satisfy nothing.

---

## 8. Migration, rollback, acceptance (read-only slice)

- **Migration:** existing `tracked.json`/`.bak`/`cleanup.log` are UNTRUSTED
  input. Read each via §3 bound-read-or-refuse, schema-validate as
  classification input, report `corrupt-untrusted`/`refused-symlink`/
  `refused-escape` as appropriate. Never quarantine/rename/rewrite/delete
  legacy files. No silent auto-repair.
- **Rollback:** no format change, no write — rollback = stop running the new
  reader. MUST NOT restore or delete (there are none). Downgrade readers see
  files unchanged because nothing was written.

**Adversarial tests (mandatory, deterministic barriers — hammer alone
satisfies nothing):**

- **A-ZERO-1 — exact-entrypoint zero-write.** Invoke EACH of `quick`,
  `_delete_item`-reachability, `_sweep_empty_dirs`-reachability,
  `save_tracked`-reachability, `_log`-reachability, `track`, `forget`,
  `_on_post_tool_call`, `_on_session_end` (both `had_tracks` states),
  slash `quick`/`deep`/`track`/`forget` — including on anchor-refusal and
  corrupt-JSON paths — and assert: mtime/inode/byte census of the state dir
  unchanged, `touched == []`, no new files. Census taken before/after each
  call, not once per suite.
- **A-BARRIER-1…6 — per-boundary deterministic barrier per finding F1–F6**
  (from rev2 §1, restated read-path): each test plants a deterministic
  Ordering barrier (eventfd/pipe/futex rendezvous, not sleep sampling) that
  forces the swap exactly inside the victim gap (ingress component swap,
  leaf swap, `.bak`/log-path swap attempt, anchor swap, JSON-name swap,
  enumeration-vs-classify swap) with real threads/processes (no mocks, no
  single-threaded lstat stubs), then asserts refuse/`durable-state-unknown`/
  report-only. Statistical hammer without a barrier satisfies nothing.
- **A-TRACER-1 — tracer absent is FAIL, not skip.** The read-only syscall
  profile (allowed: `openat2`/`openat(O_RDONLY|O_NOFOLLOW|O_CLOEXEC|
  O_DIRECTORY)` on the §3 chain, `fstat`/`fstatat(AT_SYMLINK_NOFOLLOW)`,
  `read`/`close`, `getdents` via held dirfd; forbidden: `mkdir`/`mkdirat`,
  `mkstemp`/`O_TMPFILE`/`O_CREAT`/`O_EXCL` on state, `write` to state,
  `renameat`/`linkat`/`os.replace`/`Path.replace`, `unlinkat`/`unlink`/
  `rmdir`/`rmtree`, `fsync`/`fdatasync` on state, `chmod`/`fchmod`/`chown`,
  `symlink`, `execve(git)`/`execve(any)` on read paths, `socket`/`connect`
  from slice) is asserted via fd-trace/seccomp/`strace`-equivalent. **If the
  tracer facility is unavailable, the test FAILS** (required gate), never
  skips. The profile explicitly asserts **zero git spawns including no
  `.git/index` writes** (A-NOIMPLICIT-2).
- **A-ESCAPE-1 — protected-root escapes refused.** Symlinked state dir,
  `/mnt/*`, `/tmp` non-`hermes-*`, project-tree (`projects/`, `workspace/`,
  `plans/`, `home/`), and absolute/`..`/empty/NUL JSON-name candidates are
  all refused + reported, none written, even when JSON validates. Each case
  asserted under BOTH bind paths (a) component-walk and (b) `openat2` from
  the same `selectedRootFD` + `rootID` (A-PAIR-1): `openat2` from `/` or
  from a non-retained fd is a test failure even when the walk refuses.
- **A-PAIR-1 — component-walk and `openat2` share one policy.** Every
  A-BARRIER/A-ESCAPE case runs twice (same `{rootID, relative}`, same
  concurrent-swap barrier, same multi-condition setup: symlink + XDEV +
  `rootID`-mismatch attempts under real threads) — once via (a), once via
  (b) — asserting identical refuse/report and identical `rootID` pin. A test
  passing one path only satisfies nothing.
- **B-ENUM-FLAG-1 — actual enum + flag + actual entrypoints.** Drive
  `skill_view` / `_serve_plugin_skill` / `_preflight_check_skills` /
  `_preflight_job_config` / `_preflight_or_block` (`scheduler.py:1697-1725`)
  / `_resolve_cron_agent_setup` (`scheduler.py:2423-2462`) with payloads
  carrying the ACTUAL enum (`available`/`setup_needed`/`unsupported`) +
  `success` + `setup_needed` + `error`: READY only per B-READY-1; every
  other combination → `[blocked_config]` diagnostic, zero activation. Drive
  BOTH `1712` and `2458` with `cron.preflight:false`: the NEW mandatory
  guard blocks an unready skill while the optional provider probe skips —
  assert the new helper was called (not an imaginary early hint).
- **C-BACKEND-IRR-1 — irrelevant-dep + outer-crash tests.** Browser-use
  PASS with Chromium/`playwright`/`agent-browser` absent (only harness
  launch oracle); agent-browser PASS with harness/`playwright` absent and
  FAIL without Chromium (never because of `playwright`); explicit-backend
  pass via the other backend → FAIL; unset-healthy-other-backend fallback
  → FAIL (skip only genuinely-none-configured). Outer
  `maybe_run_live_checks:326-327` crash (raise inside `run_live_checks`)
  → `check_fail` + `issues` append + nonzero `run_doctor` exit; per-probe
  `_run_one` crash → `fail`. `check_warn` at `:326-327` fails the test.
- **Flakiness guard:** bounded iterations; ANY escape or ANY write fails.
  No statistical pass.

---

## 9. Reviewer checklist (all must be YES before any implementation PR)

1. (A-E1…A-S4) Every §2 row is wired refusal/report-only; grep for `mkdir`,
   `mkstemp`, `O_TMPFILE`, `O_CREAT`, `renameat`, `linkat`, `os.replace`,
   `Path.replace`, `unlinkat`, `os.remove`, `Path.unlink`, `rmdir`, `rmtree`,
   `shutil.*`, `fsync`, `cleanup.log`, `quarantine`, `atomic_replace`,
   `atomic_json_write`, `_log(`, `_git_ok`, `ls-files` on slice paths returns
   only fixtures asserting absence.
2. (A-ROOTS-1/2, A-BIND-1, A-JSON-1) Bootstrap `/` only to locate explicit
   `R_HERMES_HOME`/`R_HERMES_TMP`; retained `selectedRootFD` + fixed
   `rootID`; component-walk AND `openat2` start from `selectedRootFD` (never
   `/`) with same validation; project/`/mnt`/outside-`hermes-`temp refused
   even when lexically valid; JSON only `{rootID, relative}` (no absolute,
   no `..`); uncertain/symlink/XDEV/`rootID`-mismatch → refuse; no path
   reopen/retry; report-only grants no deletion authority.
3. (A-AUTH-1/2, A-NONE-1) Schema-valid/metadata never authorize; no unlink
   protocol/tables as policy; `touched == []` asserted per entrypoint.
4. (A-NOIMPLICIT-1/2) No `_log`, no git spawn (incl. no index writes) on slice
   paths; `log_stale` in-memory only.
5. (A-ZERO-1, A-BARRIER-1…6, A-TRACER-1, A-ESCAPE-1, A-PAIR-1) Zero-write census per exact
   hook/slash even on failure; deterministic barriers per boundary on BOTH
   bind paths under multi-concurrent swaps; tracer absent → FAIL; read-only
   syscall profile incl. no-git-index-writes held.
6. (B-ENUM-1, B-READY-1, B-DIAG-1, B-CRED-1, B-PM-1, B-PLUGIN-1, B-CRON-1…6, B-PREFLIGHT-FLAG, B-VIEW-1,
   B-ACT-1, B-ENUM-FLAG-1) Actual `available`/`setup_needed`/`unsupported`
   only, ready = `available`+`success`+`setup_needed:false`+error-absent, no
   new enum; `blocked_config` diagnostic only for `setup_needed`/unready (not
   activatable); no `except→AVAILABLE`/`continue`/`None` carve-out; NEW
   mandatory guard invoked regardless of flag at BOTH `1712` and `2458`
   (optional provider probe alone may skip); view performs zero setup;
   real-entrypoint tests, no patched-ready stubs.
7. (C-DECIDE-1, C-ORACLE-1/2, C-BACKEND-1, C-LIVE-1, C-CRASH-1, C-FIX-1, C-BACKEND-IRR-1) No
   version/import/PATH/other-backend PASS; ordered config→selection→
   selected-backend-prereqs→launch with irrelevant deps ignored
   (browser-use = harness only, agent-browser = binary+Chromium, never
   Python `playwright` for agent-browser); unset uses the explicit
   `is_browser_use_cli_mode` default order; unknown/`except`→`fail`;
   outer `:326-327` → `check_fail`+`issues`+nonzero (not only `_run_one`);
   `--live` non-downloading, no `ensure`; `fix` separate human-approved scope.
8. `utils.*` atomic helpers untouched (diff empty).
9. Out-of-scope dependency/desktop items absent from the implementation diff
   (or split PRs).
10. PR1 remains OPEN/untouched until 1–9 hold on the implementation branch.
    This design grants no GO by itself.

---

## Record

- Rereviewed `46ad80b1c85036394d701c54af26287e34eaea86` (branch
  `hermes/hermes-repair-all`, PR1). Verdict: BLOCKED, HIGH TOCTOU, no merge.
- Revised `8761fcfb1a1ca3ca70442e66ed17186a794fa4eb` (branch
  `hermes/hermes-repair-design`, `plugins/disk-cleanup/DESIGN-FIRST.md`).
  Verdict: **NO-GO** (R1–R7 generic).
- Revised `f1e7b5c76685ac16fdd9ba82ede7e3b7d46fd7d4` (same branch/file).
  Verdict: **NO-GO** (§1 R1–R7: unnamed entrypoints, invented `--apply`,
  unspecified anchor origin, metadata/JSON authority gaps, hammer+skip tests,
  unnamed B/C lines, version-OR-launch oracle, empty matrix).
- This rev3 (same branch/file, no runtime changes) enumerates the exact
  entrypoints/hooks/slash (§2), the inherited-or-`/` single-basename anchor
  with bans (§3), metadata/JSON authority removal (§§3–4), deterministic
  barrier + FAIL-on-no-tracer + no-git-index-writes acceptance (§8), the exact
  B fail-open lines incl. `skills_tool.py:439-444`/`617-641`,
  `skills_tool_plugin.py:164-172`, all `cron/scheduler_preflight.py` +
  `cron/scheduler.py:1719-1722` paths with `cron.preflight:false` non-bypass
  (§6), and the launch-only oracle with `except→broken`, full 5×6 matrix,
  static-path non-download, and separate `fix` scope (§7). It neither closes
  nor supersedes PR1.
  Verdict on rev3: **NO-GO** (remaining contradictions: dual anchor policies
  with `/`-anchored `openat2` escape; invented `blocked-*` readiness enum +
  imaginary early-hint without a new helper or `1712`/`2458` split; generic
  5×6 with cross-backend deps + version-pass residue + unpinned `326-327`).
- This rev4 (same branch/file, no runtime changes) fixes EXACTLY those three:
  (A) one allowed-root policy — bootstrap `/` only to locate explicit
  `R_HERMES_HOME`/`R_HERMES_TMP` (old `is_safe_path:32-56`), retain
  `selectedRootFD` + fixed `rootID`, JSON only `{rootID, relative}`,
  component-walk and `openat2` both start from `selectedRootFD` (never `/`),
  project/`/mnt`/outside-`hermes-`temp refused even when lexically valid,
  report-only with no deletion authority (§3); (B) actual
  `available`/`setup_needed`/`unsupported` enum (`skills_tool_setup.py:19-22`)
  + ready = `available`+`success`+`setup_needed:false`+error-absent, no new
  enum, `blocked_config` diagnostic only for `setup_needed`/unready, NEW
  mandatory guard (e.g. `_cron_mandatory_readiness_guard`) invoked
  regardless of `_cron_preflight_enabled:80-83` at BOTH `scheduler.py:1712`
  and `:2458`, optional provider probe alone may skip (§6); (C) ordered
  backend-specific oracle replacing the 5×6 — config-fail→fail, exact
  `get_browser_backend:219-223` selection, `is_browser_use_cli_mode:251-259`
  default order for unset, selected-backend actual deps with irrelevant deps
  ignored (browser-use = harness only, agent-browser = binary+Chromium,
  never Python `playwright`), launch-only PASS (predetermined binary,
  known-DOM eval, bounded cleanup, no version-pass), skip only
  genuinely-none-configured, outer `:326-327` → `check_fail`+`issues`+
  nonzero explicitly pinned (§7); paired (a)/(b) + enum/flag-entrypoint +
  irrelevant-dep + outer-crash acceptance (§8). It neither closes nor
  supersedes PR1.
- Next (separate, after design sign-off): implementation branch + §§6–8 tests
  + fresh rereview. Mutation authority stays **nonexistent** until that review
  explicitly grants it — this file does not pre-grant it.
