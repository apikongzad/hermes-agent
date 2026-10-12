# DESIGN-FIRST rev3: report-only sweep, zero writes (no runtime change)

> **Status: DESIGN ONLY — no runtime implementation in this commit.**
> Rev3 revises `f1e7b5c7` (rev2) after review returned **NO-GO for generic prose**.
> Rev2 described authorities and oracles without naming the exact functions,
> lines, flags, and verdict cells an implementer must change. Rev3 is the
> implementable contract: every mutation site, anchor step, fail-open line,
> and oracle cell is enumerated with `file:line` read at rev `f1e7b5c7`.
> Per order: **design only, on the design branch, commit docs only, no
> runtime code or host changes.**
>
> - **PR1 BLOCKED — DO NOT MERGE:** `apikongzad/hermes-agent#1`
>   (`hermes/hermes-repair-all` → `main`). OPEN and unmerged until a future
>   implementation lands and is re-reviewed. This commit does **not**
>   supersede, close, or fix PR1.
> - **Rereviewed commits:** `46ad80b1` (FAILED, HIGH TOCTOU), `8761fcfb`
>   (NO-GO R1–R7), `f1e7b5c7` (**NO-GO**, this revision's basis: generic
>   `--apply`-only framing, unspecified anchor origin, unspecified
>   entrypoints/hooks/slash, hammer-only tests with skip-on-no-tracer,
>   unnamed B/C lines, version-OR-launch oracle, empty matrix).
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

## 1. Why rev2 was NO-GO (each closed by the cited rev3 section, proved by diff+tests+review, never by prose)

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

## 2. Design A: exact mutation entrypoints and required rev3 wiring

All paths read at `f1e7b5c7`. The initial slice wires **every** row to
refusal/report-only. Leaving any row live fails review. There is **no**
`--apply`/`--force`/`--delete`/`--commit` flag in
`plugins/disk-cleanup/disk_cleanup.py` (596 lines) or
`plugins/disk-cleanup/__init__.py` (236 lines) — acceptance MUST exercise the
real rows below, never an invented flag.

| ID | Entrypoint (file:line) | Current mutation (must be removed/disabled in initial slice) | Rev3 wiring |
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

**A-ANCHOR-1 — origin.** The anchor fd originates ONLY from (a) an inherited
trusted fd passed by the caller, or (b) a `/` dirfd (`os.open("/", O_DIRECTORY
| O_NOFOLLOW | O_CLOEXEC)`) followed by walking **single validated basenames**.
No opening `$HERMES_HOME`, `disk-cleanup/`, `tracked.json`, or any candidate
by a multi-component pathname. No `open(path)`, `Path(path).open()`,
`Path.exists()/stat()/read_text()` on state paths.

**A-ANCHOR-2 — single-component walk.** Each descent step opens exactly one
validated basename with `openat(parent_fd, name, O_RDONLY | O_DIRECTORY |
O_NOFOLLOW | O_CLOEXEC)` (files: without `O_DIRECTORY` but still
`O_NOFOLLOW`), then `fstat(child)` (`S_ISDIR`/`S_ISREG` as appropriate) while
**holding the parent fd open**. Never release-then-reopen. `O_NOFOLLOW` on
every step; `ELOOP` → refuse (`A-REFUSE-1`).

**A-ANCHOR-3 — preferred `openat2`.** Where available, `openat2(anchor_fd,
path, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` (plus `RESOLVE_NO_XDEV` where
supported) may bind one validated relative chain in one kernel-checked step.
It does NOT relax A-ANCHOR-1/2: the `anchor_fd` is still the inherited-or-`/`
fd, each basename in `path` is still validated per A-JSON-1, and any symlink/
XDEV/escape → refuse.

**A-ANCHOR-4 — bans (each fails §9 if present on state paths outside
fixtures asserting absence).** `Path.resolve()` / `os.path.realpath()` /
`Path.exists()/is_symlink()-then-open()` splits (current `disk_cleanup.py:
39,53,72,107,194,197,203,207,308,325,343,369,371,383,570,580`); multi-component
`os.open(str(p))` / `open()` (current `88,109,136` pattern + `65,201,209`);
`Path("/tmp").resolve()` alias relaxation + `relative_to(hermes_home)` +
`parts[0].startswith("hermes-")` (current `32-56` `is_safe_path`); `mkdir(
parents=True)` unbound-chain creation (current `63,193,239`); pathname
`dir_fsync` (`77-92` reopen by name); `readlink`-driven repair; silent
Windows downgrade to pathname behavior (refuse fail-closed where
`O_DIRECTORY`/`O_NOFOLLOW`/`openat2` absent).

**A-REFUSE-1 — reject uncertain.** `ELOOP`, `st_dev`/`st_ino`/mode/ownership
surprise, non-directory, mount/XDEV escape, I/O error, or any error where safe
binding cannot be proven → fail-closed refuse before any read. Symlink at any
ingress component (preexisting or swapped in) → refuse. Never path-reopen,
never `Path.resolve()` retry, never `exists()` fallback.

**A-JSON-1 — `tracked.json` names are untrusted input.** Each `path` string in
the JSON array is validated: reject absolute (`os.path.isabs`), reject `..`
components, reject empty, reject NUL, then bind each via A-ANCHOR-2/3
(`openat2 RESOLVE_BENEATH|NO_SYMLINKS` or exact held-component path). No
candidate string is ever `open()`ed/`stat()`ed/`unlink()`ed by name. Schema
validation is classification input only (§4).

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

Normative: only `ready` activates. Every other verdict
(`blocked-missing-cmd`, `blocked-refused`, `blocked-error`,
`blocked-timeout`, `blocked-unconfigured`, `blocked-unknown`) blocks skill
load, plugin enable, cron dispatch, and dependent-service enablement,
uniformly across CLI/gateway/TUI/Desktop/cron. `TerminalPolicyRefusal`/
`TerminalPolicyUnavailable` is a denial signal → blocked, never allow/skip.
"Unconfigured"/"unknown" never activates. Per-view recheck (no latched ready).

| ID | Fail-open line (read at current HEAD) | Required fail-closed wiring |
|---|---|---|
| B-CRED-1 | `tools/skills_tool.py:439-444` `register_credential_files` wrapped in `try/except → debug` leaving `missing_cred_files=[]`, `setup_needed` unchanged | exception → `blocked-error` (setup_needed=True, `readiness_status=setup_needed`); activation blocked; surfaced in preflight `missing_credential_files` label |
| B-PM-1 | `tools/skills_tool.py:616-641` `pm.ensure(dep)` fail → `deps_note` string only, result still `success:True` + `AVAILABLE` | declared-`deps` failure → `blocked-error` (or `blocked-missing-cmd` when the dep provides a `required_commands` binary); content MUST NOT report `success:True`+`AVAILABLE` while deps failed |
| B-PLUGIN-1 | `tools/skills_tool_plugin.py:161-172` `except Exception → AVAILABLE/setup_needed:False/setup_skipped:False` | exception → `blocked-error` with the same vocabulary as local skills; shared `_skill_readiness` path, one verdict table |
| B-CRON-1 | `cron/scheduler_preflight.py:91-95` `_job_fallback_chain` probe `except → None` | probe error → `blocked-error` (never "no fallback chain, proceed") |
| B-CRON-2 | `cron/scheduler_preflight.py:120-121` non-`AuthError` `except → None` | non-auth resolve error → `blocked-error` (real path does not get to reinterpret it as runnable) |
| B-CRON-3 | `cron/scheduler_preflight.py:275-279` gateway-config load `except → None` (fail-open skip) | load failure → `blocked-error`; `local`/`origin`/`all`/bot-chat lanes stay exempt, known-platform lanes block |
| B-CRON-4 | `cron/scheduler_preflight.py:314-317` `skill_view` `except → continue` / `not success → continue` | unreadable/missing/unready skill → `blocked-error` via `_SKILL_MISSING_FIELDS` labels (296-300); fall-through to `_build_job_prompt` skip handling is removed for the blocking path |
| B-CRON-5 | `cron/scheduler_preflight.py:399-403` `_preflight_job_config` per-check `except → continue` | check raise → `blocked-error` naming the check (`provider_key`/`skills`/`delivery`) |
| B-CRON-6 | `cron/scheduler.py:1697-1725` `_preflight_or_block`, esp. `1719-1722` outer `except → _pf_reason=None` ("validator must never take down a runnable job") | validator error → `blocked-error`; job does not dispatch |
| B-PREFLIGHT-FLAG | `cron/scheduler_preflight.py:80-83` `_cron_preflight_enabled` (`cron.preflight:false` disables all) + `cron/scheduler.py:1712` gate | `cron.preflight:false` MUST NOT bypass readiness: it disables only the *early* pre-dispatch hint; dispatch-time `_skill_readiness` + provider-key + delivery gates still block. An implementation where `false` dispatches an unready skill/key/delivery fails review |
| B-VIEW-1 | `tools/skills_tool.py:613-641` view-time `pm.ensure` (read-only `skill_view` mutates host) | read-only view performs zero setup: no `pm.ensure`, no `pm.ensure_import`, no download; missing deps → `blocked-*` verdict + `deps_note` remedy, install only via explicit `hermes pm install` + reload. Same ban covers `skills_list` and plugin-serve paths |
| B-ACT-1 | deployment/activation seam (skill load, plugin enable, cron dispatch, dependent-service enable) | activation requires `readiness_status==available` + `setup_needed==False` on the current view; every other status blocks with no side effect (no scheduling, no service enable, no tool registration for that skill) |

**Acceptance IDs:** `B-CRED-1`, `B-PM-1`, `B-PLUGIN-1`, `B-CRON-1`…`B-CRON-6`,
`B-PREFLIGHT-FLAG`, `B-VIEW-1`, `B-ACT-1` — each driven through the real
entrypoint (`skill_view`/`_serve_plugin_skill`/`_preflight_check_skills`/
`_preflight_job_config`/`_preflight_or_block`) with real faults (PATH without
command, invalid `required_commands`, refusal scope, raising probe, timeout,
unconfigured store, unknown backend, `cron.preflight:false`), asserting blocked
verdicts + zero activation/scheduling/service-enable side effects. Helper-only
or patched-ready tests satisfy nothing.

---

## 7. Design C: `doctor --live` real per-backend oracle

Failure mode: version-string/bare-import/PATH-presence/other-backend success
producing PASS, unknown→skip, `--live` mutating host, static/live/fix conflated.

**C-ORACLE-1 — REMOVE every version-OR-launch disjunct.** No `pass` from a
version string, bare `import playwright`/`browser_harness`, `shutil.which`/
`_find_cli() is not None` (`tools/browser_use_cli.py:292-297`)/
`_find_agent_browser(validate=False)` (`tools/browser_tool_install.py:60-91`)/
`chromium_executable() is not None` (`hermes_cli/browser_runtime.py:10-16`)
PATH hit, or a probe of a *different* backend than configured. Current
disjuncts that MUST NOT confer PASS: `hermes_cli/doctor_live.py:55-61`
`_browser_use_ready`, `64-70` `_agent_browser_ready`, `82-95`
`_browser_available` (`or`), `98-126` `_harness_version_probe` standalone PASS,
`129-178` `_probe_configured_backend` version-subprocess PASS, `181-207`
`_launch_browser_probe` fallback-to-other-backend. A `--version` exec is at
most a bounded liveness pre-check; **PASS requires the launch oracle below
for the configured backend only.**

**C-ORACLE-2 — launch oracle (the only PASS path).** Launch the exact
binary/entrypoint the tool spawns for the *configured* backend, open
`about:blank`, evaluate a known-DOM assertion, close, reap. Bounded:
`1s ≤ timeout ≤ 15s` (clamp `doctor.live_probe_timeout`,
`hermes_cli/doctor_live.py:293-296`), output cap 80–4k chars, `capture_output`,
`check=False`, explicit `wait`/reap, `close()` in `finally` (no zombies, no
lingering browser/daemon, no `pm.ensure`). Playwright fallback path
(`hermes_cli/doctor_live.py:194-207`) survives ONLY as the unset-default
backend's own oracle when no configured-backend probe applies — never as a
pass for an explicitly-configured `browser-use`/agent-browser backend.

**C-BACKEND-1 — configured backend decisive; exception is broken.**
Read `browser.backend` via `get_browser_backend()`
(`tools/browser_use_cli.py:219-223`). `off` → `skip` (never enables
dependents). Unset `""` → probe in documented default order, PASS requires
that backend's own C-ORACLE-2. Explicit `browser-use` MUST NOT fall back to
agent-browser and vice versa. **Unknown string → `broken` (fail-closed),
never `skip`.** `_configured_backend_key()` `except → ""`
(`hermes_cli/doctor_live.py:73-79`) becomes `except → broken` (probe error,
fail). Configured-but-broken (binary missing, `--version` non-zero/timeout,
Chromium missing, harness missing, unexpected output) → `broken`, never
`unconfigured`.

**C-MATRIX-1 — actual 5×6 matrix (rows = `browser.backend`, cols = host
condition; cells = expected `pass|fail|skip`).** `skip` is reserved for
`off`/truly-unconfigured (absent config key, no backend selected, local-audio
provider) — never for configured-but-broken or missing-dep-for-configured.
`fail` = `broken` (errors fail-closed, never `warn`/`pass`/`skip`).

| backend \ condition | (a) backend binary missing | (b) `--version` non-zero | (c) `--version` timeout | (d) Chromium executable missing | (e) playwright missing (only) | (f) other-backend-only healthy |
|---|---|---|---|---|---|---|
| `off` | skip | skip | skip | skip | skip | skip |
| `browser-use` | fail | fail | fail | fail¹ | fail | fail |
| `agent-browser` | fail | fail | fail | fail | fail² | fail |
| unset (`""`) | skip³ | fail⁴ | fail⁴ | skip³ | skip³ | pass⁵ |
| unknown string | fail | fail | fail | fail | fail | fail |

¹ `browser-use` does not need local Chromium for its own oracle, but a
configured `browser-use` whose harness entrypoint is missing/broken is still
`fail` — the Chromium column for that row records the harness-Chromium
variant where applicable, never a pass via agent-browser's Chromium.
² agent-browser without Chromium is `fail` even if playwright imports.
³ unset with nothing runnable and no error beyond absence → `skip
(not configured)`; any attempted oracle that errors → `fail`, never silent
pass.
⁴ unset where the default-order oracle ran and errored → `fail` with
remediation (not `skip`).
⁵ unset passes ONLY when the default-order backend's own C-ORACLE-2 passes
for the backend actually launched; a pass from the non-launched backend is
`fail` per C-ORACLE-1.

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
(no `--live`) performs no live probes. `maybe_run_live_checks` crash →
`fail` (via `_run_one` catch-all `274-284`), never silent `skip`. Mock the
install seam to explode in tests; any call fails the test.

**C-FIX-1 — `doctor fix` is separate, human-approved, scoped.** Only
`hermes doctor --fix` (`should_fix`, e.g. `hermes_cli/doctor_tools.py:320-343`
`_check_agent_browser` `pm.ensure` iff `should_fix`, `397-410`
`_check_node_and_browser`) may mutate, and only what the user asked to fix.
`--live` MUST NOT imply `--fix`; `--fix` MUST NOT ride along with `--live`
unless explicitly passed. No anticipatory permission: documenting a fix does
not authorize a probe to fix.

**Acceptance IDs:** `C-ORACLE-1/2`, `C-BACKEND-1`, `C-MATRIX-1` (all 30 cells
asserted with real `browser.backend` values + real faults), `C-LIVE-1`,
`C-FIX-1` — asserting exact `pass|fail|skip` per cell, zero
`pm.ensure`/download/service-enable/file-write on any `--live` path, bounded
budgets + child reap, and static-vs-live-vs-fix distinction. Single-stub
"all backends pass" tests satisfy nothing.

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
  `/mnt/*`, `/tmp` non-`hermes-*`, project-tree, and absolute/`..` JSON-name
  candidates are all refused + reported, none written, even when JSON
  validates.
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
2. (A-ANCHOR-1…A-JSON-1) Ingress from inherited-or-`/` fd, single validated
   basenames each `O_NOFOLLOW`, `openat2 RESOLVE_BENEATH|NO_SYMLINKS` or exact
   held-component path; no multi-component open, no `realpath`/`resolve`, no
   `/tmp` alias relaxation; JSON names validated (no absolute, no `..`);
   uncertain/symlink/XDEV → refuse; no path reopen/retry.
3. (A-AUTH-1/2, A-NONE-1) Schema-valid/metadata never authorize; no unlink
   protocol/tables as policy; `touched == []` asserted per entrypoint.
4. (A-NOIMPLICIT-1/2) No `_log`, no git spawn (incl. no index writes) on slice
   paths; `log_stale` in-memory only.
5. (A-ZERO-1, A-BARRIER-1…6, A-TRACER-1, A-ESCAPE-1) Zero-write census per exact
   hook/slash even on failure; deterministic barriers per boundary; tracer
   absent → FAIL; read-only syscall profile incl. no-git-index-writes held.
6. (B-CRED-1, B-PM-1, B-PLUGIN-1, B-CRON-1…6, B-PREFLIGHT-FLAG, B-VIEW-1,
   B-ACT-1) No `except→AVAILABLE`/`continue`/`None` carve-out; `cron.preflight:
   false` cannot dispatch unready; view performs zero setup; activation only
   on `ready`; real-entrypoint tests, no patched-ready stubs.
7. (C-ORACLE-1/2, C-BACKEND-1, C-MATRIX-1, C-LIVE-1, C-FIX-1) No
   version/import/PATH/other-backend PASS; unknown→`broken`; `except→broken`;
   all 30 matrix cells asserted; `--live` entire static path non-downloading,
   no `ensure`; `fix` separate human-approved scope.
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
- Next (separate, after design sign-off): implementation branch + §§6–8 tests
  + fresh rereview. Mutation authority stays **nonexistent** until that review
  explicitly grants it — this file does not pre-grant it.
