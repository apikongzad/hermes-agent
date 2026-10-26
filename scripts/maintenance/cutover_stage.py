"""Isolated candidate staging via the PM-documented build entrypoint. Stdlib only.

DESIGN v2: root NEVER imports candidate pm. The build runs as `ubuntu` with
explicit cwd=candidate_src, absolute /usr/bin/python3, isolated
HOME/HERMES_HOME/HERMES_RUNTIME_DIR, env -i, no PYTHONPATH. Re-exec probe
invokes REAL Hermes launch preparation (hermes_bootstrap + version identity),
not `python -c sys.executable`. The build carries the LIVE selection extras
(from baseline facts, secret-free) — core-only would drop messaging/telegram
— and the dashboard --skip-build requires a prebuilt source-ignored web dist.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from scripts.maintenance.cutover_git import run_owner_git
from scripts.maintenance.cutover_journal import append
from scripts.maintenance.cutover_types import (
    Baseline,
    CutoverConfig,
    Host,
    Staged,
    generation_dir_for,
    parse_pyvenv_cfg,
    venv_dir_for,
    venv_python_for,
)


class StageError(RuntimeError):
    pass


def probe_home_for(config: CutoverConfig) -> Path:
    """Isolated probe home: never the default production profile."""
    return (Path(config.generation_root).absolute()
            / f"probe-home-{config.candidate_sha[:12]}")


def _isolated_env(config: CutoverConfig) -> dict[str, str]:
    probe_home = str(probe_home_for(config))
    # Production toolchain is read-only via _unstamped_store borrowing;
    # the probe home itself is empty/isolated so the default profile
    # (/home/ubuntu/.hermes) is never HERMES_HOME here and never mutated.
    return {
        "HOME": probe_home,
        "HERMES_HOME": probe_home,
        "HERMES_RUNTIME_DIR": "/home/ubuntu/.hermes/tools",
        "PATH": "/usr/bin:/bin",
    }


def selected_extras_from_facts(facts_bytes: bytes) -> tuple[list[str], bool]:
    """Parse the LIVE selection extras (secret-free) from baseline facts.

    Returns (extras_without_all, use_all_extras). Empty means core-only
    (legacy test seeds); production carries web/telegram/etc. Raises
    StageError on malformed facts (fail-closed, pre-mutation).
    """
    import json as _json
    import re as _re

    try:
        payload = _json.loads(facts_bytes.decode("utf-8", "replace"))
    except ValueError as exc:
        raise StageError(f"selection facts are not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise StageError("selection facts are not an object")
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise StageError("selection facts have no packages")
    venv_fact = packages.get("venv")
    if not isinstance(venv_fact, dict):
        raise StageError("selection facts have no venv selection")
    raw_extras = venv_fact.get("extras", [])
    if not isinstance(raw_extras, list):
        raise StageError("selection facts venv.extras is not a list")
    cleaned: list[str] = []
    for item in raw_extras:
        if not isinstance(item, str) or not item.strip():
            raise StageError("selection facts contain a non-string extra")
        name = item.strip()
        if not _re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
            raise StageError(f"selection facts contain an invalid extra {name!r}")
        cleaned.append(name)
    # Dedupe, sorted for deterministic argv + journal.
    cleaned = sorted(set(cleaned))
    use_all = "all" in cleaned
    extras = [e for e in cleaned if e != "all"]
    return extras, use_all


def stage_argv(
    config: CutoverConfig,
    extras: list[str] | None = None,
    all_extras: bool = False,
) -> list[str]:
    """Documented PM build; the Host adds cwd/env isolation at spawn.

    extras/all_extras mirror the LIVE selection (baseline facts): core-only
    (None/[]) drops messaging/telegram and breaks the cutover fleet.
    """
    out = venv_dir_for(config)
    argv = [
        "/usr/bin/python3",
        "-m",
        "pm.build_env",
        "--source",
        str(Path(config.candidate_src).absolute()),
        "--out",
        str(out.absolute()),
    ]
    if all_extras:
        # uv sync rejects `--all-extras` with `--extra` (exit 2). `--all-extras`
        # alone is the semantic superset of the live selection (`all` + named
        # extras), so drop the individual extras when `all` is set.
        argv.append("--all-extras")
    else:
        for extra in sorted(set(extras or [])):
            argv += ["--extra", extra]
    return argv


# Trusted absolute spawn helpers (verified on this host):
# /usr/sbin/runuser exists, /usr/bin/runuser does not; isolated staging env
# carries PATH=/usr/bin:/bin so a bare `runuser` fails with ENOENT before any
# live effect. Absolute paths keep the root spawn working under env -i.
_RUNUSER = "/usr/sbin/runuser"
_ENV = "/usr/bin/env"


def _wrap_for_user(argv: list[str], env: dict[str, str]) -> list[str]:
    """Wrap for root-owned spawn: run as ubuntu with env -i when root.

    Non-root callers (tests, ubuntu dev) run the argv directly with the
    isolated env; root inserts `/usr/sbin/runuser -u ubuntu -- /usr/bin/env
    -i …` so the candidate build never runs as root and never inherits
    root's env. Absolute paths are load-bearing: the isolated env sets
    PATH=/usr/bin:/bin (no /usr/sbin), so bare `runuser` would raise
    FileNotFoundError before any live effect.
    """
    # hasattr(os, "geteuid") guard — Windows has no geteuid and runs unprivileged here.
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    env_args = [_ENV, "-i"] + [f"{k}={v}" for k, v in sorted(env.items())]
    if is_root:
        return [_RUNUSER, "-u", "ubuntu", "--", *env_args, *argv]
    return [*env_args, *argv]


def _forbidden_staging_argv(argv: list[str]) -> bool:
    text = " ".join(argv)
    return any(
        token in text
        for token in (
            "pm.py",
            "scripts/sync_venv.py",
            "scripts/publish_launcher.py",
        )
    )


def stage(host: Host, config: CutoverConfig, baseline: Baseline | None = None) -> Staged:
    extras: list[str] = []
    use_all = False
    if baseline is not None and baseline.facts_bytes:
        extras, use_all = selected_extras_from_facts(baseline.facts_bytes)
    elif baseline is not None and str(getattr(baseline, "prior_generation", "")) not in ("", "."):
        # Second-cutover migration: facts_bytes is empty by design (old
        # worktree key was never installed). Extras come from the verified
        # prior receipt's stage-ok; never invent blank facts.
        extras = sorted(set(str(x) for x in (baseline.prior_extras or ())))
        use_all = bool(baseline.prior_all_extras)
        if not extras and not use_all:
            raise StageError("prior receipt carries no extras (refusing core-only migration)")
    argv = stage_argv(config, extras, use_all)
    if _forbidden_staging_argv(argv):
        raise StageError("staging uses a forbidden entrypoint")
    # The inner argv must stay the documented entrypoint; the wrapper only
    # adds isolation (runuser/env -i) at spawn time.
    if "pm.build_env" not in " ".join(argv):
        raise StageError("staging must invoke pm.build_env")
    generation = generation_dir_for(config)
    venv_dir = venv_dir_for(config)
    venv_python = venv_python_for(config)
    env = _isolated_env(config)

    wrapped = _wrap_for_user(argv, env)
    try:
        res = host.run(
            wrapped, timeout=1800,
            cwd=Path(config.candidate_src).absolute(), env=env,
        )
    except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        append(
            host,
            config.journal_path,
            "stage-failed",
            False,
            {"argv": argv[:6], "error": f"{type(exc).__name__}: {exc}"[-500:]},
        )
        raise StageError(f"PM staging transport failed: {exc}") from exc
    if res.returncode != 0:
        append(
            host,
            config.journal_path,
            "stage-failed",
            False,
            {"argv": argv[:6], "stderr_tail": (res.stderr or "")[-500:]},
        )
        raise StageError(f"PM staging failed: {(res.stderr or '').strip()[-300:]}")

    # Read staged pyvenv.cfg to bind the expected store interpreter (exact).
    try:
        cfg_bytes = host.read_bytes(venv_dir / "pyvenv.cfg")
    except OSError as exc:
        raise StageError(f"staged pyvenv.cfg unreadable: {exc}") from exc
    cfg = parse_pyvenv_cfg(cfg_bytes)
    home = cfg.get("home", "")
    exe = cfg.get("executable", "")
    if not home:
        raise StageError("staged pyvenv.cfg has no home (refusing to proceed)")
    append(
        host,
        config.journal_path,
        "stage-ok",
        True,
        {
            "generation": str(generation),
            "venv_python": str(venv_python),
            "home": home,
            "extras": extras,
            "all_extras": use_all,
        },
    )
    return Staged(
        generation_dir=generation,
        venv_dir=venv_dir,
        venv_python=venv_python,
        store_home=Path(home),
        store_exe=Path(exe) if exe else Path(home) / "python3",
    )


# Exact mirror of pm/extras.py ANCHORS (the PM anchor contract), plus three
# sourced additions for declared extras that ANCHORS does not name:
#   mcp -> ("mcp",)          # pyproject [mcp] names mcp==2.3.0; same dist as
#                            # [computer-use]'s anchor (already "mcp").
#   sms -> ("aiohttp",)       # pyproject [sms] is exactly ["aiohttp==..."].
#   uvloop -> ("uvloop",)     # pyproject [uvloop] names uvloop>=... .
# Sourced from the same schema:
#   keychain -> ("keyring",)  # pyproject [keychain] == ["keyring==..."];
#                            # pm/extras.py ANCHORS names "keyring", and
#                            # agent/vault_keychain.py imports keyring (opt-in
#                            # OS credential store; KeychainUnavailable when
#                            # the extra or an OS keychain is absent).
# Empty extras (cron/pty/nemo-relay == []) and meta bundles
# (all/termux/termux-all == hermes-agent[...] self-refs) carry NO anchor:
# they must never invent an import (no `sms`, no `cron`, no `pty`).
# Root stays stdlib-only: unknown extras raise StageError (fail-closed
# pre-mutation) instead of inventing `extra.replace("-", "_")`.
_EXTRA_ANCHORS: dict[str, tuple[str, ...]] = {
    "acp": ("acp",),
    "anthropic": ("anthropic",),
    "audio-io": ("sounddevice", "numpy"),
    "azure-identity": ("azure.identity",),
    "bedrock": ("boto3",),
    "computer-use": ("mcp",),
    "daytona": ("daytona",),
    "ddgs": ("ddgs",),
    "dingtalk": ("dingtalk_stream",),
    "discord": ("discord",),
    "doc-extract": ("anydoc",),
    "edge-tts": ("edge_tts",),
    "exa": ("exa_py",),
    "fal": ("fal_client",),
    "feishu": ("lark_oapi",),
    "firecrawl": ("firecrawl",),
    "google": (
        "googleapiclient",
        "google.auth",
        "google_auth_oauthlib.flow",
        "google_auth_httplib2",
    ),
    "google-chat": ("google.cloud.pubsub_v1",),
    "google-meet": ("playwright.sync_api", "websockets"),
    "keychain": ("keyring",),
    "kittentts": ("kittentts", "soundfile"),
    "matrix": ("mautrix", "asyncpg", "aiosqlite", "markdown", "aiohttp_socks"),
    "mcp": ("mcp",),
    "messaging": ("telegram",),
    "mistral": ("mistralai",),
    "modal": ("modal",),
    "neutts": ("neutts",),
    "otlp": ("opentelemetry.sdk",),
    "parallel-web": ("parallel",),
    "piper": ("piper",),
    "silk": ("pilk",),
    "slack": ("slack_bolt",),
    "sms": ("aiohttp",),
    "stt-whisper": ("faster_whisper",),
    "teams": ("microsoft_teams.apps",),
    "telegram": ("telegram",),
    "trace-upload": ("huggingface_hub",),
    "tts-premium": ("elevenlabs",),
    "uvloop": ("uvloop",),
    "vercel": ("vercel",),
    "vertex": ("google.auth",),
    "vision": ("PIL",),
    "voice": ("faster_whisper",),
    "wake": ("pyopen_wakeword",),
    "wake-openwakeword": ("pyopen_wakeword",),
    "wake-porcupine": ("pvporcupine",),
    "wake-sherpa": ("sherpa_onnx",),
    "web": ("fastapi",),
    "wecom": ("defusedxml",),
    "youtube": ("youtube_transcript_api",),
}

# Declared extras with no importable anchor (sourced from pyproject
# optional-dependencies): empty back-compat aliases (cron/pty/nemo-relay == [])
# and meta bundles (all/termux/termux-all == hermes-agent[...] self-refs).
_NO_ANCHOR_EXTRAS: frozenset[str] = frozenset(
    {"cron", "pty", "nemo-relay", "all", "termux", "termux-all"}
)


def _anchors_for_extra(extra: str) -> tuple[str, ...]:
    got = _EXTRA_ANCHORS.get(extra)
    if got is not None:
        return got
    if extra in _NO_ANCHOR_EXTRAS:
        return ()
    raise StageError(f"unknown extra {extra!r} (no anchor contract; refusing to invent)")


def extras_anchors_for(extras: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for extra in extras:
        for anchor in _anchors_for_extra(extra):
            seen[anchor] = None
    return sorted(seen)


def _extras_probe_code(anchors: list[str]) -> str:
    import json as _json

    return (
        "import importlib.util, json\n"
        f"_anchors={_json.dumps(anchors)}\n"
        "_result={}\n"
        "for _a in _anchors:\n"
        " try:\n"
        "  _result[_a]=importlib.util.find_spec(_a) is not None\n"
        " except (ImportError, ValueError):\n"
        "  _result[_a]=False\n"
        "print(json.dumps(_result))"
    )


def verify_candidate_web_dist(host: Host, config: CutoverConfig) -> None:
    """Require a prebuilt source-ignored web dist (dashboard --skip-build).

    Fail-closed pre-mutation: index.html + hermes-build.json (product web)
    must exist, be non-fake, and be git-ignored (source product, never
    committed). Built fresh via npm scripts (scripts/build/web.mjs), not
    hand-crafted.
    """
    candidate = Path(config.candidate_src).absolute()
    dist = candidate / "hermes_cli" / "web_dist"
    index = dist / "index.html"
    receipt = dist / "hermes-build.json"
    try:
        index_bytes = host.read_bytes(index)
    except OSError as exc:
        raise StageError(f"candidate web dist missing index.html: {exc}") from exc
    if len(index_bytes) < 100:
        raise StageError("candidate web dist index.html too small (fake artifact?)")
    text = index_bytes.decode("utf-8", "replace")
    if "<" not in text or "fake" in text.lower() and len(text) < 500:
        raise StageError("candidate web dist index.html looks fake (refusing)")
    try:
        receipt_bytes = host.read_bytes(receipt)
    except OSError as exc:
        raise StageError(f"candidate web dist missing hermes-build.json: {exc}") from exc
    try:
        import json as _json

        payload = _json.loads(receipt_bytes.decode("utf-8", "replace"))
    except ValueError as exc:
        raise StageError(f"candidate web receipt is not JSON: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("product") != "web":
        raise StageError("candidate web receipt is not a web product (fake?)")
    if payload.get("schema") != 1:
        raise StageError("candidate web receipt schema mismatch (stale build?)")
    # Source must exist (npm build inputs), dist must be ignored (product).
    try:
        host.read_bytes(candidate / "web" / "package.json")
    except OSError as exc:
        raise StageError(f"candidate web source missing: {exc}") from exc
    ignored = run_owner_git(
        host,
        candidate,
        ["check-ignore", "-q", str(index)],
        timeout=30,
    )
    if ignored.returncode != 0:
        raise StageError("candidate web dist is not git-ignored (must be a built product)")
    append(
        host, config.journal_path, "web-dist-ok", True,
        {"dist": str(dist), "index_bytes": len(index_bytes)},
    )


def verify_staged_extras(
    host: Host, config: CutoverConfig, staged: Staged,
    extras: list[str], all_extras: bool,
) -> None:
    """Prove the staged venv carries the LIVE selection (telegram/web/etc).

    find_spec only (no import side effects, no network), isolated home,
    cwd=candidate. Empty selection (legacy tests) is a no-op; production
    always names extras. Pre-mutation failure (no rollback needed).
    """
    anchors = extras_anchors_for(extras)
    if all_extras:
        anchors = sorted(set(anchors) | {"fastapi"})
    if not anchors:
        return
    code = _extras_probe_code(anchors)
    env = _isolated_env(config)
    if env.get("HERMES_HOME") == str(config.hermes_home):
        raise StageError("extras probe HERMES_HOME must be isolated")
    argv = [str(staged.venv_python), "-I", "-B", "-c", code]
    wrapped = _wrap_for_user(argv, env)
    try:
        res = host.run(
            wrapped, timeout=60,
            cwd=Path(config.candidate_src).absolute(), env=env,
        )
    except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        raise StageError(f"staged extras probe transport failed: {exc}") from exc
    if res.returncode != 0:
        raise StageError(f"staged extras probe failed: {(res.stderr or '')[-500:]}")
    try:
        import json as _json

        payload = _json.loads((res.stdout or "").strip().splitlines()[-1])
    except Exception as exc:
        raise StageError(f"staged extras probe unparseable: {exc}") from exc
    missing = [a for a in anchors if not payload.get(a)]
    if missing:
        raise StageError(f"staged venv missing extras anchors {missing} (built core-only?)")
    append(
        host, config.journal_path, "extras-ok", True,
        {"extras": sorted(set(extras)), "all_extras": all_extras, "anchors": anchors},
    )


def verify_candidate_help(host: Host, config: CutoverConfig, staged: Staged) -> None:
    """Prove the staged venv boots the REAL candidate CLI (--help, isolated).

    Catches missing platform deps / native plugins that prepare_launch alone
    misses. No live outbound (--help only), isolated home, cwd=candidate.
    """
    env = _isolated_env(config)
    if env.get("HERMES_HOME") == str(config.hermes_home):
        raise StageError("help probe HERMES_HOME must be isolated")
    argv = [
        str(staged.venv_python), "-I", "-B",
        f"{Path(config.candidate_src).absolute()}/hermes_cli/main.py", "--help",
    ]
    wrapped = _wrap_for_user(argv, env)
    try:
        res = host.run(
            wrapped, timeout=60,
            cwd=Path(config.candidate_src).absolute(), env=env,
        )
    except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        raise StageError(f"candidate --help transport failed: {exc}") from exc
    if res.returncode != 0:
        raise StageError(f"candidate --help failed: {(res.stderr or '')[-500:]}")
    append(
        host, config.journal_path, "help-ok", True,
        {"venv_python": str(staged.venv_python)},
    )


def _launch_probe_code(candidate: str) -> str:
    return (
        "import sys, json\n"
        "_before={'exe': sys.executable, 'prefix': sys.prefix}\n"
        "sys.path.insert(0, '" + candidate + "')\n"
        "import hermes_bootstrap\n"
        "from hermes_cli.venv_sync import prepare_launch\n"
        "from hermes_cli.version_info import get_code_identity\n"
        "from pathlib import Path\n"
        "_root=Path('" + candidate + "')\n"
        "_relaunch=None\n"
        "_relaunch_error=None\n"
        "try:\n"
        " _relaunch=prepare_launch(_root, ['gateway', 'run'])\n"
        "except Exception as _exc:\n"
        " _relaunch_error=type(_exc).__name__ + ':' + str(_exc)[:300]\n"
        "_after={'exe': sys.executable, 'prefix': sys.prefix}\n"
        "_identity=get_code_identity()\n"
        "print(json.dumps({'sha': _identity.get('sha'), "
        "'short_sha': _identity.get('short_sha'), "
        "'version': _identity.get('version'), "
        "'source': _identity.get('source'), "
        "'before': _before, 'after': _after, "
        "'relaunch': str(_relaunch), "
        "'relaunch_error': _relaunch_error}))"
    )


def verify_isolated_launch(
    host: Host, config: CutoverConfig, staged: Staged, live_exe: str
) -> None:
    """Prove the staged venv boots REAL Hermes prep, not just sys.executable.

    Runs as ubuntu, isolated HOME/HERMES_HOME (never the default production
    profile), cwd=candidate:
      <staged>/bin/python -I -B -c "<probe>"
    The probe records sys.executable/sys.prefix BEFORE, imports
    hermes_bootstrap, calls hermes_cli.venv_sync.prepare_launch, records
    AFTER, then get_code_identity (sha/short_sha/version/source). The
    verifier requires sha==candidate, before==staged python,
    after==before (no mid-probe re-exec), and the prepare_launch call.
    """
    candidate = str(Path(config.candidate_src).absolute())
    if "'" in candidate:
        raise StageError("candidate path is not quotable (refusing to proceed)")
    code = _launch_probe_code(candidate)
    env = _isolated_env(config)
    if env.get("HERMES_HOME") == str(config.hermes_home):
        raise StageError("probe HERMES_HOME must be isolated (never production)")
    argv = [str(staged.venv_python), "-I", "-B", "-c", code]
    wrapped = _wrap_for_user(argv, env)
    try:
        res = host.run(
            wrapped, timeout=120,
            cwd=Path(config.candidate_src).absolute(), env=env,
        )
    except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        raise StageError(f"staged launch-prep probe transport failed: {exc}") from exc
    if res.returncode != 0:
        raise StageError(f"staged launch-prep probe failed: {(res.stderr or '')[-500:]}")
    try:
        import json as _json

        payload = _json.loads((res.stdout or "").strip().splitlines()[-1])
        reported_sha = str(payload.get("sha") or "")
        before = payload.get("before") or {}
        after = payload.get("after") or {}
    except Exception as exc:
        raise StageError(f"staged probe identity unparseable: {exc}") from exc
    if reported_sha != config.candidate_sha:
        raise StageError(
            f"staged probe sha {reported_sha[:12]} != candidate {config.candidate_sha[:12]}"
        )
    if "prepare_launch" not in code or "hermes_bootstrap" not in code:
        raise StageError("staged probe must exercise real Hermes launch prep")
    before_exe = str(before.get("exe") or "")
    after_exe = str(after.get("exe") or "")
    if not before_exe or not after_exe:
        raise StageError("staged probe must record sys.executable before/after")
    if not before.get("prefix") or not after.get("prefix"):
        raise StageError("staged probe must record sys.prefix before/after")
    try:
        same_interp = (
            Path(before_exe).resolve() == Path(staged.venv_python).resolve()
            or before_exe.strip() == str(staged.venv_python).strip()
        )
    except OSError:
        same_interp = before_exe.strip() == str(staged.venv_python).strip()
    if not same_interp:
        raise StageError("staged probe did not run in the staged interpreter")
    if after_exe != before_exe or (after.get("prefix") or "") != (before.get("prefix") or ""):
        raise StageError("staged probe re-execed mid-probe (before != after)")
    if payload.get("relaunch_error"):
        raise StageError(f"prepare_launch failed in probe: {payload.get('relaunch_error')}")
    if str(staged.generation_dir) not in str(staged.venv_python):
        raise StageError("staged python is not inside the generation dir")
    if live_exe and live_exe.strip() == str(staged.venv_python).strip():
        raise StageError("staged probe re-executes the live old generation interpreter")
    if hasattr(os, "geteuid"):
        euid = os.geteuid()  # hasattr(os, "geteuid") guard — Windows falls to unknown below
        user = "root" if euid == 0 else "ubuntu"
    else:
        user = "unknown"
    append(
        host,
        config.journal_path,
        "launch-verify-ok",
        True,
        {
            "sha": reported_sha,
            "venv_python": str(staged.venv_python),
            "user": user,
            "hermes_home": env.get("HERMES_HOME", ""),
            "before": before,
            "after": after,
            "relaunch": str(payload.get("relaunch") or ""),
        },
    )
