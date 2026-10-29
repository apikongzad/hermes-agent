"""Cron pre-run preflight: transient provider-resolution error classification, provider-key /
delivery-target / skills checks, and the shared-route adapter view used by satellite profiles.

Split out of ``cron.scheduler``. Import names from this module directly (``cron.scheduler`` only
imports the few it calls itself). Origin-resident helpers and sibling split modules are reached
late-bound (``_sched`` / module refs at the bottom) so monkeypatching the defining module works.
"""

from __future__ import annotations

import errno
import json
import logging
import os
from typing import Optional

from cron.env_settings import cron_env_setting

# Log-record parity with the origin module.
logger = logging.getLogger("cron.scheduler")

# Error-string prefixes from ``run_job``; ``run_one_job`` keys off them for last_status and the
# alert-once dedup. ``:silent`` = already alerted on a previous tick — do not deliver again.
BLOCKED_CONFIG_MARKER = "[blocked_config]"
BLOCKED_CONFIG_SILENT_MARKER = "[blocked_config:silent]"

_TRANSIENT_NET_EXC_NAMES = frozenset({
    "ConnectError", "ConnectTimeout", "ReadTimeout", "WriteTimeout", "PoolTimeout", "NetworkError",
    "TimeoutException", "ClientConnectorError", "ClientConnectorDNSError", "ServerTimeoutError",
    "ClientOSError"})
_DNS_FAILURE_NEEDLES = ("nodename nor servname", "name or service not known")
_TRANSIENT_OSERROR_NEEDLES = _DNS_FAILURE_NEEDLES + (
    "temporary failure in name resolution", "network is unreachable")
_TRANSIENT_HTTP_NEEDLES = _TRANSIENT_OSERROR_NEEDLES + (
    "failed to resolve", "connection refused", "timed out", "timeout")
_TRANSIENT_ERRNOS = frozenset({
    errno.ECONNREFUSED, errno.ECONNRESET, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN,
    errno.ETIMEDOUT, errno.EAGAIN})


def _is_transient_provider_resolve_error(exc: BaseException) -> bool:
    """True when primary provider resolution failed for a transient network reason (DNS blip,
    ConnectError...). Must be eligible for ``fallback_providers`` like AuthError, else a healthy
    fallback rung is never tried and the job dies before the first model call."""
    import socket

    # gaierror carries EAI_* codes, plain OSError carries errno — never mix the namespaces (raw
    # literals like {8, 7, 11} are macOS-only and wrong on Linux).
    eai_transient = {
        getattr(socket, n) for n in ("EAI_NONAME", "EAI_AGAIN", "EAI_FAIL", "EAI_NODATA")
        if hasattr(socket, n)
    }
    # Walk the cause chain; the scheduler wraps raw transport errors.
    seen: set[int] = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        module = type(cur).__module__ or ""
        msg = str(cur).lower()
        if type(cur).__name__ in _TRANSIENT_NET_EXC_NAMES:
            return True
        if any(m in module for m in ("httpx", "httpcore", "aiohttp")) and any(
            needle in msg for needle in _TRANSIENT_HTTP_NEEDLES):
            return True
        if isinstance(cur, OSError):
            if isinstance(cur, socket.gaierror):
                if cur.errno in eai_transient:
                    return True
            elif getattr(cur, "errno", None) in _TRANSIENT_ERRNOS:
                return True
            if any(needle in msg for needle in _TRANSIENT_OSERROR_NEEDLES):
                return True
        # Bare exceptions that carry the raw DNS text (format_runtime_provider_error).
        if any(needle in msg for needle in _DNS_FAILURE_NEEDLES):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def _cron_preflight_enabled(cfg: dict) -> bool:
    """Preflight is ON unless ``cron.preflight`` is literally ``false``."""
    cron_cfg = (cfg or {}).get("cron")
    return not isinstance(cron_cfg, dict) or cron_cfg.get("preflight", True) is not False


def _validate_raw_fallback_config(job: dict, cfg: dict) -> Optional[str]:
    """Validate RAW fallback config BEFORE get_fallback_chain filters.

    get_fallback_chain/_iter_fallback_entries silently drop non-dict entries
    and entries missing provider/model — a malformed operator config would
    vanish to []/None and never block. This check inspects the RAW
    cfg["fallback_providers"]/cfg["fallback_model"] values first and BLOCKS
    on any malformed entry (non-list/dict container, non-dict entry, missing
    provider/model). Pinned jobs never inherit the global chain, so they skip
    this (their own pin is validated via the primary probe).
    """


def cron_default_provider(cfg: dict) -> str:
    """``cron.model_provider``: the provider every cron job without its own pin resolves through."""
    cron = cfg.get("cron") if isinstance(cfg, dict) else None
    return str(cron.get("model_provider") or "").strip() if isinstance(cron, dict) else ""
    try:
        pinned = bool(_sched._job_route_pinned(job))
    except Exception:
        pinned = False
    if pinned:
        return None
    if not isinstance(cfg, dict):
        return None
    for key in ("fallback_providers", "fallback_model"):
        try:
            raw = cfg.get(key)
        except Exception:
            continue
        if raw is None:
            continue
        if isinstance(raw, dict):
            candidates = [raw]
        elif isinstance(raw, list):
            candidates = raw
        else:
            return (
                f"provider fallback config '{key}' malformed "
                f"({type(raw).__name__}): config error (fail-closed). "
                f"Fix '{key}' to a list of {{provider, model}} entries."
            )
        for entry in candidates:
            if not isinstance(entry, dict):
                return (
                    f"provider fallback entry is not a dict ({entry!r}): "
                    "config error (fail-closed). Fix the job's fallback chain."
                )
            prov = str(entry.get("provider") or "").strip()
            mod = str(entry.get("model") or "").strip()
            if not prov or not mod:
                return (
                    f"provider fallback entry missing provider/model ({entry!r}): "
                    "config error (fail-closed). Fix the job's fallback chain."
                )
    return None


def _preflight_check_provider_key(job: dict, cfg: dict) -> Optional[str]:
    """READ-ONLY probe: would provider resolution fail for lack of a key?

    Rev6 disjoint fallback-chain policy (B-PREFLIGHT-FLAG, B-CRON-1/2):
    - :92-93 valid chain-present requires mandatory validation of
      fallback-provider readiness (allowed only if all mandatory pass),
      never blanket return None.
    - :94-95 probe exception/error -> blocked diagnostic per B-CRON-1
      regardless of cron.preflight flag.
    - Optional hint (rate-limited AuthError deferral) may skip; mandatory
      readiness never skips.
    """
    # RAW validation BEFORE get_fallback_chain filters (malformed would
    # otherwise vanish to []/None and never block).
    try:
        raw_reason = _validate_raw_fallback_config(job, cfg)
    except Exception as exc:
        return f"provider fallback chain probe failed: {exc} (fail-closed)"
    if raw_reason:
        return raw_reason
    try:
        chain = _sched._job_fallback_chain(job, cfg)
    except Exception as exc:
        # B-CRON-1 fail-closed: probe error -> blocked, never proceed
        return f"provider fallback chain probe failed: {exc} (fail-closed)"
    if chain:
        # :92-93 valid chain-present: validate fallback-provider readiness,
        # not blanket None. Allowed only if fallback creds resolve.
        from hermes_cli.auth import AuthError as _AE2
        try:
            from hermes_cli.runtime_provider import resolve_runtime_provider as _rr2
            for entry in chain:
                if not isinstance(entry, dict):
                    return (
                        f"provider fallback entry is not a dict ({entry!r}): "
                        "config error (fail-closed). Fix the job's fallback chain."
                    )
                try:
                    _rr2(requested=entry.get("provider"),
                         target_model=entry.get("model") or job.get("model") or "")
                except _AE2 as exc2:
                    from hermes_cli.auth import is_rate_limited_auth_error as _rl2
                    try:
                        if _rl2(exc2):
                            continue
                    except Exception:
                        pass
                    return (
                        f"provider fallback credential missing: {exc2} "
                        f"{_credential_store_scope_label()}. "
                    )
                except Exception as exc3:
                    return f"provider fallback probe failed: {exc3} (fail-closed)"
        except Exception as exc:
            return f"provider fallback validation failed: {exc} (fail-closed)"
        # Fallback ready: primary missing may still be rescued, but mandatory
        # guard at higher level still requires all 4 parts. Return None here
        # only after successful fallback validation (not blanket).
        return None

    requested = job.get("provider") or cron_default_provider(cfg) or None
    model = job.get("model") or cron_env_setting("HERMES_MODEL") or ""

    from hermes_cli.auth import AuthError, is_rate_limited_auth_error
    try:
        from hermes_cli.runtime_provider import resolve_runtime_provider
        kwargs = {"requested": requested, "target_model": model}
        if job.get("base_url"):
            kwargs["explicit_base_url"] = job.get("base_url")
        resolve_runtime_provider(**kwargs)
    except AuthError as exc:
        if is_rate_limited_auth_error(exc):
            # Optional costly non-security hint: quota/rate-limit is not a
            # missing credential; real path reports it. May skip even with
            # preflight:false (informational only).
            return None
        return (
            f"provider credential missing: {exc} {_credential_store_scope_label()}. "
            "Set the provider API key in .env (or `hermes setup`) for that home, or pin a "
            "working provider via `hermes cron edit "
            f"{job.get('id')} --provider <p>`."
        )
    except Exception as exc:
        # B-CRON-2 fail-closed: non-auth resolve error -> blocked
        return f"provider resolution failed: {exc} (fail-closed)"
    return None


def _credential_store_scope_label() -> str:
    """``[profile '<name>', HERMES_HOME <path>]`` for the home this preflight read credentials from.

    The verdict must name the store it judged: a scheduler process whose home differs from the
    shell where "the same credential works" (Docker HOME vs HERMES_HOME, a multiplexed satellite
    profile, a gateway launched without the shell's env) otherwise reports a bare "No credentials
    stored" that cannot be told apart from a real login gap (#116213).
    """
    from hermes_cli.profiles import get_active_profile_name
    from hermes_constants import get_hermes_home
    return f"[profile '{get_active_profile_name() or 'default'}', HERMES_HOME {get_hermes_home()}]"


def _primary_profile_routes_for_current_home() -> list:
    """Primary gateway ``profile_routes`` targeting the profile being served; ``[]`` if this IS the
    primary home. Satellite crons are ticked and delivered by the primary gateway (a satellite
    holding its own token is a ``duplicate_credential`` fatal). Reads the primary home's YAML
    layers (user file + managed-scope overlay, top-level or nested ``gateway.``) through the same
    loader ``load_gateway_config()`` uses, without bridging platform config into this process.
    Shared by preflight rescue and delivery-time resolution so they cannot drift.

    Under ``gateway.multiplex_profiles`` a satellite profile's cron jobs are ticked by the primary gateway's
    in-process ticker (#69377) and delivered through the primary gateway's live adapters — the satellite
    home never holds the platform credentials itself (giving it a token of its own is a
    ``duplicate_credential`` fatal).
    """
    try:
        from hermes_constants import get_default_hermes_root, get_hermes_home
        primary_home = get_default_hermes_root()
        current_home = _sched.Path(get_hermes_home())
        if (
            primary_home.expanduser().resolve(strict=False)
            == current_home.expanduser().resolve(strict=False)
        ):
            return []  # this IS the primary home — nothing to consult

        # Same layers the primary gateway's own loader reads: routes pinned in the managed scope
        # (/etc/hermes/config.yaml) never reached the raw user-file read (#121212), so preflight
        # false-blocked and routed delivery failed closed on centrally-managed installs.
        from gateway.config_loader import read_yaml_layers
        layered = read_yaml_layers(primary_home.expanduser())
        routes_raw = layered.get("profile_routes")
        if routes_raw is None and isinstance(layered.get("gateway"), dict):
            routes_raw = layered["gateway"].get("profile_routes")
        if not isinstance(routes_raw, list):
            return []

        from gateway.profile_routing import parse_profile_routes
        from hermes_cli.profiles import profile_matches_home
        return [
            route for route in parse_profile_routes(routes_raw)
            if route.enabled and profile_matches_home(route.profile)
        ]
    except Exception:
        logger.debug("primary-gateway profile-route lookup unavailable", exc_info=True)
        return []


def _delivery_platform_routed_from_primary_gateway(platform_name: str) -> bool:
    """True when the primary gateway routes this platform to the profile being served.

    scheduler is currently serving (preflight rescue, #97476).
    """
    platform_key = platform_name.lower()
    return any(
        str(route.platform).lower() == platform_key
        for route in _primary_profile_routes_for_current_home()
    )


class SharedRouteAdapters:
    """Read-only adapter map for a credentialless satellite profile. ``get(platform, target)``
    resolves the PRIMARY adapter iff the inbound route matcher (``ProfileRoute.matches``) accepts
    the target; anything else (unmatched target, disabled route, other profile, or target-less
    ``get(platform)``) is a miss — fail closed, never the default bot.

    See #101113.
    """

    def __init__(self, primary_adapters, routes) -> None:
        self._primary = dict(primary_adapters or {})
        self._routes = list(routes or [])

    def __bool__(self) -> bool:
        return bool(self._primary) and bool(self._routes)

    def get(self, platform, target=None, default=None):
        if not target:
            return default
        adapter = self._primary.get(platform)
        if adapter is None:
            return default
        platform_key = str(getattr(platform, "value", platform)).lower()
        chat_id = str(target.get("chat_id") or "") or None
        thread_id = target.get("thread_id")
        thread_id = str(thread_id) if thread_id else None
        # A cron target carries no inbound guild anchor, so a route's guild_id is matched against
        # itself — the target-exact discriminators (chat_id/thread_id) authorize the send. Without
        # this the documented ``guild_id + chat_id`` Discord route never authorized cron output.
        for route in self._routes:
            if str(route.platform).lower() != platform_key:
                continue
            if not (route.chat_id or route.thread_id):
                continue  # guild-only routes are not target-exact
            if route.matches(
                str(route.platform), guild_id=route.guild_id, chat_id=chat_id, thread_id=thread_id,
            ):
                return adapter
        return default


def has_credential_platform(adapters, owned=None) -> bool:
    """True when the profile has a bot of its own. Any local session (Desktop chat, CLI run, Kanban
    worker) adds a ``LOCAL`` adapter, which holds no platform credential: a profile with only that is
    still a credentialless satellite that may ride routed primary adapters. ``owned`` is the
    profile's ``_profile_bot_platforms`` entry: a bot that dropped leaves the live map while it
    disconnects and reconnects, and borrowing the primary meanwhile would send through the wrong bot."""
    return bool(owned) or any(
        getattr(platform, "value", platform) != "local" for platform in adapters or ())


def _preflight_check_delivery(job: dict) -> Optional[str]:
    """Check delivery targets. Rev6 B-CRON-3 fail-closed (B-READY-1 scope).

    ``local``/``origin``/``all``/bot-chat never checked (no config load).
    Unknown platform always blocks; known platform blocks when unconnected;
    gateway-config load failure with known platform in lane -> blocked
    (fail-closed), never fail-open skip.
    """
    deliver_value = _delivery._normalize_deliver_value(job.get("deliver", "local"))
    failure_deliver_value = _delivery._normalize_deliver_value(
        _delivery._delivery_lane_value(job, for_failure=True))
    lane_values = [deliver_value]
    if failure_deliver_value != deliver_value:
        lane_values.append(failure_deliver_value)
    platform_parts: list[str] = []
    for lane_value in lane_values:
        for part in lane_value.split(","):
            part = part.strip()
            if not part or part.lower() in {"local", "origin", "all"}:
                continue
            # bot-chat targets deliver via a local subprocess; failures land in last_delivery_error.
            if _delivery.parse_bot_chat_deliver_token(part) is not None:
                continue
            platform_parts.append(part.split(":", 1)[0].strip())
    if not platform_parts:
        return None

    connected: Optional[set] = None
    for platform_name in platform_parts:
        if not _delivery._is_known_delivery_platform(platform_name):
            return (
                f"delivery platform '{platform_name}' is not a known cron "
                "delivery target. Fix the job's `deliver` value or configure "
                "the platform's gateway credentials."
            )
        if connected is None:
            try:
                from gateway.config import load_gateway_config
                gateway_config = load_gateway_config()
                connected = {p.value for p in gateway_config.get_connected_platforms()}
                connected |= _delivery._relay_fronted_delivery_platforms(connected)
            except Exception as exc:
                logger.debug(
                    "preflight: gateway config unavailable — blocking "
                    "known-platform lane (fail-closed)", exc_info=True)
                # B-CRON-3: load failure with known platform -> blocked
                return (
                    f"delivery platform '{platform_name}' gateway config "
                    f"unavailable: {exc} (fail-closed). Configure it via "
                    "`hermes setup` or change the job's `deliver` target."
                )
        # Multiplex: a satellite served by the primary's adapters reads unconnected — no block.
        if (
            platform_name.lower() not in connected
            # Multiplex escape hatch: a satellite profile whose deliveries are routed by the primary
            # gateway's profile_routes is served by the primary's adapters, so its own unconnected reading
            # is a false block (#97476).
            and not _delivery_platform_routed_from_primary_gateway(platform_name)
        ):
            return (
                f"delivery platform '{platform_name}' has no gateway "
                "credentials configured (not connected). Configure it via "
                "`hermes setup` or change the job's `deliver` target."
            )
    return None


# ``skill_view`` payload keys naming missing prerequisites -> label for the preflight verdict.
_SKILL_MISSING_FIELDS = (
    ("missing_required_environment_variables", "env ${}"),
    ("missing_required_commands", "command '{}'"),
    ("missing_credential_files", "credential file {}"))


def _preflight_check_skills(job: dict) -> Optional[str]:
    """Rev6 B-CRON-4 + B-READY-1 fail-closed: every non-ready blocks.

    READY iff success True + available + setup_needed False + error absent.
    Every other combination (setup_needed, unsupported, success False,
    missing/unknown fields, view exception/unreadable) -> blocked diagnostic
    via _SKILL_MISSING_FIELDS labels. No fall-through to prompt skip for
    blocking path.
    """
    from cron.scheduler_prompt import _job_skill_names
    skill_names = _job_skill_names(job)
    if not skill_names:
        return None
    from tools.skills_tool import skill_view
    for skill_name in skill_names:
        try:
            payload = json.loads(skill_view(skill_name))
        except Exception as exc:
            return (
                f"attached skill '{skill_name}' is not ready: view failed "
                f"({exc}). Provide the missing prerequisites or detach the "
                "skill from this job."
            )
        if not isinstance(payload, dict):
            return (
                f"attached skill '{skill_name}' is not ready: unreadable payload. "
                "Provide the missing prerequisites or detach the skill from this job."
            )
        # B-READY-1: only available+success+setup_needed False+error absent is ready
        is_ready = (
            payload.get("success") is True
            and payload.get("readiness_status") == "available"
            and payload.get("setup_needed") is False
            and "error" not in payload
        )
        if is_ready:
            continue
        missing = [
            fmt.format(name)
            for key, fmt in _SKILL_MISSING_FIELDS
            for name in payload.get(key) or []
        ]
        detail = ", ".join(missing) or "required setup incomplete"
        # Include status for unsupported vs setup_needed distinction
        status = payload.get("readiness_status", "unknown")
        return (
            f"attached skill '{skill_name}' is not ready ({status}): missing "
            f"{detail}. Provide the missing prerequisites or detach the "
            "skill from this job."
        )
    return None


# (job id, server name) pairs already warned about as reconnecting; see _empty_requested_mcp_toolsets.
_RECONNECTING_WARNED: set = set()


def _empty_requested_mcp_toolsets(job: dict, cfg: dict) -> Optional[str]:
    """Reason when an MCP server the job's own ``enabled_toolsets`` names resolves to zero tools.

    Fail-closed full policy: ANY requested server resolving to zero tools
    BLOCKS, including reconnecting (never running without tools). Runs AFTER
    cron MCP discovery. Only servers the job explicitly asked for count.
    """
    requested = [str(name) for name in (job.get("enabled_toolsets") or [])]
    if not requested:
        return None
    from hermes_cli.tools_config import enabled_mcp_server_names
    from toolsets import resolve_toolset
    from tools.mcp_tool_discovery import mcp_server_reconnecting
    missing = [name for name in requested
               if name in enabled_mcp_server_names(cfg) and not resolve_toolset(name)]
    if not missing:
        return None
    # Reconnecting is still zero-tools for this dispatch: BLOCK (never run
    # without tools). Log once per outage for observability, but still block.
    reconnecting = sorted(name for name in missing if mcp_server_reconnecting(name))
    job_id = str(job.get("id", "?"))
    _RECONNECTING_WARNED.difference_update(
        key for key in list(_RECONNECTING_WARNED) if key[0] == job_id and key[1] not in reconnecting)
    unwarned = [name for name in reconnecting if (job_id, name) not in _RECONNECTING_WARNED]
    if unwarned:
        _RECONNECTING_WARNED.update((job_id, name) for name in unwarned)
        logger.warning(
            "Job '%s': MCP server(s) %s named in enabled_toolsets resolved to "
            "zero tools (reconnecting) — BLOCKED (fail-closed, never running "
            "without tools)", job_id, ", ".join(unwarned))
    # Full policy: reconnecting does NOT excuse; all missing block.
    return (
        f"MCP server(s) {', '.join(sorted(missing))} named in this job's enabled_toolsets "
        "resolved to zero tools for this profile (fail-closed, never running "
        "without tools — including reconnecting). The check re-runs on every "
        "dispatch and the job resumes once the server reconnects. "
        "If the name is wrong or belongs to another profile, fix the server or remove it from "
        "the job's toolsets.")


def _preflight_job_config(job: dict, cfg: dict) -> Optional[str]:
    """Pre-dispatch validation: fail-closed on raise (B-CRON-5).

    Each check raise -> blocked diagnostic naming the check, never skip.
    """
    for name, check in (
        ("provider_key", lambda: _preflight_check_provider_key(job, cfg)),
        ("skills", lambda: _preflight_check_skills(job)),
        ("delivery", lambda: _preflight_check_delivery(job))):
        try:
            reason = check()
        except Exception as exc:
            logger.debug("preflight check %s raised — failing closed", name, exc_info=True)
            return f"preflight check '{name}' failed: {exc} (fail-closed)"
        if reason:
            return reason
    return None


def _cron_mandatory_readiness_guard(job: dict, cfg: dict) -> Optional[str]:
    """NEW mandatory guard: EXACT list, ALWAYS run regardless of flag (B-PREFLIGHT-FLAG).

    MANDATORY PARTS — EXACT list, no vague wording, ALWAYS fail regardless of
    _cron_preflight_enabled, fail-closed on raise, full policy always fail:
    (1) skill readiness = _preflight_check_skills full B-READY-1 policy;
    (2) provider-key readiness = _preflight_check_provider_key AuthError
        missing-credential verdict -> blocked, PLUS B-CRON-1 fallback-probe
        error -> blocked and B-CRON-2 non-auth resolve error -> blocked;
    (3) delivery = _preflight_check_delivery unknown-platform verdict -> blocked
        AND known-platform loader-fail verdict -> blocked;
    (4) MCP = _empty_requested_mcp_toolsets full policy (ANY requested server
        resolving to zero tools -> blocked).
    cron.preflight:false disables ONLY optional costly non-security hints
    (rate-limited AuthError deferral, informational display after successful
    validation). It MUST NOT bypass mandatory readiness and MUST NOT skip
    probe-error blocks.
    """
    for name, check in (
        ("skills", lambda: _preflight_check_skills(job)),
        ("provider_key", lambda: _preflight_check_provider_key(job, cfg)),
        ("delivery", lambda: _preflight_check_delivery(job)),
        ("mcp", lambda: _empty_requested_mcp_toolsets(job, cfg)),
    ):
        try:
            reason = check()
        except Exception as exc:
            return f"mandatory readiness check '{name}' failed: {exc} (fail-closed)"
        if reason:
            return reason
    return None


# Late-bound origin namespace (see module docstring). Imported LAST so this module is fully
# populated before ``scheduler`` re-exports from it.
from cron import scheduler as _sched
from cron import scheduler_delivery as _delivery
