"""
ARES X v9 — Tool Router
Real LLM-driven tool calling: Gemini decides which ARES backend function
to invoke, and with what arguments, based on natural conversation —
not regex pattern matching.

Replaces the old approach (intent_mapper.py's regex-first dispatch) for
anything that isn't an exact keyword match. This is what makes ARES feel
like "an AI you talk to that happens to have red team tools", rather
than "a chatbot with keyword shortcuts": you don't need to know the
magic phrase, you just say what you want and the model figures out
which tool applies — the same mechanism used for tool use generally.

Uses Gemini's native function-calling API (tools / functionDeclarations)
so tool selection and argument extraction happen inside the model call
itself, not via fragile text parsing of the model's reply.
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import time
from dataclasses import asdict, is_dataclass
from typing import Any, Callable, Optional

logger = logging.getLogger("ares_tool_router")

# Once Gemini returns a 429 (quota exhausted), retrying it on every
# follow-up step of a multi-step turn is pure wasted latency — it will
# fail again, and that extra round-trip time makes it MORE likely the
# whole turn spills into the same Groq per-minute rate-limit window
# instead of less. This tracks "don't bother" for a short cooldown so a
# multi-step turn goes straight to Groq after the first 429, without
# needing a real token-bucket implementation (a free-tier daily quota
# doesn't reset on any schedule this process can predict anyway — this
# is purely about not re-trying inside the same turn/session, not a
# real rate limiter).
_GEMINI_COOLDOWN_SECONDS = 90
_gemini_quota_exhausted_until: float = 0.0


# ── Regex fallback dispatcher (merged from v9 intent_mapper.py) ────────
# Used when no Gemini API key is available (fully offline / Ollama-only).
# Tool-calling needs Gemini specifically; this fast regex path still works
# with any provider. (The regex path doesn't use history — it's not doing
# free-form LLM reasoning that benefits from context the way Gemini does.)

import re as _re
from typing import Any as _Any
from typing import Optional as _Optional


_PATTERNS: list[tuple] = [
    (_re.compile(r'\b(?:scan|recon(?:naissance)?\s*(?:scan)?)\s+(?:target\s+)?([a-z0-9][a-z0-9.\-]+)', _re.I), "recon"),
    (_re.compile(r'\bcve[\s\-]*(\d{4}[\s\-]*\d{4,6})\b', _re.I), "cve_lookup"),
    (_re.compile(r'\bcve\s+(?:search\s+(?:for\s+)?)?(.+)', _re.I), "cve_search"),
    # More-specific WHOIS pattern (a real domain with a TLD) must precede
    # the generic threat_actor whois pattern below, or "whois example.com"
    # gets swallowed as a threat-actor name lookup. Regex list is priority-
    # ordered (first-match-wins in _match_intent).
    (_re.compile(r'\bwhois\s+([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})', _re.I), "osint_domain_whois"),
    (_re.compile(r'\b(?:profile|threat\s+actor)\s+([a-zA-Z0-9 ]+)', _re.I), "threat_actor"),
    (_re.compile(r'\b(?:pivot|infra)\s+(?:from\s+)?([a-z0-9][a-z0-9.\-]+)', _re.I), "pivot"),
    (_re.compile(r'\b(?:github|secret)\s+(?:dork|scan)\s+(?:on\s+)?(?:org\s+)?([a-zA-Z0-9\-]+)', _re.I), "github_dork"),
    (_re.compile(r'\b(?:create|new)\s+mission\s+(?:with\s+goal|for|to)?\s*(.+)', _re.I), "create_mission"),
    (_re.compile(r'\b(?:list|show|my)\s+missions?\b', _re.I), "list_missions"),
    (_re.compile(r'\bopen\s+(?:auth\s+)?window\s+(?:for\s+)?(\d+(?:\.\d+)?)\s*h', _re.I), "open_window"),
    (_re.compile(r'\b(?:search|federated\s+search)\s+(?:for\s+)?(.+)', _re.I), "federated_search"),
    (_re.compile(r'\bstatus\b', _re.I), "status"),
    (_re.compile(r'\bwargame\b', _re.I), "wargame"),
    (_re.compile(r'\bextract\s+iocs?\s*[:\-]?\s*(.+)', _re.I), "extract_iocs"),
    # ── Phase 1c parity: OSINT ramps (Phase C tools) ─────────────
    # (osint_domain_whois's specific pattern lives at the top of _PATTERNS,
    # above the generic threat_actor whois catch-all — this comment is a
    # signpost so future readers understand the split ordering is intentional.)
    (_re.compile(r'\b(?:ip|geoip|ip\s+lookup)\s+(\d{1,3}(?:\.\d{1,3}){3})', _re.I), "osint_ip_lookup"),
    (_re.compile(r'\b(?:breach|pwned|hibp)\s+(?:check\s+)?(\S+@\S+\.\S+)', _re.I), "osint_email_breach_check"),
    (_re.compile(r'\b(?:username|handle|hunt)\s+(?:hunt\s+)?([a-zA-Z0-9_.\-]+)', _re.I), "osint_username_hunt"),
    (_re.compile(r'\bphone\s+(?:lookup\s+)?(\+?\d[\d\s\-]{6,})', _re.I), "osint_phone_lookup"),
    # ── Phase 1c parity: Graph command ramps (Phase C tools) ─────
    # Graph tools need twin_type + entity, which regex can't easily
    # capture — these patterns are best-effort; if nothing matches
    # here the request falls through to _llm_fallback which reaches
    # the same Gemini/Groq tool-selection anyway.
    (_re.compile(r'\b(?:influence|centrality|community|hidden\s+relationship|network\s+vulnerability|graph\s+analyze)\b.*\b(org|infra|supply_chain|threat_actor)\s+([a-zA-Z0-9_.\-]+)', _re.I), "graph_analyze_any"),
    # ── Phase 1c parity: Decision + Brief (Phase D tools) ────────
    (_re.compile(r'\b(?:decision|analyz[es]|recommend|what\s+should\s+i\s+do\s+about).{0,25}?\bmission\s+([a-zA-Z0-9_.\-]+)', _re.I), "run_decision_analysis"),
    (_re.compile(r'\b(?:brief|briefing|report|writeup)\s+(?:for\s+)?mission\s+([a-zA-Z0-9_.\-]+)', _re.I), "generate_brief"),
    (_re.compile(r'\b(?:generate|create|write)\s+(?:a\s+)?brief(?:ing)?\s+(?:for\s+)?([a-zA-Z0-9_.\-]+)', _re.I), "generate_brief"),
    (_re.compile(r'\b(?:give\s+me|show\s+me)\s+(?:a\s+)?brief(?:ing)?\s+(?:on|for)\s+([a-zA-Z0-9_.\-]+)', _re.I), "generate_brief"),
]


def _match_intent(message: str) -> _Optional[tuple[str, str]]:
    """Fast regex match. Returns (intent_name, captured_arg) or None."""
    for pattern, intent in _PATTERNS:
        m = pattern.search(message)
        if m:
            arg = m.group(1).strip().rstrip(".,!?") if m.groups() else ""
            return intent, arg
    return None


async def _summarize(raw_result: _Any, user_message: str, action_desc: str) -> str:
    """Format raw tool output into a readable chat reply."""
    if isinstance(raw_result, str):
        return raw_result
    try:
        import json as _json
        if isinstance(raw_result, (dict, list)):
            txt = _json.dumps(raw_result, indent=2, default=str)
        else:
            txt = str(raw_result)
    except Exception:
        txt = str(raw_result)
    return f"{action_desc} done. Result:\\n{txt}"


async def _handle_recon(target: str, message: str) -> str:
    from aresx.red import full_recon
    result = await full_recon(target)
    return await _summarize(result, message, f"full reconnaissance scan on {target}")


async def _handle_cve_lookup(cve_id: str, message: str) -> str:
    from aresx.red import lookup_cve
    full_id = f"CVE-{cve_id}" if not cve_id.upper().startswith("CVE") else cve_id
    result = await lookup_cve(full_id)
    if not result:
        return f"No CVE record found for {full_id} — it may not exist or NVD may be rate-limiting."
    return await _summarize(result, message, f"CVE lookup for {full_id}")


async def _handle_cve_search(product: str, message: str) -> str:
    from aresx.red import search_cves_by_product
    results = await search_cves_by_product(product)
    return await _summarize(results, message, f"CVE search for '{product}'")


async def _handle_threat_actor(name: str, message: str) -> str:
    from aresx.red import profile_actor
    result = await profile_actor(name)
    return await _summarize(result, message, f"threat actor profile for {name}")


async def _handle_pivot(target: str, message: str) -> str:
    from aresx.red import pivot_from_domain
    graph = await pivot_from_domain(target, max_depth=2)
    return await _summarize(graph, message, f"infrastructure pivot from {target}")


async def _handle_github_dork(org: str, message: str) -> str:
    from aresx.red import full_dork_scan
    result = await full_dork_scan(org)
    return await _summarize(result, message, f"GitHub secret-hunting scan on org '{org}'")


async def _handle_create_mission(goal: str, message: str) -> str:
    from aresx.mission import create_mission
    mission_id = create_mission(goal=goal)
    return f"Mission created — ID `{mission_id[:8]}`. Goal: {goal}"


async def _handle_list_missions(message: str) -> str:
    from aresx.mission import list_missions
    missions = list_missions()
    if not missions:
        return "No missions currently active."
    return await _summarize(missions, message, "list active missions")


async def _handle_open_window(hours_str: str, message: str) -> str:
    from aresx.red import get_shared_authorization
    hours = float(hours_str)
    auth = get_shared_authorization()
    window = auth.open_window(
        case_id=f"chat-session-{int(asyncio.get_event_loop().time())}",
        authorized_by="chat-operator",
        duration_hours=hours,
    )
    return f"Authorization window opened for {hours}h — case `{window.case_id[:8]}`."


async def _handle_federated_search(query: str, message: str) -> str:
    from aresx.domains.rag.federated_search import federated_search
    results = await federated_search(query)
    return await _summarize(results, message, f"federated search for '{query}'")


async def _handle_status(message: str) -> str:
    return "ARES is online and operational."


async def _handle_wargame(message: str) -> str:
    from aresx.mission import list_missions
    missions = list_missions()
    return f"War-game readiness check — {len(missions)} missions loaded."


async def _handle_osint_ip_lookup(ip: str, message: str) -> str:
    from aresx.chat.osint_ramps import _tool_osint_ip_lookup as _t
    return await _summarize(await _t({"ip": ip}), message, f"IP lookup for {ip}")


async def _handle_osint_email_breach_check(email: str, message: str) -> str:
    from aresx.chat.osint_ramps import _tool_osint_email_breach_check as _t
    return await _summarize(await _t({"email": email}), message, f"Breach check for {email}")


async def _handle_osint_username_hunt(username: str, message: str) -> str:
    from aresx.chat.osint_ramps import _tool_osint_username_hunt as _t
    return await _summarize(await _t({"username": username}), message, f"Username hunt for {username}")


async def _handle_osint_domain_whois(domain: str, message: str) -> str:
    from aresx.chat.osint_ramps import _tool_osint_domain_whois as _t
    return await _summarize(await _t({"domain": domain}), message, f"WHOIS lookup for {domain}")


async def _handle_osint_phone_lookup(phone: str, message: str) -> str:
    from aresx.chat.osint_ramps import _tool_osint_phone_lookup as _t
    return await _summarize(await _t({"phone": phone}), message, f"Phone lookup for {phone}")


async def _handle_graph_analyze_any(twin_type_and_entity: str, message: str) -> str:
    # regex captures "type name" as a single string; split into twin_type + entity.
    # If the message doesn't have enough info, we hand off to the LLM instead of
    # guessing — better a slightly-slower response than a wrong twin lookup.
    parts = twin_type_and_entity.split(None, 1)
    if len(parts) < 2:
        return await _llm_fallback(message)
    twin_type, entity = parts[0].strip(), parts[1].strip()
    # Pick influence as the default graph analysis — the user's specific
    # request is best answered by Gemini's tool-selection anyway; this is
    # only reached when both LLM providers are unavailable.
    from aresx.graph_command.graph_ramps import _tool_graph_analyze_influence as _t
    return await _summarize(await _t({"twin_type": twin_type, "entity": entity}),
                            message, f"Graph influence on {twin_type}/{entity}")


async def _handle_run_decision_analysis(mission_id: str, message: str) -> str:
    from aresx.chat.decision_ramps import _tool_run_decision_analysis as _t
    return await _summarize(await _t({"mission_id": mission_id}),
                            message, f"Decision analysis for mission {mission_id}")


async def _handle_generate_brief(mission_id: str, message: str) -> str:
    from aresx.chat.brief_ramps import _tool_generate_brief as _t
    return await _summarize(await _t({"mission_id": mission_id}),
                            message, f"Brief for mission {mission_id}")


async def _handle_extract_iocs(text: str, message: str) -> str:
    from aresx.red import extract_iocs
    result = await extract_iocs(text)
    return await _summarize(result, message, "IOC extraction")


async def _llm_fallback(message: str) -> str:
    from aresx.core.llm import ask_ai
    return await ask_ai(message)


_INTENT_HANDLERS = {
    "recon": _handle_recon,
    "cve_lookup": _handle_cve_lookup,
    "cve_search": _handle_cve_search,
    "threat_actor": _handle_threat_actor,
    "pivot": _handle_pivot,
    "github_dork": _handle_github_dork,
    "create_mission": _handle_create_mission,
    "list_missions": _handle_list_missions,
    "open_window": _handle_open_window,
    "federated_search": _handle_federated_search,
    "status": _handle_status,
    "wargame": _handle_wargame,
    "extract_iocs": _handle_extract_iocs,
    # ── Phase 1c parity (ADR-NATIONAL-HIGHWAY) ─────────────────────
    "osint_ip_lookup": _handle_osint_ip_lookup,
    "osint_email_breach_check": _handle_osint_email_breach_check,
    "osint_username_hunt": _handle_osint_username_hunt,
    "osint_domain_whois": _handle_osint_domain_whois,
    "osint_phone_lookup": _handle_osint_phone_lookup,
    "graph_analyze_any": _handle_graph_analyze_any,
    "run_decision_analysis": _handle_run_decision_analysis,
    "generate_brief": _handle_generate_brief,
}


async def _regex_route_message(message: str) -> str:
    """Legacy regex-based dispatcher (v9 intent_mapper). Used only when
    Gemini is unavailable; Gemini free-form routing is canonical."""
    match = _match_intent(message)
    if not match:
        return await _llm_fallback(message)
    intent, arg = match
    handler = _INTENT_HANDLERS.get(intent)
    if handler is None:
        return await _llm_fallback(message)
    try:
        return await handler(arg, message)
    except Exception as exc:
        return f"Intent '{intent}' failed: {exc}. Falling back to LLM answer: " + await _llm_fallback(message)

def _gemini_likely_exhausted() -> bool:
    return time.monotonic() < _gemini_quota_exhausted_until


def _mark_gemini_exhausted() -> None:
    global _gemini_quota_exhausted_until
    _gemini_quota_exhausted_until = time.monotonic() + _GEMINI_COOLDOWN_SECONDS


# Uses aresx.red.roe.get_shared_authorization() — the one, canonical
# process-wide AuthorizationManager instance. Do not construct a
# separate AuthorizationManager() here; a second instance has its own,
# disconnected authorization state (this exact mistake happened twice
# already — see get_shared_authorization's docstring in roe.py).
from aresx.red import get_shared_authorization
from aresx.red.roe import PendingApproval

# Maps AuthorizationManager request_id -> (tool_name, tool_args, original
# user message) for requests raised through THIS router. roe.py's
# PendingAuthRequest only knows the authorization-level details (action
# label, target) — it has no concept of "tool" or "args", since those
# are tool_router-specific. This side table is what lets a "yes" answer
# actually re-run the original tool call, instead of just marking the
# target approved for some future attempt. Cleared whenever the
# corresponding request is resolved (see route_message).
_pending_tool_calls: dict[str, tuple[str, dict, str]] = {}

# The message currently being processed by route_message(), available
# to nested handler calls without changing every TOOL_HANDLERS entry's
# signature (all 23 are called uniformly as handler(args) — adding a
# second parameter to support the 7 that need it would mean touching
# every handler, not just the gated ones). contextvars (not a plain
# module global) so this stays correct if multiple chat requests are
# ever in flight concurrently — each gets its own isolated value.
_current_message: contextvars.ContextVar[str] = contextvars.ContextVar("current_message", default="")


def has_active_auth_window() -> bool:
    """
    Whether an authorization window is currently open — used by
    network-facing tools (see RedOrchestrator.start_mission) that need
    a declared, time-boxed scope before running unattended against
    external targets. Desktop automation does not use this gate; it
    runs directly on request, the same as any other tool.
    """
    auth = get_shared_authorization()
    status = auth.status()
    return bool(status.get("active"))


def _target_dict(value: str) -> dict:
    """
    Build the {"domain": ...} or {"ip": ...} dict AuthorizationManager.
    authorize() expects, from a single string argument (most tool args
    are just "target" as a plain string, not already split into
    domain/ip the way orchestrator.start_mission's target dict wants).
    """
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return {"ip": value}
    except ValueError:
        return {"domain": value}


async def _require_authorization(action_label: str, target_str: str,
                                 tool_name: str, tool_args: dict,
                                 user_message: str) -> Optional[dict]:
    """
    Check authorization for a network-facing action before running it.
    Returns None if authorized (caller should proceed). Returns a dict
    with an "auth_pending" key if not — that dict IS the tool result;
    route_message's caller checks for this key and surfaces the
    question to the user instead of running the actual scan.

    Also registers (tool_name, tool_args, user_message) against the
    pending request's ID, so that once the user answers "yes" in a
    later message, route_message can actually re-run this exact tool
    call — not just mark the target approved for some future,
    never-automatically-happening attempt.
    """
    auth = get_shared_authorization()
    try:
        auth.authorize(action_label, _target_dict(target_str))
        return None
    except PendingApproval as pending:
        _pending_tool_calls[pending.request.request_id] = (tool_name, tool_args, user_message)
        return {
            "auth_pending": True,
            "request_id": pending.request.request_id,
            "prompt_text": pending.request.prompt_text,
        }


# ── Tool declarations ──────────────────────────────────────────────────────
# JSON Schema parameter definitions, matching Gemini's functionDeclarations
# format. Each tool's "handler" key is filled in below by _bind_handlers()
# once the actual aresx functions are imported (kept separate so this
# schema list stays readable on its own).

TOOL_SCHEMAS: list[dict] = [
    {
        "name": "recon_scan",
        "description": (
            "Run a pure-Python reconnaissance scan against a domain (no "
            "external tools required — works even without Kali tools "
            "installed): subdomain enumeration, port scanning, tech "
            "stack fingerprinting, WAF detection, S3 bucket exposure "
            "checks, JS endpoint extraction, and email harvesting. Use "
            "this for general recon requests, or when Kali-specific "
            "tools (nmap, nikto, etc.) aren't what the user asked for "
            "by name."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The domain to scan, e.g. 'example.com'",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "cve_lookup",
        "description": (
            "Look up a specific CVE by its ID to get severity, description, "
            "EPSS exploitability score, and whether it's in CISA's Known "
            "Exploited Vulnerabilities catalog. Use this when the user "
            "names a specific CVE ID."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE identifier, e.g. 'CVE-2024-3400'",
                },
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "cve_search",
        "description": (
            "Search for known vulnerabilities affecting a specific product "
            "or software, optionally a specific version. Use this when the "
            "user asks about vulnerabilities in a named piece of software "
            "rather than a specific CVE ID."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "product": {
                    "type": "string",
                    "description": "Product/software name, e.g. 'apache log4j'",
                },
                "version": {
                    "type": "string",
                    "description": "Specific version, if mentioned. Leave empty if not specified.",
                },
            },
            "required": ["product"],
        },
    },
    {
        "name": "threat_actor_profile",
        "description": (
            "Get a threat actor profile — attribution, known TTPs, "
            "targeting patterns, notable campaigns, and recent live "
            "intelligence pulses. Use this when the user wants to know "
            "about, track, or profile a named threat actor/APT group."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Actor name or alias, e.g. 'APT29' or 'Cozy Bear'",
                },
            },
            "required": ["name"],
        },
    },
    {
        "name": "infra_pivot",
        "description": (
            "Pivot from a known domain to discover related infrastructure — "
            "other domains sharing the same TLS certificates, associated "
            "IP addresses, and ASN ownership. Use this when the user wants "
            "to find infrastructure connected to a domain, or map out an "
            "adversary's broader footprint from one known indicator."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Seed domain to pivot from",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "github_secret_scan",
        "description": (
            "Search a GitHub organization's public repositories for "
            "accidentally exposed secrets — API keys, credentials, private "
            "keys, config files. Use this when the user wants to check an "
            "org for leaked secrets, exposed keys, or credential leaks on "
            "GitHub."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "org": {
                    "type": "string",
                    "description": "GitHub organization or username to search",
                },
            },
            "required": ["org"],
        },
    },
    {
        "name": "extract_iocs",
        "description": (
            "Extract indicators of compromise (IPs, domains, file hashes, "
            "CVEs, emails) from a block of raw text, such as a pasted "
            "threat report or log excerpt. Use this when the user pastes "
            "text and asks to pull out IOCs, indicators, or artifacts from it."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The raw text to extract indicators from",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "create_mission",
        "description": (
            "Create a new tracked investigation/mission in ARES with a "
            "stated goal. Use this when the user wants to start, open, or "
            "create a new investigation, case, or mission."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "goal": {
                    "type": "string",
                    "description": "The goal or objective of the mission",
                },
            },
            "required": ["goal"],
        },
    },
    {
        "name": "list_missions",
        "description": (
            "List all currently tracked missions/investigations in ARES. "
            "Use this when the user asks what's active, what missions "
            "exist, or wants a status overview of investigations."
        ),
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "open_auth_window",
        "description": (
            "Open a time-boxed authorization window that lets ARES run "
            "red-team operations (scans, recon, pivots) fully autonomously "
            "for a set duration without asking for approval on each "
            "individual target. Use this when the user wants to authorize "
            "an extended autonomous operation, e.g. 'let it run for the "
            "next few hours' or 'open a window for 4 hours'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "duration_hours": {
                    "type": "number",
                    "description": "How many hours the authorization should last",
                },
                "reason": {
                    "type": "string",
                    "description": "Brief reason/case name for the authorization, if given",
                },
            },
            "required": ["duration_hours"],
        },
    },
    {
        "name": "federated_search",
        "description": (
            "Search across ARES's connected intelligence sources "
            "simultaneously for a topic or query. Use this for general "
            "research questions about a topic, trend, or subject that "
            "isn't a specific tool request."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "What to search for"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "system_status",
        "description": (
            "Get ARES's current system status: active missions, evidence "
            "vault entries, boot state. Use this when the user asks how "
            "ARES is doing, what's the status, or wants a system health check."
        ),
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "run_wargame",
        "description": (
            "Run a red-vs-blue attack simulation to model likely attack "
            "paths and detection coverage. Use this when the user asks to "
            "simulate an attack, run a wargame, or test detection coverage. "
            "Pass twin_type + entity to wargame against a real digital "
            "twin's graph (recommended); with no twin specified, falls "
            "back to a small synthetic topology for illustrative runs."
        ),
        "parameters": {"type": "object", "properties": {
            "twin_type": {"type": "string", "description": "Optional. Twin type to wargame against: 'org' | 'infra' | 'supply_chain' | 'threat_actor'"},
            "entity": {"type": "string", "description": "Optional. Entity name the twin was built for (paired with twin_type)"},
        }, "required": []},
    },
    # ── Desktop automation — runs directly, no authorization window ──
    {
        "name": "computer_task",
        "description": (
            "Autonomously complete ANY desktop task using vision and action. "
            "Use this for EVERYTHING that involves controlling the desktop, opening apps, "
            "browsing websites, clicking things, typing, searching — any real-world computer task. "
            "Examples: 'open instagram', 'search iphones on amazon', 'open youtube and search lofi', "
            "'go to gmail', 'open twitter', 'launch burpsuite', 'open reddit and find posts about kali'. "
            "This tool sees the screen and figures out ALL steps automatically — "
            "the user never has to specify HOW, just WHAT they want done. "
            "Prefer this over individual automation tools for any goal-oriented task."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "goal": {
                    "type": "string",
                    "description": "What the user wants to accomplish, in plain English",
                },
            },
            "required": ["goal"],
        },
    },
    {
        "name": "take_screenshot",
        "description": (
            "Take a screenshot of the current screen. Use this when the "
            "user asks to capture, screenshot, or see what's currently "
            "on screen."
        ),
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "type_text",
        "description": (
            "Type text into whatever window currently has keyboard focus — "
            "e.g. filling in a field in Burp Suite, a terminal, or any "
            "open application. Use this when the user asks ARES to type "
            "or enter specific text somewhere on screen."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "The text to type"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "press_keys",
        "description": (
            "Press a keyboard shortcut/hotkey combination, e.g. 'ctrl+c', "
            "'alt+tab', 'ctrl+shift+t'. Use this when the user asks to "
            "press a specific key combo."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "combo": {
                    "type": "string",
                    "description": "Key combination, e.g. 'ctrl+c' or 'alt+tab'",
                },
            },
            "required": ["combo"],
        },
    },
    {
        "name": "click_screen",
        "description": (
            "Click at a screen coordinate, or at the current cursor "
            "position if no coordinates given. Use this when the user "
            "asks ARES to click somewhere specific on screen."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "x": {"type": "integer", "description": "X coordinate to click, if given"},
                "y": {"type": "integer", "description": "Y coordinate to click, if given"},
                "button": {
                    "type": "string",
                    "description": "'left', 'right', or 'middle'. Defaults to left.",
                },
            },
        },
    },
    {
        "name": "switch_window",
        "description": (
            "Switch to the next open window (alt+tab). Use this when the "
            "user asks to switch, alt-tab, or move to another window."
        ),
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "open_application",
        "description": (
            "Launch a desktop application by name. Supports opening browsers "
            "directly to a URL. Examples: open firefox, open chrome, open burpsuite, "
            "open firefox with url https://instagram.com, open chrome at google.com. "
            "Use the 'url' parameter whenever the user wants a browser to open a specific website."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The application command name, e.g. 'firefox', 'chrome', 'burpsuite'",
                },
                "url": {
                    "type": "string",
                    "description": "Optional URL to open in a browser, e.g. 'https://instagram.com'",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "navigate_browser",
        "description": (
            "Navigate an already-open browser to a URL, or open a browser at a URL. "
            "Use this when the user wants to visit a website, open a URL, go to a page, "
            "or browse to a specific address. More reliable than open_application for "
            "browser navigation as it focuses the address bar and types the URL directly."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to navigate to, e.g. 'https://instagram.com'",
                },
                "browser": {
                    "type": "string",
                    "description": "Browser to use: 'firefox' (default) or 'chrome'",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "run_sequence",
        "description": (
            "Execute a multi-step desktop automation sequence in order. Use this for "
            "complex tasks that require multiple actions: opening an app then navigating, "
            "typing in a field then pressing enter, clicking then typing, etc. "
            "Each step has a 'type' field. Supported types: "
            "'open_application' (command, url?), 'navigate_browser' (url, browser?), "
            "'wait' (seconds), 'press_keys' (combo), 'type_text' (text), "
            "'click' (x?, y?, button?), 'screenshot', 'scroll' (amount), "
            "'switch_window', 'move_mouse' (x, y). "
            "Example: open instagram in chrome = steps: open_application chrome, wait 3s, navigate_browser instagram.com."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "steps": {
                    "type": "array",
                    "description": "List of step objects to execute in order",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "description": "Step type"},
                            "command": {"type": "string"},
                            "url": {"type": "string"},
                            "browser": {"type": "string"},
                            "text": {"type": "string"},
                            "combo": {"type": "string"},
                            "seconds": {"type": "number"},
                            "x": {"type": "integer"},
                            "y": {"type": "integer"},
                            "button": {"type": "string"},
                            "amount": {"type": "integer"},
                            "continue_on_error": {"type": "boolean"},
                        },
                        "required": ["type"],
                    },
                },
            },
            "required": ["steps"],
        },
    },
    # ── Kali native tools — invokes actually-installed Kali binaries ──
    {
        "name": "kali_nmap_scan",
        "description": (
            "Run the real nmap tool against a target for detailed port/service/OS "
            "detection — more thorough than the pure-Python recon_scan port "
            "check. Use this specifically when the user names nmap by name, "
            "or asks for a deep/thorough port scan. scan_type: 'default' "
            "(top 1000 ports + version detection), 'quick' (fast, top ports "
            "only), 'full' (all 65535 ports, slow), 'udp' (top 100 UDP ports)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname to scan"},
                "scan_type": {
                    "type": "string",
                    "description": "'default', 'quick', 'full', or 'udp'. Defaults to 'default'.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "kali_nikto_scan",
        "description": (
            "Run nikto, a web server vulnerability scanner, against a "
            "target URL or host. Use this when the user names nikto by "
            "name, or asks for a web vulnerability/misconfiguration scan "
            "specifically (as opposed to general recon)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL or hostname to scan"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "kali_gobuster_scan",
        "description": (
            "Run gobuster to brute-force discover hidden directories on a "
            "web server, or subdomains via DNS brute-force. Use this when "
            "the user names gobuster by name, or asks to brute-force "
            "directories/paths on a target. mode: 'dir' for directory "
            "brute-forcing (target should be a full URL) or 'dns' for "
            "subdomain brute-forcing (target should be a bare domain)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL (dir mode) or domain (dns mode)"},
                "mode": {"type": "string", "description": "'dir' or 'dns'. Defaults to 'dir'."},
            },
            "required": ["target"],
        },
    },
    {
        "name": "kali_full_scan",
        "description": (
            "Run multiple Kali tools (nmap, nikto, httpx by default) "
            "against a target concurrently and combine the results into "
            "one report. Use this when the user asks for a thorough or "
            "'full' Kali-tools scan without naming a specific single tool."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, hostname, or URL to scan"},
            },
            "required": ["target"],
        },
    },
]


# ── Result formatting (shared with the old intent_mapper approach) ────────

def _to_plain(obj: Any) -> Any:
    """Recursively convert dataclasses/objects into JSON-safe plain dicts."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_plain(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_plain(v) for v in obj]
    if hasattr(obj, "__dict__") and not isinstance(obj, (str, int, float, bool, type(None))):
        try:
            return {k: _to_plain(v) for k, v in vars(obj).items() if not k.startswith("_")}
        except Exception:
            return str(obj)
    return obj


# ── Tool handlers — real ARES backend calls ────────────────────────────────
# Each takes the args dict Gemini extracted and returns plain-JSON-able data.
# No text formatting here — that happens once, after the call, so every
# tool's result goes through the same natural-language summarization step.

async def _tool_recon_scan(args: dict) -> Any:
    pending = await _require_authorization("recon scan", args["target"], "recon_scan", args, _current_message.get())
    if pending:
        return pending
    from aresx.red import full_recon
    return await full_recon(args["target"])


async def _tool_cve_lookup(args: dict) -> Any:
    from aresx.red import lookup_cve
    result = await lookup_cve(args["cve_id"])
    return result or {"error": f"No CVE record found for {args['cve_id']}"}


async def _tool_cve_search(args: dict) -> Any:
    from aresx.red import search_cves_by_product
    return await search_cves_by_product(args["product"], args.get("version", ""))


async def _tool_threat_actor_profile(args: dict) -> Any:
    from aresx.red import profile_actor
    return await profile_actor(args["name"])


async def _tool_infra_pivot(args: dict) -> Any:
    pending = await _require_authorization("infrastructure pivot", args["domain"], "infra_pivot", args, _current_message.get())
    if pending:
        return pending
    from aresx.red import pivot_from_domain
    return await pivot_from_domain(args["domain"], max_depth=2)


async def _tool_github_secret_scan(args: dict) -> Any:
    pending = await _require_authorization("GitHub secret scan", args["org"], "github_secret_scan", args, _current_message.get())
    if pending:
        return pending
    from aresx.red import full_dork_scan
    return await full_dork_scan(args["org"])


async def _tool_extract_iocs(args: dict) -> Any:
    from aresx.red import extract_iocs
    iocs = extract_iocs(args["text"])
    return {"total_iocs": len(iocs), "iocs": iocs}


async def _tool_create_mission(args: dict) -> Any:
    from aresx.mission import create_mission
    mission_id = create_mission(goal=args["goal"])
    return {"mission_id": mission_id, "goal": args["goal"], "status": "created"}


async def _tool_list_missions(args: dict) -> Any:
    from aresx.mission import list_missions
    return list_missions()


async def _tool_open_auth_window(args: dict) -> Any:
    auth = get_shared_authorization()
    window = auth.open_window(
        case_id=f"chat-session-{int(asyncio.get_event_loop().time())}",
        authorized_by="chat-operator",
        duration_hours=float(args["duration_hours"]),
        reason=args.get("reason", ""),
    )
    return {
        "case_id": window.case_id,
        "duration_hours": args["duration_hours"],
        "expires_at": window.expires_at.strftime("%Y-%m-%d %H:%M"),
    }


async def _tool_federated_search(args: dict) -> Any:
    from aresx.rag_federated import federated_search
    return await federated_search(args["query"])


async def _tool_system_status(args: dict) -> Any:
    from aresx.ui import mission_control_ui
    return mission_control_ui.full_snapshot()


async def _tool_run_wargame(args: dict) -> Any:
    """Run a red-vs-blue wargame simulation.

    Phase 1b of ADR-NATIONAL-HIGHWAY: prefer a real digital-twin graph
    when the caller passes twin_type + entity — falls back to the small
    synthetic 8-node topology only if NEITHER is specified, preserving
    backward compatibility with existing callers that didn't pass twin
    info. A partial/malformed twin request (one field given, the other
    missing or the wrong type) is treated as an error, not silently
    downgraded to the synthetic fallback — a caller who tried to specify
    a twin and got it wrong should be told that, not handed unrelated
    illustrative data with no indication their input was ignored.
    (Bug found by SENTINEL adversarial pass, /godmode: `run_wargame(
    {"twin_type": 123, "entity": None})` previously fell through to the
    synthetic graph silently, because `twin_type and entity` is False
    whenever EITHER is falsy — indistinguishable from "no twin requested
    at all" from the caller's side.)
    """
    from aresx.simulation import run_wargame

    twin_type = args.get("twin_type")
    entity = args.get("entity")

    # Normalize: empty/whitespace strings count as "not provided" for
    # the purposes of this check, same discipline as the mission_id
    # check in decision_ramps.py / brief_ramps.py.
    twin_type_given = isinstance(twin_type, str) and twin_type.strip()
    entity_given = isinstance(entity, str) and entity.strip()

    graph = None
    if twin_type_given and entity_given:
        # reuse graph_ramps' helper — single source of truth for
        # "give me the current graph_state of this twin"
        from aresx.graph_command.graph_ramps import latest_twin_graph_state
        graph = latest_twin_graph_state(twin_type, entity)
        if graph is None:
            return {
                "error": f"No twin found for twin_type={twin_type!r}, entity={entity!r}. "
                         f"Build the twin first (e.g. via a twin-builder tool), "
                         f"then re-run this wargame.",
            }
    elif twin_type_given or entity_given or twin_type is not None or entity is not None:
        # Something was supplied, but not a complete valid pair — this
        # is a caller error, not "no twin requested." Say so explicitly
        # instead of silently falling back to synthetic data.
        return {
            "error": f"Incomplete or invalid twin specification: "
                     f"twin_type={twin_type!r}, entity={entity!r}. "
                     f"Both must be non-empty strings to wargame against a real "
                     f"twin, or omit both to use the illustrative synthetic graph.",
        }

    if graph is None:
        # Explicit fallback path — synthetic topology, illustrative only.
        # Kept so callers that don't yet pass twin info don't break.
        graph = {"nodes": [{"id": f"n{i}"} for i in range(8)],
                 "edges": [{"from": f"n{i}", "to": f"n{(i+1)%8}"} for i in range(8)]}

    return run_wargame(graph, n_red=3, n_blue=2)


# ── Desktop automation handlers ─────────────────────────────────────────
# Run immediately when Gemini selects them, same as every other tool —
# no authorization window required. (The auth-window system remains in
# place for network-facing red team tools like recon_scan, which is a
# different action category: those touch external targets and benefit
# from a declared, time-boxed scope; desktop automation acts on the
# user's own machine on direct request, which doesn't need the same gate.)


async def _tool_take_screenshot(args: dict) -> Any:
    from aresx.desktop_automation import screenshot
    result = screenshot()
    return {"ok": result.ok, "detail": result.detail}


async def _tool_type_text(args: dict) -> Any:
    from aresx.desktop_automation import type_text
    result = type_text(args["text"])
    return {"ok": result.ok, "detail": result.detail}


async def _tool_press_keys(args: dict) -> Any:
    from aresx.desktop_automation import press_keys
    result = press_keys(args["combo"])
    return {"ok": result.ok, "detail": result.detail}


async def _tool_click_screen(args: dict) -> Any:
    from aresx.desktop_automation import click
    result = click(x=args.get("x"), y=args.get("y"), button=args.get("button", "left"))
    return {"ok": result.ok, "detail": result.detail}


async def _tool_switch_window(args: dict) -> Any:
    from aresx.desktop_automation import switch_window
    result = switch_window()
    return {"ok": result.ok, "detail": result.detail}


async def _tool_open_application(args: dict) -> Any:
    from aresx.desktop_automation import open_application
    result = open_application(args["command"], args.get("url"))
    return {"ok": result.ok, "detail": result.detail}


async def _tool_computer_task(args: dict) -> Any:
    from aresx.computer_agent import handle_computer_task
    return await handle_computer_task(args.get("goal", ""))


async def _tool_navigate_browser(args: dict) -> Any:
    from aresx.desktop_automation import navigate_browser
    result = navigate_browser(args["url"], args.get("browser", "firefox"))
    return {"ok": result.ok, "detail": result.detail, "steps": result.steps}


async def _tool_run_sequence(args: dict) -> Any:
    from aresx.desktop_automation import run_sequence
    result = run_sequence(args.get("steps", []))
    return {"ok": result.ok, "detail": result.detail, "steps": result.steps}


async def _tool_kali_nmap_scan(args: dict) -> Any:
    pending = await _require_authorization("nmap scan", args["target"], "kali_nmap_scan", args, _current_message.get())
    if pending:
        return pending
    from aresx.kali_tools import run_nmap
    result = await run_nmap(args["target"], scan_type=args.get("scan_type", "default"))
    return {"ok": result.ok, "output": result.raw_output[:6000]}


async def _tool_kali_nikto_scan(args: dict) -> Any:
    pending = await _require_authorization("nikto scan", args["target"], "kali_nikto_scan", args, _current_message.get())
    if pending:
        return pending
    from aresx.kali_tools import run_nikto
    result = await run_nikto(args["target"])
    return {"ok": result.ok, "output": result.raw_output[:6000]}


async def _tool_kali_gobuster_scan(args: dict) -> Any:
    pending = await _require_authorization("gobuster scan", args["target"], "kali_gobuster_scan", args, _current_message.get())
    if pending:
        return pending
    from aresx.kali_tools import run_gobuster
    result = await run_gobuster(args["target"], mode=args.get("mode", "dir"))
    return {"ok": result.ok, "output": result.raw_output[:6000]}


async def _tool_kali_full_scan(args: dict) -> Any:
    pending = await _require_authorization("full Kali tool scan", args["target"], "kali_full_scan", args, _current_message.get())
    if pending:
        return pending
    from aresx.kali_tools import full_kali_scan
    return await full_kali_scan(args["target"])


# ── Graph-command ramps (Phase C) ───────────────────────────────────────
# Async wrappers for aresx.graph_command analytics over digital-twin
# graph state (aresx.graph_command.graph_ramps). Lazy import: graph
# analytics can be selected only when a twin actually exists.
from aresx.graph_command.graph_ramps import (
    _tool_graph_analyze_influence,
    _tool_graph_find_communities,
    _tool_graph_find_hidden_relationships,
    _tool_graph_centrality,
    _tool_graph_network_vulnerability,
)

# ── OSINT ramps (Phase C) ──────────────────────────────────────────────
# aresx.modules.osint had zero inbound edges before this: all of its
# lookup tools (whois, breach checks, username hunting, …) existed but
# Gemini/Groq could never select them from chat. The _tool_osint_*
# wrappers below follow the same convention as every other ramp and
# return a result dict instead of the legacy module's speak/show
# fire-and-forget style.
from aresx.chat.osint_ramps import (
    _tool_osint_ip_lookup,
    _tool_osint_email_breach_check,
    _tool_osint_username_hunt,
    _tool_osint_domain_whois,
    _tool_osint_phone_lookup,
)

# ── Decision + Brief ramps (Phase D — ADR-NATIONAL-HIGHWAY) ────────────
# These close the DecisionPanel/BriefPanel dead-end from
# mission_control_ui.py — both real functions (decision.analyze,
# enterprise.generate_brief) exist and work, but had no chat-facing
# entry point that supplied the mission_id they require.
from aresx.chat.decision_ramps import _tool_run_decision_analysis
from aresx.chat.brief_ramps import _tool_generate_brief

# ── Gemini/LLM schemas for the Phase C on-ramps ──────────────────────
# Same functionDeclaration shape as every other entry in TOOL_SCHEMAS.
# Graph tools require a built digital twin first; OSINT tools work
# against public endpoints with no keys.
_TOOL_SCHEMAS_PHASE_C: list[dict] = [
    {
        "name": "osint_ip_lookup",
        "description": (
            "Geolocation and ISP lookup for an IP address or domain — "
            "city, region, country, ISP, ASN. Use when the user asks "
            "where an IP is, who owns it, or to look up any IP or domain."
        ),
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string", "description": "IP address or domain, e.g. '1.1.1.1'"},
        }, "required": ["ip"]},
    },
    {
        "name": "osint_email_breach_check",
        "description": (
            "Check whether an email address appears in known data "
            "breaches (haveibeenpwned-style enumeration). Use when the "
            "user asks if an email is compromised or leaked."
        ),
        "parameters": {"type": "object", "properties": {
            "email": {"type": "string", "description": "Email address, e.g. 'user@example.com'"},
        }, "required": ["email"]},
    },
    {
        "name": "osint_username_hunt",
        "description": (
            "Probe whether a username is claimed on popular platforms "
            "(GitHub, Twitter/X, Keybase). Use for OSINT on a username "
            "or to find someone's accounts across the web."
        ),
        "parameters": {"type": "object", "properties": {
            "username": {"type": "string", "description": "Username handle, e.g. 'johndoe'"},
        }, "required": ["username"]},
    },
    {
        "name": "osint_domain_whois",
        "description": (
            "Registration/whois lookup for a domain via RDAP — "
            "registration date, registrar, expiry, and status. Use when "
            "the user asks who registered a domain or when it was "
            "created."
        ),
        "parameters": {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Domain name, e.g. 'example.com'"},
        }, "required": ["domain"]},
    },
    {
        "name": "osint_phone_lookup",
        "description": (
            "Analyze a phone number — country, carrier, line type, and "
            "validity. Use when the user asks about a phone number's "
            "origin or legitimacy."
        ),
        "parameters": {"type": "object", "properties": {
            "phone": {"type": "string", "description": "Phone number, e.g. '+14155551234'"},
        }, "required": ["phone"]},
    },
    {
        "name": "graph_analyze_influence",
        "description": (
            "PageRank-based influence scoring over a DIGITAL TWIN's "
            "graph — which entities in the modeled system are the most "
            "influential. Requires the twin to be built first; if no "
            "twin exists for the entity, build one before running this."
        ),
        "parameters": {"type": "object", "properties": {
            "twin_type": {"type": "string", "description": "Twin type: 'org' | 'infra' | 'supply_chain' | 'threat_actor'"},
            "entity": {"type": "string", "description": "Entity name the twin was built for"},
            "top_k": {"type": "integer", "description": "How many top influencers to return (default 10)"},
        }, "required": ["twin_type", "entity"]},
    },
    {
        "name": "graph_find_communities",
        "description": (
            "Community detection (Louvain) over a digital twin's graph — "
            "how the modeled entity's parts cluster into groups. "
            "Requires the twin to be built first."
        ),
        "parameters": {"type": "object", "properties": {
            "twin_type": {"type": "string", "description": "Twin type: 'org' | 'infra' | 'supply_chain' | 'threat_actor'"},
            "entity": {"type": "string", "description": "Entity name the twin was built for"},
        }, "required": ["twin_type", "entity"]},
    },
    {
        "name": "graph_find_hidden_relationships",
        "description": (
            "Surface likely missing edges in a digital twin's graph — "
            "pairs of nodes that aren't directly connected but share "
            "neighbors (Jaccard neighbor scoring). Requires the twin to "
            "be built first."
        ),
        "parameters": {"type": "object", "properties": {
            "twin_type": {"type": "string", "description": "Twin type: 'org' | 'infra' | 'supply_chain' | 'threat_actor'"},
            "entity": {"type": "string", "description": "Entity name the twin was built for"},
            "top_k": {"type": "integer", "description": "How many hidden relationships to return (default 5)"},
            "min_score": {"type": "number", "description": "Minimum Jaccard score to include (default 0.3)"},
        }, "required": ["twin_type", "entity"]},
    },
    {
        "name": "graph_centrality",
        "description": (
            "Centrality analysis over a digital twin's graph — which "
            "nodes are chokepoints by degree, betweenness, and "
            "closeness. Requires the twin to be built first."
        ),
        "parameters": {"type": "object", "properties": {
            "twin_type": {"type": "string", "description": "Twin type: 'org' | 'infra' | 'supply_chain' | 'threat_actor'"},
            "entity": {"type": "string", "description": "Entity name the twin was built for"},
            "top_k": {"type": "integer", "description": "How many top nodes to return (default 5)"},
        }, "required": ["twin_type", "entity"]},
    },
    {
        "name": "graph_network_vulnerability",
        "description": (
            "Structural attack-surface analysis over a digital twin's "
            "graph — articulation points, bridges, and overall "
            "robustness score. Requires the twin to be built first."
        ),
        "parameters": {"type": "object", "properties": {
            "twin_type": {"type": "string", "description": "Twin type: 'org' | 'infra' | 'supply_chain' | 'threat_actor'"},
            "entity": {"type": "string", "description": "Entity name the twin was built for"},
        }, "required": ["twin_type", "entity"]},
    },
]
TOOL_SCHEMAS.extend(_TOOL_SCHEMAS_PHASE_C)

# ── Phase D schemas (decision + brief) ─────────────────────────────
_TOOL_SCHEMAS_PHASE_D: list[dict] = [
    {
        "name": "run_decision_analysis",
        "description": (
            "Run decision-support analysis for a mission — computes a "
            "decision tree, risk impact scores, scenario analysis, and "
            "cost-benefit for the mission's current state. Use this "
            "when the user asks 'what should I do about mission X', "
            "'analyze my options for mission X', or wants a structured "
            "recommendation on a specific mission."
        ),
        "parameters": {"type": "object", "properties": {
            "mission_id": {"type": "string", "description": "ID of an existing mission to analyze"},
        }, "required": ["mission_id"]},
    },
    {
        "name": "generate_brief",
        "description": (
            "Generate an executive brief (markdown document) for a "
            "mission — summarizes findings, evidence, decisions, and "
            "recommended actions with a classification banner. Use this "
            "when the user asks for a briefing, executive summary, "
            "report, or writeup on a specific mission."
        ),
        "parameters": {"type": "object", "properties": {
            "mission_id": {"type": "string", "description": "ID of the mission to brief on (optional — falls back to the most recent/highest-priority mission)"},
            "classification": {"type": "string", "description": "Classification banner: 'UNCLASSIFIED' | 'CONFIDENTIAL' | 'SECRET'. Default: 'UNCLASSIFIED'"},
        }, "required": []},
    },
]
TOOL_SCHEMAS.extend(_TOOL_SCHEMAS_PHASE_D)
TOOL_HANDLERS: dict[str, Callable] = {
    "recon_scan": _tool_recon_scan,
    "cve_lookup": _tool_cve_lookup,
    "cve_search": _tool_cve_search,
    "threat_actor_profile": _tool_threat_actor_profile,
    "infra_pivot": _tool_infra_pivot,
    "github_secret_scan": _tool_github_secret_scan,
    "extract_iocs": _tool_extract_iocs,
    "create_mission": _tool_create_mission,
    "list_missions": _tool_list_missions,
    "open_auth_window": _tool_open_auth_window,
    "federated_search": _tool_federated_search,
    "system_status": _tool_system_status,
    "run_wargame": _tool_run_wargame,
    "take_screenshot": _tool_take_screenshot,
    "type_text": _tool_type_text,
    "press_keys": _tool_press_keys,
    "click_screen": _tool_click_screen,
    "switch_window": _tool_switch_window,
    "computer_task": _tool_computer_task,
    "open_application": _tool_open_application,
    "navigate_browser": _tool_navigate_browser,
    "run_sequence": _tool_run_sequence,
    "kali_nmap_scan": _tool_kali_nmap_scan,
    "kali_nikto_scan": _tool_kali_nikto_scan,
    "kali_gobuster_scan": _tool_kali_gobuster_scan,
    "kali_full_scan": _tool_kali_full_scan,
    # ── Graph-command ramps (Phase C) ───────────────────────────────
    # Wired through digital_twin: graph analytics need twin graph-state
    # snapshots as input — see aresx.graph_command.graph_ramps.
    "graph_analyze_influence": _tool_graph_analyze_influence,
    "graph_find_communities": _tool_graph_find_communities,
    "graph_find_hidden_relationships": _tool_graph_find_hidden_relationships,
    "graph_centrality": _tool_graph_centrality,
    "graph_network_vulnerability": _tool_graph_network_vulnerability,
    # ── OSINT ramps (Phase C) ───────────────────────────────────────
    "osint_ip_lookup": _tool_osint_ip_lookup,
    "osint_email_breach_check": _tool_osint_email_breach_check,
    "osint_username_hunt": _tool_osint_username_hunt,
    "osint_domain_whois": _tool_osint_domain_whois,
    "osint_phone_lookup": _tool_osint_phone_lookup,
    # ── Phase D (ADR-NATIONAL-HIGHWAY: decision + brief) ────────────
    "run_decision_analysis": _tool_run_decision_analysis,
    "generate_brief": _tool_generate_brief,
}


# Low-level desktop-automation primitives that stay OUT of what Gemini/Groq
# pick from directly. They're still fully wired in TOOL_HANDLERS above and
# still get called internally — by computer_agent.py's own vision loop, and
# by run_sequence's own step dispatcher — but the LLM never selects them as
# the top-level response to a user message.
#
# Why: with all 26 tools in one flat list, the model kept reaching for
# open_application / navigate_browser / run_sequence directly on things
# like "open X and search for Y" — running exactly one of them, then
# stopping, because nothing forced it to keep going. computer_task's own
# vision loop (screenshot → decide next action → act → screenshot again,
# repeat until the goal is actually done) already solves this correctly,
# but it was competing for the model's attention against these narrower,
# more literal-sounding alternatives and kept losing. Removing the
# alternatives from the selectable list makes computer_task the only
# route for "do something on the desktop" — not the preferred one among
# several, the only one — so it can no longer be second-guessed by the
# model reaching for what looks like a more direct match.
_HIDDEN_FROM_LLM_SELECTION = frozenset({
    "open_application",
    "navigate_browser",
    "run_sequence",
    "type_text",
    "press_keys",
    "click_screen",
    "switch_window",
})

# What Gemini/Groq actually see and choose from. take_screenshot and
# computer_task stay selectable — a bare "take a screenshot" is a
# legitimate one-shot request that doesn't need the full vision loop, and
# computer_task is the intended entry point for everything else desktop-
# related now that its narrower competitors are hidden.
LLM_SELECTABLE_SCHEMAS: list[dict] = [
    s for s in TOOL_SCHEMAS if s["name"] not in _HIDDEN_FROM_LLM_SELECTION
]


# ── Gemini function-calling request ────────────────────────────────────────

async def _gemini_tool_call(message: str, history: Optional[list[dict]] = None) -> Optional[dict]:
    """
    Send the user's message to Gemini with tool declarations attached.
    Returns {"name": ..., "args": {...}} if Gemini chose a tool, or
    {"text": ...} if it just wants to respond conversationally, or
    None if the call failed entirely (caller should fall back).

    `history` (optional) is prior conversation turns, each a dict with
    "role" ("user" or "ares") and "text" — sent as real Gemini multi-turn
    `contents` so the model has actual context of what's already been
    discussed. Without this, a natural follow-up like "what is the
    summary" has no idea what "the summary" refers to, since every
    message was previously evaluated in total isolation.
    """
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return None

    if _gemini_likely_exhausted():
        # Skip the guaranteed-to-fail round-trip. This matters most for
        # the multi-step tool loop in route_message: without this, every
        # follow-up step re-pays Gemini's full request/429-response
        # latency before falling through to Groq, and that extra time
        # per step makes a multi-step turn MORE likely to land several
        # Groq calls inside the same per-minute rate-limit window.
        logger.debug("Skipping Gemini tool-call — marked exhausted this session")
        return None

    try:
        import httpx

        contents = []
        for turn in (history or []):
            role = turn.get("role", "")
            text = turn.get("text", "")
            if not text:
                continue
            # Gemini's API uses "model" for the assistant's turns, not
            # "ares" — our frontend/history format uses "ares" since
            # that's what it displays in the UI, so translate here.
            gemini_role = "model" if role == "ares" else "user"
            contents.append({"role": gemini_role, "parts": [{"text": text}]})
        contents.append({"role": "user", "parts": [{"text": message}]})

        body = {
            "contents": contents,
            "tools": [{"functionDeclarations": LLM_SELECTABLE_SCHEMAS}],
            "systemInstruction": {
                "parts": [{
                    "text": (
                        "You are ARES X, a sovereign intelligence and red team "
                        "system. Talk normally and conversationally. When the "
                        "user's request matches one of your available tools — "
                        "even if they don't use exact technical phrasing — call "
                        "that tool. Infer the right tool from what they're "
                        "actually asking for. Only respond with plain text "
                        "(no tool call) for casual conversation, questions "
                        "about what you are, or anything that doesn't map to "
                        "an available capability. Use the conversation history "
                        "to understand follow-up questions and references to "
                        "things already discussed (e.g. \"what's the summary\" "
                        "after a scan you just ran refers to that scan's result, "
                        "not a request for a new tool call)."
                    )
                }]
            },
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                "https://generativelanguage.googleapis.com/v1beta/models/"
                "gemini-flash-latest:generateContent",
                headers={"Content-Type": "application/json"},
                params={"key": api_key},
                json=body,
            )
            if r.status_code != 200:
                if r.status_code == 429:
                    _mark_gemini_exhausted()
                logger.warning("Gemini tool-call request failed: HTTP %s — %s", r.status_code, r.text[:300])
                return None

            data = r.json()
            candidates = data.get("candidates", [])
            if not candidates:
                return None

            parts = candidates[0].get("content", {}).get("parts", [])
            for part in parts:
                if "functionCall" in part:
                    fc = part["functionCall"]
                    return {"name": fc.get("name"), "args": fc.get("args", {})}

            # No function call — model responded with plain text
            text = "".join(p.get("text", "") for p in parts).strip()
            if text:
                return {"text": text}
            return None

    except Exception as exc:
        logger.warning("Gemini tool-call failed with exception: %s", exc)
        return None


# Groq's chat completions endpoint speaks the OpenAI tool-calling format —
# a different shape from Gemini's functionDeclarations, so
# LLM_SELECTABLE_SCHEMAS (already {name, description, parameters}) gets
# wrapped into {"type": "function", "function": {...}} once, here, rather
# than maintaining a second parallel schema list. Uses the filtered
# selectable set, not the full TOOL_SCHEMAS, for the same reason Gemini's
# call does — see _HIDDEN_FROM_LLM_SELECTION's comment above.
_GROQ_TOOL_SCHEMAS: list[dict] = [
    {"type": "function", "function": schema} for schema in LLM_SELECTABLE_SCHEMAS
]


def _parse_groq_retry_seconds(error_text: str) -> float:
    """
    Extract the wait time from a Groq 429 body, e.g.:
      "...Please try again in 5.649999999s. Need more tokens?..."
    Falls back to 3.0s if the pattern isn't found (still worth one
    retry attempt), and is capped at 15s so a single retry can never
    stall a request for an unreasonable amount of time.
    """
    import re
    m = re.search(r"try again in (\d+(?:\.\d+)?)s", error_text)
    if m:
        return min(float(m.group(1)) + 0.5, 15.0)  # small buffer past the exact boundary
    return 3.0


async def _groq_tool_call(message: str, history: Optional[list[dict]] = None) -> Optional[dict]:
    """
    Same contract as _gemini_tool_call (returns {"name","args"} /
    {"text": ...} / None) but via Groq — the fallback tool-selection
    path for when Gemini's quota is exhausted. Without this, a Gemini
    429 didn't just lose the primary model, it silently downgraded
    every request from "ARES runs the task" to "ARES describes how
    you'd do it yourself" — because the old conversational-only
    fallback (inference_api.generate) has no concept of tools at all.

    Verified against Groq directly before building this: a
    tools-equipped chat/completions call to llama-3.3-70b-versatile
    returns a real tool_calls response in the same shape OpenAI's API
    uses, so this mirrors _gemini_tool_call's parsing rather than
    guessing at the response format.
    """
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        return None

    try:
        import httpx

        messages = [{
            "role": "system",
            "content": (
                "You are ARES X, a sovereign intelligence and red team "
                "system. Talk normally and conversationally. When the "
                "user's request matches one of your available tools — "
                "even if they don't use exact technical phrasing — call "
                "that tool. Infer the right tool from what they're "
                "actually asking for. Only respond with plain text "
                "(no tool call) for casual conversation, questions "
                "about what you are, or anything that doesn't map to "
                "an available capability."
            ),
        }]
        for turn in (history or []):
            role = turn.get("role", "")
            text = turn.get("text", "")
            if not text:
                continue
            groq_role = "assistant" if role == "ares" else "user"
            messages.append({"role": groq_role, "content": text})
        messages.append({"role": "user", "content": message})

        body = {
            "model": "llama-3.3-70b-versatile",
            "messages": messages,
            "tools": _GROQ_TOOL_SCHEMAS,
            "max_tokens": 1024,
            "temperature": 0.3,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=body,
            )

            if r.status_code == 429:
                # Groq's free-tier TPM limit is easy to brush against
                # inside a multi-step turn (each call resends the full
                # tool schema). Groq's own error body includes a real
                # wait-time hint (e.g. "Please try again in 5.6s") —
                # respect it once with a bounded retry rather than
                # aborting the whole multi-step task on a transient,
                # short-lived limit.
                retry_after = _parse_groq_retry_seconds(r.text)
                logger.warning(
                    "Groq tool-call rate limited — retrying once after %.1fs: %s",
                    retry_after, r.text[:300],
                )
                await asyncio.sleep(retry_after)
                r = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json=body,
                )

            if r.status_code != 200:
                logger.warning("Groq tool-call request failed: HTTP %s — %s", r.status_code, r.text[:300])
                return None

            data = r.json()
            choices = data.get("choices", [])
            if not choices:
                return None

            msg = choices[0].get("message", {})
            tool_calls = msg.get("tool_calls") or []
            if tool_calls:
                fc = tool_calls[0].get("function", {})
                import json as _json
                try:
                    args = _json.loads(fc.get("arguments", "{}"))
                except (ValueError, TypeError):
                    args = {}
                return {"name": fc.get("name"), "args": args}

            text = (msg.get("content") or "").strip()
            if text:
                return {"text": text}
            return None

    except Exception as exc:
        logger.warning("Groq tool-call failed with exception: %s", exc)
        return None


async def _summarize_tool_result(
    tool_name: str, result: Any, user_message: str,
    executed: Optional[list[dict]] = None,
) -> str:
    """
    Turn a raw tool result into a natural-language response via Gemini.

    `executed` (optional) is the full list of steps run this turn when
    route_message's multi-step loop ran more than one tool — when given,
    the summary covers the whole sequence, not just the final tool.
    Existing call sites that don't pass it (e.g. the authorization-retry
    path, which only ever runs one tool) keep the original single-tool
    behavior unchanged.
    """
    from aresx.sovereign_ai import inference_api

    if executed and len(executed) > 1:
        data_str = json.dumps(executed, default=str)[:6000]
        prompt = (
            f'The user said: "{user_message}"\n'
            f"You ran this sequence of tools to accomplish it:\n{data_str}\n\n"
            f"Report back what was accomplished naturally and concisely — "
            f"like a real analyst summarizing a completed multi-step task. "
            f"Don't mention JSON, raw data, or internal tool names."
        )
    else:
        plain = _to_plain(result)
        data_str = json.dumps(plain, default=str)[:6000]
        prompt = (
            f'The user said: "{user_message}"\n'
            f"You ran the '{tool_name}' tool. Result:\n{data_str}\n\n"
            f"Report these findings back to the user naturally and concisely — "
            f"like a real analyst summarizing what was found. Don't mention "
            f"JSON or raw data."
        )

    response = inference_api.generate(
        prompt=prompt,
        task_type="general",
        system=(
            "You are ARES X, a sovereign intelligence system. Direct, "
            "precise, professional. Report findings clearly."
        ),
        max_tokens=700,
    )
    return response or f"Ran {tool_name} — check the evidence vault for full details."


# ── Public entry point ─────────────────────────────────────────────────────

# Words that count as a yes/no answer to a pending authorization
# question. Deliberately narrow (not run through the LLM) — this check
# has to be cheap, instant, and unambiguous, since misreading an
# unrelated message as an authorization answer would be a real bug in
# exactly the wrong direction (either wrongly authorizing something,
# or wrongly ignoring a real answer and leaving the request stuck).
_YES_WORDS = {"yes", "y", "yeah", "yep", "approve", "approved", "authorize", "authorized", "go ahead", "do it"}
_NO_WORDS = {"no", "n", "nope", "deny", "denied", "decline", "declined", "don't", "dont", "cancel", "stop"}


def _match_pending_answer(message: str) -> Optional[bool]:
    """
    Whether `message` looks like a yes/no answer to a pending
    authorization question. Returns True (yes), False (no), or None
    (doesn't look like an answer at all — treat as an unrelated
    message). Deliberately strict: only matches short, unambiguous
    replies, not "yes" appearing incidentally inside a longer message
    about something else.
    """
    normalized = message.strip().lower().rstrip(".!")
    if normalized in _YES_WORDS:
        return True
    if normalized in _NO_WORDS:
        return False
    return None


async def _summarize_pending_request(request_id: str, prompt_text: str) -> str:
    """Turn a fresh PendingApproval into a clear chat message asking the user."""
    return (
        f"{prompt_text}\n\n"
        f"Reply **yes** to authorize this, or **no** to decline. "
        f"(Or say something like \"open a window for 4 hours\" first, if you'd "
        f"rather authorize a whole session instead of just this one action.)"
    )


# Hard cap on tool calls per user message — same purpose as
# computer_agent.MAX_STEPS: bounds a model that never says "done" so one
# message can't loop indefinitely. 15 matches that existing constant for
# consistency between the two loops.
MAX_TOOL_STEPS = 15


async def _next_step_decision(
    original_message: str, executed: list[dict], history: Optional[list[dict]]
) -> Optional[dict]:
    """
    Ask the model whether the original request is fully done, or what
    the next tool call should be, given everything executed so far this
    turn. Same {"name","args"} / {"text"} / None contract as
    _gemini_tool_call — tries Gemini first, then Groq, same fallback
    order as the initial decision.

    Deliberately does NOT pass `history` (prior conversation turns)
    through to the follow-up calls — `executed` already carries every
    step run this turn, which is what the model actually needs to judge
    completion. Re-sending the full chat history on every follow-up step
    of a multi-step turn added real token cost for no benefit, and was
    part of what pushed a 3-step turn over Groq's per-minute token limit
    in practice.
    """
    # Trimmed from 4000: the model needs to know what ran and whether it
    # succeeded, not full raw output — keep this light since it's resent
    # on every step of a multi-step turn.
    executed_summary = json.dumps(
        [{"tool": e["tool"], "ok": (e["result"] or {}).get("ok") if isinstance(e.get("result"), dict) else None}
         for e in executed],
        default=str,
    )[:800]
    follow_up = (
        f'Original request: "{original_message}"\n\n'
        f"Steps executed so far this turn: {executed_summary}\n\n"
        f"Is the original request now fully complete? If yes, respond with "
        f"plain text summarizing what was accomplished (no tool call). If "
        f"more needs to happen to finish what the user asked for, call the "
        f"next appropriate tool now."
    )
    decision = await _gemini_tool_call(follow_up, history=None)
    if decision is None:
        decision = await _groq_tool_call(follow_up, history=None)
    return decision


async def route_message(message: str, history: Optional[list[dict]] = None) -> str:
    """
    Main entry point. Sends the message to Gemini with tool declarations;
    if Gemini selects a tool, runs the real backend function and returns
    a natural-language summary of the result. If Gemini just responds
    conversationally, returns that directly. Falls back to a plain
    conversational call if the tool-calling request fails entirely
    (e.g. no Gemini key configured, or a network error).

    `history` (optional) is prior conversation turns — see
    _gemini_tool_call's docstring for the expected shape. Passing this
    is what lets Gemini understand follow-ups like "what is the
    summary" instead of evaluating every message with zero context of
    what was said before it.

    Before any of that: if there's a currently-pending authorization
    question (a network-facing tool that needs approval — see
    _require_authorization) and this message looks like a yes/no
    answer to it, resolves that first. A red-team tool that needed
    authorization returns {"auth_pending": True, ...} instead of its
    normal result; this function is what turns that into the actual
    chat question. Saying "yes" re-runs the EXACT original tool call
    automatically (see _pending_tool_calls) — you don't need to repeat
    your request.
    """
    message = message.strip()
    if not message:
        return "Say something and I'll get to work."

    _current_message.set(message)

    auth = get_shared_authorization()
    pending_list = auth.list_pending()
    if pending_list:
        # Oldest pending request first — in normal chat use there's only
        # ever one at a time (a second tool call while one is already
        # pending is rare, but if it happens, resolve oldest-first so
        # answers apply in the order the questions were asked).
        oldest = pending_list[0]
        answer = _match_pending_answer(message)
        if answer is not None:
            resolved = auth.resolve_pending(oldest.request_id, approved=answer)
            stored = _pending_tool_calls.pop(oldest.request_id, None)

            if not answer:
                return f"Declined — {resolved.action_label} against {resolved.target_label} will not run."

            if not stored:
                # Shouldn't normally happen (every _require_authorization
                # call registers one), but degrade honestly rather than
                # silently pretending the action ran if this table entry
                # is somehow missing.
                return (
                    f"Authorized — {resolved.action_label} against {resolved.target_label} "
                    f"is approved, but I lost track of the original request to retry it "
                    f"automatically. Ask me again to run it."
                )

            tool_name, tool_args, original_message = stored
            handler = TOOL_HANDLERS.get(tool_name)
            if not handler:
                return f"Authorized, but the '{tool_name}' tool isn't wired up anymore — that's a bug, not you."

            _current_message.set(original_message)
            try:
                result = await handler(tool_args)
                return await _summarize_tool_result(tool_name, result, original_message)
            except Exception as exc:
                logger.exception("Retry after authorization failed: %s(%s)", tool_name, tool_args)
                return f"Authorized, but hit an error actually running it: {str(exc)[:200]}"
        # Doesn't look like a yes/no answer — fall through to normal
        # routing. The pending request just stays pending; the user
        # might be asking something unrelated, or asking a follow-up
        # question about the request itself, and Gemini should still
        # respond normally to that.

    decision = await _gemini_tool_call(message, history)

    if decision is None:
        # Gemini's tool-calling path failed (commonly: quota exhausted).
        # Try Groq's tool-calling next — same {"name","args"}/{"text"}/None
        # contract — before giving up on tool selection entirely. Without
        # this step, a Gemini outage silently downgraded every request
        # from "ARES runs the task" to "ARES describes how you'd do it",
        # since the old plain-conversation fallback below has no notion
        # of tools at all.
        # SIGNAGE (Phase B): the Gemini->Groq handoff is now logged, so a
        # provider outage is visible in the logs instead of happening
        # silently.
        logger.warning("[router] Gemini tool-call failed — handing off to "
                       "Groq for %r", message[:60])
        decision = await _groq_tool_call(message, history)

    if decision is None:
        # Both tool-calling providers failed — fall back to a plain
        # conversational call through the full provider chain (Gemini
        # without tools -> Groq -> Ollama -> OpenRouter -> HF), so the
        # user still gets *a* response instead of silence. This can no
        # longer select or run a tool; it's a last-resort chat reply.
        # SIGNAGE (Phase B): the final downshift to conversational-only
        # mode is now logged, so degraded capability is visible.
        logger.warning("[router] Both Gemini and Groq tool-calling failed "
                       "— downshifting to conversational-only fallback")
        from aresx.sovereign_ai import inference_api
        response = inference_api.generate(
            prompt=message,
            task_type="general",
            system=(
                "You are ARES X, a sovereign intelligence and red team "
                "system. Talk normally. You have recon, CVE intelligence, "
                "threat actor tracking, and other red team tools available, "
                "but right now you're responding without live tool access — "
                "answer conversationally."
            ),
            max_tokens=600,
        )
        return response or "I'm having trouble reaching my language model right now — check your API keys."

    if "text" in decision:
        return decision["text"]

    # ── Multi-step tool loop ──────────────────────────────────────────────
    # A single user message can require several tool calls to actually
    # finish (e.g. "open X and search for Y" is open_application, then a
    # separate search step). Previously this function ran exactly one
    # tool call per message and stopped — the LLM would say things like
    # "I've opened X, ready to search next" and then just wait, because
    # nothing here ever asked it to continue. This loop keeps feeding the
    # running history of what's been done back to the model and asking
    # for the next step, the same way computer_agent's vision loop drives
    # multi-step desktop automation — except here it's the LLM (not
    # screenshots) deciding what's next, since these tools are direct
    # backend actions rather than screen coordinates.
    #
    # Bounded to MAX_TOOL_STEPS so a model that never says "done" can't
    # loop forever. An auth_pending result ALWAYS breaks the loop
    # immediately and hands control back to the user — a red-team tool
    # waiting on human approval must never be auto-continued past.
    executed: list[dict] = []
    final_result = None
    final_tool_name = decision.get("name")

    for step_num in range(1, MAX_TOOL_STEPS + 1):
        tool_name = decision.get("name")
        tool_args = decision.get("args", {})
        handler = TOOL_HANDLERS.get(tool_name)

        if not handler:
            logger.warning("LLM requested unknown tool: %s", tool_name)
            return f"I tried to use a tool called '{tool_name}' but it isn't wired up — that's a bug, not you."

        try:
            result = await handler(tool_args)
        except Exception as exc:
            logger.exception("Tool execution failed: %s(%s)", tool_name, tool_args)
            return f"Ran into an error running that: {str(exc)[:200]}"

        if isinstance(result, dict) and result.get("auth_pending"):
            # Never auto-continue past an authorization gate — stop the
            # loop here unconditionally and surface the question verbatim.
            return await _summarize_pending_request(result["request_id"], result["prompt_text"])

        executed.append({"tool": tool_name, "args": tool_args, "result": _to_plain(result)})
        final_result = result
        final_tool_name = tool_name

        if step_num >= MAX_TOOL_STEPS:
            break

        # Ask again: given what's been done so far, is the original
        # request actually finished, or is there another step?
        next_decision = await _next_step_decision(message, executed, history)
        if next_decision is None or "text" in next_decision:
            # Model has nothing further to run (or tool-calling itself
            # failed on this follow-up ask) — treat as done and summarize
            # everything executed so far rather than losing the results.
            break
        decision = next_decision

    return await _summarize_tool_result(final_tool_name, final_result, message, executed)


async def route_message_streaming(message: str, history: Optional[list[dict]] = None):
    """
    Streaming twin of route_message — same routing and multi-step loop
    logic, but an async generator that yields structured event dicts as
    it goes, instead of returning one final string. Used by the /chat/stream
    SSE endpoint so the frontend can show each tool call as it happens
    (a live "thinking" trace) rather than only the finished reply.

    route_message itself is untouched and still returns a plain string —
    existing callers (test_chat_auth.py, the non-streaming /chat endpoint)
    keep working exactly as before. This is purely additive.

    Yielded event shapes:
      {"type": "status", "message": "..."}                     — a short human-readable status line
      {"type": "step_start", "step": N, "tool": "..."}          — about to run a tool
      {"type": "step_result", "step": N, "tool": "...", "ok": bool, "detail": "..."}  — tool finished
      {"type": "final", "text": "..."}                           — the finished reply (always the last event)
      {"type": "auth_pending", "text": "..."}                    — needs the user's yes/no (also final for this turn)
      {"type": "error", "text": "..."}                           — something failed; also final
    """
    message = message.strip()
    if not message:
        yield {"type": "final", "text": "Say something and I'll get to work."}
        return

    _current_message.set(message)

    auth = get_shared_authorization()
    pending_list = auth.list_pending()
    if pending_list:
        oldest = pending_list[0]
        answer = _match_pending_answer(message)
        if answer is not None:
            resolved = auth.resolve_pending(oldest.request_id, approved=answer)
            stored = _pending_tool_calls.pop(oldest.request_id, None)

            if not answer:
                yield {"type": "final", "text": f"Declined — {resolved.action_label} against {resolved.target_label} will not run."}
                return

            if not stored:
                yield {"type": "final", "text": (
                    f"Authorized — {resolved.action_label} against {resolved.target_label} "
                    f"is approved, but I lost track of the original request to retry it "
                    f"automatically. Ask me again to run it."
                )}
                return

            tool_name, tool_args, original_message = stored
            handler = TOOL_HANDLERS.get(tool_name)
            if not handler:
                yield {"type": "error", "text": f"Authorized, but the '{tool_name}' tool isn't wired up anymore — that's a bug, not you."}
                return

            _current_message.set(original_message)
            yield {"type": "step_start", "step": 1, "tool": tool_name}
            try:
                result = await handler(tool_args)
                ok = not (isinstance(result, dict) and result.get("ok") is False)
                yield {"type": "step_result", "step": 1, "tool": tool_name, "ok": ok, "detail": _to_plain(result)}
                final_text = await _summarize_tool_result(tool_name, result, original_message)
                yield {"type": "final", "text": final_text}
            except Exception as exc:
                logger.exception("Retry after authorization failed: %s(%s)", tool_name, tool_args)
                yield {"type": "error", "text": f"Authorized, but hit an error actually running it: {str(exc)[:200]}"}
            return

    yield {"type": "status", "message": "Deciding how to handle this..."}
    decision = await _gemini_tool_call(message, history)

    if decision is None:
        decision = await _groq_tool_call(message, history)

    if decision is None:
        yield {"type": "status", "message": "Falling back to plain conversation..."}
        from aresx.sovereign_ai import inference_api
        response = inference_api.generate(
            prompt=message,
            task_type="general",
            system=(
                "You are ARES X, a sovereign intelligence and red team "
                "system. Talk normally. You have recon, CVE intelligence, "
                "threat actor tracking, and other red team tools available, "
                "but right now you're responding without live tool access — "
                "answer conversationally."
            ),
            max_tokens=600,
        )
        yield {"type": "final", "text": response or "I'm having trouble reaching my language model right now — check your API keys."}
        return

    if "text" in decision:
        yield {"type": "final", "text": decision["text"]}
        return

    executed: list[dict] = []
    final_result = None
    final_tool_name = decision.get("name")

    for step_num in range(1, MAX_TOOL_STEPS + 1):
        tool_name = decision.get("name")
        tool_args = decision.get("args", {})
        handler = TOOL_HANDLERS.get(tool_name)

        if not handler:
            logger.warning("LLM requested unknown tool: %s", tool_name)
            yield {"type": "error", "text": f"I tried to use a tool called '{tool_name}' but it isn't wired up — that's a bug, not you."}
            return

        yield {"type": "step_start", "step": step_num, "tool": tool_name}

        try:
            result = await handler(tool_args)
        except Exception as exc:
            logger.exception("Tool execution failed: %s(%s)", tool_name, tool_args)
            yield {"type": "error", "text": f"Ran into an error running that: {str(exc)[:200]}"}
            return

        if isinstance(result, dict) and result.get("auth_pending"):
            auth_text = await _summarize_pending_request(result["request_id"], result["prompt_text"])
            yield {"type": "auth_pending", "text": auth_text}
            return

        plain_result = _to_plain(result)
        ok = not (isinstance(plain_result, dict) and plain_result.get("ok") is False)
        yield {"type": "step_result", "step": step_num, "tool": tool_name, "ok": ok, "detail": plain_result}

        executed.append({"tool": tool_name, "args": tool_args, "result": plain_result})
        final_result = result
        final_tool_name = tool_name

        if step_num >= MAX_TOOL_STEPS:
            break

        yield {"type": "status", "message": "Checking if that's everything..."}
        next_decision = await _next_step_decision(message, executed, history)
        if next_decision is None or "text" in next_decision:
            break
        decision = next_decision

    final_text = await _summarize_tool_result(final_tool_name, final_result, message, executed)
    yield {"type": "final", "text": final_text}

