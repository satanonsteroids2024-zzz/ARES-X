"""ARES X v10 — compat shim: regex fallback now lives in aresx.chat.router."""
from __future__ import annotations
from aresx.chat.router import (
    _regex_route_message,
    _match_intent,
    _PATTERNS,
    _INTENT_HANDLERS,
    _handle_recon,
    _handle_cve_lookup,
    _handle_cve_search,
    _handle_threat_actor,
    _handle_pivot,
    _handle_github_dork,
    _handle_create_mission,
    _handle_list_missions,
    _handle_open_window,
    _handle_federated_search,
    _handle_status,
    _handle_wargame,
    _handle_extract_iocs,
    _llm_fallback,
    _summarize,
    _to_plain,
)
