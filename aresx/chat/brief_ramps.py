"""
aresx.chat.brief_ramps — Phase 1a of ADR-NATIONAL-HIGHWAY.

Wraps aresx.enterprise.generate_brief() + export_brief_markdown() as a
chat-facing _tool_* function.

Same rationale as decision_ramps.py: mission_control_ui.py's BriefPanel
takes a mission_id, but full_snapshot() calls its get_state() with no
argument, so generate_brief() was never invoked via chat. This ramp
gives Gemini/Groq a direct, parameterized way to request an executive
brief for a specific mission.

BUG FIX (v12 scan): the first version of this file claimed in its
docstring and tool schema that omitting mission_id "falls back to the
most recent mission" — that was never true. aresx.enterprise.
generate_brief() has NO fallback logic at all: pass it mission_id=None
and it silently skips the entire executive-summary/findings/
recommendations block, returning a near-empty Brief with just a generic
title. A user asking "give me a brief" with no mission named would have
silently gotten a useless result. This version implements the fallback
for real, using mission.list_missions()'s own priority/recency
ordering, instead of relying on a fallback that was never built.
"""
from __future__ import annotations

from typing import Any


async def _tool_generate_brief(args: dict) -> Any:
    """Generate an executive brief for a mission, returned as JSON + markdown.

    args:
        mission_id (str, optional): ID of an existing mission. If omitted,
            the most recent/highest-priority mission is used instead —
            implemented here explicitly (see module docstring for why:
            generate_brief() itself has no such fallback).
        classification (str, optional): Security classification banner,
            e.g. "UNCLASSIFIED", "CONFIDENTIAL". Defaults to "UNCLASSIFIED".

    Returns a dict with the brief_id, title, classification, and the
    exported markdown body (ready to render or copy), or an {"error": ...}
    dict if no mission_id was given and no missions exist to fall back to.
    """
    from aresx.enterprise import generate_brief, export_brief_markdown

    mission_id = args.get("mission_id")
    # Bug found by SENTINEL adversarial pass, /godmode: a whitespace-only
    # string ("  ") is truthy, so the old `if not mission_id:` check would
    # have skipped the fallback lookup and passed "  " straight through to
    # generate_brief() as if it were a real mission_id. Since mission_id is
    # legitimately optional here (unlike decision_ramps.py), normalize
    # whitespace-only to "not given" so it correctly triggers the
    # most-recent-mission fallback below, rather than erroring OR silently
    # querying a garbage ID.
    if isinstance(mission_id, str):
        mission_id = mission_id.strip() or None
    elif mission_id is not None:
        # Non-string, non-None (e.g. an int or dict) is a caller error —
        # don't silently coerce it or pass it to generate_brief(), which
        # would surface as a confusing DB-layer exception instead of a
        # clear message.
        return {"error": f"mission_id must be a string if provided, got {type(mission_id).__name__}"}
    classification = args.get("classification", "UNCLASSIFIED")

    if not mission_id:
        from aresx.mission import list_missions
        missions = list_missions()
        if not missions:
            return {"error": "No mission_id given and no missions exist to brief on. "
                              "Create a mission first, or pass mission_id explicitly."}
        mission_id = missions[0].get("mission_id")

    try:
        brief = generate_brief(mission_id, classification=classification)
    except Exception as exc:
        return {"error": f"brief generation failed: {exc}"}

    return {
        "mission_id":     mission_id,
        "brief_id":       getattr(brief, "brief_id", None),
        "title":          getattr(brief, "title", None),
        "classification": getattr(brief, "classification", classification),
        "markdown":       export_brief_markdown(brief),
    }
