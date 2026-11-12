"""
aresx.chat.decision_ramps — Phase 1a of ADR-NATIONAL-HIGHWAY.

Wraps aresx.decision.analyze() as a chat-facing _tool_* function.

Before this file existed, aresx.decision was reachable only via
mission_control_ui.py's DecisionPanel — but full_snapshot() calls
DecisionPanel.get_state() with no arguments, so analyze() (which
requires a mission_id) was never actually invoked through any live
chat path. This ramp closes that gap by giving Gemini/Groq a direct,
parameterized tool for decision analysis, matching the same 3-hop
convention (schema → dispatch → handler) used by every other _tool_*
in aresx/chat/router.py.
"""
from __future__ import annotations

from typing import Any


async def _tool_run_decision_analysis(args: dict) -> Any:
    """Run decision-support analysis for a mission and return a plain-dict result.

    args:
        mission_id (str, required): ID of an existing mission to analyze.

    Returns a dict with the decision tree, risk impact, scenario analysis,
    and cost-benefit fields, ready for the LLM to summarize back to the
    user. Uses aresx.decision.analyze() unchanged; the result is flattened
    to a JSON-safe dict via export_decision_json() (not the router's
    generic _to_plain — the underlying DecisionSupportOutput is deeply
    nested, and export_decision_json() already knows how to flatten it
    correctly). The router's _to_plain() still runs on top of this at
    dispatch time like every other tool result, but it's a no-op here
    since the dict is already plain.
    """
    from aresx.decision import analyze, export_decision_json

    mission_id = args.get("mission_id")
    if not isinstance(mission_id, str) or not mission_id.strip():
        # Bug found by SENTINEL adversarial pass, /godmode: a whitespace-
        # only string ("  ") is truthy in Python, so the old `if not
        # mission_id:` check let it through, and the underlying analyze()
        # ran against a garbage ID, silently returning a low-confidence
        # but "successful-looking" result instead of a clean error.
        return {"error": "mission_id is required and must be a non-empty string"}
    mission_id = mission_id.strip()

    try:
        output = analyze(mission_id)
    except Exception as exc:
        return {"error": f"decision analysis failed: {exc}"}

    # export_decision_json() already gives a clean, JSON-safe dict —
    # use it so we don't rely on router-level dataclass conversion for
    # this one path (the underlying output is nested and easier for the
    # LLM to summarize once flattened).
    return export_decision_json(output)
