"""
ARES X v8.0 — Phase 2.7: Fusion explainability.

Given a confidence breakdown (from ``confidence.confidence_breakdown``)
and the underlying evidence, produce a natural-language explanation of
why the fusion engine arrived at its assertion.

The output is consumed by:
  • Decision Support (Phase 5)         — shows analysts the "why"
  • Brief Generator (Phase 7)          — embeds into PDF/DOCX briefs
  • UI Mission Control panel (Phase 8) — tooltip on confidence pill
"""
from __future__ import annotations

from typing import Sequence

from aresx.fusion.types import Evidence


def explain(
    asserted_value: str,
    supporting: Sequence[Evidence],
    contradicting: Sequence[Evidence],
    breakdown: dict,
) -> str:
    """
    Produce a single-paragraph natural-language explanation.

    Args:
        asserted_value: the value the engine chose
        supporting:     evidence pieces backing the value
        contradicting:  evidence pieces disagreeing
        breakdown:      dict returned by ``confidence.confidence_breakdown``

    Returns:
        A 2-4 sentence prose explanation suitable for embedding in
        analyst briefs or UI tooltips.
    """
    final = breakdown.get("final", 0.0)
    base = breakdown.get("base", 0.0)
    bonus = breakdown.get("bonus", 0.0)
    penalty = breakdown.get("penalty", 0.0)
    support_count = breakdown.get("support_count", len(supporting))
    unique_sources = breakdown.get("unique_sources", len({e.source_tool for e in supporting}))
    contradiction_count = breakdown.get("contradiction_count", len(contradicting))

    confidence_pct = final * 100
    confidence_tier = _tier(final)

    sources_phrase = _format_sources([e.source_tool for e in supporting])
    line1 = (
        f'Asserted value "{asserted_value}" has {confidence_tier} confidence '
        f'({confidence_pct:.0f}%), backed by {support_count} evidence piece'
        f'{"s" if support_count != 1 else ""} from {unique_sources} distinct '
        f'source{"s" if unique_sources != 1 else ""} ({sources_phrase}).'
    )

    line2 = (
        f"Base reliability-weighted score: {base:.2f}, "
        f"+{bonus:.2f} corroboration bonus, "
        f"-{penalty:.2f} contradiction penalty."
    )

    if contradiction_count:
        contradict_sources = _format_sources([e.source_tool for e in contradicting])
        line3 = (
            f"⚠ {contradiction_count} contradicting source"
            f"{'s' if contradiction_count != 1 else ''} "
            f"({contradict_sources}) — see contradiction log for details."
        )
        return f"{line1} {line2} {line3}"

    return f"{line1} {line2}"


def _tier(confidence: float) -> str:
    """Map a confidence float to a qualitative tier."""
    if confidence >= 0.90: return "very high"
    if confidence >= 0.75: return "high"
    if confidence >= 0.60: return "moderate"
    if confidence >= 0.40: return "low"
    return "very low"


def _format_sources(sources: list[str], max_inline: int = 3) -> str:
    """Render a source-tool list with a sensible ellipsis."""
    unique = []
    seen = set()
    for s in sources:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    if not unique:
        return "none"
    if len(unique) <= max_inline:
        return ", ".join(unique)
    head = ", ".join(unique[:max_inline])
    return f"{head}, and {len(unique) - max_inline} other{'s' if len(unique) - max_inline != 1 else ''}"
