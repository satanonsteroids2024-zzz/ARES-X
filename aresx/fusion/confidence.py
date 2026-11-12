"""
ARES X v8.0 — Phase 2.2: Confidence scoring.

Pure-function implementation of the confidence formula from
TRD §3.1 / Build Prompt §3 Phase 2.2::

    base_confidence       = weighted_mean(evidence_scores,
                                          weights=source_reliability_scores)
    corroboration_bonus   = min(0.2, 0.05 * corroborating_source_count)
    contradiction_penalty = 0.15 * contradiction_count
    final_confidence      = clamp(base + bonus - penalty, 0.0, 1.0)

This module has zero side-effects and zero I/O. It exists so the
formula can be unit-tested in isolation and reasoned about precisely.
"""
from __future__ import annotations

from typing import Sequence

from aresx.fusion.types import Evidence
from aresx.fusion import source_reliability as sr

# Tunable knobs (lifted from the spec; expose so they're greppable)
MAX_CORROBORATION_BONUS:    float = 0.20
CORROBORATION_PER_SOURCE:   float = 0.05
CONTRADICTION_PENALTY_UNIT: float = 0.15


def weighted_mean(values: Sequence[float], weights: Sequence[float]) -> float:
    """Standard weighted arithmetic mean. Returns 0.0 on empty input."""
    if len(values) != len(weights):
        raise ValueError("values and weights must have the same length")
    total_weight = sum(weights)
    if total_weight <= 0.0:
        return 0.0
    return sum(v * w for v, w in zip(values, weights)) / total_weight


def compute_confidence(
    supporting: Sequence[Evidence],
    contradicting: Sequence[Evidence] = (),
    reliability_lookup=sr.get_reliability,
) -> float:
    """
    Compute fused confidence for a single ``(entity, attribute)`` claim.

    Args:
        supporting:        evidence pieces that ASSERT the claim
        contradicting:     evidence pieces that REJECT the claim
        reliability_lookup: pluggable for tests — defaults to live DB

    Returns:
        Confidence in [0.0, 1.0].
    """
    if not supporting:
        return 0.0

    evidence_scores = [e.evidence_score for e in supporting]
    reliabilities   = [reliability_lookup(e.source_tool) for e in supporting]
    base = weighted_mean(evidence_scores, reliabilities)

    # Corroboration counts UNIQUE sources backing the claim — not raw count
    unique_sources = len({e.source_tool for e in supporting})
    bonus = min(MAX_CORROBORATION_BONUS,
                CORROBORATION_PER_SOURCE * unique_sources)

    penalty = CONTRADICTION_PENALTY_UNIT * len(contradicting)

    return max(0.0, min(1.0, base + bonus - penalty))


def confidence_breakdown(
    supporting: Sequence[Evidence],
    contradicting: Sequence[Evidence] = (),
    reliability_lookup=sr.get_reliability,
) -> dict:
    """
    Same computation as compute_confidence, but returns every intermediate
    value. Used by explainability.py to render natural-language traces.
    """
    if not supporting:
        return {
            "base": 0.0, "bonus": 0.0, "penalty": 0.0, "final": 0.0,
            "support_count": 0, "unique_sources": 0,
            "contradiction_count": len(contradicting),
            "weights": [], "evidence_scores": [],
        }

    evidence_scores = [e.evidence_score for e in supporting]
    reliabilities   = [reliability_lookup(e.source_tool) for e in supporting]
    base = weighted_mean(evidence_scores, reliabilities)

    unique_sources = len({e.source_tool for e in supporting})
    bonus = min(MAX_CORROBORATION_BONUS,
                CORROBORATION_PER_SOURCE * unique_sources)
    penalty = CONTRADICTION_PENALTY_UNIT * len(contradicting)
    final = max(0.0, min(1.0, base + bonus - penalty))

    return {
        "base":                base,
        "bonus":               bonus,
        "penalty":             penalty,
        "final":               final,
        "support_count":       len(supporting),
        "unique_sources":      unique_sources,
        "contradiction_count": len(contradicting),
        "weights":             reliabilities,
        "evidence_scores":     evidence_scores,
    }
