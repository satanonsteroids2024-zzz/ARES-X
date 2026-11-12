"""
ARES X v8.0 — Phase 2.3: Contradiction detection.

Given a set of evidence pieces, group by ``(entity_id, attribute)`` and
flag any group whose values disagree.

Resolution modes (Build Prompt §3 Phase 2.3):
    auto        — pick the value asserted by the highest-reliability source
    human_review — escalate to an analyst via an APPROVAL_GATE_TRIGGERED event
    unresolved  — keep both values, downgrade confidence

This module also publishes ``FUSION_CONTRADICTION`` events to the bus
so downstream watchers (UI, decision support) can react in real time.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Iterable, Sequence

from aresx.events import EventType, bus
from aresx.fusion import source_reliability as sr
from aresx.fusion.types import ContradictionEvent, Evidence

logger = logging.getLogger(__name__)


def _normalize_value(value: str) -> str:
    """Cheap value canonicalisation so trivial typographical differences
    don't register as contradictions. We lower-case, strip whitespace,
    and collapse internal whitespace runs."""
    return " ".join(value.lower().strip().split())


def detect_contradictions(
    evidence: Sequence[Evidence],
    reliability_lookup=sr.get_reliability,
    publish: bool = True,
) -> list[ContradictionEvent]:
    """
    Find all (entity, attribute) groups in ``evidence`` whose values
    disagree, and return one ContradictionEvent per disagreeing pair.

    Args:
        evidence:           list of Evidence
        reliability_lookup: pluggable source reliability fetcher
        publish:            whether to emit FUSION_CONTRADICTION on the bus

    The returned list contains pairwise contradictions — if 3 sources
    disagree pairwise, you'll get 3 events. The fusion engine handles
    deduplication when persisting to the ``contradictions`` table.
    """
    # Group by (entity_id, attribute)
    groups: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
    for e in evidence:
        groups[(e.entity_id, e.attribute)].append(e)

    contradictions: list[ContradictionEvent] = []
    for (entity_id, attribute), items in groups.items():
        if len(items) < 2:
            continue
        # Bucket by normalised value
        by_value: dict[str, list[Evidence]] = defaultdict(list)
        for ev in items:
            by_value[_normalize_value(ev.value)].append(ev)
        if len(by_value) < 2:
            continue
        # Each pair of distinct value-buckets is a contradiction
        value_groups = list(by_value.items())
        for i in range(len(value_groups)):
            for j in range(i + 1, len(value_groups)):
                ev_a = value_groups[i][1][0]
                ev_b = value_groups[j][1][0]
                resolution_mode, resolved_value = _auto_resolve(
                    ev_a, ev_b, reliability_lookup,
                )
                event = ContradictionEvent(
                    entity_id=entity_id,
                    attribute=attribute,
                    evidence_a=ev_a,
                    evidence_b=ev_b,
                    resolution_mode=resolution_mode,
                    resolved_value=resolved_value,
                )
                contradictions.append(event)

    if publish and contradictions:
        for c in contradictions:
            try:
                bus.publish_sync(
                    EventType.FUSION_CONTRADICTION,
                    payload={
                        "entity_id":       c.entity_id,
                        "attribute":       c.attribute,
                        "value_a":         c.evidence_a.value,
                        "value_b":         c.evidence_b.value,
                        "source_a":        c.evidence_a.source_tool,
                        "source_b":        c.evidence_b.source_tool,
                        "resolution_mode": c.resolution_mode,
                        "resolved_value":  c.resolved_value,
                    },
                    source="fusion.contradiction",
                    correlation_id=c.entity_id,
                )
            except Exception as exc:
                logger.error("Failed to publish contradiction event: %s", exc)

    return contradictions


def _auto_resolve(ev_a: Evidence, ev_b: Evidence,
                  reliability_lookup) -> tuple[str, str | None]:
    """
    Decide whether a contradiction can be auto-resolved.

    Rule: if the two sources differ in reliability by ≥ 0.15, the more
    reliable one wins. Otherwise human review is required.
    """
    rel_a = reliability_lookup(ev_a.source_tool)
    rel_b = reliability_lookup(ev_b.source_tool)
    delta = abs(rel_a - rel_b)
    if delta >= 0.15:
        winner = ev_a if rel_a > rel_b else ev_b
        return "auto", winner.value
    return "human_review", None


def partition_supporting_contradicting(
    evidence: Sequence[Evidence],
    asserted_value: str,
) -> tuple[list[Evidence], list[Evidence]]:
    """
    Split an evidence list into pieces that SUPPORT ``asserted_value``
    versus pieces that CONTRADICT it. Used by the engine when it has
    chosen a single best value for the attribute.
    """
    target = _normalize_value(asserted_value)
    supporting:    list[Evidence] = []
    contradicting: list[Evidence] = []
    for e in evidence:
        if _normalize_value(e.value) == target:
            supporting.append(e)
        else:
            contradicting.append(e)
    return supporting, contradicting
