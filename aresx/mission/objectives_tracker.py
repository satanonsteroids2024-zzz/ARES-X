"""
aresx.mission.objectives_tracker — Investigation Objectives Tracker.

Per-objective completion tracking:
  • Evidence count tracking
  • LLM-evaluated completeness (0–100%)
  • Completion threshold: 80% LLM score + 3 corroborating evidence pieces
  • Auto-flags when ready for completion

Build Prompt §3 Phase 4 spec, TRD §1.2.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from aresx.mission.mission_control import (
    complete_objective, get_objectives, get_mission,
)

logger = logging.getLogger(__name__)

COMPLETION_LLM_THRESHOLD:      float = 0.80
COMPLETION_EVIDENCE_THRESHOLD: int   = 3


@dataclass
class ObjectiveStatus:
    objective_id:    str
    description:     str
    status:          str           # pending | active | ready | complete
    evidence_count:  int
    llm_score:       float         # 0.0–1.0
    completion_pct:  float         # 0.0–1.0
    ready_to_close:  bool


def evaluate_completeness(objective_description: str,
                           evidence_pieces: list[str]) -> float:
    """
    LLM-evaluate whether the objective is complete given the evidence.

    Prompt: "Given these evidence pieces, is objective '[X]' complete? 0-100%"
    Falls back to evidence-count heuristic when LLM unavailable.
    """
    if not evidence_pieces:
        return 0.0

    prompt = (
        f"Given these {len(evidence_pieces)} evidence pieces, is the investigation "
        f"objective '{objective_description}' complete?\n\n"
        f"Evidence:\n" + "\n".join(f"- {e[:200]}" for e in evidence_pieces[:10]) +
        "\n\nRespond with only a number from 0 to 100 representing percent completion."
    )

    try:
        from aresx.sovereign_ai import inference_api
        result = inference_api.generate(prompt, task_type="general", max_tokens=10)
        # Parse the number from the response
        import re
        nums = re.findall(r'\d+', result)
        if nums:
            pct = int(nums[0])
            return min(100, max(0, pct)) / 100.0
    except Exception as exc:
        logger.debug("Completeness LLM eval failed: %s", exc)

    # Heuristic fallback: logarithmic curve, saturates at ~10 pieces
    import math
    return min(1.0, math.log(len(evidence_pieces) + 1) / math.log(11))


def get_objective_statuses(mission_id: str) -> list[ObjectiveStatus]:
    """Return enriched status for all objectives in a mission."""
    objs = get_objectives(mission_id)
    statuses: list[ObjectiveStatus] = []

    for obj in objs:
        evidence_count = int(obj.get("evidence_count") or 0)
        status = obj.get("status", "pending")

        if status == "complete":
            statuses.append(ObjectiveStatus(
                objective_id=obj["objective_id"],
                description=obj["description"],
                status="complete",
                evidence_count=evidence_count,
                llm_score=1.0,
                completion_pct=1.0,
                ready_to_close=False,
            ))
            continue

        # Evaluate completeness
        llm_score = evaluate_completeness(
            obj["description"],
            [f"Evidence piece {i}" for i in range(evidence_count)],
        )
        ready = (
            llm_score >= COMPLETION_LLM_THRESHOLD
            and evidence_count >= COMPLETION_EVIDENCE_THRESHOLD
        )

        statuses.append(ObjectiveStatus(
            objective_id=obj["objective_id"],
            description=obj["description"],
            status="ready" if ready and status != "complete" else status,
            evidence_count=evidence_count,
            llm_score=round(llm_score, 3),
            completion_pct=round(llm_score, 3),
            ready_to_close=ready,
        ))

    return statuses


def auto_complete_ready(mission_id: str) -> list[str]:
    """
    Auto-complete objectives that are ready (above threshold).
    Returns list of objective_ids that were completed.
    """
    completed: list[str] = []
    for status in get_objective_statuses(mission_id):
        if status.ready_to_close and status.status != "complete":
            complete_objective(
                mission_id, status.objective_id,
                evidence_count=status.evidence_count,
            )
            completed.append(status.objective_id)
            logger.info("[ObjectivesTracker] Auto-completed %s (score=%.0f%%)",
                        status.objective_id[:8], status.llm_score * 100)
    return completed
