"""aresx.decision.action_recommender — Ranked Action Recommendations with benefit/cost filter."""
from __future__ import annotations
from typing import Optional
from aresx.decision.decision_support import RecommendedAction


def generate_actions(mission_id: str, context: Optional[dict] = None) -> list[RecommendedAction]:
    """Generate candidate actions for a mission. Filters to benefit/cost ratio > 1.5."""
    from aresx.mission.mission_control import get_mission, get_objectives
    mission = get_mission(mission_id) or {}
    objs = get_objectives(mission_id)
    goal = mission.get("goal", "")
    goal_lower = goal.lower()
    completed = [o for o in objs if o["status"] == "complete"]
    candidates = []
    if completed:
        candidates.append(RecommendedAction(
            action="Add all identified entities to active watchlist",
            reasoning=f"Continuous monitoring for {len(completed)} discovered entities",
            urgency="high", confidence=0.85, benefit_cost_ratio=3.2,
            supporting_evidence=[o["objective_id"] for o in completed[:3]],
        ))
    if len(completed) >= 3:
        candidates.append(RecommendedAction(
            action="Generate executive intelligence brief and distribute to stakeholders",
            reasoning="Investigation has sufficient findings to produce actionable brief",
            urgency="medium", confidence=0.80, benefit_cost_ratio=2.4,
        ))
    if "infrastructure" in goal_lower or "domain" in goal_lower:
        candidates.append(RecommendedAction(
            action="Request infrastructure attribution from threat intelligence vendor",
            reasoning="Professional attribution increases legal admissibility",
            urgency="low", confidence=0.60, benefit_cost_ratio=1.7,
        ))
    if "financial" in goal_lower or "threat" in goal_lower:
        candidates.append(RecommendedAction(
            action="Escalate to incident response team with full evidence package",
            reasoning="Financial/threat indicators warrant professional IR engagement",
            urgency="critical", confidence=0.90, benefit_cost_ratio=4.1,
        ))
    filtered = [a for a in candidates if a.benefit_cost_ratio > 1.5]
    filtered.sort(key=lambda a: (
        {"critical":0,"high":1,"medium":2,"low":3}.get(a.urgency, 9),
        -a.benefit_cost_ratio
    ))
    return filtered


def compute_cost_benefit(action: str, **kwargs) -> dict:
    """Wrapper around decision_modules.compute_cost_benefit."""
    from aresx.decision.decision_modules import compute_cost_benefit as _cb
    return _cb(action, **kwargs)
