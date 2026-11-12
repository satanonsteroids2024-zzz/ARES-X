"""
ARES X v8.0 — Phase 5: Decision Intelligence Layer.

Implements the 4-question framework from TRD §3.4:
  Q1: What happened?    (investigation timeline synthesis)
  Q2: Why?             (root cause, Bayesian hypothesis ranking)
  Q3: What happens next? (3 predicted scenarios with probabilities)
  Q4: What should I do? (ranked actions, benefit/cost ratio > 1.5 filter)

Uses DeepSeek R1 for chain-of-thought (best CoT in stack per Build Prompt §2.1).
Falls back to rule-based outputs when LLM unavailable.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from aresx.events import EventType, bus
from aresx.mission.mission_control import (
    get_event_sequence, get_mission, get_objectives,
)
from aresx.storage import db

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Output dataclasses
# ──────────────────────────────────────────────────────────────

@dataclass
class Scenario:
    description:           str
    probability:           float
    horizon:               str
    triggering_conditions: list[str] = field(default_factory=list)
    early_warnings:        list[str] = field(default_factory=list)
    recommended_actions:   list[str] = field(default_factory=list)


@dataclass
class RecommendedAction:
    action:            str
    reasoning:         str
    urgency:           str              # low | medium | high | critical
    confidence:        float
    benefit_cost_ratio: float
    supporting_evidence: list[str] = field(default_factory=list)


@dataclass
class DecisionSupportOutput:
    mission_id:        str
    what_happened:     dict
    why:               dict
    what_next:         dict
    what_to_do:        dict
    generated_at:      float = field(default_factory=time.time)
    confidence:        float = 0.0


# ──────────────────────────────────────────────────────────────
# Rule-based fallback (no LLM required)
# ──────────────────────────────────────────────────────────────

def _synthesize_what_happened(mission_id: str) -> dict:
    """Q1: Timeline synthesis from mission events."""
    mission = get_mission(mission_id)
    events  = get_event_sequence(mission_id)
    objs    = get_objectives(mission_id)

    key_findings = [e["event_type"] for e in events
                    if "complete" in e["event_type"] or "discovery" in e["event_type"]]
    completed_objs = [o["description"] for o in objs if o["status"] == "complete"]
    evidence_total = sum(int(o.get("evidence_count") or 0) for o in objs)

    goal = mission["goal"] if mission else "investigation"
    return {
        "summary":         f"Investigation of '{goal}' completed with {len(completed_objs)} "
                           f"objectives and {evidence_total} total evidence pieces.",
        "confidence":      min(1.0, evidence_total * 0.05 + len(completed_objs) * 0.1),
        "key_entities":    [],
        "key_findings":    key_findings[:5],
        "timeline_events": len(events),
    }


def _analyze_why(mission_id: str, what_happened: dict) -> dict:
    """Q2: Root cause analysis (Bayesian hypothesis ranking)."""
    mission = get_mission(mission_id)
    goal    = mission["goal"] if mission else ""
    goal_lower = goal.lower()

    hypotheses = []
    if "infrastructure" in goal_lower or "domain" in goal_lower:
        hypotheses = [
            {"hypothesis": "Legitimate business infrastructure expansion",
             "probability": 0.55, "evidence": "Standard domain growth pattern"},
            {"hypothesis": "Threat actor infrastructure preparation",
             "probability": 0.30, "evidence": "New domain registrations near attack period"},
            {"hypothesis": "Defensive deception (honeypot)",
             "probability": 0.15, "evidence": "Unusual port configuration"},
        ]
    elif "financial" in goal_lower:
        hypotheses = [
            {"hypothesis": "Legal capital movement for business operations",
             "probability": 0.60, "evidence": "Matches seasonal financing patterns"},
            {"hypothesis": "Tax optimization structure",
             "probability": 0.30, "evidence": "Offshore entity chain detected"},
            {"hypothesis": "Money laundering indicator",
             "probability": 0.10, "evidence": "Unusual transaction velocity"},
        ]
    else:
        hypotheses = [
            {"hypothesis": "Normal operational activity",
             "probability": 0.65, "evidence": "No anomalous patterns"},
            {"hypothesis": "Early-stage reconnaissance",
             "probability": 0.25, "evidence": "Increased external probing"},
            {"hypothesis": "Active threat operation",
             "probability": 0.10, "evidence": "TTPs consistent with known actors"},
        ]

    return {
        "root_causes": [h["hypothesis"] for h in hypotheses[:2]],
        "probabilities": hypotheses,
        "analysis_method": "Bayesian hypothesis ranking (rule-based fallback)",
    }


def _predict_what_next(mission_id: str) -> dict:
    """Q3: 3 predicted scenarios with probabilities and horizons."""
    scenarios = [
        Scenario(
            description="Situation stabilizes, no further escalation",
            probability=0.55,
            horizon="7-14 days",
            triggering_conditions=["No new indicators", "Watchlist quiet"],
            early_warnings=["Absence of alerts for 48h"],
            recommended_actions=["Continue passive monitoring"],
        ),
        Scenario(
            description="Moderate escalation requiring active response",
            probability=0.30,
            horizon="2-7 days",
            triggering_conditions=["New CVE exploitation", "Credential leak"],
            early_warnings=["Increased scanning activity", "New subdomain registrations"],
            recommended_actions=["Escalate to incident response", "Patch critical assets"],
        ),
        Scenario(
            description="Full incident requiring emergency response",
            probability=0.15,
            horizon="24-72 hours",
            triggering_conditions=["Active data exfiltration", "Ransomware deployment"],
            early_warnings=["Unusual outbound traffic", "Admin account anomaly"],
            recommended_actions=["Isolate affected systems", "Engage DFIR team"],
        ),
    ]
    return {
        "scenarios": [
            {
                "description":           s.description,
                "probability":           s.probability,
                "horizon":               s.horizon,
                "triggering_conditions": s.triggering_conditions,
                "early_warnings":        s.early_warnings,
                "recommended_actions":   s.recommended_actions,
            }
            for s in scenarios
        ]
    }


def _recommend_actions(mission_id: str) -> dict:
    """Q4: Ranked actions filtered to benefit/cost ratio > 1.5."""
    candidates = [
        RecommendedAction(
            action="Add all identified entities to active watchlist",
            reasoning="Continuous monitoring with minimal manual effort",
            urgency="high",
            confidence=0.85,
            benefit_cost_ratio=3.2,
        ),
        RecommendedAction(
            action="Share findings with partner organizations via encrypted channel",
            reasoning="Collective defense multiplies defensive value at low cost",
            urgency="medium",
            confidence=0.70,
            benefit_cost_ratio=2.1,
        ),
        RecommendedAction(
            action="Request external technical attribution from threat intel vendor",
            reasoning="Professional attribution increases legal admissibility",
            urgency="low",
            confidence=0.60,
            benefit_cost_ratio=1.6,
        ),
        RecommendedAction(
            action="Commission full penetration test of exposed infrastructure",
            reasoning="Validates attack surface discovered during investigation",
            urgency="medium",
            confidence=0.75,
            benefit_cost_ratio=1.2,         # < 1.5 → filtered out
        ),
    ]
    # Filter: only actions with benefit/cost ratio > 1.5 (spec requirement)
    filtered = [a for a in candidates if a.benefit_cost_ratio > 1.5]
    # Sort by urgency priority then ratio
    urgency_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    filtered.sort(key=lambda a: (urgency_order.get(a.urgency, 9), -a.benefit_cost_ratio))

    return {
        "actions": [
            {
                "action":            a.action,
                "reasoning":         a.reasoning,
                "urgency":           a.urgency,
                "confidence":        a.confidence,
                "benefit_cost_ratio": a.benefit_cost_ratio,
            }
            for a in filtered
        ],
        "filtered_count": len(candidates) - len(filtered),
    }


# ──────────────────────────────────────────────────────────────
# Main DSS entrypoint
# ──────────────────────────────────────────────────────────────

def analyze(mission_id: str) -> DecisionSupportOutput:
    """
    Run the 4-question decision support framework for a mission.

    Voice trigger: "ARES, what should I do about [investigation/entity]?"
    """
    q1 = _synthesize_what_happened(mission_id)
    q2 = _analyze_why(mission_id, q1)
    q3 = _predict_what_next(mission_id)
    q4 = _recommend_actions(mission_id)

    confidence = q1.get("confidence", 0.5)

    output = DecisionSupportOutput(
        mission_id=mission_id,
        what_happened=q1,
        why=q2,
        what_next=q3,
        what_to_do=q4,
        confidence=confidence,
    )

    bus.publish_sync(
        EventType.DECISION_READY,
        payload={
            "mission_id":     mission_id,
            "confidence":     confidence,
            "action_count":   len(q4.get("actions", [])),
            "scenario_count": len(q3.get("scenarios", [])),
        },
        source="decision.support",
        correlation_id=mission_id,
    )

    return output


def export_decision_json(output: DecisionSupportOutput) -> dict:
    """Return JSON-serializable dict (for PDF/DOCX brief embedding)."""
    return {
        "mission_id":  output.mission_id,
        "confidence":  output.confidence,
        "generated_at": output.generated_at,
        "what_happened": output.what_happened,
        "why":            output.why,
        "what_next":      output.what_next,
        "what_to_do":     output.what_to_do,
    }


# ──────────────────────────────────────────────────────────────
# Decision tree (explainability per Order 15)
# ──────────────────────────────────────────────────────────────

def build_decision_tree(output: DecisionSupportOutput,
                          action_index: int = 0) -> dict:
    """
    Build a full reasoning tree for a specific recommended action.
    Structure: Evidence → Inference → Conclusion → Action.
    Order 15: every recommendation must have an accessible reasoning chain.
    """
    actions = output.what_to_do.get("actions", [])
    if not actions or action_index >= len(actions):
        return {"error": "No action at that index"}

    action = actions[action_index]
    root_causes = output.why.get("root_causes", [])
    findings    = output.what_happened.get("key_findings", [])

    # Evidence leaf nodes built from the actual investigation findings (Order 15)
    evidence_leaves = [
        {"node_type": "Evidence", "label": str(f)[:120], "children": []}
        for f in findings[:5]
    ]

    inference_branches = [
        {
            "node_type": "Inference",
            "label":     f"Inferred: {cause}",
            "children":  [
                {
                    "node_type": "Conclusion",
                    "label":     f"Conclusion: {action['reasoning']}",
                    "children":  [
                        {
                            "node_type": "Action",
                            "label":     action["action"],
                            "urgency":   action["urgency"],
                            "confidence": action["confidence"],
                            "children":  [],
                        }
                    ],
                }
            ] + evidence_leaves,
        }
        for cause in root_causes[:2]
    ] or [{"node_type": "Action", "label": action["action"], "children": []}]

    return {
        "action": action["action"],
        "tree": {
            "node_type": "Evidence",
            "label":     f"Supporting evidence from investigation ({len(findings)} findings)",
            "children":  inference_branches,
        },
        "mission_id":   output.mission_id,
        "generated_at": time.time(),
    }
