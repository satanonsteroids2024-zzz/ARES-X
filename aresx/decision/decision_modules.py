"""
aresx.decision — Decision sub-modules.
  cost_benefit.py, opportunity_detector.py, risk_impact.py,
  scenario_analysis.py, decision_tree.py
All conform to the TRD §1.2 interface spec.
"""
from __future__ import annotations

# ── cost_benefit.py ──────────────────────────────────────────
from dataclasses import dataclass, field
from typing import Any, Optional
import time


@dataclass
class CostBenefitAnalysis:
    action:              str
    cost_time_hours:     float
    cost_resource:       float         # 0–1 (normalized)
    cost_relationship:   float         # risk to relationships 0–1
    cost_legal:          float         # legal risk 0–1
    benefit_threat_reduction: float    # 0–1
    benefit_opportunity:      float    # opportunity value 0–1
    benefit_urgency_multiplier: float  # 1.0+
    benefit_score:       float         # computed
    cost_score:          float         # computed
    net_ratio:           float         # benefit/cost


def compute_cost_benefit(
    action: str,
    cost_time_hours: float = 2.0,
    cost_resource: float = 0.3,
    cost_relationship: float = 0.1,
    cost_legal: float = 0.05,
    benefit_threat_reduction: float = 0.6,
    benefit_opportunity: float = 0.4,
    urgency: str = "medium",
) -> CostBenefitAnalysis:
    urgency_mult = {"low": 0.8, "medium": 1.0, "high": 1.5, "critical": 2.5}.get(urgency, 1.0)
    benefit_score = (
        benefit_threat_reduction * 0.5 +
        benefit_opportunity * 0.3 +
        urgency_mult * 0.2
    )
    cost_score = (
        min(1.0, cost_time_hours / 40) * 0.4 +
        cost_resource * 0.3 +
        cost_relationship * 0.2 +
        cost_legal * 0.1
    )
    ratio = benefit_score / max(cost_score, 0.001)
    return CostBenefitAnalysis(
        action=action,
        cost_time_hours=cost_time_hours,
        cost_resource=cost_resource,
        cost_relationship=cost_relationship,
        cost_legal=cost_legal,
        benefit_threat_reduction=benefit_threat_reduction,
        benefit_opportunity=benefit_opportunity,
        benefit_urgency_multiplier=urgency_mult,
        benefit_score=round(benefit_score, 4),
        cost_score=round(cost_score, 4),
        net_ratio=round(ratio, 3),
    )


# ── opportunity_detector.py ──────────────────────────────────
@dataclass
class Opportunity:
    title:       str
    description: str
    signal:      str
    probability: float
    time_window: str


def detect_opportunities(graph_entities: list[dict]) -> list[Opportunity]:
    """
    Detect non-threat opportunities from the knowledge graph.
    Signals: financial distress + industry = acquisition, security vulnerability
    + strong posture = partnership, regulatory change = first-mover advantage.
    """
    opportunities: list[Opportunity] = []
    entity_names = [e.get("name", "").lower() for e in graph_entities]

    # Acquisition signal
    distress_keywords = {"lawsuit", "layoff", "breach", "restructuring", "debt"}
    if any(any(k in n for k in distress_keywords) for n in entity_names):
        opportunities.append(Opportunity(
            title="Strategic Acquisition Target",
            description="Entity showing financial or operational distress — potential acquisition opportunity",
            signal="financial_distress + same_industry",
            probability=0.40,
            time_window="3-6 months",
        ))

    # Partnership signal
    if len(graph_entities) >= 5:
        opportunities.append(Opportunity(
            title="Intelligence Sharing Partnership",
            description="Multiple corroborated entities suggest shared threat landscape — partnership opportunity",
            signal="shared_threat_actor + complementary_defenses",
            probability=0.55,
            time_window="1-3 months",
        ))

    # Regulatory first-mover
    opportunities.append(Opportunity(
        title="Regulatory Compliance Advantage",
        description="New NIST/ISO controls align with ARES capabilities — first-mover compliance positioning",
        signal="regulatory_change + compliance_posture",
        probability=0.65,
        time_window="6-12 months",
    ))

    return opportunities


# ── risk_impact.py ───────────────────────────────────────────
@dataclass
class RiskDimension:
    dimension:             str     # financial | reputational | operational | legal | personal
    probability:           float
    severity:              float   # 0–1
    time_horizon:          str
    mitigation_available:  bool
    expected_loss:         float   # probability × severity


@dataclass
class RiskImpactMatrix:
    entity:     str
    dimensions: list[RiskDimension]
    overall_risk: float


def model_risk_impact(entity_name: str, evidence_count: int = 0,
                       threat_type: str = "generic") -> RiskImpactMatrix:
    """Multi-dimensional risk impact model: financial, reputational, operational, legal, personal."""
    base_prob = min(0.9, 0.2 + evidence_count * 0.05)

    dims = [
        RiskDimension("financial",     base_prob,       0.7, "0-6 months",  True,  base_prob * 0.7),
        RiskDimension("reputational",  base_prob * 0.8, 0.6, "1-12 months", True,  base_prob * 0.8 * 0.6),
        RiskDimension("operational",   base_prob * 0.6, 0.5, "0-3 months",  True,  base_prob * 0.6 * 0.5),
        RiskDimension("legal",         base_prob * 0.4, 0.4, "6-24 months", False, base_prob * 0.4 * 0.4),
        RiskDimension("personal",      base_prob * 0.3, 0.3, "ongoing",     True,  base_prob * 0.3 * 0.3),
    ]

    if threat_type in ("apt_activity", "credential_breach"):
        dims[0].severity *= 1.5
        dims[0].severity = min(1.0, dims[0].severity)

    overall = sum(d.expected_loss for d in dims) / len(dims)
    return RiskImpactMatrix(entity=entity_name, dimensions=dims,
                             overall_risk=round(overall, 4))


# ── scenario_analysis.py ─────────────────────────────────────
@dataclass
class ScenarioResult:
    name:                 str     # best_case | expected_case | worst_case
    narrative:            str
    probability:          float
    triggering_conditions: list[str]
    early_warnings:       list[str]
    recommended_actions:  list[str]
    financial_exposure:   Optional[float] = None


def run_scenario_analysis(entity_name: str,
                           investigation_context: dict) -> list[ScenarioResult]:
    """
    Three-scenario generator: best / expected / worst case.
    Each scenario: narrative, probability, triggers, warnings, actions.
    """
    threat_level = investigation_context.get("severity", 0.5)

    best = ScenarioResult(
        name="best_case",
        narrative=f"Investigation reveals {entity_name} is a false positive. Monitoring continues with reduced priority.",
        probability=max(0.1, 0.6 - threat_level * 0.5),
        triggering_conditions=["No new indicators", "Third-party confirmation of benign status"],
        early_warnings=["Alert feed goes quiet", "Reliability score increases"],
        recommended_actions=["Archive investigation", "Update watchlist threshold upward"],
    )

    expected = ScenarioResult(
        name="expected_case",
        narrative=f"{entity_name} presents moderate risk requiring active monitoring and targeted response.",
        probability=0.50,
        triggering_conditions=["Continued low-level activity", "1-2 new IOCs per week"],
        early_warnings=["Watchlist change score 0.3-0.6", "New infrastructure registered"],
        recommended_actions=["Escalate watchlist priority", "Share with trusted partners", "Brief leadership"],
    )

    worst = ScenarioResult(
        name="worst_case",
        narrative=f"{entity_name} is confirmed active threat with escalating operations. Incident response required.",
        probability=max(0.05, threat_level * 0.4),
        triggering_conditions=["Active data exfiltration", "Confirmed APT attribution"],
        early_warnings=["Rapid new infrastructure buildup", "TTP match to known adversary"],
        recommended_actions=["Engage IR team immediately", "Notify legal and compliance", "Prepare public disclosure"],
        financial_exposure=500_000.0,
    )

    return [best, expected, worst]


# ── decision_tree.py ─────────────────────────────────────────
@dataclass
class TreeNode:
    node_type: str         # Evidence | Inference | Conclusion | Action
    label:     str
    confidence: float = 1.0
    children:  list["TreeNode"] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "node_type":  self.node_type,
            "label":      self.label,
            "confidence": self.confidence,
            "children":   [c.to_dict() for c in self.children],
        }


def build_decision_tree_full(
    evidence_pieces: list[str],
    inferences: list[str],
    conclusion: str,
    action: str,
    confidence: float = 0.8,
) -> TreeNode:
    """
    Build a full reasoning tree: Evidence → Inference → Conclusion → Action.
    Used by decision_support.build_decision_tree() and exported as JSON.
    Order 15: every recommendation must have an accessible reasoning chain.
    """
    action_node = TreeNode(
        node_type="Action", label=action, confidence=confidence
    )
    conclusion_node = TreeNode(
        node_type="Conclusion", label=conclusion, confidence=confidence,
        children=[action_node],
    )
    # Build evidence leaf nodes — these anchor the reasoning chain (Order 15)
    evidence_nodes = [
        TreeNode(node_type="Evidence", label=e[:120])
        for e in evidence_pieces[:5]
    ]
    # Each inference is supported by the evidence; the first inference leads
    # to the conclusion. Evidence nodes hang off every inference so the full
    # Evidence → Inference → Conclusion → Action chain is traceable.
    inference_nodes = [
        TreeNode(
            node_type="Inference", label=inf,
            confidence=round(confidence * 0.9, 3),
            children=([conclusion_node] if i == 0 else []) + list(evidence_nodes),
        )
        for i, inf in enumerate(inferences[:3])
    ]
    root = TreeNode(
        node_type="Evidence",
        label=f"Investigation evidence ({len(evidence_pieces)} pieces)",
        confidence=1.0,
        children=inference_nodes or ([conclusion_node] + evidence_nodes),
    )
    return root


def export_tree_json(tree: TreeNode) -> dict:
    return tree.to_dict()
