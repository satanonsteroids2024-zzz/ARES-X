"""
aresx.decision — TITAN Phase 5: Decision Intelligence Layer

4-question framework + full sub-module suite.
"""
from aresx.decision.decision_support import (
    analyze, export_decision_json, build_decision_tree,
    DecisionSupportOutput, Scenario, RecommendedAction,
)
from aresx.decision.action_recommender import generate_actions
from aresx.decision.decision_modules import (
    compute_cost_benefit, CostBenefitAnalysis,
    detect_opportunities, Opportunity,
    model_risk_impact, RiskImpactMatrix, RiskDimension,
    run_scenario_analysis, ScenarioResult,
    build_decision_tree_full, export_tree_json, TreeNode,
)

PHASE_STATUS = "implemented"

__all__ = [
    "analyze", "export_decision_json", "build_decision_tree",
    "DecisionSupportOutput", "Scenario", "RecommendedAction",
    "generate_actions",
    "compute_cost_benefit", "CostBenefitAnalysis",
    "detect_opportunities", "Opportunity",
    "model_risk_impact", "RiskImpactMatrix", "RiskDimension",
    "run_scenario_analysis", "ScenarioResult",
    "build_decision_tree_full", "export_tree_json", "TreeNode",
    "PHASE_STATUS",
]
