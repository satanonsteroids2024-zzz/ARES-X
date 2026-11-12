"""
aresx.simulation — TITAN Phase 6: Simulation & Wargaming

Threat propagation, what-if analysis, economic impact modeling,
red/blue team wargaming with MITRE ATT&CK.
"""
from aresx.simulation.simulation_engine import (
    run_threat_propagation,
    run_what_if,
    run_wargame,
    estimate_economic_impact,
    SimGraph,
    PropagationResult,
    WhatIfResult,
    WargameResult,
    EconomicImpactResult,
)

PHASE_STATUS = "implemented"

__all__ = [
    "run_threat_propagation", "run_what_if", "run_wargame",
    "estimate_economic_impact", "SimGraph",
    "PropagationResult", "WhatIfResult", "WargameResult", "EconomicImpactResult",
    "PHASE_STATUS",
]
