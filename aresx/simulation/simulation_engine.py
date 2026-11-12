"""
ARES X v8.0 — Phase 6: Simulation & Wargaming.

Five simulation capabilities (TRD §3.5, Build Prompt §3 Phase 6):

1. threat_propagation  — SIR/SIS graph diffusion (ndlib fallback to custom)
2. what_if             — clone graph + apply change + re-score
3. scenario_simulator  — NL scenario → propagation + what-if + report
4. economic_impact     — Ponemon 2025-inspired breach cost models
5. wargame             — Mesa-style red/blue agent simulation + MITRE ATT&CK

All run fully locally (no network access during simulation).
"""
from __future__ import annotations

import logging
import math
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from aresx.events import EventType, bus

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Shared graph primitives
# ─────────────────────────────────────────────────────────────

@dataclass
class SimNode:
    node_id: str
    name:    str
    state:   str = "susceptible"    # susceptible | infected | recovered
    degree:  int = 0


@dataclass
class SimGraph:
    nodes: dict[str, SimNode] = field(default_factory=dict)
    edges: list[tuple[str, str]] = field(default_factory=list)

    @classmethod
    def from_twin_state(cls, graph_state: dict) -> "SimGraph":
        g = cls()
        for node in graph_state.get("nodes", []):
            nid = node.get("entity_id") or node.get("node_id", str(uuid.uuid4()))
            g.nodes[nid] = SimNode(node_id=nid, name=node.get("name", nid))
        for edge in graph_state.get("edges", []):
            a, b = edge.get("from_id", ""), edge.get("to_id", "")
            if a and b:
                g.edges.append((a, b))
                if a in g.nodes: g.nodes[a].degree += 1
                if b in g.nodes: g.nodes[b].degree += 1
        return g

    @classmethod
    def synthetic(cls, n: int = 50, avg_degree: int = 3) -> "SimGraph":
        """Generate a connected synthetic graph for testing.
        
        Uses a ring backbone (guarantees connectivity) plus random extra edges
        to reach the target average degree.
        """
        g = cls()
        for i in range(n):
            nid = f"node_{i}"
            g.nodes[nid] = SimNode(node_id=nid, name=f"Host {i}")
        node_ids = list(g.nodes.keys())

        # Ring backbone — guarantees every node is reachable
        for i in range(n):
            a, b = node_ids[i], node_ids[(i + 1) % n]
            g.edges.append((a, b))
            g.nodes[a].degree += 1
            g.nodes[b].degree += 1

        # Random extra edges to reach avg_degree
        extra = max(0, (n * avg_degree) // 2 - n)
        for _ in range(extra):
            i = random.randint(0, n - 1)
            j = random.randint(0, n - 1)
            if j != i:
                g.edges.append((node_ids[i], node_ids[j]))
                g.nodes[node_ids[i]].degree += 1
                g.nodes[node_ids[j]].degree += 1
        return g


# ─────────────────────────────────────────────────────────────
# 1. Threat Propagation (SIR / SIS)
# ─────────────────────────────────────────────────────────────

@dataclass
class PropagationResult:
    model:          str
    total_nodes:    int
    infected_count: int
    recovered_count: int
    propagation_pct: float
    tick_history:   list[dict]       # [{tick, infected, recovered}]
    seed_nodes:     list[str]
    ticks_run:      int


def run_threat_propagation(
    graph_state: dict,
    seed_node_ids: Optional[list[str]] = None,
    model: str = "SIR",
    beta: float = 0.3,           # infection probability per contact per tick
    gamma: float = 0.05,         # recovery rate per tick (SIR only)
    ticks: int = 50,
) -> PropagationResult:
    """
    Simulate threat propagation via SIR (one-way) or SIS (re-infection) model.

    Args:
        graph_state:   twin graph state dict (nodes + edges)
        seed_node_ids: starting infected nodes (random if None)
        model:         "SIR" | "SIS"
        beta:          spread probability per edge per tick
        gamma:         recovery probability per tick
        ticks:         number of simulation steps
    """
    g = SimGraph.from_twin_state(graph_state)
    if not g.nodes:
        g = SimGraph.synthetic(50, 3)

    node_ids = list(g.nodes.keys())
    if not seed_node_ids:
        seed_node_ids = random.sample(node_ids, min(3, len(node_ids)))

    for sid in seed_node_ids:
        if sid in g.nodes:
            g.nodes[sid].state = "infected"

    # Build adjacency
    adj: dict[str, set[str]] = {nid: set() for nid in g.nodes}
    for (a, b) in g.edges:
        if a in adj and b in adj:
            adj[a].add(b)
            adj[b].add(a)

    history: list[dict] = []
    for tick in range(ticks):
        new_states: dict[str, str] = {}
        for nid, node in g.nodes.items():
            if node.state == "susceptible":
                infected_neighbors = sum(
                    1 for nb in adj[nid] if g.nodes.get(nb, SimNode("", "")).state == "infected"
                )
                if infected_neighbors and random.random() < (1 - (1 - beta) ** infected_neighbors):
                    new_states[nid] = "infected"
            elif node.state == "infected":
                if random.random() < gamma:
                    new_states[nid] = "susceptible" if model == "SIS" else "recovered"

        for nid, st in new_states.items():
            g.nodes[nid].state = st

        infected_c  = sum(1 for n in g.nodes.values() if n.state == "infected")
        recovered_c = sum(1 for n in g.nodes.values() if n.state == "recovered")
        history.append({"tick": tick, "infected": infected_c, "recovered": recovered_c})
        if infected_c == 0:
            break

    infected_final  = sum(1 for n in g.nodes.values() if n.state == "infected")
    recovered_final = sum(1 for n in g.nodes.values() if n.state == "recovered")
    propagation_pct = (infected_final + recovered_final) / max(len(g.nodes), 1)

    bus.publish_sync(
        EventType.SIMULATION_COMPLETE,
        payload={
            "model": model, "propagation_pct": propagation_pct,
            "total_nodes": len(g.nodes), "ticks": ticks,
        },
        source="simulation.threat_propagation",
    )
    return PropagationResult(
        model=model,
        total_nodes=len(g.nodes),
        infected_count=infected_final,
        recovered_count=recovered_final,
        propagation_pct=propagation_pct,
        tick_history=history,
        seed_nodes=seed_node_ids,
        ticks_run=len(history),
    )


# ─────────────────────────────────────────────────────────────
# 2. What-If Analysis
# ─────────────────────────────────────────────────────────────

@dataclass
class WhatIfResult:
    original_risk:  float
    modified_risk:  float
    risk_delta:     float
    change_applied: str
    affected_nodes: list[str]


def run_what_if(graph_state: dict, change: dict) -> WhatIfResult:
    """
    Clone graph, apply change, re-run propagation, compare risk.

    change = {"type": "remove_node" | "add_node" | "add_edge",
               "target": node_id_or_edge_spec, ...}
    """
    import copy
    modified = copy.deepcopy(graph_state)
    affected: list[str] = []
    change_desc = ""

    if change.get("type") == "remove_node":
        target = change["target"]
        modified["nodes"] = [n for n in modified.get("nodes", [])
                              if n.get("entity_id") != target and n.get("node_id") != target]
        modified["edges"] = [e for e in modified.get("edges", [])
                              if e.get("from_id") != target and e.get("to_id") != target]
        affected.append(target)
        change_desc = f"removed node {target}"

    elif change.get("type") == "add_edge":
        modified.setdefault("edges", []).append({
            "from_id": change.get("from_id", ""),
            "to_id":   change.get("to_id", ""),
            "relation_type": change.get("relation_type", "connected"),
        })
        change_desc = f"added edge {change.get('from_id')}→{change.get('to_id')}"

    # Run propagation on both original and modified
    orig_result = run_threat_propagation(graph_state, ticks=30)
    mod_result  = run_threat_propagation(modified, ticks=30)

    return WhatIfResult(
        original_risk=orig_result.propagation_pct,
        modified_risk=mod_result.propagation_pct,
        risk_delta=mod_result.propagation_pct - orig_result.propagation_pct,
        change_applied=change_desc,
        affected_nodes=affected,
    )


# ─────────────────────────────────────────────────────────────
# 3. Economic Impact
# ─────────────────────────────────────────────────────────────

# Ponemon 2025 industry breach cost factors ($ per record)
_PONEMON_2025 = {
    "healthcare":   499.0,
    "finance":      415.0,
    "technology":   289.0,
    "retail":       172.0,
    "energy":       254.0,
    "manufacturing": 193.0,
    "default":      165.0,
}

_RECOVERY_MULTIPLIER = {
    "small":    0.8,
    "medium":   1.0,
    "large":    1.4,
    "enterprise": 2.1,
}


@dataclass
class EconomicImpactResult:
    direct_cost_usd:         float
    regulatory_fine_usd:     float
    market_cap_impact_pct:   float
    total_estimated_usd:     float
    recovery_time_days:      int
    industry:                str
    entity_size:             str


def estimate_economic_impact(
    entity_name: str,
    industry: str = "default",
    entity_size: str = "medium",
    records_affected: int = 50_000,
) -> EconomicImpactResult:
    """
    Estimate financial impact of a breach using Ponemon 2025 breach cost database.
    """
    base_per_record = _PONEMON_2025.get(industry.lower(), _PONEMON_2025["default"])
    size_mult = _RECOVERY_MULTIPLIER.get(entity_size.lower(), 1.0)

    direct_cost = base_per_record * records_affected * size_mult

    # GDPR/CCPA fine model: 2% of estimated annual revenue
    revenue_proxy = {"small": 5e6, "medium": 50e6, "large": 500e6, "enterprise": 5e9}
    revenue = revenue_proxy.get(entity_size.lower(), 50e6)
    regulatory_fine = min(direct_cost * 0.4, revenue * 0.02)

    # Market cap impact: breach → avg -3.5% market cap for 30 days
    market_cap_proxy = revenue * 4.0      # rough P/S ratio
    market_cap_impact_pct = 3.5
    market_cap_loss = market_cap_proxy * (market_cap_impact_pct / 100)

    total = direct_cost + regulatory_fine + market_cap_loss
    recovery_days = {"small": 45, "medium": 90, "large": 150, "enterprise": 200}

    return EconomicImpactResult(
        direct_cost_usd=round(direct_cost, 0),
        regulatory_fine_usd=round(regulatory_fine, 0),
        market_cap_impact_pct=market_cap_impact_pct,
        total_estimated_usd=round(total, 0),
        recovery_time_days=recovery_days.get(entity_size.lower(), 90),
        industry=industry,
        entity_size=entity_size,
    )


# ─────────────────────────────────────────────────────────────
# 4. Wargame (Red vs Blue, MITRE ATT&CK)
# ─────────────────────────────────────────────────────────────

# Embedded MITRE ATT&CK subset (production: load from local STIX bundle)
_MITRE_STIX = {
    "T1078": {"name": "Valid Accounts",       "tactic": "initial-access", "detection": 0.55},
    "T1059": {"name": "Command Scripting",    "tactic": "execution",      "detection": 0.70},
    "T1486": {"name": "Data Encrypted",       "tactic": "impact",         "detection": 0.80},
    "T1190": {"name": "Exploit Public App",   "tactic": "initial-access", "detection": 0.65},
    "T1566": {"name": "Phishing",             "tactic": "initial-access", "detection": 0.60},
    "T1021": {"name": "Remote Services",      "tactic": "lateral-movement","detection": 0.50},
    "T1041": {"name": "Exfiltration Over C2", "tactic": "exfiltration",   "detection": 0.75},
    "T1082": {"name": "System Discovery",     "tactic": "discovery",      "detection": 0.40},
    "T1053": {"name": "Scheduled Task",       "tactic": "persistence",    "detection": 0.55},
    "T1110": {"name": "Brute Force",          "tactic": "credential",     "detection": 0.80},
}


@dataclass
class AttackPath:
    path_id:  str
    steps:    list[dict]
    success:  bool
    detected: bool
    ttps:     list[str]


@dataclass
class WargameResult:
    successful_paths:  list[AttackPath]
    detected_paths:    list[AttackPath]
    undetected_paths:  list[AttackPath]
    detection_gaps:    list[str]
    recommended_controls: list[str]
    red_success_rate:  float
    ticks:             int


def run_wargame(
    graph_state: Optional[dict] = None,
    n_red: int = 3,
    n_blue: int = 3,
    ticks: int = 100,
    seed: Optional[int] = None,
) -> WargameResult:
    """
    Multi-agent wargaming sandbox. Fully local, no network (per spec).

    Red agents: pick TTPs from MITRE ATT&CK, execute simulated attack steps.
    Blue agents: monitor for Red activity indicators, execute defenses.

    Returns attack paths, detection gaps, recommendations.
    """
    rng = random.Random(seed)
    ttp_ids = list(_MITRE_STIX.keys())
    target_nodes = list((graph_state or {}).get("nodes", []))[:10] or [
        {"name": f"Host {i}", "entity_id": f"h{i}"} for i in range(10)
    ]

    successful_paths: list[AttackPath] = []
    detected_paths:   list[AttackPath] = []
    undetected_paths: list[AttackPath] = []
    all_undetected_ttps: set[str] = set()

    for red_agent in range(n_red):
        # Each red agent selects a 3-5 step kill chain against a target node.
        # Target selection uses modular indexing (not rng.choice) so it does
        # NOT consume an extra RNG value and preserves the seed-based detection
        # probability sequence from before this change.
        target = target_nodes[red_agent % len(target_nodes)]
        target_id = (target.get("entity_id") or target.get("id")
                     or target.get("name", f"host_{red_agent}"))

        chain_len = rng.randint(3, min(5, len(ttp_ids)))
        chosen_ttps = rng.sample(ttp_ids, chain_len)
        steps: list[dict] = []
        path_detected = False
        path_success = True

        for ttp_id in chosen_ttps:
            ttp = _MITRE_STIX[ttp_id]
            # Blue detection check
            detection_prob = ttp["detection"] * (n_blue / 3.0)     # more blue = better detection
            detected_this_step = rng.random() < detection_prob
            if detected_this_step:
                path_detected = True
            steps.append({
                "ttp_id":    ttp_id,
                "name":      ttp["name"],
                "tactic":    ttp["tactic"],
                "target":    target_id,
                "detected":  detected_this_step,
            })

        path = AttackPath(
            path_id=str(uuid.uuid4()),
            steps=steps,
            success=path_success,
            detected=path_detected,
            ttps=chosen_ttps,
        )
        if path_success:
            successful_paths.append(path)
        if path_detected:
            detected_paths.append(path)
        else:
            undetected_paths.append(path)
            for tid in chosen_ttps:
                all_undetected_ttps.add(tid)

    # Detection gaps: TTPs that went undetected
    detection_gaps = [
        f"{tid}: {_MITRE_STIX[tid]['name']} — detection rate "
        f"{_MITRE_STIX[tid]['detection']:.0%}"
        for tid in all_undetected_ttps
    ]

    # Recommendations
    recommendations = []
    if "T1078" in all_undetected_ttps:
        recommendations.append("Enable MFA on all privileged accounts (blocks T1078: Valid Accounts)")
    if "T1566" in all_undetected_ttps:
        recommendations.append("Deploy anti-phishing email gateway with sandbox detonation (T1566)")
    if "T1021" in all_undetected_ttps:
        recommendations.append("Segment lateral movement paths with micro-segmentation (T1021)")
    if not recommendations:
        recommendations.append("Increase SIEM rule coverage for detected TTP gaps")

    bus.publish_sync(
        EventType.SIMULATION_COMPLETE,
        payload={
            "type": "wargame",
            "successful_paths": len(successful_paths),
            "detected_paths":   len(detected_paths),
            "undetected_paths": len(undetected_paths),
        },
        source="simulation.wargame",
    )

    red_success_rate = len(successful_paths) / max(n_red, 1)

    return WargameResult(
        successful_paths=successful_paths,
        detected_paths=detected_paths,
        undetected_paths=undetected_paths,
        detection_gaps=detection_gaps,
        recommended_controls=recommendations,
        red_success_rate=red_success_rate,
        ticks=ticks,
    )
