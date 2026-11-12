"""
ARES X v8.0 — Phase 3.6: Supply Chain + Cyber Terrain Twins.

Both twin types derive from org_twin and infra_twin respectively —
they add a semantic layer on top of an existing twin's graph rather
than performing independent collection.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from aresx.domains.twin.twin_store import (
    create_twin, get_twin, load_snapshot, list_snapshots,
    save_snapshot, update_twin_status,
)
from aresx.events import EventType, bus

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Supply Chain Twin
# ──────────────────────────────────────────────────────────────

@dataclass
class SupplyChainTwinResult:
    twin_id: str
    org_name: str
    supplier_nodes: list[dict]
    supply_chain_edges: list[dict]
    concentration_risk: float
    snapshot_id: str
    build_duration_s: float


def build_supply_chain_twin(org_twin_id: str, org_name: str) -> SupplyChainTwinResult:
    """
    Build supply chain twin derived from an existing org_twin.
    Reads the org twin's graph and extracts supplier / technology relationships.
    """
    t0 = time.time()
    twin_id = create_twin("supply_chain", f"supply_chain:{org_name}")

    bus.publish_sync(
        EventType.TWIN_BUILD_STARTED,
        payload={"twin_id": twin_id, "entity_name": org_name, "twin_type": "supply_chain"},
        source="digital_twin.supply_chain_twin",
        correlation_id=twin_id,
    )

    # Load parent org twin's snapshot
    snap_ids = list_snapshots(org_twin_id)
    supplier_nodes: list[dict] = []
    supply_chain_edges: list[dict] = []

    if snap_ids:
        state = load_snapshot(snap_ids[0])
        if state:
            for node in state.get("nodes", []):
                if node.get("entity_type") in ("Technology", "Organization", "Investor"):
                    supplier_nodes.append({
                        "node_id":     node.get("entity_id", str(uuid.uuid4())),
                        "name":        node["name"],
                        "entity_type": node["entity_type"],
                        "source":      node.get("source", "derived"),
                        "risk_tier":   _supplier_risk_tier(node),
                    })
                    supply_chain_edges.append({
                        "from_id":       org_twin_id,
                        "to_id":         node.get("entity_id", ""),
                        "relation_type": "depends_on",
                    })

    # Concentration risk: fraction of nodes that are single-vendor dependencies
    concentration_risk = min(1.0, len(supplier_nodes) * 0.05)

    graph_state = {
        "org_twin_id":   org_twin_id,
        "suppliers":     supplier_nodes,
        "edges":         supply_chain_edges,
        "concentration_risk": concentration_risk,
    }
    snapshot_id = save_snapshot(twin_id, graph_state)
    update_twin_status(twin_id, "active", 1.0 - concentration_risk)

    duration = time.time() - t0

    bus.publish_sync(
        EventType.TWIN_BUILT,
        payload={
            "twin_id": twin_id, "entity_name": org_name, "twin_type": "supply_chain",
            "supplier_count": len(supplier_nodes), "build_duration_s": duration,
        },
        source="digital_twin.supply_chain_twin",
        correlation_id=twin_id,
    )

    return SupplyChainTwinResult(
        twin_id=twin_id, org_name=org_name,
        supplier_nodes=supplier_nodes, supply_chain_edges=supply_chain_edges,
        concentration_risk=concentration_risk,
        snapshot_id=snapshot_id, build_duration_s=duration,
    )


def _supplier_risk_tier(node: dict) -> str:
    name = node.get("name", "").lower()
    high_risk_terms = {"china", "russia", "iran", "north korea", "darknet"}
    if any(t in name for t in high_risk_terms):
        return "high"
    if node.get("entity_type") == "Technology":
        return "medium"
    return "low"


# ──────────────────────────────────────────────────────────────
# Cyber Terrain Twin
# ──────────────────────────────────────────────────────────────

@dataclass
class CyberTerrainTwinResult:
    twin_id: str
    domain: str
    attack_surface_nodes: list[dict]
    chokepoint_nodes: list[dict]
    terrain_score: float
    snapshot_id: str
    build_duration_s: float


def build_cyber_terrain_twin(infra_twin_id: str, domain: str) -> CyberTerrainTwinResult:
    """
    Build cyber terrain twin derived from infra_twin.
    Identifies attack surface, chokepoints, and lateral movement paths.
    """
    t0 = time.time()
    twin_id = create_twin("cyber_terrain", f"cyber_terrain:{domain}")

    bus.publish_sync(
        EventType.TWIN_BUILD_STARTED,
        payload={"twin_id": twin_id, "entity_name": domain, "twin_type": "cyber_terrain"},
        source="digital_twin.cyber_terrain_twin",
        correlation_id=twin_id,
    )

    snap_ids = list_snapshots(infra_twin_id)
    attack_surface: list[dict] = []
    chokepoints: list[dict] = []

    if snap_ids:
        state = load_snapshot(snap_ids[0])
        if state:
            degree_count: dict[str, int] = {}
            for edge in state.get("edges", []):
                degree_count[edge["to_id"]] = degree_count.get(edge["to_id"], 0) + 1

            for node in state.get("nodes", []):
                if node.get("node_type") == "IP":
                    ports = node.get("attributes", {}).get("ports", [])
                    attack_surface.append({
                        "node_id":   node.get("node_id"),
                        "name":      node.get("name"),
                        "open_ports": ports,
                        "exposure":   _port_exposure(ports),
                    })
                nid = node.get("entity_id") or node.get("node_id", "")
                if degree_count.get(nid, 0) >= 3:
                    chokepoints.append({"node_id": nid, "name": node.get("name"),
                                        "in_degree": degree_count[nid]})

    terrain_score = min(1.0, len(attack_surface) * 0.05 + len(chokepoints) * 0.1)
    graph_state = {
        "domain": domain, "infra_twin_id": infra_twin_id,
        "attack_surface": attack_surface, "chokepoints": chokepoints,
    }
    snapshot_id = save_snapshot(twin_id, graph_state)
    update_twin_status(twin_id, "active", 1.0 - terrain_score)
    duration = time.time() - t0

    bus.publish_sync(
        EventType.TWIN_BUILT,
        payload={
            "twin_id": twin_id, "entity_name": domain, "twin_type": "cyber_terrain",
            "attack_surface_count": len(attack_surface),
            "chokepoint_count": len(chokepoints), "build_duration_s": duration,
        },
        source="digital_twin.cyber_terrain_twin", correlation_id=twin_id,
    )

    return CyberTerrainTwinResult(
        twin_id=twin_id, domain=domain,
        attack_surface_nodes=attack_surface, chokepoint_nodes=chokepoints,
        terrain_score=terrain_score,
        snapshot_id=snapshot_id, build_duration_s=duration,
    )


def _port_exposure(ports: list[int]) -> str:
    risky = {21, 23, 25, 110, 3389, 5900}
    if any(p in risky for p in ports):
        return "high"
    if any(p in {80, 443, 22} for p in ports):
        return "medium"
    return "low"
