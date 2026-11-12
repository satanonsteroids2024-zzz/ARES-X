"""
ARES X v8.0 — Phase 3.8: Twin Builder (Main Orchestrator).

Routes twin build requests to the correct twin type module.
Manages concurrent builds (max 5 parallel per spec).
Publishes progress events throughout.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from aresx.events import EventType, bus

logger = logging.getLogger(__name__)

# Max concurrent twin builds (spec: 5)
_MAX_CONCURRENT: int = 5
_semaphore: Optional[asyncio.Semaphore] = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(_MAX_CONCURRENT)
    return _semaphore


async def build_twin(twin_type: str, entity_name: str, **kwargs: Any) -> dict:
    """
    Main entry point. Routes to the correct twin builder.

    Args:
        twin_type: "org" | "infra" | "adversary" | "human" | "supply_chain" | "cyber_terrain"
        entity_name: name of the entity to twin
        **kwargs: twin-type-specific arguments (e.g. gate_id for human twin)

    Returns:
        dict with twin build result fields.
    """
    async with _get_semaphore():
        if twin_type == "org":
            from aresx.domains.twin.twins.org_twin import build_org_twin
            result = await build_org_twin(entity_name,
                                           force_rebuild=kwargs.get("force_rebuild", False))
            return {
                "twin_id":         result.twin_id,
                "twin_type":       "org",
                "entity_name":     result.entity_name,
                "entity_count":    len(result.entities),
                "edge_count":      len(result.edges),
                "confidence_score": result.confidence_score,
                "risk_score":      result.risk_score,
                "snapshot_id":     result.snapshot_id,
                "build_duration_s": result.build_duration_s,
            }

        elif twin_type == "infra":
            from aresx.domains.twin.twins.infra_twin import build_infra_twin
            result = await build_infra_twin(entity_name)
            return {
                "twin_id":         result.twin_id,
                "twin_type":       "infra",
                "entity_name":     result.root_domain,
                "node_count":      len(result.nodes),
                "edge_count":      len(result.edges),
                "exposure_score":  result.exposure_score,
                "snapshot_id":     result.snapshot_id,
                "build_duration_s": result.build_duration_s,
            }

        elif twin_type == "adversary":
            from aresx.domains.twin.twins.adversary_twin import build_adversary_twin
            result = await build_adversary_twin(entity_name)
            return {
                "twin_id":          result.twin_id,
                "twin_type":        "adversary",
                "entity_name":      result.actor_name,
                "ttp_count":        len(result.known_ttps),
                "infra_count":      len(result.known_infrastructure),
                "sophistication":   result.sophistication,
                "snapshot_id":      result.snapshot_id,
                "build_duration_s": result.build_duration_s,
            }

        elif twin_type == "human":
            gate_id = kwargs.get("gate_id")
            if not gate_id:
                raise ValueError("Human twin requires gate_id (privacy gate)")
            from aresx.domains.twin.twins.human_twin import build_human_twin
            result = build_human_twin(entity_name, gate_id)
            return {
                "twin_id":          result.twin_id,
                "twin_type":        "human",
                "entity_name":      result.subject_name,
                "privacy_gate_id":  result.privacy_gate_id,
                "snapshot_id":      result.snapshot_id,
                "build_duration_s": result.build_duration_s,
            }

        elif twin_type == "supply_chain":
            org_twin_id = kwargs.get("org_twin_id")
            if not org_twin_id:
                raise ValueError("supply_chain twin requires org_twin_id")
            from aresx.domains.twin.twins.supply_chain_and_cyber_terrain import build_supply_chain_twin
            result = build_supply_chain_twin(org_twin_id, entity_name)
            return {
                "twin_id":           result.twin_id,
                "twin_type":         "supply_chain",
                "entity_name":       result.org_name,
                "supplier_count":    len(result.supplier_nodes),
                "concentration_risk": result.concentration_risk,
                "snapshot_id":       result.snapshot_id,
                "build_duration_s":  result.build_duration_s,
            }

        elif twin_type == "cyber_terrain":
            infra_twin_id = kwargs.get("infra_twin_id")
            if not infra_twin_id:
                raise ValueError("cyber_terrain twin requires infra_twin_id")
            from aresx.domains.twin.twins.supply_chain_and_cyber_terrain import build_cyber_terrain_twin
            result = build_cyber_terrain_twin(infra_twin_id, entity_name)
            return {
                "twin_id":                result.twin_id,
                "twin_type":              "cyber_terrain",
                "entity_name":            result.domain,
                "attack_surface_count":   len(result.attack_surface_nodes),
                "chokepoint_count":       len(result.chokepoint_nodes),
                "terrain_score":          result.terrain_score,
                "snapshot_id":            result.snapshot_id,
                "build_duration_s":       result.build_duration_s,
            }

        else:
            raise ValueError(f"Unknown twin_type: {twin_type!r}")
