"""
ARES X v8.0 — Phase 3.2: Organization Digital Twin.

The highest-priority twin type. Builds a living model of an organization
from public OSINT sources, stores it in the twin store + Kuzu graph,
and publishes events to the bus on completion.

4-phase pipeline (TRD §3.2):
  Phase 1 — Entity Seed       (parallel, target 30s)
  Phase 2 — Graph Construction (target 40s)
  Phase 3 — Scoring            (target 10s)
  Phase 4 — Twin Registration  (persist, schedule refresh)

Production implementation note
--------------------------------
Full org twin requires: Subfinder, crt.sh, OpenCorporates, SEC EDGAR,
LinkedIn scraper, BuiltWith, NewsAPI. In headless/test environments
these are unavailable; the twin builder falls back to synthetic data
seeded from the entity name so the pipeline and graph structure are
still exercised end-to-end.

Each phase publishes TWIN_BUILD_STARTED / TWIN_BUILT on the event bus
so callers (UI, mission OS) get real-time progress.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from aresx.domains.twin.twin_store import (
    create_twin, find_twin_by_name, get_twin,
    save_snapshot, update_twin_status,
)
from aresx.events import EventType, bus
from aresx.storage import graph

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────────────────────

@dataclass
class OrgEntity:
    """A single entity discovered during the seed phase."""
    entity_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    entity_type: str = "Unknown"         # Person | Domain | Organization | Technology | IP | Investor
    source: str = "unknown"
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class OrgTwinResult:
    """Result returned by build_org_twin()."""
    twin_id: str
    entity_name: str
    entities: list[OrgEntity]
    edges: list[dict]                     # [{"from_id", "to_id", "relation_type", "attributes"}]
    risk_score: float
    confidence_score: float
    freshness_score: float
    snapshot_id: str
    build_duration_s: float


# ──────────────────────────────────────────────────────────────
# Phase 1 — Entity Seed
# ──────────────────────────────────────────────────────────────

async def _seed_domains(org_name: str) -> list[OrgEntity]:
    """crt.sh + Subfinder domain discovery (mock when offline)."""
    await asyncio.sleep(0)          # yield so other seeds run concurrently
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://crt.sh/?q=%.{org_name.lower().replace(' ', '')}.com&output=json"
            )
            if r.status_code == 200:
                data = r.json()
                seen: set[str] = set()
                entities = []
                for entry in data[:20]:
                    name = entry.get("name_value", "")
                    if name and name not in seen:
                        seen.add(name)
                        entities.append(OrgEntity(
                            name=name, entity_type="Domain", source="crt_sh",
                            attributes={"registered_at": entry.get("entry_timestamp")},
                        ))
                return entities
    except Exception as exc:
        logger.debug("crt.sh unavailable: %s", exc)
    # Synthetic fallback
    slug = org_name.lower().replace(" ", "")
    return [
        OrgEntity(name=f"{slug}.com",         entity_type="Domain", source="synthetic"),
        OrgEntity(name=f"api.{slug}.com",      entity_type="Domain", source="synthetic"),
        OrgEntity(name=f"careers.{slug}.com",  entity_type="Domain", source="synthetic"),
    ]


async def _seed_company_registry(org_name: str) -> list[OrgEntity]:
    """OpenCorporates — legal entity, officers."""
    await asyncio.sleep(0)
    try:
        import httpx
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                "https://api.opencorporates.com/v0.4/companies/search",
                params={"q": org_name, "per_page": "3"},
            )
            if r.status_code == 200:
                results = r.json().get("results", {}).get("companies", [])
                entities = []
                for c in results:
                    co = c.get("company", {})
                    entities.append(OrgEntity(
                        name=co.get("name", org_name),
                        entity_type="Organization",
                        source="opencorporates",
                        attributes={
                            "jurisdiction": co.get("jurisdiction_code"),
                            "company_type": co.get("company_type"),
                            "registered_at": co.get("incorporation_date"),
                        },
                    ))
                return entities
    except Exception as exc:
        logger.debug("OpenCorporates unavailable: %s", exc)
    return [OrgEntity(name=org_name, entity_type="Organization", source="synthetic")]


async def _seed_tech_stack(org_name: str) -> list[OrgEntity]:
    """BuiltWith / Wappalyzer — tech fingerprint (synthetic fallback)."""
    await asyncio.sleep(0)
    # Real: call BuiltWith API. Synthetic for CI.
    return [
        OrgEntity(name="Python",     entity_type="Technology", source="synthetic"),
        OrgEntity(name="Kubernetes", entity_type="Technology", source="synthetic"),
        OrgEntity(name="AWS",        entity_type="Technology", source="synthetic"),
    ]


async def _seed_news(org_name: str) -> list[OrgEntity]:
    """NewsAPI / Google News — recent coverage (synthetic)."""
    await asyncio.sleep(0)
    return [
        OrgEntity(
            name=f"Recent news: {org_name}",
            entity_type="NewsItem",
            source="synthetic",
            attributes={"headline": f"{org_name} news (synthetic)"},
        )
    ]


async def _seed_investors(org_name: str) -> list[OrgEntity]:
    """Crunchbase / PitchBook — investor list (synthetic)."""
    await asyncio.sleep(0)
    return [
        OrgEntity(name="Accel Partners",     entity_type="Investor", source="synthetic"),
        OrgEntity(name="Sequoia Capital",     entity_type="Investor", source="synthetic"),
    ]


async def _seed_key_people(org_name: str) -> list[OrgEntity]:
    """LinkedIn headcount + key personnel (synthetic in CI)."""
    await asyncio.sleep(0)
    return [
        OrgEntity(name="Jane Smith",  entity_type="Person",
                  source="synthetic", attributes={"role": "CEO"}),
        OrgEntity(name="Bob Johnson", entity_type="Person",
                  source="synthetic", attributes={"role": "CTO"}),
    ]


async def _phase1_seed(org_name: str) -> list[OrgEntity]:
    """Run all seed tasks in parallel (asyncio.gather per spec)."""
    results = await asyncio.gather(
        _seed_domains(org_name),
        _seed_company_registry(org_name),
        _seed_tech_stack(org_name),
        _seed_news(org_name),
        _seed_investors(org_name),
        _seed_key_people(org_name),
        return_exceptions=True,
    )
    entities: list[OrgEntity] = []
    for r in results:
        if isinstance(r, Exception):
            logger.warning("Seed task failed: %s", r)
        elif isinstance(r, list):
            entities.extend(r)
    # Deduplicate by name+type
    seen: set[tuple[str, str]] = set()
    unique: list[OrgEntity] = []
    for e in entities:
        key = (e.name.lower(), e.entity_type)
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique


# ──────────────────────────────────────────────────────────────
# Phase 2 — Graph Construction
# ──────────────────────────────────────────────────────────────

def _phase2_build_graph(org_entity: OrgEntity,
                        discovered: list[OrgEntity]) -> tuple[list[OrgEntity], list[dict]]:
    """
    Build the entity → relationship graph from discovered entities.
    Returns (all_nodes, edges).
    """
    edges: list[dict] = []
    org_id = org_entity.entity_id

    for entity in discovered:
        if entity.entity_id == org_id:
            continue
        rel = _infer_relation(org_entity, entity)
        if rel:
            edges.append({
                "from_id": org_id,
                "to_id":   entity.entity_id,
                "relation_type": rel,
                "attributes": {},
            })

    # Write to Kuzu when available (Order 20: non-fatal if absent)
    if graph.is_available():
        for e in [org_entity] + discovered:
            try:
                graph.execute(
                    "MERGE (n:Entity {entity_id: $eid}) "
                    "SET n.canonical_name = $name, n.entity_type = $etype",
                    {"eid": e.entity_id, "name": e.name, "etype": e.entity_type},
                )
            except Exception as exc:
                logger.debug("Kuzu entity write: %s", exc)
        for edge in edges:
            try:
                graph.execute(
                    "MATCH (a:Entity {entity_id: $aid}), (b:Entity {entity_id: $bid}) "
                    "MERGE (a)-[:CONNECTED_TO {relation_type: $rel}]->(b)",
                    {"aid": edge["from_id"], "bid": edge["to_id"], "rel": edge["relation_type"]},
                )
            except Exception as exc:
                logger.debug("Kuzu edge write: %s", exc)

    return [org_entity] + discovered, edges


def _infer_relation(org: OrgEntity, entity: OrgEntity) -> Optional[str]:
    """Map entity_type → relationship name."""
    mapping = {
        "Domain":       "uses_domain",
        "Technology":   "uses_technology",
        "Person":       "employs",
        "Organization": "has_subsidiary",
        "Investor":     "has_investor",
        "NewsItem":     "covered_by",
        "IP":           "has_ip",
    }
    return mapping.get(entity.entity_type)


# ──────────────────────────────────────────────────────────────
# Phase 3 — Scoring
# ──────────────────────────────────────────────────────────────

def _phase3_score(entities: list[OrgEntity]) -> tuple[float, float, float]:
    """
    Returns (risk_score, confidence_score, freshness_score).

    Risk score: crude proxy — count of entities with suspicious keywords.
    Confidence: corroborating_sources / total_sources.
    Freshness: always 1.0 right after a fresh build.
    """
    distinct_sources = {e.source for e in entities}
    synthetic_count = sum(1 for e in entities if e.source == "synthetic")
    real_count = len(entities) - synthetic_count
    # Confidence blends real-data ratio with source diversity (more distinct
    # corroborating sources → higher confidence).
    real_ratio = real_count / max(len(entities), 1)
    diversity_bonus = min(0.2, (len(distinct_sources) - 1) * 0.05) if distinct_sources else 0.0
    confidence = min(1.0, real_ratio + diversity_bonus)

    risky_keywords = {"breach", "hack", "lawsuit", "sanction", "malware", "fraud"}
    risk_hits = sum(
        1 for e in entities
        if any(k in e.name.lower() for k in risky_keywords)
    )
    risk_score = min(1.0, risk_hits * 0.1)
    freshness = 1.0
    return risk_score, confidence, freshness


# ──────────────────────────────────────────────────────────────
# Main entrypoint
# ──────────────────────────────────────────────────────────────

async def build_org_twin(org_name: str,
                          force_rebuild: bool = False) -> OrgTwinResult:
    """
    Full 4-phase org twin builder. Async because Phase 1 seeds in parallel.

    Voice trigger: "ARES, build twin for [org_name]"
    """
    t0 = time.time()

    # Check for existing twin
    if not force_rebuild:
        existing = find_twin_by_name(org_name, "org")
        if existing and existing["status"] == "active":
            logger.info("Org twin for %r already active (%s)", org_name, existing["twin_id"])
            snap_ids = []
            from aresx.domains.twin.twin_store import list_snapshots
            snap_ids = list_snapshots(existing["twin_id"])
            return OrgTwinResult(
                twin_id=existing["twin_id"],
                entity_name=org_name,
                entities=[],
                edges=[],
                risk_score=float(existing.get("confidence_score", 0)),
                confidence_score=float(existing.get("confidence_score", 0)),
                freshness_score=float(existing.get("freshness_score", 1)),
                snapshot_id=snap_ids[0] if snap_ids else "",
                build_duration_s=0.0,
            )

    # Create twin registration (status = building)
    twin_id = create_twin("org", org_name)

    bus.publish_sync(
        EventType.TWIN_BUILD_STARTED,
        payload={"twin_id": twin_id, "entity_name": org_name, "twin_type": "org"},
        source="digital_twin.org_twin",
        correlation_id=twin_id,
    )

    # Phase 1 — parallel seed
    logger.info("[OrgTwin] Phase 1: seeding %r", org_name)
    discovered = await _phase1_seed(org_name)

    # Create the org root entity
    org_entity = OrgEntity(
        entity_id=twin_id,   # org entity shares twin_id as its root node
        name=org_name,
        entity_type="Organization",
        source="seed",
    )

    # Phase 2 — graph construction
    logger.info("[OrgTwin] Phase 2: building graph (%d entities)", len(discovered))
    all_nodes, edges = _phase2_build_graph(org_entity, discovered)

    # Phase 3 — scoring
    logger.info("[OrgTwin] Phase 3: scoring")
    risk_score, confidence_score, freshness_score = _phase3_score(all_nodes)

    # Phase 4 — registration + snapshot
    logger.info("[OrgTwin] Phase 4: registering")
    graph_state = {
        "nodes": [
            {"entity_id": e.entity_id, "name": e.name,
             "entity_type": e.entity_type, "source": e.source,
             "attributes": e.attributes}
            for e in all_nodes
        ],
        "edges": edges,
    }
    snapshot_id = save_snapshot(twin_id, graph_state)
    update_twin_status(twin_id, "active", confidence_score)

    duration = time.time() - t0

    result = OrgTwinResult(
        twin_id=twin_id,
        entity_name=org_name,
        entities=all_nodes,
        edges=edges,
        risk_score=risk_score,
        confidence_score=confidence_score,
        freshness_score=freshness_score,
        snapshot_id=snapshot_id,
        build_duration_s=duration,
    )

    bus.publish_sync(
        EventType.TWIN_BUILT,
        payload={
            "twin_id":          twin_id,
            "entity_name":      org_name,
            "twin_type":        "org",
            "entity_count":     len(all_nodes),
            "edge_count":       len(edges),
            "confidence_score": confidence_score,
            "risk_score":       risk_score,
            "build_duration_s": duration,
        },
        source="digital_twin.org_twin",
        correlation_id=twin_id,
    )
    logger.info("[OrgTwin] Built %r: %d entities, %d edges, conf=%.2f in %.1fs",
                org_name, len(all_nodes), len(edges), confidence_score, duration)
    return result
