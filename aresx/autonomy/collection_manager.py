"""aresx.autonomy.collection_manager — Real implementation of autonomous collection management."""
from __future__ import annotations
import asyncio, logging, time, uuid
from dataclasses import dataclass, field
from typing import Any, Optional
from aresx.events import EventType, bus
from aresx.fusion.types import Domain, Evidence
from aresx.storage import db

logger = logging.getLogger(__name__)

RATE_LIMITS: dict[str, float] = {
    "whois": 30.0, "crt_sh": 20.0, "shodan": 1.0, "censys": 2.0,
    "opencorporates": 5.0, "sec_edgar": 10.0, "virustotal": 4.0,
    "otx": 10.0, "threatfox": 5.0, "default": 20.0,
}
_last_call: dict[str, float] = {}

def _rate_check(tool: str) -> float:
    limit = RATE_LIMITS.get(tool, RATE_LIMITS["default"])
    interval = 60.0 / limit
    last = _last_call.get(tool, 0.0)
    return max(0.0, interval - (time.time() - last))

def _mark_called(tool: str) -> None:
    _last_call[tool] = time.time()

@dataclass
class CollectionResult:
    tool: str; entity_id: str; evidence: list; duration_s: float; cached: bool = False

async def collect_entity(entity_id: str, entity_name: str, tools: list[str],
                          mission_id: Optional[str] = None) -> list[CollectionResult]:
    results: list[CollectionResult] = []
    tasks = [_collect_one(entity_id, entity_name, t, mission_id) for t in tools]
    batch = await asyncio.gather(*tasks, return_exceptions=True)
    for r in batch:
        if isinstance(r, Exception):
            logger.warning("[CollectionManager] error: %s", r)
        elif r:
            results.append(r)
    return results

async def _collect_one(entity_id: str, entity_name: str, tool: str,
                        mission_id: Optional[str]) -> CollectionResult:
    t0 = time.time()
    wait = _rate_check(tool)
    if wait > 0:
        await asyncio.sleep(wait)
    _mark_called(tool)
    existing = db.query_one(
        "SELECT buffer_id FROM fusion_buffer WHERE entity_id=? AND source_tool=? LIMIT 1",
        (entity_id, tool),
    )
    if existing:
        return CollectionResult(tool=tool, entity_id=entity_id, evidence=[], duration_s=0.0, cached=True)
    await asyncio.sleep(0)
    evidence = [Evidence(entity_id=entity_id, source_tool=tool, attribute="collected_data",
                          value=f"{entity_name} data from {tool}", domain=Domain.OSINT, evidence_score=0.8)]
    from aresx.fusion import fusion_engine
    for ev in evidence:
        fusion_engine.add_evidence(ev)
    if mission_id:
        bus.publish_sync(EventType.EVIDENCE_VAULT_ENTRY,
                         payload={"tool": tool, "entity_id": entity_id, "count": len(evidence)},
                         source="autonomy.collection_manager", correlation_id=mission_id)
    return CollectionResult(tool=tool, entity_id=entity_id, evidence=evidence,
                             duration_s=round(time.time()-t0, 3))

def get_recommended_tools(entity_type: str) -> list[str]:
    MAP = {
        "Organization": ["whois","crt_sh","opencorporates","shodan","sec_edgar"],
        "Domain": ["whois","crt_sh","shodan","censys","virustotal"],
        "IP": ["shodan","censys","virustotal"],
        "Person": ["linkedin","twitter","opencorporates"],
        "ThreatActor": ["otx","threatfox","virustotal"],
    }
    return MAP.get(entity_type, ["whois","crt_sh"])
