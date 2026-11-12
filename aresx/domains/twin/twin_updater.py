"""
ARES X v8.0 — Phase 3.9: Twin Updater (Incremental Refresh).

APScheduler job: refresh_active_twins() runs every 6 hours.
Only re-collects entities with staleness score > 0.3.
Publishes TWIN_UPDATED on completion, TWIN_STALE if freshness < 0.2.

Freshness decay: freshness = e^(-0.1 * hours_since_refresh) per Order 14.
"""
from __future__ import annotations

import asyncio
import logging
import math
import time
from typing import Optional

from aresx.domains.twin.twin_store import (
    get_twin, list_twins, list_snapshots, load_snapshot,
    save_snapshot, update_twin_status,
)
from aresx.events import EventType, bus

logger = logging.getLogger(__name__)

_FRESHNESS_K: float = 0.1
_STALE_THRESHOLD: float = 0.2     # emit TWIN_STALE when below this
_REFRESH_THRESHOLD: float = 0.3   # only refresh when staleness > 0.3 (freshness < 0.7)
_REFRESH_INTERVAL_HOURS: float = 6.0


def compute_freshness(last_updated_ts: float) -> float:
    """Freshness in [0, 1] per Order 14 decay formula."""
    hours = (time.time() - last_updated_ts) / 3600.0
    return max(0.0, math.exp(-_FRESHNESS_K * hours))


def _needs_refresh(twin: dict) -> bool:
    """Return True if twin's freshness has degraded below REFRESH_THRESHOLD."""
    freshness = float(twin.get("freshness_score", 1.0))
    return freshness < (1.0 - _REFRESH_THRESHOLD)


async def refresh_twin(twin_id: str) -> Optional[str]:
    """
    Incrementally refresh a single twin. Returns new snapshot_id or None.

    The refresh strategy per twin_type:
      org   → rebuild (re-run seed phase 1 + graph construction)
      infra → re-run infra_twin build (DNS/Shodan updates cheaply)
      adversary → re-fetch OTX + ThreatFox
      human → no re-collection (privacy gate would be required again)
      supply_chain / cyber_terrain → derive from refreshed parent
    """
    twin = get_twin(twin_id)
    if twin is None:
        logger.warning("refresh_twin: twin %s not found", twin_id)
        return None

    twin_type   = twin["twin_type"]
    entity_name = twin["entity_name"]

    try:
        if twin_type == "org":
            from aresx.domains.twin.twins.org_twin import build_org_twin
            result = await build_org_twin(entity_name, force_rebuild=True)
            new_snap = result.snapshot_id

        elif twin_type == "infra":
            from aresx.domains.twin.twins.infra_twin import build_infra_twin
            result = await build_infra_twin(entity_name, force_rebuild=True)
            new_snap = result.snapshot_id

        elif twin_type == "adversary":
            from aresx.domains.twin.twins.adversary_twin import build_adversary_twin
            result = await build_adversary_twin(entity_name, force_rebuild=True)
            new_snap = result.snapshot_id

        else:
            # human, supply_chain, cyber_terrain: no autonomous refresh
            logger.info("twin_updater: %s twin %s skipped (no autonomous refresh)", twin_type, twin_id)
            return None

    except Exception as exc:
        logger.error("refresh_twin failed for %s: %s", twin_id, exc)
        return None

    freshness = compute_freshness(time.time())
    update_twin_status(twin_id, "active")

    bus.publish_sync(
        EventType.TWIN_UPDATED,
        payload={
            "twin_id":     twin_id,
            "twin_type":   twin_type,
            "entity_name": entity_name,
            "freshness":   freshness,
            "snapshot_id": new_snap,
        },
        source="digital_twin.twin_updater",
        correlation_id=twin_id,
    )
    return new_snap


async def refresh_active_twins() -> dict[str, Optional[str]]:
    """
    Main scheduler job — refresh all active twins that need it.
    Returns {twin_id: new_snapshot_id_or_None}.
    """
    results: dict[str, Optional[str]] = {}
    for twin in list_twins(status="active"):
        tid = twin["twin_id"]
        freshness = float(twin.get("freshness_score", 1.0))

        # Emit stale event if below threshold
        if freshness < _STALE_THRESHOLD:
            bus.publish_sync(
                EventType.TWIN_STALE,
                payload={"twin_id": tid, "freshness": freshness},
                source="digital_twin.twin_updater",
                correlation_id=tid,
            )

        if _needs_refresh(twin):
            logger.info("Refreshing twin %s (freshness=%.2f)", tid, freshness)
            results[tid] = await refresh_twin(tid)
        else:
            results[tid] = None     # not needed yet

    return results
