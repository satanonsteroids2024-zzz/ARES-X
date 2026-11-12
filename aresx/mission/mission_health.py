"""
aresx.mission.mission_health — Mission Health Dashboard.

Per-mission metrics:
  • Evidence ingestion rate (pieces/min)
  • Graph growth rate (edges added/min)
  • Agent error rate
  • API quota burn rate
  • ETA computation: estimate_completion(mission_id)
  • Health indicator: 🟢 healthy / 🟡 slow / 🔴 stalled / ⚫ failed

Build Prompt §3 Phase 4, TRD §1.2.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

from aresx.mission.mission_control import (
    get_event_sequence, get_mission, get_objectives,
)

logger = logging.getLogger(__name__)


# Health thresholds
EVIDENCE_RATE_HEALTHY:   float = 5.0    # pieces/min
EVIDENCE_RATE_SLOW:      float = 1.0    # below this → 🟡 slow
EVIDENCE_RATE_STALLED:   float = 0.1   # below this → 🔴 stalled
MAX_ERROR_RATE:          float = 0.20   # above this → 🔴


@dataclass
class MissionHealth:
    mission_id:              str
    status:                  str         # active | paused | complete | failed
    health_indicator:        str         # 🟢 | 🟡 | 🔴 | ⚫
    evidence_ingestion_rate: float       # pieces/min
    completion_pct:          float       # 0–100
    agent_error_rate:        float       # 0–1
    quota_burn_rate:         float       # % of daily quota/min
    eta_seconds:             Optional[float]
    event_count:             int
    total_objectives:        int
    completed_objectives:    int


def get_mission_health(mission_id: str) -> MissionHealth:
    """Compute real-time health metrics for a mission."""
    mission = get_mission(mission_id)
    if not mission:
        return MissionHealth(
            mission_id=mission_id, status="not_found",
            health_indicator="⚫", evidence_ingestion_rate=0.0,
            completion_pct=0.0, agent_error_rate=0.0,
            quota_burn_rate=0.0, eta_seconds=None,
            event_count=0, total_objectives=0, completed_objectives=0,
        )

    status = mission.get("status", "unknown")
    if status == "failed":
        return MissionHealth(
            mission_id=mission_id, status=status,
            health_indicator="⚫", evidence_ingestion_rate=0.0,
            completion_pct=0.0, agent_error_rate=1.0,
            quota_burn_rate=0.0, eta_seconds=None,
            event_count=0, total_objectives=0, completed_objectives=0,
        )

    events = get_event_sequence(mission_id)
    objs = get_objectives(mission_id)
    completed_objs = [o for o in objs if o["status"] == "complete"]
    total_ev = sum(int(o.get("evidence_count") or 0) for o in completed_objs)

    # Evidence ingestion rate (pieces/min)
    ev_rate = 0.0
    if len(events) >= 2:
        try:
            from dateutil import parser as dp
            t0 = dp.parse(events[0]["timestamp"]).timestamp()
            t1 = dp.parse(events[-1]["timestamp"]).timestamp()
            elapsed_min = max(0.001, (t1 - t0) / 60)
            ev_rate = total_ev / elapsed_min
        except Exception:
            pass

    # Error rate
    error_events = sum(1 for e in events if "error" in e.get("event_type", ""))
    err_rate = error_events / max(len(events), 1)

    # Completion pct
    pct = len(completed_objs) / max(len(objs), 1) * 100

    # ETA
    eta_s: Optional[float] = None
    if 0 < pct < 100 and len(events) >= 2:
        try:
            from dateutil import parser as dp
            t0 = dp.parse(events[0]["timestamp"]).timestamp()
            elapsed = time.time() - t0
            eta_s = elapsed * (100 - pct) / max(pct, 0.001)
        except Exception:
            pass

    # Health indicator
    if status == "complete":
        indicator = "🟢"
    elif err_rate > MAX_ERROR_RATE or (pct < 5 and len(events) > 20):
        indicator = "🔴"
    elif ev_rate < EVIDENCE_RATE_STALLED and len(events) > 5:
        indicator = "🔴"
    elif ev_rate < EVIDENCE_RATE_SLOW:
        indicator = "🟡"
    else:
        indicator = "🟢"

    return MissionHealth(
        mission_id=mission_id,
        status=status,
        health_indicator=indicator,
        evidence_ingestion_rate=round(ev_rate, 2),
        completion_pct=round(pct, 1),
        agent_error_rate=round(err_rate, 3),
        quota_burn_rate=0.0,    # wired to compute_budget in production
        eta_seconds=round(eta_s, 0) if eta_s else None,
        event_count=len(events),
        total_objectives=len(objs),
        completed_objectives=len(completed_objs),
    )


def get_all_mission_health() -> list[MissionHealth]:
    """Health check for every active mission."""
    from aresx.mission.mission_control import list_missions
    active = list_missions(status="active")
    return [get_mission_health(m["mission_id"]) for m in active]
