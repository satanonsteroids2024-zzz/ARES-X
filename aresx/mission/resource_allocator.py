"""
aresx.mission.resource_allocator — Multi-Mission Compute Prioritization.

Priority queue of missions by (user_priority, deadline_proximity, evidence_yield_rate).
API quota allocation: distribute daily quota across active missions proportionally.
Preemption: pause lower-priority mission when higher-priority needs quota.

Build Prompt §3 Phase 4, TRD §1.2.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from aresx.mission.mission_control import (
    list_missions, pause_mission, resume_mission,
    get_event_sequence,
)

logger = logging.getLogger(__name__)

# Daily quota slices (tokens per mission per day)
DEFAULT_DAILY_QUOTA_TOKENS: int = 500_000


@dataclass
class MissionPriority:
    mission_id:         str
    user_priority:      int     # 1 highest, 10 lowest
    evidence_yield_pct: float   # evidence found / time spent
    combined_score:     float   # lower = higher priority
    quota_allocation:   int     # tokens allocated today


class ResourceAllocator:
    """
    Manages compute budget across active missions.
    Called by the autonomy layer before spawning new LLM calls.
    """

    def __init__(self, daily_quota: int = DEFAULT_DAILY_QUOTA_TOKENS) -> None:
        self.daily_quota = daily_quota
        self._used: dict[str, int] = {}    # mission_id → tokens used today

    def prioritize(self) -> list[MissionPriority]:
        """
        Rank all active missions by combined priority score.
        Lower score = higher priority.
        """
        active = list_missions(status="active")
        if not active:
            return []

        ranked: list[MissionPriority] = []
        for m in active:
            mid = m["mission_id"]
            user_p = int(m.get("priority") or 5)

            # Evidence yield rate from event history
            events = get_event_sequence(mid)
            ev_count = sum(
                1 for e in events
                if "objective_complete" in e.get("event_type", "")
            )
            ev_yield = ev_count / max(len(events), 1) * 100

            combined = user_p * 0.6 + (100 - ev_yield) * 0.4 / 10
            ranked.append(MissionPriority(
                mission_id=mid,
                user_priority=user_p,
                evidence_yield_pct=ev_yield,
                combined_score=round(combined, 3),
                quota_allocation=0,   # set below
            ))

        ranked.sort(key=lambda r: r.combined_score)

        # Allocate quota proportionally (top mission gets largest slice)
        total_weight = sum(
            max(0.1, 11 - r.user_priority) for r in ranked
        )
        for r in ranked:
            weight = max(0.1, 11 - r.user_priority)
            r.quota_allocation = int(self.daily_quota * weight / total_weight)

        return ranked

    def check_preempt(self, requesting_mission_id: str,
                       tokens_needed: int = 1000) -> Optional[str]:
        """
        Check if a lower-priority mission should be preempted to free quota.
        Returns mission_id to pause, or None if no preemption needed.
        """
        ranked = self.prioritize()
        if not ranked:
            return None

        # Find requesting mission's rank and allocation
        req_rank = next(
            (i for i, r in enumerate(ranked) if r.mission_id == requesting_mission_id),
            len(ranked),
        )
        used = self._used.get(requesting_mission_id, 0)
        req_alloc = next(
            (r.quota_allocation for r in ranked if r.mission_id == requesting_mission_id),
            0,
        )

        # Only consider preemption if the requester would exceed its own allocation
        if used + tokens_needed <= req_alloc:
            return None  # requester has headroom — no preemption needed

        # Pause the lowest-priority mission still consuming quota
        for i in range(len(ranked) - 1, req_rank, -1):
            lower = ranked[i]
            lower_used = self._used.get(lower.mission_id, 0)
            if lower_used > 0:
                logger.info("[ResourceAllocator] Preempting %s to free quota for %s",
                            lower.mission_id[:8], requesting_mission_id[:8])
                return lower.mission_id

        return None

    def record_usage(self, mission_id: str, tokens: int) -> None:
        self._used[mission_id] = self._used.get(mission_id, 0) + tokens

    def usage_summary(self) -> dict:
        return {
            "daily_quota":    self.daily_quota,
            "total_used":     sum(self._used.values()),
            "per_mission":    dict(self._used),
            "pct_used":       round(sum(self._used.values()) / max(self.daily_quota, 1) * 100, 1),
        }


resource_allocator = ResourceAllocator()
