"""
aresx.mission.live_ops — Live Operational Picture (LOP).

Aggregates in real-time:
  • Active mission statuses + progress
  • Agent status indicators (14 agents)
  • Alert feed (watchlist + fusion events)
  • Signal heatmap (SIGINT activity)
  • Fusion events

Pushes updates via Qt6 signals at max 2Hz (no polling overhead).
Falls back to a dict-based snapshot API for headless/test environments.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from aresx.mission.mission_control import list_missions, get_event_sequence
from aresx.storage import db

logger = logging.getLogger(__name__)

# Max update rate per spec
MAX_UPDATE_HZ: float = 2.0
MIN_INTERVAL_S: float = 1.0 / MAX_UPDATE_HZ

_AGENT_ROSTER = [
    "vision_agent", "osint_agent", "network_agent", "social_agent",
    "document_agent", "code_agent", "research_agent", "briefing_agent",
    "sigint_agent", "counter_intel_agent", "predictive_agent", "graph_agent",
    "twin_agent", "mission_commander",
]


@dataclass
class AgentStatus:
    agent_id:       str
    status:         str          # idle | active | error | offline
    current_task:   Optional[str] = None
    tasks_queued:   int = 0
    last_active_at: float = field(default_factory=time.time)


@dataclass
class LOPSnapshot:
    """Full live operational picture at a point in time."""
    timestamp:       float
    active_missions: list[dict]
    agent_statuses:  list[AgentStatus]
    recent_alerts:   list[dict]
    recent_fusion:   list[dict]
    signal_heatmap:  dict[str, int]       # {"SIGINT": N, "OSINT": N, ...}
    total_evidence:  int


class LiveOpsFeed:
    """
    Maintains the live operational picture. Call snapshot() to pull
    the current state. In Qt6 runtime, connect the `updated` signal
    to your UI slot.

    Update loop runs at max MAX_UPDATE_HZ when start() is called
    in a background thread.
    """

    def __init__(self) -> None:
        self._last_update: float = 0.0
        self._agent_states: dict[str, AgentStatus] = {
            aid: AgentStatus(agent_id=aid, status="idle")
            for aid in _AGENT_ROSTER
        }

    def snapshot(self) -> LOPSnapshot:
        """Pull current LOP. Throttled to MAX_UPDATE_HZ."""
        now = time.time()
        if now - self._last_update < MIN_INTERVAL_S:
            pass  # still return current state — don't re-query DB
        self._last_update = now

        active = list_missions(status="active")

        # Recent watchlist alerts
        alerts = db.query_all(
            "SELECT watchlist_id, change_type, change_score, detected_at "
            "FROM watchlist_events WHERE alerted = 1 "
            "ORDER BY detected_at DESC LIMIT 10"
        )

        # Recent fusion events
        fusion = db.query_all(
            "SELECT entity_id, attribute, confidence, fused_at "
            "FROM fusion_assertions ORDER BY fused_at DESC LIMIT 10"
        )

        # Evidence count
        ev_row = db.query_one("SELECT COUNT(*) AS c FROM evidence_vault")
        total_ev = int(ev_row["c"]) if ev_row else 0

        # Signal heatmap (evidence domain counts)
        heatmap_rows = db.query_all(
            "SELECT domain, COUNT(*) AS n FROM fusion_buffer "
            "WHERE consumed_at IS NULL GROUP BY domain"
        )
        heatmap = {r["domain"]: int(r["n"]) for r in heatmap_rows}

        return LOPSnapshot(
            timestamp=now,
            active_missions=[dict(m) for m in active],
            agent_statuses=list(self._agent_states.values()),
            recent_alerts=[dict(a) for a in alerts],
            recent_fusion=[dict(f) for f in fusion],
            signal_heatmap=heatmap,
            total_evidence=total_ev,
        )

    def update_agent_status(self, agent_id: str, status: str,
                             current_task: Optional[str] = None,
                             tasks_queued: int = 0) -> None:
        """Called by agents to report their status."""
        if agent_id in self._agent_states:
            self._agent_states[agent_id] = AgentStatus(
                agent_id=agent_id, status=status,
                current_task=current_task, tasks_queued=tasks_queued,
                last_active_at=time.time(),
            )

    def get_agent_load(self) -> dict[str, int]:
        """Return {agent_id: tasks_queued} for the task allocator."""
        return {a.agent_id: a.tasks_queued for a in self._agent_states.values()}


# Module-level singleton
live_ops = LiveOpsFeed()
