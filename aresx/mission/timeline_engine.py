"""
aresx.mission.timeline_engine — Mission Timeline Engine.

Renders the full ordered event sequence for any mission.
Used by the Qt6 timeline widget AND by forensic replay.

Features:
  • Filterable by event_type
  • Export as JSON for external audit
  • ETA computation based on progress rate
  • Sequence integrity check (Order 16)
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Optional

from aresx.mission.mission_control import (
    get_event_sequence, get_objectives, get_mission,
)

logger = logging.getLogger(__name__)


@dataclass
class TimelineEvent:
    sequence_num: int
    event_type:   str
    agent_id:     Optional[str]
    payload:      dict
    timestamp:    str


def get_timeline(mission_id: str,
                  filter_types: Optional[list[str]] = None) -> list[TimelineEvent]:
    """
    Return the ordered event timeline for a mission.

    Args:
        mission_id:   which mission
        filter_types: optional list of event_type strings to include
                      (None = all types)
    """
    raw = get_event_sequence(mission_id)
    events: list[TimelineEvent] = []
    for r in raw:
        etype = r.get("event_type", "")
        if filter_types and etype not in filter_types:
            continue
        try:
            payload = json.loads(r.get("payload") or "{}")
        except json.JSONDecodeError:
            payload = {}
        events.append(TimelineEvent(
            sequence_num=int(r["sequence_num"]),
            event_type=etype,
            agent_id=r.get("agent_id"),
            payload=payload,
            timestamp=r.get("timestamp", ""),
        ))
    return events


def check_sequence_integrity(mission_id: str) -> dict:
    """
    Verify sequence_num is strictly monotonic (Order 16).
    Returns {intact, event_count, first_gap_at}.
    """
    events = get_timeline(mission_id)
    if not events:
        return {"intact": True, "event_count": 0, "first_gap_at": None}
    prev = events[0].sequence_num
    for ev in events[1:]:
        if ev.sequence_num <= prev:
            return {
                "intact": False,
                "event_count": len(events),
                "first_gap_at": ev.sequence_num,
            }
        prev = ev.sequence_num
    return {"intact": True, "event_count": len(events), "first_gap_at": None}


def export_timeline_json(mission_id: str) -> dict:
    """Export full timeline for external audit tools."""
    mission = get_mission(mission_id)
    events = get_timeline(mission_id)
    integrity = check_sequence_integrity(mission_id)
    return {
        "mission_id":   mission_id,
        "mission":      dict(mission) if mission else {},
        "integrity":    integrity,
        "event_count":  len(events),
        "events": [
            {
                "seq":        e.sequence_num,
                "type":       e.event_type,
                "agent":      e.agent_id,
                "payload":    e.payload,
                "timestamp":  e.timestamp,
            }
            for e in events
        ],
    }


def estimate_completion(mission_id: str) -> dict:
    """
    Estimate remaining time for an active mission.
    Uses evidence ingestion rate vs total objectives.
    Returns {pct_complete, eta_seconds, evidence_rate_per_min}.
    """
    objs = get_objectives(mission_id)
    total = len(objs)
    if total == 0:
        return {"pct_complete": 0.0, "eta_seconds": None, "evidence_rate_per_min": 0.0}

    completed = [o for o in objs if o["status"] == "complete"]
    pct = len(completed) / total

    events = get_timeline(mission_id)
    if len(events) >= 2:
        t_start = events[0].timestamp
        t_latest = events[-1].timestamp
        try:
            from dateutil import parser as dp
            t0 = dp.parse(t_start).timestamp()
            t1 = dp.parse(t_latest).timestamp()
            elapsed_min = max(0.001, (t1 - t0) / 60)
            evidence_count = sum(int(o.get("evidence_count") or 0) for o in completed)
            ev_rate = evidence_count / elapsed_min
            if pct > 0 and pct < 1.0:
                eta_s = ((1.0 - pct) / pct) * (elapsed_min * 60)
            else:
                eta_s = None
        except Exception:
            ev_rate = 0.0
            eta_s = None
    else:
        ev_rate = 0.0
        eta_s = None

    return {
        "pct_complete":          round(pct * 100, 1),
        "eta_seconds":           round(eta_s, 0) if eta_s else None,
        "evidence_rate_per_min": round(ev_rate, 2),
        "total_objectives":      total,
        "completed_objectives":  len(completed),
    }
