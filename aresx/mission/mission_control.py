"""
ARES X v8.0 — Phase 4.1: Mission Control Center.

Central coordinator for all active missions. Exposes:
  create_mission(goal) → mission_id
  pause_mission(id)
  resume_mission(id)
  branch_mission(id, hypothesis) → branch_id
  get_mission(id)
  list_missions(status)

Subscribes to all mission_events on the event bus to maintain
live mission state. Writes every state change to the SQLite
mission_events table (Order 16: microsecond-precise, monotonic).
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Optional

from aresx.events import EventType, bus
from aresx.storage import db

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# CRUD
# ──────────────────────────────────────────────────────────────

def create_mission(goal: str,
                   name: Optional[str] = None,
                   priority: int = 5,
                   resource_budget: Optional[dict] = None) -> str:
    """
    Register a new mission. Returns mission_id.
    Publishes MISSION_STARTED.
    """
    mission_id = str(uuid.uuid4())
    if not name:
        name = goal[:60] + ("…" if len(goal) > 60 else "")
    budget = resource_budget or {"api_calls": 1000, "compute_time": 3600, "agent_slots": 5}

    db.execute(
        """
        INSERT INTO missions
            (mission_id, name, goal, status, priority, created_at,
             updated_at, resource_budget)
        VALUES (?, ?, ?, 'active', ?, datetime('now'), datetime('now'), ?)
        """,
        (mission_id, name, goal, priority, json.dumps(budget)),
    )

    _emit_mission_event(mission_id, "mission_created",
                         payload={"goal": goal, "priority": priority})

    bus.publish_sync(
        EventType.MISSION_STARTED,
        payload={"mission_id": mission_id, "goal": goal, "name": name},
        source="mission.control",
        correlation_id=mission_id,
    )
    return mission_id


def get_mission(mission_id: str) -> Optional[dict]:
    """Return mission row as dict or None."""
    row = db.query_one("SELECT * FROM missions WHERE mission_id = ?", (mission_id,))
    if row is None:
        return None
    return dict(row)


def list_missions(status: Optional[str] = None) -> list[dict]:
    if status:
        rows = db.query_all(
            "SELECT * FROM missions WHERE status = ? ORDER BY priority, created_at DESC",
            (status,),
        )
    else:
        rows = db.query_all(
            "SELECT * FROM missions ORDER BY priority, created_at DESC"
        )
    return [dict(r) for r in rows]


def update_mission_status(mission_id: str, status: str) -> None:
    db.execute(
        "UPDATE missions SET status = ?, updated_at = datetime('now') WHERE mission_id = ?",
        (status, mission_id),
    )
    _emit_mission_event(mission_id, f"mission_{status}")


def pause_mission(mission_id: str) -> None:
    """Pause an active mission."""
    update_mission_status(mission_id, "paused")
    bus.publish_sync(
        EventType.MISSION_PAUSED,
        payload={"mission_id": mission_id},
        source="mission.control",
        correlation_id=mission_id,
    )


def resume_mission(mission_id: str) -> None:
    """Resume a paused mission."""
    update_mission_status(mission_id, "active")
    bus.publish_sync(
        EventType.MISSION_RESUMED,
        payload={"mission_id": mission_id},
        source="mission.control",
        correlation_id=mission_id,
    )


def complete_mission(mission_id: str) -> None:
    db.execute(
        """
        UPDATE missions SET status = 'complete', completed_at = datetime('now'),
                            updated_at = datetime('now')
        WHERE mission_id = ?
        """,
        (mission_id,),
    )
    _emit_mission_event(mission_id, "mission_complete")
    bus.publish_sync(
        EventType.MISSION_COMPLETE,
        payload={"mission_id": mission_id},
        source="mission.control",
        correlation_id=mission_id,
    )


def fail_mission(mission_id: str, reason: str = "") -> None:
    db.execute(
        "UPDATE missions SET status = 'failed', updated_at = datetime('now') WHERE mission_id = ?",
        (mission_id,),
    )
    _emit_mission_event(mission_id, "mission_failed", payload={"reason": reason})
    bus.publish_sync(
        EventType.MISSION_FAILED,
        payload={"mission_id": mission_id, "reason": reason},
        source="mission.control",
        correlation_id=mission_id,
    )


def branch_mission(parent_id: str, hypothesis: str) -> str:
    """
    Fork a mission into an alternate investigation branch.
    Returns branch_id (also registered as a new mission).
    """
    # Get the last event sequence_num as the fork point
    row = db.query_one(
        "SELECT MAX(sequence_num) AS sn FROM mission_events WHERE mission_id = ?",
        (parent_id,),
    )
    fork_seq = int(row["sn"] or 0) if row else 0

    branch_id = str(uuid.uuid4())
    db.execute(
        """
        INSERT INTO mission_branches
            (branch_id, parent_mission_id, forked_at_event, hypothesis, status)
        VALUES (?, ?, ?, ?, 'active')
        """,
        (branch_id, parent_id, fork_seq, hypothesis),
    )

    # Create a new mission for the branch
    new_mission_id = create_mission(
        goal=f"[BRANCH] {hypothesis}",
        name=f"Branch of {parent_id[:8]}: {hypothesis[:40]}",
    )

    bus.publish_sync(
        EventType.MISSION_BRANCHED,
        payload={
            "parent_mission_id": parent_id,
            "branch_id":         branch_id,
            "new_mission_id":    new_mission_id,
            "hypothesis":        hypothesis,
        },
        source="mission.control",
        correlation_id=parent_id,
    )
    return branch_id


# ──────────────────────────────────────────────────────────────
# Objective management
# ──────────────────────────────────────────────────────────────

def add_objective(mission_id: str, description: str,
                   dependencies: Optional[list[str]] = None) -> str:
    """Register a named objective. Returns objective_id."""
    obj_id = str(uuid.uuid4())
    db.execute(
        """
        INSERT INTO mission_objectives
            (objective_id, mission_id, description, status,
             created_at, dependencies)
        VALUES (?, ?, ?, 'pending', datetime('now'), ?)
        """,
        (obj_id, mission_id, description,
         json.dumps(dependencies or [])),
    )
    _emit_mission_event(mission_id, "objective_added",
                         payload={"objective_id": obj_id, "description": description})
    bus.publish_sync(
        EventType.MISSION_OBJECTIVE_STARTED,
        payload={"mission_id": mission_id, "objective_id": obj_id,
                 "description": description},
        source="mission.control",
        correlation_id=mission_id,
    )
    return obj_id


def complete_objective(mission_id: str, objective_id: str,
                        evidence_count: int = 0) -> None:
    db.execute(
        """
        UPDATE mission_objectives
        SET status = 'complete', completed_at = datetime('now'),
            completion_pct = 1.0, evidence_count = ?
        WHERE objective_id = ?
        """,
        (evidence_count, objective_id),
    )
    _emit_mission_event(mission_id, "objective_complete",
                         payload={"objective_id": objective_id,
                                  "evidence_count": evidence_count})
    bus.publish_sync(
        EventType.MISSION_OBJECTIVE_COMPLETE,
        payload={"mission_id": mission_id, "objective_id": objective_id},
        source="mission.control",
        correlation_id=mission_id,
    )


def get_objectives(mission_id: str) -> list[dict]:
    rows = db.query_all(
        "SELECT * FROM mission_objectives WHERE mission_id = ? ORDER BY created_at",
        (mission_id,),
    )
    return [dict(r) for r in rows]


# ──────────────────────────────────────────────────────────────
# Event logging (Order 16: monotonic sequence_num)
# ──────────────────────────────────────────────────────────────

def _next_sequence(mission_id: str) -> int:
    row = db.query_one(
        "SELECT COALESCE(MAX(sequence_num), 0) + 1 AS next "
        "FROM mission_events WHERE mission_id = ?",
        (mission_id,),
    )
    return int(row["next"]) if row else 1


def _emit_mission_event(mission_id: str, event_type: str,
                          agent_id: Optional[str] = None,
                          payload: Optional[dict] = None) -> int:
    """
    Persist a mission event with a monotonic sequence_num (Order 16).
    Returns the sequence_num assigned.
    """
    seq = _next_sequence(mission_id)
    db.execute(
        """
        INSERT INTO mission_events
            (event_id, mission_id, event_type, agent_id, payload,
             timestamp, sequence_num)
        VALUES (?, ?, ?, ?, ?, datetime('now'), ?)
        """,
        (
            str(uuid.uuid4()),
            mission_id,
            event_type,
            agent_id,
            json.dumps(payload or {}, default=str),
            seq,
        ),
    )
    return seq


def get_event_sequence(mission_id: str) -> list[dict]:
    """Return all events for a mission, ordered by sequence_num."""
    rows = db.query_all(
        "SELECT * FROM mission_events WHERE mission_id = ? ORDER BY sequence_num ASC",
        (mission_id,),
    )
    return [dict(r) for r in rows]


def emit_agent_event(mission_id: str, agent_id: str,
                      event_type: str, payload: dict) -> int:
    """Public API for agents to log their actions to the mission timeline."""
    return _emit_mission_event(mission_id, event_type, agent_id, payload)
