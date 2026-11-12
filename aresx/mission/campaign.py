"""
aresx.mission.campaign — Long-Running Campaign Execution Engine.

Campaigns are multi-mission investigations spanning hours to days.
State saved every 10 minutes to SQLite for crash recovery.
Crash recovery: on restart, resume from last checkpoint.

Build Prompt §3 Phase 4, TRD §3.3.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from aresx.storage import db
from aresx.events import EventType, bus

logger = logging.getLogger(__name__)

MAX_CAMPAIGN_DURATION_HOURS: float = 72.0
CHECKPOINT_INTERVAL_S: float = 600.0    # 10 minutes


@dataclass
class Campaign:
    campaign_id:    str = field(default_factory=lambda: str(uuid.uuid4()))
    name:           str = ""
    goal:           str = ""
    status:         str = "active"       # active | paused | complete | failed
    mission_ids:    list[str] = field(default_factory=list)
    created_at:     float = field(default_factory=time.time)
    last_checkpoint: float = field(default_factory=time.time)
    metadata:       dict[str, Any] = field(default_factory=dict)


def create_campaign(name: str, goal: str) -> Campaign:
    """Create and persist a new campaign."""
    c = Campaign(name=name, goal=goal)
    db.execute(
        """
        INSERT INTO campaigns
            (campaign_id, name, goal, status, created_at, last_checkpoint)
        VALUES (?, ?, ?, 'active', datetime('now'), datetime('now'))
        """,
        (c.campaign_id, c.name, c.goal),
    )
    logger.info("[Campaign] Created %s: %s", c.campaign_id[:8], name)
    return c


def add_mission_to_campaign(campaign_id: str, mission_id: str) -> None:
    db.execute(
        "UPDATE campaigns SET mission_ids = json_insert(COALESCE(mission_ids,'[]'), '$[#]', ?) "
        "WHERE campaign_id = ?",
        (mission_id, campaign_id),
    )


def checkpoint_campaign(campaign: Campaign) -> None:
    """Save campaign state. Called every CHECKPOINT_INTERVAL_S."""
    now = time.time()
    campaign.last_checkpoint = now
    db.execute(
        "UPDATE campaigns SET last_checkpoint = datetime('now'), status = ?, metadata = ? "
        "WHERE campaign_id = ?",
        (campaign.status, json.dumps(campaign.metadata), campaign.campaign_id),
    )
    logger.debug("[Campaign] Checkpoint saved for %s", campaign.campaign_id[:8])


def resume_campaign(campaign_id: str) -> Optional[Campaign]:
    """Load a campaign from its last checkpoint."""
    row = db.query_one("SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,))
    if not row:
        return None
    return Campaign(
        campaign_id=row["campaign_id"],
        name=row["name"],
        goal=row["goal"],
        status=row["status"],
        created_at=0.0,
        metadata=json.loads(row.get("metadata") or "{}"),
    )


def list_campaigns(status: Optional[str] = None) -> list[dict]:
    if status:
        rows = db.query_all(
            "SELECT * FROM campaigns WHERE status = ? ORDER BY created_at DESC", (status,)
        )
    else:
        rows = db.query_all("SELECT * FROM campaigns ORDER BY created_at DESC")
    return [dict(r) for r in rows]
