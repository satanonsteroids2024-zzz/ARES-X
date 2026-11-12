"""
ARES X v8.0 — Phase 3.5: Human Behavioral Twin.

PRIVACY GATE: requires explicit user confirmation before building.
Approval gate action_type = "human_twin_build" must be approved
before any collection occurs (Order 19, Build Prompt §3 Phase 3.5).

Sources: public social profiles ONLY. No private data. Ever.
Stores: activity patterns, communication style, public relationship network.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from aresx.domains.twin.twin_store import (
    create_twin, save_snapshot, update_twin_status,
)
from aresx.events import EventType, bus

logger = logging.getLogger(__name__)


@dataclass
class HumanTwinResult:
    twin_id: str
    subject_name: str
    public_profiles: list[dict]
    activity_patterns: dict[str, Any]
    communication_style: dict[str, Any]
    public_network: list[dict]
    privacy_gate_id: str
    snapshot_id: str
    build_duration_s: float


class HumanTwinPrivacyGateRequired(Exception):
    """Raised when human twin build is attempted without approval."""
    def __init__(self, gate_id: str) -> None:
        self.gate_id = gate_id
        super().__init__(
            f"Human twin build requires approval gate {gate_id} "
            f"(Order 19). Call approve_gate(gate_id) before proceeding."
        )


def request_human_twin_approval(subject_name: str) -> str:
    """
    Create an approval gate for human twin build. Returns gate_id.
    The caller MUST pass this gate_id to build_human_twin() after
    the user approves via the UI modal.
    """
    gate_id = str(uuid.uuid4())
    from aresx.storage import db
    db.execute(
        """
        INSERT INTO approval_gates
            (gate_id, action_type, action_payload, requested_at, status, risk_level)
        VALUES (?, 'HUMAN_TWIN_BUILD', ?, datetime('now'), 'pending', 'high')
        """,
        (gate_id, f'{{"subject_name": "{subject_name}"}}'),
    )
    bus.publish_sync(
        EventType.APPROVAL_GATE_TRIGGERED,
        payload={
            "gate_id":      gate_id,
            "action_type":  "HUMAN_TWIN_BUILD",
            "subject_name": subject_name,
            "risk_level":   "high",
        },
        source="digital_twin.human_twin",
    )
    return gate_id


def approve_gate(gate_id: str, approved_by: str = "user") -> None:
    """Mark an approval gate as approved (called by UI after user clicks Approve)."""
    import hmac, hashlib, json, time as t
    payload = f"{gate_id}:{approved_by}:{t.time()}"
    sig = hmac.new(b"ares_x_approval_key", payload.encode(), hashlib.sha256).hexdigest()
    from aresx.storage import db
    db.execute(
        """
        UPDATE approval_gates
        SET status = 'approved', approved_at = datetime('now'),
            approved_by = ?, approval_signature = ?
        WHERE gate_id = ?
        """,
        (approved_by, sig, gate_id),
    )
    bus.publish_sync(
        EventType.APPROVAL_GATE_RESOLVED,
        payload={"gate_id": gate_id, "resolution": "approved", "approved_by": approved_by},
        source="digital_twin.human_twin",
    )


def _is_gate_approved(gate_id: str) -> bool:
    from aresx.storage import db
    row = db.query_one(
        "SELECT status FROM approval_gates WHERE gate_id = ?", (gate_id,)
    )
    return row is not None and row["status"] == "approved"


def build_human_twin(subject_name: str, gate_id: str) -> HumanTwinResult:
    """
    Build human behavioral twin. gate_id MUST be pre-approved.

    Sources: public social profiles only. No private data ever.
    """
    if not _is_gate_approved(gate_id):
        raise HumanTwinPrivacyGateRequired(gate_id)

    t0 = time.time()
    twin_id = create_twin("human", subject_name)

    bus.publish_sync(
        EventType.TWIN_BUILD_STARTED,
        payload={
            "twin_id": twin_id, "entity_name": subject_name,
            "twin_type": "human", "gate_id": gate_id,
        },
        source="digital_twin.human_twin",
        correlation_id=twin_id,
    )

    # Public data only — synthetic for headless environments
    public_profiles = [
        {"platform": "linkedin", "url": f"linkedin.com/in/{subject_name.lower().replace(' ','-')}", "source": "public"},
        {"platform": "twitter",  "url": f"twitter.com/{subject_name.lower().replace(' ','')}", "source": "public"},
    ]

    activity_patterns = {
        "posting_frequency": "daily",
        "peak_activity_hours": [9, 17, 21],
        "content_themes": ["technology", "business"],
    }

    communication_style = {
        "formality": "professional",
        "average_post_length": "medium",
        "emoji_usage": "rare",
    }

    public_network: list[dict] = []

    graph_state = {
        "subject_name": subject_name,
        "public_profiles": public_profiles,
        "activity_patterns": activity_patterns,
        "communication_style": communication_style,
        "public_network": public_network,
    }
    snapshot_id = save_snapshot(twin_id, graph_state)
    update_twin_status(twin_id, "active", 0.5)

    duration = time.time() - t0

    bus.publish_sync(
        EventType.TWIN_BUILT,
        payload={
            "twin_id": twin_id, "entity_name": subject_name, "twin_type": "human",
            "profile_count": len(public_profiles), "build_duration_s": duration,
        },
        source="digital_twin.human_twin",
        correlation_id=twin_id,
    )

    return HumanTwinResult(
        twin_id=twin_id,
        subject_name=subject_name,
        public_profiles=public_profiles,
        activity_patterns=activity_patterns,
        communication_style=communication_style,
        public_network=public_network,
        privacy_gate_id=gate_id,
        snapshot_id=snapshot_id,
        build_duration_s=duration,
    )
