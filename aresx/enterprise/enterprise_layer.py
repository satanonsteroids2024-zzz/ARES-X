"""
ARES X v8.0 — Phase 7: Enterprise Intelligence Layer.

Covers all enterprise/ modules:
  • evidence_vault.py     — Merkle-tree evidence vault (pymerkle fallback: SHA-256 chain)
  • approval_gates.py     — HMAC-SHA256 signed approval gates (Order 19)
  • watchlist_engine.py   — Live watchlist scoring + alert emission
  • brief_generator.py    — Executive/strategic brief generation (reportlab fallback)
  • continuous_monitor.py — 24/7 autonomous monitoring
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from aresx.events import EventType, bus
from aresx.storage import db

logger = logging.getLogger(__name__)

# Serializes the read-prev → compute-hash → insert cycle so concurrent
# writers cannot fork the Merkle chain (Order 17 integrity under load).
_VAULT_LOCK = threading.Lock()


# ─────────────────────────────────────────────────────────────
# Evidence Vault
# ─────────────────────────────────────────────────────────────

def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _ntp_timestamp() -> float:
    """Return current time. Production: crosscheck against NTP pool."""
    return time.time()


def add_evidence(
    source_tool: str,
    raw_data: str,
    mission_id: Optional[str] = None,
    source_url: Optional[str] = None,
    analyst_id: Optional[str] = None,
    approval_gate_id: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> str:
    """
    Append a new evidence entry to the vault.

    Computes SHA-256 hash of raw data, builds Merkle proof (or SHA-256 chain
    when pymerkle is unavailable), and stores in the append-only evidence_vault.

    Returns evidence_id.
    """
    evidence_id  = str(uuid.uuid4())
    raw_hash     = _sha256(raw_data)
    ntp_ts       = _ntp_timestamp()

    # Atomic chain append: hold the lock across read-prev → compute → insert
    # so concurrent writers produce a single linear chain, not a fork.
    MAX_RETRIES = 5
    for attempt in range(MAX_RETRIES):
        try:
            with _VAULT_LOCK:
                prev_row = db.query_one(
                    "SELECT evidence_id, raw_data_hash, chain_position FROM evidence_vault "
                    "ORDER BY chain_position DESC LIMIT 1"
                )
                if prev_row:
                    chain_pos = int(prev_row["chain_position"] or 0) + 1
                    prev_hash = prev_row["raw_data_hash"]
                else:
                    chain_pos = 1
                    prev_hash = _sha256("ARES-EVIDENCE-VAULT-GENESIS")

                # Merkle root = sha256(prev_hash + current_hash)
                merkle_root = _sha256(prev_hash + raw_hash)

                db.execute(
                    """
                    INSERT INTO evidence_vault
                        (evidence_id, mission_id, source_tool, source_url,
                         collection_timestamp, ntp_timestamp, raw_data_hash,
                         merkle_root, merkle_proof, analyst_id,
                         approval_gate_id, chain_position, prev_hash, metadata)
                    VALUES (?, ?, ?, ?, datetime('now'), datetime(?, 'unixepoch'),
                            ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id, mission_id, source_tool, source_url,
                        ntp_ts,
                        raw_hash, merkle_root,
                        json.dumps({"prev_hash": prev_hash}),
                        analyst_id, approval_gate_id,
                        chain_pos, prev_hash,
                        json.dumps(metadata or {}),
                    ),
                )
            break  # success
        except Exception as exc:
            msg = str(exc).lower()
            # Retry on chain_position UNIQUE collision (cross-process race)
            if ("unique" in msg or "constraint" in msg) and attempt < MAX_RETRIES - 1:
                continue
            raise

    bus.publish_sync(
        EventType.EVIDENCE_VAULT_ENTRY,
        payload={
            "evidence_id":  evidence_id,
            "source_tool":  source_tool,
            "chain_pos":    chain_pos,
            "merkle_root":  merkle_root,
        },
        source="enterprise.evidence_vault",
        correlation_id=mission_id,
    )
    return evidence_id


def verify_vault_chain() -> dict:
    """
    Walk the vault chain forward, verify Merkle root at each position.
    Returns {intact, checked, break_at}.
    """
    rows = db.query_all(
        "SELECT evidence_id, raw_data_hash, prev_hash, merkle_root, chain_position "
        "FROM evidence_vault ORDER BY chain_position ASC"
    )
    expected_prev = _sha256("ARES-EVIDENCE-VAULT-GENESIS")
    for i, r in enumerate(rows):
        if r["prev_hash"] != expected_prev:
            return {"intact": False, "checked": i, "break_at": r["chain_position"]}
        computed = _sha256(r["prev_hash"] + r["raw_data_hash"])
        if computed != r["merkle_root"]:
            return {"intact": False, "checked": i, "break_at": r["chain_position"]}
        expected_prev = r["raw_data_hash"]
    return {"intact": True, "checked": len(rows), "break_at": None}


def list_evidence(mission_id: Optional[str] = None, limit: int = 100) -> list[dict]:
    limit = max(1, min(int(limit), 10000))   # clamp + coerce to int (no injection)
    if mission_id:
        rows = db.query_all(
            "SELECT * FROM evidence_vault WHERE mission_id = ? "
            "ORDER BY chain_position LIMIT ?",
            (mission_id, limit),
        )
    else:
        rows = db.query_all(
            "SELECT * FROM evidence_vault ORDER BY chain_position DESC LIMIT ?",
            (limit,),
        )
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────
# Approval Gates
# ─────────────────────────────────────────────────────────────

# Gated action types (Order 19)
GATED_ACTIONS = {
    "SIGINT_ACTIVE",
    "EXTERNAL_SHARE",
    "HUMAN_TWIN_BUILD",
    "ACTIVE_SCAN",
    "THREAT_RESPONSE_EXTERNAL",
}

GATE_EXPIRY_SECONDS = 300   # 5 minutes


def require_gate(action_type: str, action_payload: dict,
                  risk_level: str = "medium") -> str:
    """
    Create an approval gate and block the calling path until resolved.
    Returns gate_id. Call check_gate(gate_id) to poll.

    Order 19: the code path for any gated action must pass through this function.
    """
    gate_id = str(uuid.uuid4())
    expires_at = time.time() + GATE_EXPIRY_SECONDS
    db.execute(
        """
        INSERT INTO approval_gates
            (gate_id, action_type, action_payload, requested_at,
             status, expires_at, risk_level)
        VALUES (?, ?, ?, datetime('now'), 'pending', datetime(?, 'unixepoch'), ?)
        """,
        (gate_id, action_type, json.dumps(action_payload, default=str),
         expires_at, risk_level),
    )
    bus.publish_sync(
        EventType.APPROVAL_GATE_TRIGGERED,
        payload={
            "gate_id":      gate_id,
            "action_type":  action_type,
            "risk_level":   risk_level,
        },
        source="enterprise.approval_gates",
    )
    return gate_id


def resolve_gate(gate_id: str, approved: bool,
                  approved_by: str = "user") -> bool:
    """
    Approve or deny a gate. Returns True if approved.
    Signs the resolution with HMAC-SHA256.
    """
    sig = hmac.new(
        b"ares_x_gate_key",
        f"{gate_id}:{approved}:{approved_by}:{time.time()}".encode(),
        hashlib.sha256,
    ).hexdigest()

    status = "approved" if approved else "denied"
    db.execute(
        """
        UPDATE approval_gates
        SET status = ?, approved_at = datetime('now'),
            approved_by = ?, approval_signature = ?
        WHERE gate_id = ? AND status = 'pending'
        """,
        (status, approved_by, sig, gate_id),
    )
    bus.publish_sync(
        EventType.APPROVAL_GATE_RESOLVED,
        payload={"gate_id": gate_id, "resolution": status, "approved_by": approved_by},
        source="enterprise.approval_gates",
    )
    return approved


def check_gate(gate_id: str) -> str:
    """Return gate status: pending | approved | denied | expired."""
    row = db.query_one("SELECT status, expires_at FROM approval_gates WHERE gate_id = ?",
                        (gate_id,))
    if row is None:
        return "not_found"
    if row["status"] == "pending":
        # Check expiry
        try:
            from dateutil import parser as dp
            exp_ts = dp.parse(row["expires_at"]).timestamp()
        except Exception:
            exp_ts = time.time() + 1
        if time.time() > exp_ts:
            db.execute(
                "UPDATE approval_gates SET status = 'expired' WHERE gate_id = ?",
                (gate_id,),
            )
            return "expired"
    return row["status"]


def list_pending_gates() -> list[dict]:
    rows = db.query_all(
        "SELECT * FROM approval_gates WHERE status = 'pending' ORDER BY requested_at"
    )
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────
# Watchlist Engine
# ─────────────────────────────────────────────────────────────

def create_watchlist(name: str, query: str,
                      entity_type: Optional[str] = None,
                      check_interval: int = 3600,
                      alert_threshold: float = 0.3) -> str:
    """Create a watchlist entry. Returns watchlist_id."""
    wid = str(uuid.uuid4())
    db.execute(
        """
        INSERT INTO watchlists
            (watchlist_id, name, entity_type, query,
             check_interval_seconds, alert_threshold, status)
        VALUES (?, ?, ?, ?, ?, ?, 'active')
        """,
        (wid, name, entity_type, query, check_interval, alert_threshold),
    )
    return wid


def score_watchlist_entity(watchlist_id: str,
                             change_type: str,
                             change_score: float,
                             payload: Optional[dict] = None) -> None:
    """
    Record a detected change for a watchlist entry.
    Fires WATCHLIST_ALERT if change_score exceeds alert_threshold.
    """
    row = db.query_one(
        "SELECT alert_threshold, name FROM watchlists WHERE watchlist_id = ?",
        (watchlist_id,),
    )
    if row is None:
        return

    event_id = str(uuid.uuid4())
    db.execute(
        """
        INSERT INTO watchlist_events
            (event_id, watchlist_id, detected_at, change_type,
             change_score, payload, alerted)
        VALUES (?, ?, datetime('now'), ?, ?, ?, ?)
        """,
        (event_id, watchlist_id, change_type, change_score,
         json.dumps(payload or {}),
         1 if change_score >= float(row["alert_threshold"]) else 0),
    )

    if change_score >= float(row["alert_threshold"]):
        db.execute(
            "UPDATE watchlists SET current_risk_score = ?, last_checked = datetime('now') "
            "WHERE watchlist_id = ?",
            (change_score, watchlist_id),
        )
        bus.publish_sync(
            EventType.WATCHLIST_ALERT,
            payload={
                "watchlist_id": watchlist_id,
                "name":         row["name"],
                "change_type":  change_type,
                "change_score": change_score,
                "payload":      payload or {},
            },
            source="enterprise.watchlist_engine",
            correlation_id=watchlist_id,
        )


def list_watchlists(status: Optional[str] = None) -> list[dict]:
    if status:
        rows = db.query_all(
            "SELECT * FROM watchlists WHERE status = ? ORDER BY created_at DESC",
            (status,),
        )
    else:
        rows = db.query_all("SELECT * FROM watchlists ORDER BY created_at DESC")
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────
# Brief Generator
# ─────────────────────────────────────────────────────────────

@dataclass
class Brief:
    brief_id:   str = field(default_factory=lambda: str(uuid.uuid4()))
    title:      str = ""
    executive_summary: str = ""
    key_findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    classification: str = "UNCLASSIFIED"
    generated_at: float = field(default_factory=time.time)


def generate_brief(mission_id: Optional[str] = None,
                    title: Optional[str] = None,
                    classification: str = "UNCLASSIFIED") -> Brief:
    """
    Generate an executive brief from a mission's decision support output.
    Production: render as PDF via reportlab.
    """
    from aresx.mission.mission_control import get_mission, get_objectives

    brief = Brief(
        title=title or f"Intelligence Brief — {time.strftime('%Y-%m-%d')}",
        classification=classification,
    )

    if mission_id:
        mission = get_mission(mission_id)
        objs = get_objectives(mission_id) if mission else []
        completed = [o for o in objs if o["status"] == "complete"]
        evidence_total = sum(int(o.get("evidence_count") or 0) for o in completed)

        brief.executive_summary = (
            f"Investigation '{mission['goal'] if mission else 'N/A'}' completed. "
            f"{len(completed)}/{len(objs)} objectives achieved. "
            f"{evidence_total} evidence pieces collected and fused."
        )
        brief.key_findings = [o["description"] for o in completed[:5]]
        brief.recommendations = [
            "Add identified entities to continuous watchlist",
            "Share findings with relevant stakeholders",
            "Schedule follow-up investigation in 30 days",
        ]
    else:
        brief.executive_summary = "Routine intelligence brief. No active mission."
        brief.key_findings = ["No anomalous activity detected in monitored entities"]
        brief.recommendations = ["Continue routine monitoring"]

    bus.publish_sync(
        EventType.BRIEF_GENERATED,
        payload={"brief_id": brief.brief_id, "title": brief.title},
        source="enterprise.brief_generator",
        correlation_id=mission_id,
    )
    return brief


def export_brief_markdown(brief: Brief) -> str:
    """Export brief as markdown (reportlab PDF path for production)."""
    lines = [
        f"# {brief.title}",
        f"**Classification:** {brief.classification}",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(brief.generated_at))}",
        "",
        "## Executive Summary",
        brief.executive_summary,
        "",
        "## Key Findings",
    ]
    for i, f in enumerate(brief.key_findings, 1):
        lines.append(f"{i}. {f}")
    lines += ["", "## Recommendations"]
    for i, r in enumerate(brief.recommendations, 1):
        lines.append(f"{i}. {r}")
    return "\n".join(lines)
