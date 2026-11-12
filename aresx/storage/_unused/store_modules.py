"""
aresx.storage — Storage sub-modules per TRD §1.2.

Per-spec individual store modules. All implementations live in db.py
(SQLite wrapper) and schema_v8.sql. These modules expose domain-specific
query helpers on top of the raw db layer.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Optional

from aresx.storage import db

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
# twin_store — Digital twin persistence helpers
# ══════════════════════════════════════════════════════════════

def get_active_twins() -> list[dict]:
    rows = db.query_all(
        "SELECT * FROM twin_registry WHERE status = 'active' ORDER BY last_updated DESC"
    )
    return [dict(r) for r in rows]


def archive_twin(twin_id: str) -> None:
    db.execute(
        "UPDATE twin_registry SET status = 'archived' WHERE twin_id = ?", (twin_id,)
    )


# ══════════════════════════════════════════════════════════════
# mission_store — Mission + campaign persistence helpers
# ══════════════════════════════════════════════════════════════

def get_mission_summary(mission_id: str) -> Optional[dict]:
    """Full mission + objectives + event count in one query."""
    from aresx.mission.mission_control import get_mission, get_objectives
    m = get_mission(mission_id)
    if not m:
        return None
    objs = get_objectives(mission_id)
    ev_row = db.query_one(
        "SELECT COUNT(*) AS n FROM mission_events WHERE mission_id = ?", (mission_id,)
    )
    return {
        **m,
        "objectives":      objs,
        "event_count":     int(ev_row["n"]) if ev_row else 0,
        "completed_count": sum(1 for o in objs if o["status"] == "complete"),
    }


def prune_completed_missions(older_than_days: int = 30) -> int:
    """Archive completed missions older than N days."""
    cutoff_ts = time.time() - older_than_days * 86400
    rows = db.query_all(
        "SELECT mission_id FROM missions WHERE status = 'complete' "
        "AND created_at < datetime(?, 'unixepoch')",
        (cutoff_ts,),
    )
    for r in rows:
        db.execute(
            "UPDATE missions SET status = 'archived' WHERE mission_id = ?",
            (r["mission_id"],),
        )
    return len(rows)


# ══════════════════════════════════════════════════════════════
# evidence_vault_store — Cryptographic evidence store helpers
# ══════════════════════════════════════════════════════════════

def get_evidence_stats() -> dict:
    """Summary statistics for the evidence vault."""
    total = db.query_one("SELECT COUNT(*) AS n FROM evidence_vault")
    by_source = db.query_all(
        "SELECT source_tool, COUNT(*) AS n FROM evidence_vault "
        "GROUP BY source_tool ORDER BY n DESC LIMIT 10"
    )
    return {
        "total":     int(total["n"]) if total else 0,
        "by_source": [{"source": r["source_tool"], "count": int(r["n"])} for r in by_source],
    }


def export_vault_csv(limit: int = 1000) -> str:
    """Export evidence vault as CSV for external audit tools."""
    rows = db.query_all(
        "SELECT evidence_id, source_tool, collection_timestamp, raw_data_hash, "
        "chain_position, prev_hash, merkle_root FROM evidence_vault "
        "ORDER BY chain_position ASC LIMIT ?",
        (limit,),
    )
    lines = ["evidence_id,source_tool,timestamp,raw_hash,chain_pos,prev_hash,merkle_root"]
    for r in rows:
        lines.append(",".join(str(r[k] or "") for k in [
            "evidence_id","source_tool","collection_timestamp",
            "raw_data_hash","chain_position","prev_hash","merkle_root"
        ]))
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
# watchlist_store — Watchlist persistence helpers
# ══════════════════════════════════════════════════════════════

def get_watchlist_summary() -> dict:
    """High-level watchlist summary for the UI dashboard."""
    total = db.query_one("SELECT COUNT(*) AS n FROM watchlists")
    active = db.query_one("SELECT COUNT(*) AS n FROM watchlists WHERE status = 'active'")
    high_risk = db.query_one(
        "SELECT COUNT(*) AS n FROM watchlists WHERE current_risk_score >= 0.7"
    )
    recent_alerts = db.query_all(
        "SELECT watchlist_id, change_type, change_score, detected_at "
        "FROM watchlist_events ORDER BY detected_at DESC LIMIT 5"
    )
    return {
        "total":         int(total["n"]) if total else 0,
        "active":        int(active["n"]) if active else 0,
        "high_risk":     int(high_risk["n"]) if high_risk else 0,
        "recent_alerts": [dict(r) for r in recent_alerts],
    }


def update_watchlist_interval(watchlist_id: str, interval_seconds: int) -> None:
    db.execute(
        "UPDATE watchlists SET check_interval_seconds = ? WHERE watchlist_id = ?",
        (interval_seconds, watchlist_id),
    )


# ══════════════════════════════════════════════════════════════
# simulation_store — Simulation results persistence
# ══════════════════════════════════════════════════════════════

def save_simulation_result(
    sim_type: str,
    entity_id: Optional[str],
    result_data: dict,
    mission_id: Optional[str] = None,
) -> str:
    """Persist a simulation result for later retrieval."""
    sim_id = str(uuid.uuid4())
    db.execute(
        """
        INSERT OR IGNORE INTO simulation_results
            (sim_id, sim_type, entity_id, mission_id, result_data, created_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
        """,
        (sim_id, sim_type, entity_id, mission_id, json.dumps(result_data, default=str)),
    )
    return sim_id


def list_simulation_results(sim_type: Optional[str] = None,
                              entity_id: Optional[str] = None) -> list[dict]:
    q = "SELECT sim_id, sim_type, entity_id, created_at FROM simulation_results"
    params: list = []
    clauses: list[str] = []
    if sim_type:
        clauses.append("sim_type = ?")
        params.append(sim_type)
    if entity_id:
        clauses.append("entity_id = ?")
        params.append(entity_id)
    if clauses:
        q += " WHERE " + " AND ".join(clauses)
    q += " ORDER BY created_at DESC LIMIT 50"
    rows = db.query_all(q, params)
    return [dict(r) for r in rows]
