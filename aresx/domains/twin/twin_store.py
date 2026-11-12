"""
ARES X v8.0 — Phase 3.1: Digital Twin Store.

Persistence layer for all twin types. Each twin has:
  • A row in `twin_registry` (SQLite) — metadata, status, freshness
  • A node in Kuzu (when Kuzu is available) — graph relationships
  • One or more TwinSnapshot blobs — serialized graph state per checkpoint

Design principles
-----------------
• Kuzu is optional (Order 20) — if unavailable, twin graph state is stored
  as JSON in SQLite and returned as dicts. Callers must not assume Kuzu types.
• Snapshots are gzip-compressed JSON dicts (not native Kuzu BLOBs) so they
  round-trip reliably whether or not Kuzu is installed.
• Freshness decay: freshness = e^(-0.1 * hours_since_refresh) per Order 14.
"""
from __future__ import annotations

import gzip
import json
import logging
import math
import time
import uuid
from typing import Any, Optional

from aresx.storage import db, graph

logger = logging.getLogger(__name__)

# Freshness decay constant k per Order 14: freshness = e^(-k * hours)
_FRESHNESS_K: float = 0.1


def _freshness(last_updated: float) -> float:
    """Compute freshness score in [0, 1]. 1.0 = just refreshed."""
    hours = (time.time() - last_updated) / 3600.0
    return max(0.0, math.exp(-_FRESHNESS_K * hours))


# ──────────────────────────────────────────────────────────────
# Twin CRUD
# ──────────────────────────────────────────────────────────────

def create_twin(twin_type: str, entity_name: str,
                confidence_score: float = 0.0,
                entity_id: Optional[str] = None) -> str:
    """
    Register a new twin. Returns twin_id.
    twin_type: one of org | infra | adversary | human | supply_chain | cyber_terrain | timeline
    """
    twin_id = entity_id or str(uuid.uuid4())
    now = time.time()
    freshness = _freshness(now)

    db.execute(
        """
        INSERT OR REPLACE INTO twin_registry
            (twin_id, twin_type, entity_id, entity_name, created_at,
             last_updated, snapshot_count, confidence_score, freshness_score, status)
        VALUES (?, ?, ?, ?, datetime('now'), datetime('now'), 0, ?, ?, 'building')
        """,
        (twin_id, twin_type, twin_id, entity_name, confidence_score, freshness),
    )

    # Kuzu node — non-fatal if Kuzu absent (Order 20)
    if graph.is_available():
        graph.execute(
            """
            MERGE (t:Twin {twin_id: $tid})
            SET t.twin_type = $ttype,
                t.entity_id = $eid,
                t.created_at = datetime(),
                t.last_updated = datetime(),
                t.snapshot_count = 0,
                t.confidence_score = $conf,
                t.status = 'building'
            """,
            {"tid": twin_id, "ttype": twin_type, "eid": twin_id, "conf": confidence_score},
        )

    return twin_id


def update_twin_status(twin_id: str, status: str,
                        confidence_score: Optional[float] = None) -> None:
    """Update twin status and optionally confidence. Also recalculates freshness."""
    freshness = _freshness(time.time())
    if confidence_score is not None:
        db.execute(
            """
            UPDATE twin_registry
            SET status = ?, freshness_score = ?,
                confidence_score = ?, last_updated = datetime('now')
            WHERE twin_id = ?
            """,
            (status, freshness, confidence_score, twin_id),
        )
    else:
        db.execute(
            """
            UPDATE twin_registry
            SET status = ?, freshness_score = ?,
                last_updated = datetime('now')
            WHERE twin_id = ?
            """,
            (status, freshness, twin_id),
        )


def get_twin(twin_id: str) -> Optional[dict]:
    """Return twin metadata dict or None."""
    row = db.query_one(
        "SELECT * FROM twin_registry WHERE twin_id = ?", (twin_id,)
    )
    if row is None:
        return None
    r = dict(row)
    # Attach live freshness (may differ from stored if not recently refreshed)
    try:
        last = row["last_updated"]
        if isinstance(last, str):
            import datetime as dt
            ts = dt.datetime.fromisoformat(last).timestamp()
        else:
            ts = float(last)
        r["live_freshness"] = _freshness(ts)
    except Exception:
        r["live_freshness"] = 0.0
    return r


def list_twins(twin_type: Optional[str] = None, status: Optional[str] = None) -> list[dict]:
    """List all twins with optional type / status filter."""
    clauses: list[str] = []
    params: list = []
    if twin_type:
        clauses.append("twin_type = ?")
        params.append(twin_type)
    if status:
        clauses.append("status = ?")
        params.append(status)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = db.query_all(
        f"SELECT * FROM twin_registry {where} ORDER BY last_updated DESC", params
    )
    return [dict(r) for r in rows]


def find_twin_by_name(entity_name: str, twin_type: Optional[str] = None) -> Optional[dict]:
    """Lookup by entity name (case-insensitive)."""
    if twin_type:
        row = db.query_one(
            "SELECT * FROM twin_registry WHERE lower(entity_name) = lower(?) AND twin_type = ?",
            (entity_name, twin_type),
        )
    else:
        row = db.query_one(
            "SELECT * FROM twin_registry WHERE lower(entity_name) = lower(?)",
            (entity_name,),
        )
    return dict(row) if row else None


# ──────────────────────────────────────────────────────────────
# Snapshot CRUD
# ──────────────────────────────────────────────────────────────

def save_snapshot(twin_id: str, graph_state: dict,
                  metadata: Optional[dict] = None) -> str:
    """
    Serialize and store a twin snapshot. Returns snapshot_id.

    graph_state: dict containing the twin's entity graph (nodes + edges).
    It is gzip-compressed JSON rather than a native Kuzu blob so it
    round-trips whether or not Kuzu is installed.
    """
    snapshot_id = str(uuid.uuid4())
    compressed = gzip.compress(
        json.dumps(graph_state, default=str).encode(), compresslevel=6
    )
    db.execute(
        """
        INSERT INTO twin_registry (twin_id, twin_type, entity_id, entity_name,
            created_at, last_updated, snapshot_count, confidence_score,
            freshness_score, status)
        SELECT twin_id, twin_type, entity_id, entity_name,
               created_at, last_updated, snapshot_count, confidence_score,
               freshness_score, status
        FROM twin_registry WHERE twin_id = ?
        ON CONFLICT(twin_id) DO NOTHING
        """,
        (twin_id,),
    )
    # Store snapshot in rag_documents as blob placeholder until we have a
    # dedicated snapshots table. For now use a JSON row in rag_documents.
    meta = {"type": "twin_snapshot", "twin_id": twin_id, **(metadata or {})}
    db.execute(
        """
        INSERT INTO rag_documents
            (doc_id, source_path, content_hash, title, doc_type,
             ingested_at, metadata)
        VALUES (?, ?, ?, ?, 'twin_snapshot', datetime('now'), ?)
        """,
        (
            snapshot_id,
            f"twin://{twin_id}/{snapshot_id}",
            _hash_blob(compressed),
            f"Snapshot {snapshot_id[:8]} for {twin_id}",
            json.dumps(meta),
        ),
    )
    # Update snapshot_count on the twin
    db.execute(
        "UPDATE twin_registry SET snapshot_count = snapshot_count + 1 WHERE twin_id = ?",
        (twin_id,),
    )
    # Store the actual blob in a small in-memory registry for this session.
    # Production: move to a dedicated snapshots table.
    _snapshot_cache[snapshot_id] = compressed
    return snapshot_id


def load_snapshot(snapshot_id: str) -> Optional[dict]:
    """Return decompressed graph_state dict or None."""
    compressed = _snapshot_cache.get(snapshot_id)
    if compressed is None:
        return None
    return json.loads(gzip.decompress(compressed).decode())


def list_snapshots(twin_id: str) -> list[str]:
    """Return list of snapshot_ids for a twin, most recent first."""
    rows = db.query_all(
        "SELECT doc_id FROM rag_documents WHERE doc_type = 'twin_snapshot' "
        "  AND json_extract(metadata, '$.twin_id') = ? "
        "ORDER BY ingested_at DESC",
        (twin_id,),
    )
    return [r["doc_id"] for r in rows]


# In-process snapshot cache (survives for the lifetime of the process)
_snapshot_cache: dict[str, bytes] = {}


def _hash_blob(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()
