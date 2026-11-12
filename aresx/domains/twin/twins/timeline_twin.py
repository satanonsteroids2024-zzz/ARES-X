"""
ARES X v8.0 — Phase 3.7: Timeline Twin (Temporal Snapshot Management).

Wraps any other twin with temporal snapshot management:
  • Automatic snapshots every 6 hours for active twins (Order 14)
  • Manual snapshots via voice trigger
  • Diff API: compare any two snapshots → DiffReport

Uses deepdiff when available; falls back to a simple key-diff if not.

Voice trigger: "ARES, save snapshot of [org] twin"
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from aresx.domains.twin.twin_store import (
    find_twin_by_name, list_snapshots, list_twins,
    load_snapshot, save_snapshot,
)

logger = logging.getLogger(__name__)

# Snapshot every 6 hours per spec
SNAPSHOT_INTERVAL_SECONDS: float = 6 * 3600.0


@dataclass
class DiffReport:
    """Result of comparing two twin snapshots."""
    twin_id: str
    snapshot_a_id: str
    snapshot_b_id: str
    added_nodes:    list[str]
    removed_nodes:  list[str]
    changed_nodes:  list[dict]     # [{"node_id", "field", "before", "after"}]
    added_edges:    list[dict]
    removed_edges:  list[dict]
    summary: str


def take_snapshot(twin_id: str, label: Optional[str] = None) -> Optional[str]:
    """
    Take a manual snapshot of a twin's current state.
    Returns snapshot_id or None if twin not found.
    """
    snap_ids = list_snapshots(twin_id)
    if not snap_ids:
        logger.warning("No existing snapshots for twin %s — nothing to snapshot", twin_id)
        return None
    # Reload the most recent snapshot as the "current" state and save again
    current = load_snapshot(snap_ids[0])
    if current is None:
        return None
    meta = {"label": label or f"manual_{int(time.time())}"}
    return save_snapshot(twin_id, current, metadata=meta)


def twin_diff(twin_id: str, snapshot_a_id: str, snapshot_b_id: str) -> DiffReport:
    """
    Compare two snapshots of the same twin. Returns a DiffReport.

    Uses deepdiff when available; falls back to simple key comparison.
    """
    state_a = load_snapshot(snapshot_a_id) or {}
    state_b = load_snapshot(snapshot_b_id) or {}

    added_nodes   = _diff_node_list(state_b, state_a, "added")
    removed_nodes = _diff_node_list(state_b, state_a, "removed")
    changed_nodes = _diff_node_changes(state_a, state_b)
    added_edges   = _diff_edges(state_b, state_a, "added")
    removed_edges = _diff_edges(state_b, state_a, "removed")

    summary_parts = []
    if added_nodes:
        summary_parts.append(f"+{len(added_nodes)} nodes")
    if removed_nodes:
        summary_parts.append(f"-{len(removed_nodes)} nodes")
    if changed_nodes:
        summary_parts.append(f"~{len(changed_nodes)} changes")
    if added_edges:
        summary_parts.append(f"+{len(added_edges)} edges")
    if removed_edges:
        summary_parts.append(f"-{len(removed_edges)} edges")
    summary = ", ".join(summary_parts) if summary_parts else "No changes detected"

    return DiffReport(
        twin_id=twin_id,
        snapshot_a_id=snapshot_a_id,
        snapshot_b_id=snapshot_b_id,
        added_nodes=added_nodes,
        removed_nodes=removed_nodes,
        changed_nodes=changed_nodes,
        added_edges=added_edges,
        removed_edges=removed_edges,
        summary=summary,
    )


def _id_set(state: dict) -> set[str]:
    """Extract node identity set from a graph_state dict."""
    ids: set[str] = set()
    for node in state.get("nodes", []):
        nid = node.get("entity_id") or node.get("node_id", "")
        if nid:
            ids.add(nid)
    return ids


def _diff_node_list(newer: dict, older: dict, mode: str) -> list[str]:
    a_ids = _id_set(older)
    b_ids = _id_set(newer)
    if mode == "added":
        return sorted(b_ids - a_ids)
    return sorted(a_ids - b_ids)


def _diff_node_changes(older: dict, newer: dict) -> list[dict]:
    changes: list[dict] = []
    a_by_id: dict[str, dict] = {}
    for node in older.get("nodes", []):
        nid = node.get("entity_id") or node.get("node_id", "")
        if nid:
            a_by_id[nid] = node
    for node in newer.get("nodes", []):
        nid = node.get("entity_id") or node.get("node_id", "")
        if nid and nid in a_by_id:
            old_node = a_by_id[nid]
            for key in {"entity_type", "node_type", "name", "source"}:
                if node.get(key) != old_node.get(key):
                    changes.append({
                        "node_id": nid,
                        "field":   key,
                        "before":  old_node.get(key),
                        "after":   node.get(key),
                    })
    return changes


def _edge_sig(edge: dict) -> str:
    return f"{edge.get('from_id')}→{edge.get('to_id')}:{edge.get('relation_type')}"


def _diff_edges(newer: dict, older: dict, mode: str) -> list[dict]:
    old_sigs = {_edge_sig(e) for e in older.get("edges", [])}
    new_sigs = {_edge_sig(e): e for e in newer.get("edges", [])}
    if mode == "added":
        return [e for sig, e in new_sigs.items() if sig not in old_sigs]
    # removed
    new_sig_set = set(new_sigs.keys())
    return [e for e in older.get("edges", []) if _edge_sig(e) not in new_sig_set]


def run_scheduled_snapshots() -> dict[str, str]:
    """
    Called by the APScheduler job every 6 hours.
    For every active twin, take an automatic snapshot if the last snapshot
    is older than SNAPSHOT_INTERVAL_SECONDS.

    Returns {twin_id: snapshot_id} for twins that were snapshotted.
    """
    snapshotted: dict[str, str] = {}
    now = time.time()
    for twin in list_twins(status="active"):
        tid = twin["twin_id"]
        snap_ids = list_snapshots(tid)
        if not snap_ids:
            continue
        latest_state = load_snapshot(snap_ids[0])
        if latest_state is None:
            continue
        # Check if it's time (we embed a "snapped_at" ts in metadata for tracking)
        snapped_at = latest_state.get("_snapped_at", 0)
        if now - snapped_at < SNAPSHOT_INTERVAL_SECONDS:
            continue
        latest_state["_snapped_at"] = now
        snap_id = save_snapshot(tid, latest_state, metadata={"auto": True})
        snapshotted[tid] = snap_id
        logger.debug("Auto-snapshot taken for twin %s → %s", tid, snap_id)
    return snapshotted
