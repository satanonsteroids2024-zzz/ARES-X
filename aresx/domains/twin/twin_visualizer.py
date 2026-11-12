"""
ARES X v8.0 — Phase 3.10: Twin Visualizer.

Generates layout data for twin graph visualization.

Two rendering paths:
  1. Qt6 (PySide6) — rich interactive: org chart, network topology, timeline.
     Only available when PySide6 is installed (desktop runtime).
  2. Headless layout data — always available. Returns JSON-serializable
     dict of nodes + positions suitable for any frontend renderer.

Order 20: never crashes when Qt6 is absent — degrades to layout data.
"""
from __future__ import annotations

import logging
import math
from typing import Any, Optional

logger = logging.getLogger(__name__)

try:
    from PySide6.QtWidgets import QWidget
    _QT = True
except ImportError:
    _QT = False


# ──────────────────────────────────────────────────────────────
# Layout algorithms (headless — always available)
# ──────────────────────────────────────────────────────────────

def _circular_layout(nodes: list[dict]) -> dict[str, tuple[float, float]]:
    """Place nodes evenly on a circle. Suitable for small graphs."""
    n = len(nodes)
    if n == 0:
        return {}
    positions: dict[str, tuple[float, float]] = {}
    for i, node in enumerate(nodes):
        angle = 2 * math.pi * i / n
        nid = node.get("entity_id") or node.get("node_id", str(i))
        positions[nid] = (math.cos(angle), math.sin(angle))
    return positions


def _hierarchical_layout(root_id: str, nodes: list[dict],
                          edges: list[dict]) -> dict[str, tuple[float, float]]:
    """BFS-based hierarchical layout rooted at root_id."""
    adjacency: dict[str, list[str]] = {}
    for e in edges:
        fid, tid = e.get("from_id", ""), e.get("to_id", "")
        adjacency.setdefault(fid, []).append(tid)

    positions: dict[str, tuple[float, float]] = {}
    queue = [(root_id, 0, 0.0)]
    visited: set[str] = {root_id}
    level_counts: dict[int, int] = {}

    while queue:
        nid, depth, _ = queue.pop(0)
        level_counts[depth] = level_counts.get(depth, 0)
        slot = level_counts[depth]
        level_counts[depth] += 1
        positions[nid] = (float(slot) - (depth * 0.5), -float(depth))
        for child in adjacency.get(nid, []):
            if child not in visited:
                visited.add(child)
                queue.append((child, depth + 1, 0.0))

    # Place any disconnected nodes off to the side
    x_offset = max((p[0] for p in positions.values()), default=0.0) + 2.0
    for node in nodes:
        nid = node.get("entity_id") or node.get("node_id", "")
        if nid and nid not in positions:
            positions[nid] = (x_offset, 0.0)
            x_offset += 1.0

    return positions


def get_layout_data(twin_id: str, graph_state: dict,
                     layout: str = "hierarchical") -> dict:
    """
    Return JSON-serializable layout data for a twin's graph state.

    Args:
        twin_id:     the twin's ID (used as root for hierarchical)
        graph_state: dict with "nodes" + "edges" keys
        layout:      "circular" | "hierarchical"

    Returns:
        {
          "nodes": [{"id", "name", "type", "x", "y", ...}],
          "edges": [{"from", "to", "label"}],
        }
    """
    raw_nodes = graph_state.get("nodes", [])
    raw_edges = graph_state.get("edges", [])

    if layout == "hierarchical":
        positions = _hierarchical_layout(twin_id, raw_nodes, raw_edges)
    else:
        positions = _circular_layout(raw_nodes)

    out_nodes = []
    for node in raw_nodes:
        nid = node.get("entity_id") or node.get("node_id", "")
        x, y = positions.get(nid, (0.0, 0.0))
        out_nodes.append({
            "id":   nid,
            "name": node.get("name", nid),
            "type": node.get("entity_type") or node.get("node_type", "Unknown"),
            "source": node.get("source", ""),
            "x":    round(x, 4),
            "y":    round(y, 4),
        })

    out_edges = [
        {
            "from":  e.get("from_id", ""),
            "to":    e.get("to_id", ""),
            "label": e.get("relation_type", "related"),
        }
        for e in raw_edges
    ]

    return {"twin_id": twin_id, "nodes": out_nodes, "edges": out_edges}


def get_diff_visualization(diff_report) -> dict:
    """
    Return a visualization-friendly representation of a DiffReport.
    Nodes colored by: green=added, red=removed, yellow=changed, gray=unchanged.
    """
    added_ids   = set(diff_report.added_nodes)
    removed_ids = set(diff_report.removed_nodes)
    changed_ids = {c["node_id"] for c in diff_report.changed_nodes}

    def _color(nid: str) -> str:
        if nid in added_ids:   return "#00cc44"
        if nid in removed_ids: return "#cc2200"
        if nid in changed_ids: return "#ccaa00"
        return "#888888"

    return {
        "twin_id":        diff_report.twin_id,
        "summary":        diff_report.summary,
        "snapshot_a":     diff_report.snapshot_a_id,
        "snapshot_b":     diff_report.snapshot_b_id,
        "node_colors":    {nid: _color(nid) for nid in
                           added_ids | removed_ids | changed_ids},
        "added_nodes":    diff_report.added_nodes,
        "removed_nodes":  diff_report.removed_nodes,
        "changed_nodes":  diff_report.changed_nodes,
        "added_edges":    diff_report.added_edges,
        "removed_edges":  diff_report.removed_edges,
    }
