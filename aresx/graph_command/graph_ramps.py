"""
aresx.graph_command.graph_ramps — digital_twin → graph_command bridge
=====================================================================
Before this module existed, graph_command's analytics functions
(map_influence, detect_communities, ...) took a raw `graph_state` dict
that nobody in the system ever produced. They were an unwired
capability: the spec existed, the road existed, but no traffic ever
reached it.

This module wires that road to the on-ramp: the **digital twin**, which
is the only subsystem that actually builds {nodes, edges} graph-state
dicts (via its twin_store snapshots and twin builders).

Two kinds of ramps live here:

1. **State ramps** — `twin_graph_state(twin_id)` and
   `latest_twin_graph_state(twin_type, entity_name)` turn a digital twin
   into the graph_state dict that graph_analytics expects.
2. **Tool ramps** — async `_tool_graph_*` wrappers that follow the
   aresx/chat/router.py _tool_* convention (dict args in, dict result
   out) so Gemini/Groq can select them from the chat. These are
   registered by the chat router in its TOOL_SCHEMAS / TOOL_HANDLERS.
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("ares.graph_ramps")


def twin_graph_state(twin_id: str) -> Optional[dict]:
    """
    Load the most recent digital-twin snapshot and return its
    graph_state dict ({"nodes": [...], "edges": [...]}), ready to feed
    aresx.graph_command.graph_analytics.

    Returns None when the twin has no snapshots yet (analyzer
    callers should degrade gracefully rather than crash).
    """
    from aresx.digital_twin import list_snapshots, load_snapshot

    snaps = list_snapshots(twin_id)
    if not snaps:
        return None
    return load_snapshot(snaps[-1])


def latest_twin_graph_state(twin_type: str, entity_name: str) -> Optional[dict]:
    """
    Convenience: find a twin by type + entity name and load its latest
    graph state. Used by the chat tool ramps so a user can say
    "analyze influence for org Acme" without knowing twin IDs.
    """
    from aresx.digital_twin import find_twin_by_name

    twin = find_twin_by_name(entity_name, twin_type=twin_type)
    if twin is None:
        return None
    return twin_graph_state(twin["twin_id"])


# ── Router tool ramps (async, dict-in/dict-out convention) ──────────────

async def _tool_graph_analyze_influence(args: dict) -> dict:
    """
    PageRank-based influence scoring over a digital twin's graph.
    Expects {"twin_type": "org"|"infra"|..., "entity": "<name>"}.
    Requires the digital twin to exist first — that's the whole point
    of the twin→graph dependency: analysis over state nobody built is
    analysis over nothing.
    """
    state = latest_twin_graph_state(args["twin_type"], args["entity"])
    if state is None:
        return {
            "error": (
                f"No digital twin with graph snapshots found for "
                f"{args['twin_type']}/{args['entity']} — build the twin "
                "first, then analyze it."
            ),
            "suggested_next_tool": "build_digital_twin",
        }
    from aresx.graph_command import map_influence

    k = int(args.get("top_k", 10))
    result = map_influence(state, top_k=max(1, min(k, 50)))
    return {
        "entity": args["entity"],
        "top_influencers": result.top_influencers,
        "node_count": len(state.get("nodes", [])),
        "algorithm": "pagerank",
    }


async def _tool_graph_find_communities(args: dict) -> dict:
    """
    Community detection (Louvain / label-propagation) over a digital
    twin's graph — reveals how the modeled entity's parts cluster.
    """
    state = latest_twin_graph_state(args["twin_type"], args["entity"])
    if state is None:
        return {
            "error": (
                f"No digital twin with graph snapshots found for "
                f"{args['twin_type']}/{args['entity']} — build the twin first."
            ),
            "suggested_next_tool": "build_digital_twin",
        }
    from aresx.graph_command import detect_communities

    result = detect_communities(state)
    return {
        "entity": args["entity"],
        "community_count": result.community_count,
        "modularity": round(result.modularity, 6),
        "algorithm": result.algorithm_used,
        "communities": [
            {"id": i, "size": len(c), "members": c[:20]}
            for i, c in enumerate(result.communities)
        ],
    }


async def _tool_graph_find_hidden_relationships(args: dict) -> dict:
    """
    Surface non-obvious links between nodes that aren't directly
    connected but share neighbors (Jaccard neighbor-scoring) — likely
    missing edges in the twin model.
    """
    state = latest_twin_graph_state(args["twin_type"], args["entity"])
    if state is None:
        return {
            "error": (
                f"No digital twin with graph snapshots found for "
                f"{args['twin_type']}/{args['entity']} — build the twin first."
            ),
            "suggested_next_tool": "build_digital_twin",
        }
    from aresx.graph_command import find_hidden_relationships

    rels = find_hidden_relationships(
        state,
        top_k=int(args.get("top_k", 5)),
        min_score=float(args.get("min_score", 0.3)),
    )
    return {
        "entity": args["entity"],
        "hidden_relationships": [
            {"node_a": r.node_a, "node_b": r.node_b,
             "name_a": r.name_a, "name_b": r.name_b,
             "score": r.score, "method": r.method}
            for r in rels[:20]
        ],
        "count": len(rels),
    }


async def _tool_graph_centrality(args: dict) -> dict:
    """
    Centrality dashboard (degree, betweenness, closeness) over the twin
    graph — which nodes are chokepoints if removed.
    """
    state = latest_twin_graph_state(args["twin_type"], args["entity"])
    if state is None:
        return {
            "error": (
                f"No digital twin with graph snapshots found for "
                f"{args['twin_type']}/{args['entity']} — build the twin first."
            ),
            "suggested_next_tool": "build_digital_twin",
        }
    from aresx.graph_command import compute_centrality

    k = int(args.get("top_k", 5))
    result = compute_centrality(state, top_k=max(1, min(k, 50)))
    return {
        "entity": args["entity"],
        "top_central_nodes": result.top_nodes,
        "node_count": len(state.get("nodes", [])),
    }


async def _tool_graph_network_vulnerability(args: dict) -> dict:
    """
    Structural attack-surface analysis over the twin graph —
    articulation points, bridges, and overall robustness.
    """
    state = latest_twin_graph_state(args["twin_type"], args["entity"])
    if state is None:
        return {
            "error": (
                f"No digital twin with graph snapshots found for "
                f"{args['twin_type']}/{args['entity']} — build the twin first."
            ),
            "suggested_next_tool": "build_digital_twin",
        }
    from aresx.graph_command import analyze_network_vulnerability

    result = analyze_network_vulnerability(state)
    return {
        "entity": args["entity"],
        "articulation_points": result.articulation_points,
        "bridges": [{"from": a, "to": b} for a, b in result.bridges[:20]],
        "attack_robustness": round(result.attack_robustness, 6),
        "recommendations": result.recommendations,
    }


# Keep the public API small and explicit.
__all__ = [
    "twin_graph_state",
    "latest_twin_graph_state",
    "_tool_graph_analyze_influence",
    "_tool_graph_find_communities",
    "_tool_graph_find_hidden_relationships",
    "_tool_graph_centrality",
    "_tool_graph_network_vulnerability",
]
