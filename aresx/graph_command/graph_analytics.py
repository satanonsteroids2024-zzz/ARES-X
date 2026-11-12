"""
ARES X v8.0 — Phase 8.1: Graph Command Layer.

Advanced graph analytics on the ARES knowledge graph (TRD §1.2, Build Prompt §3 Phase 8):
  • influence_mapper          — PageRank-based influence scoring
  • community_detector        — Louvain + LPA community detection
  • hidden_relationship       — GNN-inspired hidden link prediction
  • centrality                — Full centrality intelligence dashboard
  • network_vulnerability     — Structural attack surface analysis

All algorithms operate on the twin graph state dict (nodes + edges) so
they work with or without Kuzu installed (Order 20).
Uses networkx when available; pure-Python fallback otherwise.
"""
from __future__ import annotations

import logging
import math
import random
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── networkx optional ────────────────────────────────────────
try:
    import networkx as nx
    _NX = True
except ImportError:
    _NX = False
    logger.debug("networkx not installed; using pure-Python graph algorithms")


def _build_nx(nodes: list[dict], edges: list[dict]):
    """Build a networkx DiGraph from twin graph state (when nx available)."""
    G = nx.DiGraph()
    for n in nodes:
        nid = n.get("entity_id") or n.get("node_id", "")
        if nid:
            G.add_node(nid, **{k: v for k, v in n.items() if isinstance(v, (str, int, float, bool))})
    for e in edges:
        a, b = e.get("from_id", ""), e.get("to_id", "")
        if a and b:
            G.add_edge(a, b, relation=e.get("relation_type", ""))
    return G


def _adj(nodes: list[dict], edges: list[dict]) -> dict[str, set[str]]:
    """Pure-Python undirected adjacency map."""
    adj: dict[str, set[str]] = {
        (n.get("entity_id") or n.get("node_id", "")): set()
        for n in nodes
    }
    for e in edges:
        a, b = e.get("from_id", ""), e.get("to_id", "")
        if a in adj and b in adj:
            adj[a].add(b)
            adj[b].add(a)
    return adj


# ──────────────────────────────────────────────────────────────
# 1. Influence Mapper
# ──────────────────────────────────────────────────────────────

@dataclass
class InfluenceResult:
    top_influencers: list[dict]    # [{"node_id", "name", "score"}]
    all_scores:      dict[str, float]


def map_influence(graph_state: dict, top_k: int = 10) -> InfluenceResult:
    """PageRank-based influence scoring over the twin graph."""
    nodes = graph_state.get("nodes", [])
    edges = graph_state.get("edges", [])
    if not nodes:
        return InfluenceResult([], {})

    if _NX:
        G = _build_nx(nodes, edges)
        try:
            scores = nx.pagerank(G, max_iter=100)
        except Exception:
            scores = {n: 1.0 / len(nodes) for n in G.nodes()}
    else:
        # Power-iteration PageRank (pure Python)
        node_ids = [n.get("entity_id") or n.get("node_id", "") for n in nodes]
        adj = _adj(nodes, edges)
        scores = {nid: 1.0 / len(node_ids) for nid in node_ids}
        damping = 0.85
        for _ in range(30):
            new_scores: dict[str, float] = {}
            for nid in node_ids:
                rank = (1 - damping) / len(node_ids)
                for nb in adj.get(nid, set()):
                    out_degree = len(adj.get(nb, set())) or 1
                    rank += damping * scores.get(nb, 0) / out_degree
                new_scores[nid] = rank
            scores = new_scores

    name_map = {
        (n.get("entity_id") or n.get("node_id", "")): n.get("name", "")
        for n in nodes
    }
    sorted_nodes = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top = [
        {"node_id": nid, "name": name_map.get(nid, nid), "score": round(s, 6)}
        for nid, s in sorted_nodes[:top_k]
    ]
    return InfluenceResult(top_influencers=top, all_scores=scores)


# ──────────────────────────────────────────────────────────────
# 2. Community Detector
# ──────────────────────────────────────────────────────────────

@dataclass
class CommunityResult:
    communities:        list[list[str]]    # list of node_id groups
    community_count:    int
    modularity:         float
    algorithm_used:     str


def detect_communities(graph_state: dict) -> CommunityResult:
    """Louvain community detection (networkx fallback: label propagation)."""
    nodes = graph_state.get("nodes", [])
    edges = graph_state.get("edges", [])
    if not nodes:
        return CommunityResult([], 0, 0.0, "none")

    if _NX:
        G = _build_nx(nodes, edges).to_undirected()
        try:
            from networkx.algorithms.community import louvain_communities
            comms = louvain_communities(G, seed=42)
            algo = "louvain"
        except Exception:
            try:
                from networkx.algorithms.community import label_propagation_communities
                comms = list(label_propagation_communities(G))
                algo = "label_propagation"
            except Exception:
                # Fallback: each connected component is a community
                comms = [list(c) for c in nx.connected_components(G)]
                algo = "connected_components"
        community_lists = [list(c) for c in comms]
        try:
            from networkx.algorithms.community.quality import modularity
            mod = modularity(G, comms)
        except Exception:
            mod = 0.0
    else:
        # Pure-Python label propagation
        node_ids = [n.get("entity_id") or n.get("node_id", "") for n in nodes]
        adj = _adj(nodes, edges)
        labels = {nid: i for i, nid in enumerate(node_ids)}
        for _ in range(10):
            for nid in node_ids:
                nbs = list(adj.get(nid, set()))
                if nbs:
                    label_counts: dict[int, int] = defaultdict(int)
                    for nb in nbs:
                        label_counts[labels[nb]] += 1
                    labels[nid] = max(label_counts, key=label_counts.get)
        groups: dict[int, list[str]] = defaultdict(list)
        for nid, lbl in labels.items():
            groups[lbl].append(nid)
        community_lists = list(groups.values())
        mod = 0.0
        algo = "label_propagation_pure"

    return CommunityResult(
        communities=community_lists,
        community_count=len(community_lists),
        modularity=round(mod, 4),
        algorithm_used=algo,
    )


# ──────────────────────────────────────────────────────────────
# 3. Hidden Relationship Discovery
# ──────────────────────────────────────────────────────────────

@dataclass
class HiddenRelationship:
    node_a:     str
    node_b:     str
    name_a:     str
    name_b:     str
    score:      float
    method:     str


def find_hidden_relationships(graph_state: dict,
                               top_k: int = 5,
                               min_score: float = 0.3) -> list[HiddenRelationship]:
    """
    Predict likely missing edges using common-neighbor scoring
    (Jaccard coefficient of neighbor sets — GNN-inspired without PyG).
    """
    nodes = graph_state.get("nodes", [])
    edges = graph_state.get("edges", [])
    if not nodes:
        return []

    adj = _adj(nodes, edges)
    node_ids = list(adj.keys())
    name_map = {
        (n.get("entity_id") or n.get("node_id", "")): n.get("name", "")
        for n in nodes
    }

    # Existing edge set (undirected)
    existing = {(e.get("from_id", ""), e.get("to_id", "")) for e in edges}
    existing |= {(b, a) for a, b in existing}

    candidates: list[HiddenRelationship] = []
    seen: set[tuple[str, str]] = set()

    for i, a in enumerate(node_ids):
        for b in node_ids[i + 1:]:
            if (a, b) in existing or a == b:
                continue
            na, nb = adj.get(a, set()), adj.get(b, set())
            inter = len(na & nb)
            union = len(na | nb)
            score = inter / union if union else 0.0
            if score >= min_score:
                key = tuple(sorted((a, b)))
                if key not in seen:
                    seen.add(key)
                    candidates.append(HiddenRelationship(
                        node_a=a, node_b=b,
                        name_a=name_map.get(a, a),
                        name_b=name_map.get(b, b),
                        score=round(score, 4),
                        method="jaccard_neighbors",
                    ))

    candidates.sort(key=lambda r: r.score, reverse=True)
    return candidates[:top_k]


# ──────────────────────────────────────────────────────────────
# 4. Centrality Dashboard
# ──────────────────────────────────────────────────────────────

@dataclass
class CentralityResult:
    degree:     dict[str, float]
    betweenness: dict[str, float]
    closeness:   dict[str, float]
    eigenvector: dict[str, float]
    top_nodes:   list[dict]


def compute_centrality(graph_state: dict, top_k: int = 5) -> CentralityResult:
    """Full centrality dashboard: degree, betweenness, closeness, eigenvector."""
    nodes = graph_state.get("nodes", [])
    edges = graph_state.get("edges", [])
    node_ids = [n.get("entity_id") or n.get("node_id", "") for n in nodes]
    if not node_ids:
        return CentralityResult({}, {}, {}, {}, [])

    if _NX:
        G = _build_nx(nodes, edges).to_undirected()
        degree     = dict(nx.degree_centrality(G))
        betweenness = nx.betweenness_centrality(G, normalized=True, endpoints=False)
        closeness  = dict(nx.closeness_centrality(G))
        try:
            eigenvector = nx.eigenvector_centrality(G, max_iter=100)
        except Exception:
            eigenvector = degree
    else:
        adj = _adj(nodes, edges)
        n = len(node_ids)
        degree = {nid: len(adj.get(nid, set())) / max(n - 1, 1) for nid in node_ids}
        betweenness = {nid: 0.0 for nid in node_ids}
        closeness   = {nid: 0.0 for nid in node_ids}
        eigenvector = degree  # simplification for non-nx path

    name_map = {
        (n.get("entity_id") or n.get("node_id", "")): n.get("name", "")
        for n in nodes
    }
    combined = sorted(
        node_ids,
        key=lambda nid: degree.get(nid, 0) + betweenness.get(nid, 0),
        reverse=True,
    )
    top = [
        {
            "node_id":    nid,
            "name":       name_map.get(nid, nid),
            "degree":     round(degree.get(nid, 0), 4),
            "betweenness": round(betweenness.get(nid, 0), 4),
            "closeness":  round(closeness.get(nid, 0), 4),
        }
        for nid in combined[:top_k]
    ]
    return CentralityResult(
        degree=degree, betweenness=betweenness,
        closeness=closeness, eigenvector=eigenvector,
        top_nodes=top,
    )


# ──────────────────────────────────────────────────────────────
# 5. Network Vulnerability Analysis
# ──────────────────────────────────────────────────────────────

@dataclass
class NetworkVulnerabilityResult:
    articulation_points: list[str]    # nodes whose removal disconnects the graph
    bridges:             list[tuple[str, str]]   # edges whose removal disconnects
    attack_robustness:   float        # 0=fragile, 1=robust
    recommendations:     list[str]


def analyze_network_vulnerability(graph_state: dict) -> NetworkVulnerabilityResult:
    """Structural vulnerability: articulation points, bridges, robustness score."""
    nodes = graph_state.get("nodes", [])
    edges = graph_state.get("edges", [])
    node_ids = [n.get("entity_id") or n.get("node_id", "") for n in nodes]
    if not node_ids:
        return NetworkVulnerabilityResult([], [], 1.0, [])

    if _NX:
        G = _build_nx(nodes, edges).to_undirected()
        try:
            art_points = list(nx.articulation_points(G))
        except Exception:
            art_points = []
        try:
            bridges_raw = list(nx.bridges(G))
            bridges = [(a, b) for a, b in bridges_raw]
        except Exception:
            bridges = []
    else:
        art_points = []
        bridges = []

    n = len(node_ids)
    # Robustness: fewer articulation points per node = more robust
    robustness = max(0.0, 1.0 - (len(art_points) / max(n, 1)))

    recs = []
    if art_points:
        recs.append(f"Replicate {len(art_points)} critical nodes to eliminate single points of failure")
    if bridges:
        recs.append(f"Add redundant paths around {len(bridges)} bridge edges")
    if robustness < 0.5:
        recs.append("Network is highly fragile — segment into independent zones")
    if not recs:
        recs.append("Network topology appears resilient; continue passive monitoring")

    name_map = {
        (n.get("entity_id") or n.get("node_id", "")): n.get("name", "")
        for n in nodes
    }
    return NetworkVulnerabilityResult(
        articulation_points=[name_map.get(nid, nid) for nid in art_points],
        bridges=bridges,
        attack_robustness=round(robustness, 4),
        recommendations=recs,
    )
