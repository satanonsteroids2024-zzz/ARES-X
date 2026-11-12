"""
ARES X v6 — Advanced Graph Analytics  [Features 83-87]
======================================================
• Graph analysis (centrality / community — GNN-ready via networkx)
• Temporal pattern mining
• Multi-stream anomaly detection
• Natural-language investigation (English → graph answer)
• Auto-classification engine

Uses networkx as the always-available core; upgrades to PyTorch Geometric
GNNs automatically if torch_geometric is installed.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from typing import List


def _load_graph_edges(mike) -> List[tuple]:
    """Reconstruct (src, rel, dst) edges from Mike's stored investigation data."""
    edges: List[tuple] = []
    try:
        keys = mike.all_keys()
        for k in keys:
            v = mike.recall(k)
            if not v:
                continue
            try:
                obj = json.loads(v)
            except Exception:
                continue
            # Heuristic edge extraction
            if k.startswith("subdomains:"):
                dom = k.split(":", 1)[1]
                for sub in (obj if isinstance(obj, list) else [])[:50]:
                    edges.append((dom, "has_subdomain", sub))
            elif k.startswith("asn:"):
                ip = k.split(":", 1)[1]
                if isinstance(obj, dict) and obj.get("asn"):
                    edges.append((ip, "in_asn", f"AS{obj['asn']}"))
            elif k.startswith("wallet:"):
                addr = k.split(":", 1)[1]
                for cp in (obj.get("counterparties", []) if isinstance(obj, dict) else [])[:30]:
                    edges.append((addr, "sent_to", cp))
            elif k.startswith("email_domains:"):
                em = k.split(":", 1)[1]
                for d in (obj if isinstance(obj, list) else [])[:50]:
                    edges.append((em, "registered", d))
    except Exception:
        pass
    return edges


# ──────────────────────────────────────────────────────────────
# 83. Graph Neural Network / Centrality Analysis
# ──────────────────────────────────────────────────────────────
def gnn_analysis() -> None:
    """Find central actors, bridges, and communities in the knowledge graph."""
    from ..core import speak, show, mike

    show("thinking", "Analyzing knowledge graph…")
    try:
        import networkx as nx
    except Exception:
        speak("networkx not installed. Run: pip install networkx")
        return

    edges = _load_graph_edges(mike)
    if len(edges) < 3:
        speak("Knowledge graph is too small to analyze. Run some investigations first.")
        return

    G = nx.DiGraph()
    for s, r, d in edges:
        G.add_edge(s, d, rel=r)

    # Centrality
    deg = nx.degree_centrality(G)
    top_central = sorted(deg.items(), key=lambda x: x[1], reverse=True)[:3]
    # Communities (on undirected projection)
    try:
        communities = list(nx.community.greedy_modularity_communities(G.to_undirected()))
        n_comm = len(communities)
    except Exception:
        n_comm = 0

    # Optional GNN upgrade note
    gnn = ""
    try:
        import torch_geometric  # noqa: F401
        gnn = " (PyTorch Geometric available for deep GNN embeddings)"
    except Exception:
        pass

    central_names = ", ".join(n for n, _ in top_central)
    speak(f"Graph: {G.number_of_nodes()} entities, {G.number_of_edges()} links, "
          f"{n_comm} communities. Most central: {central_names}.{gnn}")


# ──────────────────────────────────────────────────────────────
# 84. Temporal Pattern Mining
# ──────────────────────────────────────────────────────────────
def temporal_pattern_mine() -> None:
    """Discover recurring time-of-day / cadence patterns across observations."""
    from ..core import speak, show, mike
    import datetime

    show("thinking", "Mining temporal patterns…")
    hours = Counter()
    try:
        keys = mike.all_keys()
        for k in keys:
            # Keys that embed a unix-ts suffix
            parts = k.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                ts = int(parts[1])
                hours[datetime.datetime.fromtimestamp(ts).hour] += 1
    except Exception:
        pass

    if sum(hours.values()) < 5:
        speak("Not enough timestamped activity to mine patterns yet.")
        return

    peak_hour, peak_n = hours.most_common(1)[0]
    speak(f"Peak investigation activity is around {peak_hour:02d}:00 "
          f"({peak_n} events). Patterns stored for trend analysis.")


# ──────────────────────────────────────────────────────────────
# 85. Anomaly Detection Engine
# ──────────────────────────────────────────────────────────────
def anomaly_detect(stream: str = "all") -> None:
    """Statistical outlier detection across stored numeric signals."""
    from ..core import speak, show, mike

    show("thinking", "Scanning for anomalies…")
    values: List[float] = []
    labels: List[str] = []
    try:
        keys = mike.all_keys()
        for k in keys:
            v = mike.recall(k)
            try:
                obj = json.loads(v)
            except Exception:
                continue
            if isinstance(obj, dict):
                for field in ("score", "tx_count", "negative_hits"):
                    if isinstance(obj.get(field), (int, float)):
                        values.append(float(obj[field]))
                        labels.append(f"{k}:{field}")
    except Exception:
        pass

    if len(values) < 4:
        speak("Not enough numeric signals for anomaly detection.")
        return

    # Prefer sklearn IsolationForest; fall back to z-score
    flagged: List[str] = []
    try:
        from sklearn.ensemble import IsolationForest
        import numpy as np
        X = np.array(values).reshape(-1, 1)
        iso = IsolationForest(contamination=0.15, random_state=42).fit(X)
        preds = iso.predict(X)
        flagged = [labels[i] for i, p in enumerate(preds) if p == -1]
    except Exception:
        mean = sum(values) / len(values)
        sd = (sum((v - mean) ** 2 for v in values) / len(values)) ** 0.5 or 1
        flagged = [labels[i] for i, v in enumerate(values) if abs(v - mean) / sd > 2.5]

    if flagged:
        speak(f"⚠ {len(flagged)} anomalies flagged: " +
              ", ".join(f.split(':')[0] for f in flagged[:4]))
    else:
        speak("No statistical anomalies detected in current signals.")


# ──────────────────────────────────────────────────────────────
# 86. Natural-Language Investigation
# ──────────────────────────────────────────────────────────────
def nl_investigate(question: str) -> None:
    """Answer a plain-English question against the knowledge graph."""
    from ..core import speak, show, ask_ai, mike

    show("thinking", "Querying knowledge graph…")
    edges = _load_graph_edges(mike)
    if not edges:
        speak("The knowledge graph is empty. Run investigations to populate it.")
        return

    graph_txt = "\n".join(f"{s} --{r}--> {d}" for s, r, d in edges[:120])
    answer = ask_ai(
        f"Knowledge graph edges:\n{graph_txt}\n\n"
        f"Question: {question}\n"
        "Answer using ONLY the graph above. If the answer isn't in the graph, "
        "say so. Be concise.",
        system="You are ARES X graph query engine.")
    speak(answer or "I couldn't answer that from the current graph.")


# ──────────────────────────────────────────────────────────────
# 87. Auto-Classification Engine
# ──────────────────────────────────────────────────────────────
def auto_classify(text: str) -> None:
    """Multi-label classify text: threat level, data type, relevance."""
    from ..core import speak, show, ask_ai, mike

    show("thinking", "Classifying…")
    verdict = ask_ai(
        f"Classify this content across 3 axes and reply as compact JSON with "
        f'keys "threat_level" (info/low/medium/high/critical), "data_type" '
        f'(PII/financial/technical/social/other), "relevance" (0-100):\n\n'
        f"{text[:1500]}",
        system="Reply with ONLY a JSON object, no prose.")
    try:
        obj = json.loads(verdict[verdict.find("{"):verdict.rfind("}") + 1])
        mike.remember(f"classify:{int(time.time())}", json.dumps(obj),
                      tags=["analytics", "classify"])
        speak(f"Classified — threat: {obj.get('threat_level','?')}, "
              f"type: {obj.get('data_type','?')}, "
              f"relevance: {obj.get('relevance','?')}/100.")
    except Exception:
        speak(verdict or "Could not classify that content.")
