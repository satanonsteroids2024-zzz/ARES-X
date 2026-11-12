"""
ARES X v6 — Predictive Intelligence (PREDINT)  [Features 67-70]
===============================================================
• Threat forecasting (trend analysis on public threat signals)
• Entity risk scoring (0-100 composite)
• Sentiment trajectory analysis (over time)
• Event cascade predictor (scenario trees via LLM reasoning)
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List


# ──────────────────────────────────────────────────────────────
# 67. Threat Forecasting Engine
# ──────────────────────────────────────────────────────────────
def threat_forecast() -> None:
    """Aggregate recent public threat chatter and produce a short forecast."""
    from ..core import speak, show, ask_ai, mike, run_async
    from ..brain import ddg_search_async

    show("thinking", "Forecasting threat landscape…")
    queries = [
        "latest CVE actively exploited this week",
        "trending ransomware campaigns 2026",
        "new phishing techniques recent",
    ]
    snippets: List[str] = []
    for q in queries:
        res = run_async(ddg_search_async(q, max_results=3)) or []
        snippets += [r.get("body", "")[:180] for r in res]

    context = "\n".join(f"• {s}" for s in snippets if s)[:2500]
    forecast = ask_ai(
        "You are a threat-intel analyst. From these recent signals, produce a "
        "concise 4-line forecast: (1) top emerging threat, (2) likely target "
        "sectors, (3) recommended defensive action, (4) confidence level.\n\n"
        f"{context}",
        system="You are ARES X PREDINT. Be specific and brief.")
    mike.remember(f"forecast:{int(time.time())}", forecast or "",
                  tags=["predint", "forecast"])
    speak(forecast or "Could not generate a threat forecast right now.")


# ──────────────────────────────────────────────────────────────
# 68. Entity Risk Scoring
# ──────────────────────────────────────────────────────────────
def entity_risk_score(entity: str) -> None:
    """Composite 0-100 risk score for a person/org/domain/email."""
    from ..core import speak, show, ask_ai, mike, run_async
    from ..brain import ddg_search_async

    show("thinking", f"Scoring risk for {entity}…")
    signals: Dict[str, Any] = {}

    # Public reputation chatter
    rep = run_async(ddg_search_async(f"{entity} scam OR breach OR fraud OR leak",
                                     max_results=5)) or []
    signals["negative_hits"] = sum(
        1 for r in rep
        if any(w in (r.get("body", "") + r.get("title", "")).lower()
               for w in ("scam", "breach", "fraud", "leak", "hacked", "sanction")))

    # Dark-web / paste mention proxy
    dw = run_async(ddg_search_async(f'"{entity}" site:pastebin.com OR leak database',
                                    max_results=3)) or []
    signals["paste_hits"] = len(dw)

    # Compose a score via weighted heuristic + LLM sanity check
    raw = min(100, signals["negative_hits"] * 12 + signals["paste_hits"] * 8)
    verdict = ask_ai(
        f"Entity: {entity}\nNegative reputation hits: {signals['negative_hits']}\n"
        f"Paste/leak hits: {signals['paste_hits']}\n"
        f"Heuristic score: {raw}/100.\n"
        "Give a one-line risk verdict (Low/Medium/High/Critical) + the single "
        "biggest contributing factor.",
        system="You are ARES X risk engine. One line only.")
    mike.remember(f"risk:{entity}", json.dumps({"score": raw, "signals": signals}),
                  tags=["predint", "risk", entity])
    speak(f"Risk score for {entity}: {raw}/100. {verdict or ''}")


# ──────────────────────────────────────────────────────────────
# 69. Sentiment Trajectory Analysis
# ──────────────────────────────────────────────────────────────
def sentiment_trajectory(entity: str) -> None:
    """Track sentiment about an entity now and compare to stored history."""
    from ..core import speak, show, ask_ai, mike, run_async
    from ..brain import ddg_search_async

    show("thinking", f"Analyzing sentiment for {entity}…")
    res = run_async(ddg_search_async(f"{entity} opinion OR review OR reaction",
                                     max_results=6)) or []
    context = "\n".join(r.get("body", "")[:160] for r in res)[:2200]
    score_txt = ask_ai(
        f"Rate overall public sentiment toward '{entity}' on a -100 (very "
        f"negative) to +100 (very positive) scale. Reply with ONLY the integer.\n\n"
        f"{context}",
        system="Reply with a single integer only.")
    try:
        score = int(''.join(c for c in (score_txt or "0") if c in "-0123456789")[:4])
    except ValueError:
        score = 0

    hist_raw = mike.recall(f"sentiment:{entity}")
    hist = json.loads(hist_raw) if hist_raw else []
    prev = hist[-1]["score"] if hist else None
    hist.append({"ts": time.time(), "score": score})
    mike.remember(f"sentiment:{entity}", json.dumps(hist[-30:]),
                  tags=["predint", "sentiment", entity])

    if prev is not None:
        delta = score - prev
        arrow = "↑ improving" if delta > 8 else "↓ declining" if delta < -8 else "→ stable"
        speak(f"Sentiment for {entity}: {score:+d} ({arrow}, was {prev:+d}).")
    else:
        speak(f"Sentiment baseline for {entity}: {score:+d}. Tracking from now.")


# ──────────────────────────────────────────────────────────────
# 70. Event Cascade Predictor
# ──────────────────────────────────────────────────────────────
def event_cascade_predict(event: str) -> None:
    """Model downstream effects of a trigger event as a scenario tree."""
    from ..core import speak, show, ask_ai, mike

    show("thinking", "Modeling cascade…")
    tree = ask_ai(
        f"Trigger event: '{event}'.\n"
        "Predict the cascade of downstream second- and third-order effects. "
        "Give 3 branches, each with a probability estimate and a one-line "
        "consequence. Format: 'Branch (p=NN%): consequence'.",
        system="You are ARES X cascade predictor. Be concrete and brief.")
    mike.remember(f"cascade:{int(time.time())}",
                  json.dumps({"event": event, "tree": tree}),
                  tags=["predint", "cascade"])
    speak(tree or "Could not model the cascade for that event.")
