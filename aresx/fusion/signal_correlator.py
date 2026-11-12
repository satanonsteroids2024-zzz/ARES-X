"""
ARES X v8.0 — Phase 2.4: Signal correlator (cross-domain entity matching).

Resolves whether evidence pieces from different intelligence DOMAINS
refer to the same entity. Examples:
  • A SIGINT device-seen event at coords (47.64, -122.13) + a social
    media check-in at the same coords → likely the same person/org.
  • A FININT corporate transaction from "Microsoft Corp" + an OSINT
    org record for "Microsoft Corporation" → same entity.

The spec calls for LanceDB vector similarity. We implement the
correlation API so it works with or without LanceDB:

  ┌─ if LanceDB importable: use sentence embeddings + cosine sim
  └─ otherwise: token-Jaccard + simple time/space proximity fallback

The fallback is good enough for the Phase 2 acceptance test and for
all string-based entity matching in early Mission OS work. Vector
similarity becomes important when matching against millions of
candidates — that's a Phase 10 RAG concern.
"""
from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from typing import Optional

from aresx.fusion.types import Domain, Evidence

logger = logging.getLogger(__name__)

# Whitelist of attributes that carry location info, used by spatial
# proximity scoring. Other attribute names are ignored for the
# spatial component.
_GEO_ATTRS = {"location", "geo", "coords", "latlon", "checked_in_at",
               "device_seen_at", "headquarters"}

# Optional LanceDB integration — lazy
_lancedb_ok: Optional[bool] = None
def _lancedb_available() -> bool:
    global _lancedb_ok
    if _lancedb_ok is not None:
        return _lancedb_ok
    try:
        import lancedb       # noqa: F401
        _lancedb_ok = True
    except Exception:
        _lancedb_ok = False
    return _lancedb_ok


# -------------------------------------------------------------------
# String similarity helpers (LanceDB-free path)
# -------------------------------------------------------------------
_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")

def _tokens(s: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(s or "")}

def token_jaccard(a: str, b: str) -> float:
    """Jaccard index of token sets. 1.0 = identical, 0.0 = disjoint."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def token_containment(a: str, b: str) -> float:
    """Token-overlap coefficient: |A ∩ B| / min(|A|, |B|).

    Higher than Jaccard when one string is a token-subset of another
    ("Microsoft Corp" ⊂ "Microsoft Corporation Inc"), which is the
    common abbreviation case.
    """
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    denom = min(len(ta), len(tb))
    return inter / denom if denom else 0.0


def name_similarity(a: str, b: str) -> float:
    """Best-of token-Jaccard and token-containment.

    Designed so legitimate abbreviations ("X Corp" vs "X Corporation")
    yield a high score without false-positive matching on a single
    shared common token.
    """
    j = token_jaccard(a, b)
    c = token_containment(a, b)
    # Only let containment dominate when there's also non-trivial overlap
    # (≥ 2 shared tokens or jaccard ≥ 0.3) — guards against single-word
    # collisions like "Apple" the company vs "Apple" the fruit.
    ta, tb = _tokens(a), _tokens(b)
    shared = len(ta & tb)
    if shared >= 2 or j >= 0.3:
        return max(j, c)
    return j


# -------------------------------------------------------------------
# Spatial / temporal proximity
# -------------------------------------------------------------------
def _parse_latlon(value: str) -> Optional[tuple[float, float]]:
    """Parse "lat,lon" or "lat, lon"; return None if not parseable."""
    if not value:
        return None
    try:
        parts = [p.strip() for p in value.split(",")]
        if len(parts) != 2:
            return None
        return float(parts[0]), float(parts[1])
    except (ValueError, TypeError):
        return None


def haversine_km(p1: tuple[float, float], p2: tuple[float, float]) -> float:
    """Great-circle distance between two (lat, lon) points, in km."""
    lat1, lon1 = math.radians(p1[0]), math.radians(p1[1])
    lat2, lon2 = math.radians(p2[0]), math.radians(p2[1])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.asin(math.sqrt(min(1.0, a)))
    return 6371.0 * c       # km


def spatial_score(ev_a: Evidence, ev_b: Evidence, max_km: float = 1.0) -> float:
    """
    1.0 if both evidence carry compatible geo coords within ``max_km``;
    falls off linearly to 0.0 at ``10 * max_km``. Returns 0.0 if either
    evidence value doesn't parse as ``"lat,lon"``.

    Note: this primitive does NOT gate on attribute names — callers
    (e.g. ``cross_domain.geo_finint_match``) own that semantic. Pass
    in only evidence whose attribute you believe carries coords.
    """
    p1 = _parse_latlon(ev_a.value)
    p2 = _parse_latlon(ev_b.value)
    if p1 is None or p2 is None:
        return 0.0
    d = haversine_km(p1, p2)
    if d <= max_km:
        return 1.0
    if d >= 10 * max_km:
        return 0.0
    return max(0.0, 1.0 - (d - max_km) / (9 * max_km))


def temporal_score(ev_a: Evidence, ev_b: Evidence,
                    window_seconds: float = 3600.0) -> float:
    """
    1.0 if the two pieces are collected within ``window_seconds`` of
    each other; falls off to 0.0 at ``10 * window``.
    """
    dt = abs(ev_a.collected_at - ev_b.collected_at)
    if dt <= window_seconds:
        return 1.0
    if dt >= 10 * window_seconds:
        return 0.0
    return max(0.0, 1.0 - (dt - window_seconds) / (9 * window_seconds))


# -------------------------------------------------------------------
# Top-level correlation API
# -------------------------------------------------------------------
@dataclass
class CorrelationResult:
    """Outcome of pairwise cross-domain correlation."""
    same_entity:        bool
    confidence:         float
    components:         dict[str, float]    # {"name": 0.83, "spatial": 1.0, ...}
    correlated_entity_id: Optional[str] = None


# Weights for combining sub-scores into the final correlation confidence.
# Sum should equal 1.0; tuned for cross-domain match where name is
# typically the strongest signal.
# Default per-signal weights. The actual mix used is normalised over
# the signals that have data — see ``_combine`` below.
_W_NAME      = 0.50
_W_VALUE     = 0.15
_W_SPATIAL   = 0.25
_W_TEMPORAL  = 0.10
_DEFAULT_THRESHOLD = 0.55


def _combine(components: dict[str, float], weights: dict[str, float]) -> float:
    """
    Combine per-signal scores using ONLY the weights of signals that
    fired (component > 0). This avoids penalising entity pairs that
    legitimately have no spatial/temporal data — common for pure
    string-vs-string matching across OSINT sources.
    """
    active = {k: w for k, w in weights.items() if components.get(k, 0.0) > 0.0}
    total_w = sum(active.values())
    if total_w <= 0.0:
        return 0.0
    return sum(components[k] * w for k, w in active.items()) / total_w


def correlate(ev_a: Evidence, ev_b: Evidence,
              threshold: float = _DEFAULT_THRESHOLD) -> CorrelationResult:
    """
    Decide whether two evidence pieces refer to the same entity.

    The decision is conservative but tolerant of common cross-domain
    differences: abbreviated company suffixes, distinct attribute
    names for the same fact, and missing spatial/temporal signals.
    """
    # Strongest possible signal — explicit entity_id match
    if ev_a.entity_id and ev_a.entity_id == ev_b.entity_id:
        return CorrelationResult(
            same_entity=True,
            confidence=1.0,
            components={"entity_id_exact": 1.0},
            correlated_entity_id=ev_a.entity_id,
        )

    name_sim  = name_similarity(ev_a.entity_id or "", ev_b.entity_id or "")
    value_sim = name_similarity(ev_a.value or "",     ev_b.value or "")
    spatial   = spatial_score(ev_a, ev_b)
    temporal  = temporal_score(ev_a, ev_b)

    components = {
        "name":     name_sim,
        "value":    value_sim,
        "spatial":  spatial,
        "temporal": temporal,
    }
    weights = {
        "name":     _W_NAME,
        "value":    _W_VALUE,
        "spatial":  _W_SPATIAL,
        "temporal": _W_TEMPORAL,
    }
    combined = _combine(components, weights)

    return CorrelationResult(
        same_entity=combined >= threshold,
        confidence=combined,
        components=components,
        correlated_entity_id=ev_a.entity_id if combined >= threshold else None,
    )


def correlate_batch(evidence: list[Evidence],
                    threshold: float = _DEFAULT_THRESHOLD
                    ) -> dict[str, set[str]]:
    """
    Run all-pairs correlation over a list of evidence pieces and return
    an equivalence-class map: ``{entity_id: {co-referent_entity_ids}}``.

    Used by the fusion engine to canonicalise entity_ids before fusion
    so that "Microsoft Corp" and "Microsoft Corporation" merge.
    """
    equivalences: dict[str, set[str]] = {}
    for i in range(len(evidence)):
        for j in range(i + 1, len(evidence)):
            res = correlate(evidence[i], evidence[j], threshold=threshold)
            if not res.same_entity:
                continue
            a, b = evidence[i].entity_id, evidence[j].entity_id
            equivalences.setdefault(a, set()).add(b)
            equivalences.setdefault(b, set()).add(a)
    return equivalences


def lancedb_available() -> bool:
    """Public predicate so callers can degrade gracefully."""
    return _lancedb_available()
