"""
ARES X v8.0 — Phase 2.6: Cross-domain fusion specializations.

Specialised fusion logic for pairs of domains where the generic
signal_correlator isn't expressive enough.

Provides:
    GEOINT + FININT  — physical location ↔ financial activity location
    SIGINT + OSINT   — device sightings ↔ social check-ins
    HUMINT + OSINT   — human-collected report ↔ public profile

These exist as thin wrappers over signal_correlator with tuned
thresholds, attribute whitelists, and domain-pair constraints.
"""
from __future__ import annotations

from typing import Iterable

from aresx.fusion import signal_correlator as sc
from aresx.fusion.types import Domain, Evidence


# -------------------------------------------------------------------
# GEOINT + FININT — physical/financial co-location
# -------------------------------------------------------------------
_FININT_LOCATION_ATTRS = {
    "transaction_location", "merchant_address", "branch_location",
    "wire_origin", "wire_destination",
}

_GEOINT_LOCATION_ATTRS = {
    "observed_at", "imagery_centroid", "fix_location", "device_seen_at",
}


def geo_finint_match(
    geo_evidence: Iterable[Evidence],
    finint_evidence: Iterable[Evidence],
    radius_km: float = 0.5,
    window_seconds: float = 86_400.0,
) -> list[tuple[Evidence, Evidence, float]]:
    """
    Return (geo_ev, finint_ev, confidence) tuples for every
    cross-domain pair that co-located within ``radius_km`` and
    ``window_seconds``.
    """
    matches: list[tuple[Evidence, Evidence, float]] = []
    for g in geo_evidence:
        if g.attribute not in _GEOINT_LOCATION_ATTRS:
            continue
        for f in finint_evidence:
            if f.attribute not in _FININT_LOCATION_ATTRS:
                continue
            spatial = sc.spatial_score(g, f, max_km=radius_km)
            temporal = sc.temporal_score(g, f, window_seconds=window_seconds)
            if spatial == 0.0 or temporal == 0.0:
                continue
            confidence = 0.6 * spatial + 0.4 * temporal
            matches.append((g, f, confidence))
    return matches


# -------------------------------------------------------------------
# SIGINT + OSINT — device seen ↔ social check-in
# -------------------------------------------------------------------
_SIGINT_DEVICE_ATTRS = {"device_seen_at", "mac_observed", "imsi_observed"}
_OSINT_CHECKIN_ATTRS = {"checked_in_at", "tweet_location", "post_geo"}


def sigint_osint_match(
    sigint_evidence: Iterable[Evidence],
    osint_evidence: Iterable[Evidence],
    radius_km: float = 0.1,
    window_seconds: float = 1800.0,
) -> list[tuple[Evidence, Evidence, float]]:
    """
    Detect device-sighting ↔ social-check-in coincidences. Tighter
    spatial+temporal thresholds than the finint variant since SIGINT
    coords are device-precise.
    """
    matches: list[tuple[Evidence, Evidence, float]] = []
    for s in sigint_evidence:
        if s.attribute not in _SIGINT_DEVICE_ATTRS:
            continue
        for o in osint_evidence:
            if o.attribute not in _OSINT_CHECKIN_ATTRS:
                continue
            spatial = sc.spatial_score(s, o, max_km=radius_km)
            temporal = sc.temporal_score(s, o, window_seconds=window_seconds)
            if spatial == 0.0 or temporal == 0.0:
                continue
            name_sim = sc.token_jaccard(s.entity_id or "", o.entity_id or "")
            confidence = 0.4 * spatial + 0.3 * temporal + 0.3 * name_sim
            matches.append((s, o, confidence))
    return matches


# -------------------------------------------------------------------
# Helper for the engine — partition evidence by domain
# -------------------------------------------------------------------
def partition_by_domain(evidence: Iterable[Evidence]) -> dict[Domain, list[Evidence]]:
    """Split a flat evidence list into per-domain buckets."""
    out: dict[Domain, list[Evidence]] = {d: [] for d in Domain}
    for e in evidence:
        out[e.domain].append(e)
    return out
