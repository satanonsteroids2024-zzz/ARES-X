"""
aresx.fusion — TITAN Phase 2: Sensor Fusion Layer

Multi-source, multi-domain intelligence fusion. Combines OSINT, SIGINT,
FININT, GEOINT, HUMINT, and BEHINT evidence into ``FusedAssertion``
records with confidence scores, contradiction tracking, and natural-
language explanations.

Public API
----------
    from aresx.fusion import fusion_engine, Evidence, Domain, FusedAssertion
    fusion_engine.add_evidence(Evidence(...))
    assertions = fusion_engine.fuse("Microsoft")
    for a in assertions:
        print(a.attribute, a.value, a.confidence, a.explanation)

Submodules
----------
    types               — dataclasses (Evidence, FusedAssertion, …)
    source_reliability  — per-tool reliability scoring
    confidence          — pure-function confidence formula
    contradiction       — contradiction detection + resolution
    signal_correlator   — cross-domain entity matching
    event_correlator    — temporal sliding-window correlation
    cross_domain        — GEOINT+FININT, SIGINT+OSINT specializations
    explainability      — natural-language fusion explanations
    engine              — main orchestrator (singleton ``fusion_engine``)

Note: the module is ``aresx.fusion.engine`` (with ``engine`` being the
submodule name). The singleton instance is exposed here as
``fusion_engine`` so it doesn't shadow the submodule for callers who
do ``import aresx.fusion.engine``.
"""
from aresx.fusion.types import (
    Domain,
    Evidence,
    FusedAssertion,
    ContradictionEvent,
    CorrelationChain,
)
# Import the class, and import the singleton under a non-conflicting name.
from aresx.fusion.engine import FusionEngine
from aresx.fusion.engine import engine as fusion_engine

PHASE_STATUS = "implemented"

__all__ = [
    "Domain",
    "Evidence",
    "FusedAssertion",
    "ContradictionEvent",
    "CorrelationChain",
    "FusionEngine",
    "fusion_engine",
    "PHASE_STATUS",
]
