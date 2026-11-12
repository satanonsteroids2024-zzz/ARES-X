"""
ARES X v8.0 — Fusion layer dataclasses.

These are the canonical shapes that flow through the fusion pipeline.
Every other module in ``aresx.fusion`` imports from here.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Domain(str, Enum):
    """Top-level intelligence domains. Matches v6 module taxonomy."""
    OSINT  = "OSINT"
    SIGINT = "SIGINT"
    FININT = "FININT"
    GEOINT = "GEOINT"
    HUMINT = "HUMINT"
    BEHINT = "BEHINT"
    CYBINT = "CYBINT"
    OTHER  = "OTHER"


@dataclass
class Evidence:
    """
    A single, atomic piece of intelligence about an entity.

    The fusion engine works on ``(entity, attribute, value)`` triples.
    LLM-driven fact extraction (which is what turns raw blobs of OSINT
    text into these triples) lives in ``contradiction.py`` and friends.
    """
    entity_id:        str
    source_tool:      str            # e.g. "crt_sh", "shodan", "whois"
    attribute:        str            # e.g. "founded_year", "registered_domain"
    value:            str            # the asserted value
    domain:           Domain = Domain.OTHER
    evidence_score:   float = 1.0    # 0.0–1.0; how directly the source supports the claim
    collected_at:     float = field(default_factory=time.time)
    evidence_id:      str = field(default_factory=lambda: str(uuid.uuid4()))
    raw_text:         Optional[str] = None
    metadata:         dict[str, Any] = field(default_factory=dict)


@dataclass
class FusedAssertion:
    """Output of fusion for a single (entity, attribute) pair."""
    entity_id:           str
    attribute:           str
    value:               str
    confidence:          float                                    # 0.0–1.0
    supporting_evidence: list[str]                                # evidence_id list
    contradicting:       list[str]                                # evidence_id list
    explanation:         str
    assertion_id:        str = field(default_factory=lambda: str(uuid.uuid4()))
    fused_at:            float = field(default_factory=time.time)


@dataclass
class ContradictionEvent:
    """Two or more evidence pieces disagreeing about the same fact."""
    entity_id:        str
    attribute:        str
    evidence_a:       Evidence
    evidence_b:       Evidence
    resolution_mode:  str = "unresolved"       # auto | human_review | unresolved
    resolved_value:   Optional[str] = None
    contradiction_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detected_at:      float = field(default_factory=time.time)


@dataclass
class CorrelationChain:
    """A temporally-correlated chain of intelligence events."""
    chain_id:          str = field(default_factory=lambda: str(uuid.uuid4()))
    pattern_name:      str = "generic_chain"
    members:           list[dict] = field(default_factory=list)   # raw event dicts
    window_seconds:    float = 0.0
    suspicion_score:   float = 0.0
    detected_at:       float = field(default_factory=time.time)


__all__ = [
    "Domain",
    "Evidence",
    "FusedAssertion",
    "ContradictionEvent",
    "CorrelationChain",
]
