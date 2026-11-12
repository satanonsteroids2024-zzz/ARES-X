"""
ARES X v8.0 — Phase 2.8: Fusion engine (main orchestrator).

The Engine is what ties all of Phase 2 together. It:

  1. Subscribes to intelligence-stream events on the bus
       (osint.finding, sigint.detection, behint.anomaly, …)
  2. Writes incoming evidence to the ``fusion_buffer`` table
       (rolling 24h window per entity)
  3. Fires on trigger conditions:
       • 3+ unconsumed evidence pieces for the same entity
       • the 5-minute periodic sweep
       • explicit ``engine.fuse(entity_id)`` voice/API call
  4. Runs the full fusion pipeline per attribute:
       contradiction detection → confidence scoring → explainability
  5. Persists the resulting ``FusedAssertion`` to the
       ``fusion_assertions`` table and (optionally) writes the entity
       to the Kuzu graph for the digital-twin builders to consume.
  6. Publishes ``FUSION_COMPLETE`` on the bus.

The engine deliberately exposes a SYNCHRONOUS ``fuse(entity_id)``
entry point so unit tests can run the pipeline without spinning up an
event loop. The async event-driven path is built on top of it.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from collections import defaultdict
from typing import Any, Iterable, Optional

from aresx.events import EventType, bus
from aresx.fusion import confidence as conf
from aresx.fusion import contradiction as contra
from aresx.fusion import explainability as expl
from aresx.fusion import source_reliability as sr
# Note: `from aresx.fusion import <name>` here resolves each <name> to
# the sibling SUBMODULE (aresx.fusion.confidence, etc.), not to a symbol
# re-exported by aresx/fusion/__init__.py — Python imports the submodule
# directly, so this pattern is load-order-safe even if __init__.py is
# emptied. Verified empirically. (Do not "fix" this to
# `from aresx.fusion.X import X` — the submodules don't export a name
# equal to their module name, so that transformation would break the
# whole engine.)
from aresx.fusion.types import (
    Domain,
    Evidence,
    FusedAssertion,
)
from aresx.storage import db

logger = logging.getLogger(__name__)

# Trigger thresholds (Build Prompt §3 Phase 2.8)
TRIGGER_EVIDENCE_COUNT: int = 3
TRIGGER_AGE_SECONDS:    float = 300.0     # 5-minute periodic sweep
BUFFER_RETENTION_S:     float = 86_400.0  # rolling 24h


# ===================================================================
# ENGINE
# ===================================================================
class FusionEngine:
    """Singleton-style orchestrator. Stateless apart from the DB."""

    def __init__(self,
                 trigger_evidence_count: int = TRIGGER_EVIDENCE_COUNT,
                 trigger_age_seconds:    float = TRIGGER_AGE_SECONDS,
                 buffer_retention_s:     float = BUFFER_RETENTION_S) -> None:
        self.trigger_evidence_count = trigger_evidence_count
        self.trigger_age_seconds    = trigger_age_seconds
        self.buffer_retention_s     = buffer_retention_s

    # ── ingestion ─────────────────────────────────────────────
    def add_evidence(self, evidence: Evidence) -> None:
        """Insert a single evidence piece into the buffer."""
        db.execute(
            """
            INSERT INTO fusion_buffer
                (buffer_id, entity_id, evidence_id, source_tool,
                 attribute, value, domain, evidence_score,
                 raw_text, collected_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                evidence.entity_id,
                evidence.evidence_id,
                evidence.source_tool,
                evidence.attribute,
                evidence.value,
                evidence.domain.value if isinstance(evidence.domain, Domain) else str(evidence.domain),
                evidence.evidence_score,
                evidence.raw_text,
                evidence.collected_at,
                json.dumps(evidence.metadata, default=str) if evidence.metadata else None,
            ),
        )
        # Ensure source has a reliability row (auto-create at default)
        sr.get_reliability(evidence.source_tool)

    def add_many(self, evidences: Iterable[Evidence]) -> None:
        """Batch-insert evidence (single transaction for speed)."""
        with db.transaction():
            for e in evidences:
                self.add_evidence(e)

    # ── retrieval ─────────────────────────────────────────────
    def get_buffer(self, entity_id: str, include_consumed: bool = False
                   ) -> list[Evidence]:
        """
        Return all buffered evidence for an entity inside the retention
        window. Excludes already-fused records by default.
        """
        cutoff = time.time() - self.buffer_retention_s
        consumed_filter = "" if include_consumed else "AND consumed_at IS NULL"
        rows = db.query_all(
            f"""
            SELECT evidence_id, source_tool, attribute, value, domain,
                   evidence_score, raw_text, collected_at, metadata
            FROM fusion_buffer
            WHERE entity_id = ? AND collected_at >= ? {consumed_filter}
            ORDER BY collected_at ASC
            """,
            (entity_id, cutoff),
        )
        out: list[Evidence] = []
        for r in rows:
            try:
                domain = Domain(r["domain"]) if r["domain"] else Domain.OTHER
            except ValueError:
                domain = Domain.OTHER
            md = json.loads(r["metadata"]) if r["metadata"] else {}
            out.append(Evidence(
                entity_id=entity_id,
                source_tool=r["source_tool"],
                attribute=r["attribute"],
                value=r["value"],
                domain=domain,
                evidence_score=float(r["evidence_score"] or 1.0),
                collected_at=float(r["collected_at"]),
                evidence_id=r["evidence_id"] or str(uuid.uuid4()),
                raw_text=r["raw_text"],
                metadata=md,
            ))
        return out

    def entities_pending_fusion(self) -> list[tuple[str, int, float]]:
        """
        Return entities whose buffer hits a trigger condition.

        Tuples: (entity_id, unconsumed_count, oldest_collected_at)
        """
        cutoff = time.time() - self.buffer_retention_s
        rows = db.query_all(
            """
            SELECT entity_id,
                   COUNT(*) AS n,
                   MIN(collected_at) AS oldest
            FROM fusion_buffer
            WHERE consumed_at IS NULL AND collected_at >= ?
            GROUP BY entity_id
            """,
            (cutoff,),
        )
        now = time.time()
        out: list[tuple[str, int, float]] = []
        for r in rows:
            n = int(r["n"])
            oldest = float(r["oldest"])
            if n >= self.trigger_evidence_count or (now - oldest) >= self.trigger_age_seconds:
                out.append((r["entity_id"], n, oldest))
        return out

    # ── the fusion pipeline ───────────────────────────────────
    def fuse(self, entity_id: str, publish: bool = True
             ) -> list[FusedAssertion]:
        """
        Run the full fusion pipeline for a single entity. Returns one
        FusedAssertion per distinct attribute in the buffer.
        """
        buffer = self.get_buffer(entity_id)
        if not buffer:
            return []

        # Group by attribute
        by_attr: dict[str, list[Evidence]] = defaultdict(list)
        for e in buffer:
            by_attr[e.attribute].append(e)

        # Detect contradictions across the whole buffer first
        contradictions = contra.detect_contradictions(buffer, publish=publish)
        contradiction_pairs: dict[tuple[str, str], int] = defaultdict(int)
        for c in contradictions:
            contradiction_pairs[(c.entity_id, c.attribute)] += 1

        assertions: list[FusedAssertion] = []
        consumed_ids: set[str] = set()

        for attribute, items in by_attr.items():
            # Pick the value asserted by the most-reliable source as the
            # candidate value (auto-resolution for the attribute).
            items_sorted = sorted(
                items,
                key=lambda e: sr.get_reliability(e.source_tool),
                reverse=True,
            )
            candidate_value = items_sorted[0].value

            supporting, contradicting = contra.partition_supporting_contradicting(
                items, candidate_value,
            )

            breakdown = conf.confidence_breakdown(supporting, contradicting)
            explanation = expl.explain(
                candidate_value, supporting, contradicting, breakdown,
            )

            assertion = FusedAssertion(
                entity_id=entity_id,
                attribute=attribute,
                value=candidate_value,
                confidence=breakdown["final"],
                supporting_evidence=[e.evidence_id for e in supporting],
                contradicting=[e.evidence_id for e in contradicting],
                explanation=explanation,
            )
            assertions.append(assertion)

            # Persist
            db.execute(
                """
                INSERT INTO fusion_assertions
                    (assertion_id, entity_id, attribute, value,
                     confidence, supporting_evidence, contradicting,
                     fused_at, explanation)
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
                """,
                (
                    assertion.assertion_id,
                    assertion.entity_id,
                    assertion.attribute,
                    assertion.value,
                    assertion.confidence,
                    json.dumps(assertion.supporting_evidence),
                    json.dumps(assertion.contradicting),
                    assertion.explanation,
                ),
            )
            consumed_ids.update(assertion.supporting_evidence)
            consumed_ids.update(assertion.contradicting)

        # Mark buffer rows as consumed
        if consumed_ids:
            now = time.time()
            placeholders = ",".join("?" for _ in consumed_ids)
            db.execute(
                f"UPDATE fusion_buffer SET consumed_at = ? "
                f"WHERE evidence_id IN ({placeholders})",
                (now, *consumed_ids),
            )

        # Publish FUSION_COMPLETE so downstream modules (twins, decision
        # support, UI) can react.
        if publish:
            bus.publish_sync(
                EventType.FUSION_COMPLETE,
                payload={
                    "entity_id":        entity_id,
                    "assertion_count":  len(assertions),
                    "evidence_count":   len(buffer),
                    "max_confidence":   max(
                        (a.confidence for a in assertions),
                        default=0.0,
                    ),
                    "attributes":       sorted(by_attr.keys()),
                },
                source="fusion.engine",
                correlation_id=entity_id,
            )

        return assertions

    # ── periodic sweep ────────────────────────────────────────
    def sweep(self) -> dict[str, list[FusedAssertion]]:
        """
        Process every entity that has hit a trigger condition. Returns
        ``{entity_id: [assertions...]}``. Use from a scheduler (e.g.
        APScheduler in Phase 4) or a simple background thread.
        """
        results: dict[str, list[FusedAssertion]] = {}
        for entity_id, _n, _oldest in self.entities_pending_fusion():
            try:
                results[entity_id] = self.fuse(entity_id)
            except Exception as exc:
                logger.error("Fusion failed for %s: %s", entity_id, exc)
                results[entity_id] = []
        return results

    # ── housekeeping ──────────────────────────────────────────
    def prune_buffer(self) -> int:
        """
        Delete buffer rows older than the retention window. Returns the
        number of rows removed. Safe to call frequently.
        """
        cutoff = time.time() - self.buffer_retention_s
        cur = db.execute(
            "DELETE FROM fusion_buffer WHERE collected_at < ?",
            (cutoff,),
        )
        return cur.rowcount or 0


# Module-level singleton — most callers want this.
engine: FusionEngine = FusionEngine()
