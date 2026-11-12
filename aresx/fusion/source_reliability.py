"""
ARES X v8.0 — Phase 2.1: Source Reliability.

Maintains a per-source-tool reliability score (0.0–1.0) backed by the
``source_reliability`` SQLite table. Reliability is consumed by the
confidence scorer as the weight in its weighted mean.

Update formula (from Build Prompt §3 Phase 2.1):

    reliability = 0.7 * historical_accuracy + 0.3 * corroboration_rate

Public API
----------
    get_reliability(source_tool)           -> float
    record_outcome(source_tool, was_correct, was_corroborated)
    update_reliability(source_tool, historical_accuracy, corroboration_rate)
    list_all() -> list[dict]
"""
from __future__ import annotations

import logging
from typing import Optional

from aresx.storage import db

logger = logging.getLogger(__name__)

# Reliability assigned to a source we've never seen before. 0.7 is the
# neutral default — high enough to give new sources a fair voice,
# low enough to reward sources with a track record.
DEFAULT_RELIABILITY: float = 0.7

# Formula weights (Build Prompt §3 Phase 2.1)
W_HISTORICAL:      float = 0.7
W_CORROBORATION:   float = 0.3


def get_reliability(source_tool: str) -> float:
    """
    Return the reliability score for a source tool, auto-creating a
    row at DEFAULT_RELIABILITY if it doesn't exist.
    """
    row = db.query_one(
        "SELECT reliability_score FROM source_reliability WHERE source_tool = ?",
        (source_tool,),
    )
    if row is not None:
        return float(row["reliability_score"])

    db.execute(
        "INSERT OR IGNORE INTO source_reliability "
        "(source_tool, reliability_score, notes) VALUES (?, ?, ?)",
        (source_tool, DEFAULT_RELIABILITY, "auto-created on first use"),
    )
    return DEFAULT_RELIABILITY


def update_reliability(source_tool: str,
                        historical_accuracy: float,
                        corroboration_rate: float) -> float:
    """
    Recompute reliability via the spec formula and persist.

    Args:
        historical_accuracy: fraction of past assertions that turned out correct (0.0–1.0)
        corroboration_rate:  fraction of past assertions independently corroborated (0.0–1.0)

    Returns the new reliability score.
    """
    historical_accuracy = max(0.0, min(1.0, historical_accuracy))
    corroboration_rate  = max(0.0, min(1.0, corroboration_rate))
    new_score = W_HISTORICAL * historical_accuracy + W_CORROBORATION * corroboration_rate
    new_score = max(0.0, min(1.0, new_score))

    db.execute(
        """
        INSERT INTO source_reliability
            (source_tool, reliability_score, historical_accuracy,
             corroboration_rate, last_updated, notes)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 'formula updated')
        ON CONFLICT(source_tool) DO UPDATE SET
            reliability_score    = excluded.reliability_score,
            historical_accuracy  = excluded.historical_accuracy,
            corroboration_rate   = excluded.corroboration_rate,
            last_updated         = CURRENT_TIMESTAMP
        """,
        (source_tool, new_score, historical_accuracy, corroboration_rate),
    )
    return new_score


def record_outcome(source_tool: str,
                    was_correct: bool,
                    was_corroborated: bool) -> float:
    """
    Streaming update — record a single observation and re-run the
    formula using a running average.

    This is what production callers use (e.g. when an analyst marks an
    assertion as confirmed/disconfirmed). ``update_reliability`` is for
    batch/manual recomputation.
    """
    row = db.query_one(
        "SELECT historical_accuracy, corroboration_rate, sample_count "
        "FROM source_reliability WHERE source_tool = ?",
        (source_tool,),
    )
    if row is None:
        # First observation
        new_accuracy      = 1.0 if was_correct else 0.0
        new_corroboration = 1.0 if was_corroborated else 0.0
        sample_count      = 1
    else:
        prior_accuracy      = float(row["historical_accuracy"] or 0.5)
        prior_corroboration = float(row["corroboration_rate"]   or 0.5)
        sample_count        = int(row["sample_count"] or 0) + 1
        # Running mean
        new_accuracy      = prior_accuracy      + ((1.0 if was_correct      else 0.0) - prior_accuracy)      / sample_count
        new_corroboration = prior_corroboration + ((1.0 if was_corroborated else 0.0) - prior_corroboration) / sample_count

    new_score = W_HISTORICAL * new_accuracy + W_CORROBORATION * new_corroboration
    new_score = max(0.0, min(1.0, new_score))

    db.execute(
        """
        INSERT INTO source_reliability
            (source_tool, reliability_score, historical_accuracy,
             corroboration_rate, sample_count, last_updated, notes)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'streaming update')
        ON CONFLICT(source_tool) DO UPDATE SET
            reliability_score    = excluded.reliability_score,
            historical_accuracy  = excluded.historical_accuracy,
            corroboration_rate   = excluded.corroboration_rate,
            sample_count         = excluded.sample_count,
            last_updated         = CURRENT_TIMESTAMP
        """,
        (source_tool, new_score, new_accuracy, new_corroboration, sample_count),
    )
    return new_score


def list_all() -> list[dict]:
    """Snapshot of every known source and its current reliability."""
    rows = db.query_all(
        "SELECT source_tool, reliability_score, historical_accuracy, "
        "       corroboration_rate, sample_count, last_updated "
        "FROM source_reliability ORDER BY reliability_score DESC"
    )
    return [dict(r) for r in rows]
