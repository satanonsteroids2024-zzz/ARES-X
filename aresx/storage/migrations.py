"""
ARES X v8.0 — Storage migrations.

Idempotent: ``init_storage()`` is safe to call on every boot. The schema
file uses CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS, and
seed rows use INSERT OR IGNORE, so re-application is a no-op.

Version tracking lives in the ``schema_version`` table created by the
schema file itself.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from aresx.storage import db

logger = logging.getLogger(__name__)

# Current schema version of v8 TITAN-ENTERPRISE.
# Increment in lockstep when adding a new migration step.
#   v1 — Phase 1 foundation (evidence_vault, audit_log_v2, etc.)
#   v2 — Phase 2 fusion (fusion_buffer table)
#   v3 — Phases 3-12 (twin_registry, rag_documents, sovereign_models, compliance, PQ, etc.)
CURRENT_SCHEMA_VERSION: int = 3

_SCHEMA_FILE: Path = Path(__file__).resolve().parent / "schema_v8.sql"


def current_version() -> int:
    """Return the highest applied schema version, or 0 if none."""
    try:
        row = db.query_one(
            "SELECT MAX(version) AS v FROM schema_version"
        )
        if row is None or row["v"] is None:
            return 0
        return int(row["v"])
    except Exception:
        # Table doesn't exist yet → version 0
        return 0


def _repair_evidence_chain(conn) -> int:
    """
    Heal forked chain_position values left by pre-lock versions of add_evidence.

    A legacy DB written by the old (racy) code can contain duplicate
    chain_position values, which would make the new UNIQUE index fail to
    create. We re-sequence every row by insertion order (rowid) so positions
    become contiguous 1..N again, then recompute prev_hash / merkle_root so
    verify_vault_chain() stays valid.

    Returns the number of rows that were re-sequenced (0 if nothing to fix).
    Safe to call on a fresh DB (no evidence_vault rows → no-op) and on an
    already-healthy DB (positions already contiguous → no-op).
    """
    try:
        # Does the table even exist yet?
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='evidence_vault'"
        ).fetchone()
        if not exists:
            return 0

        rows = conn.execute(
            "SELECT rowid, raw_data_hash, chain_position FROM evidence_vault "
            "ORDER BY chain_position ASC, rowid ASC"
        ).fetchall()
        if not rows:
            return 0

        positions = [r[2] for r in rows]
        # If already contiguous 1..N with no dupes, nothing to do.
        if positions == list(range(1, len(rows) + 1)):
            return 0

        import hashlib
        def _h(s: str) -> str:
            return hashlib.sha256(s.encode()).hexdigest()

        prev_hash = _h("ARES-EVIDENCE-VAULT-GENESIS")
        repaired = 0
        for new_pos, (rowid, raw_hash, _old_pos) in enumerate(rows, start=1):
            merkle_root = _h(prev_hash + (raw_hash or ""))
            conn.execute(
                "UPDATE evidence_vault SET chain_position = ?, prev_hash = ?, "
                "merkle_root = ?, merkle_proof = ? WHERE rowid = ?",
                (new_pos, prev_hash, merkle_root,
                 '{"prev_hash": "%s"}' % prev_hash, rowid),
            )
            prev_hash = raw_hash or prev_hash
            repaired += 1
        conn.commit()
        logger.warning("[migration] Repaired %d forked evidence_vault rows "
                       "(re-sequenced chain_position).", repaired)
        return repaired
    except Exception as exc:
        logger.error("[migration] Evidence chain repair failed: %s", exc)
        return 0


def apply_schema(force: bool = False) -> int:
    """
    Apply the v8 schema file. Returns the version after application.

    Strategy:
    - Heal any forked evidence_vault chain_position values FIRST (legacy DBs),
      so the UNIQUE index in the schema can be created.
    - Full schema (CREATE TABLE, CREATE TRIGGER, INSERT OR IGNORE, PRAGMA)
      runs via executescript — handles multi-statement triggers correctly.
    - ALTER TABLE statements are extracted and run individually afterward
      so "duplicate column" errors can be caught and swallowed.
    """
    if not _SCHEMA_FILE.exists():
        raise FileNotFoundError(f"Schema file missing: {_SCHEMA_FILE}")

    sql = _SCHEMA_FILE.read_text(encoding="utf-8")
    conn = db.connect()

    # Repair forked evidence chains BEFORE the schema's UNIQUE index is created.
    _repair_evidence_chain(conn)

    # Separate ALTER TABLE statements (executescript would abort on them if column exists)
    import re
    alter_stmts = re.findall(r'ALTER TABLE.*?;', sql, re.IGNORECASE | re.DOTALL)
    # Remove ALTER TABLE lines so executescript only sees safe DDL
    safe_sql = re.sub(r'ALTER TABLE.*?;\n?', '', sql, flags=re.IGNORECASE | re.DOTALL)

    try:
        conn.executescript(safe_sql)
    except Exception as exc:
        logger.warning("executescript warning (usually safe): %s", exc)

    # Now run ALTER TABLE individually, swallowing "duplicate column" errors
    for stmt in alter_stmts:
        stmt = stmt.strip()
        if not stmt:
            continue
        try:
            conn.execute(stmt)
            conn.commit()
        except Exception as exc:
            msg = str(exc).lower()
            if "duplicate column" in msg or "already exists" in msg:
                continue
            logger.debug("ALTER TABLE skipped (%s): %.80s", exc, stmt)

    existing = current_version()
    if existing < CURRENT_SCHEMA_VERSION or force:
        db.execute(
            "INSERT OR REPLACE INTO schema_version (version, note) VALUES (?, ?)",
            (CURRENT_SCHEMA_VERSION, "v8 TITAN-ENTERPRISE baseline"),
        )
    return CURRENT_SCHEMA_VERSION


def init_storage(verbose: bool = False) -> dict:
    """
    Bootstrap storage. Called by aresx.v8_bootstrap.boot().

    Returns a dict with status info:
        {
          "db_path":          "...",
          "sqlite_version":   N,
          "graph_available":  True/False,
          "graph_message":    "...",
        }
    """
    sqlite_version = apply_schema()
    if verbose:
        logger.info("SQLite schema applied (v%d) at %s", sqlite_version, db.DB_PATH)

    # Initialise graph DB (Kuzu) — optional; fall back gracefully.
    from aresx.storage import graph as graph_mod
    graph_status = graph_mod.init_graph(verbose=verbose)

    return {
        "db_path":         str(db.DB_PATH),
        "sqlite_version":  sqlite_version,
        "graph_available": graph_status["available"],
        "graph_message":   graph_status["message"],
        "graph_path":      graph_status.get("path"),
    }
