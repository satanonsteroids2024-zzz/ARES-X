"""
ARES X v8.0 — Graph database wrapper (Kuzu).

Kuzu is an embedded property graph database. We use it for:
  • Entity knowledge graph (Person, Org, Domain, IP, ASN, ...)
  • Digital twin subgraphs (Phase 3)
  • Threat actor TTP graph (Adversary Twin)

Kuzu ships as a native wheel and may not be importable on every host
(unsupported platform, install failure, headless CI). When unavailable
this module exposes a no-op stub so the rest of v8 keeps running with
graceful degradation per Engineering Order 20.

Public surface
--------------
    graph.init_graph(verbose=False) -> {"available": bool, ...}
    graph.is_available() -> bool
    graph.execute(query: str, params: dict | None = None) -> list[dict]
    graph.bulk_execute(queries: list[str]) -> None
    graph.close() -> None
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Where Kuzu stores its on-disk database
_HERE = Path(__file__).resolve()
BASE_DIR: Path = _HERE.parent.parent.parent
GRAPH_PATH: Path = BASE_DIR / "titan_graph.kuzu"
SCHEMA_FILE: Path = _HERE.parent / "graph_schema.cypher"

# Lazy state
_kuzu_module = None        # the kuzu module if importable
_db = None                 # kuzu.Database instance
_conn = None               # kuzu.Connection instance
_initialised = False
_status: dict = {"available": False, "message": "not initialised"}


def _try_import_kuzu():
    """Import kuzu lazily so the package loads even when kuzu is missing."""
    global _kuzu_module
    if _kuzu_module is not None:
        return _kuzu_module
    try:
        import kuzu  # type: ignore
        _kuzu_module = kuzu
        return kuzu
    except Exception as exc:        # ImportError or native-lib failure
        logger.warning("Kuzu unavailable; graph features degraded: %s", exc)
        return None


def _split_cypher(script: str) -> list[str]:
    """
    Split a Cypher script on `;` while respecting C-style line comments.

    Kuzu's Python driver only accepts ONE statement per execute() call,
    so we split here on top-level semicolons. Comments starting with //
    are stripped to make the split reliable.
    """
    stmts: list[str] = []
    buf: list[str] = []
    for line in script.splitlines():
        # strip line comments
        if "//" in line:
            line = line.split("//", 1)[0]
        # split on semicolons within the cleaned line
        while ";" in line:
            head, sep, tail = line.partition(";")
            buf.append(head)
            stmt = "\n".join(buf).strip()
            if stmt:
                stmts.append(stmt)
            buf = []
            line = tail
        if line.strip():
            buf.append(line)
    tail = "\n".join(buf).strip()
    if tail:
        stmts.append(tail)
    return stmts


def init_graph(verbose: bool = False) -> dict:
    """
    Initialise the graph DB. Returns a status dict consumed by storage.init_storage.

    Always returns rather than raising — a missing graph engine is a
    degraded-mode condition, not a fatal one (Order 20).
    """
    global _db, _conn, _initialised, _status

    if _initialised:
        return _status

    kuzu = _try_import_kuzu()
    if kuzu is None:
        _status = {
            "available": False,
            "message":   "kuzu module not importable; graph features disabled",
            "path":      None,
        }
        _initialised = True
        return _status

    try:
        GRAPH_PATH.parent.mkdir(parents=True, exist_ok=True)
        _db = kuzu.Database(str(GRAPH_PATH))
        _conn = kuzu.Connection(_db)
    except Exception as exc:
        logger.error("Failed to open Kuzu database at %s: %s", GRAPH_PATH, exc)
        _status = {
            "available": False,
            "message":   f"kuzu database open failed: {exc}",
            "path":      str(GRAPH_PATH),
        }
        _initialised = True
        return _status

    # Apply schema (CREATE ... IF NOT EXISTS — safe to repeat)
    if SCHEMA_FILE.exists():
        script = SCHEMA_FILE.read_text(encoding="utf-8")
        for stmt in _split_cypher(script):
            try:
                _conn.execute(stmt)
            except Exception as exc:
                # Kuzu's IF NOT EXISTS handles re-runs cleanly, but some
                # Kuzu versions still raise on existing-relationship-table.
                # Log + continue rather than bail.
                if verbose:
                    logger.debug("graph schema stmt issue (continuing): %s", exc)

    _status = {
        "available": True,
        "message":   "kuzu graph initialised",
        "path":      str(GRAPH_PATH),
    }
    _initialised = True
    if verbose:
        logger.info("Kuzu graph ready at %s", GRAPH_PATH)
    return _status


def is_available() -> bool:
    """Return True if the graph DB is usable."""
    if not _initialised:
        init_graph()
    return _status["available"]


def execute(query: str, params: Optional[dict[str, Any]] = None) -> list[dict]:
    """
    Execute a Cypher query and return rows as list of dicts.

    Returns an empty list when the graph DB is unavailable, so callers
    can use ``if rows:`` idioms without needing to special-case the
    degraded mode.
    """
    if not is_available() or _conn is None:
        return []
    try:
        if params:
            result = _conn.execute(query, params)
        else:
            result = _conn.execute(query)
    except Exception as exc:
        logger.error("Cypher execute failed: %s\nquery: %s", exc, query)
        return []

    rows: list[dict] = []
    try:
        # Kuzu's QueryResult is iterable per row; columns via get_column_names()
        cols = result.get_column_names()
        while result.has_next():
            values = result.get_next()
            rows.append({c: v for c, v in zip(cols, values)})
    except Exception as exc:
        logger.error("Cypher result read failed: %s", exc)
    return rows


def bulk_execute(queries: list[str]) -> None:
    """Run a list of queries sequentially, swallowing per-stmt errors."""
    for q in queries:
        execute(q)


def close() -> None:
    """Tear down the connection (mostly for tests)."""
    global _conn, _db, _initialised, _status
    try:
        if _conn is not None:
            # Kuzu connections close implicitly on GC; no explicit method needed
            _conn = None
        if _db is not None:
            _db = None
    finally:
        _initialised = False
        _status = {"available": False, "message": "closed"}
