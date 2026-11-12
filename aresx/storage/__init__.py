"""
ARES X v8.0 — Storage Layer
=============================
Single source of truth for all v8 persistence:
  • SQLite (titan.db)  — relational state (missions, evidence, vault, audit, etc.)
  • Kuzu               — knowledge graph (entities, twins, TTPs)
  • LanceDB            — vector embeddings (initialized lazily by RAG module)

v6's mike_v3.db is left UNTOUCHED. The v8 storage lives alongside it.

Public API:
    from aresx.storage import db, graph, init_storage
    init_storage()                       # idempotent, safe on every boot
    with db.connect() as conn: ...
    graph.execute("MATCH (n:Entity) RETURN n LIMIT 10")
"""
from __future__ import annotations

from aresx.storage.db import (
    DB_PATH,
    connect,
    execute,
    executemany,
    query_one,
    query_all,
    transaction,
)
from aresx.storage.migrations import (
    apply_schema,
    current_version,
    init_storage,
)
from aresx.storage import graph

# Convenient namespace alias so callers can do `storage.db.connect()`
import sys as _sys
db = _sys.modules[__name__ + ".db"]

__all__ = [
    "DB_PATH",
    "connect",
    "execute",
    "executemany",
    "query_one",
    "query_all",
    "transaction",
    "apply_schema",
    "current_version",
    "init_storage",
    "graph",
    "db",
]
