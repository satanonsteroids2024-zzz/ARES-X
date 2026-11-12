"""
ARES X v8.0 — SQLite connection layer for titan.db.

Design notes
------------
• One database file: titan.db, located beside v6's mike_v3.db (BASE_DIR).
• WAL journal mode + NORMAL sync → concurrent readers, single writer.
• Per-thread connection cache: sqlite3.Connection is NOT thread-safe by
  default, so we keep one connection per OS thread via threading.local.
• All boolean fields are stored as INTEGER (0/1) per SQLite convention.
• PRAGMA foreign_keys = ON is applied on every new connection.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Sequence

# ── Path: titan.db lives alongside v6's mike_v3.db ─────────────
# aresx/storage/db.py → BASE_DIR is two levels up (project root)
_HERE = Path(__file__).resolve()
BASE_DIR: Path = _HERE.parent.parent.parent
DB_PATH: Path = BASE_DIR / "titan.db"

_tls = threading.local()


def _new_connection() -> sqlite3.Connection:
    """Create a fresh, properly-configured sqlite3 connection."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(DB_PATH),
        # No PARSE_DECLTYPES — we want raw values for the audit chain's
        # canonical timestamp strings. Callers parse timestamps explicitly
        # when they need them as datetime objects.
        timeout=30.0,
        isolation_level=None,           # autocommit; we manage transactions manually
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous  = NORMAL;")
    conn.execute("PRAGMA busy_timeout = 30000;")   # 30s for writer lock
    return conn


def connect() -> sqlite3.Connection:
    """
    Return the per-thread connection, creating it on first call.

    Caller does NOT close the connection — it is reused for the thread's
    lifetime and torn down at interpreter exit.
    """
    conn = getattr(_tls, "conn", None)
    if conn is None:
        conn = _new_connection()
        _tls.conn = conn
    return conn


def close_thread_connection() -> None:
    """Close the current thread's connection (mostly used in tests)."""
    conn = getattr(_tls, "conn", None)
    if conn is not None:
        try:
            conn.close()
        finally:
            _tls.conn = None


# ── Query helpers ──────────────────────────────────────────────

def execute(sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
    """Execute a single statement and return its cursor."""
    return connect().execute(sql, params)


def executemany(sql: str, seq_of_params: Iterable[Sequence[Any]]) -> sqlite3.Cursor:
    """Execute a single statement against a batch of parameter rows."""
    return connect().executemany(sql, seq_of_params)


def query_one(sql: str, params: Sequence[Any] = ()) -> Optional[sqlite3.Row]:
    """Run a query and fetch a single row, or None."""
    cur = execute(sql, params)
    return cur.fetchone()


def query_all(sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
    """Run a query and fetch all rows as a list of sqlite3.Row."""
    cur = execute(sql, params)
    return list(cur.fetchall())


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    """
    BEGIN / COMMIT / ROLLBACK context manager.

    Usage::

        with transaction() as conn:
            conn.execute("INSERT ...")
            conn.execute("UPDATE ...")
        # commits on clean exit, rolls back on exception
    """
    conn = connect()
    conn.execute("BEGIN IMMEDIATE;")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK;")
        raise
    else:
        conn.execute("COMMIT;")
