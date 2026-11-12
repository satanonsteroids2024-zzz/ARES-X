"""
ARES X v10 — Mike async SQLite memory (split from core.py)
==========================================================
Split out of the v9 core.py god-file into a focused module.

All original public symbols are re-exported by aresx.core (the
compat facade) so existing importers keep working unmodified.
"""
from __future__ import annotations

from aresx.core.paths import BASE_DIR, MEMORY_DB, ARCHIVE_DIR, cfg

import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
import math
import os
import platform
import queue
import re
import secrets
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
# ══════════════════════════════════════════════════════════════
# MIKE v3 — Async SQLite Vector Memory with Episodic Decay
# ══════════════════════════════════════════════════════════════
_MIKE_SCHEMA = """
CREATE TABLE IF NOT EXISTS facts (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL,
    ts      REAL NOT NULL,
    decay   REAL DEFAULT 1.0,
    tags    TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS commands (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cmd     TEXT NOT NULL,
    result  TEXT DEFAULT '',
    ts      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    note    TEXT NOT NULL,
    ts      REAL NOT NULL,
    tags    TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS osint_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    target  TEXT NOT NULL,
    result  TEXT NOT NULL,
    ts      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS graph (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    from_key TEXT NOT NULL,
    to_key   TEXT NOT NULL,
    relation TEXT DEFAULT 'related',
    ts       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    name    TEXT PRIMARY KEY,
    desc    TEXT DEFAULT '',
    status  TEXT DEFAULT 'active',
    links   TEXT DEFAULT '[]',
    ts      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS patterns (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ptype   TEXT NOT NULL,
    data    TEXT NOT NULL,
    ts      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_commands_ts ON commands(ts);
CREATE INDEX IF NOT EXISTS idx_facts_key   ON facts(key);
CREATE INDEX IF NOT EXISTS idx_notes_ts    ON notes(ts);
"""

_DECAY_HALF_LIFE = 60 * 60 * 24 * 7  # 7 days in seconds


def _compute_decay(ts: float) -> float:
    """Exponential decay: relevance halves every 7 days."""
    age = time.time() - ts
    return math.exp(-0.693 * age / _DECAY_HALF_LIFE)


class Mike:
    """Async-native relational graph memory with episodic decay."""

    def __init__(self) -> None:
        self._db_path = str(MEMORY_DB)
        self._ready = False
        self._init_task: Optional[asyncio.Task] = None
        self._sync_lock = threading.Lock()

    async def _ensure_db(self) -> "aiosqlite.Connection":
        if not _AIOSQLITE:
            raise RuntimeError("aiosqlite not installed")
        conn = await aiosqlite.connect(self._db_path)
        await conn.executescript(_MIKE_SCHEMA)
        await conn.commit()
        return conn

    # ── Public async API ───────────────────────────────────────

    async def remember_async(self, key: str, value: str, tags: Optional[List[str]] = None) -> None:
        async with await self._ensure_db() as db:
            await db.execute(
                "INSERT OR REPLACE INTO facts(key,value,ts,decay,tags) VALUES(?,?,?,?,?)",
                (str(key), str(value)[:2000], time.time(), 1.0, json.dumps(tags or []))
            )
            await db.commit()

    async def all_keys_async(self, prefix: str = "") -> List[str]:
        """Return all stored fact keys, optionally filtered by prefix.
        Additive helper used by the v6 graph-analytics / investigation modules."""
        async with await self._ensure_db() as db:
            if prefix:
                q = "SELECT key FROM facts WHERE key LIKE ? ORDER BY ts DESC"
                args = (prefix + "%",)
            else:
                q = "SELECT key FROM facts ORDER BY ts DESC"
                args = ()
            async with db.execute(q, args) as cur:
                rows = await cur.fetchall()
                return [r[0] for r in rows]

    async def recall_async(self, key: str) -> Optional[str]:
        async with await self._ensure_db() as db:
            async with db.execute(
                "SELECT value, ts FROM facts WHERE key=?", (str(key),)
            ) as cur:
                row = await cur.fetchone()
                if row:
                    decay = _compute_decay(row[1])
                    if decay > 0.01:
                        return row[0]
        return None

    async def log_command_async(self, cmd: str, result: str = "") -> None:
        async with await self._ensure_db() as db:
            await db.execute(
                "INSERT INTO commands(cmd,result,ts) VALUES(?,?,?)",
                (str(cmd)[:500], str(result)[:300], time.time())
            )
            # Keep only last 1000
            await db.execute(
                "DELETE FROM commands WHERE id NOT IN "
                "(SELECT id FROM commands ORDER BY ts DESC LIMIT 1000)"
            )
            await db.commit()

    async def log_osint_async(self, target: str, result: str) -> None:
        async with await self._ensure_db() as db:
            await db.execute(
                "INSERT INTO osint_log(target,result,ts) VALUES(?,?,?)",
                (str(target)[:200], str(result)[:1000], time.time())
            )
            await db.execute(
                "DELETE FROM osint_log WHERE id NOT IN "
                "(SELECT id FROM osint_log ORDER BY ts DESC LIMIT 500)"
            )
            await db.commit()

    async def add_note_async(self, text: str, tags: Optional[List[str]] = None) -> None:
        async with await self._ensure_db() as db:
            await db.execute(
                "INSERT INTO notes(note,ts,tags) VALUES(?,?,?)",
                (str(text)[:2000], time.time(), json.dumps(tags or []))
            )
            await db.commit()
        try:
            with open(NOTES_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M')}] {text}\n")
        except OSError:
            pass

    async def link_async(self, from_key: str, to_key: str, relation: str = "related") -> None:
        async with await self._ensure_db() as db:
            await db.execute(
                "INSERT INTO graph(from_key,to_key,relation,ts) VALUES(?,?,?,?)",
                (str(from_key), str(to_key), relation, time.time())
            )
            await db.execute(
                "DELETE FROM graph WHERE id NOT IN "
                "(SELECT id FROM graph ORDER BY ts DESC LIMIT 2000)"
            )
            await db.commit()

    async def add_project_async(self, name: str, desc: str = "",
                                 links: Optional[List[str]] = None) -> None:
        async with await self._ensure_db() as db:
            await db.execute(
                "INSERT OR REPLACE INTO projects(name,desc,status,links,ts) VALUES(?,?,?,?,?)",
                (name, desc, "active", json.dumps(links or []), time.time())
            )
            await db.commit()

    async def log_pattern_async(self, ptype: str, data: str) -> None:
        async with await self._ensure_db() as db:
            await db.execute(
                "INSERT INTO patterns(ptype,data,ts) VALUES(?,?,?)",
                (ptype, str(data)[:500], time.time())
            )
            await db.execute(
                "DELETE FROM patterns WHERE id NOT IN "
                "(SELECT id FROM patterns ORDER BY ts DESC LIMIT 500)"
            )
            await db.commit()

    async def recent_commands_async(self, n: int = 8) -> List[Dict]:
        async with await self._ensure_db() as db:
            async with db.execute(
                "SELECT cmd, result, ts FROM commands ORDER BY ts DESC LIMIT ?", (n,)
            ) as cur:
                rows = await cur.fetchall()
        return [{"cmd": r[0], "result": r[1], "ts": r[2]} for r in reversed(rows)]

    async def context_for_ai_async(self, n: int = 10) -> str:
        parts: List[str] = []
        async with await self._ensure_db() as db:
            # Recent commands with decay scoring
            async with db.execute(
                "SELECT cmd, ts FROM commands ORDER BY ts DESC LIMIT ?", (n,)
            ) as cur:
                cmds = await cur.fetchall()
            if cmds:
                relevant = [c[0] for c in cmds if _compute_decay(c[1]) > 0.1][:n]
                if relevant:
                    parts.append("Recent: " + "; ".join(relevant))

            # High-decay facts (most relevant)
            async with db.execute(
                "SELECT key, value, ts FROM facts ORDER BY ts DESC LIMIT 10"
            ) as cur:
                facts = await cur.fetchall()
            if facts:
                top = [(f[0], f[1]) for f in facts if _compute_decay(f[2]) > 0.3][:5]
                if top:
                    parts.append("Facts: " + "; ".join(f"{k}={v}" for k, v in top))

            # Recent notes
            async with db.execute(
                "SELECT note FROM notes ORDER BY ts DESC LIMIT 3"
            ) as cur:
                notes = await cur.fetchall()
            if notes:
                parts.append("Notes: " + "; ".join(n[0][:80] for n in notes))

            # Active projects
            async with db.execute(
                "SELECT name FROM projects WHERE status='active' LIMIT 5"
            ) as cur:
                projs = await cur.fetchall()
            if projs:
                parts.append("Projects: " + ", ".join(p[0] for p in projs))

        return "\n".join(parts)

    async def summary_async(self) -> str:
        async with await self._ensure_db() as db:
            async with db.execute("SELECT COUNT(*) FROM commands") as c:
                n_cmds = (await c.fetchone())[0]
            async with db.execute("SELECT COUNT(*) FROM facts") as c:
                n_facts = (await c.fetchone())[0]
            async with db.execute("SELECT COUNT(*) FROM notes") as c:
                n_notes = (await c.fetchone())[0]
            async with db.execute("SELECT COUNT(*) FROM osint_log") as c:
                n_osint = (await c.fetchone())[0]
            async with db.execute("SELECT COUNT(*) FROM graph") as c:
                n_graph = (await c.fetchone())[0]
        return (f"Mike v3: {n_cmds} cmds, {n_facts} facts, "
                f"{n_notes} notes, {n_osint} OSINT, {n_graph} links")

    # ── Sync wrappers (for legacy callers) ─────────────────────
    def remember(self, key: str, value: str, tags: Optional[List[str]] = None) -> None:
        run_async(self.remember_async(key, value, tags))

    def recall(self, key: str) -> Optional[str]:
        return run_async(self.recall_async(key))

    def all_keys(self, prefix: str = "") -> List[str]:
        return run_async(self.all_keys_async(prefix)) or []

    def log_command(self, cmd: str, result: str = "") -> None:
        run_async(self.log_command_async(cmd, result))

    def log_osint(self, target: str, result: str) -> None:
        run_async(self.log_osint_async(target, result))

    def add_note(self, text: str, tags: Optional[List[str]] = None) -> None:
        run_async(self.add_note_async(text, tags))

    def log_pattern(self, ptype: str, data: str) -> None:
        run_async(self.log_pattern_async(ptype, data))

    def add_project(self, name: str, desc: str = "", links: Optional[List[str]] = None) -> None:
        run_async(self.add_project_async(name, desc, links))

    def link(self, from_key: str, to_key: str, relation: str = "related") -> None:
        run_async(self.link_async(from_key, to_key, relation))

    def recent_commands(self, n: int = 8) -> List[Dict]:
        return run_async(self.recent_commands_async(n)) or []

    def context_for_ai(self, n: int = 10) -> str:
        return run_async(self.context_for_ai_async(n)) or ""

    def summary(self) -> str:
        return run_async(self.summary_async()) or "Mike v3: not initialized"

    def get_project(self, name: str) -> Optional[Dict]:
        async def _get():
            async with await self._ensure_db() as db:
                async with db.execute(
                    "SELECT name,desc,status,links,ts FROM projects WHERE name=?", (name,)
                ) as cur:
                    row = await cur.fetchone()
                    if row:
                        return {"name": row[0], "desc": row[1], "status": row[2],
                                "links": json.loads(row[3]), "ts": row[4]}
            return None
        return run_async(_get())

    # data shim for legacy code accessing .data["facts"] etc.
    @property
    def data(self) -> Dict:
        """Legacy shim: returns snapshot dict. Prefer async methods."""
        async def _snap():
            out: Dict[str, Any] = {"facts": {}, "commands": [], "notes": [],
                                    "osint": [], "graph": [], "projects": {}, "patterns": []}
            try:
                async with await self._ensure_db() as db:
                    async with db.execute("SELECT key,value FROM facts") as c:
                        for r in await c.fetchall():
                            out["facts"][r[0]] = {"value": r[1]}
                    async with db.execute(
                        "SELECT cmd,result,ts FROM commands ORDER BY ts DESC LIMIT 500"
                    ) as c:
                        out["commands"] = [{"cmd": r[0], "result": r[1], "ts": r[2]}
                                           for r in await c.fetchall()]
                    async with db.execute(
                        "SELECT note,ts FROM notes ORDER BY ts DESC LIMIT 200"
                    ) as c:
                        out["notes"] = [{"note": r[0], "ts": r[1]} for r in await c.fetchall()]
            except Exception:
                pass
            return out
        return run_async(_snap()) or {}


mike = Mike()
