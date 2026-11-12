# red_module/engagement/engagement_tracker.py
"""
Engagement Tracker for ARES X
Tracks scope, findings, and ROE compliance.
"""

import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


class EngagementTracker:
    def __init__(self, db_path: str = "output/engagements.db"):
        # BUG 7 FIX: was storing in self.engagements dict — lost on process exit
        # now persists to SQLite so findings survive restarts
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite schema."""
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS engagements (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    scope       TEXT,
                    roe         TEXT,
                    status      TEXT DEFAULT 'active',
                    start_time  TEXT
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id            TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    title         TEXT,
                    severity      TEXT,
                    description   TEXT,
                    data          TEXT,
                    timestamp     TEXT,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                );
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def create_engagement(self, name: str, scope: Dict, roe: Dict) -> str:
        """Create and persist a new engagement."""
        eng_id = str(uuid.uuid4())[:8]
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO engagements VALUES (?,?,?,?,?,?)",
                (eng_id, name, json.dumps(scope), json.dumps(roe),
                 "active", datetime.now().isoformat()),
            )
        return eng_id

    def add_finding(self, eng_id: str, finding: Dict) -> Optional[str]:
        """Add a finding to an engagement — persisted to SQLite."""
        find_id = str(uuid.uuid4())[:6]
        with self._conn() as conn:
            # Verify engagement exists
            row = conn.execute(
                "SELECT id FROM engagements WHERE id = ?", (eng_id,)
            ).fetchone()
            if not row:
                print(f"[TRACKER] Engagement {eng_id} not found")
                return None
            conn.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?)",
                (
                    find_id,
                    eng_id,
                    finding.get("title", ""),
                    finding.get("severity", "info"),
                    finding.get("description", ""),
                    json.dumps(finding.get("data", {})),
                    datetime.now().isoformat(),
                ),
            )
        return find_id

    def get_findings(self, eng_id: str) -> List[Dict]:
        """Retrieve all findings for an engagement from DB."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE engagement_id = ? ORDER BY timestamp",
                (eng_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def close_engagement(self, eng_id: str) -> None:
        """Mark engagement as completed."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE engagements SET status = 'completed' WHERE id = ?",
                (eng_id,),
            )

    def generate_report_scaffold(self, eng_id: str) -> Dict:
        """Generate a report scaffold from persisted findings."""
        with self._conn() as conn:
            eng = conn.execute(
                "SELECT * FROM engagements WHERE id = ?", (eng_id,)
            ).fetchone()
        if not eng:
            return {}

        findings = self.get_findings(eng_id)
        critical = [f for f in findings if f.get("severity") == "critical"]
        high     = [f for f in findings if f.get("severity") == "high"]

        return {
            "engagement":      eng["name"],
            "status":          eng["status"],
            "exec_summary":    (
                f"Found {len(findings)} issues — "
                f"{len(critical)} critical, {len(high)} high."
            ),
            "findings":        findings,
            "recommendations": ["Review critical findings first",
                                 "Retest after remediation",
                                 "Update threat model based on findings"],
            "export_formats":  ["markdown", "json", "pdf"],
        }
