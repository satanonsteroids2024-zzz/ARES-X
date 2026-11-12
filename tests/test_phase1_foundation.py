"""
ARES X v8.0 — Phase 1 Foundation Tests
========================================

Verifies the Phase 1 deliverables from the v8 Build Prompt:
  • SQLite schema applies and is idempotent
  • All 18 v8 tables exist with correct shape
  • Append-only triggers on evidence_vault and audit_log_v2 actually block
  • Seed data (source_reliability, retention_policies) is present
  • Event bus pub/sub works (async + sync)
  • Wildcard subscriptions work
  • Audit hook chains correctly with SHA-3
  • Chain integrity verification detects tampering
  • Graph layer degrades gracefully when kuzu missing (most CI hosts)

Run with::

    python -m pytest tests/test_phase1_foundation.py -v

Or standalone (no pytest)::

    python tests/test_phase1_foundation.py
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class Phase1FoundationTests(unittest.TestCase):
    """Phase 1 acceptance tests. Each test uses an isolated tempdir DB."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = Path(tempfile.mkdtemp(prefix="ares_x_phase1_"))
        # Patch DB_PATH BEFORE importing aresx modules
        os.environ["ARES_X_TEST_DB"] = str(cls._tmpdir / "titan.db")

        # Patch db module's DB_PATH to point at the temp file
        from aresx.storage import db as db_mod
        db_mod.DB_PATH = cls._tmpdir / "titan.db"
        # Reset the per-thread connection so it reopens at the new path
        db_mod.close_thread_connection()

        # Reset bootstrap state so each class fresh-boots
        import aresx.v8_bootstrap as bs
        bs._booted = False
        bs._boot_status = None

        # Reset graph module state to point at temp dir too
        from aresx.storage import graph as graph_mod
        graph_mod.GRAPH_PATH = cls._tmpdir / "titan_graph.kuzu"
        graph_mod._initialised = False
        graph_mod._status = {"available": False, "message": "not initialised"}

    @classmethod
    def tearDownClass(cls) -> None:
        from aresx.storage import db as db_mod
        db_mod.close_thread_connection()
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    # ──────────────────────────────────────────────────────────
    # SCHEMA TESTS
    # ──────────────────────────────────────────────────────────

    def test_01_init_storage_runs(self):
        from aresx.storage import init_storage
        status = init_storage()
        # Phase 1 was schema v1; later phases bump this. Assert ≥ 1.
        self.assertGreaterEqual(status["sqlite_version"], 1)
        self.assertIn("graph_available", status)
        # Graph may be False (kuzu not installed) — that's allowed (Order 20)
        self.assertIsInstance(status["graph_available"], bool)

    def test_02_init_storage_idempotent(self):
        """Calling init_storage twice must not error and must produce same result."""
        from aresx.storage import init_storage
        first = init_storage()
        second = init_storage()
        self.assertEqual(first["sqlite_version"], second["sqlite_version"])

    def test_03_all_v8_tables_exist(self):
        from aresx.storage import db
        # Re-apply schema in case prior tests reset state
        from aresx.storage import init_storage
        init_storage()

        expected_tables = {
            # TITAN
            "schema_version", "evidence_vault", "missions", "mission_objectives",
            "mission_events", "mission_branches", "watchlists", "watchlist_events",
            "approval_gates", "source_reliability", "fusion_assertions",
            "contradictions", "twin_registry",
            # ENTERPRISE
            "sovereign_models", "sovereign_inference_log", "compute_budget",
            "rag_documents", "search_sessions", "audit_log_v2",
            "key_rotation_log", "hsm_attestation", "compliance_checks",
            "retention_policies",
        }
        rows = db.query_all(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        )
        actual = {r["name"] for r in rows}
        missing = expected_tables - actual
        self.assertEqual(missing, set(), f"missing v8 tables: {missing}")

    def test_04_seed_source_reliability(self):
        from aresx.storage import db, init_storage
        init_storage()
        rows = db.query_all("SELECT source_tool, reliability_score FROM source_reliability")
        scores = {r["source_tool"]: r["reliability_score"] for r in rows}
        # Per TRD §3.1
        self.assertAlmostEqual(scores["dark_web"], 0.40)
        self.assertAlmostEqual(scores["social_media"], 0.60)
        self.assertAlmostEqual(scores["official_registry"], 0.90)
        self.assertAlmostEqual(scores["direct_dns"], 0.95)

    def test_05_seed_retention_policies(self):
        from aresx.storage import db, init_storage
        init_storage()
        rows = db.query_all("SELECT data_type, retention_days FROM retention_policies")
        policies = {r["data_type"]: r["retention_days"] for r in rows}
        self.assertEqual(policies["sigint"], 30)
        self.assertEqual(policies["osint"], 365)
        self.assertEqual(policies["evidence"], -1)        # indefinite

    # ──────────────────────────────────────────────────────────
    # APPEND-ONLY ENFORCEMENT (Orders 17 and 27)
    # ──────────────────────────────────────────────────────────

    def test_06_evidence_vault_blocks_delete(self):
        from aresx.storage import db, init_storage
        init_storage()
        db.execute(
            "INSERT INTO evidence_vault "
            "(evidence_id, source_tool, collection_timestamp, raw_data_hash) "
            "VALUES (?, ?, datetime('now'), ?)",
            ("ev_test_06", "test_tool", "deadbeef"),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM evidence_vault WHERE evidence_id='ev_test_06'")

    def test_07_evidence_vault_blocks_update_of_data(self):
        """Order 17: data fields can't be mutated. Only the archive flag is."""
        from aresx.storage import db, init_storage
        init_storage()
        db.execute(
            "INSERT INTO evidence_vault "
            "(evidence_id, source_tool, collection_timestamp, raw_data_hash) "
            "VALUES (?, ?, datetime('now'), ?)",
            ("ev_test_07", "test_tool", "cafebabe"),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute(
                "UPDATE evidence_vault SET source_tool='hacked' "
                "WHERE evidence_id='ev_test_07'"
            )

    def test_08_evidence_vault_allows_soft_archive(self):
        """Soft-archive (toggling 'archived' flag) IS permitted by Order 17."""
        from aresx.storage import db, init_storage
        init_storage()
        db.execute(
            "INSERT INTO evidence_vault "
            "(evidence_id, source_tool, collection_timestamp, raw_data_hash) "
            "VALUES (?, ?, datetime('now'), ?)",
            ("ev_test_08", "test_tool", "feedface"),
        )
        # This should NOT raise — archive flag change is allowed
        db.execute(
            "UPDATE evidence_vault SET archived=1, archived_at=datetime('now') "
            "WHERE evidence_id='ev_test_08'"
        )
        row = db.query_one(
            "SELECT archived FROM evidence_vault WHERE evidence_id='ev_test_08'"
        )
        self.assertEqual(row["archived"], 1)

    def test_09_audit_log_blocks_update_and_delete(self):
        from aresx.storage import db, init_storage
        init_storage()
        db.execute(
            "INSERT INTO audit_log_v2 "
            "(log_id, sequence_num, actor, action, timestamp, this_sha3_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("audit_test_09", 9999, "test", "test_action", "0.0", "0" * 64),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE audit_log_v2 SET actor='hacked' WHERE log_id='audit_test_09'")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM audit_log_v2 WHERE log_id='audit_test_09'")

    # ──────────────────────────────────────────────────────────
    # EVENT BUS
    # ──────────────────────────────────────────────────────────

    def test_10_async_pubsub(self):
        from aresx.events import EventBus, Event, EventType

        async def scenario():
            bus = EventBus()
            sub = bus.subscribe(EventType.FUSION_COMPLETE)
            received: list[Event] = []

            async def consume():
                async for ev in sub:
                    received.append(ev)
                    if len(received) >= 2:
                        sub.close()
                        return

            task = asyncio.create_task(consume())
            await asyncio.sleep(0.01)        # let consumer reach queue.get
            await bus.publish(EventType.FUSION_COMPLETE, payload={"id": 1}, source="test")
            await bus.publish(EventType.FUSION_COMPLETE, payload={"id": 2}, source="test")
            await asyncio.wait_for(task, timeout=2.0)
            return received

        received = asyncio.run(scenario())
        self.assertEqual(len(received), 2)
        self.assertEqual(received[0].payload["id"], 1)
        self.assertEqual(received[1].payload["id"], 2)

    def test_11_wildcard_subscriptions(self):
        from aresx.events import EventBus, EventType

        async def scenario():
            bus = EventBus()
            sub = bus.subscribe("mission.*")
            received = []

            async def consume():
                async for ev in sub:
                    received.append(ev.type.value)
                    if len(received) >= 3:
                        sub.close()
                        return

            task = asyncio.create_task(consume())
            await asyncio.sleep(0.01)
            await bus.publish(EventType.MISSION_STARTED, source="test")
            await bus.publish(EventType.MISSION_COMPLETE, source="test")
            await bus.publish(EventType.FUSION_COMPLETE, source="test")    # SHOULD NOT MATCH
            await bus.publish(EventType.MISSION_FAILED, source="test")
            await asyncio.wait_for(task, timeout=2.0)
            return received

        received = asyncio.run(scenario())
        self.assertEqual(set(received), {
            "mission.started", "mission.complete", "mission.failed",
        })
        self.assertNotIn("fusion.complete", received)

    def test_12_subscription_drops_when_slow(self):
        """Slow subscriber must drop events, not block the publisher (Order 20)."""
        from aresx.events import EventBus, EventType

        async def scenario():
            bus = EventBus()
            sub = bus.subscribe(EventType.OSINT_FINDING, queue_size=4)
            # Publish more than the queue can hold — without consuming
            for i in range(20):
                await bus.publish(EventType.OSINT_FINDING, payload={"i": i}, source="test")
            return sub.dropped, sub.queue.qsize()

        dropped, qsize = asyncio.run(scenario())
        self.assertGreater(dropped, 0, "expected drops with a slow subscriber")
        self.assertLessEqual(qsize, 4)

    # ──────────────────────────────────────────────────────────
    # AUDIT CHAIN INTEGRITY (Order 27)
    # ──────────────────────────────────────────────────────────

    def test_13_boot_creates_audit_chain(self):
        """Fresh boot must produce a clean, intact audit chain rooted at genesis."""
        from aresx.storage import db
        import aresx.v8_bootstrap as bs

        # Test isolation: prior tests inserted synthetic audit records that
        # broke the chain on purpose (test_07, test_09). For this test we
        # need a virgin DB.
        db.close_thread_connection()
        if db.DB_PATH.exists():
            db.DB_PATH.unlink()
        # Also clear any associated WAL/SHM files
        for ext in ("-wal", "-shm"):
            p = db.DB_PATH.with_name(db.DB_PATH.name + ext)
            if p.exists():
                p.unlink()

        bs._booted = False
        bs._boot_status = None
        status = bs.boot()
        self.assertTrue(
            status["audit_chain"]["intact"],
            f"fresh-boot chain not intact: {status['audit_chain']}",
        )
        row = db.query_one(
            "SELECT action FROM audit_log_v2 ORDER BY sequence_num ASC LIMIT 1"
        )
        self.assertIsNotNone(row, "boot should have written at least one audit record")
        self.assertEqual(row["action"], "system.boot.complete")

    def test_14_chain_detects_tampering(self):
        from aresx.storage import db
        import aresx.v8_bootstrap as bs

        # Same isolation as test_13: start with a clean DB.
        db.close_thread_connection()
        if db.DB_PATH.exists():
            db.DB_PATH.unlink()
        for ext in ("-wal", "-shm"):
            p = db.DB_PATH.with_name(db.DB_PATH.name + ext)
            if p.exists():
                p.unlink()

        bs._booted = False
        bs._boot_status = None
        bs.boot()
        # Sanity: fresh chain should be intact
        self.assertTrue(bs.verify_audit_chain()["intact"])

        # Tamper with the genesis record by directly mutating via a fresh
        # connection that doesn't fire triggers (simulating a hostile actor
        # with file-level access). We need to bypass the no-update trigger,
        # so we drop+recreate the trigger temporarily.
        conn = db.connect()
        conn.execute("DROP TRIGGER IF EXISTS audit_log_v2_no_update")
        conn.execute(
            "UPDATE audit_log_v2 SET payload='{\"tampered\":true}' "
            "WHERE sequence_num=1"
        )
        # Restore trigger so subsequent tests behave normally
        conn.execute("""
            CREATE TRIGGER audit_log_v2_no_update
            BEFORE UPDATE ON audit_log_v2
            BEGIN
                SELECT RAISE(ABORT, 'audit_log_v2 is inviolable (Order 27).');
            END
        """)

        verify = bs.verify_audit_chain()
        self.assertFalse(verify["intact"], "tampering should be detected")
        self.assertIsNotNone(verify["break_at"])

    # ──────────────────────────────────────────────────────────
    # GRAPH LAYER GRACEFUL DEGRADATION (Order 20)
    # ──────────────────────────────────────────────────────────

    def test_15_graph_layer_degrades_gracefully(self):
        from aresx.storage import graph
        # Whether kuzu is installed or not, init_graph() must return a
        # status dict and not raise.
        status = graph.init_graph()
        self.assertIn("available", status)
        self.assertIn("message", status)
        # If unavailable, execute() returns empty list (not raise)
        rows = graph.execute("MATCH (n) RETURN n LIMIT 1")
        self.assertIsInstance(rows, list)


# ── pytest-less runner ───────────────────────────────────────
if __name__ == "__main__":
    unittest.main(verbosity=2)
