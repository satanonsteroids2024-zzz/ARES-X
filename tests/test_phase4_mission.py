"""
ARES X v8.0 — Phase 4 Mission OS Tests
========================================

Critical tests from the Build Prompt §3 Phase 4:
  - Commander decomposes into 4+ objectives
  - Mission executes without human intervention
  - mission_events table populated with full event sequence
  - Replay produces identical events at any seek point
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class Phase4MissionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = Path(tempfile.mkdtemp(prefix="ares_x_phase4_"))
        from aresx.storage import db as db_mod
        db_mod.DB_PATH = cls._tmpdir / "titan.db"
        db_mod.close_thread_connection()
        from aresx.storage import graph as g
        g._initialised = False; g.GRAPH_PATH = cls._tmpdir / "kg.kuzu"
        import aresx.v8_bootstrap as bs
        bs._booted = False; bs._boot_status = None
        bs.boot()

    @classmethod
    def tearDownClass(cls) -> None:
        from aresx.storage import db as db_mod
        db_mod.close_thread_connection()
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    # ── mission control basics ────────────────────────────────

    def test_01_create_and_get_mission(self):
        from aresx.mission import create_mission, get_mission
        mid = create_mission("Test investigation goal")
        self.assertIsInstance(mid, str)
        m = get_mission(mid)
        self.assertIsNotNone(m)
        self.assertEqual(m["goal"], "Test investigation goal")
        self.assertEqual(m["status"], "active")

    def test_02_add_objectives_and_complete(self):
        from aresx.mission import (
            create_mission, add_objective, complete_objective,
            get_objectives,
        )
        mid = create_mission("Multi-objective test")
        oid1 = add_objective(mid, "Objective 1")
        oid2 = add_objective(mid, "Objective 2", dependencies=[oid1])
        complete_objective(mid, oid1, evidence_count=5)
        objs = get_objectives(mid)
        statuses = {o["objective_id"]: o["status"] for o in objs}
        self.assertEqual(statuses[oid1], "complete")
        self.assertEqual(statuses[oid2], "pending")

    def test_03_pause_and_resume(self):
        from aresx.mission import (
            create_mission, pause_mission, resume_mission, get_mission,
        )
        mid = create_mission("Pause resume test")
        pause_mission(mid)
        self.assertEqual(get_mission(mid)["status"], "paused")
        resume_mission(mid)
        self.assertEqual(get_mission(mid)["status"], "active")

    def test_04_branch_mission(self):
        from aresx.mission import create_mission, branch_mission, get_mission
        mid = create_mission("Parent mission")
        bid = branch_mission(mid, "Alternate hypothesis: entity is a shell company")
        self.assertIsInstance(bid, str)
        # branch_mission returns branch_id, which also creates a new mission
        from aresx.mission import list_missions
        all_missions = list_missions()
        self.assertGreater(len(all_missions), 1)

    def test_05_event_sequence_monotonic(self):
        """Order 16: sequence_num must be strictly increasing."""
        from aresx.mission import (
            create_mission, add_objective, complete_objective,
            get_event_sequence,
        )
        mid = create_mission("Sequence test mission")
        for i in range(5):
            oid = add_objective(mid, f"Objective {i}")
            complete_objective(mid, oid, evidence_count=i)

        events = get_event_sequence(mid)
        self.assertGreater(len(events), 0)
        seqs = [int(e["sequence_num"]) for e in events]
        for j in range(1, len(seqs)):
            self.assertGreater(seqs[j], seqs[j - 1],
                f"sequence_num not monotonic: {seqs[j - 1]} → {seqs[j]}")

    # ── AUTONOMOUS COMMANDER — critical test ──────────────────

    def test_06_commander_decomposes_4_plus_objectives(self):
        """
        Critical test from the Build Prompt:
        Create test mission: "Investigate the infrastructure connections of example.com"
        Verify: commander decomposes into 4+ objectives
        """
        async def _run():
            from aresx.autonomy import launch_mission
            return await launch_mission(
                "Investigate the infrastructure connections of example.com",
                name="example.com Infrastructure Investigation",
            )
        result = asyncio.run(_run())
        self.assertEqual(result["status"], "complete")
        self.assertGreaterEqual(
            result["objectives"], 4,
            f"Expected ≥4 objectives, got {result['objectives']}"
        )

    def test_07_commander_executes_without_human_intervention(self):
        """
        Critical test: mission executes without human intervention.
        All objectives complete with zero human_approval_gate triggers.
        """
        async def _run():
            from aresx.autonomy import launch_mission
            return await launch_mission("Investigate financial connections of ACME Corp")
        result = asyncio.run(_run())
        # All objectives must auto-complete (no stuck-on-approval state)
        self.assertEqual(result["completed"], result["objectives"])

    def test_08_mission_events_table_populated(self):
        """
        Critical test: mission_events table populated with full event sequence.
        """
        async def _run():
            from aresx.autonomy import launch_mission
            return await launch_mission("Map open-source intelligence on test-target.io")
        result = asyncio.run(_run())
        mid = result["mission_id"]
        from aresx.mission import get_event_sequence
        events = get_event_sequence(mid)
        self.assertGreater(
            len(events), 0,
            "mission_events must be populated during autonomous execution"
        )
        event_types = {e["event_type"] for e in events}
        # mission_created must be present
        self.assertIn("mission_created", event_types)
        # At least one objective-related event
        obj_events = {et for et in event_types
                      if "objective" in et or "agent" in et or "started" in et}
        self.assertGreater(len(obj_events), 0,
                           f"Expected objective events; found: {event_types}")

    def test_09_mission_replay_any_seek_point(self):
        """
        Critical test: replay produces identical events at any seek point.
        """
        async def _run():
            from aresx.autonomy import launch_mission
            return await launch_mission("Replay test investigation")
        result = asyncio.run(_run())
        mid = result["mission_id"]

        from aresx.mission.mission_replay import (
            get_replay_frames, seek_to, export_replay_json,
        )
        full_frames = get_replay_frames(mid)
        self.assertGreater(len(full_frames), 0)

        # Seek to midpoint
        mid_seq = full_frames[len(full_frames) // 2].sequence_num
        frames_up_to_mid = seek_to(mid, mid_seq)
        self.assertLessEqual(len(frames_up_to_mid), len(full_frames))
        # All frames up to midpoint must have sequence_num ≤ mid_seq
        for f in frames_up_to_mid:
            self.assertLessEqual(f.sequence_num, mid_seq)

        # Export JSON round-trip
        export = export_replay_json(mid)
        self.assertIn("frames", export)
        self.assertEqual(export["frame_count"], len(full_frames))

    def test_10_list_missions_status_filter(self):
        from aresx.mission import create_mission, complete_mission, list_missions
        mid = create_mission("Status filter test")
        complete_mission(mid)
        completed = list_missions(status="complete")
        ids = [m["mission_id"] for m in completed]
        self.assertIn(mid, ids)
        active = list_missions(status="active")
        self.assertNotIn(mid, [m["mission_id"] for m in active])

    def test_11_emit_agent_events(self):
        """Agents can log their actions to the mission timeline."""
        from aresx.mission import create_mission, emit_agent_event, get_event_sequence
        mid = create_mission("Agent event test")
        seq = emit_agent_event(mid, "osint_agent", "tool_called",
                                {"tool": "whois", "target": "example.com"})
        self.assertIsInstance(seq, int)
        self.assertGreater(seq, 0)
        events = get_event_sequence(mid)
        tool_events = [e for e in events if e["event_type"] == "tool_called"]
        self.assertGreater(len(tool_events), 0)

    def test_12_concurrent_missions_slot_limit(self):
        """
        MAX_CONCURRENT_MISSIONS = 5: launching a 6th while slots are full returns error.
        (We test the limit mechanism, not actual concurrency for CI speed.)
        """
        from aresx.autonomy import commander
        original = commander._active_slots
        commander._active_slots = commander.MAX_CONCURRENT_MISSIONS
        try:
            result = asyncio.run(commander.launch_mission("Overflow test"))
            self.assertIn("error", result)
        finally:
            commander._active_slots = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
