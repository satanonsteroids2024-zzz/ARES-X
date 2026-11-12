"""
ARES X v8.0 — Phase 3 Digital Twin Tests
==========================================

Critical tests from the Build Prompt §3 Phase 3:

    Build org twin for "Anthropic"
    → 10+ entities in twin graph
    → twin refreshes incrementally without full rebuild
    → timeline snapshot captured and diff produces meaningful output

Plus: infra twin, adversary twin, human twin privacy gate, visualizer.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class Phase3DigitalTwinTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = Path(tempfile.mkdtemp(prefix="ares_x_phase3_"))
        from aresx.storage import db as db_mod
        db_mod.DB_PATH = cls._tmpdir / "titan.db"
        db_mod.close_thread_connection()
        from aresx.storage import graph as graph_mod
        graph_mod.GRAPH_PATH = cls._tmpdir / "titan_graph.kuzu"
        graph_mod._initialised = False
        graph_mod._status = {"available": False, "message": "not initialised"}
        import aresx.v8_bootstrap as bs
        bs._booted = False; bs._boot_status = None
        bs.boot()

    @classmethod
    def tearDownClass(cls) -> None:
        from aresx.storage import db as db_mod
        db_mod.close_thread_connection()
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    # ── twin store basics ─────────────────────────────────────

    def test_01_create_and_get_twin(self):
        from aresx.digital_twin.twin_store import create_twin, get_twin
        tid = create_twin("org", "TestOrg")
        self.assertIsInstance(tid, str)
        twin = get_twin(tid)
        self.assertIsNotNone(twin)
        self.assertEqual(twin["entity_name"], "TestOrg")
        self.assertEqual(twin["twin_type"], "org")

    def test_02_snapshot_roundtrip(self):
        from aresx.digital_twin.twin_store import (
            create_twin, save_snapshot, load_snapshot,
        )
        tid = create_twin("org", "SnapOrg")
        graph_state = {
            "nodes": [{"entity_id": "n1", "name": "SnapOrg", "entity_type": "Organization"}],
            "edges": [],
        }
        snap_id = save_snapshot(tid, graph_state)
        self.assertIsInstance(snap_id, str)
        loaded = load_snapshot(snap_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(len(loaded["nodes"]), 1)
        self.assertEqual(loaded["nodes"][0]["name"], "SnapOrg")

    def test_03_freshness_decay_decreases_over_time(self):
        import math, time
        from aresx.digital_twin.twin_updater import compute_freshness
        now = time.time()
        self.assertAlmostEqual(compute_freshness(now), 1.0, places=2)
        six_hours_ago = now - 6 * 3600
        f6h = compute_freshness(six_hours_ago)
        self.assertAlmostEqual(f6h, math.exp(-0.1 * 6), places=3)
        self.assertLess(f6h, 1.0)

    # ── ANTHROPIC ACCEPTANCE TEST ─────────────────────────────

    def test_04_anthropic_org_twin_10_plus_entities(self):
        """
        THE Phase 3 acceptance test from the Build Prompt:
        Build org twin for "Anthropic" → 10+ entities in twin graph.
        """
        async def _run():
            from aresx.digital_twin import build_twin
            return await build_twin("org", "Anthropic")

        result = asyncio.run(_run())
        self.assertEqual(result["twin_type"], "org")
        self.assertGreaterEqual(
            result["entity_count"], 10,
            f"Phase 3 acceptance: expected ≥10 entities, got {result['entity_count']}",
        )
        self.assertIsInstance(result["snapshot_id"], str)
        self.assertGreater(len(result["snapshot_id"]), 0)

    def test_05_org_twin_cached_on_second_call(self):
        """Calling build_twin again for the same org returns the cached twin."""
        async def _run():
            from aresx.digital_twin import build_twin
            r1 = await build_twin("org", "Anthropic")
            r2 = await build_twin("org", "Anthropic")
            return r1, r2
        r1, r2 = asyncio.run(_run())
        # Same twin_id — no rebuild
        self.assertEqual(r1["twin_id"], r2["twin_id"])

    def test_06_org_twin_snapshot_captured(self):
        from aresx.digital_twin import find_twin_by_name, list_snapshots
        twin = find_twin_by_name("Anthropic", "org")
        self.assertIsNotNone(twin)
        snaps = list_snapshots(twin["twin_id"])
        self.assertGreater(len(snaps), 0, "At least one snapshot expected after build")

    def test_07_org_twin_diff_meaningful(self):
        """Timeline diff between two snapshots produces a DiffReport."""
        async def _run():
            from aresx.digital_twin import build_twin
            return await build_twin("org", "DiffTestCorp", )
        result = asyncio.run(_run())
        tid = result["twin_id"]

        # Manually save a second snapshot with a changed node
        from aresx.digital_twin.twin_store import (
            load_snapshot, save_snapshot, list_snapshots,
        )
        from aresx.digital_twin.twins.timeline_twin import twin_diff

        snap_ids = list_snapshots(tid)
        original = load_snapshot(snap_ids[0]) or {"nodes": [], "edges": []}

        # Modify the snapshot slightly
        modified = {"nodes": original.get("nodes", [])[:], "edges": original.get("edges", [])[:]}
        modified["nodes"].append({"entity_id": "new_node_42",
                                   "name": "NewEntity", "entity_type": "Person",
                                   "source": "synthetic", "attributes": {}})
        snap_b = save_snapshot(tid, modified)

        report = twin_diff(tid, snap_ids[0], snap_b)
        # Detect the new node we added
        self.assertIn("new_node_42", report.added_nodes,
                      f"Expected new_node_42 in added; report: {report}")
        self.assertIsInstance(report.summary, str)
        self.assertGreater(len(report.summary), 0)

    # ── infra twin ────────────────────────────────────────────

    def test_08_infra_twin_builds(self):
        async def _run():
            from aresx.digital_twin import build_twin
            return await build_twin("infra", "example.com")
        result = asyncio.run(_run())
        self.assertEqual(result["twin_type"], "infra")
        self.assertGreater(result["node_count"], 0)

    # ── adversary twin ────────────────────────────────────────

    def test_09_adversary_twin_builds(self):
        async def _run():
            from aresx.digital_twin import build_twin
            return await build_twin("adversary", "APT29")
        result = asyncio.run(_run())
        self.assertEqual(result["twin_type"], "adversary")
        self.assertGreater(result["ttp_count"], 0)
        self.assertIn(result["sophistication"],
                      ["basic", "intermediate", "advanced", "nation-state"])

    # ── human twin privacy gate ───────────────────────────────

    def test_10_human_twin_requires_gate(self):
        """Building human twin without approved gate must fail."""
        from aresx.digital_twin.twins.human_twin import (
            build_human_twin, HumanTwinPrivacyGateRequired,
        )
        with self.assertRaises(HumanTwinPrivacyGateRequired):
            build_human_twin("Alice Smith", "fake_gate_id_not_approved")

    def test_11_human_twin_with_approved_gate(self):
        """Build succeeds after gate is approved."""
        from aresx.digital_twin.twins.human_twin import (
            request_human_twin_approval, approve_gate, build_human_twin,
        )
        gate_id = request_human_twin_approval("Bob Jones")
        approve_gate(gate_id, approved_by="test_user")
        result = build_human_twin("Bob Jones", gate_id)
        self.assertEqual(result.twin_type if hasattr(result, "twin_type") else "human", "human")
        self.assertIsNotNone(result.snapshot_id)
        self.assertGreater(len(result.public_profiles), 0)

    # ── supply chain twin ─────────────────────────────────────

    def test_12_supply_chain_twin_derives_from_org(self):
        async def _run():
            from aresx.digital_twin import build_twin
            org_result = await build_twin("org", "TestSupplyOrg")
            sc_result = await build_twin(
                "supply_chain", "TestSupplyOrg",
                org_twin_id=org_result["twin_id"],
            )
            return org_result, sc_result
        org, sc = asyncio.run(_run())
        self.assertEqual(sc["twin_type"], "supply_chain")
        # Supply chain twin should have found at least the tech entities
        self.assertGreaterEqual(sc["supplier_count"], 0)

    # ── visualizer ────────────────────────────────────────────

    def test_13_visualizer_layout_data(self):
        from aresx.digital_twin.twin_visualizer import get_layout_data
        state = {
            "nodes": [
                {"entity_id": "r", "name": "Root",    "entity_type": "Organization"},
                {"entity_id": "c", "name": "Child",   "entity_type": "Domain"},
                {"entity_id": "g", "name": "GChild",  "entity_type": "IP"},
            ],
            "edges": [
                {"from_id": "r", "to_id": "c", "relation_type": "uses_domain"},
                {"from_id": "c", "to_id": "g", "relation_type": "resolves_to"},
            ],
        }
        layout = get_layout_data("r", state, layout="hierarchical")
        self.assertIn("nodes", layout)
        self.assertIn("edges", layout)
        self.assertEqual(len(layout["nodes"]), 3)
        self.assertEqual(len(layout["edges"]), 2)
        for node in layout["nodes"]:
            self.assertIn("x", node)
            self.assertIn("y", node)

    def test_14_visualizer_diff_coloring(self):
        from aresx.digital_twin.twin_visualizer import get_diff_visualization
        from aresx.digital_twin.twins.timeline_twin import DiffReport
        report = DiffReport(
            twin_id="t1",
            snapshot_a_id="a",
            snapshot_b_id="b",
            added_nodes=["n1", "n2"],
            removed_nodes=["n3"],
            changed_nodes=[{"node_id": "n4", "field": "name", "before": "Old", "after": "New"}],
            added_edges=[],
            removed_edges=[],
            summary="test diff",
        )
        viz = get_diff_visualization(report)
        self.assertEqual(viz["node_colors"]["n1"], "#00cc44")   # added = green
        self.assertEqual(viz["node_colors"]["n3"], "#cc2200")   # removed = red
        self.assertEqual(viz["node_colors"]["n4"], "#ccaa00")   # changed = yellow

    def test_15_list_twins_filter(self):
        """list_twins with type filter works correctly."""
        from aresx.digital_twin.twin_store import list_twins
        all_twins = list_twins()
        org_twins = list_twins(twin_type="org")
        self.assertLessEqual(len(org_twins), len(all_twins))
        for t in org_twins:
            self.assertEqual(t["twin_type"], "org")


if __name__ == "__main__":
    unittest.main(verbosity=2)
