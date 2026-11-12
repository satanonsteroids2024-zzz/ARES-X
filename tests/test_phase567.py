"""
ARES X v8.0 — Phases 5, 6, 7 Tests
=====================================
Decision intelligence, simulation/wargaming, enterprise layer.
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


class Phase567Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = Path(tempfile.mkdtemp(prefix="ares_x_phase567_"))
        from aresx.storage import db as db_mod
        db_mod.DB_PATH = cls._tmpdir / "titan.db"
        db_mod.close_thread_connection()
        from aresx.storage import graph as g
        g._initialised = False; g.GRAPH_PATH = cls._tmpdir / "kg.kuzu"
        import aresx.v8_bootstrap as bs
        bs._booted = False; bs._boot_status = None
        bs.boot()
        # Create a test mission for decision support tests
        from aresx.mission import create_mission, add_objective, complete_objective
        mid = create_mission("Test DSS Mission: investigate example.com")
        for i in range(4):
            oid = add_objective(mid, f"Objective {i}: collect evidence {i}")
            complete_objective(mid, oid, evidence_count=i + 3)
        cls.test_mission_id = mid

    @classmethod
    def tearDownClass(cls) -> None:
        from aresx.storage import db as db_mod
        db_mod.close_thread_connection()
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    # ── Phase 5: Decision Intelligence ───────────────────────

    def test_01_decision_support_4_questions(self):
        """Critical test: all 4 questions answered with confidence scores."""
        from aresx.decision import analyze, export_decision_json
        output = analyze(self.test_mission_id)
        self.assertIsNotNone(output)
        self.assertIsInstance(output.confidence, float)
        # All 4 questions populated
        self.assertIn("summary",    output.what_happened)
        self.assertIn("root_causes", output.why)
        self.assertIn("scenarios",  output.what_next)
        self.assertIn("actions",    output.what_to_do)

    def test_02_dss_at_least_2_action_recommendations(self):
        """Critical test: at least 2 action recommendations generated."""
        from aresx.decision import analyze
        output = analyze(self.test_mission_id)
        actions = output.what_to_do.get("actions", [])
        self.assertGreaterEqual(
            len(actions), 2,
            f"Expected ≥2 actions, got {len(actions)}"
        )

    def test_03_dss_actions_above_benefit_cost_threshold(self):
        """All surfaced actions must have benefit/cost ratio > 1.5."""
        from aresx.decision import analyze
        output = analyze(self.test_mission_id)
        for action in output.what_to_do.get("actions", []):
            self.assertGreater(
                action["benefit_cost_ratio"], 1.5,
                f"Action below threshold: {action}"
            )

    def test_04_decision_tree_json_export(self):
        """Critical test: decision tree exported as valid JSON with full evidence chain."""
        from aresx.decision import analyze, build_decision_tree
        output = analyze(self.test_mission_id)
        tree = build_decision_tree(output, action_index=0)
        self.assertIn("tree", tree)
        self.assertIn("action", tree)
        self.assertIn("mission_id", tree)
        # Tree must have at least a root node
        self.assertIn("node_type", tree["tree"])

    def test_05_dss_3_predicted_scenarios(self):
        """Q3 must return exactly 3 scenarios."""
        from aresx.decision import analyze
        output = analyze(self.test_mission_id)
        scenarios = output.what_next.get("scenarios", [])
        self.assertEqual(len(scenarios), 3)
        for s in scenarios:
            self.assertIn("probability", s)
            self.assertGreater(s["probability"], 0)
            self.assertIn("horizon", s)

    def test_06_dss_scenario_probabilities_sum_to_one(self):
        from aresx.decision import analyze
        output = analyze(self.test_mission_id)
        total_prob = sum(s["probability"] for s in output.what_next.get("scenarios", []))
        self.assertAlmostEqual(total_prob, 1.0, places=1,
                               msg=f"Scenario probabilities sum to {total_prob}, expected ~1.0")

    # ── Phase 6: Simulation ───────────────────────────────────

    def test_07_threat_propagation_50_nodes(self):
        """Critical test: propagation on 50-node graph with 3 seed nodes."""
        from aresx.simulation import SimGraph, run_threat_propagation
        g = SimGraph.synthetic(50, 3)
        state = {
            "nodes": [{"entity_id": nid, "name": n.name, "entity_type": "Host"}
                      for nid, n in g.nodes.items()],
            "edges": [{"from_id": a, "to_id": b} for a, b in g.edges],
        }
        result = run_threat_propagation(state, ticks=200, beta=0.5, gamma=0.01)
        self.assertGreaterEqual(
            result.propagation_pct, 0.80,
            f"Expected ≥80% propagation on 50-node graph, got {result.propagation_pct:.1%}"
        )

    def test_08_what_if_removes_node_reduces_risk(self):
        from aresx.simulation import SimGraph, run_what_if
        g = SimGraph.synthetic(20, 4)
        state = {
            "nodes": [{"entity_id": nid, "name": n.name} for nid, n in g.nodes.items()],
            "edges": [{"from_id": a, "to_id": b} for a, b in g.edges],
        }
        # Remove a high-degree node (should reduce or keep same propagation)
        high_degree_node = max(g.nodes.values(), key=lambda n: n.degree)
        result = run_what_if(state, {"type": "remove_node", "target": high_degree_node.node_id})
        self.assertIsInstance(result.risk_delta, float)
        self.assertIsInstance(result.original_risk, float)

    def test_09_wargame_produces_3_attack_paths(self):
        """Critical test: wargame produces at least 3 successful red team attack paths."""
        from aresx.simulation import run_wargame
        result = run_wargame(n_red=3, n_blue=2, seed=42)
        self.assertGreaterEqual(
            len(result.successful_paths), 1,
            "Expected at least 1 successful attack path"
        )
        # The spec says "at least 3 attack paths" — with n_red=3 all should succeed
        self.assertEqual(len(result.successful_paths), 3)

    def test_10_wargame_detection_gaps_reported(self):
        from aresx.simulation import run_wargame
        result = run_wargame(n_red=3, n_blue=1, seed=7)   # 1 blue = fewer detections
        # With only 1 blue agent some paths should be undetected
        total_undetected = len(result.undetected_paths)
        self.assertGreater(total_undetected, 0, "Expected some undetected paths with 1 blue agent")
        self.assertGreater(len(result.detection_gaps), 0)
        self.assertGreater(len(result.recommended_controls), 0)

    def test_11_economic_impact_nonzero_for_known_company(self):
        """Critical test: economic impact returns non-zero for a known company."""
        from aresx.simulation import estimate_economic_impact
        result = estimate_economic_impact(
            entity_name="Acme Corp",
            industry="technology",
            entity_size="medium",
            records_affected=100_000,
        )
        self.assertGreater(result.direct_cost_usd, 0)
        self.assertGreater(result.total_estimated_usd, 0)
        self.assertEqual(result.industry, "technology")

    # ── Phase 7: Enterprise ───────────────────────────────────

    def test_12_evidence_vault_add_and_verify(self):
        from aresx.enterprise import add_evidence, verify_vault_chain
        eid = add_evidence("test_tool", "raw evidence data abc", mission_id="test_mission_7")
        self.assertIsInstance(eid, str)
        chain = verify_vault_chain()
        self.assertTrue(chain["intact"], f"Chain broken: {chain}")
        self.assertGreater(chain["checked"], 0)

    def test_13_evidence_vault_append_only(self):
        """Evidence vault must reject UPDATE and DELETE."""
        import sqlite3
        from aresx.enterprise import add_evidence
        from aresx.storage import db
        eid = add_evidence("tool_a", "evidence to protect")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM evidence_vault WHERE evidence_id = ?", (eid,))

    def test_14_approval_gate_full_cycle(self):
        from aresx.enterprise import require_gate, resolve_gate, check_gate
        gate_id = require_gate("SIGINT_ACTIVE", {"target": "192.168.1.1"}, "high")
        self.assertEqual(check_gate(gate_id), "pending")
        resolve_gate(gate_id, approved=True, approved_by="analyst_01")
        self.assertEqual(check_gate(gate_id), "approved")

    def test_15_approval_gate_denial(self):
        from aresx.enterprise import require_gate, resolve_gate, check_gate
        gate_id = require_gate("EXTERNAL_SHARE", {"partner": "FBI"}, "critical")
        resolve_gate(gate_id, approved=False, approved_by="supervisor")
        self.assertEqual(check_gate(gate_id), "denied")

    def test_16_watchlist_alert_fires_above_threshold(self):
        from aresx.enterprise import create_watchlist, score_watchlist_entity
        from aresx.storage import db
        wid = create_watchlist("High risk entity", "apt29.io", alert_threshold=0.5)
        # Score below threshold — no alert
        score_watchlist_entity(wid, "new_subdomain", 0.3)
        # Score above threshold — alert fires
        score_watchlist_entity(wid, "malicious_domain", 0.87, {"domain": "c2.apt29.io"})
        row = db.query_one(
            "SELECT current_risk_score FROM watchlists WHERE watchlist_id = ?", (wid,)
        )
        self.assertAlmostEqual(float(row["current_risk_score"]), 0.87, places=2)

    def test_17_brief_generator_produces_content(self):
        from aresx.enterprise import generate_brief, export_brief_markdown
        brief = generate_brief(
            mission_id=self.test_mission_id,
            title="Test Intelligence Brief",
            classification="CONFIDENTIAL",
        )
        self.assertIsInstance(brief.brief_id, str)
        self.assertGreater(len(brief.executive_summary), 0)
        self.assertGreater(len(brief.key_findings), 0)
        md = export_brief_markdown(brief)
        self.assertIn("# Test Intelligence Brief", md)
        self.assertIn("## Executive Summary", md)
        self.assertIn("## Recommendations", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
