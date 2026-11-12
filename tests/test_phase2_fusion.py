"""
ARES X v8.0 — Phase 2 Fusion Tests
=====================================

The acceptance criteria from the Build Prompt §3 Phase 2:

    Inject 5 OSINT pieces for "Microsoft"
    + 1 SIGINT device seen at Microsoft HQ
    + 1 FININT corporate record
    → fusion engine produces FusedAssertion with confidence ≥ 0.85
    → 7 evidence pieces visible in buffer
    → reliability scores stored for all 3 source types

Plus unit tests for every Phase 2 sub-module.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class Phase2FusionTests(unittest.TestCase):
    """Phase 2 acceptance suite. Each test gets a fresh DB."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = Path(tempfile.mkdtemp(prefix="ares_x_phase2_"))

        from aresx.storage import db as db_mod
        db_mod.DB_PATH = cls._tmpdir / "titan.db"
        db_mod.close_thread_connection()

        from aresx.storage import graph as graph_mod
        graph_mod.GRAPH_PATH = cls._tmpdir / "titan_graph.kuzu"
        graph_mod._initialised = False
        graph_mod._status = {"available": False, "message": "not initialised"}

        # Bootstrap v8 substrate
        import aresx.v8_bootstrap as bs
        bs._booted = False
        bs._boot_status = None
        bs.boot()

    @classmethod
    def tearDownClass(cls) -> None:
        from aresx.storage import db as db_mod
        db_mod.close_thread_connection()
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    # ──────────────────────────────────────────────────────────
    # source_reliability
    # ──────────────────────────────────────────────────────────

    def test_01_seeded_reliability(self):
        """Seed scores from schema must be readable."""
        from aresx.fusion import source_reliability as sr
        self.assertAlmostEqual(sr.get_reliability("direct_dns"), 0.95)
        self.assertAlmostEqual(sr.get_reliability("dark_web"), 0.40)

    def test_02_auto_create_unknown_source(self):
        from aresx.fusion import source_reliability as sr
        score = sr.get_reliability("brand_new_tool_xyz")
        self.assertAlmostEqual(score, sr.DEFAULT_RELIABILITY)
        # Second call hits the same row, not creates a new one
        again = sr.get_reliability("brand_new_tool_xyz")
        self.assertAlmostEqual(again, sr.DEFAULT_RELIABILITY)

    def test_03_formula_update_reliability(self):
        from aresx.fusion import source_reliability as sr
        # 0.7 * 0.9 + 0.3 * 0.6 = 0.63 + 0.18 = 0.81
        new_score = sr.update_reliability("test_tool_a", 0.9, 0.6)
        self.assertAlmostEqual(new_score, 0.81, places=6)
        # Persisted
        self.assertAlmostEqual(sr.get_reliability("test_tool_a"), 0.81, places=6)

    def test_04_streaming_update(self):
        from aresx.fusion import source_reliability as sr
        # First outcome: correct + corroborated → 0.7*1.0 + 0.3*1.0 = 1.0
        score1 = sr.record_outcome("stream_tool", True, True)
        self.assertAlmostEqual(score1, 1.0, places=6)
        # Second outcome: incorrect + uncorroborated → drives down via running mean
        score2 = sr.record_outcome("stream_tool", False, False)
        self.assertLess(score2, score1)

    # ──────────────────────────────────────────────────────────
    # confidence formula
    # ──────────────────────────────────────────────────────────

    def test_05_confidence_formula_pure(self):
        """Verify the spec formula in isolation, no DB."""
        from aresx.fusion import confidence
        from aresx.fusion.types import Evidence, Domain
        fake_rel = {"src_a": 0.9, "src_b": 0.8, "src_c": 0.7}
        evidence = [
            Evidence(entity_id="E", source_tool="src_a", attribute="x", value="1", domain=Domain.OSINT),
            Evidence(entity_id="E", source_tool="src_b", attribute="x", value="1", domain=Domain.OSINT),
            Evidence(entity_id="E", source_tool="src_c", attribute="x", value="1", domain=Domain.OSINT),
        ]
        score = confidence.compute_confidence(
            supporting=evidence,
            contradicting=(),
            reliability_lookup=fake_rel.__getitem__,
        )
        # base = mean of 1.0s = 1.0; bonus = min(0.2, 0.05*3=0.15) = 0.15
        # final = clamp(1.0 + 0.15, 0, 1) = 1.0
        self.assertAlmostEqual(score, 1.0, places=6)

    def test_06_confidence_contradiction_penalty(self):
        from aresx.fusion import confidence
        from aresx.fusion.types import Evidence, Domain
        rel = lambda t: 0.8
        supporting = [Evidence(entity_id="E", source_tool="s1", attribute="x",
                               value="v1", domain=Domain.OSINT,
                               evidence_score=0.8)]
        contradicting = [
            Evidence(entity_id="E", source_tool="s2", attribute="x",
                     value="v2", domain=Domain.OSINT),
            Evidence(entity_id="E", source_tool="s3", attribute="x",
                     value="v3", domain=Domain.OSINT),
        ]
        score = confidence.compute_confidence(
            supporting=supporting,
            contradicting=contradicting,
            reliability_lookup=rel,
        )
        # base = 0.8 (single piece); bonus = 0.05; penalty = 0.30
        # final = clamp(0.8 + 0.05 - 0.30) = 0.55
        self.assertAlmostEqual(score, 0.55, places=6)

    def test_07_confidence_empty_supporting(self):
        from aresx.fusion import confidence
        score = confidence.compute_confidence(supporting=[], contradicting=[])
        self.assertEqual(score, 0.0)

    # ──────────────────────────────────────────────────────────
    # contradiction detection
    # ──────────────────────────────────────────────────────────

    def test_08_no_contradictions_when_agreed(self):
        from aresx.fusion import contradiction
        from aresx.fusion.types import Evidence, Domain
        rel = lambda t: 0.8
        ev = [
            Evidence(entity_id="E", source_tool="s1", attribute="founded", value="1975", domain=Domain.OSINT),
            Evidence(entity_id="E", source_tool="s2", attribute="founded", value="1975", domain=Domain.OSINT),
        ]
        c = contradiction.detect_contradictions(ev, reliability_lookup=rel, publish=False)
        self.assertEqual(c, [])

    def test_09_contradiction_detected_auto_resolution(self):
        from aresx.fusion import contradiction
        from aresx.fusion.types import Evidence, Domain
        # Spread reliability so auto-resolve triggers (delta ≥ 0.15)
        rel = {"high_rel": 0.95, "low_rel": 0.50}.get
        ev = [
            Evidence(entity_id="E", source_tool="high_rel", attribute="ceo",
                     value="Alice", domain=Domain.OSINT),
            Evidence(entity_id="E", source_tool="low_rel", attribute="ceo",
                     value="Bob", domain=Domain.OSINT),
        ]
        c = contradiction.detect_contradictions(ev, reliability_lookup=rel, publish=False)
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].resolution_mode, "auto")
        self.assertEqual(c[0].resolved_value, "Alice")

    def test_10_contradiction_human_review_when_close_reliability(self):
        from aresx.fusion import contradiction
        from aresx.fusion.types import Evidence, Domain
        # Close reliability → can't auto-resolve
        rel = {"a": 0.82, "b": 0.80}.get
        ev = [
            Evidence(entity_id="E", source_tool="a", attribute="ceo", value="X", domain=Domain.OSINT),
            Evidence(entity_id="E", source_tool="b", attribute="ceo", value="Y", domain=Domain.OSINT),
        ]
        c = contradiction.detect_contradictions(ev, reliability_lookup=rel, publish=False)
        self.assertEqual(c[0].resolution_mode, "human_review")
        self.assertIsNone(c[0].resolved_value)

    # ──────────────────────────────────────────────────────────
    # signal correlator
    # ──────────────────────────────────────────────────────────

    def test_11_jaccard_token_similarity(self):
        from aresx.fusion import signal_correlator as sc
        self.assertGreater(sc.token_jaccard("Microsoft Corp", "Microsoft Corporation"), 0.3)
        self.assertEqual(sc.token_jaccard("a b c", "d e f"), 0.0)

    def test_12_spatial_score_close(self):
        from aresx.fusion import signal_correlator as sc
        from aresx.fusion.types import Evidence, Domain
        a = Evidence(entity_id="E", source_tool="s", attribute="device_seen_at",
                     value="47.640,-122.130", domain=Domain.SIGINT)
        b = Evidence(entity_id="E", source_tool="s", attribute="device_seen_at",
                     value="47.6401,-122.1301", domain=Domain.SIGINT)
        self.assertAlmostEqual(sc.spatial_score(a, b, max_km=1.0), 1.0)

    def test_13_correlate_same_entity(self):
        from aresx.fusion import signal_correlator as sc
        from aresx.fusion.types import Evidence, Domain
        a = Evidence(entity_id="Microsoft Corp", source_tool="finint",
                     attribute="name", value="Microsoft Corp", domain=Domain.FININT)
        b = Evidence(entity_id="Microsoft Corporation", source_tool="osint",
                     attribute="name", value="Microsoft Corporation", domain=Domain.OSINT)
        res = sc.correlate(a, b)
        self.assertTrue(res.same_entity)

    # ──────────────────────────────────────────────────────────
    # event correlator
    # ──────────────────────────────────────────────────────────

    def test_14_event_correlator_matches_chain(self):
        from aresx.fusion.event_correlator import EventCorrelator, CorrelationRule
        ec = EventCorrelator(rules=[
            CorrelationRule(
                name="test_chain",
                required_types=["A", "B", "C"],
                window_seconds=120,
                suspicion_score=0.9,
            ),
        ])
        t0 = time.time()
        ec.ingest("A", {}, timestamp=t0)
        ec.ingest("B", {}, timestamp=t0 + 10)
        chains = ec.ingest("C", {}, timestamp=t0 + 50)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].pattern_name, "test_chain")
        self.assertEqual(len(chains[0].members), 3)

    def test_15_event_correlator_rejects_out_of_window(self):
        from aresx.fusion.event_correlator import EventCorrelator, CorrelationRule
        ec = EventCorrelator(rules=[
            CorrelationRule(name="t", required_types=["A", "B"],
                            window_seconds=60, suspicion_score=0.5),
        ])
        t0 = time.time()
        ec.ingest("A", {}, timestamp=t0)
        chains = ec.ingest("B", {}, timestamp=t0 + 600)   # way outside window
        self.assertEqual(chains, [])

    # ──────────────────────────────────────────────────────────
    # cross-domain
    # ──────────────────────────────────────────────────────────

    def test_16_geo_finint_co_location(self):
        from aresx.fusion import cross_domain as cd
        from aresx.fusion.types import Evidence, Domain
        t = time.time()
        geo = [Evidence(entity_id="E", source_tool="geoint", attribute="observed_at",
                        value="47.640,-122.130", domain=Domain.GEOINT, collected_at=t)]
        fin = [Evidence(entity_id="E", source_tool="finint", attribute="transaction_location",
                        value="47.641,-122.131", domain=Domain.FININT, collected_at=t + 60)]
        matches = cd.geo_finint_match(geo, fin)
        self.assertEqual(len(matches), 1)
        self.assertGreater(matches[0][2], 0.5)

    # ──────────────────────────────────────────────────────────
    # explainability
    # ──────────────────────────────────────────────────────────

    def test_17_explanation_includes_key_facts(self):
        from aresx.fusion import explainability as expl
        from aresx.fusion.types import Evidence, Domain
        ev = [
            Evidence(entity_id="E", source_tool="opencorporates", attribute="x",
                     value="Y", domain=Domain.OSINT),
            Evidence(entity_id="E", source_tool="crt_sh", attribute="x",
                     value="Y", domain=Domain.OSINT),
        ]
        breakdown = {
            "final": 0.87, "base": 0.85, "bonus": 0.10, "penalty": 0.08,
            "support_count": 2, "unique_sources": 2, "contradiction_count": 1,
        }
        text = expl.explain("Y", ev, [], breakdown)
        self.assertIn("87%", text)
        self.assertIn("opencorporates", text)

    # ──────────────────────────────────────────────────────────
    # END-TO-END: ENGINE — THE MICROSOFT TEST
    # ──────────────────────────────────────────────────────────

    def test_18_engine_buffer_persist(self):
        import aresx.fusion.engine as eng_mod
        from aresx.fusion.types import Evidence, Domain
        e = eng_mod.FusionEngine()
        e.add_evidence(Evidence(
            entity_id="test_entity_18",
            source_tool="t",
            attribute="a",
            value="v",
            domain=Domain.OSINT,
        ))
        buf = e.get_buffer("test_entity_18")
        self.assertEqual(len(buf), 1)
        self.assertEqual(buf[0].attribute, "a")
        self.assertEqual(buf[0].domain, Domain.OSINT)

    def test_19_engine_trigger_on_3_pieces(self):
        import aresx.fusion.engine as eng_mod
        from aresx.fusion.types import Evidence, Domain
        e = eng_mod.FusionEngine()
        for i in range(3):
            e.add_evidence(Evidence(
                entity_id="entity_trigger_19",
                source_tool=f"src_{i}",
                attribute="founded_year",
                value="1999",
                domain=Domain.OSINT,
            ))
        pending = e.entities_pending_fusion()
        ids = {p[0] for p in pending}
        self.assertIn("entity_trigger_19", ids)

    def test_20_microsoft_acceptance(self):
        """
        THE Phase 2 acceptance test from the Build Prompt:

            5 OSINT + 1 SIGINT + 1 FININT  →  confidence ≥ 0.85
            7 buffer rows, 3 distinct domains, source reliability seeded.
        """
        import aresx.fusion.engine as eng_mod
        from aresx.fusion import source_reliability as sr
        from aresx.fusion.types import Evidence, Domain

        engine = eng_mod.FusionEngine()
        t = time.time()

        # 5 OSINT — all agreeing on Microsoft's HQ
        osint_sources = ["opencorporates", "crt_sh", "whois", "shodan", "censys"]
        for src in osint_sources:
            engine.add_evidence(Evidence(
                entity_id="Microsoft",
                source_tool=src,
                attribute="headquarters",
                value="Redmond, WA",
                domain=Domain.OSINT,
                collected_at=t,
            ))

        # 1 SIGINT — device seen at Microsoft HQ coordinates
        engine.add_evidence(Evidence(
            entity_id="Microsoft",
            source_tool="device_signal_intel",
            attribute="device_seen_at",
            value="47.640,-122.130",
            domain=Domain.SIGINT,
            collected_at=t,
        ))

        # 1 FININT — corporate record matches
        engine.add_evidence(Evidence(
            entity_id="Microsoft",
            source_tool="sec_edgar",
            attribute="headquarters",
            value="Redmond, WA",
            domain=Domain.FININT,
            collected_at=t,
        ))

        # Verify buffer count
        buf = engine.get_buffer("Microsoft")
        self.assertEqual(len(buf), 7, f"expected 7 pieces in buffer, got {len(buf)}")

        # Verify 3 distinct domains
        domains_seen = {e.domain for e in buf}
        self.assertEqual(domains_seen, {Domain.OSINT, Domain.SIGINT, Domain.FININT})

        # Verify reliability scores stored for all source types
        for src in osint_sources + ["device_signal_intel", "sec_edgar"]:
            score = sr.get_reliability(src)
            self.assertGreater(score, 0.0)
            self.assertLessEqual(score, 1.0)

        # Run fusion
        assertions = engine.fuse("Microsoft")

        # Find the headquarters assertion (most-supported)
        hq_assertion = next(
            (a for a in assertions if a.attribute == "headquarters"), None,
        )
        self.assertIsNotNone(hq_assertion, "expected a headquarters assertion")
        self.assertEqual(hq_assertion.value, "Redmond, WA")
        self.assertGreaterEqual(
            hq_assertion.confidence, 0.85,
            f"acceptance criterion failed: confidence={hq_assertion.confidence:.4f}, "
            f"explanation={hq_assertion.explanation}",
        )

        # Buffer should now be marked consumed
        buf_after = engine.get_buffer("Microsoft", include_consumed=False)
        self.assertEqual(len(buf_after), 0, "buffer should be drained after fusion")
        buf_all = engine.get_buffer("Microsoft", include_consumed=True)
        self.assertEqual(len(buf_all), 7, "consumed evidence should still be inspectable")

        # FUSION_COMPLETE event should have been published — verify by checking
        # the audit log (every published event goes through the audit hook).
        from aresx.storage import db
        audit_row = db.query_one(
            "SELECT action FROM audit_log_v2 "
            "WHERE action = 'fusion.complete' "
            "  AND resource = 'Microsoft' "
            "ORDER BY sequence_num DESC LIMIT 1"
        )
        self.assertIsNotNone(audit_row,
            "FUSION_COMPLETE event should have been audited")
        self.assertEqual(audit_row["action"], "fusion.complete")


if __name__ == "__main__":
    unittest.main(verbosity=2)
