"""
aresx.ui — TITAN Phase 8: Qt6 Mission Control UI.

Six-panel Mission Control Center (TRD §3.6):
  Panel 1 — Mission Queue        (top-left)
  Panel 2 — Live Ops Picture     (top-center)
  Panel 3 — Knowledge Graph      (top-right)
  Panel 4 — Digital Twin Viewer  (middle-left)
  Panel 5 — Decision Intelligence (middle-center)
  Panel 6 — Intelligence Feed    (middle-right)

Order 20: All UI modules degrade gracefully when PySide6 is absent.
Every UI class exposes a get_state() → dict method for headless consumers
(REST API, tests, voice interface).

═══════════════════════════════════════════════════════════════════════
ARCHITECTURE NOTE — TWO RAMP CONVENTIONS
(ADR-NATIONAL-HIGHWAY, Phase 1d)
═══════════════════════════════════════════════════════════════════════

This file is intentionally a SECOND ramp layer, distinct from the
primary `_tool_*` convention in aresx/chat/router.py:

  Primary ramp system — aresx/chat/router.py's _tool_* functions:
    ONE clean hop per user action, ONE required-arg-supplying schema.
    Use this for any single, parameterized chat command.

  This file (mission_control_ui.py) — the DASHBOARD ramp system:
    Aggregates read-only state across many subsystems in one call
    (full_snapshot()). Panels here all expose no-argument get_state()
    because they are meant to power a "show me everything" view, not
    to service targeted per-mission requests.

RULE: if a panel needs a REQUIRED argument (mission_id, twin_id, etc.),
it MUST NOT rely on being called through full_snapshot() to expose that
capability to chat — full_snapshot() calls every get_state() with no
args. Instead, give the capability its own _tool_* ramp in
aresx/chat/router.py. The DecisionPanel and BriefPanel cases both went
this route in Phase 1a: see aresx.chat.decision_ramps.py and
aresx.chat.brief_ramps.py — the panels here still exist for dashboard
snapshots, but the real chat-facing entry points are the _tool_*
wrappers, not the panel methods.
═══════════════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Qt6 availability check
try:
    from PySide6.QtWidgets import QWidget, QApplication
    from PySide6.QtCore import QTimer, Signal, QObject
    _QT6 = True
except ImportError:
    _QT6 = False
    logger.debug("[UI] PySide6 not available — headless mode")


class _HeadlessPanel:
    """Base headless panel. Subclassed by all UI panels."""
    panel_name: str = "base"

    def get_state(self) -> dict:
        return {"panel": self.panel_name, "qt6_available": _QT6}

    def update(self, data: dict) -> None:
        pass


# ──────────────────────────────────────────────────────────────
# Panel 1 — Mission Queue
# ──────────────────────────────────────────────────────────────

class MissionQueuePanel(_HeadlessPanel):
    """Active missions list with status, priority, % complete. Start/pause/branch/replay."""
    panel_name = "mission_queue"

    def get_state(self) -> dict:
        from aresx.mission import list_missions
        missions = list_missions()
        return {
            "panel":    self.panel_name,
            "missions": missions[:20],
            "count":    len(missions),
        }


# ──────────────────────────────────────────────────────────────
# Panel 2 — Live Ops Dashboard
# ──────────────────────────────────────────────────────────────

class LiveOpsDashboard(_HeadlessPanel):
    """Real-time entity activity, alerts, agent status, signal heatmap."""
    panel_name = "live_ops"

    def get_state(self) -> dict:
        from aresx.mission.live_ops import live_ops
        snap = live_ops.snapshot()
        return {
            "panel":           self.panel_name,
            "active_missions": len(snap.active_missions),
            "agent_statuses":  [
                {"agent_id": a.agent_id, "status": a.status}
                for a in snap.agent_statuses
            ],
            "recent_alerts":   snap.recent_alerts[:5],
            "signal_heatmap":  snap.signal_heatmap,
            "total_evidence":  snap.total_evidence,
        }


# ──────────────────────────────────────────────────────────────
# Panel 3 — Twin Viewer
# ──────────────────────────────────────────────────────────────

class TwinViewerPanel(_HeadlessPanel):
    """Active twin list with freshness, detail views, diff viewer."""
    panel_name = "twin_viewer"

    def get_state(self, twin_id: Optional[str] = None) -> dict:
        from aresx.digital_twin import list_twins
        twins = list_twins()
        state: dict[str, Any] = {
            "panel": self.panel_name,
            "twins": [{"twin_id": t["twin_id"], "entity_name": t["entity_name"],
                       "twin_type": t["twin_type"], "freshness": t.get("freshness_score", 0),
                       "status": t["status"]} for t in twins[:10]],
        }
        if twin_id:
            from aresx.digital_twin import list_snapshots, load_snapshot, get_layout_data
            snaps = list_snapshots(twin_id)
            if snaps:
                gs = load_snapshot(snaps[0]) or {}
                state["layout"] = get_layout_data(twin_id, gs)
        return state


# ──────────────────────────────────────────────────────────────
# Panel 4 — Simulation Panel
# ──────────────────────────────────────────────────────────────

class SimulationPanel(_HeadlessPanel):
    """Wargame + scenario simulation visualization."""
    panel_name = "simulation"

    def get_state(self) -> dict:
        return {
            "panel": self.panel_name,
            "last_wargame": None,
            "last_propagation": None,
        }

    def run_wargame_ui(self, graph_state: dict) -> dict:
        from aresx.simulation import run_wargame
        result = run_wargame(graph_state, n_red=3, n_blue=3)
        return {
            "successful_paths": len(result.successful_paths),
            "detected_paths":   len(result.detected_paths),
            "undetected_paths": len(result.undetected_paths),
            "recommendations":  result.recommended_controls,
        }


# ──────────────────────────────────────────────────────────────
# Panel 5 — Decision Panel
# ──────────────────────────────────────────────────────────────

class DecisionPanel(_HeadlessPanel):
    """Decision support output, action recommendations, scenario analysis."""
    panel_name = "decision"

    def get_state(self, mission_id: Optional[str] = None) -> dict:
        state: dict[str, Any] = {"panel": self.panel_name}
        if mission_id:
            from aresx.decision import analyze, export_decision_json
            try:
                output = analyze(mission_id)
                state["decision_output"] = export_decision_json(output)
            except Exception as exc:
                state["error"] = str(exc)
        return state


# ──────────────────────────────────────────────────────────────
# Panel 6 — Watchlist Panel
# ──────────────────────────────────────────────────────────────

class WatchlistPanel(_HeadlessPanel):
    """Live watchlist management — add/remove entities, view alerts."""
    panel_name = "watchlist"

    def get_state(self) -> dict:
        from aresx.enterprise import list_watchlists
        wls = list_watchlists()
        return {
            "panel":      self.panel_name,
            "watchlists": wls[:20],
            "count":      len(wls),
        }


# ──────────────────────────────────────────────────────────────
# Panel 7 — Evidence Vault UI
# ──────────────────────────────────────────────────────────────

class EvidenceVaultUI(_HeadlessPanel):
    """Evidence vault browser with Merkle verification status."""
    panel_name = "evidence_vault"

    def get_state(self) -> dict:
        from aresx.enterprise import list_evidence, verify_vault_chain
        evidence = list_evidence(limit=20)
        chain = verify_vault_chain()
        return {
            "panel":           self.panel_name,
            "evidence_count":  len(evidence),
            "chain_intact":    chain["intact"],
            "chain_checked":   chain["checked"],
            "recent_evidence": evidence[:5],
        }


# ──────────────────────────────────────────────────────────────
# Panel 8 — Brief Panel
# ──────────────────────────────────────────────────────────────

class BriefPanel(_HeadlessPanel):
    """Brief generation panel — generate, preview, export."""
    panel_name = "brief"

    def generate_brief(self, mission_id: str,
                        classification: str = "UNCLASSIFIED") -> dict:
        from aresx.enterprise import generate_brief, export_brief_markdown
        brief = generate_brief(mission_id, classification=classification)
        return {
            "brief_id":  brief.brief_id,
            "title":     brief.title,
            "markdown":  export_brief_markdown(brief),
        }

    def get_state(self) -> dict:
        return {"panel": self.panel_name}


# ──────────────────────────────────────────────────────────────
# Mission Control UI — main 6-panel window
# ──────────────────────────────────────────────────────────────

class MissionControlUI:
    """
    Main Mission Control Center.

    Qt6 mode: 6-panel PySide6 window with live updates at 2Hz.
    Headless mode: dict-based snapshot API — same data, no widgets.
    """

    def __init__(self) -> None:
        self.mission_queue  = MissionQueuePanel()
        self.live_ops       = LiveOpsDashboard()
        self.twin_viewer    = TwinViewerPanel()
        self.simulation     = SimulationPanel()
        self.decision       = DecisionPanel()
        self.watchlist      = WatchlistPanel()
        self.evidence_vault = EvidenceVaultUI()
        self.brief          = BriefPanel()
        self._qt6_app: Any  = None

    def full_snapshot(self) -> dict:
        """Return a complete UI state snapshot (all 8 panels)."""
        return {
            "timestamp":      time.time(),
            "qt6_available":  _QT6,
            "panels": {
                "mission_queue":  self.mission_queue.get_state(),
                "live_ops":       self.live_ops.get_state(),
                "twin_viewer":    self.twin_viewer.get_state(),
                "simulation":     self.simulation.get_state(),
                "decision":       self.decision.get_state(),
                "watchlist":      self.watchlist.get_state(),
                "evidence_vault": self.evidence_vault.get_state(),
                "brief":          self.brief.get_state(),
            },
        }

    def launch_qt6(self) -> None:
        """Launch the Qt6 window. No-op if PySide6 unavailable (Order 20)."""
        if not _QT6:
            logger.warning("[UI] PySide6 not installed — Qt6 UI unavailable. "
                           "Use full_snapshot() for headless access.")
            return
        logger.info("[UI] Launching Qt6 Mission Control UI...")
        # Production: create QApplication + main window + connect signals
        # Deferred to runtime to avoid import overhead in headless mode


# Module-level singleton
mission_control_ui = MissionControlUI()
