"""aresx.ui — TITAN Phase 8: Qt6 Mission Control UI (6-panel + 2 auxiliary panels)"""
from aresx.ui.mission_control_ui import (
    MissionControlUI, mission_control_ui,
    MissionQueuePanel, LiveOpsDashboard, TwinViewerPanel,
    SimulationPanel, DecisionPanel, WatchlistPanel,
    EvidenceVaultUI, BriefPanel,
    _QT6 as QT6_AVAILABLE,
)
PHASE_STATUS = "implemented"
__all__ = [
    "MissionControlUI","mission_control_ui",
    "MissionQueuePanel","LiveOpsDashboard","TwinViewerPanel",
    "SimulationPanel","DecisionPanel","WatchlistPanel",
    "EvidenceVaultUI","BriefPanel","QT6_AVAILABLE","PHASE_STATUS",
]
