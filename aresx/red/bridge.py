# aresx/red/bridge.py
"""
ARES X v8 — Red Module Audit Bridge (Phase 13 integration)
======================================================
Wires RedOrchestrator into the v8 audited event bus, matching how
every other v8 subsystem (fusion, sovereign_ai, threat_response)
reports through aresx.events.bus rather than operating silently.

This is a thin wrapper — it does NOT change or duplicate any
authorization/ROE logic (that lives entirely in
aresx.red.roe.AuthorizationManager; RedOrchestrator holds one as
self.auth and this class calls it directly, the same as any other
caller — see open_auth_window/close_auth_window below). It only
ensures every mission start/decline/complete, and every authorization
window opened/closed, is audited the same way Order 27 (audit chain)
already requires for the rest of v8.

Usage:
    from aresx.red.bridge import AuditedRedOrchestrator

    red = AuditedRedOrchestrator(config_path="config/roe.json")
    mission_id = await red.start_mission("recon", target={"domain": "example.com"})

    # Opening/closing authorization windows goes through self.auth
    # directly (there's no open_auth_window/close_auth_window method
    # on RedOrchestrator itself) — this class provides audited
    # convenience wrappers for exactly that:
    red.open_auth_window("case-1", "operator", duration_hours=4)
    red.close_auth_window()
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from aresx.events import bus, EventType
from aresx.red.orchestrator import RedOrchestrator


class AuditedRedOrchestrator(RedOrchestrator):
    """
    Same as RedOrchestrator, except every mission lifecycle event —
    plus every authorization window opened/closed via the convenience
    methods below — also publishes onto the v8 event bus, which means
    it flows into the same audit chain (Order 27) as fusion,
    sovereign_ai, and threat_response events.

    Authorization decisions themselves are entirely unchanged: these
    methods call self.auth (an aresx.red.roe.AuthorizationManager)
    directly, exactly as any other caller would — this class adds
    audit logging on top, it does not loosen, bypass, or duplicate any
    part of the authorization logic itself.
    """

    def open_auth_window(self, case_id: str, authorized_by: str,
                         duration_hours: float, reason: str = ""):
        """Audited convenience wrapper around self.auth.open_window()."""
        window = self.auth.open_window(case_id, authorized_by, duration_hours, reason)
        bus.publish_sync(
            EventType.RED_AUTH_WINDOW_OPENED,
            payload=window.to_dict(),
            source="red_module",
        )
        return window

    def close_auth_window(self) -> None:
        """Audited convenience wrapper around self.auth.close_window()."""
        status = self.auth.status()
        case_id = status["window"]["case_id"] if status.get("window") else None
        self.auth.close_window()
        if case_id:
            bus.publish_sync(
                EventType.RED_AUTH_WINDOW_CLOSED,
                payload={"case_id": case_id, "closed_at": None},
                source="red_module",
            )

    async def start_mission(
        self,
        mission_type: str,
        target: Dict,
        roe_override: Optional[Dict] = None,
    ) -> str:
        try:
            mission_id = await super().start_mission(mission_type, target, roe_override)
        except ValueError as declined:
            # Operator said no (or something else raised) — audit the
            # decline, then re-raise so the caller still sees the same
            # hard failure as before.
            bus.publish_sync(
                EventType.RED_MISSION_BLOCKED,
                payload={
                    "mission_type": mission_type,
                    "target": target,
                    "reason": str(declined),
                },
                source="red_module",
            )
            raise


        bus.publish_sync(
            EventType.RED_MISSION_STARTED,
            payload={
                "mission_id": mission_id,
                "mission_type": mission_type,
                "target": target,
            },
            source="red_module",
        )
        return mission_id

    def complete_mission(self, mission_id: str, result: Dict[str, Any]) -> None:
        """Call when a mission wraps up — audits completion + result summary."""
        if mission_id in self.active_missions:
            self.active_missions[mission_id]["status"] = "complete"

        bus.publish_sync(
            EventType.RED_MISSION_COMPLETE,
            payload={"mission_id": mission_id, "result": result},
            source="red_module",
        )

    def log_recon_finding(self, mission_id: str, finding: Dict[str, Any]) -> None:
        """Call from ReconAgent output — audits each finding as it's produced."""
        bus.publish_sync(
            EventType.RED_RECON_FINDING,
            payload={"mission_id": mission_id, "finding": finding},
            source="red_module",
        )


__all__ = ["AuditedRedOrchestrator"]


