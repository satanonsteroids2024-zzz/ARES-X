# red_module/core/red_orchestrator.py
"""
ARES X - Red Module Orchestrator
Phase 13 Hollow Purple - Safe Red Layer
Coordinates recon, intel, and simulation agents. Contains NO
authorization/ROE logic of its own — every authorization decision is
made by an aresx.red.roe.AuthorizationManager, held here as self.auth
and called directly. Callers that need to open/check an authorization
window call self.auth.open_window(...) / self.auth.status() etc.
directly — there are no same-named pass-through methods on this class
for that (previously there were; removed so aresx/red/roe.py is the
only file with any authorization-related code in it).
"""

import uuid
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from aresx.red.roe import AuthorizationManager, get_shared_authorization


class RedOrchestrator:
    def __init__(self, config_path: str = "config/roe.json",
                 confirm_fn: Optional[Callable[[str], bool]] = None,
                 auth: Optional[AuthorizationManager] = None):
        """
        Args:
            config_path: only used if `auth` is not provided — passed to
                get_shared_authorization() to build/fetch the process-wide
                AuthorizationManager. Ignored if `auth` is given directly.
            confirm_fn: only used if `auth` is not provided and no shared
                instance exists yet. To customize confirm_fn on an
                already-existing shared manager, construct your own
                AuthorizationManager and pass it as `auth` instead.
            auth: an existing AuthorizationManager to use. Defaults to
                the process-wide shared instance (see
                aresx.red.roe.get_shared_authorization) so authorization
                state is visible across every RedOrchestrator instance
                and every other caller in the same process, unless you
                explicitly want an isolated one (e.g. in tests).
        """
        self.active_missions: Dict = {}
        self.agents: Dict = {}
        self.auth: AuthorizationManager = auth or get_shared_authorization(config_path)

    def register_agent(self, name: str, agent_instance: Any) -> None:
        """Register a red agent by name."""
        self.agents[name] = agent_instance

    # ── Mission lifecycle ────────────────────────────────────────────────

    async def start_mission(
        self,
        mission_type: str,
        target: Dict,
        roe_override: Optional[Dict] = None,
    ) -> str:
        """
        Start a red mission. Authorization is decided entirely by
        self.auth.authorize() — raises ValueError if the target isn't
        authorized (pre-approved list, session memory, active window,
        or a live y/n decline). See aresx.red.roe for the decision logic.
        """
        self.auth.authorize(mission_type, target, roe_override)

        window_active = self.auth.window_covers(target)
        target_label = target.get("domain") or target.get("ip") or "unknown target"

        mission_id = f"red_{mission_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        self.active_missions[mission_id] = {
            "status":     "running",
            "type":       mission_type,
            "target":     target,
            "start_time": datetime.now().isoformat(),
            "findings":   [],
            "agent_logs": [],
            "auth_window_case": self.auth.current_case_id if window_active else None,
        }

        print(f"[ARES RED] Mission {mission_id} started for {target_label}"
              + (f" (window: {self.auth.current_case_id})" if window_active else ""))

        # Route to registered agent
        if mission_type == "recon" and "recon" in self.agents:
            findings = await self.agents["recon"].execute(target)
            self.active_missions[mission_id]["findings"].extend(findings)

        self.active_missions[mission_id]["status"] = "completed"
        return mission_id

    def get_mission_status(self, mission_id: str) -> Dict:
        return self.active_missions.get(mission_id, {"status": "not_found"})

    def list_missions(self) -> List[Dict]:
        return [
            {"id": mid, "status": m["status"], "type": m["type"],
             "target": m["target"], "finding_count": len(m["findings"])}
            for mid, m in self.active_missions.items()
        ]
