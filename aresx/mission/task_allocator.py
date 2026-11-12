"""
aresx.mission.task_allocator — Dynamic Task Allocation.

Monitors agent load (tasks queued / active per agent).
Rebalances: if agent A has 5 queued and agent B is idle, moves
lowest-priority task to B — but only if B has the required capability.

Build Prompt §3 Phase 4, TRD §1.2 mission/.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Agent capability registry — which agents can handle which task types
AGENT_CAPABILITIES: dict[str, set[str]] = {
    "vision_agent":       {"screen_capture", "image_analysis", "ocr"},
    "osint_agent":        {"osint", "domain_enum", "whois", "crt_sh", "shodan"},
    "network_agent":      {"network_scan", "dns", "port_scan", "asn"},
    "social_agent":       {"social_media", "linkedin", "twitter", "person_osint"},
    "document_agent":     {"document_parse", "pdf_extract", "docx_parse", "finint"},
    "code_agent":         {"code_analysis", "decompile", "malware_static"},
    "research_agent":     {"research", "synthesis", "rag_query", "federated_search"},
    "briefing_agent":     {"brief_generate", "report_write", "summary"},
    "sigint_agent":       {"sigint", "wifi_probe", "ble_scan", "packet_capture"},
    "counter_intel_agent":{"counter_intel", "anomaly_detect", "tscm"},
    "predictive_agent":   {"predict", "timeseries", "risk_score"},
    "graph_agent":        {"graph_query", "graph_analysis", "kuzu"},
    "twin_agent":         {"twin_build", "twin_refresh", "twin_query"},
    "mission_commander":  {"mission_planning", "goal_decompose", "coordinate"},
}

REBALANCE_THRESHOLD: int = 3   # queue depth that triggers rebalance


@dataclass
class Task:
    task_id:      str
    mission_id:   str
    objective_id: str
    task_type:    str
    priority:     int = 5       # 1 (highest) → 10 (lowest)
    assigned_to:  Optional[str] = None
    status:       str = "queued"


@dataclass
class AllocationPlan:
    task_id:      str
    from_agent:   Optional[str]
    to_agent:     str
    reason:       str


class TaskAllocator:
    """
    Stateful task allocator. In production this coordinates with Celery/Redis.
    In standalone mode it manages an in-process queue per agent.
    """

    def __init__(self) -> None:
        self._queues: dict[str, list[Task]] = {
            aid: [] for aid in AGENT_CAPABILITIES
        }

    def assign(self, task: Task) -> Optional[str]:
        """
        Assign a task to the best available agent.
        Returns agent_id or None if no capable agent available.
        """
        capable = [
            aid for aid, caps in AGENT_CAPABILITIES.items()
            if task.task_type in caps
        ]
        if not capable:
            logger.warning("[TaskAllocator] No agent capable of %s", task.task_type)
            return None

        # Pick the agent with the shortest queue among capable agents
        best = min(capable, key=lambda aid: len(self._queues[aid]))
        task.assigned_to = best
        task.status = "assigned"
        self._queues[best].append(task)
        logger.debug("[TaskAllocator] %s → %s (queue depth %d)",
                     task.task_id[:8], best, len(self._queues[best]))
        return best

    def rebalance(self) -> list[AllocationPlan]:
        """
        Check all agent queues. If any agent has depth ≥ REBALANCE_THRESHOLD
        and another capable agent is idle, move the lowest-priority task.
        Returns list of moves made.
        """
        moves: list[AllocationPlan] = []
        for overloaded, queue in self._queues.items():
            if len(queue) < REBALANCE_THRESHOLD:
                continue
            # Find the lowest-priority queued task
            pending = [t for t in queue if t.status == "queued"]
            if not pending:
                continue
            lowest = max(pending, key=lambda t: t.priority)

            # Find an idle capable agent
            idle = [
                aid for aid, caps in AGENT_CAPABILITIES.items()
                if lowest.task_type in caps
                and aid != overloaded
                and len(self._queues[aid]) == 0
            ]
            if not idle:
                continue

            target = idle[0]
            self._queues[overloaded].remove(lowest)
            lowest.assigned_to = target
            self._queues[target].append(lowest)
            plan = AllocationPlan(
                task_id=lowest.task_id,
                from_agent=overloaded,
                to_agent=target,
                reason=f"queue depth {len(self._queues[overloaded]) + 1} ≥ {REBALANCE_THRESHOLD}",
            )
            moves.append(plan)
            logger.info("[TaskAllocator] Rebalanced %s: %s → %s",
                        lowest.task_id[:8], overloaded, target)

        return moves

    def queue_depths(self) -> dict[str, int]:
        return {aid: len(q) for aid, q in self._queues.items()}

    def complete_task(self, task_id: str, agent_id: str) -> bool:
        queue = self._queues.get(agent_id, [])
        for t in queue:
            if t.task_id == task_id:
                t.status = "complete"
                queue.remove(t)
                return True
        return False


task_allocator = TaskAllocator()
