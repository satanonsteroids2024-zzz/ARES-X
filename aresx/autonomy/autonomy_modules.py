"""
aresx.autonomy — Remaining autonomy sub-modules.
  report_writer.py  — Autonomous Report Writer
  monitoring_agent.py — Persistent background monitoring
  alert_triage.py   — Alert Triage Engine
  prioritizer.py    — Autonomous Prioritization Engine
  goal_executor.py  — Goal-Based Mission Execution
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from aresx.events import EventType, bus

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
# REPORT WRITER
# ══════════════════════════════════════════════════════════════

@dataclass
class IntelligenceReport:
    report_id:    str = field(default_factory=lambda: str(uuid.uuid4()))
    mission_id:   str = ""
    title:        str = ""
    classification: str = "UNCLASSIFIED"
    executive_summary: str = ""
    key_findings: list[str] = field(default_factory=list)
    decision_output: Optional[dict] = None
    recommendations: list[str] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)
    format:       str = "markdown"


def write_report(mission_id: str, classification: str = "UNCLASSIFIED") -> IntelligenceReport:
    """
    Autonomous report writer. Synthesizes investigation findings into
    a structured intelligence report. Uses the decision support framework
    for the analysis layer.

    Voice trigger: "ARES, generate report for mission [X]"
    """
    from aresx.mission.mission_control import get_mission, get_objectives
    from aresx.decision.decision_support import analyze, export_decision_json

    mission = get_mission(mission_id) or {}
    objs = get_objectives(mission_id)
    completed = [o for o in objs if o["status"] == "complete"]
    evidence_total = sum(int(o.get("evidence_count") or 0) for o in completed)

    # Run decision support
    try:
        dss = analyze(mission_id)
        dss_dict = export_decision_json(dss)
    except Exception:
        dss_dict = {}

    key_findings = [o["description"] for o in completed[:8]]
    recommendations = []
    if dss_dict:
        for a in dss_dict.get("what_to_do", {}).get("actions", [])[:3]:
            recommendations.append(a.get("action", ""))

    report = IntelligenceReport(
        mission_id=mission_id,
        title=f"Intelligence Report: {mission.get('goal', 'Investigation')[:60]}",
        classification=classification,
        executive_summary=(
            f"Autonomous investigation completed with {len(completed)}/{len(objs)} objectives "
            f"and {evidence_total} evidence pieces collected. "
            f"{dss_dict.get('what_happened', {}).get('summary', '')}"
        ),
        key_findings=key_findings,
        decision_output=dss_dict,
        recommendations=[r for r in recommendations if r],
    )
    bus.publish_sync(
        EventType.BRIEF_GENERATED,
        payload={"report_id": report.report_id, "mission_id": mission_id},
        source="autonomy.report_writer",
        correlation_id=mission_id,
    )
    return report


def export_report_markdown(report: IntelligenceReport) -> str:
    lines = [
        f"# {report.title}",
        f"**Classification:** {report.classification}",
        f"**Report ID:** {report.report_id}",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(report.generated_at))}",
        "",
        "## Executive Summary",
        report.executive_summary,
        "",
        "## Key Findings",
    ]
    for i, f in enumerate(report.key_findings, 1):
        lines.append(f"{i}. {f}")
    if report.recommendations:
        lines += ["", "## Recommendations"]
        for i, r in enumerate(report.recommendations, 1):
            lines.append(f"{i}. {r}")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
# MONITORING AGENT
# ══════════════════════════════════════════════════════════════

class MonitoringAgent:
    """
    Persistent background monitoring agent. Watches active watchlists,
    checks for new entity changes, fires WATCHLIST_ALERT when threshold crossed.
    Runs in a background asyncio task.
    """

    def __init__(self) -> None:
        self._running = False
        self._check_interval_s = 300.0    # 5 minutes default

    async def run(self) -> None:
        """Main monitoring loop. Call as asyncio.create_task(agent.run())."""
        self._running = True
        logger.info("[MonitoringAgent] Started background monitoring")
        while self._running:
            try:
                await self._check_watchlists()
            except Exception as exc:
                logger.error("[MonitoringAgent] Error: %s", exc)
            await asyncio.sleep(self._check_interval_s)

    async def _check_watchlists(self) -> None:
        """Check all active watchlists for changes."""
        from aresx.enterprise.enterprise_layer import (
            list_watchlists, score_watchlist_entity,
        )
        active = list_watchlists(status="active")
        for wl in active:
            wid = wl["watchlist_id"]
            # Simulate a check (real: run OSINT tools against wl["query"])
            change_score = 0.0   # no change by default
            if change_score >= float(wl.get("alert_threshold", 0.3)):
                score_watchlist_entity(wid, "automated_check", change_score)
        logger.debug("[MonitoringAgent] Checked %d watchlists", len(active))

    def stop(self) -> None:
        self._running = False


monitoring_agent = MonitoringAgent()


# ══════════════════════════════════════════════════════════════
# ALERT TRIAGE
# ══════════════════════════════════════════════════════════════

@dataclass
class TriagedAlert:
    alert_id:     str = field(default_factory=lambda: str(uuid.uuid4()))
    source:       str = ""
    severity:     float = 0.0
    triage_score: float = 0.0
    priority:     str = "low"
    assigned_to:  str = "analyst"
    action:       str = "monitor"


def triage_alert(alert_payload: dict) -> TriagedAlert:
    """
    Score and prioritize an incoming alert.
    Assigns priority and recommended action automatically.
    """
    severity = float(alert_payload.get("change_score", 0))
    source = alert_payload.get("name", "unknown")

    # Triage score: weighted combination
    triage_score = severity * 0.7 + min(1.0, len(str(alert_payload)) / 500) * 0.3

    if triage_score >= 0.8:
        priority = "critical"
        action = "immediate_response"
        assigned_to = "incident_response"
    elif triage_score >= 0.6:
        priority = "high"
        action = "escalate"
        assigned_to = "senior_analyst"
    elif triage_score >= 0.4:
        priority = "medium"
        action = "investigate"
        assigned_to = "analyst"
    else:
        priority = "low"
        action = "monitor"
        assigned_to = "automated"

    return TriagedAlert(
        source=source,
        severity=severity,
        triage_score=round(triage_score, 3),
        priority=priority,
        assigned_to=assigned_to,
        action=action,
    )


def batch_triage(alerts: list[dict]) -> list[TriagedAlert]:
    """Triage a batch of alerts and return sorted by triage_score descending."""
    triaged = [triage_alert(a) for a in alerts]
    triaged.sort(key=lambda t: t.triage_score, reverse=True)
    return triaged


# ══════════════════════════════════════════════════════════════
# PRIORITIZER
# ══════════════════════════════════════════════════════════════

@dataclass
class PriorityItem:
    item_id:   str
    item_type: str    # mission | entity | alert | objective
    score:     float  # higher = higher priority
    reason:    str


def prioritize_items(items: list[dict], item_type: str = "entity") -> list[PriorityItem]:
    """
    Autonomous Prioritization Engine. Scores items by:
      • Evidence freshness (recency bonus)
      • Risk score (from fusion assertions or watchlist)
      • Strategic importance (based on entity type)
    Returns sorted list, highest priority first.
    """
    scored: list[PriorityItem] = []
    for item in items:
        iid = item.get("id") or item.get("mission_id") or item.get("entity_id", str(uuid.uuid4()))
        risk = float(item.get("risk_score", 0) or item.get("change_score", 0))
        recency = float(item.get("freshness_score", 1.0))
        strategic = {"Organization": 0.8, "ThreatActor": 1.0, "IP": 0.6}.get(
            item.get("entity_type", ""), 0.5
        )
        score = risk * 0.5 + recency * 0.3 + strategic * 0.2
        reason = f"risk={risk:.2f}, freshness={recency:.2f}, strategic={strategic:.2f}"
        scored.append(PriorityItem(item_id=iid, item_type=item_type,
                                    score=round(score, 4), reason=reason))
    scored.sort(key=lambda p: p.score, reverse=True)
    return scored


# ══════════════════════════════════════════════════════════════
# GOAL EXECUTOR
# ══════════════════════════════════════════════════════════════

@dataclass
class GoalExecution:
    goal_id:         str = field(default_factory=lambda: str(uuid.uuid4()))
    goal:            str = ""
    success_criteria: str = ""
    status:          str = "active"
    mission_ids:     list[str] = field(default_factory=list)
    attempts:        int = 0
    max_attempts:    int = 3
    created_at:      float = field(default_factory=time.time)


class GoalExecutor:
    """
    Maintains a goal stack for long-running campaigns. Each goal has
    a success criterion (LLM-evaluated). Escalates to user if goal
    cannot be satisfied within resource budget.
    """

    def __init__(self) -> None:
        self._goal_stack: list[GoalExecution] = []

    def push(self, goal: str, success_criteria: str) -> GoalExecution:
        ge = GoalExecution(goal=goal, success_criteria=success_criteria)
        self._goal_stack.append(ge)
        return ge

    def evaluate_success(self, ge: GoalExecution, evidence_summary: str) -> bool:
        """LLM-evaluate whether goal is satisfied given current evidence."""
        prompt = (
            f"Is the goal '{ge.goal}' satisfied given this evidence?\n"
            f"Success criteria: {ge.success_criteria}\n"
            f"Evidence: {evidence_summary[:400]}\n"
            f"Answer: YES or NO only."
        )
        try:
            from aresx.sovereign_ai import inference_api
            result = inference_api.generate(prompt, task_type="general", max_tokens=5)
            return "yes" in result.lower()
        except Exception:
            return False

    async def execute_goal(self, goal: str, success_criteria: str) -> GoalExecution:
        """Execute a goal by launching missions until criteria met or max_attempts reached."""
        from aresx.autonomy.commander import launch_mission
        ge = self.push(goal, success_criteria)

        while ge.attempts < ge.max_attempts and ge.status == "active":
            ge.attempts += 1
            result = await launch_mission(goal)
            ge.mission_ids.append(result.get("mission_id", ""))

            evidence_summary = f"Mission {ge.attempts}: {result.get('total_evidence', 0)} pieces"
            if self.evaluate_success(ge, evidence_summary):
                ge.status = "complete"
                break

        if ge.status != "complete":
            ge.status = "escalated"
            bus.publish_sync(
                EventType.APPROVAL_GATE_TRIGGERED,
                payload={
                    "goal_id": ge.goal_id,
                    "goal": ge.goal,
                    "reason": f"Goal not satisfied after {ge.max_attempts} attempts",
                },
                source="autonomy.goal_executor",
            )

        return ge

    def get_stack(self) -> list[GoalExecution]:
        return list(self._goal_stack)


goal_executor = GoalExecutor()
