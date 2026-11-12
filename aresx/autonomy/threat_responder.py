"""
ARES X v8.0 — Phase 12: Agentic Threat Response.

Closes the autonomous loop: detect → investigate → recommend → gate → act.

Build Prompt §4 Phase 11 / TRD §10.7:
  • Subscribe to WATCHLIST_ALERT (severity >= 0.7) + anomaly events
  • classify_threat()    — LLM + pattern matching → threat_type
  • load_playbook()      — fetch response playbook from template_library
  • launch_response_mission() — MissionCommander.launch_mission() with playbook
  • APPROVAL_GATE before any external action (Order 25: non-negotiable)
  • Auto-generate threat response summary on mission complete

4 built-in playbooks (spec):
  • new_infrastructure_playbook
  • credential_breach_playbook
  • apt_activity_playbook
  • insider_threat_playbook

Hard limits (always enforced per TRD §10.7):
  1. NEVER takes external action without human approval gate
  2. NEVER modifies target systems (read-only collection only)
  3. NEVER exfiltrates data to external servers
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from aresx.enterprise.enterprise_layer import require_gate, resolve_gate, check_gate
from aresx.events import EventType, bus
from aresx.mission.mission_control import complete_mission, create_mission, get_mission

logger = logging.getLogger(__name__)

# Severity threshold for auto-response (spec: 0.7)
ALERT_SEVERITY_THRESHOLD: float = 0.7

# Max concurrent threat response missions
MAX_CONCURRENT_RESPONSE_MISSIONS: int = 3
_active_response_slots: int = 0

# ──────────────────────────────────────────────────────────────
# Threat classification
# ──────────────────────────────────────────────────────────────

_THREAT_PATTERNS: dict[str, list[str]] = {
    "new_infrastructure": ["new domain", "new ip", "new subdomain", "staging", "infrastructure"],
    "credential_breach":  ["breach", "credential", "password", "leak", "dump", "data exposure"],
    "apt_activity":       ["apt", "advanced persistent", "nation state", "ttp", "mitre", "c2", "command and control"],
    "insider_threat":     ["insider", "behavioral", "anomaly", "employee", "privileged user", "lateral"],
}


def classify_threat(alert_payload: dict) -> str:
    """
    Classify alert into threat_type using pattern matching + LLM fallback.
    Returns one of: new_infrastructure | credential_breach | apt_activity | insider_threat | generic
    """
    text = " ".join([
        str(alert_payload.get("change_type", "")),
        str(alert_payload.get("name", "")),
        str(alert_payload.get("payload", {})),
    ]).lower()

    for threat_type, keywords in _THREAT_PATTERNS.items():
        if any(kw in text for kw in keywords):
            return threat_type

    # LLM fallback (Order 21: route through inference_api)
    try:
        from aresx.sovereign_ai import inference_api
        prompt = (
            f"Classify this security alert into exactly one category: "
            f"new_infrastructure | credential_breach | apt_activity | insider_threat | generic\n\n"
            f"Alert: {text[:300]}\n\nRespond with only the category name."
        )
        result = inference_api.generate(prompt, task_type="general", max_tokens=20)
        for t in _THREAT_PATTERNS:
            if t in result.lower():
                return t
    except Exception:
        pass

    return "generic"


# ──────────────────────────────────────────────────────────────
# Playbooks
# ──────────────────────────────────────────────────────────────

_PLAYBOOKS: dict[str, dict] = {
    "new_infrastructure": {
        "name": "New Infrastructure Response",
        "goal_template": "Collect data on new IP/domain {entity}, assess if malicious, update infra twin, alert if confirmed threat",
        "objectives": [
            "Perform DNS and WHOIS lookup on new infrastructure",
            "Check against threat intelligence feeds (VirusTotal, OTX)",
            "Build or update infra twin for discovered assets",
            "Assess maliciousness and generate risk score",
        ],
        "external_action_required": False,
    },
    "credential_breach": {
        "name": "Credential Breach Response",
        "goal_template": "Find evidence of breach involving {entity}, identify affected credentials, generate remediation steps",
        "objectives": [
            "Search breach databases for entity credentials",
            "Identify affected users and access levels",
            "Correlate with active sessions and recent logins",
            "Generate remediation checklist",
        ],
        "external_action_required": True,   # sharing breach data requires gate
    },
    "apt_activity": {
        "name": "APT Activity Response",
        "goal_template": "Collect TTPs for activity {entity}, match to known threat actors, simulate attack via wargame, recommend defenses",
        "objectives": [
            "Collect TTP indicators from threat intel feeds",
            "Match to MITRE ATT&CK and adversary twin library",
            "Run wargame simulation against current infrastructure twin",
            "Generate prioritized defensive recommendations",
        ],
        "external_action_required": False,
    },
    "insider_threat": {
        "name": "Insider Threat Response",
        "goal_template": "Analyze behavioral anomaly for {entity}, generate timeline, flag for security team review",
        "objectives": [
            "Collect behavioral telemetry for flagged entity",
            "Build timeline of anomalous activities",
            "Compare against baseline behavioral patterns",
            "Generate human-readable anomaly report for security team",
        ],
        "external_action_required": True,   # sending to HR requires gate
    },
    "generic": {
        "name": "Generic Threat Response",
        "goal_template": "Investigate security alert for {entity}: collect evidence, assess risk, recommend response",
        "objectives": [
            "Collect available intelligence on alert entity",
            "Assess severity and impact",
            "Generate response recommendations",
        ],
        "external_action_required": False,
    },
}


def load_playbook(threat_type: str) -> dict:
    """Load a response playbook by threat type. Returns playbook dict."""
    return _PLAYBOOKS.get(threat_type, _PLAYBOOKS["generic"])


# ──────────────────────────────────────────────────────────────
# Threat Response Engine
# ──────────────────────────────────────────────────────────────

@dataclass
class ThreatResponseResult:
    response_id:    str
    alert_payload:  dict
    threat_type:    str
    playbook_name:  str
    mission_id:     Optional[str]
    gate_id:        Optional[str]
    status:         str         # launched | gated | completed | failed
    summary:        str = ""
    started_at:     float = field(default_factory=time.time)
    completed_at:   Optional[float] = None


async def respond_to_alert(alert_payload: dict,
                             severity: float = 0.0) -> Optional[ThreatResponseResult]:
    """
    Main entry point: receive a WATCHLIST_ALERT and launch autonomous response.

    Hard limits enforced:
      • severity must be >= ALERT_SEVERITY_THRESHOLD
      • any external action requires human approval gate (Order 25)
      • read-only collection only — never modifies target systems
      • never exfiltrates data externally
    """
    global _active_response_slots

    effective_severity = severity or float(alert_payload.get("change_score", 0))
    if effective_severity < ALERT_SEVERITY_THRESHOLD:
        logger.debug("[ThreatResponse] Severity %.2f below threshold %.2f — skipping",
                     effective_severity, ALERT_SEVERITY_THRESHOLD)
        return None

    if _active_response_slots >= MAX_CONCURRENT_RESPONSE_MISSIONS:
        logger.warning("[ThreatResponse] Max concurrent response missions reached (%d)",
                       MAX_CONCURRENT_RESPONSE_MISSIONS)
        return None

    _active_response_slots += 1
    response_id = str(uuid.uuid4())

    try:
        return await _run_response(response_id, alert_payload, effective_severity)
    finally:
        _active_response_slots -= 1


async def _run_response(response_id: str, alert_payload: dict,
                         severity: float) -> ThreatResponseResult:
    """Internal response pipeline."""
    # 1. Classify threat
    threat_type = classify_threat(alert_payload)
    playbook = load_playbook(threat_type)
    entity = alert_payload.get("name", "unknown entity")

    bus.publish_sync(
        EventType.THREAT_RESPONSE_STARTED,
        payload={
            "response_id": response_id,
            "threat_type": threat_type,
            "severity":    severity,
            "entity":      entity,
        },
        source="autonomy.threat_responder",
    )

    # 2. Check if external action requires gate BEFORE launching mission
    gate_id: Optional[str] = None
    if playbook["external_action_required"]:
        gate_id = require_gate(
            "THREAT_RESPONSE_EXTERNAL",
            action_payload={
                "threat_type": threat_type,
                "entity":      entity,
                "severity":    severity,
                "playbook":    playbook["name"],
            },
            risk_level="high",
        )
        logger.info("[ThreatResponse] External action gate created: %s", gate_id)

    # 3. Launch autonomous investigation mission (collection is always OK without gate)
    goal = playbook["goal_template"].format(entity=entity)
    from aresx.autonomy.commander import launch_mission
    mission_result = await launch_mission(
        goal=goal,
        name=f"[THREAT RESPONSE] {playbook['name']} — {entity}",
        priority=1,   # highest priority
    )
    mission_id = mission_result.get("mission_id")

    # 4. Generate summary
    completed_objs = mission_result.get("completed", 0)
    total_objs = mission_result.get("objectives", 0)
    evidence = mission_result.get("total_evidence", 0)

    summary = (
        f"Threat response complete for '{entity}' (severity {severity:.2f}). "
        f"Threat type: {threat_type}. "
        f"Mission: {completed_objs}/{total_objs} objectives, {evidence} evidence pieces. "
    )
    if gate_id:
        gate_status = check_gate(gate_id)
        summary += f"External action gate: {gate_status} (gate_id={gate_id[:8]}). "
        if gate_status != "approved":
            summary += "No external action taken pending approval."

    result = ThreatResponseResult(
        response_id=response_id,
        alert_payload=alert_payload,
        threat_type=threat_type,
        playbook_name=playbook["name"],
        mission_id=mission_id,
        gate_id=gate_id,
        status="completed" if mission_result.get("status") == "complete" else "partial",
        summary=summary,
        completed_at=time.time(),
    )

    bus.publish_sync(
        EventType.THREAT_RESPONSE_COMPLETE,
        payload={
            "response_id":  response_id,
            "threat_type":  threat_type,
            "mission_id":   mission_id,
            "status":       result.status,
            "gate_id":      gate_id,
            "summary":      summary[:200],
        },
        source="autonomy.threat_responder",
    )
    logger.info("[ThreatResponse] %s", summary)
    return result


def agentic_threat_response(alert_payload: dict, severity: float = 0.0):
    """Synchronous wrapper for callers without an event loop."""
    return asyncio.run(respond_to_alert(alert_payload, severity))
