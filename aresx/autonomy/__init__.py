"""aresx.autonomy — TITAN Phase 4 + Phase 12: Autonomous Agents (full TRD module roster)"""
from aresx.autonomy.commander import launch_mission
from aresx.autonomy.threat_responder import (
    respond_to_alert, agentic_threat_response,
    classify_threat, load_playbook, ThreatResponseResult, ALERT_SEVERITY_THRESHOLD,
)
from aresx.autonomy.collection_manager import (
    collect_entity, get_recommended_tools, CollectionResult,
)
from aresx.autonomy.autonomy_modules import (
    write_report, export_report_markdown, IntelligenceReport,
    monitoring_agent, MonitoringAgent,
    triage_alert, batch_triage, TriagedAlert,
    prioritize_items, PriorityItem,
    goal_executor, GoalExecutor, GoalExecution,
)
PHASE_STATUS = "implemented"
