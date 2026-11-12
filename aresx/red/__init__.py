"""
ARES X v8 TITAN — Red Module (Phase 13: Hollow Purple)

Offensive intelligence and red team support layer. Covers recon,
vulnerability intelligence, threat actor profiling, IOC handling,
infrastructure pivoting, kill chain mapping, engagement tracking,
CVSS scoring, and pentest report generation.

Does NOT include: exploit code, payload generation, or C2
deployment tooling — those require human expertise, certification,
and signed authorization, and are intentionally out of scope here.

All active-recon functions require explicit target authorization —
wire RedOrchestrator's ROE (Rules of Engagement) validation before
running anything against real infrastructure.
"""

RED_VERSION = "1.0.0"
RED_CODENAME = "Hollow Purple"

# Recon (pure-Python engine)
from aresx.red.recon import (
    full_recon, enumerate_subdomains, port_scan, get_asn_info,
    detect_waf, fingerprint_tech, analyze_security_headers,
    enumerate_s3_buckets, extract_js_endpoints, harvest_emails,
    recon_summary, ReconResult, OpenPort,
)

# Recon (external tool wrapper — subfinder/nmap/httpx if installed)
from aresx.red.recon_agent import ReconAgent

# Vulnerability Intelligence
from aresx.red.vuln_intel import (
    lookup_cve, search_cves_by_product, get_epss_score, get_epss_bulk,
    check_cisa_kev, get_recent_kev_additions, search_exploitdb,
    scan_dependency, scan_requirements, full_vuln_report, CVERecord,
)

# Threat Actor Profiling
from aresx.red.threat_actor import (
    get_known_actor, search_actors_by_ttp, search_actors_by_target,
    enrich_actor_otx, profile_actor, list_known_actors, actor_summary,
    ActorProfile,
)

# IOC Engine
from aresx.red.ioc_engine import (
    extract_iocs, refang, defang, enrich_ioc, bulk_enrich, tag_ioc,
    export_stix21, export_csv, export_json, process_report, IOC,
)

# Infrastructure Pivot
from aresx.red.infra_pivot import (
    pivot_from_domain, pivot_from_ip, full_pivot_report,
    summarize_pivot, graph_to_json, PivotGraph, PivotNode,
)

# Kill Chain Builder
from aresx.red.kill_chain import KillChainBuilder

# GitHub Dork Engine
from aresx.red.github_dork import (
    dork_org, full_dork_scan, summarize_dork_findings, DorkFinding,
)

# Engagement Tracker
from aresx.red.engagement import EngagementTracker

# CVSS Calculator + Findings
from aresx.red.cvss_calc import (
    calculate_cvss, parse_vector_string, quick_score, list_common_vuln_types,
    create_finding, sort_findings_by_severity, findings_summary,
    CVSSVector, CVSSResult, Finding, Severity,
)

# Report Generator
from aresx.red.report_gen import (
    generate_executive_summary, generate_technical_report,
    generate_attack_narrative, generate_full_report, export_findings_json,
)

# Orchestrator (ROE-gated mission runner)
from aresx.red.orchestrator import RedOrchestrator

# ROE and authorization — the single source of truth for time-boxed
# authorization windows, used by RedOrchestrator internally (via its
# .auth attribute) and importable directly for anything that needs to
# construct or inspect authorization state without a full orchestrator.
from aresx.red.roe import AuthorizationManager, AuthWindow, load_roe, get_shared_authorization

# Audited orchestrator — wires mission lifecycle into Order 27 audit chain
from aresx.red.bridge import AuditedRedOrchestrator

__all__ = [
    "RED_VERSION", "RED_CODENAME",
    # Recon
    "full_recon", "enumerate_subdomains", "port_scan", "get_asn_info",
    "detect_waf", "fingerprint_tech", "analyze_security_headers",
    "enumerate_s3_buckets", "extract_js_endpoints", "harvest_emails",
    "recon_summary", "ReconResult", "OpenPort", "ReconAgent",
    # Vuln intel
    "lookup_cve", "search_cves_by_product", "get_epss_score", "get_epss_bulk",
    "check_cisa_kev", "get_recent_kev_additions", "search_exploitdb",
    "scan_dependency", "scan_requirements", "full_vuln_report", "CVERecord",
    # Threat actor
    "get_known_actor", "search_actors_by_ttp", "search_actors_by_target",
    "enrich_actor_otx", "profile_actor", "list_known_actors", "actor_summary",
    "ActorProfile",
    # IOC
    "extract_iocs", "refang", "defang", "enrich_ioc", "bulk_enrich", "tag_ioc",
    "export_stix21", "export_csv", "export_json", "process_report", "IOC",
    # Infra pivot
    "pivot_from_domain", "pivot_from_ip", "full_pivot_report",
    "summarize_pivot", "graph_to_json", "PivotGraph", "PivotNode",
    # Kill chain
    "KillChainBuilder",
    # GitHub dork
    "dork_org", "full_dork_scan", "summarize_dork_findings", "DorkFinding",
    # Engagement
    "EngagementTracker",
    # CVSS
    "calculate_cvss", "parse_vector_string", "quick_score", "list_common_vuln_types",
    "create_finding", "sort_findings_by_severity", "findings_summary",
    "CVSSVector", "CVSSResult", "Finding", "Severity",
    # Reports
    "generate_executive_summary", "generate_technical_report",
    "generate_attack_narrative", "generate_full_report", "export_findings_json",
    # Orchestrator
    "RedOrchestrator",
    "AuthorizationManager", "AuthWindow", "load_roe", "get_shared_authorization",
    "AuditedRedOrchestrator",
]
