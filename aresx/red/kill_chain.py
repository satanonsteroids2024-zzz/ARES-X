# red_module/utils/killchain_builder.py
"""
Kill Chain Builder for ARES X Red Module
Maps findings to MITRE ATT&CK tactics/techniques.
"""

from datetime import datetime
from typing import Dict, List, Any


# Full ATT&CK technique IDs + names per tactic
_ATTACK_TECHNIQUES: Dict[str, List[Dict]] = {
    "Reconnaissance": [
        {"id": "T1595", "name": "Active Scanning"},
        {"id": "T1592", "name": "Gather Victim Host Info"},
        {"id": "T1589", "name": "Gather Victim Identity Info"},
        {"id": "T1590", "name": "Gather Victim Network Info"},
        {"id": "T1591", "name": "Gather Victim Org Info"},
        {"id": "T1598", "name": "Phishing for Info"},
        {"id": "T1597", "name": "Search Closed Sources"},
        {"id": "T1596", "name": "Search Open Technical Databases"},
        {"id": "T1593", "name": "Search Open Websites / Domains"},
        {"id": "T1594", "name": "Search Victim-Owned Websites"},
    ],
    "Resource Development": [
        {"id": "T1583", "name": "Acquire Infrastructure"},
        {"id": "T1586", "name": "Compromise Accounts"},
        {"id": "T1584", "name": "Compromise Infrastructure"},
        {"id": "T1587", "name": "Develop Capabilities"},
        {"id": "T1585", "name": "Establish Accounts"},
        {"id": "T1588", "name": "Obtain Capabilities"},
    ],
    "Initial Access": [
        {"id": "T1189", "name": "Drive-by Compromise"},
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1133", "name": "External Remote Services"},
        {"id": "T1200", "name": "Hardware Additions"},
        {"id": "T1566", "name": "Phishing"},
        {"id": "T1195", "name": "Supply Chain Compromise"},
        {"id": "T1199", "name": "Trusted Relationship"},
        {"id": "T1078", "name": "Valid Accounts"},
    ],
    "Execution": [
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
        {"id": "T1203", "name": "Exploitation for Client Execution"},
        {"id": "T1559", "name": "Inter-Process Communication"},
        {"id": "T1106", "name": "Native API"},
        {"id": "T1053", "name": "Scheduled Task / Job"},
        {"id": "T1129", "name": "Shared Modules"},
        {"id": "T1072", "name": "Software Deployment Tools"},
        {"id": "T1569", "name": "System Services"},
    ],
    "Persistence": [
        {"id": "T1098", "name": "Account Manipulation"},
        {"id": "T1197", "name": "BITS Jobs"},
        {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
        {"id": "T1037", "name": "Boot or Logon Initialization Scripts"},
        {"id": "T1176", "name": "Browser Extensions"},
        {"id": "T1554", "name": "Compromise Client Software Binary"},
        {"id": "T1136", "name": "Create Account"},
        {"id": "T1543", "name": "Create or Modify System Process"},
    ],
    "Privilege Escalation": [
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
        {"id": "T1134", "name": "Access Token Manipulation"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
        {"id": "T1574", "name": "Hijack Execution Flow"},
        {"id": "T1055", "name": "Process Injection"},
        {"id": "T1053", "name": "Scheduled Task / Job"},
        {"id": "T1078", "name": "Valid Accounts"},
    ],
    "Defense Evasion": [
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
        {"id": "T1134", "name": "Access Token Manipulation"},
        {"id": "T1197", "name": "BITS Jobs"},
        {"id": "T1622", "name": "Debugger Evasion"},
        {"id": "T1140", "name": "Deobfuscate / Decode Files or Information"},
        {"id": "T1006", "name": "Direct Volume Access"},
        {"id": "T1484", "name": "Domain Policy Modification"},
    ],
    "Credential Access": [
        {"id": "T1110", "name": "Brute Force"},
        {"id": "T1555", "name": "Credentials from Password Stores"},
        {"id": "T1212", "name": "Exploitation for Credential Access"},
        {"id": "T1187", "name": "Forced Authentication"},
        {"id": "T1606", "name": "Forge Web Credentials"},
        {"id": "T1056", "name": "Input Capture"},
        {"id": "T1557", "name": "Adversary-in-the-Middle"},
        {"id": "T1003", "name": "OS Credential Dumping"},
    ],
    "Discovery": [
        {"id": "T1087", "name": "Account Discovery"},
        {"id": "T1010", "name": "Application Window Discovery"},
        {"id": "T1217", "name": "Browser Information Discovery"},
        {"id": "T1580", "name": "Cloud Infrastructure Discovery"},
        {"id": "T1538", "name": "Cloud Service Dashboard"},
        {"id": "T1526", "name": "Cloud Service Discovery"},
        {"id": "T1613", "name": "Container and Resource Discovery"},
        {"id": "T1046", "name": "Network Service Discovery"},
        {"id": "T1082", "name": "System Information Discovery"},
        {"id": "T1016", "name": "System Network Configuration Discovery"},
    ],
    "Lateral Movement": [
        {"id": "T1210", "name": "Exploitation of Remote Services"},
        {"id": "T1534", "name": "Internal Spearphishing"},
        {"id": "T1570", "name": "Lateral Tool Transfer"},
        {"id": "T1563", "name": "Remote Service Session Hijacking"},
        {"id": "T1021", "name": "Remote Services"},
        {"id": "T1091", "name": "Replication Through Removable Media"},
        {"id": "T1072", "name": "Software Deployment Tools"},
        {"id": "T1080", "name": "Taint Shared Content"},
    ],
    "Collection": [
        {"id": "T1557", "name": "Adversary-in-the-Middle"},
        {"id": "T1560", "name": "Archive Collected Data"},
        {"id": "T1123", "name": "Audio Capture"},
        {"id": "T1119", "name": "Automated Collection"},
        {"id": "T1115", "name": "Clipboard Data"},
        {"id": "T1530", "name": "Data from Cloud Storage"},
        {"id": "T1602", "name": "Data from Configuration Repository"},
        {"id": "T1213", "name": "Data from Information Repositories"},
        {"id": "T1005", "name": "Data from Local System"},
    ],
    "Command and Control": [
        {"id": "T1071", "name": "Application Layer Protocol"},
        {"id": "T1092", "name": "Communication Through Removable Media"},
        {"id": "T1132", "name": "Data Encoding"},
        {"id": "T1001", "name": "Data Obfuscation"},
        {"id": "T1568", "name": "Dynamic Resolution"},
        {"id": "T1573", "name": "Encrypted Channel"},
        {"id": "T1008", "name": "Fallback Channels"},
        {"id": "T1105", "name": "Ingress Tool Transfer"},
        {"id": "T1104", "name": "Multi-Stage Channels"},
        {"id": "T1095", "name": "Non-Application Layer Protocol"},
    ],
    "Exfiltration": [
        {"id": "T1020", "name": "Automated Exfiltration"},
        {"id": "T1030", "name": "Data Transfer Size Limits"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
        {"id": "T1011", "name": "Exfiltration Over Other Network Medium"},
        {"id": "T1052", "name": "Exfiltration Over Physical Medium"},
        {"id": "T1567", "name": "Exfiltration Over Web Service"},
        {"id": "T1029", "name": "Scheduled Transfer"},
        {"id": "T1537", "name": "Transfer Data to Cloud Account"},
    ],
    "Impact": [
        {"id": "T1531", "name": "Account Access Removal"},
        {"id": "T1485", "name": "Data Destruction"},
        {"id": "T1486", "name": "Data Encrypted for Impact"},
        {"id": "T1565", "name": "Data Manipulation"},
        {"id": "T1491", "name": "Defacement"},
        {"id": "T1561", "name": "Disk Wipe"},
        {"id": "T1499", "name": "Endpoint Denial of Service"},
        {"id": "T1495", "name": "Firmware Corruption"},
        {"id": "T1490", "name": "Inhibit System Recovery"},
        {"id": "T1498", "name": "Network Denial of Service"},
    ],
}

# Finding type → tactic mapping
_FINDING_TO_TACTIC: Dict[str, str] = {
    "subdomains":       "Reconnaissance",
    "portscan":         "Discovery",
    "http_fingerprint": "Reconnaissance",
    "credentials":      "Credential Access",
    "vulnerabilities":  "Initial Access",
    "open_s3":          "Collection",
    "js_endpoints":     "Reconnaissance",
    "emails":           "Reconnaissance",
    "tech_stack":       "Reconnaissance",
}


class KillChainBuilder:
    def __init__(self):
        self.tactics = list(_ATTACK_TECHNIQUES.keys())   # 14 ATT&CK tactics

    def build_from_findings(self, findings: List[Dict], target: Dict) -> Dict:
        """Build ATT&CK-mapped kill chain from recon/intel findings."""
        chain = {
            "target":         target,
            "timestamp":      datetime.now().isoformat(),
            "stages":         [],
            "coverage_score": 0.0,
        }

        for finding in findings:
            ftype  = finding.get("type", "")
            tactic = _FINDING_TO_TACTIC.get(ftype, "Reconnaissance")
            techniques = _ATTACK_TECHNIQUES.get(tactic, [])

            # Pick best-fit technique based on finding type
            technique = self._map_technique(ftype, techniques)

            chain["stages"].append({
                "tactic":      tactic,
                "technique_id":   technique["id"],
                "technique_name": technique["name"],
                "confidence":  self._confidence(finding),
                "details":     self._describe(finding),
                "finding_ref": ftype,
            })

        # BUG 6 FIX: cap at 100% — original could exceed 100 if stages > 14
        unique_tactics = len({s["tactic"] for s in chain["stages"]})
        chain["coverage_score"] = round(
            min(100.0, unique_tactics / len(self.tactics) * 100), 1
        )
        return chain

    def _map_technique(self, ftype: str, techniques: List[Dict]) -> Dict:
        """Pick the most relevant ATT&CK technique for a finding type."""
        mapping = {
            "subdomains":       "T1595",
            "portscan":         "T1046",
            "http_fingerprint": "T1592",
            "credentials":      "T1110",
            "vulnerabilities":  "T1190",
            "open_s3":          "T1530",
            "js_endpoints":     "T1593",
            "emails":           "T1589",
            "tech_stack":       "T1592",
        }
        target_id = mapping.get(ftype)
        for t in techniques:
            if t["id"] == target_id:
                return t
        return techniques[0] if techniques else {"id": "T1000", "name": "Unknown"}

    def _confidence(self, finding: Dict) -> float:
        """Confidence score based on finding quality."""
        if finding.get("type") == "error":
            return 0.1
        count = finding.get("count", 0)
        if count > 10:
            return 0.95
        if count > 0:
            return 0.8
        if finding.get("data"):
            return 0.75
        return 0.5

    def _describe(self, finding: Dict) -> str:
        """Human-readable description for a finding stage."""
        ftype = finding.get("type", "unknown")
        if ftype == "subdomains":
            return f"Discovered {finding.get('count', 0)} subdomains via enum"
        if ftype == "portscan":
            data = finding.get("data", [])
            return f"Port scan returned {len(data)} lines of output"
        if ftype == "http_fingerprint":
            return f"HTTP tech fingerprint: {len(finding.get('data', []))} results"
        return f"Finding type: {ftype}"

    def simulate_attack_path(self, chain: Dict) -> Dict:
        """Simulate likely attack path and risk from the kill chain."""
        stages    = chain.get("stages", [])
        coverage  = chain.get("coverage_score", 0.0)

        # Risk score: weighted by coverage + stage count
        risk_score = min(100, int(coverage * 0.6 + len(stages) * 3))

        recommendations = []
        tactics_found = {s["tactic"] for s in stages}
        if "Reconnaissance" in tactics_found:
            recommendations.append("Reduce public attack surface — audit DNS, S3, GitHub")
        if "Discovery" in tactics_found:
            recommendations.append("Restrict service exposure — firewall open ports")
        if "Credential Access" in tactics_found:
            recommendations.append("Enforce MFA + rotate exposed credentials")
        if "Initial Access" in tactics_found:
            recommendations.append("Patch public-facing applications — prioritize by EPSS")
        if not recommendations:
            recommendations.append("Review recon findings and remediate exposures")

        return {
            "most_likely_path":  [s["tactic"] for s in stages],
            "technique_ids":     [s["technique_id"] for s in stages],
            "risk_score":        risk_score,
            "coverage_score":    coverage,
            "recommendations":   recommendations,
        }
