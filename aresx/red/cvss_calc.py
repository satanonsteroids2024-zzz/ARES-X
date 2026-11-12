"""
ARES X Red Module — CVSS v3.1 Calculator + Finding Management
Full CVSS v3.1 base score calculator per the official FIRST.org spec.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# ── CVSS v3.1 metric value tables (per FIRST.org spec) ────────────────────────

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}          # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                                # Attack Complexity
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}                   # Privileges Required (Scope Unchanged)
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}                   # Privileges Required (Scope Changed)
_UI = {"N": 0.85, "R": 0.62}                                # User Interaction
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}                     # Confidentiality/Integrity/Availability


@dataclass
class CVSSVector:
    av: str = "N"    # Attack Vector: N/A/L/P
    ac: str = "L"    # Attack Complexity: L/H
    pr: str = "N"    # Privileges Required: N/L/H
    ui: str = "N"    # User Interaction: N/R
    s: str = "U"     # Scope: U/C
    c: str = "N"     # Confidentiality: N/L/H
    i: str = "N"     # Integrity: N/L/H
    a: str = "N"     # Availability: N/L/H


@dataclass
class CVSSResult:
    base_score: float
    severity: Severity
    vector_string: str
    exploitability: float
    impact: float


def calculate_cvss(vector: CVSSVector) -> CVSSResult:
    """
    Full CVSS v3.1 base score calculation per official FIRST.org formula.
    https://www.first.org/cvss/v3.1/specification-document

    Returns base score 0.0-10.0, severity rating, and the vector string.
    """
    # Privileges Required depends on Scope
    pr_table = _PR_C if vector.s == "C" else _PR_U
    pr_val = pr_table.get(vector.pr, 0.85)

    iss = 1 - ((1 - _CIA.get(vector.c, 0)) *
               (1 - _CIA.get(vector.i, 0)) *
               (1 - _CIA.get(vector.a, 0)))

    if vector.s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = (
        8.22 * _AV.get(vector.av, 0.85) *
        _AC.get(vector.ac, 0.77) *
        pr_val *
        _UI.get(vector.ui, 0.85)
    )

    if impact <= 0:
        base_score = 0.0
    elif vector.s == "U":
        base_score = min(10.0, _roundup(impact + exploitability))
    else:
        base_score = min(10.0, _roundup(1.08 * (impact + exploitability)))

    severity = _score_to_severity(base_score)

    vector_string = (
        f"CVSS:3.1/AV:{vector.av}/AC:{vector.ac}/PR:{vector.pr}/"
        f"UI:{vector.ui}/S:{vector.s}/C:{vector.c}/I:{vector.i}/A:{vector.a}"
    )

    return CVSSResult(
        base_score=round(base_score, 1),
        severity=severity,
        vector_string=vector_string,
        exploitability=round(exploitability, 2),
        impact=round(impact, 2),
    )


def _roundup(value: float) -> float:
    """CVSS spec's specific roundup function — rounds to nearest 0.1."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (int_value // 10000 + 1) / 10


def _score_to_severity(score: float) -> Severity:
    if score == 0.0:
        return Severity.NONE
    elif score < 4.0:
        return Severity.LOW
    elif score < 7.0:
        return Severity.MEDIUM
    elif score < 9.0:
        return Severity.HIGH
    else:
        return Severity.CRITICAL


def parse_vector_string(vector_str: str) -> CVSSVector:
    """Parse a CVSS:3.1/AV:N/AC:L/... vector string into a CVSSVector."""
    parts = vector_str.replace("CVSS:3.1/", "").split("/")
    kv = dict(p.split(":") for p in parts if ":" in p)
    return CVSSVector(
        av=kv.get("AV", "N"), ac=kv.get("AC", "L"), pr=kv.get("PR", "N"),
        ui=kv.get("UI", "N"), s=kv.get("S", "U"),
        c=kv.get("C", "N"), i=kv.get("I", "N"), a=kv.get("A", "N"),
    )


# ── Finding Management ────────────────────────────────────────────────────────

@dataclass
class Finding:
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    affected_asset: str = ""
    proof_of_concept: str = ""
    remediation: str = ""
    status: str = "open"       # open, in-review, remediated, accepted-risk, false-positive
    cwe_id: str = ""
    references: list[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: list[str] = field(default_factory=list)


def create_finding(title: str, description: str, affected_asset: str,
                   cvss_vector: Optional[CVSSVector] = None,
                   remediation: str = "", cwe_id: str = "") -> Finding:
    """Create a new finding with automatic CVSS scoring if a vector is provided."""
    finding = Finding(
        title=title,
        description=description,
        affected_asset=affected_asset,
        remediation=remediation,
        cwe_id=cwe_id,
    )
    if cvss_vector:
        result = calculate_cvss(cvss_vector)
        finding.cvss_score = result.base_score
        finding.cvss_vector = result.vector_string
        finding.severity = result.severity
    return finding


def sort_findings_by_severity(findings: list[Finding]) -> list[Finding]:
    """Sort findings critical → low, with CVSS score as tiebreaker."""
    severity_order = {
        Severity.CRITICAL: 0, Severity.HIGH: 1,
        Severity.MEDIUM: 2, Severity.LOW: 3, Severity.NONE: 4,
    }
    return sorted(
        findings,
        key=lambda f: (severity_order.get(f.severity, 4), -(f.cvss_score or 0)),
    )


def findings_summary(findings: list[Finding]) -> dict:
    """Aggregate stats for a set of findings."""
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        by_status[f.status] = by_status.get(f.status, 0) + 1

    avg_cvss = 0.0
    scored = [f.cvss_score for f in findings if f.cvss_score is not None]
    if scored:
        avg_cvss = round(sum(scored) / len(scored), 2)

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_status": by_status,
        "avg_cvss_score": avg_cvss,
        "critical_open": sum(
            1 for f in findings if f.severity == Severity.CRITICAL and f.status == "open"
        ),
    }


# ── Common vulnerability CVSS presets (for quick scoring) ────────────────────

_COMMON_VECTORS: dict[str, CVSSVector] = {
    "sql_injection_unauth":       CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "xss_reflected":               CVSSVector(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"),
    "xss_stored":                  CVSSVector(av="N", ac="L", pr="N", ui="N", s="C", c="L", i="L", a="N"),
    "rce_unauth":                  CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "rce_auth":                    CVSSVector(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="H"),
    "auth_bypass":                 CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "idor":                        CVSSVector(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="N", a="N"),
    "ssrf":                        CVSSVector(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="L", a="N"),
    "path_traversal":              CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "misconfigured_s3_public":     CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "exposed_secrets_github":      CVSSVector(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "weak_tls_config":             CVSSVector(av="N", ac="H", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "missing_security_headers":    CVSSVector(av="N", ac="H", pr="N", ui="R", s="U", c="L", i="N", a="N"),
    "outdated_software_known_cve": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
}


def quick_score(vuln_type: str) -> Optional[CVSSResult]:
    """Get a pre-calculated CVSS score for a common vulnerability class."""
    vector = _COMMON_VECTORS.get(vuln_type)
    if vector:
        return calculate_cvss(vector)
    return None


def list_common_vuln_types() -> list[str]:
    return list(_COMMON_VECTORS.keys())
