"""
ARES X Red Module — GitHub Dork Engine
Search GitHub for exposed secrets, API keys, config files, credentials
belonging to a target organization. Uses GitHub's public code search API
(free, rate-limited, optionally authenticated for higher limits).
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Dork templates for common secret patterns ─────────────────────────────────

_SECRET_DORKS: dict[str, str] = {
    "aws_keys":          'AKIA OR "aws_secret_access_key"',
    "generic_api_key":   '"api_key" OR "apikey" OR "api-key"',
    "private_keys":      '"BEGIN RSA PRIVATE KEY" OR "BEGIN PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY"',
    "env_files":         'filename:.env',
    "docker_secrets":    'filename:docker-compose.yml "password"',
    "database_conn":     '"mongodb://" OR "postgres://" OR "mysql://"',
    "slack_tokens":      '"xoxb-" OR "xoxp-" OR "xoxa-"',
    "google_api":        '"AIza"',
    "stripe_keys":       '"sk_live_" OR "sk_test_"',
    "jwt_secrets":       '"jwt_secret" OR "JWT_SECRET"',
    "ssh_config":        'filename:known_hosts',
    "github_tokens":     '"ghp_" OR "gho_" OR "ghu_"',
    "firebase_config":   '"firebaseio.com" "apiKey"',
    "npm_tokens":        'filename:.npmrc "_authToken"',
    "terraform_state":   'filename:terraform.tfstate "secret"',
    "kubeconfig":        'filename:.kube/config',
    "htpasswd":          'filename:.htpasswd',
    "wp_config":         'filename:wp-config.php "DB_PASSWORD"',
    "azure_keys":        '"DefaultEndpointsProtocol=https;AccountName="',
    "twilio_keys":       '"AC" "auth_token"',
    "generic_password":  '"password" filename:config',
}

_SEVERITY_MAP = {
    "aws_keys":         "critical",
    "private_keys":     "critical",
    "database_conn":    "critical",
    "azure_keys":       "critical",
    "stripe_keys":      "critical",
    "github_tokens":    "high",
    "slack_tokens":     "high",
    "google_api":       "high",
    "jwt_secrets":       "high",
    "firebase_config":  "high",
    "twilio_keys":       "high",
    "kubeconfig":       "high",
    "terraform_state":  "high",
    "env_files":        "medium",
    "docker_secrets":   "medium",
    "npm_tokens":       "medium",
    "wp_config":        "medium",
    "htpasswd":         "medium",
    "generic_api_key":  "medium",
    "ssh_config":       "low",
    "generic_password": "low",
}


@dataclass
class DorkFinding:
    dork_category: str
    severity: str
    repo_name: str
    file_path: str
    html_url: str
    snippet: str = ""
    score: float = 0.0


async def _github_code_search(query: str, org: str, token: Optional[str] = None,
                               max_results: int = 10) -> list[dict]:
    """
    Search GitHub code search API. Requires a GitHub PAT for meaningful rate limits
    (free: 10 req/min authenticated, 10 req/min unauthenticated for code search).
    Get a free token at github.com/settings/tokens (no special scopes needed for public search).
    """
    full_query = f"{query} org:{org}"
    try:
        import httpx
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                "https://api.github.com/search/code",
                params={"q": full_query, "per_page": max_results},
                headers=headers,
            )
            if r.status_code == 200:
                return r.json().get("items", [])
            elif r.status_code == 403:
                logger.warning("GitHub API rate limited — set a GITHUB_TOKEN for higher limits")
            elif r.status_code == 422:
                logger.debug("GitHub search query invalid or org not found: %s", org)
    except Exception as exc:
        logger.debug("GitHub search failed: %s", exc)
    return []


async def dork_org(org: str, categories: Optional[list[str]] = None,
                   github_token: Optional[str] = None,
                   max_per_category: int = 5) -> list[DorkFinding]:
    """
    Run secret-hunting dorks against a GitHub organization.

    Args:
        org: GitHub organization or username to search
        categories: which dork categories to run (default: all)
        github_token: optional PAT for higher rate limits (get free at github.com/settings/tokens)
        max_per_category: max results per dork category

    Returns list of DorkFinding — file locations only, does NOT extract or
    display the actual secret content.
    """
    import asyncio

    cats = categories or list(_SECRET_DORKS.keys())
    findings: list[DorkFinding] = []

    async def run_category(cat: str) -> None:
        query = _SECRET_DORKS.get(cat)
        if not query:
            return
        results = await _github_code_search(query, org, github_token, max_per_category)
        for item in results:
            findings.append(DorkFinding(
                dork_category=cat,
                severity=_SEVERITY_MAP.get(cat, "low"),
                repo_name=item.get("repository", {}).get("full_name", ""),
                file_path=item.get("path", ""),
                html_url=item.get("html_url", ""),
                score=item.get("score", 0.0),
            ))
        # GitHub code search: 10 req/min — space out requests
        await asyncio.sleep(6.5)

    for cat in cats:
        await run_category(cat)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: severity_order.get(f.severity, 4))

    return findings


def summarize_dork_findings(findings: list[DorkFinding]) -> str:
    """Human-readable summary of GitHub dork results."""
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    lines = [
        "=== GITHUB DORK RESULTS ===",
        f"Total findings: {len(findings)}",
        f"Critical: {by_severity.get('critical', 0)} | "
        f"High: {by_severity.get('high', 0)} | "
        f"Medium: {by_severity.get('medium', 0)} | "
        f"Low: {by_severity.get('low', 0)}",
        "",
    ]
    for f in findings[:30]:
        lines.append(
            f"  [{f.severity.upper():8}] {f.dork_category:20} "
            f"{f.repo_name}/{f.file_path}"
        )
    return "\n".join(lines)


async def full_dork_scan(org: str, github_token: Optional[str] = None) -> dict:
    """
    Full dork scan against an org, auto-stored to ARES evidence vault.
    NOTE: due to GitHub's 10 req/min code search rate limit, scanning all
    20 categories takes ~2 minutes.
    """
    findings = await dork_org(org, github_token=github_token)

    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    result = {
        "org": org,
        "total_findings": len(findings),
        "by_severity": by_severity,
        "findings": [
            {
                "category": f.dork_category, "severity": f.severity,
                "repo": f.repo_name, "path": f.file_path, "url": f.html_url,
            }
            for f in findings
        ],
    }

    try:
        from aresx.enterprise import add_evidence
        add_evidence(
            source_tool="ares_red_github_dork",
            raw_data=json.dumps({
                "org": org, "total_findings": len(findings),
                "by_severity": by_severity,
            }),
        )
    except Exception as exc:
        logger.debug("Vault store failed (non-critical): %s", exc)

    return result
