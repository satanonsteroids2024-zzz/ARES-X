"""
ARES X Red Module — Vulnerability Intelligence
CVE lookup, EPSS scoring, CISA KEV check, ExploitDB search.
All free/public APIs — NVD, FIRST.org EPSS, CISA, ExploitDB mirror.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CVERecord:
    cve_id: str
    description: str = ""
    cvss_v3_score: Optional[float] = None
    cvss_v3_severity: str = ""
    cvss_v3_vector: str = ""
    published: str = ""
    modified: str = ""
    references: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_cisa_kev: bool = False
    kev_date_added: str = ""
    kev_due_date: str = ""
    kev_ransomware_use: bool = False
    exploitdb_ids: list[str] = field(default_factory=list)


async def _http_get_json(url: str, timeout: float = 15.0) -> Optional[dict]:
    """Async GET returning parsed JSON, or None on failure."""
    try:
        import httpx
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.get(url, headers={"User-Agent": "ARES-X-VulnIntel/8.0"})
            if r.status_code == 200:
                return r.json()
    except Exception as exc:
        logger.debug("HTTP GET failed for %s: %s", url, exc)
    return None


# ── NVD (National Vulnerability Database) ────────────────────────────────────

async def lookup_cve(cve_id: str) -> Optional[CVERecord]:
    """
    Look up a single CVE by ID from NVD (free, no key required for low volume).
    e.g. lookup_cve("CVE-2024-3400")
    """
    cve_id = cve_id.upper().strip()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        logger.warning("Invalid CVE ID format: %s", cve_id)
        return None

    data = await _http_get_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    )
    if not data or not data.get("vulnerabilities"):
        return None

    cve = data["vulnerabilities"][0]["cve"]
    record = CVERecord(cve_id=cve_id)

    # Description
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            record.description = desc.get("value", "")
            break

    # CVSS v3 metrics (prefer v3.1, fall back to v3.0)
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            cvss = metrics[key][0]["cvssData"]
            record.cvss_v3_score = cvss.get("baseScore")
            record.cvss_v3_severity = cvss.get("baseSeverity", "")
            record.cvss_v3_vector = cvss.get("vectorString", "")
            break

    record.published = cve.get("published", "")
    record.modified = cve.get("lastModified", "")
    record.references = [r.get("url", "") for r in cve.get("references", [])][:10]

    # CWE IDs
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("value", "").startswith("CWE-"):
                record.cwe_ids.append(desc["value"])

    # Enrich with EPSS + KEV
    epss = await get_epss_score(cve_id)
    if epss:
        record.epss_score = epss.get("epss")
        record.epss_percentile = epss.get("percentile")

    kev = await check_cisa_kev(cve_id)
    if kev:
        record.in_cisa_kev = True
        record.kev_date_added = kev.get("dateAdded", "")
        record.kev_due_date = kev.get("dueDate", "")
        record.kev_ransomware_use = kev.get("knownRansomwareCampaignUse", "") == "Known"

    return record


async def search_cves_by_product(product: str, version: str = "",
                                  max_results: int = 20) -> list[CVERecord]:
    """
    Search NVD for CVEs affecting a product (optionally a specific version).
    e.g. search_cves_by_product("apache log4j", "2.14.1")
    """
    query = f"{product} {version}".strip()
    data = await _http_get_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={query.replace(' ', '+')}&resultsPerPage={max_results}"
    )
    if not data or not data.get("vulnerabilities"):
        return []

    records = []
    for item in data["vulnerabilities"][:max_results]:
        cve = item["cve"]
        cve_id = cve.get("id", "")
        record = CVERecord(cve_id=cve_id)
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                record.description = desc.get("value", "")
                break
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0]["cvssData"]
                record.cvss_v3_score = cvss.get("baseScore")
                record.cvss_v3_severity = cvss.get("baseSeverity", "")
                record.cvss_v3_vector = cvss.get("vectorString", "")
                break
        record.published = cve.get("published", "")
        records.append(record)

    return records


# ── EPSS (Exploit Prediction Scoring System) ──────────────────────────────────

async def get_epss_score(cve_id: str) -> Optional[dict]:
    """
    Get EPSS score for a CVE — probability of exploitation in next 30 days.
    Free API, no key. FIRST.org's Exploit Prediction Scoring System.
    Returns {"epss": 0.0-1.0, "percentile": 0.0-1.0} or None.
    """
    data = await _http_get_json(f"https://api.first.org/data/v1/epss?cve={cve_id}")
    if data and data.get("data"):
        entry = data["data"][0]
        return {
            "epss": float(entry.get("epss", 0)),
            "percentile": float(entry.get("percentile", 0)),
        }
    return None


async def get_epss_bulk(cve_ids: list[str]) -> dict[str, dict]:
    """Bulk EPSS lookup for multiple CVEs in one call (max 100 per request)."""
    if not cve_ids:
        return {}
    batch = cve_ids[:100]
    query = ",".join(batch)
    data = await _http_get_json(f"https://api.first.org/data/v1/epss?cve={query}")
    result = {}
    if data and data.get("data"):
        for entry in data["data"]:
            result[entry["cve"]] = {
                "epss": float(entry.get("epss", 0)),
                "percentile": float(entry.get("percentile", 0)),
            }
    return result


# ── CISA KEV (Known Exploited Vulnerabilities) ────────────────────────────────

_kev_cache: dict = {"data": None, "fetched_at": 0.0}
_KEV_CACHE_TTL = 3600  # 1 hour


async def _fetch_kev_catalog() -> dict:
    """Fetch + cache the full CISA KEV catalog (updated ~daily by CISA)."""
    now = time.time()
    if _kev_cache["data"] and (now - _kev_cache["fetched_at"]) < _KEV_CACHE_TTL:
        return _kev_cache["data"]

    data = await _http_get_json(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    if data:
        by_cve = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        _kev_cache["data"] = by_cve
        _kev_cache["fetched_at"] = now
        return by_cve
    return _kev_cache["data"] or {}


async def check_cisa_kev(cve_id: str) -> Optional[dict]:
    """
    Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog.
    If it's in KEV, it means it's confirmed being actively exploited in the wild —
    highest priority for patching.
    """
    catalog = await _fetch_kev_catalog()
    return catalog.get(cve_id.upper())


async def get_recent_kev_additions(days: int = 7) -> list[dict]:
    """Get CVEs added to CISA KEV in the last N days — active threat radar."""
    from datetime import datetime, timedelta
    catalog = await _fetch_kev_catalog()
    cutoff = datetime.now() - timedelta(days=days)
    recent = []
    for cve_id, entry in catalog.items():
        try:
            added = datetime.strptime(entry.get("dateAdded", ""), "%Y-%m-%d")
            if added >= cutoff:
                recent.append(entry)
        except ValueError:
            continue
    return sorted(recent, key=lambda e: e.get("dateAdded", ""), reverse=True)


# ── ExploitDB Search ──────────────────────────────────────────────────────────

async def search_exploitdb(query: str, max_results: int = 10) -> list[dict]:
    """
    Search Exploit-DB for public PoCs matching a query (product name, CVE, etc.)
    Uses the free Exploit-DB GitLab CSV mirror (no key required).
    Returns metadata only — title, EDB-ID, date, type. Not the exploit code itself.
    """
    # Exploit-DB publishes a searchable CSV via their GitLab mirror
    data_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            r = await client.get(data_url)
            if r.status_code != 200:
                return []
            lines = r.text.splitlines()
    except Exception as exc:
        logger.debug("ExploitDB fetch failed: %s", exc)
        return []

    import csv, io
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    query_lower = query.lower()
    results = []
    for row in reader:
        title = row.get("description", "")
        if query_lower in title.lower():
            results.append({
                "edb_id":   row.get("id", ""),
                "title":    title,
                "date":     row.get("date_published", ""),
                "type":     row.get("type", ""),
                "platform": row.get("platform", ""),
                "port":     row.get("port", ""),
            })
            if len(results) >= max_results:
                break
    return results


# ── Dependency Vulnerability Scanner ──────────────────────────────────────────

async def scan_dependency(package_name: str, version: str,
                          ecosystem: str = "pypi") -> list[dict]:
    """
    Check a package@version against OSV.dev (Open Source Vulnerabilities, free, no key).
    ecosystem: "pypi", "npm", "go", "maven", "cargo", etc.
    """
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(
                "https://api.osv.dev/v1/query",
                json={
                    "version": version,
                    "package": {"name": package_name, "ecosystem": ecosystem},
                },
            )
            if r.status_code == 200:
                data = r.json()
                return data.get("vulns", [])
    except Exception as exc:
        logger.debug("OSV query failed: %s", exc)
    return []


async def scan_requirements(requirements: list[tuple[str, str]],
                            ecosystem: str = "pypi") -> dict[str, list[dict]]:
    """
    Batch-scan a list of (package, version) tuples against OSV.
    e.g. scan_requirements([("django", "3.2.0"), ("requests", "2.25.0")])
    """
    import asyncio
    results = {}

    async def scan_one(pkg: str, ver: str):
        vulns = await scan_dependency(pkg, ver, ecosystem)
        if vulns:
            results[f"{pkg}=={ver}"] = vulns

    await asyncio.gather(*[scan_one(p, v) for p, v in requirements])
    return results


# ── Full Vuln Intel Orchestrator ──────────────────────────────────────────────

async def full_vuln_report(cve_ids: list[str]) -> dict:
    """
    Generate a complete vulnerability intelligence report for a list of CVEs.
    Enriches with EPSS + KEV + severity, sorted by priority.
    """
    import asyncio
    records = await asyncio.gather(*[lookup_cve(c) for c in cve_ids])
    records = [r for r in records if r is not None]

    # Priority scoring: KEV=highest, then EPSS score, then CVSS
    def priority_score(r: CVERecord) -> float:
        score = 0.0
        if r.in_cisa_kev:
            score += 100
        if r.kev_ransomware_use:
            score += 50
        if r.epss_score:
            score += r.epss_score * 30
        if r.cvss_v3_score:
            score += r.cvss_v3_score
        return score

    ranked = sorted(records, key=priority_score, reverse=True)

    return {
        "total_cves": len(ranked),
        "kev_count": sum(1 for r in ranked if r.in_cisa_kev),
        "critical_count": sum(1 for r in ranked if r.cvss_v3_severity == "CRITICAL"),
        "ransomware_associated": sum(1 for r in ranked if r.kev_ransomware_use),
        "cves": [
            {
                "cve_id": r.cve_id,
                "cvss_score": r.cvss_v3_score,
                "severity": r.cvss_v3_severity,
                "epss": r.epss_score,
                "in_kev": r.in_cisa_kev,
                "ransomware": r.kev_ransomware_use,
                "description": r.description[:200],
            }
            for r in ranked
        ],
    }
