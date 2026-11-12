"""
ARES X Red Module — IOC Engine
Extract, defang/refang, enrich, and export Indicators of Compromise.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ── Regex patterns for IOC extraction ─────────────────────────────────────────

_PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "ipv6": re.compile(
        r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(?:com|net|org|edu|gov|mil|int|info|biz|io|co|ru|cn|xyz|top|club|'
        r'online|site|tech|app|dev|cloud|link|pw|tk|ml|ga|cf|shop|store)\b',
        re.IGNORECASE,
    ),
    "url": re.compile(
        r'\bhxxps?://[^\s<>"\']+|https?://[^\s<>"\']+', re.IGNORECASE
    ),
    "email": re.compile(
        r'\b[A-Za-z0-9._%+\-]+(?:\[at\]|@)[A-Za-z0-9.\-]+(?:\[dot\]|\.)[A-Za-z]{2,}\b',
        re.IGNORECASE,
    ),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "cve": re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE),
    "bitcoin": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    "registry_key": re.compile(
        r'\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\s"\']+', re.IGNORECASE
    ),
    "file_path_windows": re.compile(
        r'\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\b'
    ),
    "mutex": re.compile(r'\bGlobal\\[A-Za-z0-9_\-{}]+\b'),
    "asn": re.compile(r'\bAS\d{1,6}\b'),
}

# Common defanging patterns to reverse (refang)
_REFANG_RULES = [
    (r'hxxps?://', lambda m: m.group(0).replace('hxxp', 'http')),
    (r'\[\.\]', '.'),
    (r'\(\.\)', '.'),
    (r'\[dot\]', '.'),
    (r'\[at\]', '@'),
    (r'\[://\]', '://'),
]

# Defanging rules (for safe sharing)
_DEFANG_RULES = [
    (r'https?://', lambda m: m.group(0).replace('http', 'hxxp')),
    (r'\.', '[.]'),
    (r'@', '[at]'),
]


@dataclass
class IOC:
    ioc_id: str
    type: str            # ip, domain, url, email, md5, sha1, sha256, cve, etc.
    value: str
    defanged: str = ""
    confidence: float = 0.7
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: list[str] = field(default_factory=list)
    source_text_context: str = ""
    enrichment: dict = field(default_factory=dict)


# ── Extraction ─────────────────────────────────────────────────────────────────

def refang(text: str) -> str:
    """Convert defanged indicators back to their real form for processing."""
    result = text
    result = re.sub(r'hxxps?://', lambda m: m.group(0).replace('hxxp', 'http'), result, flags=re.I)
    result = result.replace('[.]', '.').replace('(.)', '.')
    result = result.replace('[dot]', '.').replace('[DOT]', '.')
    result = result.replace('[at]', '@').replace('[AT]', '@')
    result = result.replace('[://]', '://')
    return result


def defang(value: str) -> str:
    """Convert a live indicator to a safe-for-sharing defanged form."""
    result = value
    result = re.sub(r'^https?://', lambda m: m.group(0).replace('http', 'hxxp'), result, flags=re.I)
    # Defang dots but not in the protocol part
    if '://' in result:
        proto, rest = result.split('://', 1)
        rest = rest.replace('.', '[.]')
        result = f"{proto}://{rest}"
    else:
        result = result.replace('.', '[.]')
    result = result.replace('@', '[at]')
    return result


def extract_iocs(text: str, defang_urls: bool = True) -> list[IOC]:
    """
    Extract all IOCs from raw text — reports, logs, pastes, threat intel feeds.
    Automatically refangs defanged text first so patterns match either form.
    """
    working_text = refang(text)
    found: list[IOC] = []
    seen: set[tuple[str, str]] = set()

    for ioc_type, pattern in _PATTERNS.items():
        for match in pattern.finditer(working_text):
            value = match.group(0)

            # Filter out obvious false positives
            if ioc_type == "domain":
                # Skip if it's actually a file path or looks like a version number
                if re.match(r'^\d+\.\d+\.\d+', value):
                    continue
            if ioc_type == "ipv4":
                try:
                    ip = ipaddress.ip_address(value)
                    if ip.is_private or ip.is_loopback:
                        continue  # skip RFC1918 / localhost — not real IOCs usually
                except ValueError:
                    continue

            key = (ioc_type, value.lower())
            if key in seen:
                continue
            seen.add(key)

            # Context snippet
            start = max(0, match.start() - 40)
            end = min(len(working_text), match.end() + 40)
            context = working_text[start:end].strip()

            ioc = IOC(
                ioc_id=str(uuid.uuid4())[:8],
                type=ioc_type,
                value=value,
                defanged=defang(value) if defang_urls and ioc_type in ("url", "domain", "ipv4", "email") else value,
                source_text_context=context,
            )
            found.append(ioc)

    return found


def classify_hash_type(hash_value: str) -> Optional[str]:
    """Determine hash algorithm from length."""
    hash_value = hash_value.strip()
    lengths = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
    if re.match(r'^[a-fA-F0-9]+$', hash_value):
        return lengths.get(len(hash_value))
    return None


# ── Enrichment ─────────────────────────────────────────────────────────────────

async def _http_get_json(url: str, headers: Optional[dict] = None, timeout: float = 10.0) -> Optional[dict]:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url, headers=headers or {})
            if r.status_code == 200:
                return r.json()
    except Exception as exc:
        logger.debug("Enrichment fetch failed: %s", exc)
    return None


async def enrich_ip(ip: str) -> dict:
    """Enrich an IP IOC via free ip-api.com — geolocation, ASN, hosting flag."""
    data = await _http_get_json(
        f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,"
        f"isp,org,as,asname,hosting,proxy"
    )
    if data and data.get("status") == "success":
        return data
    return {}


async def enrich_domain(domain: str) -> dict:
    """Enrich a domain IOC via crt.sh — certificate history."""
    data = await _http_get_json(f"https://crt.sh/?q={domain}&output=json")
    if isinstance(data, list):
        return {
            "cert_count": len(data),
            "first_cert": min((e.get("entry_timestamp", "") for e in data), default=""),
            "issuers": list({e.get("issuer_name", "") for e in data})[:5],
        }
    return {}


async def enrich_ioc(ioc: IOC) -> IOC:
    """Enrich a single IOC based on its type using free OSINT sources."""
    if ioc.type == "ipv4":
        ioc.enrichment = await enrich_ip(ioc.value)
    elif ioc.type == "domain":
        ioc.enrichment = await enrich_domain(ioc.value)
    elif ioc.type in ("md5", "sha1", "sha256"):
        ioc.enrichment = {"hash_type": ioc.type, "note": "submit to VirusTotal/OTX manually for verdict"}
    return ioc


async def bulk_enrich(iocs: list[IOC], max_concurrent: int = 10) -> list[IOC]:
    """Enrich a batch of IOCs concurrently."""
    import asyncio
    sem = asyncio.Semaphore(max_concurrent)

    async def enrich_one(ioc: IOC) -> IOC:
        async with sem:
            return await enrich_ioc(ioc)

    return list(await asyncio.gather(*[enrich_one(i) for i in iocs]))


# ── Tagging ────────────────────────────────────────────────────────────────────

def tag_ioc(ioc: IOC, campaign: str = "", malware_family: str = "", actor: str = "") -> IOC:
    """Attach campaign/malware/actor tags to an IOC for tracking."""
    if campaign:
        ioc.tags.append(f"campaign:{campaign}")
    if malware_family:
        ioc.tags.append(f"malware:{malware_family}")
    if actor:
        ioc.tags.append(f"actor:{actor}")
    return ioc


# ── Export ─────────────────────────────────────────────────────────────────────

def export_stix21(iocs: list[IOC], bundle_name: str = "ARES-X IOC Bundle") -> dict:
    """
    Export IOCs as a STIX 2.1 bundle — standard threat intel exchange format.
    Compatible with MISP, OpenCTI, ThreatConnect, etc.
    """
    stix_type_map = {
        "ipv4": ("ipv4-addr", "value"),
        "ipv6": ("ipv6-addr", "value"),
        "domain": ("domain-name", "value"),
        "url": ("url", "value"),
        "email": ("email-addr", "value"),
        "md5": ("file", "hashes.MD5"),
        "sha1": ("file", "hashes.SHA-1"),
        "sha256": ("file", "hashes.SHA-256"),
    }

    objects = []
    indicators = []
    now = datetime.now(timezone.utc).isoformat()

    for ioc in iocs:
        if ioc.type not in stix_type_map:
            continue
        stix_type, _ = stix_type_map[ioc.type]
        obj_id = f"{stix_type}--{ioc.ioc_id}-{uuid.uuid4().hex[:8]}"

        sco = {"type": stix_type, "id": obj_id}
        if ioc.type in ("md5", "sha1", "sha256"):
            hash_key = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[ioc.type]
            sco["hashes"] = {hash_key: ioc.value}
        else:
            sco["value"] = ioc.value
        objects.append(sco)

        # Create matching indicator SDO
        pattern_map = {
            "ipv4":   f"[ipv4-addr:value = '{ioc.value}']",
            "ipv6":   f"[ipv6-addr:value = '{ioc.value}']",
            "domain": f"[domain-name:value = '{ioc.value}']",
            "url":    f"[url:value = '{ioc.value}']",
            "email":  f"[email-addr:value = '{ioc.value}']",
            "md5":    f"[file:hashes.MD5 = '{ioc.value}']",
            "sha1":   f"[file:hashes.'SHA-1' = '{ioc.value}']",
            "sha256": f"[file:hashes.'SHA-256' = '{ioc.value}']",
        }
        indicators.append({
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "created": ioc.first_seen,
            "modified": now,
            "pattern": pattern_map.get(ioc.type, ""),
            "pattern_type": "stix",
            "valid_from": ioc.first_seen,
            "labels": ioc.tags or ["malicious-activity"],
            "confidence": int(ioc.confidence * 100),
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects + indicators,
        "_meta": {"name": bundle_name, "generated": now, "generator": "ARES-X-v8-Red"},
    }


def export_csv(iocs: list[IOC]) -> str:
    """Export IOCs as CSV — type, value, defanged, confidence, tags."""
    lines = ["type,value,defanged,confidence,tags,first_seen"]
    for ioc in iocs:
        tags_str = "|".join(ioc.tags)
        lines.append(
            f'{ioc.type},"{ioc.value}","{ioc.defanged}",{ioc.confidence},"{tags_str}",{ioc.first_seen}'
        )
    return "\n".join(lines)


def export_json(iocs: list[IOC]) -> str:
    """Export IOCs as ARES-native JSON."""
    return json.dumps([
        {
            "ioc_id": i.ioc_id, "type": i.type, "value": i.value,
            "defanged": i.defanged, "confidence": i.confidence,
            "tags": i.tags, "first_seen": i.first_seen,
            "enrichment": i.enrichment,
        }
        for i in iocs
    ], indent=2)


# ── Full pipeline ──────────────────────────────────────────────────────────────

async def process_report(text: str, enrich: bool = True,
                         campaign: str = "", actor: str = "") -> dict:
    """
    Full IOC pipeline: extract → tag → enrich → summarize.
    Auto-stores to ARES evidence vault.
    """
    iocs = extract_iocs(text)
    for ioc in iocs:
        tag_ioc(ioc, campaign=campaign, actor=actor)

    if enrich:
        iocs = await bulk_enrich(iocs)

    by_type: dict[str, int] = {}
    for i in iocs:
        by_type[i.type] = by_type.get(i.type, 0) + 1

    result = {
        "total_iocs": len(iocs),
        "by_type": by_type,
        "iocs": iocs,
    }

    try:
        from aresx.enterprise import add_evidence
        add_evidence(
            source_tool="ares_red_ioc_engine",
            raw_data=json.dumps({
                "total_iocs": len(iocs), "by_type": by_type,
                "campaign": campaign, "actor": actor,
            }),
        )
    except Exception as exc:
        logger.debug("Vault store failed (non-critical): %s", exc)

    return result
