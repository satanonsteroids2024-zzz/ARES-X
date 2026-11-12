"""
ARES X Red Module — Threat Actor Profiler
Profile threat actors by TTPs, known infrastructure, and targeting patterns.
Enriches via AlienVault OTX (free) and MITRE ATT&CK groups data (free, public).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Known threat actor seed data (MITRE ATT&CK groups — public domain) ───────
# Source: attack.mitre.org/groups — free public knowledge base

_KNOWN_ACTORS: dict[str, dict] = {
    "APT29": {
        "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard", "NOBELIUM"],
        "attributed_to": "Russia (SVR)",
        "first_seen": "2008",
        "known_ttps": ["T1566.001", "T1078", "T1195.002", "T1053.005", "T1027"],
        "targets": ["Government", "Think tanks", "Healthcare", "Energy"],
        "motivation": "Espionage",
        "notable_campaigns": ["SolarWinds supply chain attack", "COVID-19 vaccine research targeting"],
    },
    "APT28": {
        "aliases": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
        "attributed_to": "Russia (GRU)",
        "first_seen": "2004",
        "known_ttps": ["T1566.002", "T1110", "T1074", "T1105", "T1071.001"],
        "targets": ["Government", "Military", "Media", "Political organizations"],
        "motivation": "Espionage",
        "notable_campaigns": ["DNC hack 2016", "IOC 2018 targeting"],
    },
    "Lazarus Group": {
        "aliases": ["Hidden Cobra", "Guardians of Peace", "ZINC"],
        "attributed_to": "North Korea",
        "first_seen": "2009",
        "known_ttps": ["T1566.001", "T1204.002", "T1486", "T1027", "T1055"],
        "targets": ["Financial institutions", "Cryptocurrency exchanges", "Defense"],
        "motivation": "Financial gain, Espionage",
        "notable_campaigns": ["Sony Pictures hack", "WannaCry", "Bangladesh Bank heist"],
    },
    "FIN7": {
        "aliases": ["Carbanak Group", "Navigator Group"],
        "attributed_to": "Financially motivated (unattributed nation-state)",
        "first_seen": "2013",
        "known_ttps": ["T1566.001", "T1204.002", "T1055", "T1027", "T1071.001"],
        "targets": ["Retail", "Restaurant", "Hospitality"],
        "motivation": "Financial gain",
        "notable_campaigns": ["POS malware campaigns targeting retail chains"],
    },
    "APT41": {
        "aliases": ["Double Dragon", "Barium", "Winnti"],
        "attributed_to": "China",
        "first_seen": "2012",
        "known_ttps": ["T1195.002", "T1078", "T1027", "T1071.001", "T1053.005"],
        "targets": ["Healthcare", "Telecom", "Technology", "Video games"],
        "motivation": "Espionage, Financial gain",
        "notable_campaigns": ["Supply chain attacks", "Healthcare data theft"],
    },
}


@dataclass
class ActorProfile:
    name: str
    aliases: list[str] = field(default_factory=list)
    attributed_to: str = ""
    first_seen: str = ""
    known_ttps: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    motivation: str = ""
    notable_campaigns: list[str] = field(default_factory=list)
    recent_pulses: list[dict] = field(default_factory=list)
    confidence: str = "public_reference"  # vs "osint_enriched"


async def _http_get_json(url: str, timeout: float = 10.0) -> Optional[dict]:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            if r.status_code == 200:
                return r.json()
    except Exception as exc:
        logger.debug("Actor profile fetch failed: %s", exc)
    return None


def get_known_actor(name: str) -> Optional[ActorProfile]:
    """
    Look up a known threat actor from the built-in MITRE ATT&CK-sourced database.
    Matches on name or any alias, case-insensitive.
    """
    name_lower = name.lower().strip()

    for actor_name, data in _KNOWN_ACTORS.items():
        if actor_name.lower() == name_lower:
            return ActorProfile(name=actor_name, **data)
        for alias in data.get("aliases", []):
            if alias.lower() == name_lower:
                return ActorProfile(name=actor_name, **data)

    return None


def search_actors_by_ttp(technique_id: str) -> list[ActorProfile]:
    """Find all known actors that use a specific ATT&CK technique."""
    technique_id = technique_id.upper()
    matches = []
    for actor_name, data in _KNOWN_ACTORS.items():
        if technique_id in data.get("known_ttps", []):
            matches.append(ActorProfile(name=actor_name, **data))
    return matches


def search_actors_by_target(sector: str) -> list[ActorProfile]:
    """Find all known actors that target a specific sector (e.g. 'Healthcare')."""
    sector_lower = sector.lower()
    matches = []
    for actor_name, data in _KNOWN_ACTORS.items():
        if any(sector_lower in t.lower() for t in data.get("targets", [])):
            matches.append(ActorProfile(name=actor_name, **data))
    return matches


async def enrich_actor_otx(actor_name: str) -> list[dict]:
    """
    Enrich actor profile with recent AlienVault OTX pulses (free, no key
    required for basic search).
    """
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                "https://otx.alienvault.com/api/v1/search/pulses",
                params={"q": actor_name, "limit": 5},
            )
            if r.status_code == 200:
                pulses = r.json().get("results", [])
                return [
                    {
                        "name": p.get("name"),
                        "created": p.get("created"),
                        "tags": p.get("tags", [])[:5],
                        "tlp": p.get("TLP", ""),
                    }
                    for p in pulses
                ]
    except Exception as exc:
        logger.debug("OTX enrichment failed: %s", exc)
    return []


async def profile_actor(name: str, enrich: bool = True) -> ActorProfile:
    """
    Full actor profiling — checks known database first, then enriches with
    live OTX pulse data if requested.
    """
    profile = get_known_actor(name)
    if not profile:
        profile = ActorProfile(name=name, confidence="unknown_actor")

    if enrich:
        pulses = await enrich_actor_otx(name)
        profile.recent_pulses = pulses
        if pulses:
            profile.confidence = "osint_enriched"

    try:
        from aresx.enterprise import add_evidence
        add_evidence(
            source_tool="ares_red_threat_actor",
            raw_data=json.dumps({
                "actor": profile.name,
                "ttps": profile.known_ttps,
                "pulses_found": len(profile.recent_pulses),
            }),
        )
    except Exception as exc:
        logger.debug("Vault store failed (non-critical): %s", exc)

    return profile


def list_known_actors() -> list[str]:
    """List all actors in the built-in database."""
    return list(_KNOWN_ACTORS.keys())


def actor_summary(profile: ActorProfile) -> str:
    """Human-readable actor profile summary."""
    lines = [
        f"=== THREAT ACTOR: {profile.name} ===",
        f"Aliases:      {', '.join(profile.aliases) or 'none known'}",
        f"Attribution:  {profile.attributed_to or 'unknown'}",
        f"First seen:   {profile.first_seen or 'unknown'}",
        f"Motivation:   {profile.motivation or 'unknown'}",
        f"Targets:      {', '.join(profile.targets) or 'unknown'}",
        f"Known TTPs:   {', '.join(profile.known_ttps) or 'none catalogued'}",
        f"Confidence:   {profile.confidence}",
    ]
    if profile.notable_campaigns:
        lines.append("\nNotable campaigns:")
        for c in profile.notable_campaigns:
            lines.append(f"  - {c}")
    if profile.recent_pulses:
        lines.append(f"\nRecent OTX pulses ({len(profile.recent_pulses)}):")
        for p in profile.recent_pulses[:5]:
            lines.append(f"  - {p['name']} ({p['created'][:10]})")
    return "\n".join(lines)
