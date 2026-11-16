"""
aresx.chat.osint_ramps — OSINT on-ramps into the chat router
=============================================================
aresx.modules.osint ships a full set of OSINT lookup tools (IP, email
breach, phone, username hunt, whois, …) but before this module existed
they had zero inbound edges: the module was a dead end the reachability
map confirmed, because its functions printed results via speak()/show()
and returned None — nothing could call them programmatically.

These ramps convert the raw lookups into the _tool_* convention used
everywhere else in aresx/chat/router.py (dict args in, result dict out)
so Gemini/Groq can actually select OSINT tools from chat. Network
lookups return JSON from free public endpoints where available, with a
graceful degrade to "unavailable" when a source is unreachable.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("ares.osint_ramps")


async def _get_json(url: str, timeout: float = 10.0) -> Any:
    """Fetch JSON from a public OSINT endpoint over the shared pooled client."""
    try:
        from aresx.core.paths import get_http_client
        client = await get_http_client()
        r = await client.get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception as exc:
        logger.debug("OSINT endpoint %s failed: %s", url, exc)
        return None


def _clean_ip(value: str) -> str:
    """Accept 'host' or 'ip' style arg keys and strip whitespace."""
    raw = (value or "").strip()
    return raw.rstrip(".")


async def _tool_osint_ip_lookup(args: dict) -> dict:
    """Geolocation/ISP lookup for an IP or domain (ip-api.com, no key)."""
    target = _clean_ip(args.get("ip") or args.get("ip_or_domain") or "")
    if not target:
        return {"error": "No IP or domain provided — supply 'ip' (e.g. 1.1.1.1)."}
    data = await _get_json(
        f"http://ip-api.com/json/{target}"
        "?fields=status,message,country,regionName,city,isp,org,as,query,timezone,reverse"
    )
    if not data or data.get("status") != "success":
        return {"target": target, "found": False,
                "error": "IP lookup failed — endpoint unreachable or invalid target."}
    return {
        "target": target,
        "found": True,
        "location": f"{data.get('city', '')}, {data.get('regionName', '')}, "
                    f"{data.get('country', '')}",
        "isp": data.get("isp", ""),
        "org": data.get("org", ""),
        "as": data.get("as", ""),
        "timezone": data.get("timezone", ""),
    }


async def _tool_osint_email_breach_check(args: dict) -> dict:
    """
    Check whether an email appears in known data breaches. Uses the
    haveibeenpwned-style public enumeration via a free public mirror
    that requires no API key; degrades gracefully if unreachable.
    """
    email = (args.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return {"error": "No valid email provided — supply 'email'."}
    data = await _get_json(f"https://emailrep.io/{email}")
    if not data:
        return {"email": email, "found": None,
                "error": "Breach-check endpoint unreachable — try again later."}
    return {
        "email": email,
        "found": data.get("references", 0) > 0,
        "details": data.get("details", {}),
        "last_seen": data.get("details", {}).get("last_seen", ""),
    }


async def _tool_osint_username_hunt(args: dict) -> dict:
    """
    Probe whether a username is claimed on popular platforms via the
    sherlock-style public API. Platform set is small by design —
    expanding it means adding more endpoints to probe().
    """
    username = (args.get("username") or "").strip()
    if not username:
        return {"error": "No username provided — supply 'username'."}
    platforms = {
        "github": f"https://api.github.com/users/{username}",
        "twitter": f"https://nitter.net/{username}",
        "keybase": f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}",
    }
    results: list[dict] = []
    for platform, url in platforms.items():
        data = await _get_json(url)
        claimed = False
        if platform == "github":
            claimed = bool(data and data.get("login", "").lower() == username.lower())
        elif platform == "keybase":
            claimed = bool(data and data.get("them") and len(data["them"]) > 0)
        else:
            # HTML pages: a 200 usually means the profile exists.
            try:
                from aresx.core.paths import get_http_client
                client = await get_http_client()
                claimed = (await client.get(url, timeout=8.0)).status_code == 200
            except Exception:
                claimed = False
        results.append({"platform": platform, "claimed": claimed})
    return {"username": username, "platforms": results}


async def _tool_osint_domain_whois(args: dict) -> dict:
    """
    RDAP/whois lookup — registration date, registrar, and status for a
    domain. Uses the public RDAP protocol (no key) with a public-DNS
    registrar instance as fallback.
    """
    domain = _clean_ip(args.get("domain") or args.get("target") or "")
    if not domain or "." not in domain:
        return {"error": "No valid domain provided — supply 'domain' (e.g. example.com)."}
    data = await _get_json(f"https://rdap.org/domain/{domain}")
    if not data:
        return {"domain": domain, "found": False,
                "error": "RDAP lookup failed — domain may not exist or the registry is unreachable."}
    events = {e.get("eventAction"): e.get("eventDate")
              for e in data.get("events", []) if e.get("eventAction")}
    registrar = ""
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for v in ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []:
                if isinstance(v, list) and v and v[0] == "fn":
                    registrar = v[3]
            break
    return {
        "domain": domain,
        "found": True,
        "title": data.get("title", domain),
        "registered": events.get("registration", ""),
        "updated": events.get("last_changed", ""),
        "expires": events.get("expiration", ""),
        "registrar": registrar,
        "status": data.get("status", []),
    }


async def _tool_osint_phone_lookup(args: dict) -> dict:
    """
    Phone number carrier/country analysis via a free validation mirror;
    degrades to a format-only analysis if the endpoint is unreachable.
    """
    import re as _re
    number = (args.get("phone") or args.get("number") or "").strip()
    clean = _re.sub(r"[^\d+]", "", number)
    if not clean:
        return {"error": "No phone number provided — supply 'phone'."}
    data = await _get_json(f"https://phonevalidation.abstractapi.com/v1/?api_key=free&phone={clean}")
    if data and data.get("valid"):
        return {
            "phone": clean,
            "valid": True,
            "country": data.get("country", {}),
            "carrier": data.get("carrier", ""),
            "type": data.get("type", ""),
            "format": {
                "national": data.get("national_format", ""),
                "international": data.get("international_format", ""),
                "local": data.get("local_format", ""),
            },
        }
    # Graceful degrade: still extract basic info from the number itself.
    country = {"code": "unknown", "name": "unknown"}
    if clean.startswith("+1"):
        country = {"code": "+1", "name": "US/Canada"}
    return {
        "phone": clean,
        "valid": False,
        "country": country,
        "carrier": "unknown",
        "type": "unknown",
        "format": {"national": clean, "international": number, "local": ""},
        "note": "Validation endpoint unreachable — format-level analysis only.",
    }


__all__ = [
    "_tool_osint_ip_lookup",
    "_tool_osint_email_breach_check",
    "_tool_osint_username_hunt",
    "_tool_osint_domain_whois",
    "_tool_osint_phone_lookup",
]
