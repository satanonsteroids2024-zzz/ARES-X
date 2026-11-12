"""
ARES X v8 TITAN — Red Module: Active Recon Engine
Phase 13: Hollow Purple

Pure-Python recon — no external tool dependencies required.
Capabilities:
  - Subdomain enumeration (brute force + cert transparency)
  - Port scanning + banner grabbing (async TCP, no nmap required)
  - ASN / IP org mapping
  - Web technology fingerprinting
  - WAF detection
  - Email harvesting (crt.sh + DDG)
  - S3 bucket enumeration
  - JavaScript endpoint extraction
  - HTTP security header analysis
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
    "mx", "mx1", "mx2", "vpn", "remote", "api", "dev", "staging", "test",
    "beta", "admin", "portal", "dashboard", "app", "apps", "mobile", "m",
    "static", "cdn", "assets", "media", "img", "images", "video", "docs",
    "wiki", "blog", "shop", "store", "pay", "payment", "checkout", "secure",
    "login", "auth", "sso", "oauth", "git", "gitlab", "github", "jenkins",
    "ci", "cd", "build", "deploy", "prod", "production", "internal", "intra",
    "intranet", "corp", "corporate", "employee", "hr", "finance", "accounting",
    "help", "support", "helpdesk", "ticket", "jira", "confluence", "notion",
    "monitor", "nagios", "zabbix", "grafana", "kibana", "elastic", "splunk",
    "db", "database", "mysql", "postgres", "mongo", "redis", "cache", "backup",
    "files", "upload", "download", "share", "sharepoint", "office", "outlook",
    "exchange", "mail2", "email", "webdav", "owa", "autodiscover",
    "cloud", "aws", "azure", "gcp", "s3", "storage", "blob", "bucket",
    "sandbox", "qa", "uat", "preprod", "demo", "preview", "new", "old",
    "legacy", "v1", "v2", "v3", "api2", "api3", "rest", "graphql", "ws",
]

_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 631,
    993, 995, 1433, 1521, 1723, 2049, 2121, 2222, 3000, 3306, 3389, 4443,
    5000, 5432, 5900, 5984, 6379, 6443, 7001, 7443, 8000, 8008, 8080,
    8081, 8443, 8888, 9000, 9090, 9200, 9300, 9443, 27017, 27018,
]

_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    587: "SMTP/TLS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2222: "SSH-alt", 3000: "Dev", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    7001: "WebLogic", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}

_WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare":  ["cf-ray", "__cfduid", "cloudflare", "cf-cache-status"],
    "AWS WAF":     ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
    "Akamai":      ["akamai", "ak-bmsc", "x-check-cacheable"],
    "Imperva":     ["incap_ses", "visid_incap", "x-iinfo", "incapsula"],
    "F5 BIG-IP":   ["bigipserver", "f5-ltm"],
    "Fortinet":    ["fortigate", "fortiweb", "x-waf-event-info"],
    "Sucuri":      ["sucuri-cache", "x-sucuri-id"],
    "ModSecurity": ["mod_security", "modsecurity", "x-modsec"],
    "Barracuda":   ["barra_counter_session", "barracudassl"],
}

_TECH_SIGNATURES: dict[str, list[str]] = {
    "nginx": ["nginx"], "Apache": ["apache", "mod_"],
    "IIS": ["microsoft-iis", "x-aspnet-version"],
    "Cloudflare": ["cloudflare"],
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Drupal": ["drupal", "x-generator: drupal"],
    "Joomla": ["joomla", "/components/com_"],
    "React": ["react", "__next", "_next/static"],
    "Angular": ["ng-version", "angular"],
    "Vue.js": ["__vue__", "vue.js"],
    "Laravel": ["laravel_session"],
    "Django": ["csrfmiddlewaretoken"],
    "Express": ["x-powered-by: express"],
    "FastAPI": ["x-process-time", "fastapi"],
    "Tomcat": ["apache-coyote", "jsessionid"],
    "Spring": ["x-application-context"],
    "ASP.NET": ["x-aspnet-version", "x-aspnetmvc-version", "viewstate"],
    "PHP": ["x-powered-by: php", "phpsessid"],
}

_SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "x-xss-protection", "cross-origin-embedder-policy", "cross-origin-opener-policy",
]


@dataclass
class OpenPort:
    port: int
    service: str
    banner: str = ""
    tls: bool = False


@dataclass
class ReconResult:
    target: str
    subdomains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    asn_info: dict = field(default_factory=dict)
    open_ports: list[OpenPort] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    waf: Optional[str] = None
    email_harvested: list[str] = field(default_factory=list)
    s3_buckets: list[dict] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    security_headers: dict = field(default_factory=dict)
    headers_raw: dict = field(default_factory=dict)
    scan_duration_s: float = 0.0
    timestamp: float = field(default_factory=time.time)


def _strip_scheme(target: str) -> str:
    target = target.strip()
    for scheme in ("https://", "http://", "ftp://"):
        if target.startswith(scheme):
            target = target[len(scheme):]
    return target.split("/")[0].split("?")[0].split(":")[0]


async def _resolve(domain: str) -> list[str]:
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        return list({i[4][0] for i in infos})
    except Exception:
        return []


async def _tcp_connect(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        if port in (443, 8443, 4443, 9443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        if port in (80, 8080, 8000, 8008):
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


async def _http_fetch(url: str, timeout: float = 6.0) -> tuple[int, dict, str]:
    try:
        import httpx
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, verify=False,
        ) as client:
            r = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (ARES-X-Recon/8.0)"})
            return r.status_code, dict(r.headers), r.text[:4000]
    except ImportError:
        pass
    except Exception:
        return 0, {}, ""

    try:
        import urllib.request as ur
        loop = asyncio.get_running_loop()

        def _get():
            req = ur.Request(url, headers={"User-Agent": "Mozilla/5.0 (ARES-X-Recon/8.0)"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ur.urlopen(req, timeout=timeout, context=ctx) as resp:
                hdrs = dict(resp.headers)
                body = resp.read(4000).decode("utf-8", errors="replace")
                return resp.status, hdrs, body

        return await loop.run_in_executor(None, _get)
    except Exception:
        return 0, {}, ""


async def _crt_sh_subdomains(domain: str) -> list[str]:
    try:
        status, _, body = await _http_fetch(
            f"https://crt.sh/?q=%.{domain}&output=json", timeout=10.0
        )
        if status == 200 and body:
            entries = json.loads(body)
            found = set()
            for e in entries:
                name = e.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(f".{domain}") or n == domain:
                        found.add(n.lower())
            return sorted(found)
    except Exception as exc:
        logger.debug("crt.sh failed: %s", exc)
    return []


async def _brute_subdomains(domain: str, wordlist: Optional[list[str]] = None,
                             concurrency: int = 50) -> list[str]:
    words = wordlist or _SUBDOMAIN_WORDLIST
    found: list[str] = []
    sem = asyncio.Semaphore(concurrency)

    async def check(word: str) -> None:
        subdomain = f"{word}.{domain}"
        async with sem:
            ips = await _resolve(subdomain)
            if ips:
                found.append(subdomain)

    await asyncio.gather(*[check(w) for w in words], return_exceptions=True)
    return sorted(found)


async def enumerate_subdomains(domain: str, brute: bool = True,
                                cert_transparency: bool = True) -> list[str]:
    """Full subdomain enumeration: cert transparency (passive) + DNS brute force (active)."""
    results: set[str] = set()
    tasks = []
    if cert_transparency:
        tasks.append(_crt_sh_subdomains(domain))
    if brute:
        tasks.append(_brute_subdomains(domain))
    for batch in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(batch, list):
            results.update(batch)
    return sorted(results)


async def port_scan(host: str, ports: Optional[list[int]] = None,
                    concurrency: int = 100, grab_banners: bool = True,
                    timeout: float = 1.5) -> list[OpenPort]:
    """Async TCP port scanner — pure Python, no nmap required."""
    target_ports = ports or _COMMON_PORTS
    sem = asyncio.Semaphore(concurrency)
    open_ports: list[OpenPort] = []

    async def scan_port(port: int) -> None:
        async with sem:
            is_open = await _tcp_connect(host, port, timeout)
            if is_open:
                tls = port in (443, 8443, 4443, 9443, 465, 993, 995)
                banner = ""
                if grab_banners:
                    banner = await _grab_banner(host, port, timeout * 1.5)
                open_ports.append(OpenPort(
                    port=port, service=_SERVICE_MAP.get(port, "unknown"),
                    banner=banner, tls=tls,
                ))

    await asyncio.gather(*[scan_port(p) for p in target_ports], return_exceptions=True)
    return sorted(open_ports, key=lambda p: p.port)


async def get_asn_info(ip: str) -> dict:
    """ASN + org info for an IP via ip-api.com free tier (45 req/min)."""
    try:
        status, _, body = await _http_fetch(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,"
            f"regionName,city,isp,org,as,asname,hosting", timeout=5.0
        )
        if status == 200 and body:
            data = json.loads(body)
            if data.get("status") == "success":
                return data
    except Exception as exc:
        logger.debug("ASN lookup failed: %s", exc)
    return {}


def detect_waf(headers: dict, body: str) -> Optional[str]:
    """Fingerprint WAF from HTTP response headers + body."""
    combined = " ".join(list(headers.keys()) + list(headers.values()) + [body[:500]]).lower()
    for waf_name, sigs in _WAF_SIGNATURES.items():
        if any(sig.lower() in combined for sig in sigs):
            return waf_name
    return None


def fingerprint_tech(headers: dict, body: str) -> list[str]:
    """Identify web technologies from response headers + HTML body."""
    combined = " ".join(list(headers.keys()) + list(headers.values()) + [body[:2000]]).lower()
    detected: list[str] = []
    for tech, sigs in _TECH_SIGNATURES.items():
        if any(sig.lower() in combined for sig in sigs):
            detected.append(tech)
    return list(dict.fromkeys(detected))


def analyze_security_headers(headers: dict) -> dict:
    """Check for presence/absence of security headers."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    result = {h: headers_lower.get(h) for h in _SECURITY_HEADERS}
    missing = [h for h, v in result.items() if v is None]
    result["_missing_count"] = len(missing)
    result["_missing"] = missing
    return result


async def enumerate_s3_buckets(domain: str) -> list[dict]:
    """Check common S3 bucket naming patterns for public access."""
    base = domain.replace(".", "-").replace("_", "-")
    company = base.split("-")[0]
    patterns = [
        base, company, f"{company}-prod", f"{company}-dev", f"{company}-staging",
        f"{company}-backup", f"{company}-data", f"{company}-assets",
        f"{company}-media", f"{company}-static", f"{company}-public",
        f"{company}-private", f"{company}-internal", f"{company}-files",
        f"{company}-uploads", f"{company}-logs", f"{base}-prod", f"{base}-dev",
        f"{base}-data", f"{base}-assets", f"{base}-files", f"{base}-backup",
    ]
    found: list[dict] = []
    sem = asyncio.Semaphore(20)

    async def check(bucket: str) -> None:
        async with sem:
            url = f"https://{bucket}.s3.amazonaws.com/"
            status, headers, body = await _http_fetch(url, timeout=4.0)
            if status in (200, 301, 302, 403):
                public = status == 200 and "<ListBucketResult" in body
                found.append({
                    "bucket": bucket, "url": url, "status": status, "public": public,
                    "note": "PUBLICLY READABLE" if public else
                            "EXISTS (forbidden)" if status == 403 else
                            "redirects" if status in (301, 302) else "exists",
                })

    await asyncio.gather(*[check(p) for p in patterns], return_exceptions=True)
    return found


async def extract_js_endpoints(base_url: str) -> list[str]:
    """Crawl a page's JS files and extract API endpoints / paths."""
    status, headers, body = await _http_fetch(base_url, timeout=8.0)
    if not body:
        return []

    endpoints: set[str] = set()
    js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body)
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for pattern in [
        r'["\']/(api|v\d+|graphql|admin|internal|auth|oauth|rest)[^"\'<> ]{0,100}["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'url:\s*["\']([^"\']+)["\']',
    ]:
        for match in re.findall(pattern, body, re.IGNORECASE):
            if isinstance(match, tuple):
                match = "/" + match[0] if not match[0].startswith("/") else match[0]
            endpoints.add(match)

    sem = asyncio.Semaphore(10)

    async def parse_js(js_url: str) -> None:
        async with sem:
            if not js_url.startswith("http"):
                js_url = base + js_url if js_url.startswith("/") else base + "/" + js_url
            _, _, js_body = await _http_fetch(js_url, timeout=5.0)
            for pattern in [
                r'["\`]/([\w\-/]+(?:api|v\d+|graphql|admin|auth)[\w\-/]*)["\`]',
                r'path:\s*["\`]([/\w\-{}:]+)["\`]',
                r'route:\s*["\`]([/\w\-{}:]+)["\`]',
            ]:
                for m in re.findall(pattern, js_body, re.IGNORECASE):
                    endpoints.add("/" + m.lstrip("/"))

    await asyncio.gather(*[parse_js(j) for j in js_files[:20]], return_exceptions=True)
    return sorted(endpoints)[:200]


async def harvest_emails(domain: str) -> list[str]:
    """Harvest email addresses via crt.sh cert subjects + DDG dork."""
    found: set[str] = set()
    email_pattern = re.compile(
        r'\b[A-Za-z0-9._%+\-]+@' + re.escape(domain) + r'\b', re.IGNORECASE
    )

    status, _, body = await _http_fetch(f"https://crt.sh/?q={domain}&output=json", timeout=8.0)
    if body:
        try:
            entries = json.loads(body)
            for e in entries:
                for field_val in [e.get("issuer_name", ""), e.get("name_value", "")]:
                    for match in email_pattern.findall(field_val):
                        found.add(match.lower())
        except Exception:
            pass

    for query_url in [
        f"https://html.duckduckgo.com/html/?q=site:{domain}+email",
        f"https://html.duckduckgo.com/html/?q=%40{domain}+contact",
    ]:
        status, _, body = await _http_fetch(query_url, timeout=6.0)
        for match in email_pattern.findall(body):
            found.add(match.lower())

    return sorted(found)


async def full_recon(target: str,
                     scan_ports: bool = True,
                     enum_subs: bool = True,
                     check_s3: bool = True,
                     extract_js: bool = True,
                     harvest_email: bool = True,
                     port_list: Optional[list[int]] = None) -> ReconResult:
    """
    Full recon orchestrator — runs all recon tasks concurrently.
    Auto-wires results into ARES evidence vault.
    """
    t0 = time.time()
    domain = _strip_scheme(target)
    result = ReconResult(target=domain)

    result.ips = await _resolve(domain)
    logger.info("[Recon] %s → IPs: %s", domain, result.ips)

    tasks: dict[str, Any] = {}
    if enum_subs:
        tasks["subs"] = enumerate_subdomains(domain)
    if scan_ports and result.ips:
        tasks["ports"] = port_scan(result.ips[0], ports=port_list)
    if check_s3:
        tasks["s3"] = enumerate_s3_buckets(domain)
    if extract_js:
        tasks["js"] = extract_js_endpoints(f"https://{domain}")
    if harvest_email:
        tasks["email"] = harvest_emails(domain)

    tasks["http_https"] = _http_fetch(f"https://{domain}", timeout=8.0)
    tasks["http_http"] = _http_fetch(f"http://{domain}", timeout=8.0)
    if result.ips:
        tasks["asn"] = get_asn_info(result.ips[0])

    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    task_results = dict(zip(tasks.keys(), gathered))

    if "subs" in task_results and isinstance(task_results["subs"], list):
        result.subdomains = task_results["subs"]
    if "ports" in task_results and isinstance(task_results["ports"], list):
        result.open_ports = task_results["ports"]
    if "s3" in task_results and isinstance(task_results["s3"], list):
        result.s3_buckets = task_results["s3"]
    if "js" in task_results and isinstance(task_results["js"], list):
        result.js_endpoints = task_results["js"]
    if "email" in task_results and isinstance(task_results["email"], list):
        result.email_harvested = task_results["email"]
    if "asn" in task_results and isinstance(task_results["asn"], dict):
        result.asn_info = task_results["asn"]

    for key in ("http_https", "http_http"):
        if key in task_results and isinstance(task_results[key], tuple):
            status, headers, body = task_results[key]
            if status > 0:
                result.headers_raw = headers
                result.technologies = fingerprint_tech(headers, body)
                result.waf = detect_waf(headers, body)
                result.security_headers = analyze_security_headers(headers)
                break

    result.scan_duration_s = round(time.time() - t0, 2)

    try:
        from aresx.enterprise import add_evidence
        add_evidence(
            source_tool="ares_red_recon",
            raw_data=json.dumps({
                "target": domain, "ips": result.ips,
                "subdomains": result.subdomains[:20],
                "open_ports": [{"port": p.port, "service": p.service} for p in result.open_ports],
                "technologies": result.technologies, "waf": result.waf,
                "s3_public": [b for b in result.s3_buckets if b.get("public")],
                "email_count": len(result.email_harvested),
                "scan_duration_s": result.scan_duration_s,
            }),
        )
    except Exception as exc:
        logger.debug("Vault store failed (non-critical): %s", exc)

    logger.info(
        "[Recon] %s done in %.1fs — %d subs, %d ports, %d techs, WAF=%s",
        domain, result.scan_duration_s, len(result.subdomains),
        len(result.open_ports), len(result.technologies), result.waf,
    )
    return result


def recon_summary(result: ReconResult) -> str:
    """Human-readable summary of a ReconResult."""
    lines = [
        f"=== RECON: {result.target} ===",
        f"IPs:         {', '.join(result.ips) or 'none resolved'}",
        f"ASN:         {result.asn_info.get('org', 'unknown')} / {result.asn_info.get('as', '')}",
        f"Subdomains:  {len(result.subdomains)} found",
        f"Open ports:  {', '.join(str(p.port) for p in result.open_ports) or 'none'}",
        f"Tech stack:  {', '.join(result.technologies) or 'unknown'}",
        f"WAF:         {result.waf or 'not detected'}",
        f"S3 buckets:  {len(result.s3_buckets)} patterns checked, "
        f"{sum(1 for b in result.s3_buckets if b.get('public'))} public",
        f"Emails:      {len(result.email_harvested)} harvested",
        f"JS endpoints:{len(result.js_endpoints)} extracted",
        f"Missing sec headers: {result.security_headers.get('_missing_count', 'n/a')}",
        f"Scan time:   {result.scan_duration_s}s",
    ]
    if result.open_ports:
        lines.append("\nOpen ports detail:")
        for p in result.open_ports:
            tls_str = " [TLS]" if p.tls else ""
            banner_str = f" | {p.banner[:60]}" if p.banner else ""
            lines.append(f"  {p.port:5d}  {p.service:<15}{tls_str}{banner_str}")
    return "\n".join(lines)
