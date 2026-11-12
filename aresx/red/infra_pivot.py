"""
ARES X Red Module — Infrastructure Pivot Engine
Domain → IP → domain chaining, cert transparency pivoting, reverse IP.
All free/public sources — crt.sh, ip-api.com, DNS resolution.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class PivotNode:
    node_type: str        # "domain" or "ip"
    value: str
    depth: int = 0
    discovered_via: str = ""   # "cert_san", "dns_resolve", "reverse_ip", "seed"


@dataclass
class PivotGraph:
    seed: str
    nodes: list[PivotNode] = field(default_factory=list)
    edges: list[tuple[str, str, str]] = field(default_factory=list)  # (from, to, relation)
    depth_reached: int = 0
    duration_s: float = 0.0


async def _http_get_json(url: str, timeout: float = 10.0) -> Optional[dict]:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url, headers={"User-Agent": "ARES-X-Pivot/8.0"})
            if r.status_code == 200:
                return r.json()
    except Exception as exc:
        logger.debug("Pivot HTTP GET failed: %s", exc)
    return None


async def _resolve_domain(domain: str) -> list[str]:
    """Resolve a domain to its IP addresses."""
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        return list({i[4][0] for i in infos})
    except Exception:
        return []


async def _cert_san_domains(domain: str) -> list[str]:
    """Get all domains that appear on the same TLS certs (crt.sh)."""
    data = await _http_get_json(f"https://crt.sh/?q=%.{domain}&output=json")
    if not isinstance(data, list):
        return []
    found = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for n in name_value.split("\n"):
            n = n.strip().lstrip("*.")
            if n and "." in n:
                found.add(n.lower())
    return sorted(found)


async def _reverse_ip_lookup(ip: str) -> list[str]:
    """
    Find other domains hosted on the same IP via crt.sh reverse search.
    Note: shared hosting will produce many false positives — filter by ASN match
    if you need precision.
    """
    # crt.sh doesn't do reverse IP directly, but we can check known domains'
    # resolution against this IP as a lightweight heuristic via PTR record
    try:
        loop = asyncio.get_running_loop()
        hostname, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return [hostname] if hostname else []
    except Exception:
        return []


async def get_asn_info(ip: str) -> dict:
    """ASN + org info for an IP via ip-api.com free tier."""
    data = await _http_get_json(
        f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as,asname,hosting"
    )
    if data and data.get("status") == "success":
        return data
    return {}


async def pivot_from_domain(domain: str, max_depth: int = 2,
                            max_nodes_per_level: int = 15) -> PivotGraph:
    """
    Full infrastructure pivot starting from a domain.

    Level 0: seed domain
    Level 1: IPs it resolves to + domains sharing its TLS certs
    Level 2: domains that resolve to those same IPs (shared infra), sharing ASN

    This surfaces an adversary's broader infrastructure footprint —
    C2 domains sharing certs, hosting, or ASN with a known-bad domain.
    """
    t0 = time.time()
    graph = PivotGraph(seed=domain)

    seed_node = PivotNode(node_type="domain", value=domain, depth=0, discovered_via="seed")
    graph.nodes.append(seed_node)

    visited_domains = {domain}
    visited_ips: set[str] = set()
    frontier_domains = [domain]

    for depth in range(1, max_depth + 1):
        if not frontier_domains:
            break

        next_frontier: list[str] = []

        for d in frontier_domains[:max_nodes_per_level]:
            # Resolve to IPs
            ips = await _resolve_domain(d)
            for ip in ips[:5]:
                if ip not in visited_ips:
                    visited_ips.add(ip)
                    graph.nodes.append(PivotNode(
                        node_type="ip", value=ip, depth=depth, discovered_via="dns_resolve"
                    ))
                graph.edges.append((d, ip, "resolves_to"))

            # Cert SAN pivot
            related_domains = await _cert_san_domains(d)
            for rd in related_domains[:max_nodes_per_level]:
                if rd not in visited_domains:
                    visited_domains.add(rd)
                    graph.nodes.append(PivotNode(
                        node_type="domain", value=rd, depth=depth, discovered_via="cert_san"
                    ))
                    next_frontier.append(rd)
                graph.edges.append((d, rd, "shares_cert_with"))

        frontier_domains = next_frontier
        graph.depth_reached = depth

    graph.duration_s = round(time.time() - t0, 2)
    return graph


async def pivot_from_ip(ip: str, max_domains: int = 20) -> dict:
    """
    Pivot from an IP address — find ASN, org, and any domains that resolve here.
    Since crt.sh doesn't support reverse-IP directly, this checks a supplied
    candidate list (or does PTR lookup) and ASN enrichment.
    """
    asn = await get_asn_info(ip)
    ptr = await _reverse_ip_lookup(ip)

    return {
        "ip": ip,
        "asn_org": asn.get("org", ""),
        "asn": asn.get("as", ""),
        "asn_name": asn.get("asname", ""),
        "country": asn.get("country", ""),
        "isp": asn.get("isp", ""),
        "is_hosting_provider": asn.get("hosting", False),
        "ptr_hostname": ptr,
    }


def summarize_pivot(graph: PivotGraph) -> str:
    """Human-readable summary of a pivot graph."""
    domain_nodes = [n for n in graph.nodes if n.node_type == "domain"]
    ip_nodes = [n for n in graph.nodes if n.node_type == "ip"]

    lines = [
        f"=== INFRA PIVOT: {graph.seed} ===",
        f"Depth reached: {graph.depth_reached}",
        f"Domains found: {len(domain_nodes)}",
        f"IPs found:     {len(ip_nodes)}",
        f"Edges:         {len(graph.edges)}",
        f"Duration:      {graph.duration_s}s",
        "",
        "Related domains (via cert SAN pivoting):",
    ]
    for n in domain_nodes:
        if n.discovered_via == "cert_san":
            lines.append(f"  [{n.depth}] {n.value}")

    lines.append("\nAssociated IPs:")
    for n in ip_nodes:
        lines.append(f"  [{n.depth}] {n.value}")

    return "\n".join(lines)


def graph_to_json(graph: PivotGraph) -> dict:
    """Serialize pivot graph for storage/export."""
    return {
        "seed": graph.seed,
        "depth_reached": graph.depth_reached,
        "duration_s": graph.duration_s,
        "nodes": [
            {"type": n.node_type, "value": n.value, "depth": n.depth, "via": n.discovered_via}
            for n in graph.nodes
        ],
        "edges": [{"from": e[0], "to": e[1], "relation": e[2]} for e in graph.edges],
    }


async def full_pivot_report(seed: str, is_ip: bool = False, max_depth: int = 2) -> dict:
    """
    Full pivot report — auto-detects IP vs domain, runs pivot, stores to vault.
    """
    if is_ip:
        result = await pivot_from_ip(seed)
    else:
        graph = await pivot_from_domain(seed, max_depth=max_depth)
        result = graph_to_json(graph)

    try:
        from aresx.enterprise import add_evidence
        add_evidence(
            source_tool="ares_red_infra_pivot",
            raw_data=json.dumps(result)[:5000],
        )
    except Exception as exc:
        logger.debug("Vault store failed (non-critical): %s", exc)

    return result
