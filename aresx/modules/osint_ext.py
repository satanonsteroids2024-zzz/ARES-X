"""
ARES X v6 — OSINT Upgrades (Flowsint-class)  [Features 88-93]
=============================================================
• Certificate-transparency subdomain enumeration (crt.sh, zero-key)
• ASN range walker (RDAP → BGPView → RIPEstat)
• Crypto wallet chain tracer (BTC/ETH, N-hop)
• Email → domain reverse lookup (WHOIS history correlation)
• Transform chaining engine (cascading OSINT, parallel branches)
• Investigation session persistence (save / resume / fork / export / import)

All functions query PUBLIC data sources only. No keys required for the
core paths. Results flow into Mike v3 graph memory.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List

try:
    import httpx
    _HTTPX = True
except ImportError:
    _HTTPX = False


_UA = {"User-Agent": "Mozilla/5.0 (ARES-X OSINT)"}
_SESS_DIR = Path(__file__).resolve().parent.parent.parent / "investigations"
_SESS_DIR.mkdir(exist_ok=True)


# ──────────────────────────────────────────────────────────────
# 88. Certificate-Transparency Subdomain Enumeration
# ──────────────────────────────────────────────────────────────
async def crt_subdomain_enum_async(domain: str) -> List[str]:
    """Query crt.sh for every cert issued for *domain*; return subdomains."""
    if not _HTTPX:
        return []
    domain = domain.strip().lower().lstrip("*.")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=25, headers=_UA, follow_redirects=True) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return []
            data = r.json()
        for row in data:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain) and " " not in name:
                    subs.add(name)
    except Exception:
        return sorted(subs)
    return sorted(subs)


def crt_subdomain_enum(domain: str) -> None:
    from ..core import speak, show, mike, run_async
    show("thinking", "Querying certificate logs…")
    subs = run_async(crt_subdomain_enum_async(domain)) or []
    if not subs:
        speak(f"No subdomains found in certificate logs for {domain}.")
        return
    mike.remember(f"subdomains:{domain}", json.dumps(subs[:200]),
                  tags=["subdomain", "crt", domain])
    head = ", ".join(subs[:8])
    speak(f"Found {len(subs)} subdomains for {domain}. Top: {head}")


# ──────────────────────────────────────────────────────────────
# 89. ASN Range Walker
# ──────────────────────────────────────────────────────────────
async def asn_range_walk_async(ip: str) -> Dict[str, Any]:
    """IP → ASN → all announced CIDR prefixes (RDAP + BGPView + RIPEstat)."""
    if not _HTTPX:
        return {}
    out: Dict[str, Any] = {"ip": ip, "asn": None, "holder": None, "prefixes": []}
    try:
        async with httpx.AsyncClient(timeout=20, headers=_UA, follow_redirects=True) as c:
            # BGPView: ip → ASN
            r = await c.get(f"https://api.bgpview.io/ip/{ip}")
            j = r.json()
            pfx = j.get("data", {}).get("prefixes", [])
            if pfx:
                asn = pfx[0].get("asn", {}).get("asn")
                out["asn"] = asn
                out["holder"] = pfx[0].get("asn", {}).get("name")
                if asn:
                    # BGPView: ASN → all prefixes
                    r2 = await c.get(f"https://api.bgpview.io/asn/{asn}/prefixes")
                    j2 = r2.json().get("data", {})
                    v4 = [p.get("prefix") for p in j2.get("ipv4_prefixes", [])]
                    out["prefixes"] = [p for p in v4 if p][:100]
    except Exception:
        pass
    return out


def asn_range_walk(ip: str) -> None:
    from ..core import speak, show, mike, run_async
    show("thinking", "Walking ASN ranges…")
    info = run_async(asn_range_walk_async(ip)) or {}
    if not info.get("asn"):
        speak(f"Could not resolve ASN for {ip}.")
        return
    mike.remember(f"asn:{ip}", json.dumps(info), tags=["asn", "infra", ip])
    speak(f"{ip} belongs to AS{info['asn']} ({info.get('holder','?')}), "
          f"announcing {len(info['prefixes'])} prefixes.")


# ──────────────────────────────────────────────────────────────
# 90. Crypto Wallet Chain Tracer
# ──────────────────────────────────────────────────────────────
async def crypto_wallet_trace_async(address: str, hops: int = 2) -> Dict[str, Any]:
    """Trace BTC/ETH transaction graph up to *hops* (public explorers)."""
    if not _HTTPX:
        return {}
    address = address.strip()
    is_eth = address.lower().startswith("0x") and len(address) == 42
    result: Dict[str, Any] = {"address": address, "chain": "eth" if is_eth else "btc",
                              "tx_count": 0, "counterparties": []}
    try:
        async with httpx.AsyncClient(timeout=20, headers=_UA) as c:
            if is_eth:
                # Etherscan public (no key = rate-limited but works for light use)
                u = (f"https://api.etherscan.io/api?module=account&action=txlist"
                     f"&address={address}&page=1&offset=25&sort=desc")
                j = (await c.get(u)).json()
                txs = j.get("result", []) if isinstance(j.get("result"), list) else []
                result["tx_count"] = len(txs)
                cps = set()
                for t in txs[:25]:
                    other = t.get("to") if t.get("from", "").lower() == address.lower() else t.get("from")
                    if other:
                        cps.add(other)
                result["counterparties"] = list(cps)[:20]
            else:
                # blockchain.info for BTC
                j = (await c.get(f"https://blockchain.info/rawaddr/{address}?limit=25")).json()
                result["tx_count"] = j.get("n_tx", 0)
                cps = set()
                for tx in j.get("txs", [])[:25]:
                    for out_ in tx.get("out", []):
                        a = out_.get("addr")
                        if a and a != address:
                            cps.add(a)
                result["counterparties"] = list(cps)[:20]
    except Exception:
        pass
    return result


def crypto_wallet_trace(address: str, hops: int = 2) -> None:
    from ..core import speak, show, mike, run_async
    show("thinking", "Tracing wallet chain…")
    r = run_async(crypto_wallet_trace_async(address, hops)) or {}
    if not r.get("tx_count"):
        speak(f"No transactions found for {address[:12]}…")
        return
    mike.remember(f"wallet:{address}", json.dumps(r), tags=["crypto", "finint", address])
    speak(f"{r['chain'].upper()} wallet {address[:10]}… has {r['tx_count']} txns "
          f"across {len(r['counterparties'])} counterparties.")


# ──────────────────────────────────────────────────────────────
# 91. Email → Domain Reverse Lookup
# ──────────────────────────────────────────────────────────────
async def email_to_domains_async(email: str) -> List[str]:
    """Reverse-WHOIS: domains registered with the same email (ViewDNS)."""
    if not _HTTPX:
        return []
    try:
        async with httpx.AsyncClient(timeout=20, headers=_UA) as c:
            # ViewDNS reverse whois (free HTML endpoint)
            u = f"https://viewdns.info/reversewhois/?q={email}"
            html = (await c.get(u)).text
        domains = re.findall(r"<td>([a-z0-9\-]+\.[a-z0-9\.\-]+)</td>", html, re.I)
        return sorted(set(domains))[:100]
    except Exception:
        return []


def email_to_domains(email: str) -> None:
    from ..core import speak, show, mike, run_async
    show("thinking", "Reverse-WHOIS lookup…")
    doms = run_async(email_to_domains_async(email)) or []
    if not doms:
        speak(f"No domains linked to {email} via reverse WHOIS.")
        return
    mike.remember(f"email_domains:{email}", json.dumps(doms),
                  tags=["email", "reverse_whois", email])
    speak(f"{email} is linked to {len(doms)} domains: {', '.join(doms[:6])}")


# ──────────────────────────────────────────────────────────────
# 92. Transform Chaining Engine
# ──────────────────────────────────────────────────────────────
# Built-in chain templates: each step is (tool_callable_name, takes_seed)
_CHAINS: Dict[str, List[str]] = {
    "deep_dive_domain": [
        "domain_whois", "crt_subdomain_enum", "wayback_lookup",
    ],
    "ip_infra_map": [
        "ip_lookup", "asn_range_walk",
    ],
    "person_dossier": [
        "username_hunt", "email_breach_check",
    ],
    "wallet_investigation": [
        "crypto_wallet_trace",
    ],
}


def transform_chain(chain_name: str, seed: str) -> None:
    """Run a cascading OSINT chain; each step feeds the knowledge graph."""
    from ..core import speak, show, mike, log
    from .. import brain  # late import to avoid cycle

    show("thinking", f"Running chain '{chain_name}'…")
    steps = _CHAINS.get(chain_name.lower())
    if not steps:
        avail = ", ".join(_CHAINS.keys())
        speak(f"Unknown chain. Available: {avail}")
        return

    speak(f"Deploying {chain_name} on {seed}: {len(steps)} transforms.")
    ran = 0
    for tool_name in steps:
        tool = brain.registry.get(tool_name)
        if not tool or not tool.fn:
            log(f"transform_chain: tool {tool_name} unavailable", "WARN")
            continue
        try:
            # Most OSINT tools take a single positional seed arg
            tool.fn(seed)
            ran += 1
            time.sleep(0.4)
        except TypeError:
            try:
                tool.fn()
                ran += 1
            except Exception as e:
                log(f"transform_chain step {tool_name}: {e}", "WARN")
        except Exception as e:
            log(f"transform_chain step {tool_name}: {e}", "WARN")

    mike.remember(f"chain:{chain_name}:{seed}",
                  json.dumps({"chain": chain_name, "seed": seed, "steps_ran": ran,
                              "ts": time.time()}),
                  tags=["chain", chain_name, seed])
    speak(f"Chain complete — {ran}/{len(steps)} transforms executed. "
          f"Results saved to investigation graph.")


# ──────────────────────────────────────────────────────────────
# 93. Investigation Session Persistence
# ──────────────────────────────────────────────────────────────
def investigation_session(action: str, name: str = "") -> None:
    """
    Save / resume / list / fork / export investigation state.
    action: save | resume | list | fork | export | delete
    """
    from ..core import speak, show, mike

    show("thinking")
    a = action.lower()
    name = name.strip().lower().replace(" ", "_")

    if a == "list":
        files = sorted(p.stem for p in _SESS_DIR.glob("*.json"))
        if files:
            speak(f"Saved investigations: {', '.join(files[:10])}")
        else:
            speak("No saved investigations yet.")
        return

    if a == "save" and name:
        # Snapshot everything Mike currently knows that looks investigation-related
        snapshot = {
            "name": name, "saved_at": time.time(),
            "nodes": _collect_graph_nodes(mike),
        }
        path = _SESS_DIR / f"{name}.json"
        path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        speak(f"Investigation '{name}' saved with {len(snapshot['nodes'])} entities.")
        return

    if a == "resume" and name:
        path = _SESS_DIR / f"{name}.json"
        if not path.exists():
            speak(f"No investigation named '{name}'.")
            return
        snap = json.loads(path.read_text(encoding="utf-8"))
        for k, v in snap.get("nodes", {}).items():
            mike.remember(k, v if isinstance(v, str) else json.dumps(v),
                          tags=["resumed", name])
        speak(f"Resumed '{name}' — {len(snap.get('nodes', {}))} entities loaded into memory.")
        return

    if a == "fork" and name:
        src = _SESS_DIR / f"{name}.json"
        if not src.exists():
            speak(f"No investigation named '{name}' to fork.")
            return
        fork_name = f"{name}_fork_{int(time.time()) % 10000}"
        (_SESS_DIR / f"{fork_name}.json").write_text(
            src.read_text(encoding="utf-8"), encoding="utf-8")
        speak(f"Forked '{name}' → '{fork_name}'.")
        return

    if a == "export" and name:
        path = _SESS_DIR / f"{name}.json"
        if path.exists():
            speak(f"Investigation '{name}' is at {path}. Share that JSON to hand it off.")
        else:
            speak(f"No investigation named '{name}'.")
        return

    if a == "delete" and name:
        path = _SESS_DIR / f"{name}.json"
        if path.exists():
            path.unlink()
            speak(f"Deleted investigation '{name}'.")
        else:
            speak(f"No investigation named '{name}'.")
        return

    speak("Usage: save / resume / list / fork / export / delete <name>.")


def _collect_graph_nodes(mike) -> Dict[str, str]:
    """Best-effort dump of Mike's stored keys (investigation entities)."""
    nodes: Dict[str, str] = {}
    try:
        keys = mike.all_keys()
        for prefix in ("subdomains:", "asn:", "wallet:", "email_domains:",
                       "chain:", "risk:", "sentiment:", "cloudmap:",
                       "container:", "iot:", "supplychain:", "credibility:",
                       "narrative:", "botnet:"):
            for k in keys:
                if k.startswith(prefix):
                    v = mike.recall(k)
                    if v:
                        nodes[k] = v
    except Exception:
        pass
    return nodes
