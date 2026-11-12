"""
ARES X v6 — Infrastructure Intelligence (INFRINT)  [Features 75-78]
===================================================================
• Cloud infrastructure mapper (passive asset discovery)
• Container & Kubernetes recon (exposed-service detection)
• IoT device fingerprinting (mDNS/SSDP + banner)
• Supply-chain dependency auditor (CVE / typosquat check)

All recon is passive / external-observation. Container & IoT checks only
test whether a port is open (a TCP connect) — no exploitation, no auth
bypass, no payloads.
"""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from typing import Dict, List

try:
    import httpx
    _HTTPX = True
except ImportError:
    _HTTPX = False

_UA = {"User-Agent": "Mozilla/5.0 (ARES-X INFRINT)"}


# ──────────────────────────────────────────────────────────────
# 75. Cloud Infrastructure Mapper
# ──────────────────────────────────────────────────────────────
def cloud_infra_map(domain: str) -> None:
    """Discover likely cloud assets for a domain via cert logs + DNS hints."""
    from ..core import speak, show, mike, run_async
    from .osint_ext import crt_subdomain_enum_async

    show("thinking", "Mapping cloud footprint…")
    subs = run_async(crt_subdomain_enum_async(domain)) or []

    cloud_hints = {
        "aws": [], "gcp": [], "azure": [], "cloudflare": [], "other": [],
    }
    keywords = {
        "aws": ("aws", "s3", "ec2", "elb", "cloudfront", "amazonaws"),
        "gcp": ("gcp", "gke", "appspot", "googleapis", "cloudfunctions"),
        "azure": ("azure", "blob", "windows.net", "azurewebsites"),
        "cloudflare": ("cf", "cloudflare"),
    }
    for s in subs:
        placed = False
        for prov, kws in keywords.items():
            if any(k in s for k in kws):
                cloud_hints[prov].append(s)
                placed = True
                break
        if not placed and any(k in s for k in ("api", "cdn", "static", "storage")):
            cloud_hints["other"].append(s)

    mike.remember(f"cloudmap:{domain}", json.dumps(cloud_hints),
                  tags=["infrint", "cloud", domain])
    nonempty = {k: len(v) for k, v in cloud_hints.items() if v}
    if nonempty:
        parts = ", ".join(f"{k}: {n}" for k, n in nonempty.items())
        speak(f"Cloud footprint for {domain} — {parts} (from {len(subs)} subdomains).")
    else:
        speak(f"Scanned {len(subs)} subdomains for {domain}; no obvious cloud "
              "asset naming found.")


# ──────────────────────────────────────────────────────────────
# 76. Container & Kubernetes Recon
# ──────────────────────────────────────────────────────────────
_CONTAINER_PORTS = {
    2375: "Docker API (unencrypted)",
    2376: "Docker API (TLS)",
    2379: "etcd client",
    6443: "Kubernetes API",
    10250: "Kubelet",
    5000: "Docker registry",
    8001: "K8s dashboard proxy",
}


def container_recon(target: str) -> None:
    """Check whether common container/orchestration ports are exposed."""
    from ..core import speak, show, mike

    show("thinking", "Probing container surface…")
    host = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    open_ports: Dict[int, str] = {}
    for port, label in _CONTAINER_PORTS.items():
        try:
            with socket.create_connection((host, port), timeout=1.5):
                open_ports[port] = label
        except Exception:
            pass

    mike.remember(f"container:{host}", json.dumps(open_ports),
                  tags=["infrint", "container", host])
    if open_ports:
        items = "; ".join(f"{prt} ({lbl})" for prt, lbl in open_ports.items())
        speak(f"⚠ Exposed container services on {host}: {items}. "
              "These should not be internet-facing.")
    else:
        speak(f"No common container/Kubernetes ports exposed on {host}.")


# ──────────────────────────────────────────────────────────────
# 77. IoT Device Fingerprinting
# ──────────────────────────────────────────────────────────────
def iot_fingerprint(target_or_local: str = "local") -> None:
    """Discover IoT devices via SSDP (local) or banner grab (target)."""
    from ..core import speak, show, mike

    show("thinking", "Fingerprinting IoT devices…")

    if target_or_local.lower() in ("local", "lan", ""):
        devices = _ssdp_discover()
        mike.remember(f"iot:local:{int(time.time())}", json.dumps(devices),
                      tags=["infrint", "iot"])
        if devices:
            speak(f"Found {len(devices)} UPnP/IoT devices on the local network: " +
                  ", ".join(d[:40] for d in devices[:5]))
        else:
            speak("No UPnP/SSDP devices responded on the local network.")
        return

    # Banner grab a specific host
    host = target_or_local.strip()
    banners = {}
    for port in (80, 443, 554, 8080, 1883, 8883, 23):
        try:
            with socket.create_connection((host, port), timeout=1.5) as s:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = s.recv(256).decode(errors="ignore")
                if data:
                    banners[port] = data.split("\r\n")[0][:60]
        except Exception:
            pass
    mike.remember(f"iot:{host}", json.dumps(banners), tags=["infrint", "iot", host])
    if banners:
        speak(f"{host} banners: " +
              "; ".join(f"{p}:{b}" for p, b in list(banners.items())[:4]))
    else:
        speak(f"No banners retrieved from {host}.")


def _ssdp_discover(timeout: float = 3.0) -> List[str]:
    """Passive SSDP M-SEARCH to enumerate local UPnP devices."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()
    devices = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.sendto(msg, ("239.255.255.250", 1900))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = s.recvfrom(1024)
                txt = data.decode(errors="ignore")
                server = ""
                for line in txt.splitlines():
                    if line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                devices.add(f"{addr[0]} {server}".strip())
            except socket.timeout:
                break
        s.close()
    except Exception:
        pass
    return sorted(devices)


# ──────────────────────────────────────────────────────────────
# 78. Supply-Chain Dependency Auditor
# ──────────────────────────────────────────────────────────────
async def _osv_query(name: str, ecosystem: str) -> int:
    """Return count of known vulns for a package via OSV.dev."""
    if not _HTTPX:
        return 0
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post("https://api.osv.dev/v1/query",
                             json={"package": {"name": name, "ecosystem": ecosystem}})
            return len(r.json().get("vulns", []) or [])
    except Exception:
        return 0


def supply_chain_audit(repo_or_path: str) -> None:
    """Audit a project's dependencies for known CVEs + typosquat risk."""
    from ..core import speak, show, mike, run_async, err

    show("thinking", "Auditing supply chain…")
    p = Path(repo_or_path).expanduser()
    deps: List[tuple] = []   # (name, ecosystem)

    try:
        if p.is_dir():
            req = p / "requirements.txt"
            pkg = p / "package.json"
            if req.exists():
                for line in req.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        name = line.split("==")[0].split(">=")[0].split("[")[0].strip()
                        if name:
                            deps.append((name, "PyPI"))
            if pkg.exists():
                j = json.loads(pkg.read_text(errors="ignore"))
                for d in {**j.get("dependencies", {}), **j.get("devDependencies", {})}:
                    deps.append((d, "npm"))
        elif p.is_file() and p.name == "requirements.txt":
            for line in p.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    deps.append((line.split("==")[0].split(">=")[0].strip(), "PyPI"))
        else:
            speak("Point me at a project folder or a requirements.txt.")
            return
    except Exception as e:
        err(f"Supply chain parse: {e}")
        return

    if not deps:
        speak("No dependencies found to audit.")
        return

    vuln_pkgs = []
    for name, eco in deps[:40]:
        n = run_async(_osv_query(name, eco)) or 0
        if n:
            vuln_pkgs.append(f"{name} ({n} CVE)")

    mike.remember(f"supplychain:{p.name}",
                  json.dumps({"deps": len(deps), "vulnerable": vuln_pkgs}),
                  tags=["infrint", "supplychain"])
    if vuln_pkgs:
        speak(f"⚠ {len(vuln_pkgs)}/{len(deps)} dependencies have known CVEs: " +
              ", ".join(vuln_pkgs[:5]))
    else:
        speak(f"Audited {len(deps)} dependencies — no known CVEs found in OSV.")
