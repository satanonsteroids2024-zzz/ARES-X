# red_module/agents/recon_agent.py
"""
Active Recon Agent for ARES X
Safe orchestration of open-source recon tools.
"""

import subprocess
import asyncio
from datetime import datetime          # BUG 1 FIX: was missing — NameError on datetime.now()
from typing import Dict, List, Any
from pathlib import Path


class ReconAgent:
    def __init__(self, output_dir: str = "output/recon"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # BUG 3 FIX: tools_config was defined but never actually used
        # now _run_tool() reads directly from this — single source of truth
        self.tools_config = {
            "subfinder": {"cmd": ["subfinder", "-d", "{target}", "-silent"]},
            "nmap":      {"cmd": ["nmap", "-sV", "-sC", "-T4", "{target}"]},
            "httpx":     {"cmd": ["httpx", "-u", "{target}", "-title", "-tech-detect", "-silent"]},
        }

    def _run_tool(self, tool: str, target: str, timeout: int = 120) -> List[str]:
        """
        BUG 2 FIX: original used subprocess.check_output(cmd, shell=True)
        shell=True + string interpolation = shell injection if target has ;|& chars.

        Fixed:
          - list-based args (no shell=True)
          - {target} replaced per-arg, never concatenated into a shell string
          - FileNotFoundError caught gracefully (tool not installed = skip, not crash)
        """
        config = self.tools_config.get(tool)
        if not config:
            return []

        cmd = [part.replace("{target}", target) for part in config["cmd"]]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout.strip().splitlines()
        except FileNotFoundError:
            print(f"[RECON] {tool} not installed — skipping")
            return []
        except subprocess.TimeoutExpired:
            print(f"[RECON] {tool} timed out after {timeout}s")
            return []
        except Exception as e:
            print(f"[RECON] {tool} error: {e}")
            return []

    async def execute(self, target: Dict) -> List[Dict]:
        """Run full recon pipeline against a target dict."""
        findings = []
        domain_or_ip = target.get("domain") or target.get("ip")

        if not domain_or_ip:
            return findings

        print(f"[RECON] Starting on {domain_or_ip}")

        loop = asyncio.get_running_loop()

        # Subdomain enumeration
        subdomains = await loop.run_in_executor(
            None, self._run_tool, "subfinder", domain_or_ip
        )
        findings.append({
            "type":      "subdomains",
            "count":     len(subdomains),
            "data":      subdomains[:50],
            "timestamp": datetime.now().isoformat(),   # BUG 1 FIX: works now
        })
        print(f"[RECON] Found {len(subdomains)} subdomains")

        # Port scan
        nmap_out = await loop.run_in_executor(
            None, self._run_tool, "nmap", domain_or_ip
        )
        if nmap_out:
            findings.append({
                "type":      "portscan",
                "data":      nmap_out,
                "timestamp": datetime.now().isoformat(),
            })

        # HTTP fingerprint
        httpx_out = await loop.run_in_executor(
            None, self._run_tool, "httpx", domain_or_ip
        )
        if httpx_out:
            findings.append({
                "type":      "http_fingerprint",
                "data":      httpx_out,
                "timestamp": datetime.now().isoformat(),
            })

        return findings
