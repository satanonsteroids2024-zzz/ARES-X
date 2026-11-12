"""
ARES X v9 — Kali Native Tools
Wraps installed Kali reconnaissance/scanning tools (nmap, nikto,
gobuster, subfinder, httpx) so ARES can invoke them directly, in
addition to the pure-Python implementations in aresx/red/recon.py.

Why both exist: aresx/red/recon.py works with zero external
dependencies (pure Python subdomain enum, async port scanning). This
module invokes the actual installed Kali tools when you want their
specific output — nmap's service/OS fingerprinting is more thorough
than the pure-Python port scanner, nikto finds web-server-specific
issues neither of the others check for, etc. Use whichever fits; both
are available as separate tools.

SCOPE: this module only wraps scanning/reconnaissance tools (nmap,
nikto, gobuster, subfinder, httpx) — tools that observe a target
without attempting to exploit or brute-force it. Tools that actively
attempt exploitation (sqlmap, hydra, metasploit) are a different
category and are deliberately not included here.

Every tool call uses list-based subprocess args (never shell=True),
matching the shell-injection-safe pattern already established in
aresx/red/recon_agent.py. If a tool isn't installed, that call is
skipped gracefully — this module doesn't require Kali specifically,
it just uses whichever of these tools happen to be present.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("ares_kali_tools")


# ── Tool availability ──────────────────────────────────────────────────────

def which_tools_available() -> dict[str, bool]:
    """Check which of the wrapped tools are actually installed."""
    tools = ["nmap", "nikto", "gobuster", "subfinder", "httpx"]
    return {t: shutil.which(t) is not None for t in tools}


# ── Command execution (shell-injection-safe) ────────────────────────────────

async def _run(cmd: list[str], timeout: int = 180) -> tuple[bool, str]:
    """
    Run a command with list-based args — never shell=True, so target
    strings containing shell metacharacters (;, |, &, $, etc.) can't
    break out of the intended command. Returns (success, output).
    """
    tool_name = cmd[0]
    if shutil.which(tool_name) is None:
        return False, f"{tool_name} is not installed on this system"

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return False, f"{tool_name} timed out after {timeout}s"

        output = stdout.decode("utf-8", errors="replace")
        if proc.returncode != 0 and not output.strip():
            err_text = stderr.decode("utf-8", errors="replace")
            return False, f"{tool_name} exited with an error: {err_text[:500]}"
        return True, output
    except Exception as exc:
        logger.warning("%s execution failed: %s", tool_name, exc)
        return False, f"{tool_name} failed to run: {exc}"


# ── Individual tool wrappers ─────────────────────────────────────────────

@dataclass
class ScanOutput:
    tool: str
    target: str
    ok: bool
    raw_output: str = ""
    summary: str = ""


async def run_nmap(target: str, scan_type: str = "default", timeout: int = 300) -> ScanOutput:
    """
    Run nmap against a target.
    scan_type: 'default' (top 1000 ports, -sV -sC), 'quick' (-T4 -F),
               'full' (-p- all ports, slower), 'udp' (top 100 UDP ports).
    """
    scan_flags = {
        "default": ["-sV", "-sC", "-T4"],
        "quick":   ["-T4", "-F"],
        "full":    ["-p-", "-sV", "-T4"],
        "udp":     ["-sU", "--top-ports", "100"],
    }
    flags = scan_flags.get(scan_type, scan_flags["default"])
    cmd = ["nmap", *flags, target]
    ok, output = await _run(cmd, timeout=timeout)
    return ScanOutput(tool="nmap", target=target, ok=ok, raw_output=output)


async def run_nikto(target: str, timeout: int = 300) -> ScanOutput:
    """Run nikto web server vulnerability scan against a target URL/host."""
    cmd = ["nikto", "-h", target, "-Format", "txt"]
    ok, output = await _run(cmd, timeout=timeout)
    return ScanOutput(tool="nikto", target=target, ok=ok, raw_output=output)


async def run_gobuster(target: str, wordlist: Optional[str] = None,
                       mode: str = "dir", timeout: int = 300) -> ScanOutput:
    """
    Run gobuster directory/DNS brute-forcing.
    mode: 'dir' (directory brute-force) or 'dns' (subdomain brute-force).
    wordlist defaults to Kali's common.txt if not specified.
    """
    default_wordlist = "/usr/share/wordlists/dirb/common.txt"
    wl = wordlist or default_wordlist
    if mode == "dir":
        cmd = ["gobuster", "dir", "-u", target, "-w", wl, "-q"]
    elif mode == "dns":
        cmd = ["gobuster", "dns", "-d", target, "-w", wl, "-q"]
    else:
        return ScanOutput(tool="gobuster", target=target, ok=False,
                          raw_output=f"Unknown mode: {mode}")
    ok, output = await _run(cmd, timeout=timeout)
    return ScanOutput(tool="gobuster", target=target, ok=ok, raw_output=output)


async def run_subfinder(target: str, timeout: int = 120) -> ScanOutput:
    """Run subfinder for fast passive subdomain enumeration."""
    cmd = ["subfinder", "-d", target, "-silent"]
    ok, output = await _run(cmd, timeout=timeout)
    return ScanOutput(tool="subfinder", target=target, ok=ok, raw_output=output)


async def run_httpx_probe(target: str, timeout: int = 120) -> ScanOutput:
    """
    Run httpx (ProjectDiscovery's recon tool) to probe live hosts and
    fingerprint tech/titles.

    NOTE: 'httpx' is a name collision risk — the Python httpx *library*
    (used elsewhere in ARES for HTTP calls) sometimes installs its own
    CLI entry point under the same command name on some setups, which
    is a completely different, unrelated tool. If that's what's on
    PATH instead of ProjectDiscovery's httpx, this returns a clear
    error rather than silently reporting success with wrong-tool output.
    """
    if shutil.which("httpx") is None:
        return ScanOutput(tool="httpx", target=target, ok=False,
                          raw_output="httpx is not installed on this system")

    # Distinguish the real recon tool from the Python httpx CLI shim:
    # ProjectDiscovery's httpx supports -version and prints a version
    # string; the Python library's CLI, if present under the same
    # name, does not behave the same way.
    check_ok, check_output = await _run(["httpx", "-version"], timeout=10)
    if not check_ok or "projectdiscovery" not in check_output.lower():
        return ScanOutput(
            tool="httpx", target=target, ok=False,
            raw_output=(
                "A program named 'httpx' is on PATH, but it doesn't look like "
                "ProjectDiscovery's httpx recon tool (got a different or "
                "unrecognized -version response). Skipping to avoid "
                "misleading results — install the real tool with: "
                "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
            ),
        )

    cmd = ["httpx", "-u", target, "-title", "-tech-detect", "-status-code", "-silent"]
    ok, output = await _run(cmd, timeout=timeout)
    return ScanOutput(tool="httpx", target=target, ok=ok, raw_output=output)


# ── Combined orchestrator ────────────────────────────────────────────────

async def full_kali_scan(target: str, tools: Optional[list[str]] = None) -> dict:
    """
    Run multiple Kali tools against a target concurrently and combine
    results. tools defaults to ['nmap', 'nikto', 'httpx'] if not given
    — the fast, broadly-useful combination. Pass an explicit list to
    control exactly which tools run.
    """
    tool_list = tools or ["nmap", "nikto", "httpx"]
    runners = {
        "nmap": run_nmap,
        "nikto": run_nikto,
        "httpx": run_httpx_probe,
        "subfinder": run_subfinder,
    }

    tasks = {}
    for t in tool_list:
        runner = runners.get(t)
        if runner:
            tasks[t] = runner(target)

    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    combined = {}
    for name, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            combined[name] = {"ok": False, "error": str(result)}
        else:
            combined[name] = {"ok": result.ok, "output": result.raw_output[:4000]}

    try:
        from aresx.enterprise import add_evidence
        import json
        add_evidence(
            source_tool="ares_kali_tools",
            raw_data=json.dumps({"target": target, "tools_run": list(combined.keys())}),
        )
    except Exception as exc:
        logger.debug("Vault store failed (non-critical): %s", exc)

    return {"target": target, "tools_available": which_tools_available(), "results": combined}
