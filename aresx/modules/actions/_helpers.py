"""
ARES X v5 — MCP Tool Library (actions.py)
==========================================
• All system-mutating calls wrapped in IPC token validation
• Async subprocess pipelines for git, exif, system ops
• DuckDuckGo async web search integrated directly
• Clipboard injection-sanitized before processing
• PySide6 API key manager (Qt dialog, no tkinter)
• Full v4 feature parity + v5 async upgrades
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import subprocess
import sys
import threading
import time
import webbrowser
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import pyautogui
    pyautogui.FAILSAFE = True
    pyautogui.PAUSE    = 0.05
except ImportError:
    pyautogui = None

# Shared "is httpx available" flag — several action modules (assistant,
# content, dev, system, web) each referenced a module-local `_HTTPX`
# that only ever got defined in system.py when actions.py was split;
# the rest import it from here so there's exactly one probe.
try:
    import httpx  # noqa: F401
    _HTTPX = True
except ImportError:
    _HTTPX = False

from aresx.core import (
    ask_ai, ask_vision, cfg, done, err, generate_ipc_token, log, mike,
    needs_confirm, ask_confirm, NOTES_FILE, orb, run_async, screenshot_save,
    show, speak, validate_ipc_token,
)

# ── Safe subprocess helpers ───────────────────────────────────
def _ps_run(script: str, input_text: Optional[str] = None,
            timeout: int = 15) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            input=input_text, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8",
        )
    except subprocess.TimeoutExpired:
        log(f"PS timeout: {script[:50]}", "WARN")
        return None
    except (OSError, FileNotFoundError) as e:
        log(f"PS error: {e}", "WARN")
        return None


async def _ps_async(script: str, input_text: Optional[str] = None,
                     timeout: float = 15.0) -> Optional[str]:
    """Non-blocking PowerShell via asyncio subprocess."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "powershell", "-NoProfile", "-Command", script,
            stdin=asyncio.subprocess.PIPE if input_text else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        inp = input_text.encode() if input_text else None
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(inp), timeout=timeout)
            return stdout.decode("utf-8", errors="ignore").strip()
        except asyncio.TimeoutError:
            proc.kill()
            log(f"PS async timeout: {script[:50]}", "WARN")
            return None
    except (OSError, FileNotFoundError) as e:
        log(f"PS async error: {e}", "WARN")
        return None


def _safe_pyauto() -> bool:
    if pyautogui is None:
        err("pyautogui missing")
        speak("Cannot control mouse — pyautogui not installed.")
        return False
    return True


# ── Injection sanitizer for clipboard ────────────────────────
_INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"forget all previous",
    r"system:\s*you are now",
    r"<\|im_start\|>",
    r"\\x[0-9a-fA-F]{2}",
]


def _sanitize(text: str) -> str:
    for pat in _INJECTION_PATTERNS:
        text = re.sub(pat, "[SANITIZED]", text, flags=re.IGNORECASE | re.DOTALL)
    return text.strip()


# ══════════════════════════════════════════════════════════════
# APPS
# ══════════════════════════════════════════════════════════════
APP_MAP = {
    "chrome": "chrome", "firefox": "firefox", "edge": "msedge",
    "notepad": "notepad", "calculator": "calc", "paint": "mspaint",
    "explorer": "explorer", "task manager": "taskmgr", "cmd": "cmd",
    "powershell": "powershell", "settings": "ms-settings:", "control panel": "control",
    "spotify": "spotify", "discord": "discord", "telegram": "telegram",
    "vs code": "code", "vscode": "code", "visual studio code": "code",
    "outlook": "outlook", "word": "winword", "excel": "excel",
    "powerpoint": "powerpnt", "obs": "obs", "steam": "steam",
}

# ══════════════════════════════════════════════════════════════
# LEGACY brain compat — the deleted ``aresx.brain`` agent module exposed
# ``ddg_search_async``, ``classify``, and ``dispatch``. Action handlers still
# reference them behind lazy imports. Keep minimal equivalents here so nothing
# silently breaks; new code should use ``aresx.red``, ``aresx.modules.osint``,
# or the chat router directly.
# ══════════════════════════════════════════════════════════════

async def ddg_search_async(query: str, max_results: int = 5) -> list:
    """Async DuckDuckGo search. Falls back to an empty list on failure."""
    try:
        from duckduckgo_search import DDGS

        loop = asyncio.get_running_loop()

        def _sync_search() -> list:
            try:
                with DDGS() as ddgs:
                    results = list(ddgs.text(query, max_results=max_results))
                return [{"title": r.get("title", ""), "url": r.get("href", ""),
                         "body": r.get("body", "")} for r in results]
            except Exception as exc:  # noqa: BLE001
                log(f"DDG search: {exc}", "WARN")
                return []

        return await loop.run_in_executor(None, _sync_search)
    except ImportError:
        return []


def classify(text: str):  # noqa: ANN201
    """Legacy sync classifier — returns a generic fallback intent."""
    log("legacy brain.classify called (brain module removed in v11); "
        "use the chat router / osint ramps instead", "WARN")
    return {"intent": "generic_query", "text": text, "confidence": 0.0}


def dispatch(intent: dict) -> bool:
    """Legacy sync dispatcher — no-ops for deleted agent pipeline."""
    log("legacy brain.dispatch called (brain module removed in v11); "
        "use the chat router / osint ramps instead", "WARN")
    return False


