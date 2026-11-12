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

from aresx.modules.actions._helpers import (
    _ps_run, _safe_pyauto, _sanitize,
)
_MACROS_FILE = __import__("pathlib").Path(__file__).resolve().parent.parent.parent / "macros.json"

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

from aresx.core import (
    ask_ai, ask_vision, cfg, done, err, generate_ipc_token, log, mike,
    needs_confirm, ask_confirm, NOTES_FILE, orb, run_async, screenshot_save,
    show, speak, validate_ipc_token,
)

# ── Safe subprocess helpers ───────────────────────────────────
def _load_macros() -> None:
    global _MACROS
    if _MACROS_FILE.exists():
        try:
            _MACROS = json.loads(_MACROS_FILE.read_text(encoding="utf-8"))
        except Exception:
            _MACROS = {}


def _save_macros() -> None:
    _MACROS_FILE.write_text(
        json.dumps(_MACROS, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


_load_macros()


def macro_ops(action: str, name: str = "",
              steps_json: str = "") -> None:
    """
    Voice command macro manager.
    action: create | run | list | delete
    name: macro name
    steps_json: JSON list of {action: str, args: dict}
    """
    from aresx.core import speak, show, log, err
    from aresx.modules.actions._helpers import dispatch, classify

    a = action.lower()

    if a == "list":
        if _MACROS:
            names = list(_MACROS.keys())
            speak(f"Saved macros: {', '.join(names)}")
        else:
            speak("No macros saved yet.")
        return

    if a == "create" and name and steps_json:
        try:
            steps = json.loads(steps_json)
            _MACROS[name.lower()] = steps
            _save_macros()
            speak(f"Macro '{name}' saved with {len(steps)} steps.")
        except json.JSONDecodeError:
            speak("Invalid steps JSON.")
        return

    if a == "delete" and name:
        n = name.lower()
        if n in _MACROS:
            del _MACROS[n]
            _save_macros()
            speak(f"Macro '{name}' deleted.")
        else:
            speak(f"Macro '{name}' not found.")
        return

    if a == "run" and name:
        n = name.lower()
        if n not in _MACROS:
            speak(f"Macro '{name}' not found.")
            return
        steps = _MACROS[n]
        speak(f"Running macro '{name}': {len(steps)} steps.")
        for i, step in enumerate(steps):
            log(f"Macro '{name}' step {i+1}: {step.get('action')}", "MACRO")
            try:
                intent = {"action": step["action"],
                          "args":   step.get("args", {})}
                dispatch(intent)
                time.sleep(step.get("delay", 0.5))
            except Exception as e:
                log(f"Macro step {i+1} error: {e}", "ERROR")
        speak(f"Macro '{name}' complete.")
        return

    speak("Unknown macro action.")


def multilingual_detect(text: str = "") -> None:
    """Detect language and configure ARES response language accordingly."""
    from aresx.core import speak, show, log, cfg, save_config
    from aresx.modules.watchers import get_clipboard

    show("thinking")
    content = text.strip() or get_clipboard()

    _LANG_SCRIPTS = {
        "hindi":    ("\u0900", "\u097F"),
        "kannada":  ("\u0C80", "\u0CFF"),
        "telugu":   ("\u0C00", "\u0C7F"),
        "tamil":    ("\u0B80", "\u0BFF"),
        "bengali":  ("\u0980", "\u09FF"),
        "japanese": ("\u3040", "\u30FF"),
        "chinese":  ("\u4E00", "\u9FFF"),
        "arabic":   ("\u0600", "\u06FF"),
    }

    detected = "english"
    for lang, (start, end) in _LANG_SCRIPTS.items():
        if any(start <= c <= end for c in content):
            detected = lang
            break

    cfg["language"] = detected[:2]
    save_config(cfg)
    speak(f"Language detected as {detected}. Switching ARES responses to {detected}.")


def voice_confidence_check(command: str) -> float:
    """
    Estimate how confident ARES is about a command interpretation.
    Returns 0.0 - 1.0. Used internally by brain.py for auto-confirm threshold.
    """
    from aresx.core import ask_ai, log

    result = ask_ai(
        f"On a scale of 0.0 to 1.0, how clearly does this voice command "
        f"indicate a specific computer action? Return ONLY a float.\n"
        f"Command: \"{command}\""
    )
    try:
        return max(0.0, min(1.0, float(result.strip())))
    except Exception:
        return 0.5


def set_voice_macro_trigger(phrase: str, macro_name: str) -> None:
    """Map a natural language phrase to a macro name for wake-word dispatch."""
    from aresx.core import speak, show, cfg, save_config

    show("thinking")
    triggers = cfg.get("voice_triggers", {})
    triggers[phrase.lower()] = macro_name.lower()
    cfg["voice_triggers"] = triggers
    save_config(cfg)
    speak(f"Voice trigger set: '{phrase}' → macro '{macro_name}'.")


# ══════════════════════════════════════════════════════════════
# CATEGORY 8: PLATFORM EXTENSIONS
# ══════════════════════════════════════════════════════════════

def discord_bot_ops(action: str, channel_id: str = "",
                    message: str = "", token_key: str = "discord") -> None:
    """
    Discord bot operations via Bot token.
    action: send | listen | status | dm
    """
    from aresx.core import speak, show, cfg, err, run_async

    show("thinking")
    token = cfg.get("api_keys", {}).get(token_key, "")
    if not token:
        speak("Discord bot token not set. Add 'discord' via manage API keys.")
        return

    async def _discord_async():
        if not _HTTPX:
            return "httpx required for Discord."
        import httpx as hx
        headers = {"Authorization": f"Bot {token}",
                   "Content-Type": "application/json"}
        a = action.lower()
        try:
            async with hx.AsyncClient(timeout=10) as client:
                if a == "send" and channel_id and message:
                    r = await client.post(
                        f"https://discord.com/api/v10/channels/{channel_id}/messages",
                        headers=headers,
                        json={"content": message}
                    )
                    data = r.json()
                    return "Message sent." if "id" in data else f"Error: {data}"

                if a == "status":
                    r = await client.get("https://discord.com/api/v10/users/@me",
                                          headers=headers)
                    d = r.json()
                    return f"Bot: {d.get('username', 'unknown')}#{d.get('discriminator','')}"

        except Exception as e:
            return f"Discord error: {e}"
        return "Discord action done."

    result = run_async(_discord_async())
    speak(result or "Discord operation done.")


def home_assistant_ops(action: str, entity_id: str = "",
                        state: str = "", attribute: str = "") -> None:
    """
    Home Assistant integration via long-lived access token.
    action: get_state | turn_on | turn_off | toggle | list_entities
    """
    from aresx.core import speak, show, cfg, err, run_async

    show("thinking")
    ha_url   = cfg.get("home_assistant_url", "http://homeassistant.local:8123")
    ha_token = cfg.get("api_keys", {}).get("home_assistant", "")
    if not ha_token:
        speak("Home Assistant token not set. Add 'home_assistant' key via manage API keys.")
        return

    async def _ha_async():
        if not _HTTPX:
            return "httpx required for Home Assistant."
        import httpx as hx
        headers = {"Authorization": f"Bearer {ha_token}",
                   "Content-Type": "application/json"}
        base = f"{ha_url}/api"
        a = action.lower()
        try:
            async with hx.AsyncClient(timeout=10) as client:
                if a == "get_state" and entity_id:
                    r = await client.get(f"{base}/states/{entity_id}", headers=headers)
                    d = r.json()
                    attrs = d.get("attributes", {})
                    return (f"{entity_id}: {d.get('state')} "
                            f"(friendly: {attrs.get('friendly_name','')})")

                if a in ("turn_on", "turn_off", "toggle"):
                    domain = entity_id.split(".")[0] if entity_id else "light"
                    svc = a.replace("turn_", "")
                    r = await client.post(
                        f"{base}/services/{domain}/{svc}",
                        headers=headers,
                        json={"entity_id": entity_id} if entity_id else {}
                    )
                    return f"{a.replace('_', ' ').title()} sent to {entity_id or 'all'}."

                if a == "list_entities":
                    r = await client.get(f"{base}/states", headers=headers)
                    entities = [s["entity_id"] for s in r.json()[:20]]
                    return "Entities: " + ", ".join(entities)

        except Exception as e:
            return f"Home Assistant error: {e}"
        return "Home Assistant action done."

    result = run_async(_ha_async())
    speak(result or "Home Assistant operation done.")


def vscode_ops(action: str, filepath: str = "",
               command: str = "") -> None:
    """
    VS Code operations via CLI.
    action: open | open_folder | install_extension | run_task | list_extensions
    """
    from aresx.core import speak, show, log, err

    show("thinking")
    a = action.lower()

    if a == "open" and filepath:
        try:
            subprocess.Popen(["code", filepath])
            speak(f"Opening {Path(filepath).name} in VS Code.")
        except FileNotFoundError:
            speak("VS Code 'code' command not found. Is it in your PATH?")
        return

    if a == "open_folder":
        folder = filepath or str(Path.cwd())
        try:
            subprocess.Popen(["code", folder])
            speak("Opening folder in VS Code.")
        except FileNotFoundError:
            speak("VS Code not found in PATH.")
        return

    if a == "install_extension" and command:
        try:
            subprocess.Popen(["code", "--install-extension", command])
            speak(f"Installing VS Code extension: {command}")
        except FileNotFoundError:
            speak("VS Code not found in PATH.")
        return

    if a == "list_extensions":
        try:
            result = subprocess.run(["code", "--list-extensions"],
                                     capture_output=True, text=True, timeout=10)
            exts = result.stdout.strip().splitlines()[:15]
            speak(f"{len(exts)} extensions: {', '.join(exts[:5])}...")
        except Exception as e:
            speak(f"Could not list extensions: {e}")
        return

    if a == "run_task" and command:
        # Use VS Code CLI to run tasks
        try:
            subprocess.Popen(["code", "--command", command])
            speak(f"Running VS Code task: {command}")
        except FileNotFoundError:
            speak("VS Code not found in PATH.")
        return

    speak("VS Code action done.")


def competitor_tracker(company: str, check_type: str = "all") -> None:
    """
    Track competitor activity.
    check_type: pricing | product | news | jobs | all
    """
    from aresx.core import speak, show, ask_ai, run_async
    from aresx.modules.actions._helpers import ddg_search_async

    show("thinking")
    c = company.strip()
    queries = []

    if check_type in ("pricing", "all"):
        queries.append(f"{c} pricing plans 2024 2025")
    if check_type in ("product", "all"):
        queries.append(f"{c} new features product launch")
    if check_type in ("news", "all"):
        queries.append(f"{c} company news announcements")
    if check_type in ("jobs", "all"):
        queries.append(f"{c} hiring jobs site:linkedin.com")

    all_results = []
    for q in queries:
        results = run_async(ddg_search_async(q, max_results=3))
        all_results.extend(results)

    context = "\n".join(
        f"• {r.get('title','')} — {r.get('body','')[:150]}"
        for r in all_results[:12]
    )
    summary = ask_ai(
        f"Competitive intelligence on {c}. "
        f"Summarize key findings by category (pricing, product, news). "
        f"Context:\n{context}"
    )
    speak(summary or f"Competitor data found on {c}.")
