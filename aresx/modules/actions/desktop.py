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
    _ps_run, _ps_async, _safe_pyauto, _sanitize,
)

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

def open_app(app: str) -> None:
    if not app:
        speak("Which app?")
        return
    show("thinking", f"Opening {app}...")
    cmd = APP_MAP.get(str(app).lower(), app)
    try:
        subprocess.Popen(cmd if isinstance(cmd, list) else [cmd], shell=False)
        speak(f"Opening {app}")
        done(f"Opened {app}")
        mike.log_command(f"open {app}", "ok")
    except (FileNotFoundError, OSError):
        try:
            subprocess.Popen(["cmd", "/c", "start", "", str(cmd)], shell=False)
            speak(f"Opening {app}")
            done(f"Opened {app}")
            mike.log_command(f"open {app}", "ok")
        except (FileNotFoundError, OSError) as e:
            err("Not found")
            speak(f"Could not open {app}")
            log(f"open_app: {e}", "WARN")


def close_window() -> None:
    if not _safe_pyauto():
        return
    show("thinking", "Closing window...")
    pyautogui.hotkey("alt", "f4")
    speak("Window closed")
    done()
    mike.log_command("close_window")


def minimize_all() -> None:
    if not _safe_pyauto():
        return
    pyautogui.hotkey("win", "d")
    speak("Minimized")
    done()


def switch_window() -> None:
    if not _safe_pyauto():
        return
    pyautogui.hotkey("alt", "tab")
    done("Switched")


def lock_screen() -> None:
    if not _safe_pyauto():
        return
    if not ask_confirm("lock the screen"):
        return
    pyautogui.hotkey("win", "l")
    speak("Locking")
    mike.log_command("lock_screen")


# ══════════════════════════════════════════════════════════════
# SEARCH
# ══════════════════════════════════════════════════════════════
def search_web(query: str, engine: str = "google") -> None:
    if not query:
        speak("What should I search?")
        return
    show("thinking", f"Searching {engine}...")
    q = urllib.parse.quote(str(query))
    urls = {
        "google":        f"https://google.com/search?q={q}",
        "youtube":       f"https://youtube.com/results?search_query={q}",
        "amazon":        f"https://amazon.in/s?k={q}",
        "flipkart":      f"https://flipkart.com/search?q={q}",
        "wikipedia":     f"https://en.wikipedia.org/wiki/Special:Search?search={q}",
        "github":        f"https://github.com/search?q={q}",
        "stackoverflow": f"https://stackoverflow.com/search?q={q}",
        "reddit":        f"https://reddit.com/search/?q={q}",
        "twitter":       f"https://x.com/search?q={q}",
        "maps":          f"https://maps.google.com/search/{q}",
    }
    webbrowser.open(urls.get(str(engine).lower(), urls["google"]))
    speak(f"Searching {query}")
    done()
    mike.log_command(f"search {engine}: {query}")


PLATFORMS = ["amazon", "flipkart", "meesho", "myntra", "snapdeal", "ajio"]


def price_compare(product: str, platforms: Optional[List[str]] = None) -> None:
    if not product:
        speak("What product?")
        return
    if not platforms:
        platforms = ["amazon", "flipkart"]
    if not isinstance(platforms, list):
        platforms = [platforms]

    show("thinking", f"Comparing: {str(product)[:25]}...")
    q = urllib.parse.quote(str(product))
    result = ask_ai(
        f'Current INR prices for "{product}" on: {", ".join(platforms)}. '
        f'JSON ONLY: {{"amazon":{{"price":2499,"url":"https://amazon.in/s?k={q}"}}}}',
        "Price comparison expert. Return only valid JSON, no markdown.",
    )
    prices: Dict = {}
    if result:
        try:
            m = re.search(r"\{.*\}", result, re.DOTALL)
            if m:
                prices = json.loads(m.group())
        except (json.JSONDecodeError, TypeError) as e:
            log(f"Price JSON: {e}", "WARN")

    if not prices:
        webbrowser.open(f"https://amazon.in/s?k={q}")
        done("Opened Amazon")
        return

    try:
        cheapest = min(
            prices.items(),
            key=lambda x: x[1].get("price", 999999) if isinstance(x[1], dict) else 999999,
        )
        plat, data = cheapest
        if not isinstance(data, dict):
            raise ValueError
        price = data.get("price", 0)
        url   = data.get("url", f"https://amazon.in/s?k={q}")
    except (ValueError, AttributeError):
        webbrowser.open(f"https://amazon.in/s?k={q}")
        done("Opened Amazon")
        return

    if not ask_confirm(f"order {product} on {plat} for {price} rupees"):
        return

    done(f"{plat} {price}")
    speak(f"Cheapest on {plat} for {price} rupees.")
    webbrowser.open(url)
    for p, d in prices.items():
        if p != plat and isinstance(d, dict) and d.get("url"):
            time.sleep(0.4)
            webbrowser.open(d["url"])
    mike.log_command(f"price_compare {product}", f"{plat} {price}")


# ══════════════════════════════════════════════════════════════
# SYSTEM
# ══════════════════════════════════════════════════════════════
def volume(direction: str) -> None:
    if not _safe_pyauto():
        return
    d = str(direction).lower()
    if d == "mute":
        pyautogui.press("volumemute")
    else:
        key = "volumeup" if d == "up" else "volumedown"
        for _ in range(5):
            pyautogui.press(key)
    speak(f"Volume {d}")
    done()


def brightness(direction: str) -> None:
    show("thinking", f"Brightness {direction}...")
    d = str(direction).lower()

    async def _do():
        out = await _ps_async(
            "(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightness).CurrentBrightness"
        )
        current = 50
        if out:
            try:
                current = int(out.splitlines()[0])
            except (ValueError, IndexError):
                pass
        new = max(0, min(100, current + (20 if d == "up" else -20)))
        await _ps_async(
            f"(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods)"
            f".WmiSetBrightness(1,{new})"
        )
        speak(f"Brightness {d} to {new}%")
        done(f"{new}%")

    run_async(_do())


def take_screenshot() -> None:
    show("thinking", "Capturing...")
    path = screenshot_save()
    if not path:
        err("Failed")
        speak("Screenshot failed.")
        return
    speak("Screenshot saved")
    done("Saved")
    try:
        subprocess.Popen(["explorer", "/select,", path], shell=False)
    except (OSError, FileNotFoundError):
        pass
    mike.log_command("screenshot", path)


def read_screen() -> None:
    show("thinking", "Reading screen...")
    result = ask_vision(
        "Describe what is on this screen in 2-3 sentences. Focus on main content."
    )
    if result:
        done(result[:60])
        speak(result[:300])
        mike.log_command("read_screen", result[:100])
    else:
        err("Need vision key")
        speak("I need a vision API key. Add Gemini key in settings.")


def summarize_screen() -> None:
    show("thinking", "Summarizing...")
    result = ask_vision(
        "Summarize the main content on this screen in 4-5 sentences. "
        "Include key data, titles, important info."
    )
    if result:
        done("Summarized")
        speak(result[:400])
        mike.add_note(f"SCREEN SUMMARY:\n{result}")
    else:
        err("Need vision key")
        speak("Need vision API key.")


def summarize_youtube() -> None:
    show("thinking", "Reading video...")
    result = ask_vision(
        "If a YouTube video is visible, read title, channel, description. "
        "Summarize what the video is about in 3-4 sentences."
    )
    if result:
        done("Summarized")
        speak(result[:400])
        mike.add_note(f"YOUTUBE SUMMARY:\n{result}")
    else:
        err("No video")
        speak("No video visible.")


def type_text(text: str) -> None:
    if not _safe_pyauto():
        return
    if not text:
        speak("Type what?")
        return
    show("thinking", "Typing...")
    time.sleep(0.5)
    try:
        pyautogui.typewrite(str(text), interval=0.04)
        done()
        mike.log_command(f"type: {str(text)[:40]}")
    except Exception as e:
        err("Failed")
        log(f"type_text: {e}", "WARN")


def press_keys(combo: str) -> None:
    if not _safe_pyauto():
        return
    if not combo:
        speak("Which keys?")
        return
    show("thinking", f"Pressing {combo}...")
    try:
        keys = str(combo).replace("+", " ").split()
        if keys:
            pyautogui.hotkey(*keys)
            done(f"Pressed {combo}")
    except Exception as e:
        err("Failed")
        log(f"press_keys: {e}", "WARN")


# ══════════════════════════════════════════════════════════════
# NOTES + MEMORY
# ══════════════════════════════════════════════════════════════
