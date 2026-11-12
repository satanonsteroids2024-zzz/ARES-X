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
def take_note(note: str) -> None:
    if not note:
        speak("What should I note?")
        return
    show("thinking", "Saving note...")
    mike.add_note(str(note))
    speak("Noted")
    done("Saved")


def recall_memory(query: str) -> None:
    show("thinking", "Checking memory...")
    ctx  = mike.context_for_ai(10)
    result = ask_ai(
        f"User asked: '{query}'\nMike's memory:\n{ctx}\nAnswer from memory only.",
        "You are Mike, ARES X's memory assistant. Answer from context.",
    )
    done(result[:60] if result else "")
    speak(result[:280] if result else "Nothing relevant in memory.")


def show_notes() -> None:
    if Path(NOTES_FILE).exists():
        try:
            os.startfile(NOTES_FILE)
            done("Opened")
            speak("Opening notes")
        except (AttributeError, OSError):
            subprocess.Popen(["notepad", str(NOTES_FILE)])
            done("Opened")
    else:
        err("No notes")
        speak("No notes yet.")


# ══════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════
def calculator(expr: str) -> None:
    if not expr:
        speak("Calculate what?")
        return
    show("thinking", "Calculating...")
    clean = re.sub(r"[^\d+\-*/().\s%]", "", str(expr).replace("x", "*").replace("X", "*"))
    if not clean.strip():
        err("Invalid")
        speak("No math found.")
        return
    try:
        result = eval(clean, {"__builtins__": {}}, {})
        msg = f"{expr} equals {result}"
        done(str(result))
        speak(msg)
        mike.log_command(f"calc {expr}", str(result))
    except (SyntaxError, ZeroDivisionError, NameError, TypeError) as e:
        err("Invalid")
        speak("Couldn't calculate.")
        log(f"calc: {e}", "WARN")


def weather(location: str = "") -> None:
    show("thinking", "Weather...")

    async def _do():
        import httpx
        loc = urllib.parse.quote(str(location)) if location else ""
        url = f"https://wttr.in/{loc}?format=j1"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                d = resp.json()
            c    = d["current_condition"][0]
            area = ""
            try:
                area = d["nearest_area"][0]["areaName"][0]["value"]
            except (KeyError, IndexError):
                pass
            info = (f"{area}: {c['temp_C']}°C, {c['weatherDesc'][0]['value']}. "
                    f"Feels {c['FeelsLikeC']}°C. Humidity {c['humidity']}%.")
            done(f"{c['temp_C']}°C")
            speak(info)
            mike.log_osint(f"weather_{location or 'here'}", info)
        except Exception as e:
            err("Failed")
            speak("Weather fetch failed.")
            log(f"weather: {e}", "WARN")

    run_async(_do())


def currency_convert(amount: str, from_curr: str, to_curr: str) -> None:
    if not (amount and from_curr and to_curr):
        speak("Need amount and currencies.")
        return
    show("thinking", "Converting...")

    async def _do():
        try:
            a  = float(amount)
            fc = str(from_curr).upper().strip()
            tc = str(to_curr).upper().strip()
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"https://api.exchangerate-api.com/v4/latest/{fc}")
                resp.raise_for_status()
                d = resp.json()
            rate = d["rates"].get(tc)
            if rate:
                result = a * rate
                msg = f"{a} {fc} = {result:.2f} {tc}"
                done(f"{result:.2f}")
                speak(msg)
                mike.log_command(f"convert {a}{fc}_{tc}", msg)
            else:
                err("Unknown currency")
                speak(f"Unknown currency {tc}.")
        except Exception as e:
            err("Failed")
            speak("Conversion failed.")
            log(f"convert: {e}", "WARN")

    run_async(_do())


def time_in(location: str) -> None:
    if not location:
        speak("Time where?")
        return
    show("thinking", f"Time in {location}...")

    async def _do():
        tz_resp = ask_ai(
            f"What is the IANA timezone string for '{location}'? "
            "Reply ONLY with the timezone like 'America/New_York' — nothing else.",
            "Timezone expert. Reply with timezone string only.",
        )
        if not tz_resp:
            err("No AI")
            speak("Need API key.")
            return
        tz = tz_resp.strip().strip('"').strip("'").split("\n")[0].strip()
        if not re.match(r"^[A-Za-z_]+/[A-Za-z_]+", tz):
            err("Bad timezone")
            speak("Couldn't find timezone.")
            return
        import httpx
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(f"https://worldtimeapi.org/api/timezone/{tz}")
                resp.raise_for_status()
                d = resp.json()
            dt  = d["datetime"][:19].replace("T", " ")
            msg = f"Time in {location} is {dt}"
            done(dt)
            speak(msg)
        except Exception as e:
            err("Failed")
            speak("Time lookup failed.")
            log(f"time_in: {e}", "WARN")

    run_async(_do())


def wikipedia(topic: str) -> None:
    if not topic:
        speak("About what?")
        return
    show("thinking", f"Wiki: {str(topic)[:30]}...")

    async def _do():
        import httpx
        url = (f"https://en.wikipedia.org/api/rest_v1/page/summary/"
               f"{urllib.parse.quote(str(topic))}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                d = resp.json()
            summary = d.get("extract", "Not found")[:600]
            done(d.get("title", "")[:30])
            speak(summary[:400])
            mike.add_note(f"WIKI: {topic}\n{summary}")
            page = d.get("content_urls", {}).get("desktop", {}).get("page")
            if page:
                webbrowser.open(page)
        except Exception as e:
            err("Not found")
            speak("Wikipedia lookup failed.")
            log(f"wiki: {e}", "WARN")

    run_async(_do())


def define_word(word: str) -> None:
    if not word:
        speak("Define what?")
        return
    show("thinking", f"Define {word}...")

    async def _do():
        import httpx
        url = f"https://api.dictionaryapi.dev/api/v2/entries/en/{urllib.parse.quote(str(word).strip())}"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                d = resp.json()
            if isinstance(d, list) and d:
                m    = d[0].get("meanings", [{}])[0]
                defn = m.get("definitions", [{}])[0].get("definition", "")
                pos  = m.get("partOfSpeech", "")
                msg  = f"{word} ({pos}): {defn}"
                done(word)
                speak(msg)
            else:
                err("Not found")
                speak(f"No definition for {word}.")
        except Exception as e:
            err("Not found")
            speak("Definition not found.")
            log(f"define: {e}", "WARN")

    run_async(_do())


def set_timer(seconds: int, label: str = "timer") -> None:
    try:
        secs = int(seconds)
    except (ValueError, TypeError):
        speak("Invalid time.")
        return
    if not 1 <= secs <= 86400:
        speak("Timer must be 1 second to 24 hours.")
        return
    show("thinking", f"Timer {secs}s...")
    done(f"Timer: {label}")
    speak(f"Timer set for {secs} seconds")

    def fire():
        time.sleep(secs)
        speak(f"Timer done. {label}")
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", "[console]::beep(800,500)"],
                capture_output=True, timeout=3,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

    threading.Thread(target=fire, daemon=True).start()


# ══════════════════════════════════════════════════════════════
# COMMUNICATION
# ══════════════════════════════════════════════════════════════
