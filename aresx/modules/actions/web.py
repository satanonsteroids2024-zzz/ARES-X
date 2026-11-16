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
    _ps_run, _safe_pyauto, _sanitize, _HTTPX,
)

import asyncio
import base64
import hashlib
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
def browser_tabs(action: str, urls: str = "", tab_index: int = 0) -> None:
    """Sync wrapper for browser_tabs_async (defined in office.py — the
    actions.py split left this cross-file reference unimported)."""
    from aresx.core import speak, show, run_async
    from aresx.modules.actions.office import browser_tabs_async
    show("thinking")
    result = run_async(browser_tabs_async(action, urls, tab_index))
    speak(result or "Done.")


async def web_scrape_async(url: str, selector: str = "",
                            extract: str = "text") -> str:
    """
    Scrape a web page.
    selector: CSS selector (empty = full text)
    extract: text | links | tables | images
    """
    from aresx.core import log

    if not url.startswith("http"):
        url = "https://" + url

    try:
        if _HTTPX:
            import httpx as hx
            async with hx.AsyncClient(timeout=15,
                    headers={"User-Agent": "Mozilla/5.0"}) as client:
                r = await client.get(url)
                html = r.text
        else:
            from urllib.request import urlopen, Request
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=15) as resp:
                html = resp.read().decode("utf-8", errors="ignore")

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")

            if extract == "links":
                links = [a.get("href", "") for a in soup.find_all("a", href=True)]
                return "\n".join(links[:30])

            if extract == "tables":
                tables = []
                for t in soup.find_all("table")[:3]:
                    rows = []
                    for tr in t.find_all("tr"):
                        cells = [td.get_text(strip=True) for td in tr.find_all(["td", "th"])]
                        rows.append(" | ".join(cells))
                    tables.append("\n".join(rows))
                return "\n\n".join(tables)

            if extract == "images":
                imgs = [i.get("src", "") for i in soup.find_all("img", src=True)]
                return "\n".join(imgs[:20])

            if selector:
                elements = soup.select(selector)
                return "\n".join(e.get_text(strip=True) for e in elements[:10])

            # Default: main text content
            for tag in soup(["script", "style", "nav", "header", "footer"]):
                tag.decompose()
            return soup.get_text(separator="\n", strip=True)[:3000]

        except ImportError:
            # BeautifulSoup not available — return raw truncated HTML
            return html[:2000]

    except Exception as e:
        log(f"web_scrape: {e}", "ERROR")
        return f"Scrape failed: {e}"


def web_scrape(url: str, selector: str = "", extract: str = "text") -> None:
    """Sync wrapper for web_scrape_async."""
    from aresx.core import speak, show, run_async, ask_ai
    show("thinking")
    raw = run_async(web_scrape_async(url, selector, extract))
    if not raw:
        speak("Scraping failed or returned empty.")
        return
    # Summarize with AI if text is long
    if len(raw) > 500:
        summary = ask_ai(f"Summarize this web content in 3 sentences:\n{raw[:2000]}")
        speak(summary or raw[:300])
    else:
        speak(raw)


async def price_monitor_async(url: str, label: str = "",
                               check_interval_hours: float = 6.0) -> str:
    """
    Monitor a product page URL for price changes.
    Saves baseline to Mike v3 memory and alerts on change.
    """
    from aresx.core import speak, mike, log

    if not url.startswith("http"):
        url = "https://" + url

    mem_key = f"price_monitor:{hashlib.md5(url.encode()).hexdigest()[:8]}"
    label = label or url.split("/")[2]

    # Scrape price
    raw = await web_scrape_async(url, extract="text")
    # Heuristic: find price-like strings
    prices = re.findall(r"[\$₹€£¥][\d,]+\.?\d*|[\d,]+\.?\d*\s*(?:USD|INR|EUR|GBP)", raw)
    current_price = prices[0] if prices else "unknown"

    # Load baseline from memory
    baseline = mike.recall(mem_key) or ""

    if baseline and baseline != current_price:
        msg = f"Price change for {label}: {baseline} → {current_price}"
        speak(msg)
        log(msg, "PRICE")
    elif not baseline:
        msg = f"Price monitor set for {label} at {current_price}."
        speak(msg)

    mike.remember(mem_key, current_price, tags=["price_monitor", label])
    return current_price


def price_monitor(url: str, label: str = "",
                  check_interval_hours: float = 6.0) -> None:
    """Sync wrapper for price_monitor_async."""
    from aresx.core import run_async, show
    show("thinking")
    run_async(price_monitor_async(url, label, check_interval_hours))


def form_autofill(url: str, field_data: str = "") -> None:
    """
    Fill web forms using Selenium.
    field_data: JSON string {css_selector: value, ...}
    """
    from aresx.core import speak, show, log, err

    show("thinking")
    try:
        fields = json.loads(field_data) if field_data else {}
    except json.JSONDecodeError:
        speak("Invalid field data JSON.")
        return

    try:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.chrome.options import Options
        opts = Options()
        opts.add_experimental_option("debuggerAddress", "127.0.0.1:9222")
        try:
            driver = webdriver.Chrome(options=opts)
        except Exception:
            driver = webdriver.Chrome()
        if url:
            driver.get(url if url.startswith("http") else "https://" + url)
            time.sleep(1.5)
        for selector, value in fields.items():
            try:
                el = driver.find_element(By.CSS_SELECTOR, selector)
                el.clear()
                el.send_keys(value)
            except Exception as e:
                log(f"form_autofill field '{selector}': {e}", "WARN")
        speak(f"Form filled with {len(fields)} fields.")
    except ImportError:
        speak("Selenium not installed. Run: pip install selenium")
    except Exception as e:
        err(f"Form fill: {e}")


def screenshot_to_markdown(source: str = "") -> None:
    """Convert screenshot (or current screen) to clean markdown text."""
    from aresx.core import speak, show, log, ask_vision, screenshot_b64, clipboard_set

    show("thinking")
    if source and Path(source).exists():
        from PIL import Image
        import base64, io
        img = Image.open(source)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=80)
        img_b64 = base64.b64encode(buf.getvalue()).decode()
    else:
        img_b64 = screenshot_b64(quality=70)

    if not img_b64:
        speak("Could not capture image.")
        return

    result = ask_vision(
        "Convert all visible text in this image to clean markdown. "
        "Preserve structure, headings, lists, tables. Return ONLY the markdown.",
        image_b64=img_b64
    )
    if result:
        clipboard_set(result)
        speak(f"Converted to markdown and copied to clipboard. {len(result)} characters.")
    else:
        speak("Could not convert image to text.")


# ══════════════════════════════════════════════════════════════
# CATEGORY 4: CODING & DEV TOOLS
# ══════════════════════════════════════════════════════════════

async def git_advanced_async(action: str, repo_path: str = "",
                              branch: str = "", message: str = "",
                              remote: str = "origin") -> str:
    """
    Extended git operations.
    action: branch | checkout | merge | pull | stash | log | diff | clone | pr_open
    """
    from aresx.core import log
    # _run_git_async is defined in file_ops.py — this cross-file reference
    # was left unimported when actions.py was split. It returns
    # (returncode, output), not a bare string; unpack it below instead of
    # treating the tuple itself as the result (which was always truthy).
    from aresx.modules.actions.file_ops import _run_git_async

    cwd = repo_path or str(Path.cwd())
    a = action.lower()

    cmd_map = {
        "pull":    ["git", "pull", remote, branch or "HEAD"],
        "log":     ["git", "log", "--oneline", "-10"],
        "diff":    ["git", "diff", "--stat"],
        "stash":   ["git", "stash"],
        "stash_pop": ["git", "stash", "pop"],
        "branch":  ["git", "branch", "-a"],
    }

    if a in cmd_map:
        _, out = await _run_git_async(cmd_map[a], cwd, timeout=30.0)
        return out or "Done."

    if a == "checkout" and branch:
        _, out = await _run_git_async(["git", "checkout", branch], cwd)
        return out or f"Switched to {branch}."

    if a == "merge" and branch:
        _, out = await _run_git_async(["git", "merge", branch], cwd)
        return out or f"Merged {branch}."

    if a == "clone" and message:  # message = URL here
        _, out = await _run_git_async(["git", "clone", message], cwd)
        return out or f"Cloned {message}."

    if a == "pr_open":
        # Open PR on GitHub using gh CLI
        _, out = await _run_git_async(["gh", "pr", "create", "--fill"], cwd, timeout=20.0)
        return out or "PR opened."

    return "Unknown git action."


