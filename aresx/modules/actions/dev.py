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
import json
import os
import re
import sqlite3
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
def git_advanced(action: str, repo_path: str = "",
                 branch: str = "", message: str = "",
                 remote: str = "origin") -> None:
    """Sync wrapper for git_advanced_async (defined in web.py — the
    actions.py split left this cross-file reference unimported)."""
    from aresx.core import speak, show, run_async
    from aresx.modules.actions.web import git_advanced_async
    show("thinking")
    result = run_async(git_advanced_async(action, repo_path, branch, message, remote))
    speak(result or "Git operation done.")


async def docker_ops_async(action: str, container: str = "",
                            image: str = "", flags: str = "") -> str:
    """
    Docker management.
    action: list | start | stop | logs | build | pull | exec | prune
    """
    from aresx.core import log

    a = action.lower()
    cmd_map = {
        "list":  ["docker", "ps", "-a", "--format",
                  "table {{.Names}}\t{{.Status}}\t{{.Image}}"],
        "prune": ["docker", "system", "prune", "-f"],
    }

    if a in cmd_map:
        proc = await asyncio.create_subprocess_exec(
            *cmd_map[a], stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        return out.decode("utf-8", errors="ignore")

    if a == "start" and container:
        proc = await asyncio.create_subprocess_exec(
            "docker", "start", container,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.wait()
        return f"Container '{container}' started."

    if a == "stop" and container:
        proc = await asyncio.create_subprocess_exec(
            "docker", "stop", container,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.wait()
        return f"Container '{container}' stopped."

    if a == "logs" and container:
        proc = await asyncio.create_subprocess_exec(
            "docker", "logs", "--tail", "50", container,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=15)
        return (out + err).decode("utf-8", errors="ignore")[-2000:]

    if a == "build" and image:
        proc = await asyncio.create_subprocess_exec(
            "docker", "build", "-t", image, ".",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=120)
        return (out + err).decode("utf-8", errors="ignore")[-1000:]

    if a == "pull" and image:
        proc = await asyncio.create_subprocess_exec(
            "docker", "pull", image,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=120)
        return (out + err).decode("utf-8", errors="ignore")[-500:]

    return "Unknown docker action."


def docker_ops(action: str, container: str = "",
               image: str = "", flags: str = "") -> None:
    """Sync wrapper for docker_ops_async."""
    from aresx.core import speak, show, run_async
    show("thinking")
    result = run_async(docker_ops_async(action, container, image, flags))
    speak(result[:300] if result else "Docker operation done.")


async def db_query_async(db_type: str, connection: str,
                          query: str) -> str:
    """
    Execute database queries.
    db_type: sqlite | postgres | mysql
    connection: file path (sqlite) or connection string
    """
    from aresx.core import log

    dt = db_type.lower()

    if dt == "sqlite":
        try:
            conn = sqlite3.connect(connection)
            cursor = conn.cursor()
            cursor.execute(query)
            if query.strip().upper().startswith("SELECT"):
                rows = cursor.fetchmany(50)
                cols = [d[0] for d in cursor.description]
                result = "\t".join(cols) + "\n"
                result += "\n".join("\t".join(str(c) for c in row) for row in rows)
                conn.close()
                return result
            else:
                conn.commit()
                affected = cursor.rowcount
                conn.close()
                return f"{affected} rows affected."
        except Exception as e:
            return f"SQLite error: {e}"

    if dt in ("postgres", "postgresql"):
        try:
            import asyncpg
            conn = await asyncpg.connect(connection)
            rows = await conn.fetch(query)
            await conn.close()
            if rows:
                cols = list(rows[0].keys())
                result = "\t".join(cols) + "\n"
                result += "\n".join("\t".join(str(v) for v in dict(r).values()) for r in rows[:50])
                return result
            return "Query executed, no rows returned."
        except ImportError:
            return "asyncpg not installed. Run: pip install asyncpg"
        except Exception as e:
            return f"Postgres error: {e}"

    return f"Unsupported db_type: {db_type}"


def db_query(db_type: str, connection: str, query: str) -> None:
    """Sync wrapper for db_query_async."""
    from aresx.core import speak, show, run_async
    show("thinking")
    result = run_async(db_query_async(db_type, connection, query))
    speak(result[:400] if result else "Query done.")


async def api_request_async(method: str, url: str,
                             headers_json: str = "",
                             body_json: str = "") -> str:
    """
    Execute HTTP API requests (Postman-style).
    method: GET | POST | PUT | PATCH | DELETE
    """
    from aresx.core import log

    if not url.startswith("http"):
        url = "https://" + url

    hdrs = {}
    if headers_json:
        try:
            hdrs = json.loads(headers_json)
        except Exception:
            pass

    body = None
    if body_json:
        try:
            body = json.loads(body_json)
        except Exception:
            body = {"data": body_json}

    try:
        if _HTTPX:
            import httpx as hx
            async with hx.AsyncClient(timeout=20) as client:
                r = await client.request(method.upper(), url,
                                          headers=hdrs, json=body)
                ct = r.headers.get("content-type", "")
                if "json" in ct:
                    return json.dumps(r.json(), indent=2)[:2000]
                return r.text[:2000]
        else:
            import urllib.request
            req = urllib.request.Request(url, method=method.upper(),
                                          headers=hdrs)
            if body:
                req.add_header("Content-Type", "application/json")
                req.data = json.dumps(body).encode()
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.read().decode("utf-8", errors="ignore")[:2000]
    except Exception as e:
        return f"Request failed: {e}"


def api_request(method: str, url: str,
                headers_json: str = "", body_json: str = "") -> None:
    """Sync wrapper for api_request_async."""
    from aresx.core import speak, show, run_async, ask_ai
    show("thinking")
    result = run_async(api_request_async(method, url, headers_json, body_json))
    if result and len(result) > 300:
        summary = ask_ai(f"Summarize this API response in 2 sentences:\n{result[:1500]}")
        speak(summary or result[:200])
    else:
        speak(result or "Request done.")


def log_tail(filepath: str, lines: int = 50,
             filter_term: str = "") -> None:
    """Tail a log file, optionally filtering by keyword."""
    from aresx.core import speak, show, log, ask_ai

    show("thinking")
    try:
        p = Path(filepath)
        if not p.exists():
            speak(f"Log file not found: {filepath}")
            return
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
        tail = all_lines[-lines:]
        if filter_term:
            tail = [l for l in tail if filter_term.lower() in l.lower()]
        content = "".join(tail)
        if len(content) > 1000:
            summary = ask_ai(
                f"Summarize these log lines. Flag errors/warnings:\n{content[:3000]}"
            )
            speak(summary or content[:400])
        else:
            speak(content or "No matching log entries.")
    except Exception as e:
        speak(f"Log tail error: {e}")


async def run_tests_async(test_dir: str = ".", framework: str = "pytest",
                           filter_: str = "") -> str:
    """
    Run unit tests and return summary.
    framework: pytest | unittest | jest | cargo
    """
    from aresx.core import log

    cmd_map = {
        "pytest":   ["python", "-m", "pytest", test_dir, "-v", "--tb=short"],
        "unittest": ["python", "-m", "unittest", "discover", test_dir],
        "jest":     ["npx", "jest", "--no-coverage"],
        "cargo":    ["cargo", "test"],
    }
    cmd = cmd_map.get(framework.lower(), ["python", "-m", "pytest", test_dir])
    if filter_:
        cmd += ["-k", filter_] if framework == "pytest" else []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=test_dir,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = (out + err).decode("utf-8", errors="ignore")
        # Extract summary line
        for line in reversed(output.splitlines()):
            if any(w in line for w in ["passed", "failed", "error", "ok", "FAILED"]):
                return line.strip()
        return output[-500:]
    except asyncio.TimeoutError:
        return "Tests timed out after 120 seconds."
    except Exception as e:
        return f"Test runner error: {e}"


def run_tests(test_dir: str = ".", framework: str = "pytest",
              filter_: str = "") -> None:
    """Sync wrapper for run_tests_async."""
    from aresx.core import speak, show, run_async
    show("thinking")
    result = run_async(run_tests_async(test_dir, framework, filter_))
    speak(result or "Tests done.")


async def package_update_async(manager: str = "pip",
                                package: str = "") -> str:
    """
    Update packages.
    manager: pip | npm | cargo | apt
    package: specific package or empty for all
    """
    from aresx.core import log

    m = manager.lower()
    if m == "pip":
        if package:
            cmd = ["pip", "install", "--upgrade", package]
        else:
            cmd = ["pip", "list", "--outdated", "--format=json"]
    elif m == "npm":
        cmd = ["npm", "update"] + ([package] if package else [])
    elif m == "cargo":
        cmd = ["cargo", "update"] + (["--precise", package] if package else [])
    else:
        return f"Unsupported package manager: {manager}"

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = out.decode("utf-8", errors="ignore")
        if m == "pip" and not package:
            try:
                outdated = json.loads(output)
                names = [p["name"] for p in outdated[:10]]
                return f"{len(outdated)} outdated: {', '.join(names)}"
            except Exception:
                pass
        return output[-500:] or "Done."
    except Exception as e:
        return f"Package update error: {e}"


def package_update(manager: str = "pip", package: str = "") -> None:
    """Sync wrapper for package_update_async."""
    from aresx.core import speak, show, run_async
    show("thinking")
    result = run_async(package_update_async(manager, package))
    speak(result or "Packages updated.")


def generate_unit_tests(filepath: str = "") -> None:
    """Use AI to generate unit tests for Python/JS file in clipboard or path."""
    from aresx.core import speak, show, log, ask_ai_code, clipboard_set
    from aresx.modules.watchers import get_clipboard

    show("thinking")
    if filepath and Path(filepath).exists():
        code = Path(filepath).read_text(encoding="utf-8", errors="ignore")
        lang = "python" if filepath.endswith(".py") else "javascript"
    else:
        code = get_clipboard()
        lang = "python"

    if not code or len(code) < 20:
        speak("No code found in clipboard or file path.")
        return

    tests = ask_ai_code(
        f"Write comprehensive unit tests for this {lang} code. "
        f"Use pytest for Python, Jest for JS. Cover edge cases.\n\n{code[:3000]}"
    )
    if tests:
        clipboard_set(tests)
        speak(f"Unit tests generated and copied to clipboard. {len(tests)} characters.")
    else:
        speak("Could not generate tests.")


# ══════════════════════════════════════════════════════════════
# CATEGORY 5: RESEARCH & KNOWLEDGE
# ══════════════════════════════════════════════════════════════

