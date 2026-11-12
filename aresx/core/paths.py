"""
ARES X v10 — Paths, config, IPC, logging, loop, http (split from core.py)
=========================================================================
Split out of the v9 core.py god-file into a focused module.

All original public symbols are re-exported by aresx.core (the
compat facade) so existing importers keep working unmodified.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
import math
import os
import platform
import queue
import re
import secrets
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
BASE_DIR    = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / "config.json"
MEMORY_DB   = BASE_DIR / "mike_v3.db"
NOTES_FILE  = BASE_DIR / "ares_notes.txt"
ARCHIVE_DIR = BASE_DIR / "archive"

# ── Default Config ─────────────────────────────────────────────
DEFAULT_CONFIG: Dict[str, Any] = {
    "setup_complete":   False,
    "wake_word":        "ares",
    "api_keys": {
        "gemini_key": "",   # free: aistudio.google.com — 15 RPM / 1M TPD / 1500 RPD
        "groq_key":   "",   # free: console.groq.com — NOT xAI Grok — 25 RPM / 250K TPM / 250K req/mo
        "hf_token":   "",   # free: huggingface.co — 30K calls/month
        "openrouter": "",   # optional, free models work without key
        "opencorporates": "", "hibp": "",
    },
    "permissions": {
        "screen": False, "keyboard": False, "mouse": False,
        "downloads": False, "automate": False, "network": False,
        "camera": False,
    },
    "confirm_actions":  ["order","delete","format","uninstall","send",
                          "wipe","kill","shutdown","restart"],
    "mike_enabled":     True,
    "brain_mode":       "smart",
    "orb_position":     [None, None],
    "tts_rate":         1,
    "quiet_hours":      [22, 6],
    "camera_enabled":   False,
    "self_heal":        True,
    "language":         "en",
    "use_local_stt":    True,    # Faster-Whisper vs google fallback
    "use_local_tts":    True,    # Piper/Kokoro vs PowerShell fallback
    "whisper_model":    "base",  # tiny/base/small/medium
    "ipc_secret":       "",      # generated on first run
}

_config_lock = threading.Lock()


def load_config() -> Dict[str, Any]:
    if CONFIG_FILE.exists():
        try:
            c = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            for k, v in DEFAULT_CONFIG.items():
                if k not in c:
                    c[k] = v
            for k2, v2 in DEFAULT_CONFIG["api_keys"].items():
                c.setdefault("api_keys", {})[k2] = c["api_keys"].get(k2, v2)
            if not c.get("ipc_secret"):
                c["ipc_secret"] = secrets.token_hex(32)
                _write_config(c)
            return c
        except (json.JSONDecodeError, OSError):
            pass
    c = json.loads(json.dumps(DEFAULT_CONFIG))
    c["ipc_secret"] = secrets.token_hex(32)
    _write_config(c)
    return c


def _write_config(c: Dict[str, Any]) -> None:
    try:
        tmp = CONFIG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(c, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(CONFIG_FILE)
    except OSError as e:
        _log(f"Config save: {e}", "WARN")


def save_config(c: Dict[str, Any]) -> None:
    with _config_lock:
        _write_config(c)


cfg = load_config()

# ── IPC Cryptographic Token (Cognitive ↔ Executor separation) ──
_IPC_SECRET: bytes = cfg["ipc_secret"].encode()


def generate_ipc_token(action_id: str) -> str:
    """Generate HMAC-SHA256 one-time token for IPC command validation."""
    nonce = secrets.token_hex(16)
    payload = f"{action_id}:{nonce}:{int(time.time())}"
    sig = hmac.new(_IPC_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def validate_ipc_token(token: str, action_id: str, max_age: int = 30) -> bool:
    """Validate IPC token — reject if expired or tampered."""
    try:
        parts = token.rsplit(":", 1)
        if len(parts) != 2:
            return False
        payload, sig = parts
        expected = hmac.new(_IPC_SECRET, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        pid_parts = payload.split(":")
        if len(pid_parts) < 3:
            return False
        ts = int(pid_parts[2])
        if abs(time.time() - ts) > max_age:
            return False
        return pid_parts[0] == action_id
    except Exception:
        return False


# ── Logging ────────────────────────────────────────────────────
_log_lock = threading.Lock()


def _log(msg: str, level: str = "INFO") -> None:
    ts = time.strftime("%H:%M:%S")
    with _log_lock:
        try:
            print(f"[{ts}][{level}] {msg}", flush=True)
        except (UnicodeEncodeError, OSError):
            print(f"[{ts}][{level}] {str(msg).encode('ascii','ignore').decode()}", flush=True)


log = _log  # public alias


# ── Quiet Hours ────────────────────────────────────────────────
def is_quiet_hours() -> bool:
    try:
        h = datetime.now().hour
        start, end = cfg.get("quiet_hours", [22, 6])
        return (h >= start or h < end) if start > end else (start <= h < end)
    except (TypeError, ValueError):
        return False


# ── Async Event Loop (background thread) ──────────────────────
_loop: Optional[asyncio.AbstractEventLoop] = None
_loop_thread: Optional[threading.Thread] = None
_loop_ready = threading.Event()


def _start_async_loop() -> None:
    global _loop
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    _loop_ready.set()
    _loop.run_forever()


def get_loop() -> asyncio.AbstractEventLoop:
    global _loop_thread
    if _loop is None or not _loop.is_running():
        _loop_thread = threading.Thread(target=_start_async_loop, daemon=True, name="async_loop")
        _loop_thread.start()
        _loop_ready.wait(timeout=5)
    return _loop  # type: ignore


def run_async(coro) -> Any:
    """Schedule coroutine on the background loop and return result synchronously."""
    loop = get_loop()
    fut = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return fut.result(timeout=120)
    except Exception as e:
        log(f"run_async error: {e}", "ERROR")
        return None


# ── HTTPX Async Client Pool ────────────────────────────────────
_http_client: Optional["httpx.AsyncClient"] = None
_http_lock = asyncio.Lock() if asyncio.get_event_loop_policy() else None


async def _get_http() -> "httpx.AsyncClient":
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=5.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            http2=True,
            follow_redirects=True,
        )
    return _http_client


async def _async_post(url: str, body: Dict, headers: Dict,
                       timeout: float = 30.0) -> Optional[Dict]:
    try:
        client = await _get_http()
        resp = await client.post(url, json=body, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log(f"HTTP POST [{url[:60]}]: {e}", "WARN")
        return None


async def _async_get(url: str, timeout: float = 15.0) -> Optional[bytes]:
    try:
        client = await _get_http()
        resp = await client.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.content
    except Exception as e:
        log(f"HTTP GET [{url[:60]}]: {e}", "WARN")
        return None


# ── Online Check (async, cached 30s) ──────────────────────────
_online_cache: Dict[str, Any] = {"val": True, "ts": 0.0}
_online_lock = asyncio.Lock() if False else threading.Lock()


async def is_online_async() -> bool:
    now = time.time()
    with _online_lock:
        if now - _online_cache["ts"] < 30:
            return _online_cache["val"]
    try:
        data = await _async_get("https://1.1.1.1", timeout=3.0)
        val = data is not None
    except Exception:
        val = False
    with _online_lock:
        _online_cache.update({"val": val, "ts": time.time()})
    return val


def is_online() -> bool:
    return run_async(is_online_async()) or False
