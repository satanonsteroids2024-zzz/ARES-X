"""
ARES X v10 — Confirmation & status helpers (split from core.py)
===============================================================
Split out of the v9 core.py god-file into a focused module.

All original public symbols are re-exported by aresx.core (the
compat facade) so existing importers keep working unmodified.
"""
from __future__ import annotations

from aresx.core.paths import cfg, log, get_loop, run_async
from aresx.core.orb import orb
from aresx.core.audio import speak, listen

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
def needs_confirm(text: str) -> bool:
    return any(w in str(text).lower() for w in cfg.get("confirm_actions", []))


def ask_confirm(action: str) -> bool:
    orb.do(lambda: orb.set("confirming", f"Confirm: {action[:30]}?"))
    speak(f"Should I {action}? Yes or no.", blocking=True)
    r = listen(timeout=6, phrase_time_limit=4)
    if r and any(w in r for w in ["yes", "yeah", "yep", "do it", "confirm",
                                   "proceed", "sure", "go", "ok", "okay"]):
        return True
    speak("Cancelled.")
    orb.do(lambda: orb.set("idle", ""))
    return False


# ── Status helpers ────────────────────────────────────────────
def show(mode: str, text: str = "") -> None:
    orb.do(lambda: orb.set(mode, text))


def done(text: str = "") -> None:
    orb.do(lambda: orb.set("done", text))
    threading.Timer(3.0, lambda: orb.do(lambda: orb.set("idle", ""))).start()


def err(text: str = "") -> None:
    orb.do(lambda: orb.set("error", text))
    threading.Timer(3.0, lambda: orb.do(lambda: orb.set("idle", ""))).start()


# ── Start async loop eagerly ──────────────────────────────────
get_loop()
