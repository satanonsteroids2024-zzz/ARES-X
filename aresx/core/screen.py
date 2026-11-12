"""
ARES X v10 — Screenshot capture (split from core.py)
====================================================
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
def screenshot_b64(quality: int = 65) -> Optional[str]:
    if not _MSS or not _PIL:
        return None
    try:
        with mss.mss() as sct:
            raw = sct.grab(sct.monitors[1])
            img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
        w, h = img.size
        if w > 1280:
            img = img.resize((1280, int(h * 1280 / w)), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        log(f"Screenshot: {e}", "ERROR")
        return None


def screenshot_save(path: Optional[str] = None) -> Optional[str]:
    if path is None:
        desk = Path.home() / "Desktop"
        if not desk.is_dir():
            desk = Path.home()
        path = str(desk / f"ares_{int(time.time())}.png")
    try:
        if _MSS:
            with mss.mss() as sct:
                raw = sct.grab(sct.monitors[1])
                mss.tools.to_png(raw.rgb, raw.size, output=path)
            return path
    except Exception as e:
        log(f"Screenshot save: {e}", "ERROR")
    return None
