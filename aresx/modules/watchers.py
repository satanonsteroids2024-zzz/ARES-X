"""
ARES X v5 — Async Background Watchers
=======================================
• Async clipboard watcher (asyncio + injection sanitization)
• Perceptual Hash Engine for screen change detection (PIL imagehash)
• Camera ambient feed (cv2 → frame-diff → only process on change)
• Window cycling frustration detector (ctypes Win32, async-safe)
• All loops non-blocking — run on background asyncio executor threads
• Clipboard content sanitized for injection signatures before indexing
"""

from __future__ import annotations

import asyncio
import base64
import re
import subprocess
import threading
import time
from typing import Any, Optional

from ..core import (
    ARCHIVE_DIR, cfg, is_quiet_hours, log, mike, run_async, speak,
)

# ── Clipboard State ───────────────────────────────────────────
_clipboard_last:    str = ""
_clipboard_current: str = ""
_clipboard_lock = threading.Lock()

# ── Camera State ──────────────────────────────────────────────
_camera_brightness: int = 128
_camera_frame:      Optional[bytes] = None
_camera_lock = threading.Lock()

# ── Frustration State ─────────────────────────────────────────
_switch_times:       list = []
_frustration_level:  int  = 0
_frustration_lock = threading.Lock()

# ── Screen Hash State ─────────────────────────────────────────
_last_screen_hash: Optional[Any] = None
_screen_hash_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════
# INJECTION SANITIZER — for clipboard / screen content
# ══════════════════════════════════════════════════════════════
_INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"forget all previous",
    r"system:\s*you are now",
    r"new system prompt",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"\[\[.*?system.*?\]\]",
    r"\\x[0-9a-fA-F]{2}",
]


def _sanitize_content(text: str) -> str:
    """Strip prompt injection signatures from untrusted content."""
    for pat in _INJECTION_PATTERNS:
        text = re.sub(pat, "[SANITIZED]", text, flags=re.IGNORECASE | re.DOTALL)
    return text.strip()


# ══════════════════════════════════════════════════════════════
# CLIPBOARD WATCHER — async poll, injection-sanitized
# ══════════════════════════════════════════════════════════════
def get_clipboard() -> str:
    with _clipboard_lock:
        return _clipboard_current


async def _clipboard_loop_async() -> None:
    """Async clipboard watcher: poll every 2s via executor."""
    global _clipboard_last, _clipboard_current
    log("Async clipboard watcher started")
    loop = asyncio.get_running_loop()

    while True:
        try:
            def _read_clipboard() -> str:
                try:
                    result = subprocess.run(
                        ["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
                        capture_output=True, text=True, timeout=5,
                        encoding="utf-8", errors="ignore",
                    )
                    return (result.stdout or "").strip()
                except Exception:
                    return ""

            text = await loop.run_in_executor(None, _read_clipboard)

            if text and text != _clipboard_last:
                # Sanitize before indexing (Cognitive zone — untrusted)
                clean = _sanitize_content(text)
                with _clipboard_lock:
                    _clipboard_current = clean
                _clipboard_last = text  # compare against raw to detect changes

                log(f"Clipboard: {clean[:60]}...")
                # Index into Mike v3 memory (async)
                await mike.remember_async(
                    "_clipboard", clean[:500], tags=["clipboard", "temp"]
                )

        except Exception as e:
            log(f"Clipboard watcher: {e}", "WARN")

        await asyncio.sleep(2.0)


def start_clipboard_watcher() -> None:
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_clipboard_loop_async())

    threading.Thread(target=_run, daemon=True, name="clipboard_watcher").start()


# ══════════════════════════════════════════════════════════════
# PERCEPTUAL HASH ENGINE — detect screen changes efficiently
# ══════════════════════════════════════════════════════════════
try:
    import imagehash
    from PIL import Image as _PILImage
    _IMAGEHASH = True
except ImportError:
    _IMAGEHASH = False


def compute_screen_hash() -> Optional[Any]:
    """Compute perceptual hash of current screen for change detection."""
    if not _IMAGEHASH:
        return None
    try:
        import mss
        with mss.mss() as sct:
            raw = sct.grab(sct.monitors[1])
            img = _PILImage.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
        # Downsample for hash efficiency
        img = img.resize((64, 36), _PILImage.LANCZOS).convert("L")
        return imagehash.phash(img)
    except Exception as e:
        log(f"Screen hash: {e}", "WARN")
        return None


def screen_changed(threshold: int = 8) -> bool:
    """
    Returns True if screen has changed significantly since last check.
    threshold: max Hamming distance before considered 'same'
    """
    global _last_screen_hash
    new_hash = compute_screen_hash()
    if new_hash is None:
        return False
    with _screen_hash_lock:
        if _last_screen_hash is None:
            _last_screen_hash = new_hash
            return True
        changed = (_last_screen_hash - new_hash) > threshold
        if changed:
            _last_screen_hash = new_hash
        return changed


# ══════════════════════════════════════════════════════════════
# CAMERA AMBIENT FEED — frame-diff triggered, low CPU
# ══════════════════════════════════════════════════════════════
def get_ambient_brightness() -> int:
    with _camera_lock:
        return _camera_brightness


def get_camera_frame_b64() -> Optional[str]:
    with _camera_lock:
        if _camera_frame:
            return base64.b64encode(_camera_frame).decode()
    return None


async def _camera_loop_async() -> None:
    """
    Async camera feed: capture via executor, only encode on brightness change.
    CPU target: <0.5% on idle.
    """
    global _camera_brightness, _camera_frame
    loop = asyncio.get_running_loop()

    try:
        import cv2
    except ImportError:
        log("cv2 not installed — camera disabled (pip install opencv-python)", "WARN")
        return

    log("Async camera feed started (frame-diff triggered)")

    def _open_cap():
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        if not cap.isOpened():
            return None
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 320)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 240)
        return cap

    cap = await loop.run_in_executor(None, _open_cap)
    if cap is None:
        log("No webcam — camera disabled", "WARN")
        return

    last_brightness = -1

    try:
        while True:
            def _read_frame():
                ret, frame = cap.read()
                if not ret:
                    return None, None
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                brightness = int(gray.mean())
                return frame, brightness

            frame, brightness = await loop.run_in_executor(None, _read_frame)

            if frame is None:
                await asyncio.sleep(5.0)
                continue

            with _camera_lock:
                _camera_brightness = brightness

            # Only encode frame if brightness changed significantly (frame-diff)
            if abs(brightness - last_brightness) > 5:
                def _encode(f):
                    success, buf = cv2.imencode(
                        ".jpg", f, [cv2.IMWRITE_JPEG_QUALITY, 50]
                    )
                    return buf.tobytes() if success else None

                encoded = await loop.run_in_executor(None, _encode, frame)
                with _camera_lock:
                    _camera_frame = encoded
                last_brightness = brightness

            await asyncio.sleep(3.0)
    finally:
        def _release():
            try:
                cap.release()
            except Exception:
                pass

        await loop.run_in_executor(None, _release)


def start_camera_feed() -> None:
    if not cfg.get("camera_enabled"):
        log("Camera disabled in config")
        return

    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_camera_loop_async())

    threading.Thread(target=_run, daemon=True, name="camera_feed").start()


# ══════════════════════════════════════════════════════════════
# WINDOW CYCLING FRUSTRATION DETECTOR — async-safe Win32 poll
# ══════════════════════════════════════════════════════════════
def get_frustration() -> int:
    with _frustration_lock:
        return _frustration_level


async def _frustration_loop_async() -> None:
    """
    Async frustration detector: poll foreground window every 5s via executor.
    Rapid window switches → elevated frustration score → ambient support message.
    """
    global _frustration_level
    log("Async frustration detector started")
    loop = asyncio.get_running_loop()

    try:
        import ctypes
        user32 = ctypes.windll.user32
    except (ImportError, AttributeError, OSError):
        log("No Win32 API — frustration detector disabled", "WARN")
        return

    last_title = ""
    _last_alert = 0.0

    while True:
        try:
            def _get_title() -> str:
                hwnd   = user32.GetForegroundWindow()
                length = user32.GetWindowTextLengthW(hwnd)
                buf    = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                return buf.value

            title = await loop.run_in_executor(None, _get_title)

            if title and title != last_title:
                _switch_times.append(time.time())
                last_title = title

            # Prune switch times older than 60s
            cutoff = time.time() - 60
            while _switch_times and _switch_times[0] < cutoff:
                _switch_times.pop(0)

            count = len(_switch_times)
            with _frustration_lock:
                if count > 15:
                    _frustration_level = min(100, count * 4)
                elif count > 8:
                    _frustration_level = count * 3
                else:
                    _frustration_level = max(0, _frustration_level - 5)

            # Alert if very high (max once per 5 min)
            if _frustration_level > 80 and not is_quiet_hours():
                now = time.time()
                if now - _last_alert > 300:
                    _last_alert = now
                    speak("Hey, you seem stressed. Take a breath. I'm here if you need.")
                    await mike.log_pattern_async(
                        "frustration",
                        f"level={_frustration_level} switches={count}/min",
                    )

        except Exception as e:
            log(f"Frustration detector: {e}", "WARN")

        await asyncio.sleep(5.0)


def start_frustration_detector() -> None:
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_frustration_loop_async())

    threading.Thread(target=_run, daemon=True, name="frustration_detector").start()


# ══════════════════════════════════════════════════════════════
# START ALL WATCHERS
# ══════════════════════════════════════════════════════════════
def start_all() -> None:
    start_clipboard_watcher()
    start_camera_feed()
    start_frustration_detector()
    log("All async watchers started")
