#!/usr/bin/env python3
"""
ARES X v9 — Native Desktop Launcher (Kali / XFCE)
====================================================
Runs the exact same FastAPI backend as ares_server.py, but instead of
opening a browser tab, wraps the chat UI in a real native GTK window —
own icon, own taskbar entry, closable/minimizable like any other app.

This does NOT duplicate ares_server.py's logic. It imports and reuses
the same FastAPI `app` object, so there is exactly one backend
implementation — this file only changes how the frontend is presented.

Requires: pywebview with the GTK backend (python3-webview + PyGObject,
both standard on Kali's XFCE desktop — see packaging/install.sh).
"""
from __future__ import annotations

import logging
import sys
import threading
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ares_native")

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path: sys.path.insert(0, str(APP_DIR))


def _start_backend() -> None:
    """
    Boot ARES + start uvicorn in a background thread. Reuses the exact
    same `app` object as ares_server.py — no separate backend logic.
    """
    import uvicorn
    from ares_server import app  # noqa: E402 — boots ARES on import, by design

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")


def _wait_for_backend(url: str, timeout_s: float = 15.0) -> bool:
    """Poll until the backend actually responds, so the window doesn't
    open to a blank/error page during the ~1s ARES boot + server startup."""
    import urllib.request

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1.5)
            return True
        except Exception:
            time.sleep(0.3)
    return False


def main() -> None:
    try:
        import webview
    except ImportError:
        logger.error(
            "pywebview not installed. Run packaging/install.sh first, "
            "or: pip install --break-system-packages pywebview PyGObject"
        )
        sys.exit(1)

    backend_thread = threading.Thread(target=_start_backend, daemon=True, name="ares-backend")
    backend_thread.start()

    logger.info("Waiting for ARES backend to come online...")
    if not _wait_for_backend("http://127.0.0.1:8000/status"):
        logger.error("Backend did not respond within timeout — check logs above for boot errors.")
        sys.exit(1)
    logger.info("Backend online — opening native window.")

    icon_path = APP_DIR / "packaging" / "ares-x.png"

    webview.create_window(
        title="ARES X v9 — TITAN",
        url="http://127.0.0.1:8000/",
        width=1280,
        height=820,
        min_size=(820, 560),
        background_color="#0a0a0a",
        text_select=True,
    )

    # GTK is the correct backend on XFCE (GTK-based desktop) — explicit
    # rather than relying on autodetection, so it doesn't silently try Qt.
    webview.start(gui="gtk", icon=str(icon_path) if icon_path.exists() else None)


if __name__ == "__main__":
    main()
