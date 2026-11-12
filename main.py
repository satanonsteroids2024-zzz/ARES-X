#!/usr/bin/env python3
"""
ARES X v10 — Single Launcher
===============================
One entry point replacing the three v9 scripts (ares_x.py / ares_server.py /
ares_native.py). Presentation mode is chosen with a subcommand:

    python3 main.py desktop     # Qt orb + tray + wake-word (was ares_x.py)
    python3 main.py server      # FastAPI chat server + browser UI (was ares_server.py)
    python3 main.py native      # GTK native window over the same server (was ares_native.py)

Global flags (before the subcommand):
    --debug                     verbose logging
    --setup                     force setup wizard
    --port PORT                 server port (default 8000)

Everything stays optional and import-lazy, exactly like v9: a missing
PySide6, webview, or FastAPI degrades gracefully or prints a clear
dependency hint instead of crashing the whole boot.
"""
from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR))  # only here, once, at project root

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("aresx.main")

MODES = {
    "desktop": "ares_x.py",
    "server":  "ares_server.py",
    "native":  "ares_native.py",
}


def _run_script(script: Path, extra_args: list[str]) -> None:
    """Run a legacy entry script in a subprocess with PYTHONPATH rooted here,
    so no entry script needs its own sys.path hacks for downstream uses."""
    env = {**__import__("os").environ}
    pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{APP_DIR}" + (f":{pythonpath}" if pythonpath else "")
    raise SystemExit(subprocess.call(
        [sys.executable, str(script), *extra_args], cwd=str(APP_DIR), env=env))


def cmd_desktop(args: argparse.Namespace) -> None:
    from ares_x import boot  # boots Qt orb, healers, watchers, tray, wizard/wake
    boot(
        headless=getattr(args, "headless", False),
        force_setup=args.setup,
        debug=args.debug,
    )


def cmd_server(args: argparse.Namespace) -> None:
    """Start the FastAPI server via uvicorn. Boot happens inside ares_server
    on import (by design — same as v9), then uvicorn serves the app."""
    import ares_server
    import uvicorn
    uvicorn.run(ares_server.app, host="0.0.0.0", port=args.port,
                log_level="warning")


def cmd_native(args: argparse.Namespace) -> None:
    try:
        from ares_native import main as native_main
        native_main()
    except ImportError as exc:
        logger.error(
            "Native mode needs pywebview (python3-webview) and PyGObject, "
            "standard on Kali XFCE: sudo apt install -y python3-webview python3-gi\n"
            "Original error: %s", exc)
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aresx",
        description="ARES X v10 — Sovereign Intelligence OS (single launcher)",
    )
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    parser.add_argument("--setup", action="store_true", help="force setup wizard")
    parser.add_argument("--port", type=int, default=8000, help="server port")
    parser.add_argument(
        "--headless", action="store_true",
        help="desktop mode: run without Orb overlay or system tray")

    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("desktop", help="Qt orb + tray + wake-word desktop agent (legacy ares_x.py)")
    sub.add_parser("server", help="FastAPI chat server + browser UI (legacy ares_server.py)")
    sub.add_parser("native", help="GTK native window over the chat server (legacy ares_native.py)")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    {
        "desktop": cmd_desktop,
        "server": cmd_server,
        "native": cmd_native,
    }[args.mode](args)


if __name__ == "__main__":
    main()
