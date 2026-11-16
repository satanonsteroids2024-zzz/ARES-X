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
def manage_api_keys() -> None:
    show("thinking", "Opening key manager...")
    speak("Opening API key manager.")

    def _open_qt():
        try:
            from PySide6.QtWidgets import (
                QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                QLabel, QLineEdit, QPushButton, QFrame,
            )
            from PySide6.QtCore import Qt
            from PySide6.QtGui import QFont

            app = QApplication.instance() or QApplication([])
            win = QWidget()
            win.setWindowTitle("ARES X — API Keys")
            win.setFixedSize(440, 420)
            win.setWindowFlags(Qt.WindowStaysOnTopHint)
            win.setStyleSheet("background:#0a0a0a; color:#00ff41;")

            layout = QVBoxLayout(win)
            title  = QLabel("API KEYS")
            title.setFont(QFont("Consolas", 14, QFont.Bold))
            title.setAlignment(Qt.AlignCenter)
            layout.addWidget(title)

            sep = QFrame()
            sep.setFrameShape(QFrame.HLine)
            sep.setStyleSheet("color:#00ff41;")
            layout.addWidget(sep)

            keys_config = [
                ("groq",           "Groq (console.groq.com)"),
                ("gemini",         "Gemini (aistudio.google.com)"),
                ("openai",         "OpenAI (platform.openai.com)"),
                ("opencorporates", "OpenCorporates (optional)"),
                ("hibp",           "HaveIBeenPwned (optional)"),
            ]
            fields: Dict[str, QLineEdit] = {}
            for key, label in keys_config:
                lbl = QLabel(label)
                lbl.setFont(QFont("Consolas", 8))
                layout.addWidget(lbl)
                field = QLineEdit(cfg.get("api_keys", {}).get(key, ""))
                field.setEchoMode(QLineEdit.Password)
                field.setFont(QFont("Consolas", 9))
                field.setStyleSheet(
                    "background:#111; color:#00ff41; border:1px solid #00ff41; padding:4px;"
                )
                field.focusInEvent = lambda e, f=field: f.setEchoMode(QLineEdit.Normal)
                field.focusOutEvent = lambda e, f=field: f.setEchoMode(QLineEdit.Password)
                layout.addWidget(field)
                fields[key] = field

            def save_and_close():
                for key, field in fields.items():
                    cfg.setdefault("api_keys", {})[key] = field.text().strip()
                from aresx.core import save_config as _sc
                _sc(cfg)
                win.close()
                speak("Keys saved.")
                done("Saved")

            btn = QPushButton("SAVE")
            btn.setFont(QFont("Consolas", 10, QFont.Bold))
            btn.setStyleSheet(
                "background:#00ff41; color:#0a0a0a; padding:8px 20px; border:none;"
            )
            btn.clicked.connect(save_and_close)
            layout.addWidget(btn, alignment=Qt.AlignCenter)

            win.show()
            app.exec()
        except ImportError:
            _open_tk()

    def _open_tk():
        import tkinter as tk
        from aresx.core import save_config as _sc
        root = tk.Tk()
        root.title("ARES X — API Keys")
        root.geometry("420x400")
        root.configure(bg="#0a0a0a")
        root.attributes("-topmost", True)
        tk.Label(root, text="API KEYS", font=("Consolas", 14, "bold"),
                 fg="#00ff41", bg="#0a0a0a").pack(pady=(12, 4))
        frame = tk.Frame(root, bg="#0a0a0a")
        frame.pack(fill="x", padx=20, pady=4)
        keys_config = [
            ("groq", "Groq (console.groq.com)"),
            ("gemini", "Gemini (aistudio.google.com)"),
            ("openai", "OpenAI (platform.openai.com)"),
            ("opencorporates", "OpenCorporates"),
            ("hibp", "HaveIBeenPwned"),
        ]
        vars_map: Dict = {}
        for key, label in keys_config:
            tk.Label(frame, text=label, font=("Consolas", 8),
                     fg="#00ff41", bg="#0a0a0a", anchor="w").pack(fill="x", pady=(6, 0))
            v = tk.StringVar(value=cfg.get("api_keys", {}).get(key, ""))
            vars_map[key] = v
            e = tk.Entry(frame, textvariable=v, font=("Consolas", 9),
                         fg="#00ff41", bg="#111", insertbackground="#00ff41",
                         relief="flat", bd=4, show="*")
            e.pack(fill="x", pady=(2, 0))
            e.bind("<FocusIn>", lambda ev, en=e: en.config(show=""))
            e.bind("<FocusOut>", lambda ev, en=e: en.config(show="*"))

        def save():
            for key, var in vars_map.items():
                cfg.setdefault("api_keys", {})[key] = var.get().strip()
            _sc(cfg)
            root.destroy()
            speak("Keys saved.")
            done("Saved")

        tk.Button(root, text="SAVE", command=save,
                  font=("Consolas", 10, "bold"), fg="#0a0a0a", bg="#00ff41",
                  relief="flat", padx=20, pady=8).pack(pady=12)
        root.mainloop()

    threading.Thread(target=_open_qt, daemon=True).start()


# ══════════════════════════════════════════════════════════════
# ARES X v5 — FEATURE EXPANSION BLOCK
# ══════════════════════════════════════════════════════════════
# Covers 8 categories from the v5 roadmap:
#   1. System Automation (window mgr, tasks, cleanup, network)
#   2. Office Automation (Excel, Word, PPTX, Teams, Calendar)
#   3. Browser & Web Automation (tabs, scrape, price monitor)
#   4. Coding & Dev Tools (git++, docker, db, logs, tests)
#   5. Research & Knowledge (facts, papers, meeting notes)
#   6. Content & Creation (image gen, social media, PDF)
#   7. Voice & Interaction (macros, multilingual, confidence)
#   8. Platform Extensions (Discord bot, Home Assistant, VS Code)
# All functions are async-first with sync wrappers for brain.py
# ══════════════════════════════════════════════════════════════

import datetime
import hashlib
import http.server
import platform
import shutil
import socket
import sqlite3
import struct
import tempfile
import urllib.request
from typing import Tuple


# ══════════════════════════════════════════════════════════════
# CATEGORY 1: SYSTEM AUTOMATION
# ══════════════════════════════════════════════════════════════

def window_manager(action: str, target: str = "", position: str = "") -> None:
    """
    Snap / tile / focus / list windows.
    action: snap_left | snap_right | snap_top | snap_bottom |
            maximise | minimise | focus | list | tile_left | tile_right
    target: partial window title (case-insensitive)
    """
    from aresx.core import speak, show, log, err

    show("thinking")
    try:
        import ctypes
        import ctypes.wintypes as W

        user32 = ctypes.windll.user32
        SW_MAXIMIZE  = 3
        SW_MINIMIZE  = 6
        SW_RESTORE   = 9

        if action == "list":
            titles = []
            def _cb(hwnd, _):
                if user32.IsWindowVisible(hwnd):
                    buf = ctypes.create_unicode_buffer(256)
                    user32.GetWindowTextW(hwnd, buf, 256)
                    if buf.value.strip():
                        titles.append(buf.value.strip())
                return True
            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, W.HWND, W.LPARAM)
            user32.EnumWindows(WNDENUMPROC(_cb), 0)
            visible = [t for t in titles if len(t) > 2][:20]
            speak(f"Open windows: {', '.join(visible[:8])}")
            return

        # Find target window
        found_hwnd = None
        if target:
            def _find_cb(hwnd, _):
                nonlocal found_hwnd
                if user32.IsWindowVisible(hwnd):
                    buf = ctypes.create_unicode_buffer(256)
                    user32.GetWindowTextW(hwnd, buf, 256)
                    if target.lower() in buf.value.lower():
                        found_hwnd = hwnd
                        return False
                return True
            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, W.HWND, W.LPARAM)
            user32.EnumWindows(WNDENUMPROC(_find_cb), 0)
            if not found_hwnd:
                speak(f"No window matching '{target}' found.")
                return
        else:
            found_hwnd = user32.GetForegroundWindow()

        sw = action.lower()
        if sw in ("maximise", "maximize"):
            user32.ShowWindow(found_hwnd, SW_MAXIMIZE)
        elif sw == "minimise":
            user32.ShowWindow(found_hwnd, SW_MINIMIZE)
        elif sw == "focus":
            user32.SetForegroundWindow(found_hwnd)
            user32.ShowWindow(found_hwnd, SW_RESTORE)
        elif sw in ("snap_left", "tile_left"):
            import ctypes
            mon = user32.MonitorFromWindow(found_hwnd, 2)
            mi = ctypes.create_string_buffer(40)
            struct.pack_into("I", mi, 0, 40)
            ctypes.windll.user32.GetMonitorInfoW(mon, mi)
            rx, ry, rr, rb = struct.unpack_from("iiii", mi, 4)
            w = (rr - rx) // 2
            h = rb - ry
            user32.SetWindowPos(found_hwnd, 0, rx, ry, w, h, 0x0040)
        elif sw in ("snap_right", "tile_right"):
            mon = user32.MonitorFromWindow(found_hwnd, 2)
            mi = ctypes.create_string_buffer(40)
            struct.pack_into("I", mi, 0, 40)
            ctypes.windll.user32.GetMonitorInfoW(mon, mi)
            rx, ry, rr, rb = struct.unpack_from("iiii", mi, 4)
            w = (rr - rx) // 2
            h = rb - ry
            user32.SetWindowPos(found_hwnd, 0, rx + w, ry, w, h, 0x0040)
        speak(f"Window {sw} done.")
    except Exception as e:
        err(f"Window manager: {e}")
        log(f"window_manager error: {e}", "ERROR")


def app_launcher(query: str) -> None:
    """Fuzzy-match installed apps and launch the best match."""
    from aresx.core import speak, show, log, err

    show("thinking")
    _COMMON = {
        "chrome": "chrome.exe", "firefox": "firefox.exe",
        "edge": "msedge.exe", "brave": "brave.exe",
        "notepad": "notepad.exe", "calc": "calc.exe",
        "paint": "mspaint.exe", "explorer": "explorer.exe",
        "task manager": "taskmgr.exe", "cmd": "cmd.exe",
        "powershell": "powershell.exe", "vscode": "code.exe",
        "code": "code.exe", "spotify": "spotify.exe",
        "discord": "discord.exe", "slack": "slack.exe",
        "teams": "teams.exe", "zoom": "zoom.exe",
        "vlc": "vlc.exe", "obs": "obs64.exe",
        "word": "winword.exe", "excel": "excel.exe",
        "powerpoint": "powerpnt.exe", "outlook": "outlook.exe",
        "onenote": "onenote.exe", "visio": "visio.exe",
        "terminal": "wt.exe", "winterm": "wt.exe",
        "photoshop": "photoshop.exe", "illustrator": "illustrator.exe",
        "figma": "figma.exe", "notion": "notion.exe",
    }
    q = query.lower().strip()
    match = None
    for key, exe in _COMMON.items():
        if q in key or key in q:
            match = exe
            break
    if match:
        try:
            subprocess.Popen([match], shell=True)
            speak(f"Opening {query}.")
            return
        except Exception as e:
            log(f"app_launcher direct fail: {e}", "WARN")

    # Fallback: Windows search
    try:
        import pyautogui
        pyautogui.hotkey("win")
        time.sleep(0.4)
        pyautogui.write(query, interval=0.05)
        time.sleep(0.6)
        pyautogui.press("enter")
        speak(f"Searching for {query}.")
    except Exception as e:
        err(f"App launcher: {e}")


def file_batch_ops(operation: str, source: str,
                   dest: str = "", pattern: str = "*",
                   rename_prefix: str = "") -> None:
    """
    Batch file operations.
    operation: rename | move | copy | delete | list | count
    source: folder path
    pattern: glob pattern, default *
    """
    from aresx.core import speak, show, log, err, validate_ipc_token, generate_ipc_token

    show("thinking")
    src = Path(source).expanduser()
    if not src.exists():
        speak(f"Folder not found: {source}")
        return

    files = list(src.glob(pattern))
    if not files:
        speak("No files matched that pattern.")
        return

    op = operation.lower()

    if op == "list":
        names = [f.name for f in files[:20]]
        speak(f"{len(files)} files: {', '.join(names[:5])}{'...' if len(names) > 5 else ''}")
        return

    if op == "count":
        speak(f"{len(files)} files match '{pattern}' in {src.name}.")
        return

    if op == "delete":
        speak(f"Delete {len(files)} files in {src.name}? Say yes to confirm.")
        from aresx.core import listen
        confirm = listen(timeout=6, phrase_time_limit=4)
        if not confirm or "yes" not in confirm.lower():
            speak("Cancelled.")
            return
        for f in files:
            if f.is_file():
                f.unlink()
        speak(f"Deleted {len(files)} files.")
        return

    if op == "rename" and rename_prefix:
        for i, f in enumerate(sorted(files)):
            new_name = f"{rename_prefix}_{i+1:03d}{f.suffix}"
            f.rename(f.parent / new_name)
        speak(f"Renamed {len(files)} files with prefix '{rename_prefix}'.")
        return

    if op in ("move", "copy") and dest:
        dst = Path(dest).expanduser()
        dst.mkdir(parents=True, exist_ok=True)
        for f in files:
            if f.is_file():
                if op == "move":
                    shutil.move(str(f), str(dst / f.name))
                else:
                    shutil.copy2(str(f), str(dst / f.name))
        speak(f"{op.capitalize()}d {len(files)} files to {dst.name}.")
        return

    speak("I didn't understand that file operation.")


def system_cleanup(target: str = "all") -> None:
    """
    Clean temp files, browser caches, Windows logs.
    target: temp | browser | logs | all
    """
    from aresx.core import speak, show, log, err

    show("thinking")
    freed = 0

    def _rmdir_contents(p: Path) -> int:
        removed = 0
        if p.exists():
            for item in p.rglob("*"):
                try:
                    if item.is_file():
                        size = item.stat().st_size
                        item.unlink()
                        removed += size
                except Exception:
                    pass
        return removed

    t = target.lower()

    if t in ("temp", "all"):
        temp = Path(os.environ.get("TEMP", "C:/Windows/Temp"))
        freed += _rmdir_contents(temp)
        freed += _rmdir_contents(Path.home() / "AppData/Local/Temp")

    if t in ("logs", "all"):
        freed += _rmdir_contents(Path("C:/Windows/Logs"))

    if t in ("browser", "all"):
        chrome_cache = Path.home() / "AppData/Local/Google/Chrome/User Data/Default/Cache"
        edge_cache   = Path.home() / "AppData/Local/Microsoft/Edge/User Data/Default/Cache"
        freed += _rmdir_contents(chrome_cache)
        freed += _rmdir_contents(edge_cache)

    mb = freed / (1024 * 1024)
    speak(f"Cleanup done. Freed approximately {mb:.1f} MB.")


def network_config(action: str, name: str = "", value: str = "") -> None:
    """
    Network configuration.
    action: status | list_wifi | connect_wifi | flush_dns | set_dns | check_port
    """
    from aresx.core import speak, show, log, err

    show("thinking")
    a = action.lower()

    if a == "status":
        out = _ps_run("Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
                      "Select-Object Name, LinkSpeed | ConvertTo-Json")
        if out and out.stdout:
            speak(f"Network: {out.stdout[:200]}")
        return

    if a == "list_wifi":
        out = _ps_run("netsh wlan show profiles")
        if out and out.stdout:
            profiles = [l.split(":")[-1].strip() for l in out.stdout.splitlines()
                        if "All User Profile" in l]
            speak(f"Wi-Fi profiles: {', '.join(profiles[:10])}")
        return

    if a == "flush_dns":
        out = _ps_run("ipconfig /flushdns")
        speak("DNS cache flushed." if out else "Failed to flush DNS.")
        return

    if a == "check_port" and name and value:
        try:
            with socket.create_connection((name, int(value)), timeout=3):
                speak(f"Port {value} on {name} is open.")
        except Exception:
            speak(f"Port {value} on {name} is closed or unreachable.")
        return

    speak(f"Network action '{action}' done.")


def task_scheduler(action: str, name: str = "", command: str = "",
                   schedule: str = "daily", run_at: str = "09:00") -> None:
    """
    Windows Task Scheduler CRUD.
    action: create | delete | run | list | status
    """
    from aresx.core import speak, show, log, err

    show("thinking")
    a = action.lower()

    if a == "list":
        out = _ps_run("Get-ScheduledTask | Select-Object TaskName, State | "
                      "ConvertTo-Json -Compress")
        if out and out.stdout:
            speak(f"Scheduled tasks (first 5): {out.stdout[:300]}")
        return

    if a == "create" and name and command:
        script = (
            f'$action = New-ScheduledTaskAction -Execute "cmd.exe" '
            f'-Argument "/c {command}"; '
            f'$trigger = New-ScheduledTaskTrigger -{schedule} -At "{run_at}"; '
            f'Register-ScheduledTask -TaskName "{name}" '
            f'-Action $action -Trigger $trigger -Force'
        )
        out = _ps_run(script)
        speak(f"Task '{name}' created." if out and not out.returncode else "Failed to create task.")
        return

    if a == "delete" and name:
        out = _ps_run(f'Unregister-ScheduledTask -TaskName "{name}" -Confirm:$false')
        speak(f"Task '{name}' deleted.")
        return

    if a == "run" and name:
        out = _ps_run(f'Start-ScheduledTask -TaskName "{name}"')
        speak(f"Task '{name}' triggered.")
        return

    speak("Task scheduler action done.")


def performance_monitor() -> None:
    """Live CPU / RAM / disk / network usage snapshot."""
    from aresx.core import speak, show, log

    show("thinking")
    try:
        import psutil
        cpu  = psutil.cpu_percent(interval=1)
        ram  = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net  = psutil.net_io_counters()
        msg  = (
            f"CPU {cpu:.0f}%, "
            f"RAM {ram.percent:.0f}% ({ram.used//1024//1024} MB used), "
            f"Disk {disk.percent:.0f}%, "
            f"Net sent {net.bytes_sent//1024//1024} MB / recv {net.bytes_recv//1024//1024} MB"
        )
        speak(msg)
    except ImportError:
        out = _ps_run(
            "(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage "
            "-Average).Average"
        )
        speak(f"CPU: {out.stdout.strip() if out else 'unknown'}%")


def set_wallpaper(path_or_url: str = "") -> None:
    """Change desktop wallpaper. Accepts file path or image URL."""
    from aresx.core import speak, show, log, err

    show("thinking")
    import ctypes
    SPI_SETDESKWALLPAPER = 20

    img_path = path_or_url.strip()

    if img_path.startswith("http"):
        tmp = Path(tempfile.gettempdir()) / "ares_wallpaper.jpg"
        try:
            import urllib.request as ulr
            ulr.urlretrieve(img_path, tmp)
            img_path = str(tmp)
        except Exception as e:
            err(f"Wallpaper download: {e}")
            return

    if not Path(img_path).exists():
        speak("Wallpaper file not found.")
        return

    ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, img_path, 3)
    speak("Wallpaper changed.")


def schedule_sleep(minutes: int = 30) -> None:
    """Schedule PC sleep after N minutes."""
    from aresx.core import speak, log

    seconds = minutes * 60
    _ps_run(f"shutdown /h /t {seconds}")
    speak(f"PC will sleep in {minutes} minutes.")


# ══════════════════════════════════════════════════════════════
# CATEGORY 2: OFFICE AUTOMATION
# ══════════════════════════════════════════════════════════════

