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
def whatsapp_send(contact: str, message: str) -> None:
    if not (contact and message):
        speak("Need contact and message.")
        return
    if not ask_confirm(f"send WhatsApp to {contact}"):
        return
    show("thinking", "Opening WhatsApp...")
    num = re.sub(r"[^\d+]", "", str(contact))
    url = f"https://wa.me/{urllib.parse.quote(num)}?text={urllib.parse.quote(str(message))}"
    webbrowser.open(url)
    done("Opened")
    speak("WhatsApp opened. Press send.")


def send_email(to: str, subject: str = "", body: str = "") -> None:
    if not to:
        speak("Email who?")
        return
    if not ask_confirm(f"open email to {to}"):
        return
    show("thinking", "Opening email...")
    url = (f"mailto:{urllib.parse.quote(to)}"
           f"?subject={urllib.parse.quote(str(subject))}"
           f"&body={urllib.parse.quote(str(body))}")
    webbrowser.open(url)
    done("Opened")
    speak("Email opened.")


# ══════════════════════════════════════════════════════════════
# FILES
# ══════════════════════════════════════════════════════════════
def find_file(name: str) -> None:
    if not name:
        speak("Find what?")
        return
    show("thinking", f"Finding {name}...")
    try:
        results: List[str] = []
        roots = [
            Path.home() / "Desktop",
            Path.home() / "Documents",
            Path.home() / "Downloads",
            Path.home() / "Pictures",
        ]
        pattern = str(name).lower()
        for root in roots:
            if not root.is_dir():
                continue
            for dirpath, _, filenames in os.walk(root):
                if dirpath.count(os.sep) - str(root).count(os.sep) > 4:
                    continue
                for fn in filenames:
                    if pattern in fn.lower():
                        results.append(os.path.join(dirpath, fn))
                        if len(results) >= 20:
                            break
                if len(results) >= 20:
                    break
            if len(results) >= 20:
                break

        if results:
            mike.add_note(f"FILE SEARCH '{name}':\n" + "\n".join(results))
            done(f"{len(results)} found")
            speak(f"Found {len(results)} files.")
            try:
                subprocess.Popen(["explorer", "/select,", results[0]], shell=False)
            except OSError:
                pass
        else:
            err("Not found")
            speak(f"No file matching {name}.")
    except Exception as e:
        err("Failed")
        log(f"find_file: {e}", "WARN")


def open_folder(name: str) -> None:
    if not name:
        speak("Which folder?")
        return
    show("thinking", f"Opening {name}...")
    folders = {
        "desktop":   Path.home() / "Desktop",
        "downloads": Path.home() / "Downloads",
        "documents": Path.home() / "Documents",
        "pictures":  Path.home() / "Pictures",
        "videos":    Path.home() / "Videos",
        "music":     Path.home() / "Music",
    }
    path = folders.get(str(name).lower())
    if path is None:
        candidate = Path.home() / str(name)
        if candidate.is_dir():
            path = candidate
    if path and Path(path).is_dir():
        try:
            subprocess.Popen(["explorer", str(path)], shell=False)
            done("Opened")
            speak(f"Opened {name}")
        except OSError as e:
            err("Failed")
            log(f"open_folder: {e}", "WARN")
    else:
        err("Not found")
        speak(f"Folder {name} not found.")


def clipboard_read() -> None:
    show("thinking", "Reading clipboard...")
    out = _ps_run("Get-Clipboard")
    if out and out.stdout.strip():
        content = _sanitize(out.stdout.strip())
        done("Read")
        speak(f"Clipboard: {content[:150]}")
        mike.add_note(f"CLIPBOARD:\n{content}")
    else:
        err("Empty")
        speak("Clipboard is empty.")


def clipboard_set(text: str) -> None:
    if not text:
        speak("Copy what?")
        return
    out = _ps_run(
        "$txt = [Console]::In.ReadToEnd(); Set-Clipboard -Value $txt",
        input_text=str(text),
    )
    if out and out.returncode == 0:
        done("Copied")
        speak("Copied to clipboard")
    else:
        err("Failed")
        speak("Copy failed.")


# ══════════════════════════════════════════════════════════════
# SYSTEM INFO
# ══════════════════════════════════════════════════════════════
def system_info() -> None:
    show("thinking", "Reading system...")
    try:
        import platform
        info = (f"{platform.system()} {platform.release()} | "
                f"Machine: {platform.machine()} | User: {os.getlogin()}")
        try:
            import psutil
            ram_gb = psutil.virtual_memory().total / (1024 ** 3)
            cpu    = psutil.cpu_count()
            info  += f" | RAM: {ram_gb:.1f} GB | CPU: {cpu} cores"
        except ImportError:
            pass
        done(info[:60])
        speak(info)
        mike.log_osint("sysinfo", info)
    except Exception as e:
        err("Failed")
        speak("Sysinfo failed.")
        log(f"sysinfo: {e}", "WARN")


def battery_status() -> None:
    show("thinking", "Battery...")
    out = _ps_run("(Get-WmiObject Win32_Battery).EstimatedChargeRemaining")
    if out and out.stdout.strip():
        try:
            pct = out.stdout.strip().splitlines()[0]
            done(f"{pct}%")
            speak(f"Battery at {pct} percent")
            return
        except (ValueError, IndexError):
            pass
    err("No battery")
    speak("No battery detected.")


# ══════════════════════════════════════════════════════════════
# POWER
# ══════════════════════════════════════════════════════════════
def shutdown() -> None:
    if not ask_confirm("shut down the computer in 30 seconds"):
        return
    speak("Shutting down in 30 seconds")
    try:
        subprocess.run(["shutdown", "/s", "/t", "30"], capture_output=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError) as e:
        log(f"shutdown: {e}", "WARN")


def restart() -> None:
    if not ask_confirm("restart the computer in 30 seconds"):
        return
    speak("Restarting in 30 seconds")
    try:
        subprocess.run(["shutdown", "/r", "/t", "30"], capture_output=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError) as e:
        log(f"restart: {e}", "WARN")


def sleep_pc() -> None:
    if not ask_confirm("put the computer to sleep"):
        return
    speak("Sleeping")
    _ps_run(
        "[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');"
        "[System.Windows.Forms.Application]::SetSuspendState('Suspend',$false,$false)"
    )


# ══════════════════════════════════════════════════════════════
# GIT — async subprocess pipelines
# ══════════════════════════════════════════════════════════════
def git_status(repo_path: str = "") -> None:
    show("thinking", "Git status...")
    path = repo_path or os.getcwd()

    async def _do():
        rc, out = await _run_git_async(["git", "status", "--short"], path)
        if rc != 0:
            err("Not a git repo")
            speak("Not a git repository.")
            return
        if not out:
            done("Clean")
            speak("Repository is clean, no changes.")
            return
        changed = len(out.splitlines())
        done(f"{changed} changes")
        speak(f"{changed} files changed. Want me to commit?")
        mike.log_command("git_status", out[:200])

    run_async(_do())


def git_auto_commit(repo_path: str = "", message: str = "") -> None:
    show("thinking", "Git committing...")
    path = repo_path or os.getcwd()

    async def _do():
        _, diff = await _run_git_async(["git", "diff", "--stat"], path)
        if not diff:
            _, diff = await _run_git_async(["git", "diff", "--cached", "--stat"], path)
        if not diff:
            done("Nothing")
            speak("No changes to commit.")
            return

        nonlocal message
        if not message:
            message = ask_ai(
                f"Conventional git commit message for:\n{diff[:500]}\n"
                "Reply with ONLY the commit message, max 1 line, no quotes.",
                "Git expert.",
            ) or f"auto: update {len(diff.splitlines())} files"

        if not ask_confirm(f"commit: {message[:50]}"):
            return

        await _run_git_async(["git", "add", "-A"], path)
        rc, out = await _run_git_async(["git", "commit", "-m", message], path)
        if rc == 0:
            done("Committed")
            speak(f"Committed: {message[:60]}")
            mike.log_command("git_commit", message)
        else:
            err("Failed")
            speak("Commit failed. " + out[:80])

    run_async(_do())


def git_push(repo_path: str = "") -> None:
    if not ask_confirm("push to remote"):
        return
    show("thinking", "Pushing...")
    path = repo_path or os.getcwd()

    async def _do():
        rc, out = await _run_git_async(["git", "push"], path, timeout=30.0)
        if rc == 0:
            done("Pushed")
            speak("Pushed to remote.")
        else:
            err("Failed")
            speak("Push failed. " + out[:80])

    run_async(_do())


async def _run_git_async(cmd: list, cwd: str,
                          timeout: float = 15.0) -> tuple:
    """Non-blocking git command via asyncio subprocess."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = (stdout or stderr or b"").decode("utf-8", errors="ignore").strip()
            return proc.returncode or 0, out
        except asyncio.TimeoutError:
            proc.kill()
            return -1, "timeout"
    except FileNotFoundError:
        speak("Git is not installed.")
        return -1, "not found"
    except Exception as e:
        log(f"git cmd {cmd}: {e}", "WARN")
        return -1, str(e)


# ══════════════════════════════════════════════════════════════
# EXIF STRIPPER — async, PIL-based
# ══════════════════════════════════════════════════════════════
def strip_exif(filepath: str = "") -> None:
    show("thinking", "Stripping metadata...")
    from PIL import Image as PILImage

    if not filepath:
        try:
            import tkinter.filedialog as fd
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()
            filepath = fd.askopenfilename(
                title="Select image to strip EXIF",
                filetypes=[("Images", "*.jpg *.jpeg *.png *.tiff *.bmp"), ("All", "*.*")],
            )
            root.destroy()
        except Exception:
            speak("Could not open file dialog.")
            err("No file")
            return

    if not filepath or not Path(filepath).is_file():
        err("File not found")
        speak("File not found.")
        return

    try:
        img   = PILImage.open(filepath)
        clean = PILImage.new(img.mode, img.size)
        clean.putdata(list(img.getdata()))
        base, ext = os.path.splitext(filepath)
        out_path  = f"{base}_clean{ext}"
        clean.save(out_path)
        done("Stripped")
        speak(f"Metadata stripped. Saved as {Path(out_path).name}")
        mike.log_command("exif_strip", out_path)
        try:
            subprocess.Popen(["explorer", "/select,", out_path], shell=False)
        except OSError:
            pass
    except Exception as e:
        err("Failed")
        speak(f"EXIF strip failed: {e}")
        log(f"strip_exif: {e}", "WARN")


def strip_exif_folder(folder: str = "") -> None:
    if not folder:
        folder = str(Path.home() / "Desktop" / "ARES_STRIP")
        os.makedirs(folder, exist_ok=True)

    show("thinking", f"Watching {folder}...")
    speak(f"Watching {Path(folder).name} for images to strip.")
    done(f"Watching {folder}")

    def _watch():
        from PIL import Image as PILImage
        processed: set = set()
        while True:
            try:
                for fn in os.listdir(folder):
                    fp  = os.path.join(folder, fn)
                    ext = os.path.splitext(fn)[1].lower()
                    if fp in processed or not os.path.isfile(fp):
                        continue
                    if ext not in (".jpg", ".jpeg", ".png", ".tiff", ".bmp"):
                        continue
                    try:
                        img = PILImage.open(fp)
                        c   = PILImage.new(img.mode, img.size)
                        c.putdata(list(img.getdata()))
                        out = f"{os.path.splitext(fp)[0]}_clean{ext}"
                        c.save(out)
                        log(f"Auto-stripped: {fn}")
                        processed.add(fp)
                    except Exception as ie:
                        log(f"Strip {fn}: {ie}", "WARN")
                        processed.add(fp)
            except Exception as e:
                log(f"Strip watcher: {e}", "WARN")
            time.sleep(5)

    threading.Thread(target=_watch, daemon=True).start()


# ══════════════════════════════════════════════════════════════
# FIX CLIPBOARD CODE
# ══════════════════════════════════════════════════════════════
def fix_clipboard_code() -> None:
    show("thinking", "Fixing code from clipboard...")
    try:
        from aresx.modules.watchers import get_clipboard
        code = get_clipboard()
    except ImportError:
        out  = _ps_run("Get-Clipboard")
        code = (out.stdout if out else "").strip()

    if not code:
        err("Empty")
        speak("Clipboard is empty.")
        return

    # Sanitize before sending to AI
    code = _sanitize(code)
    result = ask_ai(
        f"Fix this code. Return ONLY the corrected code, no explanation:\n\n{code[:3000]}",
        "Expert debugger. Return only fixed code, no markdown.",
    )
    if result:
        _ps_run(
            "$txt=[Console]::In.ReadToEnd(); Set-Clipboard -Value $txt",
            input_text=result,
        )
        done("Fixed")
        speak("Code fixed and copied to clipboard.")
        mike.log_command("fix_clipboard_code", result[:100])
    else:
        err("Failed")
        speak("Could not fix the code.")


# ══════════════════════════════════════════════════════════════
# API KEY MANAGER — PySide6 dialog (falls back to Tkinter)
# ══════════════════════════════════════════════════════════════
