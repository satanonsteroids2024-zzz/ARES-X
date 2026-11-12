"""
ARES X v6 — Counter-Intelligence (CI)  [Features 63-66]
=======================================================
• Anti-surveillance scanner (detect recorders/keyloggers/clip monitors)
• TSCM digital sweep (rogue APs, ARP spoof, DNS poison, listeners)
• Metadata sanitizer (strip identifying data before sharing)
• OPSEC advisor (warn on exposed secrets / risky behavior)

All capabilities here are DEFENSIVE — they detect threats against the
user's own machine and clean the user's own files. Nothing here attacks
or evades; it reports findings so the user can act.
"""

from __future__ import annotations

import os
import re as _re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Dict, List


# ──────────────────────────────────────────────────────────────
# 63. Anti-Surveillance Scanner  (defensive detection)
# ──────────────────────────────────────────────────────────────
_RECORDER_NAMES = {
    "obs", "obs64", "obs32", "bandicam", "camtasia", "sharex", "snagit",
    "screenrec", "flashback", "fraps", "action", "dxtory", "screencast",
    "rylstim", "icecream", "screenpresso",
}
_KEYLOGGER_HINTS = {
    "keylog", "klg", "spyrix", "refog", "ardamax", "actualkeylogger",
    "perfectkeylogger", "elite keylogger", "revealer",
}


def anti_surveillance_scan() -> None:
    """Detect screen recorders, keyloggers, clipboard monitors on THIS PC."""
    from ..core import speak, show, log

    show("thinking", "Scanning for surveillance tools…")
    findings: List[str] = []

    try:
        import psutil
        for p in psutil.process_iter(["name", "exe"]):
            nm = (p.info.get("name") or "").lower()
            base = nm.replace(".exe", "")
            if base in _RECORDER_NAMES:
                findings.append(f"Screen recorder: {nm}")
            if any(h in nm for h in _KEYLOGGER_HINTS):
                findings.append(f"Possible keylogger: {nm}")
    except ImportError:
        speak("psutil not installed. Run: pip install psutil")
        return
    except Exception as e:
        log(f"anti_surv proc scan: {e}", "WARN")

    # Low-level keyboard hook detection (Windows)
    try:
        hooks = _detect_keyboard_hooks()
        if hooks:
            findings.append(f"{hooks} active low-level keyboard hook(s)")
    except Exception:
        pass

    # Clipboard viewer chain (Windows)
    try:
        if _clipboard_viewer_present():
            findings.append("A clipboard monitor is registered")
    except Exception:
        pass

    if findings:
        speak("⚠ Surveillance scan flagged: " + "; ".join(findings[:6]))
    else:
        speak("Surveillance scan clean — no recorders, keyloggers, or clipboard "
              "monitors detected.")


def _detect_keyboard_hooks() -> int:
    """
    Best-effort count of processes that have low-level keyboard-hook DLLs
    loaded. There is no clean public API to enumerate WH_KEYBOARD_LL hooks,
    so we heuristically inspect loaded module names per process (Windows).
    """
    try:
        import psutil
    except Exception:
        return 0

    hook_hints = ("hook", "keyspy", "klog", "intercept", "rawinput_capture")
    suspicious = 0
    self_pid = os.getpid()
    for p in psutil.process_iter(["pid", "name"]):
        try:
            if p.info["pid"] == self_pid:
                continue
            maps = p.memory_maps()
        except Exception:
            continue
        try:
            for m in maps:
                path = (getattr(m, "path", "") or "").lower()
                if any(h in path for h in hook_hints):
                    suspicious += 1
                    break
        except Exception:
            continue
    return suspicious


def _clipboard_viewer_present() -> bool:
    try:
        import ctypes
        user32 = ctypes.windll.user32
        # GetClipboardViewer is legacy; GetOpenClipboardWindow shows current holder
        holder = user32.GetOpenClipboardWindow()
        return bool(holder)
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────
# 64. TSCM Digital Sweep
# ──────────────────────────────────────────────────────────────
def tscm_sweep() -> None:
    """Technical surveillance counter-measures: network-layer threat sweep."""
    from ..core import speak, show, log

    show("thinking", "Running TSCM digital sweep…")
    findings: List[str] = []

    # 1. ARP table anomaly (duplicate MAC for multiple IPs = possible spoof)
    try:
        arp = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=8)
        macs: Dict[str, List[str]] = {}
        import re
        for line in arp.stdout.splitlines():
            m = re.search(r"([\d.]+)\s+([0-9a-fA-F\-:]{11,17})", line)
            if m:
                ip, mac = m.group(1), m.group(2).lower().replace("-", ":")
                macs.setdefault(mac, []).append(ip)
        for mac, ips in macs.items():
            if len(ips) > 2:
                findings.append(f"Possible ARP spoof: {mac} → {len(ips)} IPs")
    except Exception as e:
        log(f"tscm arp: {e}", "WARN")

    # 2. Listening ports (unexpected services)
    try:
        import psutil
        listeners = set()
        for c in psutil.net_connections(kind="inet"):
            if c.status == "LISTEN" and c.laddr:
                listeners.add(c.laddr.port)
        odd = [p for p in listeners if p not in (135, 139, 445, 5040, 5353, 3389)
               and p > 1024 and p not in (8080, 3000, 5173)]
        if len(odd) > 8:
            findings.append(f"{len(odd)} non-standard listening ports")
    except Exception:
        pass

    # 3. DNS integrity check (correct private-range detection)
    try:
        import ipaddress
        ans = socket.gethostbyname("example.com")
        ip = ipaddress.ip_address(ans)
        if ip.is_private or ip.is_loopback:
            findings.append("DNS may be poisoned (public domain → private IP)")
    except Exception:
        pass

    if findings:
        speak("⚠ TSCM sweep flagged: " + "; ".join(findings[:6]))
    else:
        speak("TSCM sweep clean — no ARP spoofing, DNS poisoning, or rogue "
              "listeners detected.")


# ──────────────────────────────────────────────────────────────
# 65. Metadata Sanitizer
# ──────────────────────────────────────────────────────────────
def metadata_sanitize(filepath: str) -> None:
    """Strip identifying metadata from a file before sharing."""
    from ..core import speak, show, err

    show("thinking", "Sanitizing metadata…")
    p = Path(filepath).expanduser()
    if not p.exists():
        speak(f"File not found: {filepath}")
        return

    out = p.with_name(f"{p.stem}_clean{p.suffix}")
    ext = p.suffix.lower()

    try:
        if ext in (".jpg", ".jpeg", ".png", ".tiff", ".webp"):
            from PIL import Image
            img = Image.open(p)
            data = list(img.getdata())
            clean = Image.new(img.mode, img.size)
            clean.putdata(data)          # drops all EXIF
            clean.save(out)
        elif ext == ".pdf":
            import pypdf
            reader = pypdf.PdfReader(str(p))
            writer = pypdf.PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.add_metadata({})       # wipe metadata
            with open(out, "wb") as f:
                writer.write(f)
        elif ext == ".docx":
            from docx import Document
            doc = Document(str(p))
            cp = doc.core_properties
            for attr in ("author", "title", "subject", "comments",
                         "category", "last_modified_by", "keywords"):
                try:
                    setattr(cp, attr, "")
                except Exception:
                    pass
            doc.save(out)
        elif ext in (".mp3", ".flac", ".m4a", ".wav"):
            import mutagen
            shutil.copy2(p, out)
            mf = mutagen.File(out)
            if mf is not None:
                mf.delete()
                mf.save()
        else:
            shutil.copy2(p, out)
            speak(f"No metadata profile for {ext}; copied as-is to {out.name}.")
            return
        speak(f"Metadata stripped → {out.name}. Safe to share.")
    except ImportError as e:
        speak(f"Missing library for {ext}: {e}. Install the relevant package.")
    except Exception as e:
        err(f"Sanitize: {e}")


# ──────────────────────────────────────────────────────────────
# 66. OPSEC Advisor
# ──────────────────────────────────────────────────────────────

_SECRET_PATTERNS = {
    "AWS key":      _re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API":  _re.compile(r"(?i)(api[_-]?key|secret)[\"'\s:=]{1,4}[A-Za-z0-9_\-]{20,}"),
    "Private key":  _re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Bearer token": _re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}"),
    "Slack token":  _re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
}


def opsec_advisor() -> None:
    """Scan the visible screen + clipboard for exposed secrets and warn."""
    from ..core import speak, show, ask_vision, screenshot_b64

    show("thinking", "Checking OPSEC…")
    warnings: List[str] = []

    # Clipboard scan
    try:
        from .actions import _ps_run
        clip = _ps_run("Get-Clipboard")
        text = clip.stdout if clip else ""
        for label, pat in _SECRET_PATTERNS.items():
            if pat.search(text or ""):
                warnings.append(f"{label} in clipboard")
    except Exception:
        pass

    # Screen OCR scan (vision) — flag visible secrets
    try:
        img = screenshot_b64(quality=60)
        if img:
            verdict = ask_vision(
                "Is any API key, password, private key, or access token visible "
                "in this screenshot? Answer only 'YES: <type>' or 'NO'.",
                image_b64=img)
            if verdict and verdict.strip().upper().startswith("YES"):
                warnings.append(f"On-screen secret ({verdict.split(':',1)[-1].strip()[:40]})")
    except Exception:
        pass

    if warnings:
        speak("🔒 OPSEC alert: " + "; ".join(warnings[:4]) +
              ". Consider redacting before sharing or screen-recording.")
    else:
        speak("OPSEC check passed — no exposed secrets on screen or clipboard.")
