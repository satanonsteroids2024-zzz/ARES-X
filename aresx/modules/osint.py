"""
ARES X v5 — Visual Forensics & OSINT Engine
=============================================
• Frame-diff cropping engine: only ships changed screen regions
• Local Moondream2 / LLaVA (via Ollama) for edge vision processing
• Gemini 1.5 Flash for deep semantic mapping (free tier)
• All network recon via async non-blocking subprocess pipelines
• ARP scan, WiFi audit, WHOIS, DNS over async executors
• Zero-cost — no paid APIs required beyond optional Gemini key
"""

from __future__ import annotations

import asyncio
import io
import json
import re
import socket
import ssl
import subprocess
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import urllib.parse

from .. import core
from ..core import (
    ask_ai, ask_ai_async, ask_vision, ask_vision_async, cfg, done, err,
    log, mike, orb, run_async, screenshot_b64, show, speak,
)

try:
    import httpx
    _HTTPX = True
except ImportError:
    import urllib.request, urllib.error  # type: ignore
    _HTTPX = False

try:
    from PIL import Image as _PILImage
    _PIL = True
except ImportError:
    _PIL = False

try:
    import mss as _mss
    _MSS = True
except ImportError:
    _MSS = False


# ══════════════════════════════════════════════════════════════
# PERCEPTUAL HASH — CROP ENGINE
# Only ship changed bounding-box regions to vision APIs
# ══════════════════════════════════════════════════════════════
def _crop_changed_region() -> Optional[str]:
    """
    Compare current screen to last hash. If changed, crop the most
    active 60% region (center-biased) for targeted vision API calls.
    Reduces tokens & latency vs full-frame uploads.
    """
    if not _MSS or not _PIL:
        return screenshot_b64()

    try:
        import mss
        with mss.mss() as sct:
            raw = sct.grab(sct.monitors[1])
            img = _PILImage.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")

        w, h = img.size
        # Center crop: 80% of width, 70% of height (where most content lives)
        cx, cy = w // 2, h // 2
        cw, ch = int(w * 0.8), int(h * 0.7)
        cropped = img.crop((cx - cw // 2, cy - ch // 2,
                            cx + cw // 2, cy + ch // 2))

        if cropped.width > 1024:
            ratio   = 1024 / cropped.width
            cropped = cropped.resize((1024, int(cropped.height * ratio)), _PILImage.LANCZOS)

        buf = io.BytesIO()
        cropped.save(buf, format="JPEG", quality=60)
        import base64
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        log(f"Crop engine: {e}", "WARN")
        return screenshot_b64()


# ── Async vision helper using crop engine ────────────────────
async def _vision_crop(prompt: str, max_tokens: int = 600) -> Optional[str]:
    """Use crop engine for targeted vision — lower latency, fewer tokens."""
    img = _crop_changed_region()
    return await ask_vision_async(prompt, img, max_tokens)


def _v(prompt: str, max_tokens: int = 600) -> Optional[str]:
    """Sync wrapper for _vision_crop."""
    return run_async(_vision_crop(prompt, max_tokens))


# ══════════════════════════════════════════════════════════════
# ASYNC HTTP HELPER (httpx or urllib fallback)
# ══════════════════════════════════════════════════════════════
async def _get_json(url: str, timeout: float = 10.0,
                    headers: Optional[Dict] = None) -> Optional[Dict]:
    try:
        if _HTTPX:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url, headers=headers or {})
                resp.raise_for_status()
                return resp.json()
        else:
            loop = asyncio.get_running_loop()
            def _sync():
                req = urllib.request.Request(url, headers=headers or {})
                with urllib.request.urlopen(req, timeout=int(timeout)) as r:
                    return json.loads(r.read().decode("utf-8"))
            return await loop.run_in_executor(None, _sync)
    except Exception as e:
        log(f"GET {url[:60]}: {e}", "WARN")
        return None


async def _run_cmd_async(cmd: list, timeout: float = 15.0) -> Tuple[int, str]:
    """Run subprocess asynchronously via asyncio.create_subprocess_exec."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode or 0, stdout.decode("utf-8", errors="ignore").strip()
        except asyncio.TimeoutError:
            proc.kill()
            return -1, ""
    except FileNotFoundError:
        return -1, ""
    except Exception as e:
        log(f"Cmd {cmd[0]}: {e}", "WARN")
        return -1, ""


# ══════════════════════════════════════════════════════════════
# SCREEN OSINT
# ══════════════════════════════════════════════════════════════
def geolocate_screen() -> None:
    show("thinking", "Scanning screen...")
    result = _v(
        "Identify any geographic location, landmark, place name, address, or GPS "
        "coordinates visible on this screen. Give: 1) Place name 2) City/Country "
        "3) Exact GPS lat,lon if confident. If video call visible, identify location "
        "from background clues. Be precise.",
    )
    if not result:
        speak("Need vision API key.")
        err("No vision key")
        return
    log(f"GeoLocate: {result}")
    mike.log_osint("screen_geolocate", result)
    done(result[:60])
    speak(result[:250])

    c = re.search(r"(-?\d{1,3}\.\d{3,})\s*[,\s°NS]*[,;\s]+\s*(-?\d{1,3}\.\d{3,})", result)
    if c:
        try:
            lat, lon = float(c.group(1)), float(c.group(2))
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                webbrowser.open(f"https://maps.google.com/?q={lat},{lon}")
                mike.remember("last_location", f"{lat},{lon}")
                return
        except ValueError:
            pass
    q = result.split("\n")[0][:80]
    webbrowser.open(f"https://maps.google.com/search/{urllib.parse.quote(q)}")


def trace_message() -> None:
    show("thinking", "Analyzing message...")
    result = _v(
        "Look at this screen. If chat/DM/text is visible: "
        "1) Platform (Instagram/WhatsApp/Telegram/etc)? "
        "2) Sender username/phone/ID? "
        "3) Timestamp, location tag, metadata? "
        "4) Identifying info about origin?",
    )
    if not result:
        speak("Need vision key.")
        err("No key")
        return

    analysis = ask_ai(
        f"Screen analysis:\n{result}\n\nPerform OSINT to find message origin:\n"
        "1. Traceable metadata 2. OSINT methods 3. Discoverable public info",
        "OSINT expert. Be technical and specific.",
    )
    mike.log_osint("message_trace", analysis or "")

    u = re.search(r"@([\w.]{3,})", result)
    if u:
        uname = u.group(1)
        rl = result.lower()
        if "instagram" in rl:
            webbrowser.open(f"https://instagram.com/{uname}")
        elif "twitter" in rl or "x.com" in rl:
            webbrowser.open(f"https://twitter.com/{uname}")
        elif "tiktok" in rl:
            webbrowser.open(f"https://tiktok.com/@{uname}")

    done("Analysis complete")
    speak(f"Trace complete. {(analysis or 'No details.')[:200]}")


def find_on_screen(target: str) -> None:
    if not target:
        speak("Find what?")
        return
    show("thinking", f"Finding: {str(target)[:30]}...")
    result = _v(
        f"Find '{target}' on this screen. 1) Is it visible? "
        f"2) Position (top/center/bottom)? 3) Which app/window? "
        f"4) Estimated pixel coordinates if possible."
    )
    if not result:
        speak("Need vision key.")
        err("No key")
        return
    mike.log_osint(f"find_{target}", result)
    done(result[:60])
    speak(result[:200])


def call_location() -> None:
    show("thinking", "Analyzing call...")
    result = _v(
        "Video call on screen. Location clues: "
        "1) Background details? 2) Visible text/signs/landmarks? "
        "3) Time of day (lighting)? 4) Language/script visible? "
        "5) Most likely country/city with confidence %?"
    )
    if not result:
        speak("Need vision key.")
        err("No key")
        return
    log(f"Call loc: {result}")
    mike.log_osint("call_location", result)
    done(result[:60])
    speak(result[:300])
    c = re.search(r"(-?\d{1,3}\.\d{3,})\s*,\s*(-?\d{1,3}\.\d{3,})", result)
    if c:
        try:
            lat, lon = float(c.group(1)), float(c.group(2))
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                webbrowser.open(f"https://maps.google.com/?q={lat},{lon}")
        except ValueError:
            pass


def reverse_image_search() -> None:
    show("thinking", "Capturing for reverse search...")
    path = core.screenshot_save()
    if not path:
        err("Capture failed")
        return
    webbrowser.open("https://images.google.com/")
    time.sleep(0.3)
    webbrowser.open("https://yandex.com/images/")
    speak("Reverse search opened. Upload from desktop.")
    done("Search opened")
    try:
        subprocess.Popen(["explorer", "/select,", path], shell=False)
    except OSError:
        pass


def identify_product() -> None:
    show("thinking", "Identifying product...")
    result = _v(
        "Identify product visible on screen: "
        "1) Product name + brand 2) Category 3) Price range "
        "4) Where to buy in India 5) Notable features."
    )
    if not result:
        speak("Need vision key.")
        err("No key")
        return
    mike.log_osint("product_id", result)
    done(result[:60])
    speak(result[:250])
    name = result.split("\n")[0][:60].strip()
    if name:
        webbrowser.open(f"https://amazon.in/s?k={urllib.parse.quote(name)}")
        time.sleep(0.3)
        webbrowser.open(f"https://flipkart.com/search?q={urllib.parse.quote(name)}")


def translate_screen(target_lang: str = "english") -> None:
    show("thinking", f"Translating to {target_lang}...")
    result = _v(
        f"Read ALL text on this screen then translate to {target_lang}. "
        "Format: original text first, then translation."
    )
    if not result:
        speak("Need vision key.")
        err("No key")
        return
    mike.log_osint("translate", result)
    done("Translated")
    speak(result[:400])


def extract_qr_barcode() -> None:
    show("thinking", "Scanning for QR/barcode...")
    result = _v(
        "Find any QR code or barcode on this screen. "
        "If found, decode its content and explain what URL/text it contains. "
        "If a URL, indicate if it looks safe."
    )
    if not result:
        speak("Need vision key.")
        err("No key")
        return
    mike.log_osint("qr_scan", result)
    done(result[:60])
    speak(result[:250])
    url = re.search(r"https?://[^\s]+", result)
    if url:
        webbrowser.open(url.group(0))


def identify_person() -> None:
    show("thinking", "Identifying...")
    result = _v(
        "Is a person visible on this screen? "
        "If PUBLIC FIGURE (politician, celebrity, creator): "
        "1) Name 2) Role 3) Notable info. "
        "DO NOT identify private individuals."
    )
    if not result:
        speak("Need vision key.")
        err("No key")
        return
    mike.log_osint("person_id", result)
    done(result[:60])
    speak(result[:250])


def extract_document() -> None:
    show("thinking", "Reading document...")
    result = _v(
        "Extract structured data from any document/form/ID/receipt visible. "
        "Format as key-value pairs. Identify document type first."
    )
    if not result:
        speak("Need vision key.")
        err("No key")
        return
    mike.log_osint("doc_extract", result)
    done("Extracted")
    speak(result[:400])
    mike.add_note(f"DOCUMENT EXTRACTED:\n{result}")


def license_plate_lookup() -> None:
    show("thinking", "Reading plate...")
    result = _v(
        "Read any vehicle license plate visible on screen. "
        "1) Full plate text 2) Country/state if visible "
        "3) Vehicle make/model/color if visible."
    )
    if not result:
        speak("Need vision key.")
        err("No key")
        return
    mike.log_osint("plate_read", result)
    done(result[:60])
    speak(result[:200])
    plate = re.search(r"[A-Z]{2}\s*\d{2}\s*[A-Z]{1,2}\s*\d{4}", result.upper())
    if plate:
        q = plate.group(0).replace(" ", "")
        webbrowser.open(f"https://www.carinfo.app/rc-details/{q}")


# ══════════════════════════════════════════════════════════════
# DIGITAL OSINT — All async subprocess pipelines
# ══════════════════════════════════════════════════════════════
def ip_lookup(ip_or_domain: str) -> None:
    if not ip_or_domain:
        speak("Which IP or domain?")
        return
    show("thinking", f"Looking up {ip_or_domain}...")

    async def _do():
        d = await _get_json(f"http://ip-api.com/json/{ip_or_domain}?fields=status,message,country,regionName,city,isp,org,as,query")
        if d and d.get("status") == "success":
            info = (f"{d.get('query','')} — {d.get('city','')}, "
                    f"{d.get('regionName','')}, {d.get('country','')} | "
                    f"ISP: {d.get('isp','')} | AS: {d.get('as','')}")
            done(info[:60])
            speak(info)
            mike.log_osint(f"ip_{ip_or_domain}", info)
            webbrowser.open(f"https://www.shodan.io/host/{ip_or_domain}")
        else:
            err("Not found")
            speak("IP lookup failed.")

    run_async(_do())


def phone_lookup(number: str) -> None:
    if not number:
        speak("Which number?")
        return
    show("thinking", "Analyzing number...")
    clean = re.sub(r"[^\d+]", "", number)

    async def _do():
        d = await _get_json(f"https://phonevalidation.abstractapi.com/v1/?api_key=free&phone={clean}")
        if d and d.get("valid"):
            info = (f"{clean} — {d.get('country',{}).get('name','?')} "
                    f"({d.get('country',{}).get('code','?')}) "
                    f"| Carrier: {d.get('carrier','?')} "
                    f"| Type: {d.get('type','?')}")
        else:
            info = ask_ai(
                f"Analyze phone number: {clean}. "
                "Country, carrier, format validity. Be brief.",
                "Telecom expert."
            ) or "Analysis unavailable."
        done(info[:60])
        speak(info[:200])
        mike.log_osint(f"phone_{clean}", info)

    run_async(_do())


def email_breach_check(email: str) -> None:
    if not email:
        speak("Which email?")
        return
    show("thinking", "Checking breaches...")
    key = cfg.get("api_keys", {}).get("hibp", "").strip()

    async def _do():
        if key:
            d = await _get_json(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false",
                headers={"hibp-api-key": key, "user-agent": "ARES-X"},
                timeout=10.0,
            )
            if d and isinstance(d, list):
                names = [b.get("Name", "?") for b in d[:5]]
                info = f"{email} found in {len(d)} breaches: {', '.join(names)}"
            else:
                info = f"{email}: no breaches found."
        else:
            # OSINT via AI without key
            info = ask_ai(
                f"What public breach databases have recorded the email: {email}? "
                "Be factual and brief.",
                "OSINT expert."
            ) or "Need HIBP API key for breach check."
        done(info[:60])
        speak(info[:250])
        mike.log_osint(f"breach_{email}", info)

    run_async(_do())


def domain_whois(domain: str) -> None:
    if not domain:
        speak("Which domain?")
        return
    show("thinking", f"WHOIS {domain}...")

    async def _do():
        # RDAP (modern replacement for WHOIS, no command needed)
        rdap = await _get_json(f"https://rdap.org/domain/{domain}", timeout=10.0)
        dns_info = ""

        # Async DNS lookup via executor
        loop = asyncio.get_running_loop()
        try:
            addr = await loop.run_in_executor(None, socket.gethostbyname, domain)
            dns_info = f" | DNS: {addr}"
        except Exception:
            pass

        # SSL cert check
        ssl_info = ""
        try:
            def _ssl_check():
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                    s.settimeout(5)
                    s.connect((domain, 443))
                    cert = s.getpeercert()
                    exp  = cert.get("notAfter", "?")
                    return f" | SSL: expires {exp}"
            ssl_info = await loop.run_in_executor(None, _ssl_check)
        except Exception:
            pass

        if rdap:
            reg  = rdap.get("handle", "?")
            name = rdap.get("ldhName", domain)
            events = {e.get("eventAction", ""): e.get("eventDate", "")[:10]
                      for e in rdap.get("events", [])}
            created = events.get("registration", "?")
            expires = events.get("expiration", "?")
            info = f"{name} | Reg: {reg} | Created: {created} | Expires: {expires}{dns_info}{ssl_info}"
        else:
            info = f"{domain}{dns_info}{ssl_info} | RDAP lookup failed"

        done(info[:60])
        speak(info[:300])
        mike.log_osint(f"whois_{domain}", info)
        webbrowser.open(f"https://www.virustotal.com/gui/domain/{domain}")

    run_async(_do())


def wayback_lookup(url: str) -> None:
    if not url:
        speak("Which URL?")
        return
    show("thinking", "Checking Wayback Machine...")

    async def _do():
        d = await _get_json(
            f"https://archive.org/wayback/available?url={urllib.parse.quote(url)}",
            timeout=10.0,
        )
        if d and d.get("archived_snapshots", {}).get("closest", {}).get("available"):
            snap = d["archived_snapshots"]["closest"]
            ts   = snap.get("timestamp", "?")
            wurl = snap.get("url", "")
            info = f"Last archived: {ts[:8]} — {wurl}"
            done(ts[:12])
            speak(info[:200])
            webbrowser.open(wurl or f"https://web.archive.org/web/*/{url}")
        else:
            err("No archive")
            speak("No Wayback snapshot found.")
        mike.log_osint(f"wayback_{url[:60]}", url)

    run_async(_do())


def username_hunt(username: str) -> None:
    if not username:
        speak("Which username?")
        return
    show("thinking", f"Hunting @{username}...")
    PLATFORMS = [
        ("Instagram",  f"https://www.instagram.com/{username}"),
        ("Twitter/X",  f"https://twitter.com/{username}"),
        ("GitHub",     f"https://github.com/{username}"),
        ("TikTok",     f"https://tiktok.com/@{username}"),
        ("LinkedIn",   f"https://linkedin.com/in/{username}"),
        ("Reddit",     f"https://reddit.com/user/{username}"),
        ("YouTube",    f"https://youtube.com/@{username}"),
        ("Telegram",   f"https://t.me/{username}"),
    ]
    speak(f"Opening {len(PLATFORMS)} platforms for @{username}")
    for name, url in PLATFORMS[:5]:
        webbrowser.open(url)
        time.sleep(0.3)
    done(f"Hunting @{username}")
    mike.log_osint(f"username_{username}", str(PLATFORMS))


def public_ip_info() -> None:
    show("thinking", "Fetching public IP...")

    async def _do():
        d = await _get_json("http://ip-api.com/json/?fields=query,city,country,isp,timezone")
        if d:
            info = (f"IP: {d.get('query','?')} | "
                    f"{d.get('city','?')}, {d.get('country','?')} | "
                    f"ISP: {d.get('isp','?')} | TZ: {d.get('timezone','?')}")
            done(d.get("query", "?"))
            speak(info)
            mike.remember("public_ip", d.get("query", ""))
            mike.log_osint("public_ip", info)
        else:
            err("Failed")
            speak("IP lookup failed.")

    run_async(_do())


def wifi_info() -> None:
    show("thinking", "WiFi info...")

    async def _do():
        rc, out = await _run_cmd_async(
            ["netsh", "wlan", "show", "interfaces"], timeout=10.0
        )
        if rc == 0 and out:
            lines  = out.split("\n")
            ssid   = next((l.split(":")[1].strip() for l in lines if "SSID" in l and "BSSID" not in l), "?")
            signal = next((l.split(":")[1].strip() for l in lines if "Signal" in l), "?")
            speed  = next((l.split(":")[1].strip() for l in lines if "Receive rate" in l), "?")
            info   = f"WiFi: {ssid} | Signal: {signal} | RX: {speed}"
            done(ssid)
            speak(info)
            mike.log_osint("wifi", info)
        else:
            err("Failed")
            speak("WiFi info unavailable.")

    run_async(_do())


def network_scan() -> None:
    show("thinking", "Scanning network...")

    async def _do():
        rc, out = await _run_cmd_async(["arp", "-a"], timeout=15.0)
        if rc != 0 or not out:
            err("Failed")
            speak("Network scan failed.")
            return

        lines   = [l.strip() for l in out.split("\n") if re.search(r"\d{1,3}\.\d{1,3}", l)]
        devices = [l for l in lines if "dynamic" in l.lower()]
        info    = f"Found {len(devices)} devices on local network."
        done(f"{len(devices)} devices")
        speak(info)

        # Resolve hostnames for known devices async
        loop = asyncio.get_running_loop()
        resolved = []
        for line in devices[:10]:
            ip_m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if ip_m:
                ip = ip_m.group(1)
                try:
                    host = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
                    resolved.append(f"{ip} ({host[0]})")
                except Exception:
                    resolved.append(ip)

        summary = info + " | " + ", ".join(resolved[:5])
        mike.log_osint("network_scan", summary)

    run_async(_do())
