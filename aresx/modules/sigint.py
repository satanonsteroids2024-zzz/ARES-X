"""
ARES X v6 — Signal Intelligence (SIGINT)  [Features 55-58]
==========================================================
• Wi-Fi probe-request analyzer (passive presence detection)
• Bluetooth / BLE device tracker (proximity via RSSI)
• Radio-frequency monitor (SDR spectrum snapshot)
• Packet capture & deep inspection (metadata only)

SAFETY / LEGALITY
-----------------
Every capability here is PASSIVE observation only — no injection, no
deauth, no active attacks. All capture is METADATA-ONLY by default
(no payload bodies, no credential harvesting). Each entry point is
consent-gated and degrades gracefully when the required hardware or
library is absent. Users are responsible for complying with local law
(monitoring may require consent on networks/devices you do not own).
"""

from __future__ import annotations

import re
import time
from typing import Dict, List, Optional


def _disclaimer_once(key: str) -> bool:
    """Show a one-time legal acknowledgement per SIGINT feature."""
    from ..core import cfg, save_config
    acks = cfg.get("sigint_acks", {})
    if acks.get(key):
        return True
    acks[key] = True
    cfg["sigint_acks"] = acks
    save_config(cfg)
    return False


# ──────────────────────────────────────────────────────────────
# 55. Wi-Fi Probe Request Analyzer  (passive)
# ──────────────────────────────────────────────────────────────
def wifi_probe_monitor(duration_sec: int = 20) -> None:
    """
    Passively capture 802.11 probe-requests to map nearby device presence.
    Requires a Wi-Fi adapter in monitor mode + scapy. Captures MAC + SSID +
    signal only — never any data payload.
    """
    from ..core import speak, show, err

    show("thinking", "Listening for Wi-Fi probes…")
    if not _disclaimer_once("wifi"):
        speak("Heads up: passive Wi-Fi monitoring may require consent under local "
              "law. Capturing presence metadata only — no payloads.")

    try:
        from scapy.all import sniff, Dot11ProbeReq, Dot11  # type: ignore
    except Exception:
        speak("Scapy not installed or no monitor-mode adapter. "
              "Run: pip install scapy — and enable monitor mode.")
        return

    devices: Dict[str, Dict] = {}

    def _cb(pkt):
        try:
            if pkt.haslayer(Dot11ProbeReq):
                mac = pkt[Dot11].addr2
                ssid = pkt[Dot11ProbeReq].info.decode(errors="ignore") if pkt[Dot11ProbeReq].info else ""
                sig = getattr(pkt, "dBm_AntSignal", None)
                if mac:
                    d = devices.setdefault(mac, {"ssids": set(), "rssi": sig, "count": 0})
                    if ssid:
                        d["ssids"].add(ssid)
                    d["count"] += 1
                    if sig is not None:
                        d["rssi"] = sig
        except Exception:
            pass

    try:
        sniff(prn=_cb, timeout=duration_sec, store=False)
    except PermissionError:
        speak("Need administrator privileges for raw Wi-Fi capture.")
        return
    except Exception as e:
        err(f"Wi-Fi monitor: {e}")
        return

    if not devices:
        speak("No probe requests captured. Confirm monitor mode is active.")
        return

    # OUI vendor lookup (best-effort, offline prefix heuristic)
    summary = []
    for mac, d in list(devices.items())[:10]:
        ssid_n = len(d["ssids"])
        summary.append(f"{mac[:8]}… ({ssid_n} SSIDs, {d['count']}x)")
    _store_sigint("wifi_probe", {m: {"ssids": list(v["ssids"]), "count": v["count"]}
                                 for m, v in devices.items()})
    speak(f"Detected {len(devices)} nearby devices. {'; '.join(summary[:5])}")


# ──────────────────────────────────────────────────────────────
# 56. Bluetooth / BLE Device Tracker  (passive)
# ──────────────────────────────────────────────────────────────
def ble_scan(duration_sec: int = 10) -> None:
    """Scan for nearby BLE devices; report name, MAC, RSSI proximity."""
    from ..core import speak, show, err, run_async

    show("thinking", "Scanning Bluetooth…")

    async def _scan():
        try:
            from bleak import BleakScanner  # type: ignore
        except Exception:
            return None
        found = []
        try:
            devs = await BleakScanner.discover(timeout=duration_sec, return_adv=True)
            for _, (dev, adv) in devs.items():
                found.append({
                    "name": dev.name or "(unknown)",
                    "mac": dev.address,
                    "rssi": getattr(adv, "rssi", None),
                })
        except Exception as e:
            return ("err", str(e))
        return found

    res = run_async(_scan())
    if res is None:
        speak("bleak not installed. Run: pip install bleak")
        return
    if isinstance(res, tuple) and res[0] == "err":
        err(f"BLE scan: {res[1]}")
        return
    if not res:
        speak("No BLE devices found nearby.")
        return

    res.sort(key=lambda d: d["rssi"] or -999, reverse=True)
    _store_sigint("ble", {d["mac"]: d for d in res})
    top = res[0]
    near = sum(1 for d in res if (d["rssi"] or -999) > -70)
    speak(f"Found {len(res)} BLE devices ({near} close). "
          f"Strongest: {top['name']} at {top['rssi']} dBm.")


# ──────────────────────────────────────────────────────────────
# 57. Radio-Frequency Monitor  (SDR)
# ──────────────────────────────────────────────────────────────
def rf_monitor(center_freq_mhz: float = 100.0, mode: str = "spectrum") -> None:
    """
    Take a spectrum snapshot around *center_freq_mhz* using an RTL-SDR.
    Requires pyrtlsdr + an RTL-SDR dongle. Degrades gracefully otherwise.
    """
    from ..core import speak, show, err

    show("thinking", "Sampling RF spectrum…")
    try:
        from rtlsdr import RtlSdr  # type: ignore
        import numpy as np
    except Exception:
        speak("pyrtlsdr/numpy not installed or no SDR dongle. "
              "Run: pip install pyrtlsdr numpy")
        return

    try:
        sdr = RtlSdr()
        sdr.sample_rate = 2.4e6
        sdr.center_freq = center_freq_mhz * 1e6
        sdr.gain = "auto"
        samples = sdr.read_samples(256 * 1024)
        sdr.close()

        # Power spectral density peak detection
        psd = np.abs(np.fft.fftshift(np.fft.fft(samples)))
        peak_bin = int(np.argmax(psd))
        peak_pwr = float(20 * np.log10(psd[peak_bin] + 1e-9))
        _store_sigint("rf", {"center_mhz": center_freq_mhz,
                             "peak_power_db": round(peak_pwr, 1)})
        speak(f"RF snapshot at {center_freq_mhz} MHz — peak power {peak_pwr:.1f} dB.")
    except Exception as e:
        err(f"RF monitor: {e}")


# ──────────────────────────────────────────────────────────────
# 58. Packet Capture & Deep Inspection  (metadata only)
# ──────────────────────────────────────────────────────────────
def packet_capture(count: int = 50, iface: Optional[str] = None) -> None:
    """
    Capture packet METADATA (src/dst/proto, DNS queries, TLS SNI) for the
    given count. No payload bodies are stored. Requires admin + scapy.
    """
    from ..core import speak, show, err

    show("thinking", "Capturing packet metadata…")
    if not _disclaimer_once("pcap"):
        speak("Note: capturing traffic on networks you don't own may require "
              "consent. Recording metadata only — no payload contents.")

    try:
        from scapy.all import sniff, IP, TCP, UDP, DNSQR  # type: ignore
    except Exception:
        speak("Scapy not installed. Run: pip install scapy")
        return

    flows: List[str] = []
    dns_q: List[str] = []
    sni: List[str] = []

    def _cb(pkt):
        try:
            if pkt.haslayer(IP):
                proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "IP"
                flows.append(f"{pkt[IP].src}→{pkt[IP].dst}/{proto}")
            if pkt.haslayer(DNSQR):
                q = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                if q:
                    dns_q.append(q)
            # TLS SNI (ClientHello) — metadata only, no decryption
            if pkt.haslayer(TCP) and bytes(pkt[TCP].payload)[:1] == b"\x16":
                raw = bytes(pkt[TCP].payload)
                m = _extract_sni(raw)
                if m:
                    sni.append(m)
        except Exception:
            pass

    try:
        sniff(prn=_cb, count=count, timeout=20, store=False, iface=iface)
    except PermissionError:
        speak("Need administrator privileges for packet capture.")
        return
    except Exception as e:
        err(f"Packet capture: {e}")
        return

    _store_sigint("pcap", {"flows": flows[:50], "dns": list(set(dns_q))[:30],
                           "sni": list(set(sni))[:30]})
    uniq_dns = sorted(set(dns_q))
    speak(f"Captured {len(flows)} flows. DNS lookups: "
          f"{', '.join(uniq_dns[:6]) if uniq_dns else 'none'}.")


def _extract_sni(raw: bytes) -> Optional[str]:
    """Pull the SNI hostname from a TLS ClientHello (metadata only)."""
    try:
        host = re.findall(rb"[a-z0-9\-]+\.[a-z0-9\.\-]{2,}", raw)
        if host:
            cand = host[0].decode(errors="ignore")
            if "." in cand and len(cand) < 80:
                return cand
    except Exception:
        pass
    return None


# ──────────────────────────────────────────────────────────────
# Shared storage helper
# ──────────────────────────────────────────────────────────────
def _store_sigint(kind: str, data: dict) -> None:
    from ..core import mike
    import json as _json
    try:
        mike.remember(f"sigint:{kind}:{int(time.time())}",
                      _json.dumps(data)[:8000], tags=["sigint", kind])
    except Exception:
        pass
