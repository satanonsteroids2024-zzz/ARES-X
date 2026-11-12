"""
ARES X v6 — Behavioral Intelligence (BEHINT)  [Features 59-62]
==============================================================
• Keystroke dynamics profiling   (TIMING-ONLY — never logs key values)
• Mouse movement biometrics
• Application-usage heatmaps
• Workflow anomaly detection

PRIVACY / SAFETY
----------------
These features fingerprint the OWNER's behaviour on their OWN machine
(e.g. "is a different person typing right now?"). The keystroke module
records ONLY inter-keystroke timing intervals — it never captures or
stores which keys are pressed, so it is NOT a keylogger and cannot
recover typed text, passwords, or messages. All biometric data is stored
locally as aggregate statistics and is never transmitted.
"""

from __future__ import annotations

import statistics
import time
from collections import Counter
from typing import List


# ──────────────────────────────────────────────────────────────
# 59. Keystroke Dynamics Profiling   (TIMING INTERVALS ONLY)
# ──────────────────────────────────────────────────────────────
def keystroke_dynamics(action: str = "profile", duration_sec: int = 45) -> None:
    """
    Build/verify a typing-rhythm fingerprint from inter-key TIMING only.
    action: profile (learn baseline) | verify (compare to baseline)

    IMPORTANT: only the time gaps between keystrokes are recorded. Key
    identities/characters are discarded immediately and never stored.
    """
    from ..core import speak, show, mike, err
    import json

    show("thinking", "Sampling typing rhythm (timing only)…")
    try:
        import keyboard  # type: ignore
    except Exception:
        speak("keyboard library not installed. Run: pip install keyboard")
        return

    intervals: List[float] = []
    last = {"t": None}

    def _on_key(_event):
        # We deliberately ignore _event.name — only timing is used.
        now = time.time()
        if last["t"] is not None:
            gap = now - last["t"]
            if 0 < gap < 2.0:      # ignore long pauses
                intervals.append(gap)
        last["t"] = now

    try:
        keyboard.on_press(_on_key)
        speak(f"Type naturally for {duration_sec} seconds…")
        time.sleep(duration_sec)
        keyboard.unhook_all()
    except Exception as e:
        err(f"Keystroke timing: {e}")
        try:
            keyboard.unhook_all()
        except Exception:
            pass
        return

    if len(intervals) < 15:
        speak("Not enough typing captured to build a rhythm profile.")
        return

    profile = {
        "mean": round(statistics.mean(intervals), 4),
        "stdev": round(statistics.pstdev(intervals), 4),
        "median": round(statistics.median(intervals), 4),
        "samples": len(intervals),
    }

    if action.lower() == "verify":
        saved = mike.recall("behint:keystroke_profile")
        if not saved:
            speak("No saved typing profile yet. Run profiling first.")
            return
        base = json.loads(saved)
        # z-distance on mean cadence
        if base["stdev"] > 0:
            z = abs(profile["mean"] - base["mean"]) / base["stdev"]
        else:
            z = 0
        if z > 3:
            speak(f"⚠ Typing rhythm differs sharply from baseline (z={z:.1f}). "
                  "A different person may be using this machine.")
        else:
            speak(f"Typing rhythm matches your baseline (z={z:.1f}). Identity consistent.")
        return

    mike.remember("behint:keystroke_profile", json.dumps(profile),
                  tags=["behint", "keystroke", "biometric"])
    speak(f"Typing-rhythm baseline saved (mean gap {profile['mean']*1000:.0f}ms, "
          f"{profile['samples']} samples). Key contents were never recorded.")


# ──────────────────────────────────────────────────────────────
# 60. Mouse Movement Biometrics
# ──────────────────────────────────────────────────────────────
def mouse_biometrics(action: str = "profile", duration_sec: int = 30) -> None:
    """Fingerprint cursor movement (velocity/jitter). Detects RAT-like motion."""
    from ..core import speak, show, mike, err
    import json

    show("thinking", "Sampling cursor movement…")
    try:
        import pyautogui
    except Exception:
        speak("pyautogui not installed. Run: pip install pyautogui")
        return

    speeds: List[float] = []
    prev = pyautogui.position()
    prev_t = time.time()
    end = time.time() + duration_sec
    try:
        while time.time() < end:
            time.sleep(0.05)
            cur = pyautogui.position()
            now = time.time()
            dist = ((cur[0] - prev[0]) ** 2 + (cur[1] - prev[1]) ** 2) ** 0.5
            dt = now - prev_t
            if dt > 0 and dist > 0:
                speeds.append(dist / dt)
            prev, prev_t = cur, now
    except Exception as e:
        err(f"Mouse biometrics: {e}")
        return

    if len(speeds) < 10:
        speak("Not enough cursor movement captured.")
        return

    profile = {
        "mean_speed": round(statistics.mean(speeds), 1),
        "max_speed": round(max(speeds), 1),
        "stdev": round(statistics.pstdev(speeds), 1),
        "samples": len(speeds),
    }

    # RAT heuristic: teleport-like jumps with near-zero intermediate motion
    teleports = sum(1 for s in speeds if s > 8000)
    if action.lower() == "verify":
        saved = mike.recall("behint:mouse_profile")
        if saved:
            base = json.loads(saved)
            drift = abs(profile["mean_speed"] - base["mean_speed"])
            msg = "consistent" if drift < base["mean_speed"] * 0.6 else "different from baseline"
            extra = " ⚠ teleport-like motion (possible remote control)" if teleports > 3 else ""
            speak(f"Cursor behaviour {msg}.{extra}")
            return

    mike.remember("behint:mouse_profile", json.dumps(profile),
                  tags=["behint", "mouse", "biometric"])
    note = " ⚠ teleport-like motion detected" if teleports > 3 else ""
    speak(f"Cursor biometric baseline saved (avg {profile['mean_speed']:.0f} px/s).{note}")


# ──────────────────────────────────────────────────────────────
# 61. Application Usage Heatmap
# ──────────────────────────────────────────────────────────────
def app_usage_heatmap(sample_sec: int = 60) -> None:
    """Track active-window usage over a sampling window; report the heatmap."""
    from ..core import speak, show, mike, err
    import json

    show("thinking", "Building app-usage heatmap…")
    try:
        import pygetwindow as gw
    except Exception:
        speak("pygetwindow not installed. Run: pip install pygetwindow")
        return

    usage: Counter = Counter()
    end = time.time() + sample_sec
    try:
        while time.time() < end:
            try:
                w = gw.getActiveWindow()
                title = (w.title if w else "") or "idle"
                app = title.split(" - ")[-1][:40] if title else "idle"
                usage[app] += 1
            except Exception:
                usage["idle"] += 1
            time.sleep(1.0)
    except Exception as e:
        err(f"App heatmap: {e}")
        return

    if not usage:
        speak("No active windows captured.")
        return

    total = sum(usage.values())
    top = usage.most_common(5)
    mike.remember(f"behint:appusage:{int(time.time())}",
                  json.dumps(dict(usage)), tags=["behint", "appusage"])
    parts = [f"{a} {100*c/total:.0f}%" for a, c in top]
    speak("App usage: " + ", ".join(parts))


# ──────────────────────────────────────────────────────────────
# 62. Workflow Anomaly Detection
# ──────────────────────────────────────────────────────────────
def workflow_anomaly_check() -> None:
    """Compare current activity against learned behavioural baseline."""
    from ..core import speak, show, mike
    import json
    import datetime

    show("thinking", "Checking workflow anomalies…")
    hour = datetime.datetime.now().hour

    # Load historical app-usage snapshots from Mike
    baseline_hours = mike.recall("behint:active_hours")
    hours = json.loads(baseline_hours) if baseline_hours else {}

    hkey = str(hour)
    hours[hkey] = hours.get(hkey, 0) + 1
    mike.remember("behint:active_hours", json.dumps(hours), tags=["behint", "baseline"])

    total = sum(hours.values())
    if total < 24:
        speak("Still learning your normal activity pattern — keep using ARES.")
        return

    # Anomaly: active in an hour that's historically <2% of activity
    share = hours.get(hkey, 0) / total
    if share < 0.02:
        speak(f"⚠ Unusual: you're active at {hour:02d}:00, which is rare for you. "
              "If this isn't you, run a security sweep.")
    else:
        speak(f"Activity at {hour:02d}:00 is within your normal pattern.")
