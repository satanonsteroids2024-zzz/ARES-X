"""
ARES X v6 — Disinformation & Influence Operations (INFOOPS)  [79-82]
====================================================================
• Bot-network detector (coordinated-behaviour heuristics)
• Narrative tracking engine (cross-platform propagation)
• Source credibility scorer
• Deepfake audio detection

These are DEFENSIVE analytics — they help the user spot manipulation,
not conduct it.
"""

from __future__ import annotations

import json
import time
from typing import List


# ──────────────────────────────────────────────────────────────
# 79. Bot Network Detector
# ──────────────────────────────────────────────────────────────
def bot_network_detect(handle_or_topic: str) -> None:
    """Heuristically assess coordinated-inauthentic-behaviour signals."""
    from ..core import speak, show, ask_ai, mike, run_async
    from ..brain import ddg_search_async

    show("thinking", "Analyzing for bot activity…")
    res = run_async(ddg_search_async(
        f"{handle_or_topic} bot OR coordinated OR fake accounts OR astroturf",
        max_results=6)) or []
    context = "\n".join(f"• {r.get('title','')} {r.get('body','')[:140]}"
                        for r in res)[:2200]
    assessment = ask_ai(
        f"Assess the likelihood that '{handle_or_topic}' is associated with "
        "coordinated inauthentic behaviour (bot network / astroturfing). "
        "Consider: posting cadence, account-age clustering, content similarity, "
        "amplification patterns. Give a 0-100 likelihood + 2 key indicators.\n\n"
        f"Signals:\n{context}",
        system="You are ARES X INFOOPS analyst. Be specific, brief.")
    mike.remember(f"botnet:{handle_or_topic}", assessment or "",
                  tags=["infoops", "botnet"])
    speak(assessment or "Insufficient signal to assess bot activity.")


# ──────────────────────────────────────────────────────────────
# 80. Narrative Tracking Engine
# ──────────────────────────────────────────────────────────────
def narrative_track(claim: str) -> None:
    """Trace how a claim/narrative propagates across platforms + time."""
    from ..core import speak, show, ask_ai, mike, run_async
    from ..brain import ddg_search_async

    show("thinking", "Tracing narrative spread…")
    platforms = ["reddit.com", "twitter.com", "news", "youtube.com"]
    hits: List[str] = []
    for plat in platforms:
        q = f'"{claim}" site:{plat}' if "." in plat else f'"{claim}" {plat}'
        res = run_async(ddg_search_async(q, max_results=2)) or []
        for r in res:
            if r.get("title"):
                hits.append(f"[{plat}] {r['title'][:80]}")

    context = "\n".join(hits)[:2000]
    analysis = ask_ai(
        f"Narrative: '{claim}'.\n"
        f"Appearances across platforms:\n{context}\n\n"
        "Summarize the propagation: likely origin, main amplifiers, and whether "
        "it shows organic vs coordinated spread. 3 lines max.",
        system="You are ARES X narrative analyst.")
    mike.remember(f"narrative:{claim[:40]}",
                  json.dumps({"hits": hits, "analysis": analysis}),
                  tags=["infoops", "narrative"])
    speak(analysis or f"Found {len(hits)} appearances of that narrative.")


# ──────────────────────────────────────────────────────────────
# 81. Source Credibility Scorer
# ──────────────────────────────────────────────────────────────
def source_credibility(domain_or_url: str) -> None:
    """Score a source's credibility from domain age + reputation + AI review."""
    from ..core import speak, show, ask_ai, mike, run_async
    from ..brain import ddg_search_async

    show("thinking", "Scoring source credibility…")
    domain = (domain_or_url.replace("https://", "").replace("http://", "")
              .split("/")[0])

    # Domain age via whois (best-effort)
    age_note = ""
    try:
        import whois  # python-whois
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if cd:
            yrs = (time.time() - cd.timestamp()) / 31557600
            age_note = f"Domain age ~{yrs:.1f} years."
    except Exception:
        pass

    # Reputation chatter
    rep = run_async(ddg_search_async(
        f"{domain} reliable OR fake news OR fact check OR bias", max_results=5)) or []
    context = "\n".join(r.get("body", "")[:150] for r in rep)[:1800]

    verdict = ask_ai(
        f"Rate the credibility of source '{domain}' from 0-100. {age_note}\n"
        f"Reputation signals:\n{context}\n\n"
        "Give: score/100, a one-word label (Reliable/Mixed/Questionable/Unreliable), "
        "and the main reason.",
        system="You are ARES X source-credibility engine. One concise answer.")
    mike.remember(f"credibility:{domain}", verdict or "",
                  tags=["infoops", "credibility", domain])
    speak(verdict or f"Could not score credibility for {domain}.")


# ──────────────────────────────────────────────────────────────
# 82. Deepfake Audio Detection
# ──────────────────────────────────────────────────────────────
def deepfake_audio_detect(filepath: str) -> None:
    """Analyze an audio file for synthetic-speech / manipulation indicators."""
    from ..core import speak, show, err
    from pathlib import Path

    show("thinking", "Analyzing audio authenticity…")
    p = Path(filepath).expanduser()
    if not p.exists():
        speak(f"Audio file not found: {filepath}")
        return

    try:
        import librosa
        import numpy as np
        y, sr = librosa.load(str(p), sr=16000, mono=True, duration=30)
    except Exception:
        speak("librosa not installed. Run: pip install librosa")
        return

    try:
        # Heuristic indicators of synthetic speech:
        # 1. Spectral flatness (synthetic audio often unusually uniform)
        flatness = float(np.mean(librosa.feature.spectral_flatness(y=y)))
        # 2. Pitch stability (TTS often has unnaturally stable F0)
        f0 = librosa.yin(y, fmin=70, fmax=400, sr=sr)
        f0_cv = float(np.std(f0) / (np.mean(f0) + 1e-6))
        # 3. Silence ratio anomaly
        rms = librosa.feature.rms(y=y)[0]
        silence_ratio = float(np.mean(rms < 0.01))

        suspicion = 0
        notes = []
        if flatness > 0.35:
            suspicion += 35
            notes.append("high spectral flatness")
        if f0_cv < 0.08:
            suspicion += 35
            notes.append("unnaturally stable pitch")
        if silence_ratio < 0.02:
            suspicion += 15
            notes.append("no natural pauses")

        label = ("likely synthetic" if suspicion >= 50
                 else "possibly synthetic" if suspicion >= 30
                 else "likely authentic")
        note_txt = (", ".join(notes)) if notes else "natural speech characteristics"
        speak(f"Audio assessment: {label} (suspicion {suspicion}/100). "
              f"Indicators: {note_txt}.")
    except Exception as e:
        err(f"Deepfake audio: {e}")
