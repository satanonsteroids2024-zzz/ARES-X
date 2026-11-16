"""
ARES X v10 — TTS speak / STT listen (split from core.py)
========================================================
Split out of the v9 core.py god-file into a focused module.

All original public symbols are re-exported by aresx.core (the
compat facade) so existing importers keep working unmodified.
"""
from __future__ import annotations

from aresx.core.paths import cfg, log, BASE_DIR, is_quiet_hours

import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
import math
import os
import platform
import queue
import re
import secrets
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
# TTS — Async Queue with Piper / Kokoro / PowerShell fallback
# ══════════════════════════════════════════════════════════════
_tts_queue: queue.Queue = queue.Queue()
_tts_started = False
_piper_available: Optional[bool] = None


def _check_piper() -> bool:
    global _piper_available
    if _piper_available is not None:
        return _piper_available
    import shutil
    _piper_available = shutil.which("piper") is not None
    return _piper_available


def _tts_piper(text: str, rate: int = 1) -> bool:
    """Piper TTS — local neural voice, near-zero latency."""
    try:
        import subprocess, shutil
        piper_voices_dir = BASE_DIR / "piper_voices"
        voice_file = next(piper_voices_dir.glob("*.onnx"), None) if piper_voices_dir.exists() else None
        if not voice_file:
            return False
        proc = subprocess.Popen(
            ["piper", "--model", str(voice_file), "--output-raw"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        raw_pcm, _ = proc.communicate(input=text.encode(), timeout=30)
        # Play via aplay (Linux) or a raw PCM player
        import subprocess as sp
        sp.run(["python", "-c",
                "import sys,wave,io;import sounddevice as sd;import numpy as np;"
                "data=sys.stdin.buffer.read();arr=np.frombuffer(data,dtype=np.int16);"
                "sd.play(arr,22050);sd.wait()"],
               input=raw_pcm, timeout=30)
        return True
    except Exception:
        return False


def _tts_powershell(text: str, rate: int = 1) -> None:
    """PowerShell SAPI fallback (Windows only)."""
    try:
        import subprocess
        vol_line = "$s.Volume=30;" if is_quiet_hours() else ""
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Add-Type -AssemblyName System.Speech;"
             "$s=New-Object System.Speech.Synthesis.SpeechSynthesizer;"
             f"$s.Rate={int(rate)};"
             f"{vol_line}"
             "$s.Speak([Console]::In.ReadToEnd())"],
            input=text, capture_output=True, text=True,
            timeout=60, encoding="utf-8",
        )
    except Exception as e:
        log(f"TTS PS: {e}", "WARN")


def _tts_worker() -> None:
    while True:
        text = _tts_queue.get()
        if text is None:
            _tts_queue.task_done()
            break
        try:
            s = str(text)[:500].strip()
            if not s:
                continue
            rate = int(cfg.get("tts_rate", 1))
            if cfg.get("use_local_tts") and _check_piper():
                if not _tts_piper(s, rate):
                    _tts_powershell(s, rate)
            else:
                _tts_powershell(s, rate)
        except Exception as e:
            log(f"TTS worker: {e}", "WARN")
        finally:
            _tts_queue.task_done()


def speak(text: str, blocking: bool = False) -> None:
    global _tts_started
    if not text:
        return
    if not _tts_started:
        _tts_started = True
        threading.Thread(target=_tts_worker, daemon=True, name="tts_worker").start()
    s = str(text)[:500].strip()
    if s:
        _tts_queue.put(s)
    if blocking:
        _tts_queue.join()


# ══════════════════════════════════════════════════════════════
# STT — Faster-Whisper + Silero VAD (offline, <100ms wake)
# ══════════════════════════════════════════════════════════════
_whisper_model = None
_silero_vad    = None
_silero_utils  = None
_stt_lock      = threading.Lock()
_mic_lock      = threading.Lock()


def _load_whisper() -> Optional[Any]:
    global _whisper_model
    if _whisper_model is not None:
        return _whisper_model
    try:
        from faster_whisper import WhisperModel
        size = cfg.get("whisper_model", "base")
        log(f"Loading Faster-Whisper ({size})...", "STT")
        _whisper_model = WhisperModel(
            size, device="cpu", compute_type="int8",
            download_root=str(BASE_DIR / "whisper_models"),
        )
        log("Faster-Whisper loaded", "STT")
        return _whisper_model
    except ImportError:
        log("faster-whisper not installed, falling back to Google STT", "WARN")
    except Exception as e:
        log(f"Whisper load: {e}", "WARN")
    return None


def _load_silero_vad() -> Optional[Tuple[Any, Any]]:
    global _silero_vad, _silero_utils
    if _silero_vad is not None:
        return _silero_vad, _silero_utils
    try:
        import torch
        model, utils = torch.hub.load(
            repo_or_dir="snakers4/silero-vad",
            model="silero_vad",
            force_reload=False,
            trust_repo=True,
        )
        _silero_vad   = model
        _silero_utils = utils
        log("Silero VAD loaded", "STT")
        return model, utils
    except Exception as e:
        log(f"Silero VAD: {e} — skipping VAD", "WARN")
    return None, None


def _transcribe_faster_whisper(audio_bytes: bytes, sample_rate: int = 16000) -> Optional[str]:
    model = _load_whisper()
    if model is None:
        return None
    try:
        import numpy as np
        arr = np.frombuffer(audio_bytes, dtype=np.int16).astype(np.float32) / 32768.0
        segments, _ = model.transcribe(arr, language=cfg.get("language", "en"), beam_size=1)
        text = " ".join(seg.text for seg in segments).strip().lower()
        return text if text else None
    except Exception as e:
        log(f"Whisper transcribe: {e}", "WARN")
        return None


def listen(timeout: int = 8, phrase_time_limit: int = 15) -> Optional[str]:
    """
    Listen for speech. Uses Faster-Whisper (offline) if available,
    falls back to Google Web Speech API.
    """
    with _mic_lock:
        try:
            if cfg.get("use_local_stt") and _load_whisper():
                # Native audio capture path for Faster-Whisper
                try:
                    import sounddevice as sd
                    import numpy as np
                    sample_rate = 16000
                    # Record until silence (simple energy-based endpoint)
                    chunks = []
                    silence_frames = 0
                    recording_started = False
                    max_frames = timeout * sample_rate // 1024
                    energy_threshold = 0.01

                    with sd.InputStream(samplerate=sample_rate, channels=1,
                                        dtype="int16", blocksize=1024) as stream:
                        for _ in range(max_frames):
                            chunk, _ = stream.read(1024)
                            energy = np.abs(chunk).mean() / 32768
                            if energy > energy_threshold:
                                recording_started = True
                                silence_frames = 0
                            elif recording_started:
                                silence_frames += 1
                            if recording_started:
                                chunks.append(chunk.flatten().tobytes())
                            if silence_frames > 12 and recording_started:  # ~0.75s silence
                                break
                    if not chunks:
                        return None
                    raw = b"".join(chunks)
                    return _transcribe_faster_whisper(raw, sample_rate)
                except ImportError:
                    pass  # sounddevice not available, fall through

            # Fallback: speech_recognition + Google
            import speech_recognition as sr
            r = sr.Recognizer()
            r.energy_threshold = 300
            r.dynamic_energy_threshold = True
            r.pause_threshold = 0.8
            with sr.Microphone() as mic:
                r.adjust_for_ambient_noise(mic, duration=0.3)
                audio = r.listen(mic, timeout=timeout, phrase_time_limit=phrase_time_limit)
            try:
                return r.recognize_google(audio).lower().strip()
            except sr.UnknownValueError:
                return None
            except sr.RequestError as e:
                log(f"STT: {e}", "WARN")
                return None
        except Exception as e:
            log(f"Listen: {e}", "WARN")
            return None
