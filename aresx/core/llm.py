"""
ARES X v10 — LLM backends & public AI API (split from core.py)
==============================================================
Split out of the v9 core.py god-file into a focused module.

All original public symbols are re-exported by aresx.core (the
compat facade) so existing importers keep working unmodified.
"""
from __future__ import annotations

from aresx.core.paths import cfg, log

# ── httpx helpers (kept local to avoid a second tiny module) ──
_http_client = None
async def _get_http():
    global _http_client
    import httpx
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=5.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            http2=True, follow_redirects=True)
    return _http_client
async def _async_post(url, body, headers, timeout=30.0):
    try:
        client = await _get_http()
        resp = await client.post(url, json=body, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        log(f"HTTP POST [{url[:60]}]: {exc}", "WARN")
        return None
async def _async_get(url, timeout=15.0):
    try:
        client = await _get_http()
        resp = await client.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.content
    except Exception as exc:
        log(f"HTTP GET [{url[:60]}]: {exc}", "WARN")
        return None
async def is_online_async():
    try:
        return await _async_get("https://1.1.1.1", timeout=3.0) is not None
    except Exception:
        return False
def is_online():
    return run_async(is_online_async()) or False

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
# AI MODEL CONSTANTS (June 2026)
# ══════════════════════════════════════════════════════════════
OLLAMA_URL      = "http://localhost:11434/api/chat"
GEMINI_URL      = "https://generativelanguage.googleapis.com/v1beta/models"
GROQ_URL        = "https://api.groq.com/openai/v1/chat/completions"
HF_API_URL      = "https://api-inference.huggingface.co/models"
OPENROUTER_URL  = "https://openrouter.ai/api/v1/chat/completions"

# Free-tier models used for each task
GEMINI_MODEL = "gemini-3.5-flash"   # free: 15 RPM / 1M TPD / 1500 RPD (2.5 retired for new keys, June 2026)
# NOTE: "Grok" here means Groq (console.groq.com) — NOT xAI Grok
GROQ_MODEL   = "llama-4-scout-17b-16e-instruct"   # Groq free: 30 RPM / 1K RPD / 30K TPM
OLLAMA_MODEL = "mistral:7b"         # local, unlimited

# ── Ollama availability (async, cached 60s) ───────────────────
_ollama_cache: Dict[str, Any] = {"ok": None, "ts": 0.0}
_ollama_lock = threading.Lock()


async def _check_ollama_async() -> bool:
    now = time.time()
    with _ollama_lock:
        if _ollama_cache["ok"] is not None and now - _ollama_cache["ts"] < 60:
            return _ollama_cache["ok"]
    try:
        data = await _async_get("http://localhost:11434/", timeout=2.0)
        ok = data is not None
    except Exception:
        ok = False
    with _ollama_lock:
        _ollama_cache.update({"ok": ok, "ts": time.time()})
    if ok:
        log("Ollama: available", "AI")
    return ok


# ── Async AI backends (all free tier) ─────────────────────────
async def _gemini_async(prompt: str, image_b64: Optional[str] = None,
                         max_tokens: int = 600) -> Optional[str]:
    """
    Google Gemini free tier.
    Free: 15 RPM / 1M tokens/day / 1500 req/day — no billing required.
    Get key free at aistudio.google.com. Set GEMINI_API_KEY env var.
    """
    import os
    key = os.getenv("GEMINI_API_KEY", cfg.get("api_keys", {}).get("gemini_key", "")).strip()
    if not key:
        return None
    try:
        parts: List[Dict] = []
        if image_b64:
            parts.append({"inline_data": {"mime_type": "image/jpeg", "data": image_b64}})
        parts.append({"text": prompt})
        d = await _async_post(
            f"{GEMINI_URL}/{GEMINI_MODEL}:generateContent?key={key}",  # gemini-3.5-flash
            {
                "contents": [{"parts": parts}],
                "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.7},
            },
            {"Content-Type": "application/json"},
            timeout=30.0,
        )
        if d:
            return (d.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [{}])[0]
                    .get("text", "").strip()) or None
    except Exception as exc:
        logger.debug("Gemini async failed: %s", exc)
    return None


async def _groq_async(messages: List[Dict], max_tokens: int = 800) -> Optional[str]:
    """
    Groq Inference API free tier — SECONDARY cloud provider.
    Provider: console.groq.com (NOT xAI Grok — different company/product).
    Free: 30 RPM / 1K RPD / 30K TPM — forever free, no credit card.
    Get key free at console.groq.com. Set GROQ_API_KEY env var.
    """
    import os
    key = os.getenv("GROQ_API_KEY", cfg.get("api_keys", {}).get("groq_key", "")).strip()
    if not key:
        return None
    try:
        d = await _async_post(
            GROQ_URL,
            {"model": GROQ_MODEL, "messages": messages, "max_tokens": max_tokens},
            {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            timeout=20.0,
        )
        if d:
            return (d.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "").strip()) or None
    except Exception as exc:
        logger.debug("Groq async failed: %s", exc)
    return None


async def _huggingface_async(model: str, messages: List[Dict],
                              max_tokens: int = 800) -> Optional[str]:
    """HuggingFace free API (30K calls/month). Set HF_TOKEN env var."""
    import os
    key = os.getenv("HF_TOKEN", cfg.get("api_keys", {}).get("hf_token", "")).strip()
    if not key:
        return None
    try:
        text_prompt = " ".join(m.get("content", "") for m in messages)
        d = await _async_post(
            f"{HF_API_URL}/{model}",
            {"inputs": text_prompt},
            {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            timeout=30.0,
        )
        if d and isinstance(d, list) and len(d) > 0:
            if "generated_text" in d[0]:
                return d[0]["generated_text"].strip()
        return None
    except Exception:
        return None



async def _openrouter_async(model: str, messages: List[Dict],
                             max_tokens: int = 800) -> Optional[str]:
    """Try OpenRouter free models (no auth required)."""
    try:
        d = await _async_post(
            OPENROUTER_URL,
            {"model": model, "max_tokens": min(max_tokens, 1000), "messages": messages},
            {"Content-Type": "application/json"},
            timeout=20.0,
        )
        if d and "choices" in d and len(d["choices"]) > 0:
            return d["choices"][0].get("message", {}).get("content", "").strip()
        return None
    except Exception:
        return None





async def _ollama_text_async(messages: List[Dict],
                              max_tokens: int = 800) -> Optional[str]:
    if not await _check_ollama_async():
        return None
    try:
        client = await _get_http()
        resp = await client.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "messages": messages,
                  "stream": False, "options": {"num_predict": max_tokens}},
            timeout=httpx.Timeout(connect=3.0, read=120.0, write=10.0, pool=5.0),
        )
        resp.raise_for_status()
        d = resp.json()
        return d.get("message", {}).get("content", "").strip() or None
    except Exception as e:
        log(f"Ollama text: {e}", "WARN")
        return None


async def _ollama_vision_async(prompt: str, image_b64: str,
                                max_tokens: int = 600) -> Optional[str]:
    if not await _check_ollama_async():
        return None
    try:
        client = await _get_http()
        resp = await client.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "stream": False,
                  "options": {"num_predict": max_tokens},
                  "messages": [{"role": "user", "content": prompt,
                                "images": [image_b64]}]},
            timeout=httpx.Timeout(connect=3.0, read=120.0, write=10.0, pool=5.0),
        )
        resp.raise_for_status()
        d = resp.json()
        return d.get("message", {}).get("content", "").strip() or None
    except Exception as e:
        log(f"Ollama vision: {e}", "WARN")
        return None


# ── Public AI API (async) ──────────────────────────────────────
async def ask_ai_async(
    prompt: str,
    system: str = "You are ARES X, an autonomous desktop agent. Be concise.",
    max_tokens: int = 800,
) -> Optional[str]:
    """
    Async text AI chain — all free tiers:
      1. Ollama local       (unlimited, needs daemon running)
      2. Gemini free        (15 RPM / 1M TPD, needs GEMINI_API_KEY)
      3. Grok free          (25 RPM / 250K TPM, needs GROK_API_KEY)
      4. OpenRouter free    (rate-limited, no key needed)
      5. HuggingFace free   (30K/month, needs HF_TOKEN)
    """
    msgs = [{"role": "system", "content": system},
            {"role": "user", "content": prompt}]

    # 1. Ollama local (fastest, no rate limits, no cost)
    if await _check_ollama_async():
        result = await _ollama_text_async(msgs, max_tokens)
        if result:
            return result

    # 2. Gemini free tier (best quality among free cloud options)
    result = await _gemini_async(prompt, max_tokens=max_tokens)
    if result:
        return result

    # 3. Grok free tier (strong reasoning, generous free limits)
    result = await _groq_async(msgs, max_tokens)
    if result:
        return result

    # 4. OpenRouter free (no key required)
    result = await _openrouter_async("qwen/qwen3-235b:free", msgs, max_tokens)
    if result:
        return result

    # 5. HuggingFace free (30K calls/month)
    result = await _huggingface_async("mistralai/Mistral-7B-Instruct-v0.1", msgs, max_tokens)
    if result:
        return result

    # Final local fallback even if check said unavailable
    log("All cloud providers failed — final Ollama fallback", "AI")
    return await _ollama_text_async(msgs, max_tokens)


async def ask_vision_async(
    prompt: str,
    image_b64: Optional[str] = None,
    max_tokens: int = 600,
) -> Optional[str]:
    """
    Async vision AI chain — all free tiers:
      1. Gemini free   (natively multimodal, 15 RPM, needs GEMINI_API_KEY)
      2. Ollama local  (with llava or moondream model for vision)
      3. Grok free     (text-only fallback)
    """
    if image_b64 is None:
        image_b64 = screenshot_b64()
    if not image_b64:
        return None

    # 1. Gemini — best free multimodal option
    result = await _gemini_async(prompt, image_b64, max_tokens)
    if result:
        return result

    # 2. Ollama local vision (needs moondream or llava pulled)
    result = await _ollama_vision_async(prompt, image_b64, max_tokens)
    if result:
        return result

    # 3. Grok / text-only fallback (describe without image)
    msgs = [{"role": "user", "content": f"[Screenshot context]\n\n{prompt}"}]
    result = await _groq_async(msgs, max_tokens)
    if result:
        return result

    return await _openrouter_async("qwen/qwen3-235b:free", msgs, max_tokens)


async def ask_ai_code_async(
    prompt: str,
    system: str = "You are an expert Python debugger. Fix the code.",
    max_tokens: int = 4000,
) -> Optional[str]:
    """
    Code AI chain — all free tiers:
      1. Grok free     (strong coding, generous limits)
      2. Gemini free   (strong at code + long context)
      3. OpenRouter free (qwen3 — top free code model)
      4. Ollama local  (offline fallback)
    """
    msgs = [{"role": "system", "content": system},
            {"role": "user", "content": prompt}]

    # 1. Grok — excellent at code, generous free tier
    result = await _groq_async(msgs, max_tokens)
    if result:
        return result

    # 2. Groq — SECONDARY (30 RPM free, good at code)
    result = await _groq_async(msgs, max_tokens)
    if result:
        return result

    # 3. OpenRouter Qwen3 (best free code model)
    result = await _openrouter_async("qwen/qwen3-235b:free", msgs, max_tokens)
    if result:
        return result

    # 4. Ollama local
    log("Falling back to Ollama code (offline)", "AI")
    return await _ollama_text_async(msgs, max_tokens)


# ── Sync wrappers ──────────────────────────────────────────────
def ask_ai(prompt: str, system: str = "You are ARES X, an autonomous desktop agent. Be concise.",
           max_tokens: int = 800) -> Optional[str]:
    return run_async(ask_ai_async(prompt, system, max_tokens))


def ask_vision(prompt: str, image_b64: Optional[str] = None,
               max_tokens: int = 600) -> Optional[str]:
    return run_async(ask_vision_async(prompt, image_b64, max_tokens))


def ask_ai_code(prompt: str,
                system: str = "You are an expert Python debugger. Fix the code.",
                max_tokens: int = 4000) -> Optional[str]:
    return run_async(ask_ai_code_async(prompt, system, max_tokens))
