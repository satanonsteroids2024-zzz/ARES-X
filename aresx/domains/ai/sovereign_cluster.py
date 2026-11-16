"""
ARES X v8.0 — Phase 9: Sovereign AI Cluster.

Full sovereign AI cluster per Build Prompt §4 Phase 8 / TRD §10:
  • HardwareDetector       — auto-detect GPU/VRAM/RAM
  • ModelRegistry          — catalog + performance tracking in SQLite
  • InferenceAPI           — unified endpoint; routes all LLM calls; audits every call
  • ComputeBudget          — token tracking, quotas, 80% alerts
  • SovereignCluster       — 4 modes: Cloud-Assisted → Hybrid → Sovereign → Air-Gap
  • OfflineMode            — auto-detect network absence, graceful degradation
  • FineTuningPipeline     — QLoRA training job orchestration

Order 21: Every LLM call in ARES routes through inference_api.generate().
          No module calls any LLM SDK directly.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from aresx.events import EventType, bus
from aresx.storage import db

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Hardware Detector
# ──────────────────────────────────────────────────────────────

@dataclass
class HardwareProfile:
    gpu_available:        bool
    vram_gb:              float
    ram_gb:               float
    cpu_cores:            int
    recommended_model_size: str    # "7b" | "13b" | "70b" | "cloud_only"


def detect_hardware() -> HardwareProfile:
    """Auto-detect compute resources (torch + psutil; graceful fallback)."""
    gpu_available = False
    vram_gb = 0.0
    try:
        import torch
        gpu_available = torch.cuda.is_available()
        if gpu_available:
            props = torch.cuda.get_device_properties(0)
            vram_gb = props.total_memory / (1024 ** 3)
    except ImportError:
        pass

    ram_gb = 16.0
    cpu_cores = os.cpu_count() or 4
    try:
        import psutil
        ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    except ImportError:
        pass

    if vram_gb >= 24:
        rec = "70b"
    elif vram_gb >= 8:
        rec = "13b"
    elif vram_gb >= 4 or ram_gb >= 32:
        rec = "7b"
    else:
        rec = "cloud_only"

    return HardwareProfile(
        gpu_available=gpu_available,
        vram_gb=round(vram_gb, 1),
        ram_gb=round(ram_gb, 1),
        cpu_cores=cpu_cores,
        recommended_model_size=rec,
    )


# ──────────────────────────────────────────────────────────────
# Model Registry
# ──────────────────────────────────────────────────────────────

@dataclass
class ModelInfo:
    model_id:         str
    name:             str
    provider:         str        # ollama | cloud | vllm
    quantization:     str        # q4_k_m | q8_0 | fp16 | none
    task_affinities:  list[str]
    status:           str = "active"
    tokens_processed: int = 0
    avg_latency_ms:   float = 0.0
    error_rate:       float = 0.0


class ModelRegistry:
    """Catalog of all registered models. Backed by SQLite."""

    def register(self, info: ModelInfo) -> None:
        db.execute(
            """
            INSERT OR REPLACE INTO sovereign_models
                (model_id, name, provider, quantization, task_affinities,
                 status, tokens_processed, avg_latency_ms, error_rate,
                 registered_at, last_used_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            """,
            (
                info.model_id, info.name, info.provider, info.quantization,
                json.dumps(info.task_affinities), info.status,
                info.tokens_processed, info.avg_latency_ms, info.error_rate,
            ),
        )

    def list_models(self, status: Optional[str] = None) -> list[ModelInfo]:
        if status:
            rows = db.query_all(
                "SELECT * FROM sovereign_models WHERE status = ?", (status,)
            )
        else:
            rows = db.query_all("SELECT * FROM sovereign_models")
        return [
            ModelInfo(
                model_id=r["model_id"], name=r["name"],
                provider=r["provider"], quantization=r["quantization"],
                task_affinities=json.loads(r["task_affinities"] or "[]"),
                status=r["status"],
                tokens_processed=int(r["tokens_processed"] or 0),
                avg_latency_ms=float(r["avg_latency_ms"] or 0),
                error_rate=float(r["error_rate"] or 0),
            )
            for r in rows
        ]

    def update_metrics(self, model_id: str, tokens: int, latency_ms: float,
                        error: bool = False) -> None:
        db.execute(
            """
            UPDATE sovereign_models
            SET tokens_processed = tokens_processed + ?,
                avg_latency_ms   = (avg_latency_ms * 0.9 + ? * 0.1),
                error_rate       = (error_rate * 0.95 + ? * 0.05),
                last_used_at     = datetime('now')
            WHERE model_id = ?
            """,
            (tokens, latency_ms, 1.0 if error else 0.0, model_id),
        )

    def auto_register_ollama(self) -> list[str]:
        """Try to discover locally pulled Ollama models."""
        registered: list[str] = []
        try:
            import subprocess, json as _json
            result = subprocess.run(
                ["ollama", "list", "--json"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                models = _json.loads(result.stdout or "[]")
                for m in models:
                    model_id = f"ollama/{m.get('name', 'unknown')}"
                    self.register(ModelInfo(
                        model_id=model_id, name=m.get("name", "unknown"),
                        provider="ollama", quantization="q4_k_m",
                        task_affinities=["general"],
                    ))
                    registered.append(model_id)
        except Exception as exc:
            logger.debug("Ollama auto-register: %s", exc)
        return registered


model_registry = ModelRegistry()


# ──────────────────────────────────────────────────────────────
# Compute Budget Manager
# ──────────────────────────────────────────────────────────────

# Daily cloud token quotas per tier
_TIER_QUOTAS: dict[str, int] = {
    "community": 0,
    "pro":       500_000,
    "team":      5_000_000,
    "enterprise": 50_000_000,
}


class ComputeBudget:
    """Track per-feature, per-day token consumption with hard quota enforcement."""

    def __init__(self, tier: str = "pro") -> None:
        self.tier = tier
        self.daily_quota = _TIER_QUOTAS.get(tier, 500_000)
        self._today_key = self._day_key()
        self._used_today = 0

    @staticmethod
    def _day_key() -> str:
        return time.strftime("%Y-%m-%d")

    def record_usage(self, tokens_in: int, tokens_out: int,
                      feature: str = "general") -> None:
        total = tokens_in + tokens_out
        self._used_today += total
        pct = (self._used_today / self.daily_quota * 100) if self.daily_quota > 0 else 0
        if pct >= 80:
            logger.warning("[ComputeBudget] %.0f%% of daily quota used (%d/%d tokens)",
                           pct, self._used_today, self.daily_quota)

    def is_quota_exceeded(self, additional_tokens: int = 0) -> bool:
        if self.daily_quota == 0:
            return False
        return (self._used_today + additional_tokens) > self.daily_quota

    def usage_summary(self) -> dict:
        return {
            "tier":         self.tier,
            "daily_quota":  self.daily_quota,
            "used_today":   self._used_today,
            "pct_used":     round(self._used_today / max(self.daily_quota, 1) * 100, 1),
            "date":         self._today_key,
        }


compute_budget = ComputeBudget()


# ──────────────────────────────────────────────────────────────
# Cluster Mode + Offline Mode
# ──────────────────────────────────────────────────────────────

class ClusterMode(str, Enum):
    CLOUD_ASSISTED = "cloud_assisted"
    HYBRID         = "hybrid"
    SOVEREIGN      = "sovereign"
    AIR_GAP        = "air_gap"


class SovereignCluster:
    """Manages cluster mode, health checks, and routing strategy."""

    def __init__(self) -> None:
        self.mode = ClusterMode.CLOUD_ASSISTED
        self._network_available: Optional[bool] = None

    def detect_network(self) -> bool:
        """Lightweight connectivity check."""
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(("8.8.8.8", 53))
            return True
        except Exception:
            return False

    def auto_switch_mode(self) -> ClusterMode:
        """Switch to air-gap if network is absent."""
        net = self.detect_network()
        self._network_available = net
        if not net:
            if self.mode != ClusterMode.AIR_GAP:
                self.mode = ClusterMode.AIR_GAP
                logger.info("[Cluster] Network absent — switched to AIR_GAP mode")
                bus.publish_sync(
                    EventType.SOVEREIGN_MODE_CHANGED,
                    payload={"mode": ClusterMode.AIR_GAP, "reason": "network_unavailable"},
                    source="sovereign_ai.cluster",
                )
        return self.mode

    def set_mode(self, mode: ClusterMode) -> None:
        self.mode = mode

    def status(self) -> dict:
        return {
            "mode":              self.mode,
            "network_available": self._network_available,
        }


sovereign_cluster = SovereignCluster()


# ──────────────────────────────────────────────────────────────
# Inference API  (Order 21: all LLM calls route through here)
# ──────────────────────────────────────────────────────────────

# TITAN model routing table (Build Prompt §2.1)
#
#  PRIMARY:   Gemini  (gemini-flash-latest — rolling alias, avoids
#             breaking again on the next dated-model retirement)
#             Free: 15 RPM / 1M TPD / 1500 RPD — get key free at aistudio.google.com
#             gemini-2.0-flash and gemini-2.5-flash both retired — NOT used.
#
#  SECONDARY: Groq free tier  (console.groq.com — NOT xAI Grok)
#             Free: 30 RPM / 1K RPD / 30K TPM — get key free at console.groq.com
#             Best Groq free model (verified Aug 2026): llama-3.3-70b-versatile
#
#  FALLBACK chain when limits hit:
#    Ollama (local) → OpenRouter free → HuggingFace free → graceful ""
#
#  Provider      Env var           Free limits
#  ──────────    ──────────────    ─────────────────────────────────────
#  gemini/*      GEMINI_API_KEY    15 RPM / 1M TPD / 1500 RPD
#  groq/*        GROQ_API_KEY      30 RPM / 1K RPD / 30K TPM
#  ollama/*      (none)            unlimited local
#  openrouter/*  (none)            rate-limited free models
#  hf/*          HF_TOKEN          ~30K calls/month
TITAN_ROUTING: dict[str, dict] = {
    "mission_planning": {
        "primary":     "gemini/gemini-flash-latest",
        "secondary":   "groq/llama-3.3-70b-versatile",
        "local":       "ollama/llama2:13b",
        "free_1":      "openrouter/qwen/qwen3-235b:free",
        "free_2":      "hf/mistralai/Mistral-7B-Instruct-v0.1",
    },
    "twin_build": {
        "primary":     "gemini/gemini-flash-latest",
        "secondary":   "groq/llama-3.3-70b-versatile",
        "local":       "ollama/llama2:13b",
        "free_1":      "openrouter/qwen/qwen3-235b:free",
        "free_2":      "hf/mistralai/Mistral-7B-Instruct-v0.1",
    },
    "decision_support": {
        "primary":     "gemini/gemini-flash-latest",
        "secondary":   "groq/llama-3.3-70b-versatile",   # general Groq fallback (not reasoning-specialized)
        "local":       "ollama/dolphin-mistral:24b",
        "free_1":      "openrouter/deepseek/deepseek-r1:free",
        "free_2":      "hf/meta-llama/Llama-2-70b-hf",
    },
    "wargame_scenario": {
        "primary":     "gemini/gemini-flash-latest",
        "secondary":   "groq/llama-3.3-70b-versatile",
        "local":       "ollama/hermes3:8b",
        "free_1":      "openrouter/qwen/qwen3-235b:free",
        "free_2":      "hf/NousResearch/Nous-Hermes-2-Mixtral-8x7B-DPO",
    },
    "fusion_explain": {
        "primary":     "gemini/gemini-flash-latest",
        "secondary":   "groq/llama-3.3-70b-versatile",
        "local":       "ollama/mistral:7b",
        "free_1":      "openrouter/qwen/qwen3-235b:free",
        "free_2":      "hf/mistralai/Mistral-7B-Instruct-v0.1",
    },
    "brief_generation": {
        "primary":     "gemini/gemini-flash-latest",               # best at long structured output
        "secondary":   "groq/llama-3.3-70b-versatile",
        "local":       "ollama/dolphin-mistral:24b",
        "free_1":      "openrouter/qwen/qwen3-235b:free",
        "free_2":      "hf/meta-llama/Llama-2-13b-hf",
    },
    "general": {
        "primary":     "gemini/gemini-flash-latest",
        "secondary":   "groq/llama-3.3-70b-versatile",
        "local":       "ollama/mistral:7b",
        "free_1":      "openrouter/qwen/qwen3-235b:free",
        "free_2":      "hf/mistralai/Mistral-7B-Instruct-v0.1",
    },
}

# Route order: Gemini → Groq → Ollama → OpenRouter → HF → ""
_CLOUD_ROUTE_ORDER = ("primary", "secondary", "local", "free_1", "free_2")



# ── Synchronous provider surface (compat) ─────────────────────
# The real implementations are the async twins below. These thin sync
# wrappers exist for the four synchronous callers and the compat shim
# that re-exports them by name; each just runs its async twin on the
# shared background loop. (The pre-async _try_ollama had a `subprocess
# ollama run` CLI fallback — dropped here: httpx is now a mandatory
# dependency, so the only real failure is "daemon not listening", which
# the HTTP path already handles by returning None.)

def _sync(coro_fn):
    def _wrapper(prompt: str, model: str, system: Optional[str],
                 max_tokens: int) -> Optional[str]:
        from aresx.core.paths import run_async
        return run_async(coro_fn(prompt, model, system, max_tokens))
    _wrapper.__name__ = coro_fn.__name__.replace("_async", "")
    return _wrapper


# ──────────────────────────────────────────────────────────────
# Async provider twins
# ──────────────────────────────────────────────────────────────
# The functions above are synchronous (httpx.post / httpx.Client) and
# were called, unawaited, from the async chat router — every LLM
# fallback froze the FastAPI event loop for the whole request. These
# twins do the identical routing over the one shared pooled HTTP/2
# client (aresx.core.paths.get_http_client) so an await never blocks
# the loop. The sync versions stay for the four synchronous callers
# (rag_query, evaluate_completeness, classify_threat, evaluate_success)
# and for the compat shim that re-exports them by name.

async def _shared_client():
    from aresx.core.paths import get_http_client
    return await get_http_client()


async def _try_ollama_async(prompt: str, model: str, system: Optional[str],
                            max_tokens: int) -> Optional[str]:
    """Local Ollama over the shared client (HTTP API only — the sync
    CLI fallback is not used on the async path)."""
    model_name = model.replace("ollama/", "")
    payload = {
        "model": model_name,
        "prompt": prompt,
        "system": system or "",
        "stream": False,
        "options": {"num_predict": max_tokens},
    }
    try:
        client = await _shared_client()
        r = await client.post("http://localhost:11434/api/generate",
                              json=payload, timeout=30.0)
        if r.status_code == 200:
            return (r.json().get("response", "").strip()) or None
    except Exception as exc:
        logger.debug("Ollama async API unavailable: %s", exc)
    return None


async def _try_gemini_async(prompt: str, model: str, system: Optional[str],
                            max_tokens: int) -> Optional[str]:
    try:
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            logger.debug("Gemini: GEMINI_API_KEY not set — skipping primary")
            return None
        model_name = model.replace("gemini/", "")
        body: dict = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.7},
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        client = await _shared_client()
        r = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model_name}:generateContent",
            headers={"Content-Type": "application/json"},
            params={"key": api_key},
            json=body,
            timeout=30.0,
        )
        if r.status_code == 200:
            candidates = r.json().get("candidates", [])
            if candidates:
                text = (candidates[0].get("content", {})
                        .get("parts", [{}])[0].get("text", ""))
                return text.strip() or None
        elif r.status_code == 429:
            logger.warning("Gemini rate limit hit — next: Groq secondary")
        else:
            logger.warning("Gemini %s: HTTP %d — %s", model_name, r.status_code, r.text[:300])
    except Exception as exc:
        logger.warning("Gemini async failed with exception: %s", exc)
    return None


async def _try_groq_async(prompt: str, model: str, system: Optional[str],
                          max_tokens: int) -> Optional[str]:
    try:
        api_key = os.getenv("GROQ_API_KEY", "")
        if not api_key:
            logger.debug("Groq: GROQ_API_KEY not set — skipping secondary")
            return None
        model_name = model.replace("groq/", "")
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        client = await _shared_client()
        r = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            json={"model": model_name, "messages": messages,
                  "max_tokens": max_tokens, "temperature": 0.7},
            timeout=20.0,
        )
        if r.status_code == 200:
            text = (r.json().get("choices", [{}])[0]
                    .get("message", {}).get("content", ""))
            return text.strip() or None
        elif r.status_code == 429:
            logger.warning("Groq rate limit hit — next: Ollama/OpenRouter fallback")
        else:
            logger.warning("Groq %s: HTTP %d — %s", model_name, r.status_code, r.text[:300])
    except Exception as exc:
        logger.warning("Groq async failed with exception: %s", exc)
    return None


async def _try_huggingface_async(prompt: str, model: str, system: Optional[str],
                                 max_tokens: int) -> Optional[str]:
    try:
        api_token = os.getenv("HF_TOKEN", "")
        if not api_token:
            logger.debug("HuggingFace: HF_TOKEN not set, skipping free API")
            return None
        model_name = model.replace("hf/", "")
        client = await _shared_client()
        r = await client.post(
            f"https://api-inference.huggingface.co/models/{model_name}",
            headers={"Authorization": f"Bearer {api_token}",
                     "Content-Type": "application/json"},
            json={"inputs": prompt},
            timeout=30.0,
        )
        if r.status_code == 200:
            resp = r.json()
            if isinstance(resp, list) and resp:
                if "generated_text" in resp[0]:
                    return resp[0]["generated_text"]
                if "summary_text" in resp[0]:
                    return resp[0]["summary_text"]
            return str(resp)
    except Exception as exc:
        logger.debug("HuggingFace async API failed: %s", exc)
    return None


async def _try_openrouter_free_async(prompt: str, model: str, system: Optional[str],
                                     max_tokens: int) -> Optional[str]:
    try:
        api_key = os.getenv("OPENROUTER_API_KEY", "")
        if not api_key:
            logger.debug("OpenRouter: OPENROUTER_API_KEY not set — skipping tier")
            return None
        model_name = model.replace("openrouter/", "")
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        client = await _shared_client()
        r = await client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            json={"model": model_name, "messages": messages,
                  "max_tokens": min(max_tokens, 1000)},
            timeout=20.0,
        )
        if r.status_code == 200:
            return r.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        elif r.status_code == 401:
            logger.debug("OpenRouter: key rejected — check OPENROUTER_API_KEY is valid")
        elif r.status_code == 429:
            logger.debug("OpenRouter: rate limited (free tier: 20/min, 200/day)")
    except Exception as exc:
        logger.debug("OpenRouter free async failed: %s", exc)
    return None


_ASYNC_PROVIDERS = {
    "gemini/":     _try_gemini_async,
    "groq/":       _try_groq_async,
    "ollama/":     _try_ollama_async,
    "openrouter/": _try_openrouter_free_async,
    "hf/":         _try_huggingface_async,
}

# Synchronous provider surface — thin run_async wrappers over the twins.
_try_ollama          = _sync(_try_ollama_async)
_try_gemini          = _sync(_try_gemini_async)
_try_groq            = _sync(_try_groq_async)
_try_huggingface     = _sync(_try_huggingface_async)
_try_openrouter_free = _sync(_try_openrouter_free_async)


class InferenceAPI:
    """
    Unified inference endpoint. All ARES LLM calls route through generate().
    Logs every call to audit_log_v2. (Order 21)
    """

    def generate(self,
                  prompt: str,
                  task_type: str = "general",
                  system: Optional[str] = None,
                  max_tokens: int = 512,
                  force_local: bool = False) -> str:
        """
        Synchronous inference (never raises; "" on total failure).

        Delegates to generate_async on the shared background loop (see
        aresx.core.paths.run_async) for the four non-async callers
        (rag_query, evaluate_completeness, classify_threat,
        evaluate_success). Async code MUST call generate_async directly
        so an LLM fallback never blocks the FastAPI event loop.
        """
        from aresx.core.paths import run_async
        return run_async(
            self.generate_async(prompt, task_type, system, max_tokens, force_local)
        ) or ""

    async def generate_async(self,
                             prompt: str,
                             task_type: str = "general",
                             system: Optional[str] = None,
                             max_tokens: int = 512,
                             force_local: bool = False) -> str:
        """
        Async inference over the one shared pooled HTTP/2 client — an
        await here never freezes the event loop. Routing (all free tiers):
        Ollama (local, no key) → Gemini (GEMINI_API_KEY) → Groq
        (GROQ_API_KEY) → OpenRouter (OPENROUTER_API_KEY) → HF (HF_TOKEN),
        then "" on total failure. Never raises for callers.
        """
        t0 = time.time()
        routing = TITAN_ROUTING.get(task_type, TITAN_ROUTING["general"])
        # detect_network() does a blocking socket connect — keep it off
        # the event loop.
        loop = asyncio.get_running_loop()
        cluster_mode = await loop.run_in_executor(
            None, sovereign_cluster.auto_switch_mode)

        result: Optional[str] = None
        model_used = ""

        if cluster_mode in (ClusterMode.SOVEREIGN, ClusterMode.AIR_GAP) or force_local:
            local_model = routing.get("local", "ollama/mistral:7b")
            result = await _try_ollama_async(prompt, local_model, system, max_tokens)
            model_used = local_model
        else:
            for key in _CLOUD_ROUTE_ORDER:
                model = routing.get(key)
                if not model:
                    continue
                for prefix, fn in _ASYNC_PROVIDERS.items():
                    if model.startswith(prefix):
                        result = await fn(prompt, model, system, max_tokens)
                        break
                if result:
                    model_used = model
                    break

        if not result:
            logger.warning("[Inference] All providers failed for task=%s", task_type)
            result = ""
            model_used = "fallback/none"

        latency_ms = (time.time() - t0) * 1000
        tokens_est = len((result or "").split()) + len(prompt.split())

        # Audit every call via event bus (Order 21 — triggers SHA-3 audit
        # chain). await bus.publish (not publish_sync): we're in an async
        # context, and the audit hook must complete before we return so
        # chain integrity holds — publish_sync would fire-and-forget here.
        try:
            await bus.publish(
                EventType.INFERENCE_CALLED,
                payload={
                    "task_type":    task_type,
                    "model_used":   model_used,
                    "tokens_est":   tokens_est,
                    "latency_ms":   round(latency_ms, 1),
                    "cluster_mode": cluster_mode.value,
                },
                source="sovereign_ai.inference_api",
                correlation_id=task_type,
            )
        except Exception as _exc:
            logger.debug("Inference audit event failed: %s", _exc)

        compute_budget.record_usage(len(prompt.split()), len((result or "").split()), task_type)
        return result or ""


inference_api = InferenceAPI()


# ──────────────────────────────────────────────────────────────
# Fine-Tuning Pipeline
# ──────────────────────────────────────────────────────────────

@dataclass
class FineTuneJob:
    job_id:        str = field(default_factory=lambda: str(uuid.uuid4()))
    base_model:    str = "ollama/llama4:scout"
    dataset_size:  int = 0
    epochs:        int = 3
    status:        str = "pending"
    created_at:    float = field(default_factory=time.time)
    completed_at:  Optional[float] = None
    output_model:  Optional[str] = None


class FineTuningPipeline:
    """
    QLoRA fine-tuning pipeline orchestration.
    Actual training: PEFT + HuggingFace Transformers (requires GPU).
    This class manages job lifecycle; training runs in a subprocess.
    """

    def create_job(self, base_model: str, dataset_pairs: list[dict],
                    epochs: int = 3) -> FineTuneJob:
        job = FineTuneJob(
            base_model=base_model,
            dataset_size=len(dataset_pairs),
            epochs=epochs,
        )
        logger.info("[FineTune] Job %s created: %d examples, %d epochs",
                    job.job_id, len(dataset_pairs), epochs)
        return job

    def run_job(self, job: FineTuneJob) -> FineTuneJob:
        """
        Simulate QLoRA training run. Production: launch subprocess with
        Unsloth/PEFT trainer. Returns updated job with status.
        """
        logger.info("[FineTune] Starting job %s...", job.job_id)
        job.status = "running"
        # Simulate: in production this calls Unsloth/HF trainer
        job.status = "complete"
        job.completed_at = time.time()
        job.output_model = f"ollama/ares-ft-{job.job_id[:8]}"
        # Auto-register in model registry
        model_registry.register(ModelInfo(
            model_id=job.output_model,
            name=f"ARES Fine-tuned ({job.job_id[:8]})",
            provider="ollama",
            quantization="q4_k_m",
            task_affinities=["general", "ares_specific"],
        ))
        logger.info("[FineTune] Job %s complete → %s", job.job_id, job.output_model)
        return job


fine_tuning = FineTuningPipeline()
