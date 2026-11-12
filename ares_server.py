"""
ARES X v12 — Server Bridge
FastAPI server connecting the chat frontend to the real ARES backend.

Run:
    python3 ares_server.py

Then open http://localhost:8000 in your browser.
"""
from __future__ import annotations

import logging
import webbrowser
import threading
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ares_server")

# ── Load any saved API keys BEFORE booting ARES ─────────────────────────────
# Must happen first: aresx.sovereign_ai reads keys via os.getenv() at call
# time, so they need to already be in the environment before any inference
# call, though boot() itself doesn't require them (ARES degrades gracefully
# to Ollama/OpenRouter with no keys at all).
from api_keys import load_keys_into_environment, has_any_key

key_status = load_keys_into_environment()
logger.info("API keys loaded: %s", {k: v for k, v in key_status.items()})

# ── Boot ARES backend ONCE at startup ──────────────────────────────────────
import aresx.v8_bootstrap as bs

boot_result = bs.boot()
logger.info("ARES X v12 booted — tier=%s", boot_result.get("tier", "unknown"))

# ── Force chat-based authorization mode BEFORE anything else can create ────
# the shared AuthorizationManager in the default "blocking" (terminal
# input()) mode. get_shared_authorization()'s `mode` argument only takes
# effect on the call that actually constructs the singleton — so this
# has to run before tool_router (or anything it imports) gets a chance
# to call get_shared_authorization() itself. In "chat" mode, a red-team
# tool that needs authorization raises PendingApproval instead of
# blocking on input() — see /chat's handling of PendingApproval below.
from aresx.red import get_shared_authorization
get_shared_authorization(mode="chat")

import aresx.chat.router as tool_router
from aresx.chat.router import _regex_route_message  # noqa: E402

app = FastAPI(title="ARES X v12")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatRequest(BaseModel):
    message: str
    history: list[dict] = []   # [{"role": "user"|"ares", "text": "..."}, ...]
                                # optional for backward compat — older
                                # clients (or test_chat_auth.py's direct
                                # calls, which don't set this) just get
                                # no context, same as before this field existed


class ChatResponse(BaseModel):
    response: str


class SaveKeyRequest(BaseModel):
    provider: str   # "gemini" | "groq" | "hf"
    key: str


@app.get("/")
async def serve_frontend():
    return FileResponse(Path(__file__).parent / "frontend" / "index.html")


@app.get("/setup/status")
async def setup_status():
    """
    Whether the first-run key setup screen should be shown. The frontend
    checks this on load, before rendering the chat UI at all.
    """
    return {
        "needs_setup": not has_any_key(),
        "keys_present": load_keys_into_environment(),
    }


@app.post("/setup/save-key")
async def setup_save_key(req: SaveKeyRequest):
    """
    Validate a key live against the real provider API, then persist it
    to ~/.config/ares-x/env if valid. Returns ok=False with a specific
    reason on failure — never silently accepts a bad key.
    """
    from api_keys import save_key

    ok, message = await save_key(req.provider, req.key)
    return {"ok": ok, "message": message}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    import os
    if os.getenv("GEMINI_API_KEY"):
        # Natural-language tool selection — Gemini decides, from actual
        # conversational phrasing, which ARES capability applies.
        # History gives it context of what's already been discussed —
        # without it, every message was evaluated in total isolation.
        # SIGNAGE (Phase B): log which ring-road the /chat fork took —
        # previously the Gemini vs regex choice was invisible in the logs.
        logger.info("[chat] routing via Gemini tool-calling: %r", req.message[:60])
        reply = await tool_router.route_message(req.message, req.history)
    else:
        # No Gemini key configured (e.g. fully-offline/Ollama-only setup)
        # — tool-calling needs Gemini specifically, so fall back to the
        # regex-based dispatcher, which still works with any provider.
        # (The regex path doesn't use history — it's not doing free-form
        # LLM reasoning that benefits from context the way Gemini does.)
        # SIGNAGE (Phase B): log the regex ring-road path.
        logger.info("[chat] routing via regex ring-road (no Gemini key): %r", req.message[:60])
        reply = await _regex_route_message(req.message)
    return ChatResponse(response=reply)


@app.post("/chat/stream")
async def chat_stream(req: ChatRequest):
    """
    Server-Sent Events version of /chat — streams each step of a
    multi-step tool-calling turn as it happens (status updates, which
    tool is running, whether it succeeded, then the final reply) instead
    of returning only the finished text. Powers the live "thinking"
    trace in the frontend.

    Purely additive: /chat (above) is completely unchanged and still
    works exactly as before for any client that doesn't need streaming.
    Falls back to the same regex-based router as /chat when no Gemini
    key is configured — that path has no multi-step tool loop to stream,
    so it's wrapped as a single "final" event rather than duplicating
    its logic here.
    """
    import os
    import json as _json

    async def event_generator():
        try:
            if os.getenv("GEMINI_API_KEY"):
                # SIGNAGE (Phase B): same fork logging as /chat.
                logger.info("[chat/stream] streaming via Gemini tool-calling: %r", req.message[:60])
                async for event in tool_router.route_message_streaming(req.message, req.history):
                    yield f"data: {_json.dumps(event)}\n\n"
            else:
                logger.info("[chat/stream] no Gemini key — single final event via regex ring-road")
                reply = await _regex_route_message(req.message)
                yield f"data: {_json.dumps({'type': 'final', 'text': reply})}\n\n"
        except Exception as exc:
            logger.exception("chat_stream failed")
            yield f"data: {_json.dumps({'type': 'error', 'text': str(exc)[:300]})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering if ever proxied
        },
    )


@app.get("/status")
async def status():
    """Live system status — missions, evidence count, auth window."""
    try:
        from aresx.mission import list_missions
        from aresx.enterprise import list_evidence

        missions = list_missions()
        evidence = list_evidence(limit=500)

        return {
            "online": True,
            "boot": boot_result,
            "active_missions": len(missions),
            "missions": missions[:10],
            "evidence_count": len(evidence),
        }
    except Exception as exc:
        return {"online": True, "error": str(exc)}


def _open_browser_delayed():
    time.sleep(1.2)
    try:
        webbrowser.open("http://localhost:8000")
    except Exception:
        pass


if __name__ == "__main__":
    import uvicorn

    threading.Thread(target=_open_browser_delayed, daemon=True).start()
    logger.info("Starting ARES X v12 server on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")

