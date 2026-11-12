"""
ARES X v10 — Core Runtime (compat facade)
============================================

The v9 ``aresx/core.py`` was a 1,596-line god file mixing paths, config,
IPC tokens, logging, the async loop, HTTP, SQLite memory, screenshots,
LLM backends, speech, and the Qt orb. In v10 it is split into focused
modules under ``aresx.core.*``. This ``__init__.py`` remains a thin
compatibility facade: it re-exports every symbol the v9 codebase imported
from ``aresx.core``, so ``aresx/router.py``, ``aresx/healer.py``,
``aresx/agents/brain.py``, ``aresx/wizard.py``, ``aresx/modules/*``, and
``aresx/autonomy/commander.py`` keep working with zero edits.

New code should import from the focused modules directly:

    from aresx.core.paths import BASE_DIR, cfg, generate_ipc_token
    from aresx.core.loop import get_loop, run_async
    from aresx.core.llm import ask_ai
    from aresx.core.memory import mike
"""
from __future__ import annotations

from aresx.core.paths import (
    BASE_DIR, CONFIG_FILE, MEMORY_DB, NOTES_FILE, ARCHIVE_DIR,
    DEFAULT_CONFIG, cfg, load_config, save_config, is_quiet_hours,
    _IPC_SECRET, generate_ipc_token, validate_ipc_token,
    _log, log,
    get_loop, run_async,
    _get_http, _async_post, _async_get, is_online_async, is_online,
)
from aresx.core.memory import mike
from aresx.core.screen import screenshot_b64, screenshot_save
from aresx.core.llm import (
    ask_ai_async, ask_vision_async, ask_ai_code_async,
    ask_ai, ask_vision, ask_ai_code,
)
from aresx.core.audio import speak, listen
from aresx.core.orb import orb, ORB_W, ORB_H
from aresx.core.confirm import show, done, err, needs_confirm, ask_confirm

__all__ = [
    "BASE_DIR", "CONFIG_FILE", "MEMORY_DB", "NOTES_FILE", "ARCHIVE_DIR",
    "DEFAULT_CONFIG", "cfg", "load_config", "save_config", "is_quiet_hours",
    "_IPC_SECRET", "generate_ipc_token", "validate_ipc_token",
    "_log", "log", "get_loop", "run_async",
    "_get_http", "_async_post", "_async_get", "is_online_async", "is_online",
    "mike", "screenshot_b64", "screenshot_save",
    "ask_ai_async", "ask_vision_async", "ask_ai_code_async",
    "ask_ai", "ask_vision", "ask_ai_code",
    "speak", "listen", "orb", "ORB_W", "ORB_H",
    "show", "done", "err", "needs_confirm", "ask_confirm",
]
