"""
ARES X v9 — API Key Setup
Handles first-run key collection: where keys are stored, how they're
validated against the real provider APIs before being accepted, and
how they get loaded into the process environment so the rest of ARES
(aresx.sovereign_ai) picks them up transparently.

Storage location follows the same convention as the native installer
(packaging/install.sh) — ~/.config/ares-x/env — so a key entered
through the setup screen and a key edited by hand in that file are
the exact same source of truth, never two divergent copies.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

logger = logging.getLogger("ares_keys")

CONFIG_DIR = Path.home() / ".config" / "ares-x"
ENV_FILE = CONFIG_DIR / "env"

_KNOWN_KEYS = ("GEMINI_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "HF_TOKEN")

# Reject obviously-wrong pastes (empty, whitespace, or someone pasting
# the literal placeholder text) before ever spending an HTTP call on them.
_KEY_SHAPE = re.compile(r"^\S{10,}$")


def _read_env_file() -> dict[str, str]:
    """Parse the KEY=value env file. Missing file → empty dict, not an error."""
    values: dict[str, str] = {}
    if not ENV_FILE.exists():
        return values
    try:
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            values[k.strip()] = v.strip()
    except OSError as exc:
        logger.warning("Could not read %s: %s", ENV_FILE, exc)
    return values


def _write_env_file(values: dict[str, str]) -> None:
    """
    Write the env file, preserving any keys not being updated right now
    (e.g. saving GEMINI_API_KEY shouldn't blank out an existing GROQ_API_KEY).
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    existing = _read_env_file()
    existing.update({k: v for k, v in values.items() if v})  # never write empty over a real value

    lines = ["# ARES X v9 — API keys (written by setup screen / packaging/install.sh)"]
    for key in _KNOWN_KEYS:
        lines.append(f"{key}={existing.get(key, '')}")
    ENV_FILE.write_text("\n".join(lines) + "\n")
    try:
        ENV_FILE.chmod(0o600)  # keys are secrets — not world-readable
    except OSError:
        pass


def load_keys_into_environment() -> dict[str, bool]:
    """
    Load any saved keys from ~/.config/ares-x/env into os.environ, so
    aresx.sovereign_ai's normal os.getenv() lookups pick them up with
    zero changes needed there. Call this once at server startup, before
    any inference call happens.

    Returns which of the known keys are present after loading (from file
    or already in the environment from a manual `export`).
    """
    file_values = _read_env_file()
    for key, value in file_values.items():
        if value and not os.environ.get(key):
            os.environ[key] = value

    return {key: bool(os.environ.get(key)) for key in _KNOWN_KEYS}


def has_any_key() -> bool:
    """Whether at least one provider key is configured — the gate for
    whether the first-run setup screen should show."""
    return any(os.environ.get(k) for k in ("GEMINI_API_KEY", "GROQ_API_KEY"))


async def validate_gemini_key(key: str) -> tuple[bool, str]:
    """Live-check a Gemini key against the real API — a cheap, free-tier
    call that fails fast on a bad key instead of only failing later
    mid-conversation."""
    if not _KEY_SHAPE.match(key):
        return False, "That doesn't look like a real key — check for extra spaces or a partial paste."
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                params={"key": key},
            )
            if r.status_code == 200:
                return True, "Gemini key verified."
            if r.status_code in (400, 401, 403):
                return False, "Gemini rejected this key — double-check it was copied fully."
            return False, f"Gemini API returned unexpected status {r.status_code} — try again."
    except Exception as exc:
        return False, f"Couldn't reach Gemini to verify ({exc}) — check your internet connection."


async def validate_groq_key(key: str) -> tuple[bool, str]:
    """Live-check a Groq key against the real API."""
    if not _KEY_SHAPE.match(key):
        return False, "That doesn't look like a real key — check for extra spaces or a partial paste."
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
            if r.status_code == 200:
                return True, "Groq key verified."
            if r.status_code in (400, 401, 403):
                return False, "Groq rejected this key — double-check it was copied fully."
            return False, f"Groq API returned unexpected status {r.status_code} — try again."
    except Exception as exc:
        return False, f"Couldn't reach Groq to verify ({exc}) — check your internet connection."


async def validate_openrouter_key(key: str) -> tuple[bool, str]:
    """
    Live-check an OpenRouter key against the real API.
    A key with zero credits still works fine for ":free"-suffixed
    models — OpenRouter's free tier requires a real account key, it's
    just free to create (no card) and free to use on :free models.
    """
    if not _KEY_SHAPE.match(key):
        return False, "That doesn't look like a real key — check for extra spaces or a partial paste."
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                "https://openrouter.ai/api/v1/auth/key",
                headers={"Authorization": f"Bearer {key}"},
            )
            if r.status_code == 200:
                return True, "OpenRouter key verified."
            if r.status_code in (400, 401, 403):
                return False, "OpenRouter rejected this key — double-check it was copied fully."
            return False, f"OpenRouter API returned unexpected status {r.status_code} — try again."
    except Exception as exc:
        return False, f"Couldn't reach OpenRouter to verify ({exc}) — check your internet connection."


async def save_key(provider: str, key: str, skip_validation: bool = False) -> tuple[bool, str]:
    """
    Validate (unless explicitly skipped) and persist a single key.
    provider: "gemini" | "groq" | "openrouter" | "hf"
    """
    provider = provider.lower().strip()
    env_key_map = {
        "gemini": "GEMINI_API_KEY",
        "groq": "GROQ_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "hf": "HF_TOKEN",
    }
    if provider not in env_key_map:
        return False, f"Unknown provider '{provider}'."

    key = key.strip()
    if not key:
        return False, "No key provided."

    if not skip_validation:
        if provider == "gemini":
            ok, msg = await validate_gemini_key(key)
        elif provider == "groq":
            ok, msg = await validate_groq_key(key)
        elif provider == "openrouter":
            ok, msg = await validate_openrouter_key(key)
        else:
            ok, msg = True, "Saved (HuggingFace tokens aren't live-checked)."
        if not ok:
            return False, msg
    else:
        msg = "Saved without validation."

    env_key = env_key_map[provider]
    _write_env_file({env_key: key})
    os.environ[env_key] = key
    logger.info("%s saved and loaded into environment.", env_key)
    return True, msg
