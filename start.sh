#!/bin/bash
# ARES X v8 TITAN — one-command launcher
set -e

echo "═══════════════════════════════════════"
echo "  ARES X v8 TITAN — Starting"
echo "═══════════════════════════════════════"

# Check env vars
if [ -z "$GEMINI_API_KEY" ]; then
    echo "⚠  GEMINI_API_KEY not set — ARES will fall back to Groq/Ollama."
    echo "   Get a free key at https://aistudio.google.com"
fi
if [ -z "$GROQ_API_KEY" ]; then
    echo "⚠  GROQ_API_KEY not set — ARES will fall back to Ollama/OpenRouter."
    echo "   Get a free key at https://console.groq.com"
fi

# Install only what's missing
python3 - <<'PYCHECK'
import importlib, subprocess, sys
required = ["fastapi", "uvicorn", "httpx", "aiosqlite", "networkx", "pydantic"]
missing = []
for pkg in required:
    try:
        importlib.import_module(pkg)
    except ImportError:
        missing.append(pkg)
if missing:
    print(f"Installing missing packages: {', '.join(missing)}")
    subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", "-q", *missing])
else:
    print("All dependencies present.")
PYCHECK

echo ""
echo "Launching ARES on http://localhost:8000 ..."
echo "═══════════════════════════════════════"
python3 ares_server.py
