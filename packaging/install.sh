#!/bin/bash
# ARES X v12 — Kali/XFCE native installer
# Installs ARES as a real desktop application: menu entry, native window,
# and an optional background systemd service — not "cd and run a script."
set -e

INSTALL_DIR="$HOME/.local/share/ares-x"
CONFIG_DIR="$HOME/.config/ares-x"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/128x128/apps"
SYSTEMD_DIR="$HOME/.config/systemd/user"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "═══════════════════════════════════════════════════"
echo "  ARES X v12 — Kali/XFCE Native Install"
echo "═══════════════════════════════════════════════════"

# ── 1. System dependencies (GTK webview backend + X11 automation) ────────
echo ""
echo "[1/6] Checking system packages (GTK webview + desktop automation)..."
MISSING_APT=()
dpkg -s gir1.2-webkit2-4.1 >/dev/null 2>&1 || MISSING_APT+=("gir1.2-webkit2-4.1")
dpkg -s python3-gi >/dev/null 2>&1 || MISSING_APT+=("python3-gi")
dpkg -s python3-gi-cairo >/dev/null 2>&1 || MISSING_APT+=("python3-gi-cairo")
dpkg -s python3-xlib >/dev/null 2>&1 || MISSING_APT+=("python3-xlib")

if [ ${#MISSING_APT[@]} -gt 0 ]; then
    echo "  Installing: ${MISSING_APT[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y "${MISSING_APT[@]}"
else
    echo "  ✓ All system packages already present"
fi

# ── 2. Python dependencies ────────────────────────────────────────────────
echo ""
echo "[2/6] Checking Python packages..."
python3 - <<'PYCHECK'
import importlib, subprocess, sys
required = ["fastapi", "uvicorn", "httpx", "aiosqlite", "networkx", "pydantic", "webview", "pyautogui"]
pip_names = {"webview": "pywebview"}   # import name != pip package name
missing = []
for pkg in required:
    try:
        importlib.import_module(pkg)
    except ImportError:
        missing.append(pip_names.get(pkg, pkg))
if missing:
    print(f"  Installing: {', '.join(missing)}")
    subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", "-q", *missing])
else:
    print("  ✓ All Python packages already present")
PYCHECK

# ── 3. Install to proper FHS location ─────────────────────────────────────
echo ""
echo "[3/6] Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
      --exclude='*.db' --exclude='*.kuzu' \
      "$SRC_DIR"/ "$INSTALL_DIR"/
echo "  ✓ Application files installed"

# ── 4. Config directory + env template ────────────────────────────────────
echo ""
echo "[4/6] Setting up config at $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/env" ]; then
    cp "$SRC_DIR/packaging/env.template" "$CONFIG_DIR/env"
    echo "  ✓ Created $CONFIG_DIR/env — add your GEMINI_API_KEY / GROQ_API_KEY there"
else
    echo "  ✓ Existing $CONFIG_DIR/env preserved (not overwritten)"
fi

# ── 5. Desktop menu entry + icon ──────────────────────────────────────────
echo ""
echo "[5/6] Registering application menu entry..."
mkdir -p "$DESKTOP_DIR" "$ICON_DIR" "$BIN_DIR"
cp "$SRC_DIR/packaging/ares-x.png" "$ICON_DIR/ares-x.png"

cat > "$BIN_DIR/ares-x" <<EOF
#!/bin/bash
set -a
[ -f "$CONFIG_DIR/env" ] && source "$CONFIG_DIR/env"
set +a
exec python3 "$INSTALL_DIR/ares_native.py"
EOF
chmod +x "$BIN_DIR/ares-x"

sed "s|Icon=ares-x|Icon=$ICON_DIR/ares-x.png|" "$SRC_DIR/packaging/ares-x.desktop" \
    > "$DESKTOP_DIR/ares-x.desktop"
chmod +x "$DESKTOP_DIR/ares-x.desktop"

update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" 2>/dev/null || true

echo "  ✓ ARES X now in your XFCE Applications menu (Network/Security category)"

# ── 6. Optional systemd background service ────────────────────────────────
echo ""
echo "[6/6] Installing systemd user service (background mode, optional)..."
mkdir -p "$SYSTEMD_DIR"
cp "$SRC_DIR/packaging/ares-x.service" "$SYSTEMD_DIR/ares-x.service"
systemctl --user daemon-reload
echo "  ✓ Service installed (not started — see commands below)"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Install complete."
echo "═══════════════════════════════════════════════════"
echo ""
echo "  1. Add your free API keys:"
echo "       nano $CONFIG_DIR/env"
echo ""
echo "  2. Launch as a native window (from Applications menu, or):"
echo "       ares-x"
echo ""
echo "  3. OR run as a background service instead:"
echo "       systemctl --user start ares-x      # start now"
echo "       systemctl --user enable ares-x     # auto-start on login"
echo "       systemctl --user status ares-x     # check it's running"
echo "       journalctl --user -u ares-x -f     # live logs"
echo ""
echo "     (background mode serves the same UI at http://localhost:8000"
echo "      — open it in a browser, or run 'ares-x' separately for the"
echo "      native window while the service runs the backend)"
echo "═══════════════════════════════════════════════════"
