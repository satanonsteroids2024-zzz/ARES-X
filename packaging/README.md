# ARES X v9 — Kali / XFCE Native Install

Two ways to run ARES on Kali. Same backend either way — pick based on
what you want.

---

## Option A — Quick, temporary (what `start.sh` already did)

```bash
cd ares_x_v9
./start.sh
```

Opens ARES in your default browser at `localhost:8000`. No install,
nothing added to your system, good for testing.

---

## Option B — Native install (this update)

Installs ARES as a real desktop application: shows up in the XFCE
Applications menu, opens in its own window (not a browser tab), and
can optionally run as a background service that starts on login.

```bash
cd ares_x_v9
chmod +x packaging/install.sh
./packaging/install.sh
```

This does four things:
1. Installs the GTK webview system packages (`gir1.2-webkit2-4.1`,
   `python3-gi`) if missing — this is what lets `pywebview` open a
   real native window on XFCE instead of needing a browser.
2. Copies ARES to `~/.local/share/ares-x` (standard Linux app location,
   not wherever you happened to unzip it).
3. Registers `~/.local/share/applications/ares-x.desktop` — ARES now
   appears in your Applications menu under Network/Security.
4. Installs (but doesn't start) a systemd user service, so you can
   run the backend in the background if you want to.

After installing:

```bash
# launch as a native window — from the Applications menu, or:
ares-x
```

On first launch, ARES shows a setup screen right in the chat window
asking for your API key — paste it in, ARES validates it live against
the real provider before accepting it, and you're done. No config
files to find or edit. It only asks once; the key is remembered for
every future launch.

(If you'd rather set it up by hand instead — e.g. scripting an
install — you can still edit `~/.config/ares-x/env` directly. Both
paths write to the exact same file, so they never conflict.)

### Running as a background service instead

If you'd rather have ARES always running (so the chat is instantly
ready, or so you can hit it from a script/curl) rather than opening
a window each time:

```bash
systemctl --user enable --now ares-x   # start now + on every login
systemctl --user status ares-x         # confirm it's running
journalctl --user -u ares-x -f         # live logs
systemctl --user stop ares-x           # stop it
```

In this mode the same UI is available at `http://localhost:8000` in
any browser. You can still launch `ares-x` for a native window at the
same time — it'll just talk to whichever backend is already running,
or start its own if none is up. They don't conflict.

---

## What's actually different from `start.sh`

Nothing about the backend. `ares_native.py` imports the exact same
`app` object from `ares_server.py` — it does not duplicate any logic.
The only difference is presentation: a real GTK window with its own
icon and taskbar entry, instead of "open Firefox to a URL."

## Uninstalling

```bash
systemctl --user disable --now ares-x 2>/dev/null
rm -rf ~/.local/share/ares-x
rm -f ~/.local/share/applications/ares-x.desktop
rm -f ~/.local/share/icons/hicolor/128x128/apps/ares-x.png
rm -f ~/.local/bin/ares-x
rm -f ~/.config/systemd/user/ares-x.service
systemctl --user daemon-reload
# ~/.config/ares-x/env (your API keys) is left in place — remove
# manually with `rm -rf ~/.config/ares-x` if you want it gone too.
```
