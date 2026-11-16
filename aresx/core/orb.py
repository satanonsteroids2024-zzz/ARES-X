"""
ARES X v10 — Orb overlay (split from core.py)
=============================================
Split out of the v9 core.py god-file into a focused module.

All original public symbols are re-exported by aresx.core (the
compat facade) so existing importers keep working unmodified.
"""
from __future__ import annotations

try:
    from PySide6.QtWidgets import QApplication, QWidget, QLabel
    from PySide6.QtCore import (Qt, QTimer, Signal, QObject, QPoint,
                                 QPropertyAnimation, QEasingCurve)
    from PySide6.QtGui import QPainter, QColor, QRadialGradient, QPen, QFont, QBrush
    _QT = True
except ImportError:
    _QT = False

from aresx.core.paths import cfg, log, is_quiet_hours, save_config
from aresx.core.audio import speak

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
# ORB — PySide6 hardware-accelerated overlay (or PIL fallback)
# ══════════════════════════════════════════════════════════════
ORB_W = 140
ORB_H = 140


if _QT:
    class _OrbSignals(QObject):
        state_changed = Signal(str, str)  # (mode, text)

    class _QtOrb(QWidget):
        """Hardware-accelerated orb overlay using PySide6 QPainter."""

        COLORS = {
            "idle":       ("#00ff41", 0.35),
            "listening":  ("#00ffff", 0.90),
            "thinking":   ("#bd00ff", 0.90),
            "speaking":   ("#ffaa00", 0.90),
            "confirming": ("#ff3333", 0.90),
            "done":       ("#00ff41", 0.90),
            "error":      ("#ff3333", 0.90),
            "healing":    ("#ff00ff", 0.90),
        }
        LABELS = {
            "idle": "", "listening": "REC", "thinking": "...",
            "speaking": "~", "confirming": "?", "done": "OK",
            "error": "X", "healing": "FIX",
        }

        def __init__(self) -> None:
            super().__init__(
                flags=Qt.WindowType.FramelessWindowHint |
                      Qt.WindowType.WindowStaysOnTopHint |
                      Qt.WindowType.Tool,
            )
            self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground)
            self._mode = "idle"
            self._text = ""
            self._t = 0.0
            self._dx = self._dy = 0

            # Position
            try:
                ox = cfg["orb_position"][0]
                oy = cfg["orb_position"][1]
            except (TypeError, IndexError, KeyError):
                ox = oy = None
            screen = QApplication.primaryScreen().geometry()
            ox = int(ox) if ox is not None else screen.width()  - ORB_W - 20
            oy = int(oy) if oy is not None else screen.height() - ORB_H - 60
            self.setGeometry(ox, oy, ORB_W, ORB_H + 28)
            self.show()

            # Signals for thread-safe updates
            self._signals = _OrbSignals()
            self._signals.state_changed.connect(self._on_state_changed)

            # Animation timer (50ms = 20fps)
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._tick)
            self._timer.start(50)

        def _on_state_changed(self, mode: str, text: str) -> None:
            self._mode = mode
            self._text = text
            self.update()

        def _tick(self) -> None:
            self._t += 0.1
            self.update()

        def paintEvent(self, event) -> None:
            p = QPainter(self)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
            p.fillRect(self.rect(), QColor(0, 0, 0, 0))

            hex_c, alpha = self.COLORS.get(self._mode, ("#00ff41", 0.35))
            self.setWindowOpacity(alpha)

            cx = ORB_W // 2
            cy = ORB_H // 2
            r  = ORB_W // 2 - 10
            pulse = math.sin(self._t * 2) * (5 if self._mode != "idle" else 1)
            pr = int(r + pulse)

            c = QColor(hex_c)

            # Glow rings
            for i in range(3):
                gr = pr + i * 8
                glow = QColor(c.red(), c.green(), c.blue(), 25)
                p.setPen(QPen(glow, 1))
                p.drawEllipse(cx - gr, cy - gr, gr * 2, gr * 2)

            # Body
            p.setBrush(QBrush(QColor(5, 5, 5)))
            pen_width = 1 if self._mode == "idle" else 2
            p.setPen(QPen(c, pen_width))
            p.drawEllipse(cx - pr, cy - pr, pr * 2, pr * 2)

            # Inner ring
            ir = int(pr * 0.6)
            inner_c = QColor(c.red(), c.green(), c.blue(), 68)
            p.setPen(QPen(inner_c, 3))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(cx - ir, cy - ir, ir * 2, ir * 2)

            # Core
            cr = int(pr * (0.15 if self._mode == "idle" else 0.28))
            p.setBrush(QBrush(c))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(cx - cr, cy - cr, cr * 2, cr * 2)

            # Rotating arcs
            if self._mode in ("listening", "thinking", "confirming", "healing"):
                ar = pr + 14
                off = int((self._t * 55) % 360) * 16
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(c, 2))
                p.drawArc(cx - ar, cy - ar, ar * 2, ar * 2, off, 75 * 16)
                p.drawArc(cx - ar, cy - ar, ar * 2, ar * 2, off + 180 * 16, 75 * 16)

            # Label
            lbl = self.LABELS.get(self._mode, "")
            if lbl:
                font = QFont("Consolas", 9 if len(lbl) > 2 else 11)
                font.setBold(True)
                p.setFont(font)
                p.setPen(c)
                p.drawText(0, 0, ORB_W, ORB_H, Qt.AlignmentFlag.AlignCenter, lbl)

            # Status text below
            if self._text and self._mode != "idle":
                font2 = QFont("Consolas", 7)
                p.setFont(font2)
                p.setPen(c)
                disp = self._text[:40]
                p.drawText(0, ORB_H, ORB_W, 28, Qt.AlignmentFlag.AlignCenter, disp)

        def mousePressEvent(self, e) -> None:
            self._dx = e.globalPosition().toPoint().x() - self.x()
            self._dy = e.globalPosition().toPoint().y() - self.y()

        def mouseMoveEvent(self, e) -> None:
            self.move(e.globalPosition().toPoint() - QPoint(self._dx, self._dy))

        def mouseReleaseEvent(self, e) -> None:
            cfg["orb_position"] = [self.x(), self.y()]
            save_config(cfg)

    class Orb:
        """Thread-safe PySide6 orb wrapper."""

        def __init__(self) -> None:
            self._widget: Optional[_QtOrb] = None
            self.mode = "idle"
            self.text = ""
            self._built = False

        def build(self) -> None:
            if not QApplication.instance():
                self._app = QApplication(sys.argv)
            self._widget = _QtOrb()
            self._built = True

        def set(self, mode: Optional[str] = None, text: Optional[str] = None) -> None:
            if mode is not None:
                self.mode = mode
            if text is not None:
                self.text = text
            if self._built and self._widget:
                # Thread-safe: emit signal
                self._widget._signals.state_changed.emit(
                    self.mode, self.text
                )

        def do(self, fn) -> None:
            if self._built and self._widget:
                try:
                    fn()
                except Exception:
                    pass

        def run(self) -> None:
            self.build()
            if self._widget:
                self._widget._app.exec() if hasattr(self, "_app") else QApplication.exec()

else:
    # ── Tkinter fallback when PySide6 not installed ──
    try:
            import tkinter as tk
            from PIL import Image, ImageDraw, ImageTk  # type: ignore

            class Orb:  # type: ignore
                """PIL double-buffered Tkinter Orb (fallback if PySide6 unavailable)."""
                COLORS = {
                    "idle":       ("#00ff41", 0.35), "listening": ("#00ffff", 0.90),
                    "thinking":   ("#bd00ff", 0.90), "speaking":  ("#ffaa00", 0.90),
                    "confirming": ("#ff3333", 0.90), "done":      ("#00ff41", 0.90),
                    "error":      ("#ff3333", 0.90), "healing":   ("#ff00ff", 0.90),
                }
                LABELS = {
                    "idle": "", "listening": "REC", "thinking": "...",
                    "speaking": "~", "confirming": "?", "done": "OK",
                    "error": "X", "healing": "FIX",
                }

                def __init__(self) -> None:
                    self.root = self.canvas = self.lbl = self._photo = None
                    self.mode = "idle"; self.text = ""; self._t = 0.0
                    self._dx = self._dy = 0; self._built = False

                def build(self) -> None:
                    self.root = tk.Tk()
                    self.root.title("")
                    self.root.overrideredirect(True)
                    self.root.wm_attributes("-topmost", True)
                    try:
                        self.root.wm_attributes("-transparentcolor", "#010101")
                    except tk.TclError:
                        pass
                    self.root.configure(bg="#010101")
                    sw = self.root.winfo_screenwidth()
                    sh = self.root.winfo_screenheight()
                    try:
                        ox = cfg["orb_position"][0] or sw - ORB_W - 20
                        oy = cfg["orb_position"][1] or sh - ORB_H - 60
                    except (TypeError, IndexError, KeyError):
                        ox, oy = sw - ORB_W - 20, sh - ORB_H - 60
                    self.root.geometry(f"{ORB_W}x{ORB_H + 28}+{int(ox)}+{int(oy)}")
                    self.canvas = tk.Canvas(self.root, width=ORB_W, height=ORB_H,
                                            bg="#010101", highlightthickness=0)
                    self.canvas.pack()
                    self.lbl = tk.Label(self.root, text="", font=("Consolas", 7),
                                        fg="#00ff41", bg="#010101",
                                        wraplength=ORB_W - 4, justify="center")
                    self.lbl.pack(fill="x")
                    self.canvas.bind("<ButtonPress-1>", self._ds)
                    self.canvas.bind("<B1-Motion>", self._dm)
                    self.canvas.bind("<ButtonRelease-1>", self._dr)
                    self._built = True
                    self._draw()

                def _ds(self, e) -> None:
                    try:
                        self._dx, self._dy = (e.x_root - self.root.winfo_x(),
                                              e.y_root - self.root.winfo_y())
                    except tk.TclError:
                        pass

                def _dm(self, e) -> None:
                    try:
                        self.root.geometry(f"+{e.x_root - self._dx}+{e.y_root - self._dy}")
                    except tk.TclError:
                        pass

                def _dr(self, e) -> None:
                    try:
                        cfg["orb_position"] = [self.root.winfo_x(), self.root.winfo_y()]
                        save_config(cfg)
                    except (tk.TclError, KeyError):
                        pass

                def _draw(self) -> None:
                    if not self.canvas:
                        return
                    try:
                        self._t += 0.1
                        c_hex, alpha = self.COLORS.get(self.mode, ("#00ff41", 0.4))
                        try:
                            self.root.wm_attributes("-alpha", alpha)
                        except tk.TclError:
                            pass
                        img = Image.new("RGBA", (ORB_W, ORB_H), (1, 1, 1, 255))
                        draw = ImageDraw.Draw(img)
                        cx = cy = ORB_W // 2
                        r = ORB_W // 2 - 10
                        pulse = math.sin(self._t * 2) * (5 if self.mode != "idle" else 1)
                        pr = int(r + pulse)
                        for i in range(3):
                            gr = pr + i * 8
                            draw.ellipse([cx - gr, cy - gr, cx + gr, cy + gr],
                                         outline=c_hex + "33", width=1)
                        draw.ellipse([cx - pr, cy - pr, cx + pr, cy + pr],
                                     fill="#050505", outline=c_hex,
                                     width=(1 if self.mode == "idle" else 2))
                        ir = int(pr * 0.6)
                        draw.ellipse([cx - ir, cy - ir, cx + ir, cy + ir],
                                     outline=c_hex + "44", width=3)
                        cr = int(pr * (0.15 if self.mode == "idle" else 0.28))
                        draw.ellipse([cx - cr, cy - cr, cx + cr, cy + cr], fill=c_hex)
                        if self.mode in ("listening", "thinking", "confirming", "healing"):
                            ar = pr + 14
                            off = int((self._t * 55) % 360)
                            draw.arc([cx - ar, cy - ar, cx + ar, cy + ar], off, off + 75,
                                     fill=c_hex, width=2)
                            draw.arc([cx - ar, cy - ar, cx + ar, cy + ar],
                                     off + 180, off + 255, fill=c_hex, width=2)
                        self._photo = ImageTk.PhotoImage(img)
                        self.canvas.delete("all")
                        self.canvas.create_image(0, 0, anchor="nw", image=self._photo)
                        lbl = self.LABELS.get(self.mode, "")
                        if lbl:
                            self.canvas.create_text(cx, cy, text=lbl, fill=c_hex,
                                                    font=("Consolas", 9 if len(lbl) > 2 else 11, "bold"))
                        if self.lbl:
                            self.lbl.config(
                                text=self.text[:40] if self.mode != "idle" else "",
                                fg=c_hex,
                            )
                        self.root.after(50, self._draw)
                    except tk.TclError:
                        return

                def set(self, mode: Optional[str] = None, text: Optional[str] = None) -> None:
                    if mode is not None:
                        self.mode = mode
                    if text is not None:
                        self.text = text

                def do(self, fn) -> None:
                    if self.root and self._built:
                        try:
                            self.root.after(0, fn)
                        except tk.TclError:
                            pass

                def run(self) -> None:
                    self.build()
                    self.root.mainloop()


    except ImportError:
        _TK_ORB = False
        class Orb:  # type: ignore
            COLORS = {"idle": ("#00ff41", 0.35)}
            LABELS = {"idle": ""}
            def __init__(self, *a, **kw): pass
            def set(self, mode="idle", text=""): pass
            def do(self, fn): pass
            def show(self): pass
            def hide(self): pass
            def destroy(self): pass
orb = Orb()
