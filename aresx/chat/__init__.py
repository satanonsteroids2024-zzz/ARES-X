"""
ARES X v10 — Chat Router
=========================
Single chat dispatcher. Gemini free-form routing (canonical) plus the
regex fallback used when no Gemini key is available.

    from aresx.chat.router import route_message, _regex_route_message
    from aresx.chat import route_message
"""
from __future__ import annotations

from aresx.chat.router import (
    route_message,
    route_message_streaming,
    _regex_route_message,
)

__all__ = ["route_message", "route_message_streaming", "_regex_route_message"]
