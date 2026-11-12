"""
ARES X v9 — ROE & Authorization
Single source of truth for everything related to Rules of Engagement
and time-boxed authorization windows. Previously this logic lived
inside RedOrchestrator directly (aresx/red/orchestrator.py); it's
pulled out here so authorization state and mission execution are two
separate concerns, and so any other module that needs to check/open/
manage authorization does it through one place instead of duplicating
the logic (which had already happened once — see AuthorizationManager
below and tool_router.py's history for the bug that caused).

Authorization model: an operator (red teamer, cyber police, etc.) opens
an authorization window with an explicit start/end time and a case
label before a scan run. While that window is active, missions run
fully unattended — no per-target prompts, suitable for chasing
thousands of IPs/domains during an authorized operation. Outside any
active window, every target falls back to a live y/n prompt (for
network-facing tools; see orchestrator.py for which tools actually
route through this). Nothing runs unattended by default — the window
has to be opened on purpose, and it always expires on its own.

Desktop automation (aresx/desktop_automation.py) intentionally does
NOT use this system — screen/mouse/keyboard control runs directly on
request. This module is specifically for network-facing red team
operations (recon, scans) where a declared, time-boxed scope makes
sense the way it doesn't for "take a screenshot."
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("ares_roe")


class PendingApproval(Exception):
    """
    Raised by AuthorizationManager.authorize() instead of blocking, when
    the manager is in chat-confirm mode (see AuthorizationManager.mode)
    and a live decision is needed but there's no synchronous prompt to
    block on — a chat interface can't pause mid-HTTP-request waiting for
    terminal input the way a CLI script can.

    Carries everything needed to show the user the question in chat and
    resume the exact same action once they reply. The caller (see
    aresx.red.orchestrator.RedOrchestrator.start_mission) should catch
    this, surface request.prompt_text to the user, and — once a later
    message answers it — call AuthorizationManager.resolve_pending() and
    retry.
    """
    def __init__(self, request: "PendingAuthRequest"):
        self.request = request
        super().__init__(request.prompt_text)


@dataclass
class PendingAuthRequest:
    """One outstanding chat-based authorization question."""
    request_id: str
    action_label: str
    target: Dict
    target_label: str
    prompt_text: str
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "action_label": self.action_label,
            "target": self.target,
            "target_label": self.target_label,
            "prompt_text": self.prompt_text,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class AuthWindow:
    """A time-boxed, fully-autonomous authorization for a scan operation."""
    case_id: str
    authorized_by: str
    opened_at: datetime
    expires_at: datetime
    reason: str = ""

    def is_active(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now()
        return self.opened_at <= now < self.expires_at

    def to_dict(self) -> Dict:
        return {
            "case_id": self.case_id,
            "authorized_by": self.authorized_by,
            "opened_at": self.opened_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "reason": self.reason,
        }


def load_roe(config_path: str = "config/roe.json") -> Dict:
    """
    Load the optional pre-approved target list from disk. If the file
    doesn't exist, that's fine — it just means every target will
    prompt live instead of auto-passing. This is not a hard
    requirement — see AuthorizationManager.is_pre_approved.
    """
    try:
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                return json.load(f)
    except Exception as exc:
        logger.debug("Could not load ROE config from %s: %s", config_path, exc)
    return {"allowed_domains": [], "allowed_ip_ranges": []}


def default_confirm(message: str) -> bool:
    """Real terminal y/n prompt. Blocks until the user answers."""
    answer = input(f"{message} (y/n): ").strip().lower()
    return answer in ("y", "yes")


class AuthorizationManager:
    """
    Owns all ROE and authorization-window state for one ARES process.
    RedOrchestrator holds one instance of this and delegates every
    authorization decision to it — it does not duplicate any of this
    logic itself.

    Any other code that needs to check or manage authorization state
    (e.g. tool_router.py) should go through the same AuthorizationManager
    instance the active RedOrchestrator uses, not create a second one —
    a second instance has its own, disconnected state (this exact bug
    happened once already: a window opened via one instance was
    invisible to code checking a different instance). Use
    get_shared_authorization() below for that, in preference to
    constructing AuthorizationManager() directly.
    """

    def __init__(self, config_path: str = "config/roe.json",
                 confirm_fn: Optional[Callable[[str], bool]] = None,
                 mode: str = "blocking"):
        """
        Args:
            config_path: optional JSON file listing pre-approved domains/IPs
                that skip the live prompt entirely (e.g. your own sites you
                test constantly). Missing file just means everything prompts.
            confirm_fn: only used when mode="blocking". Function called
                with a prompt string, must return bool. Defaults to a
                real terminal input() y/n prompt. Ignored in "chat" mode.
            mode: "blocking" (default — the original CLI behavior: calls
                confirm_fn and waits synchronously for an answer) or
                "chat" (authorize() raises PendingApproval instead of
                blocking; the caller surfaces the question in a chat
                reply, and a later call to resolve_pending() — triggered
                by the user's next chat message — answers it). Use
                "chat" for anything driven by ares_server.py /
                tool_router.py, since an HTTP request handler can't
                block on terminal input the way a CLI script can.
        """
        self.roe_config: Dict = load_roe(config_path)
        self._session_approved: set = set()
        self._confirm_fn = confirm_fn or default_confirm
        self.mode = mode
        self._auth_window: Optional[AuthWindow] = None
        self._auth_window_history: List[AuthWindow] = []
        self._pending: Dict[str, PendingAuthRequest] = {}

    # ── Time-boxed authorization ────────────────────────────────────────

    def open_window(self, case_id: str, authorized_by: str,
                    duration_hours: float, reason: str = "") -> AuthWindow:
        """
        Open a fully-autonomous authorization window for `duration_hours`.
        While active, missions run with zero per-target prompts — intended
        for red team engagements or law-enforcement operations that need
        to chase hundreds/thousands of IPs without stopping for each one.

        The window is explicit and time-limited on purpose: it has to be
        opened deliberately, it records who opened it and why, and it
        expires automatically — it does not need to be manually closed,
        and there is no way to open one that never expires.
        """
        if duration_hours <= 0:
            raise ValueError("duration_hours must be positive")
        if duration_hours > 24 * 30:
            raise ValueError("duration_hours cannot exceed 30 days (720h) — "
                              "open a new window for longer operations")

        now = datetime.now()
        window = AuthWindow(
            case_id=case_id,
            authorized_by=authorized_by,
            opened_at=now,
            expires_at=now + timedelta(hours=duration_hours),
            reason=reason,
        )
        self._auth_window = window
        self._auth_window_history.append(window)
        logger.info("Authorization window opened: case=%s by=%s expires=%s",
                    case_id, authorized_by, window.expires_at.isoformat())
        return window

    def close_window(self) -> None:
        """Manually close the current window early (optional — it also expires on its own)."""
        self._auth_window = None

    def status(self) -> Dict:
        """Check whether a window is currently active and how much time is left."""
        if not self._auth_window:
            return {"active": False, "window": None}
        active = self._auth_window.is_active()
        remaining = (self._auth_window.expires_at - datetime.now()).total_seconds()
        return {
            "active": active,
            "window": self._auth_window.to_dict(),
            "seconds_remaining": max(0, remaining) if active else 0,
        }

    def window_covers(self, target: Dict) -> bool:
        """Whether the currently open (and unexpired) window authorizes this target."""
        return self._auth_window is not None and self._auth_window.is_active()

    @property
    def current_case_id(self) -> Optional[str]:
        """The case_id of the active window, if one is open and unexpired."""
        if self._auth_window and self._auth_window.is_active():
            return self._auth_window.case_id
        return None

    # ── Per-target authorization decision ────────────────────────────────

    def is_pre_approved(self, target: Dict, roe: Optional[Dict] = None) -> bool:
        """
        Check the optional pre-approved list — e.g. your own sites you
        test constantly, so they never interrupt you with a prompt.
        Anything not on this list falls through to the live y/n ask
        (unless an authorization window is open — see authorize()).
        """
        roe = roe if roe is not None else self.roe_config
        allowed_domains = roe.get("allowed_domains", [])
        allowed_ip_ranges = roe.get("allowed_ip_ranges", [])

        domain = target.get("domain", "")
        ip = target.get("ip", "")

        if domain and allowed_domains:
            if any(domain == d or domain.endswith("." + d) for d in allowed_domains):
                return True

        if ip and allowed_ip_ranges:
            try:
                target_ip = ipaddress.ip_address(ip)
                for cidr in allowed_ip_ranges:
                    if target_ip in ipaddress.ip_network(cidr, strict=False):
                        return True
            except ValueError:
                pass

        return False

    def authorize(self, action_label: str, target: Dict,
                  roe_override: Optional[Dict] = None) -> None:
        """
        Decide whether an action against `target` is authorized right now.

        Runs immediately, no prompt, if any of:
          - target is on the pre-approved list (config/roe.json)
          - target was already approved earlier this session
          - an authorization window is currently open and unexpired

        Otherwise:
          - mode="blocking" (default): calls confirm_fn and waits
            synchronously. Declining raises ValueError.
          - mode="chat": raises PendingApproval immediately, without
            calling anything or blocking. The caller is expected to
            surface request.prompt_text to the user and, once a later
            message answers it, call resolve_pending() and retry the
            original action — see aresx.red.orchestrator.start_mission
            for the actual retry loop.

        A ValueError from a decline (blocking mode) or an unresolved
        PendingApproval (chat mode, not yet retried) both mean the same
        thing to callers: the action did not run this time.
        """
        roe = roe_override if roe_override is not None else self.roe_config
        target_label = target.get("domain") or target.get("ip") or "unknown target"

        if self.window_covers(target):
            return
        if self.is_pre_approved(target, roe):
            return
        if target_label in self._session_approved:
            return

        prompt_text = f"Authorize {action_label} against {target_label}?"

        if self.mode == "chat":
            request = PendingAuthRequest(
                request_id=str(uuid.uuid4())[:8],
                action_label=action_label,
                target=target,
                target_label=target_label,
                prompt_text=prompt_text,
            )
            self._pending[request.request_id] = request
            raise PendingApproval(request)

        approved = self._confirm_fn(f"[ARES RED] {prompt_text}")
        if not approved:
            raise ValueError(
                f"{action_label} against {target_label} declined by operator. Blocked."
            )
        self._session_approved.add(target_label)

    def resolve_pending(self, request_id: str, approved: bool) -> PendingAuthRequest:
        """
        Answer a pending chat-based authorization question (see
        authorize()'s mode="chat" path). If approved, the target is
        remembered for the rest of the session, same as the blocking
        y/n path would — a subsequent retry of the same action will
        pass authorize() cleanly. Raises KeyError if request_id doesn't
        match anything pending (e.g. already resolved, or expired —
        see list_pending()/clear_stale_pending()).
        """
        request = self._pending.pop(request_id)
        if approved:
            self._session_approved.add(request.target_label)
        return request

    def list_pending(self) -> List[PendingAuthRequest]:
        """All currently unanswered chat-based authorization requests."""
        return list(self._pending.values())

    def get_pending(self, request_id: str) -> Optional[PendingAuthRequest]:
        return self._pending.get(request_id)


# ── Process-wide shared instance ────────────────────────────────────────
# Any caller that opens/checks an authorization window needs to see the
# SAME window every other caller sees — a fresh AuthorizationManager()
# per call has its own disconnected state, so a window opened through
# one instance is invisible everywhere else. This bug happened twice
# independently (tool_router.py and intent_mapper.py each built their
# own throwaway RedOrchestrator, each with its own disconnected
# AuthorizationManager) before being fixed here, once, centrally.
_shared_manager: Optional[AuthorizationManager] = None


def get_shared_authorization(config_path: str = "config/roe.json",
                             mode: Optional[str] = None) -> AuthorizationManager:
    """
    The single AuthorizationManager instance for this process. Use this
    — not AuthorizationManager(...) directly — whenever the caller needs
    authorization state (open_window, status, etc.) to be visible to the
    rest of the running process, which is true for essentially every
    caller outside of tests.

    `mode` only has an effect on the FIRST call that creates the
    instance — later calls return the existing shared instance
    unchanged, `mode` argument or not. ares_server.py calls this with
    mode="chat" during boot, before anything else in the process gets
    a chance to create it with the (CLI-only) blocking default — see
    ares_server.py's boot sequence.
    """
    global _shared_manager
    if _shared_manager is None:
        _shared_manager = AuthorizationManager(config_path=config_path, mode=mode or "blocking")
    return _shared_manager
