"""
ARES X v10 — Event Bus (canonical location: aresx.bus; aresx.events is a compat alias) & Event Types
========================================

A single in-process asyncio event bus that all v7/v8 modules use for
loosely-coupled communication. v6 modules continue to work without
touching the bus; v8 modules subscribe to relevant event types and
publish their own.

Design
------
* Lives entirely in-process (no Redis, no Kafka). Aligns with the
  "Zero Servers" sovereignty pillar.
* asyncio-based, but exposes a sync ``publish_sync()`` shim so legacy
  threaded modules can fire events without touching the loop.
* Bounded subscriber queues (size 1024) — if a slow subscriber falls
  behind it drops oldest events with a warning rather than blocking.
* Wildcard subscriptions supported via ``"fusion.*"`` patterns.
* Every event is also written to the audit_log_v2 table when the
  audit module is initialised (wired up by v8_bootstrap).

Public API
----------
    from aresx.events import bus, EventType, Event
    await bus.publish(Event(EventType.FUSION_COMPLETE, payload={...}))
    bus.publish_sync(EventType.MISSION_STARTED, payload={...})
    sub = bus.subscribe(EventType.FUSION_COMPLETE)
    async for event in sub:
        handle(event)
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from typing import Any, AsyncIterator, Callable, Optional

logger = logging.getLogger(__name__)


# ===================================================================
# EVENT TYPE CATALOG
# ===================================================================
class EventType(str, Enum):
    """All v7/v8 event types. v6 modules don't emit these."""

    # ── v7 TITAN — Fusion (Phase 2) ─────────────────────────────
    FUSION_COMPLETE         = "fusion.complete"
    FUSION_CONTRADICTION    = "fusion.contradiction"
    FUSION_BUFFER_FLUSHED   = "fusion.buffer.flushed"

    # ── v7 TITAN — Digital Twins (Phase 3) ──────────────────────
    TWIN_BUILD_STARTED      = "twin.build.started"
    TWIN_BUILT              = "twin.built"
    TWIN_UPDATED            = "twin.updated"
    TWIN_STALE              = "twin.stale"
    TWIN_SNAPSHOT_CAPTURED  = "twin.snapshot.captured"

    # ── v7 TITAN — Mission OS (Phase 4) ─────────────────────────
    MISSION_STARTED              = "mission.started"
    MISSION_OBJECTIVE_STARTED    = "mission.objective.started"
    MISSION_OBJECTIVE_COMPLETE   = "mission.objective.complete"
    MISSION_REPLANNING           = "mission.replanning"
    MISSION_PAUSED               = "mission.paused"
    MISSION_RESUMED              = "mission.resumed"
    MISSION_COMPLETE             = "mission.complete"
    MISSION_FAILED               = "mission.failed"
    MISSION_BRANCHED             = "mission.branched"

    # ── v7 TITAN — Decision Intelligence (Phase 5) ─────────────
    DECISION_READY               = "decision.ready"
    RECOMMENDATION_GENERATED     = "decision.recommendation"
    OPPORTUNITY_DETECTED         = "decision.opportunity"

    # ── v7 TITAN — Simulation (Phase 6) ─────────────────────────
    SIMULATION_STARTED           = "simulation.started"
    SIMULATION_COMPLETE          = "simulation.complete"
    WARGAME_PATH_FOUND           = "simulation.wargame.path"

    # ── v7 TITAN — Enterprise (Phase 7) ─────────────────────────
    EVIDENCE_VAULT_ENTRY         = "evidence.vault.entry"
    WATCHLIST_ALERT              = "watchlist.alert"
    APPROVAL_GATE_TRIGGERED      = "approval.gate.triggered"
    APPROVAL_GATE_RESOLVED       = "approval.gate.resolved"
    BRIEF_GENERATED              = "brief.generated"

    # ── v7 TITAN — Plugin System (Phase 8) ──────────────────────
    PLUGIN_LOADED                = "plugin.loaded"
    PLUGIN_UNLOADED              = "plugin.unloaded"
    PLUGIN_RESULT                = "plugin.result"
    PLUGIN_CRASHED               = "plugin.crashed"

    # ── v7 TITAN — OSINT/Intel (existing v6 modules can opt-in) ─
    OSINT_FINDING                = "osint.finding"
    SIGINT_DETECTION             = "sigint.detection"
    BEHINT_ANOMALY               = "behint.anomaly"

    # ── v8 ENTERPRISE — Sovereign AI (Phase 9) ──────────────────
    MODEL_LOADED                 = "sovereign.model.loaded"
    MODEL_UNAVAILABLE            = "sovereign.model.unavailable"
    SOVEREIGN_MODE_CHANGED       = "sovereign.mode.changed"          # cloud→hybrid→sovereign→air-gap
    INFERENCE_CALLED             = "inference.generate"              # Order 21: every LLM call audited
    COMPUTE_BUDGET_WARNING       = "sovereign.budget.warning"        # ≥ 80% quota
    COMPUTE_BUDGET_EXCEEDED      = "sovereign.budget.exceeded"

    # ── v8 ENTERPRISE — RAG / Federated Search (Phase 10) ──────
    RAG_INGESTED                 = "rag.ingested"
    RAG_QUERY                    = "rag.query"
    FEDERATED_SEARCH_COMPLETE    = "federated.search.complete"
    ENTITY_RESOLVED              = "rag.entity.resolved"

    # ── Phase 13 — Red Module (Hollow Purple) ───────────────────
    RED_MISSION_STARTED          = "red.mission.started"
    RED_MISSION_BLOCKED          = "red.mission.blocked"           # declined by operator
    RED_MISSION_COMPLETE         = "red.mission.complete"
    RED_RECON_FINDING            = "red.recon.finding"
    RED_AUTH_WINDOW_OPENED       = "red.auth_window.opened"
    RED_AUTH_WINDOW_CLOSED       = "red.auth_window.closed"

    # ── v8 ENTERPRISE — Post-Quantum Security (Phase 11) ───────
    KEY_ROTATED                  = "security.key.rotated"
    COMPLIANCE_FAIL              = "security.compliance.fail"
    COMPLIANCE_PASS              = "security.compliance.pass"
    AUDIT_CHAIN_BROKEN           = "security.audit.chain.broken"     # Order 27 critical alert
    HSM_ATTESTATION              = "security.hsm.attestation"

    # ── v8 ENTERPRISE — Agentic Threat Response (Phase 12) ─────
    THREAT_DETECTED              = "threat.detected"
    THREAT_RESPONSE_STARTED      = "threat.response.started"
    THREAT_RESPONSE_COMPLETE     = "threat.response.complete"

    # ── v8 — system lifecycle ─────────────────────────────────
    BOOT_COMPLETE                = "system.boot.complete"
    SHUTDOWN_INITIATED           = "system.shutdown.initiated"


# ===================================================================
# EVENT DATACLASS
# ===================================================================
@dataclass
class Event:
    """An immutable event published on the bus."""
    type:        EventType
    payload:     dict[str, Any] = field(default_factory=dict)
    source:      str = "unknown"
    event_id:    str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:   float = field(default_factory=time.time)
    correlation_id: Optional[str] = None        # ties related events together (e.g. mission_id)

    def to_dict(self) -> dict:
        return {
            "type":           self.type.value,
            "payload":        self.payload,
            "source":         self.source,
            "event_id":       self.event_id,
            "timestamp":      self.timestamp,
            "correlation_id": self.correlation_id,
        }


# ===================================================================
# SUBSCRIPTION
# ===================================================================
class Subscription:
    """
    Async iterator over events for a single subscriber.

    Use as::

        sub = bus.subscribe(EventType.FUSION_COMPLETE)
        async for event in sub:
            ...
        sub.close()
    """

    def __init__(self, pattern: str, queue_size: int = 1024) -> None:
        self.pattern: str = pattern
        self.queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        self.closed: bool = False
        self.dropped: int = 0

    def matches(self, event_type: str) -> bool:
        return fnmatch(event_type, self.pattern)

    async def __aiter__(self) -> AsyncIterator[Event]:
        while not self.closed:
            try:
                event = await self.queue.get()
            except asyncio.CancelledError:
                break
            if event is _SENTINEL:                 # type: ignore[arg-type]
                break
            yield event

    def close(self) -> None:
        self.closed = True
        # Push sentinel to wake up any awaiting iterator
        try:
            self.queue.put_nowait(_SENTINEL)        # type: ignore[arg-type]
        except asyncio.QueueFull:
            pass


# Sentinel used to wake up closed subscriptions
_SENTINEL: Any = object()


# ===================================================================
# EVENT BUS
# ===================================================================
class EventBus:
    """In-process async event bus with optional sync-publish shim."""

    def __init__(self) -> None:
        self._subs: list[Subscription] = []
        self._lock = asyncio.Lock()
        # Optional audit hook injected by enterprise.audit_log_v2 once available
        self._audit_hook: Optional[Callable[[Event], None]] = None

    # ── subscription management ────────────────────────────────
    def subscribe(self, event_type: EventType | str, queue_size: int = 1024) -> Subscription:
        """
        Subscribe to a specific event type or a glob pattern.

        Examples::

            bus.subscribe(EventType.FUSION_COMPLETE)
            bus.subscribe("mission.*")
            bus.subscribe("twin.*")
        """
        pattern = event_type.value if isinstance(event_type, EventType) else str(event_type)
        sub = Subscription(pattern, queue_size=queue_size)
        self._subs.append(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        if sub in self._subs:
            self._subs.remove(sub)
        sub.close()

    def set_audit_hook(self, hook: Optional[Callable[[Event], None]]) -> None:
        """Wire in the audit_log_v2 sink (called by v8_bootstrap)."""
        self._audit_hook = hook

    # ── publication ────────────────────────────────────────────
    async def publish(self, event: Event | EventType, payload: Optional[dict] = None,
                      source: str = "unknown", correlation_id: Optional[str] = None) -> None:
        """
        Publish an event. Accepts either a fully-built Event or an
        EventType + payload kwargs.
        """
        if isinstance(event, EventType):
            event = Event(
                type=event,
                payload=payload or {},
                source=source,
                correlation_id=correlation_id,
            )

        # Audit hook first — chain integrity is sacred (Order 27)
        if self._audit_hook is not None:
            try:
                self._audit_hook(event)
            except Exception as exc:
                logger.error("Audit hook failed for event %s: %s", event.type, exc)

        # Fan out to subscribers
        for sub in list(self._subs):                # copy: subs may be modified concurrently
            if sub.closed:
                continue
            if not sub.matches(event.type.value):
                continue
            try:
                sub.queue.put_nowait(event)
            except asyncio.QueueFull:
                sub.dropped += 1
                logger.warning(
                    "Subscriber for %r is slow; dropped event %s (total drops: %d)",
                    sub.pattern, event.type.value, sub.dropped,
                )

    def publish_sync(self, event: Event | EventType, payload: Optional[dict] = None,
                     source: str = "unknown", correlation_id: Optional[str] = None) -> None:
        """
        Synchronous publish for legacy/threaded callers.

        Schedules an async publish on the running event loop if there is
        one; falls back to running a temporary loop otherwise. Never
        blocks the caller.
        """
        if isinstance(event, EventType):
            event = Event(
                type=event,
                payload=payload or {},
                source=source,
                correlation_id=correlation_id,
            )
        try:
            # Python 3.10+: use get_running_loop() — raises RuntimeError if none
            loop = asyncio.get_running_loop()
            asyncio.run_coroutine_threadsafe(self.publish(event), loop)
            return
        except RuntimeError:
            pass
        # No running loop — run inline. Slow path but rare.
        try:
            asyncio.run(self.publish(event))
        except RuntimeError:
            # Already inside a loop in another thread; best-effort fail
            logger.debug("publish_sync no-loop fallback failed for %s", event.type)


# Global singleton bus
bus: EventBus = EventBus()


__all__ = ["EventType", "Event", "Subscription", "EventBus", "bus"]
