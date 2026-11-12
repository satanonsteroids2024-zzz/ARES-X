"""ARES X v10 — compat alias. Canonical home of the event bus is aresx.bus."""
from aresx.bus import bus, Event, EventType, Subscription, EventBus
__all__ = ["bus", "Event", "EventType", "Subscription", "EventBus"]
