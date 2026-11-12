"""
ARES X v8.0 — Phase 2.5: Event correlator (temporal sliding window).

Watches a stream of intelligence events and emits ``CorrelationChain``
records when two or more events fit a known suspicious pattern within
a configurable time window.

Example pattern (Build Prompt §3 Phase 2.5):
    "Network scan → Malware hash sighting → Domain registration,
     all within 2 hours" → flag suspicious.

The correlator is pattern-rule driven. Built-in rules cover the demo
patterns; new rules can be registered via ``register_rule()`` so the
Threat Response phase (12) can plug its own playbooks in here.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Sequence

from aresx.events import EventType, bus
from aresx.fusion.types import CorrelationChain

logger = logging.getLogger(__name__)


# An event arriving into the correlator. We use a small inner record so
# the correlator is independent of the full Event class.
@dataclass
class StreamEvent:
    event_type:   str
    payload:      dict
    timestamp:    float = field(default_factory=time.time)


# A rule is: name, ordered list of event_type tags that must appear,
# the time window (seconds), and a suspicion score to assign.
@dataclass
class CorrelationRule:
    name:             str
    required_types:   list[str]            # in temporal order
    window_seconds:   float
    suspicion_score:  float
    matcher:          Callable[[dict], bool] | None = None
    """Optional payload predicate per event_type, indexed by position."""


# -------------------------------------------------------------------
# Built-in rule set
# -------------------------------------------------------------------
_BUILTIN_RULES: list[CorrelationRule] = [
    CorrelationRule(
        name="recon_to_registration",
        required_types=["sigint.detection", "osint.finding", "osint.finding"],
        window_seconds=2 * 3600,
        suspicion_score=0.7,
    ),
    CorrelationRule(
        name="scan_then_breach",
        required_types=["sigint.detection", "behint.anomaly"],
        window_seconds=15 * 60,
        suspicion_score=0.8,
    ),
    CorrelationRule(
        name="impossible_travel",
        required_types=["sigint.detection", "sigint.detection"],
        window_seconds=600,
        suspicion_score=0.9,
    ),
]


class EventCorrelator:
    """Sliding-window temporal correlator with pluggable rules."""

    def __init__(self,
                 rules: Sequence[CorrelationRule] | None = None,
                 max_buffer_seconds: float = 6 * 3600) -> None:
        self._rules: list[CorrelationRule] = list(rules) if rules else list(_BUILTIN_RULES)
        self._max_buffer_seconds = max_buffer_seconds
        self._buffer: list[StreamEvent] = []

    # ── rule management ───────────────────────────────────────
    def register_rule(self, rule: CorrelationRule) -> None:
        self._rules.append(rule)

    def clear_rules(self) -> None:
        self._rules.clear()

    # ── ingest ────────────────────────────────────────────────
    def ingest(self, event_type: str, payload: dict,
               timestamp: float | None = None) -> list[CorrelationChain]:
        """
        Add an event to the sliding buffer and return any newly-matched
        chains. Also fires THREAT_DETECTED on the bus for chains above
        the high-suspicion threshold.
        """
        ts = timestamp if timestamp is not None else time.time()
        self._buffer.append(StreamEvent(event_type, payload, ts))
        self._evict_old(ts)

        matched: list[CorrelationChain] = []
        for rule in self._rules:
            chain = self._match_rule(rule, ts)
            if chain is not None:
                matched.append(chain)

        for chain in matched:
            if chain.suspicion_score >= 0.7:
                try:
                    bus.publish_sync(
                        EventType.THREAT_DETECTED,
                        payload={
                            "pattern":         chain.pattern_name,
                            "suspicion_score": chain.suspicion_score,
                            "member_count":    len(chain.members),
                            "window_seconds":  chain.window_seconds,
                        },
                        source="event_correlator",
                    )
                except Exception as exc:
                    logger.error("publish failure for chain %s: %s",
                                 chain.pattern_name, exc)
        return matched

    # ── internals ─────────────────────────────────────────────
    def _evict_old(self, now: float) -> None:
        cutoff = now - self._max_buffer_seconds
        # Trim from the front (buffer is mostly time-ordered since we
        # append; sort only if a caller injects out-of-order timestamps)
        self._buffer = [e for e in self._buffer if e.timestamp >= cutoff]

    def _match_rule(self, rule: CorrelationRule, now: float) -> CorrelationChain | None:
        """
        Naïve forward match: walk through required_types in order, find
        the earliest StreamEvent of each type that occurs after the
        previous match, and confirm all fit inside the window.
        """
        # Sort buffer once for ordered scan
        ordered = sorted(self._buffer, key=lambda e: e.timestamp)

        cursor = 0
        members: list[StreamEvent] = []
        for required in rule.required_types:
            found_at = None
            for i in range(cursor, len(ordered)):
                ev = ordered[i]
                if ev.event_type != required:
                    continue
                if members and (ev.timestamp - members[0].timestamp) > rule.window_seconds:
                    return None
                if rule.matcher and not rule.matcher(ev.payload):
                    continue
                found_at = i
                members.append(ev)
                break
            if found_at is None:
                return None
            cursor = found_at + 1

        if not members:
            return None
        window = members[-1].timestamp - members[0].timestamp
        if window > rule.window_seconds:
            return None

        return CorrelationChain(
            pattern_name=rule.name,
            members=[{"event_type": m.event_type,
                      "payload":    m.payload,
                      "timestamp":  m.timestamp} for m in members],
            window_seconds=window,
            suspicion_score=rule.suspicion_score,
        )

    # ── inspection ────────────────────────────────────────────
    def buffer_size(self) -> int:
        return len(self._buffer)

    def list_rules(self) -> list[str]:
        return [r.name for r in self._rules]
