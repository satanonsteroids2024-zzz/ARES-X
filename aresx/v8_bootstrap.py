"""
ARES X v8.0 — Bootstrap
=========================

Brings the v8 TITAN-ENTERPRISE substrate online. Idempotent: safe to
call multiple times. Must be called BEFORE any v7/v8 module is used.

Wire-up order (matters)::

    1. Storage          (SQLite schema + Kuzu graph)
    2. Event bus        (already live; we just register hooks)
    3. Audit hook       (sinks every Event to audit_log_v2 with SHA-3 chain)
    4. Boot event       (announces BOOT_COMPLETE on the bus)

This module is intentionally minimal — heavy modules
(fusion, sovereign_ai, rag_federated) lazy-load on first use.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Optional

from aresx.events import Event, EventType, bus
from aresx.storage import db, init_storage

logger = logging.getLogger(__name__)

_booted = False
_boot_status: Optional[dict] = None


# -------------------------------------------------------------------
# Audit hook — SHA-3 chained, append-only (Order 27)
# -------------------------------------------------------------------
def _format_ts(unix_ts: float) -> str:
    """Canonical timestamp format used for both storage and hashing.

    Using a fixed-precision string ensures the value that goes into the
    hash matches the value read back during verification (no float-vs-
    datetime round-trip drift).
    """
    return f"{unix_ts:.6f}"


def _compute_record_hash(seq: int, actor: str, action: str, resource: str,
                         payload_json: str, ts_str: object, prev_hash: str) -> str:
    """SHA3-256 of all record fields, in canonical order.

    Note: ``ts_str`` is coerced to str() defensively. The canonical
    format produced by ``_format_ts`` is what we expect, but if SQLite
    type-affinity ever round-trips the value as a float (e.g. someone
    re-introduces TIMESTAMP column affinity), str() of that float is
    still deterministic so the chain remains verifiable.
    """
    h = hashlib.sha3_256()
    h.update(str(seq).encode())
    h.update(b"|")
    h.update(actor.encode())
    h.update(b"|")
    h.update(action.encode())
    h.update(b"|")
    h.update(resource.encode())
    h.update(b"|")
    h.update(payload_json.encode())
    h.update(b"|")
    h.update(str(ts_str).encode())
    h.update(b"|")
    h.update(prev_hash.encode())
    return h.hexdigest()


import threading

# Lock for atomic audit log writes — prevents UNIQUE collision on sequence_num
# when multiple threads publish events concurrently.
_AUDIT_LOCK = threading.Lock()


def _audit_sink(event: Event) -> None:
    """
    Persist every event to audit_log_v2 with a SHA-3 hash chain.

    The chain is rooted at the genesis hash (sha3_256 of "ARES-X-v8")
    and each record's prev_sha3_hash equals the previous record's
    this_sha3_hash. Order 27: any break is immediately detectable.

    Thread-safe: serializes concurrent writes via _AUDIT_LOCK so the
    SELECT-MAX → INSERT cycle is atomic. Includes retry loop for
    cross-process safety against UNIQUE constraint violations.
    """
    MAX_RETRIES = 5
    for attempt in range(MAX_RETRIES):
        try:
            with _AUDIT_LOCK:
                row = db.query_one(
                    "SELECT sequence_num, this_sha3_hash FROM audit_log_v2 "
                    "ORDER BY sequence_num DESC LIMIT 1"
                )
                if row is None:
                    next_seq = 1
                    prev_hash = hashlib.sha3_256(b"ARES-X-v8").hexdigest()
                else:
                    next_seq = int(row["sequence_num"]) + 1
                    prev_hash = row["this_sha3_hash"]

                # Canonical JSON for hashing: sorted keys, no whitespace
                payload_json = json.dumps(event.payload, sort_keys=True, separators=(",", ":"))
                ts_str = _format_ts(event.timestamp)
                actor = event.source
                action = event.type.value
                resource = event.correlation_id or ""

                this_hash = _compute_record_hash(
                    next_seq, actor, action, resource, payload_json, ts_str, prev_hash
                )

                db.execute(
                    """
                    INSERT INTO audit_log_v2
                      (log_id, sequence_num, actor, action, resource, payload,
                       timestamp, prev_sha3_hash, this_sha3_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        next_seq,
                        actor,
                        action,
                        resource,
                        payload_json,
                        ts_str,
                        prev_hash,
                        this_hash,
                    ),
                )
            return  # success
        except Exception as exc:
            msg = str(exc).lower()
            # Retry on UNIQUE collision (cross-process race or SQLite WAL mode)
            if "unique" in msg or "constraint" in msg:
                if attempt < MAX_RETRIES - 1:
                    continue
            # Other errors or exhausted retries — log and give up
            logger.error("Audit sink failure for %s: %s", event.type, exc)
            return


# -------------------------------------------------------------------
# Chain integrity check — runs on every boot (Order 27)
# -------------------------------------------------------------------
def verify_audit_chain(max_records: int = 100_000) -> dict:
    """
    Walk the audit chain forward, recomputing each hash. Stops at the
    first mismatch or at max_records, whichever comes first.

    Returns:
        {
          "intact":      bool,
          "checked":     int,
          "break_at":    int | None,
          "expected":    str | None,
          "actual":      str | None,
        }
    """
    rows = db.query_all(
        "SELECT sequence_num, actor, action, resource, payload, "
        "       timestamp, prev_sha3_hash, this_sha3_hash "
        "FROM audit_log_v2 "
        "ORDER BY sequence_num ASC "
        f"LIMIT {int(max_records)}"
    )
    if not rows:
        return {"intact": True, "checked": 0, "break_at": None,
                "expected": None, "actual": None}

    expected_prev = hashlib.sha3_256(b"ARES-X-v8").hexdigest()
    checked = 0
    for r in rows:
        seq = int(r["sequence_num"])
        if r["prev_sha3_hash"] != expected_prev:
            return {"intact": False, "checked": checked, "break_at": seq,
                    "expected": expected_prev, "actual": r["prev_sha3_hash"]}
        recomputed = _compute_record_hash(
            seq, r["actor"], r["action"], r["resource"] or "",
            r["payload"] or "{}", r["timestamp"], r["prev_sha3_hash"],
        )
        if recomputed != r["this_sha3_hash"]:
            return {"intact": False, "checked": checked, "break_at": seq,
                    "expected": recomputed, "actual": r["this_sha3_hash"]}
        expected_prev = r["this_sha3_hash"]
        checked += 1

    return {"intact": True, "checked": checked, "break_at": None,
            "expected": None, "actual": None}


# -------------------------------------------------------------------
# Public boot entry
# -------------------------------------------------------------------
def boot(verbose: bool = False) -> dict:
    """
    Bring the v8 substrate online. Returns a status dict.

    Calling boot() a second time is a no-op that returns the cached
    status, except that the audit chain is re-verified.
    """
    global _booted, _boot_status

    if _booted and _boot_status is not None:
        # Always re-verify chain even on warm boot
        _boot_status["audit_chain"] = verify_audit_chain()
        return _boot_status

    t0 = time.time()
    storage_status = init_storage(verbose=verbose)

    # Verify audit chain BEFORE wiring the audit hook so the verify
    # query is not itself audited.
    chain_status = verify_audit_chain()
    if not chain_status["intact"]:
        logger.critical(
            "AUDIT CHAIN BROKEN at seq=%s (Order 27 critical alert)",
            chain_status["break_at"],
        )
        # Still proceed — but a chain-broken event is fired below.

    # Wire the audit sink into the event bus
    bus.set_audit_hook(_audit_sink)

    _boot_status = {
        "version":        "8.0.0",
        "tier":           "TITAN-ENTERPRISE",
        "storage":        storage_status,
        "audit_chain":    chain_status,
        "boot_duration_ms": int((time.time() - t0) * 1000),
    }
    _booted = True

    # Fire boot event (this is the first event to be audited)
    bus.publish_sync(
        EventType.BOOT_COMPLETE,
        payload={
            "version": "8.0.0",
            "boot_duration_ms": _boot_status["boot_duration_ms"],
            "graph_available": storage_status["graph_available"],
            "audit_intact": chain_status["intact"],
        },
        source="v8_bootstrap",
    )

    if not chain_status["intact"]:
        bus.publish_sync(
            EventType.AUDIT_CHAIN_BROKEN,
            payload=chain_status,
            source="v8_bootstrap",
        )

    return _boot_status


def is_booted() -> bool:
    return _booted


def status() -> Optional[dict]:
    return _boot_status
