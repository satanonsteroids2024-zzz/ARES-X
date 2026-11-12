"""
ARES X v8.0 TITAN ENTERPRISE — Sovereign Intelligence OS
==========================================================
Inherits v5/v6 (Autonomous Reasoning & Execution).
Adds v7 TITAN  (sensor fusion, digital twins, mission OS, decision
intelligence, simulation, evidence vault, mission-control UI).
Adds v8 ENTERPRISE (sovereign AI cluster, enterprise RAG, federated
search, post-quantum crypto, compliance pipeline, agentic threat
response).

Public surface
--------------
    from aresx import boot_v8, bus, EventType
    boot_v8()                    # one-line v8 substrate startup

Note: exported as ``boot_v8`` (NOT ``boot``) because v6's top-level
``ares_x.py`` defines its own module-level ``boot()`` function. Keeping
the names distinct avoids any "wait which boot is this" confusion.
"""

__version__ = "10.0.0"
__codename__ = "SIMPLIFY"
__author__  = "ARES X"

# Lightweight re-exports for ergonomic access. Heavy submodules
# (fusion, sovereign_ai, etc.) are NOT imported here — they lazy-load
# on first use to keep startup cheap.
from aresx.events import bus, Event, EventType
from aresx.v8_bootstrap import boot as boot_v8, status as boot_v8_status, is_booted

__all__ = [
    "__version__",
    "__codename__",
    "boot_v8",
    "boot_v8_status",
    "is_booted",
    "bus",
    "Event",
    "EventType",
]
