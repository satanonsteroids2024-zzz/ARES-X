"""
ARES X v12 — Neural Architecture: Sovereign Intelligence OS
============================================================
Sensor fusion, digital twins, mission OS, decision intelligence,
simulation, evidence vault, sovereign AI cluster, enterprise RAG,
federated search, post-quantum crypto, compliance pipeline and
agentic threat response — behind one chat interface.

Public surface
--------------
    from aresx import boot_v8, bus, EventType
    boot_v8()                    # one-line substrate startup
"""

__version__ = "12.0.0"
__codename__ = "NEURAL ARCHITECTURE"
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
