"""ARES X v10 — compat shim forwarding to aresx.domains.twin.twins.human_twin."""
from __future__ import annotations
from aresx.domains.twin.twins.human_twin import logger  # noqa: F401
from aresx.domains.twin.twins.human_twin import HumanTwinResult  # noqa: F401
from aresx.domains.twin.twins.human_twin import HumanTwinPrivacyGateRequired  # noqa: F401
from aresx.domains.twin.twins.human_twin import request_human_twin_approval  # noqa: F401
from aresx.domains.twin.twins.human_twin import approve_gate  # noqa: F401
from aresx.domains.twin.twins.human_twin import _is_gate_approved  # noqa: F401
from aresx.domains.twin.twins.human_twin import build_human_twin  # noqa: F401
