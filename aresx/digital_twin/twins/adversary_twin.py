"""ARES X v10 — compat shim forwarding to aresx.domains.twin.twins.adversary_twin."""
from __future__ import annotations
from aresx.domains.twin.twins.adversary_twin import logger  # noqa: F401
from aresx.domains.twin.twins.adversary_twin import _MITRE_TACTICS  # noqa: F401
from aresx.domains.twin.twins.adversary_twin import TTP  # noqa: F401
from aresx.domains.twin.twins.adversary_twin import AdversaryTwinResult  # noqa: F401
from aresx.domains.twin.twins.adversary_twin import _fetch_otx_pulse  # noqa: F401
from aresx.domains.twin.twins.adversary_twin import _fetch_threatfox  # noqa: F401
from aresx.domains.twin.twins.adversary_twin import _assign_ttps  # noqa: F401
from aresx.domains.twin.twins.adversary_twin import _infer_sophistication  # noqa: F401
from aresx.domains.twin.twins.adversary_twin import build_adversary_twin  # noqa: F401
