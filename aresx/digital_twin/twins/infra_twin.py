"""ARES X v10 — compat shim forwarding to aresx.domains.twin.twins.infra_twin."""
from __future__ import annotations
from aresx.domains.twin.twins.infra_twin import logger  # noqa: F401
from aresx.domains.twin.twins.infra_twin import InfraNode  # noqa: F401
from aresx.domains.twin.twins.infra_twin import InfraTwinResult  # noqa: F401
from aresx.domains.twin.twins.infra_twin import _resolve_domain  # noqa: F401
from aresx.domains.twin.twins.infra_twin import _collect_subdomains  # noqa: F401
from aresx.domains.twin.twins.infra_twin import _shodan_lookup  # noqa: F401
from aresx.domains.twin.twins.infra_twin import _compute_exposure_score  # noqa: F401
from aresx.domains.twin.twins.infra_twin import build_infra_twin  # noqa: F401
