"""ARES X v10 — compat shim forwarding to aresx.domains.twin.twins.org_twin."""
from __future__ import annotations
from aresx.domains.twin.twins.org_twin import logger  # noqa: F401
from aresx.domains.twin.twins.org_twin import OrgEntity  # noqa: F401
from aresx.domains.twin.twins.org_twin import OrgTwinResult  # noqa: F401
from aresx.domains.twin.twins.org_twin import _seed_domains  # noqa: F401
from aresx.domains.twin.twins.org_twin import _seed_company_registry  # noqa: F401
from aresx.domains.twin.twins.org_twin import _seed_tech_stack  # noqa: F401
from aresx.domains.twin.twins.org_twin import _seed_news  # noqa: F401
from aresx.domains.twin.twins.org_twin import _seed_investors  # noqa: F401
from aresx.domains.twin.twins.org_twin import _seed_key_people  # noqa: F401
from aresx.domains.twin.twins.org_twin import _phase1_seed  # noqa: F401
from aresx.domains.twin.twins.org_twin import _phase2_build_graph  # noqa: F401
from aresx.domains.twin.twins.org_twin import _infer_relation  # noqa: F401
from aresx.domains.twin.twins.org_twin import _phase3_score  # noqa: F401
from aresx.domains.twin.twins.org_twin import build_org_twin  # noqa: F401
