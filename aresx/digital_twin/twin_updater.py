"""ARES X v10 — compat shim forwarding to aresx.domains.twin.twin_updater."""
from __future__ import annotations
from aresx.domains.twin.twin_updater import logger
from aresx.domains.twin.twin_updater import _FRESHNESS_K
from aresx.domains.twin.twin_updater import _STALE_THRESHOLD
from aresx.domains.twin.twin_updater import _REFRESH_THRESHOLD
from aresx.domains.twin.twin_updater import _REFRESH_INTERVAL_HOURS
from aresx.domains.twin.twin_updater import compute_freshness
from aresx.domains.twin.twin_updater import _needs_refresh
from aresx.domains.twin.twin_updater import refresh_twin
from aresx.domains.twin.twin_updater import refresh_active_twins
