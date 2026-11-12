"""
aresx.digital_twin — TITAN Phase 3: Digital Twin Engine

Builds and maintains living digital models of organizations, infrastructure,
threat actors, humans (with privacy gate), supply chains, and cyber terrain.

Quick start:
    import asyncio
    from aresx.digital_twin import build_twin
    result = asyncio.run(build_twin("org", "Anthropic"))
    print(result["entity_count"], "entities")
"""
from aresx.domains.twin.twin_builder import build_twin
from aresx.domains.twin.twin_store import (
    get_twin, list_twins, find_twin_by_name,
    create_twin, update_twin_status,
    save_snapshot, load_snapshot, list_snapshots,
)
from aresx.domains.twin.twin_updater import refresh_active_twins, refresh_twin
from aresx.domains.twin.twin_visualizer import get_layout_data, get_diff_visualization
from aresx.domains.twin.twins.timeline_twin import twin_diff, take_snapshot

PHASE_STATUS = "implemented"

__all__ = [
    "build_twin",
    "get_twin",
    "list_twins",
    "find_twin_by_name",
    "create_twin",
    "update_twin_status",
    "save_snapshot",
    "load_snapshot",
    "list_snapshots",
    "refresh_active_twins",
    "refresh_twin",
    "get_layout_data",
    "get_diff_visualization",
    "twin_diff",
    "take_snapshot",
    "PHASE_STATUS",
]
