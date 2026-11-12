"""
aresx.mission.asset_tracker — Agent + resource + hardware status tracking.

Tracks all 14 ARES agents, current hardware utilization, and resource availability.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AssetStatus:
    asset_id:      str
    asset_type:    str           # agent | gpu | cpu | network
    status:        str           # online | busy | degraded | offline
    utilization:   float         # 0.0–1.0
    last_seen:     float = field(default_factory=time.time)
    metadata:      dict = field(default_factory=dict)


class AssetTracker:
    """Tracks system assets (agents + hardware) and their operational status."""

    def __init__(self) -> None:
        self._assets: dict[str, AssetStatus] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        from aresx.mission.live_ops import _AGENT_ROSTER
        for aid in _AGENT_ROSTER:
            self._assets[aid] = AssetStatus(
                asset_id=aid, asset_type="agent",
                status="online", utilization=0.0,
            )

    def update(self, asset_id: str, status: str,
                utilization: float = 0.0, metadata: Optional[dict] = None) -> None:
        self._assets[asset_id] = AssetStatus(
            asset_id=asset_id,
            asset_type=self._assets.get(asset_id, AssetStatus("", "agent", "", 0.0)).asset_type,
            status=status,
            utilization=utilization,
            last_seen=time.time(),
            metadata=metadata or {},
        )

    def get_available_agents(self) -> list[str]:
        return [
            aid for aid, a in self._assets.items()
            if a.asset_type == "agent" and a.status in ("online", "degraded")
        ]

    def snapshot(self) -> list[dict]:
        return [
            {
                "asset_id":    a.asset_id,
                "type":        a.asset_type,
                "status":      a.status,
                "utilization": round(a.utilization, 2),
                "last_seen":   a.last_seen,
            }
            for a in self._assets.values()
        ]

    def hardware_summary(self) -> dict:
        """Try to pull live GPU/CPU stats. Graceful fallback."""
        summary = {"cpu_count": 4, "ram_gb": 16.0, "gpu": None}
        try:
            import psutil
            summary["cpu_count"] = psutil.cpu_count()
            summary["ram_gb"] = round(psutil.virtual_memory().total / 1e9, 1)
            summary["cpu_pct"] = psutil.cpu_percent(interval=0.1)
        except ImportError:
            pass
        try:
            import torch
            if torch.cuda.is_available():
                summary["gpu"] = {
                    "name": torch.cuda.get_device_name(0),
                    "vram_gb": round(torch.cuda.get_device_properties(0).total_memory / 1e9, 1),
                }
        except Exception:
            pass
        return summary


asset_tracker = AssetTracker()
