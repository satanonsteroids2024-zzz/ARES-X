"""
ARES X v8.0 — Phase 4.5: Mission Forensic Replay.

Replay mode: replay all mission_events in sequence.
Seek: jump to any sequence_num in < 2 seconds.
Speed control: 1x / 5x / 10x / max.
Order 16: replay is deterministic — same sequence produces same graph state.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Optional

from aresx.mission.mission_control import get_event_sequence, get_mission
from aresx.storage import db

logger = logging.getLogger(__name__)


@dataclass
class ReplayFrame:
    sequence_num: int
    event_type:   str
    agent_id:     Optional[str]
    payload:      dict
    timestamp:    str


def get_replay_frames(mission_id: str,
                       start_seq: int = 1,
                       end_seq: Optional[int] = None) -> list[ReplayFrame]:
    """
    Load replay frames for a mission.
    Optionally bounded by [start_seq, end_seq].
    """
    rows = get_event_sequence(mission_id)
    frames: list[ReplayFrame] = []
    for row in rows:
        seq = int(row["sequence_num"])
        if seq < start_seq:
            continue
        if end_seq is not None and seq > end_seq:
            break
        try:
            payload = json.loads(row["payload"] or "{}")
        except json.JSONDecodeError:
            payload = {}
        frames.append(ReplayFrame(
            sequence_num=seq,
            event_type=row["event_type"],
            agent_id=row.get("agent_id"),
            payload=payload,
            timestamp=row.get("timestamp", ""),
        ))
    return frames


def seek_to(mission_id: str, sequence_num: int) -> list[ReplayFrame]:
    """
    Return all frames up to and including sequence_num.
    Suitable for rendering graph state at that point in time.
    """
    return get_replay_frames(mission_id, end_seq=sequence_num)


def replay(mission_id: str,
            on_frame: Callable[[ReplayFrame], None],
            speed: float = 1.0,
            start_seq: int = 1) -> None:
    """
    Drive replay with a callback. ``speed`` multiplies the playback rate.
    speed=0 → max speed (no delays between frames).

    Args:
        mission_id: which mission to replay
        on_frame:   called for each ReplayFrame in sequence order
        speed:      1.0 = real-time, 5.0 = 5× faster, 0 = instant
        start_seq:  first sequence_num to replay from
    """
    frames = get_replay_frames(mission_id, start_seq=start_seq)
    for i, frame in enumerate(frames):
        on_frame(frame)
        if speed > 0 and i < len(frames) - 1:
            delay = 0.01 / speed         # simulated inter-event gap
            time.sleep(delay)


def export_replay_json(mission_id: str) -> dict:
    """Export the complete mission replay as a JSON-serializable dict."""
    mission = get_mission(mission_id)
    frames = get_replay_frames(mission_id)
    return {
        "mission_id": mission_id,
        "mission":    mission,
        "frame_count": len(frames),
        "frames": [
            {
                "seq":         f.sequence_num,
                "event_type":  f.event_type,
                "agent_id":    f.agent_id,
                "payload":     f.payload,
                "timestamp":   f.timestamp,
            }
            for f in frames
        ],
    }
