"""Authoritative Unit state table for the bridge.

The bridge is the Omni-Link II controller — this module owns the truth.
The Translator polls us for status; HA writes drive state updates that
then get pushed out as seq=0 EXT_OBJECT_STATUS frames. Physical events
(wall-switch presses) arrive as CONTROLLER_COMMAND and update the table
here.

Change callbacks are synchronous and fire on every state write that
actually changes the value. The MQTT publisher and the Translator-push
logic both subscribe.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

log = logging.getLogger(__name__)

ChangeCallback = Callable[[int, int, int], None]  # (unit, old_status, new_status)


@dataclass(frozen=True)
class UnitSnapshot:
    """Immutable point-in-time view of one unit's state."""

    unit: int
    status: int
    time_remaining: int = 0


class UnitStateTable:
    """In-memory state table for units numbered 1..`count`.

    All units start at status=0 (OFF). Lookups for units outside the range
    raise `KeyError`.
    """

    def __init__(self, count: int) -> None:
        if count < 1:
            raise ValueError(f"unit count must be >=1, got {count}")
        self._count = count
        self._status: dict[int, int] = {u: 0 for u in range(1, count + 1)}
        self._time: dict[int, int] = {u: 0 for u in range(1, count + 1)}
        self._listeners: list[ChangeCallback] = []

    @property
    def count(self) -> int:
        return self._count

    def units(self) -> range:
        return range(1, self._count + 1)

    def get(self, unit: int) -> UnitSnapshot:
        self._check_range(unit)
        return UnitSnapshot(unit, self._status[unit], self._time[unit])

    def set_status(self, unit: int, status: int, *, time_remaining: int = 0) -> None:
        """Write `status` for `unit`. Fires change callbacks if the value changed."""
        self._check_range(unit)
        if not 0 <= status <= 0xFF:
            raise ValueError(f"status must be 0..255, got {status}")
        old = self._status[unit]
        self._status[unit] = status
        self._time[unit] = time_remaining
        if old != status:
            for cb in self._listeners:
                cb(unit, old, status)

    def snapshot_range(self, start: int, end: int) -> Iterable[UnitSnapshot]:
        """Yield snapshots for units `start..end` inclusive.

        Units outside `1..count` are filled with status=0 so the reply always
        has the exact number of records the requester asked for.
        """
        if start < 1 or end < start:
            raise ValueError(f"invalid range {start}..{end}")
        for u in range(start, end + 1):
            if 1 <= u <= self._count:
                yield UnitSnapshot(u, self._status[u], self._time[u])
            else:
                yield UnitSnapshot(u, 0, 0)

    def on_change(self, callback: ChangeCallback) -> None:
        """Register a callback fired whenever a unit's status changes."""
        self._listeners.append(callback)

    def _check_range(self, unit: int) -> None:
        if not 1 <= unit <= self._count:
            raise KeyError(f"unit {unit} out of range (1..{self._count})")

    # ---- Persistence -----------------------------------------------------
    #
    # The Translator polls us at session start and syncs physical devices to
    # whatever we report. A fresh state table (all 0) at bridge reboot makes
    # the Translator turn every light OFF. Saving state to disk on every
    # change and restoring it at startup prevents that.

    def save(self, path: Path) -> None:
        """Write the full state table to `path` as JSON."""
        data = {
            "units": {
                str(u): {"status": self._status[u], "time_remaining": self._time[u]}
                for u in self._status
            }
        }
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(path)

    def load(self, path: Path) -> int:
        """Restore state from `path` if present. Returns number of units loaded."""
        if not path.exists():
            return 0
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            log.warning("state load from %s failed: %s — starting fresh", path, e)
            return 0
        units = data.get("units") if isinstance(data, dict) else None
        if not isinstance(units, dict):
            log.warning("state file %s has no usable 'units' mapping — starting fresh", path)
            return 0
        loaded = 0
        for k, v in units.items():
            # A corrupt entry (non-dict value, non-numeric status, out-of-
            # range unit) is skipped rather than crashing startup — losing
            # one unit's persisted state beats losing all of them.
            try:
                unit = int(k)
                status = int(v.get("status", 0))
                time_remaining = int(v.get("time_remaining", 0))
            except (TypeError, ValueError, AttributeError):
                log.warning("state file %s: skipping malformed entry %r=%r", path, k, v)
                continue
            if 1 <= unit <= self._count and 0 <= status <= 0xFF:
                self._status[unit] = status
                self._time[unit] = max(0, time_remaining)
                loaded += 1
        return loaded
