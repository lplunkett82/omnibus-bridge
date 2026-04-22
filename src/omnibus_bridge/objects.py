"""Domain models for Omni-Bus objects.

Phase 3 scope: `Unit` only. Areas, zones, buttons, thermostats, etc. are
spec-defined Omni-Link II object types but aren't used by the Translator
on this property (PC Access shows all 36 devices in the Units list,
including the 6-button keypad at unit 14). If future deployments need
them, add types alongside `Unit`.
"""
from __future__ import annotations

from enum import IntEnum


class UnitStatus(IntEnum):
    """ALC-style Unit status byte values (confirmed for Omni-Bus).

    - 0 = OFF
    - 1 = ON
    - 100..200 = dimmer level 0..100% (subtract 100 to get percent)
    """

    OFF = 0
    ON = 1


def status_is_on(status: int) -> bool:
    """True for any non-zero status — covers plain ON and dimmer levels >= 1%."""
    return status != 0


def dim_level_percent(status: int) -> int | None:
    """If `status` is a dimmer level (100..200), return the percent. Else None."""
    if 100 <= status <= 200:
        return status - 100
    return None
