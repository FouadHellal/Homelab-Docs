"""Raspberry Pi facts (probe `pi` section): model, SoC temperature, throttling flags.

Throttle bits per raspberrypi.com/documentation/computers/os.html (get_throttled): bits 0-3
are current conditions (volatile), bits 16-19 are sticky "has occurred since boot" flags,
whose false->true transitions are the events worth having.
"""

from homelab_atlas.models.base import Fact, volatile


class PiFacts(Fact):
    model: str | None = None
    under_voltage_occurred: bool = False
    freq_capped_occurred: bool = False
    throttling_occurred: bool = False
    soft_temp_limit_occurred: bool = False
    throttled_raw: str | None = volatile()
    under_voltage_now: bool = volatile(False)
    freq_capped_now: bool = volatile(False)
    throttled_now: bool = volatile(False)
    soft_temp_limit_now: bool = volatile(False)
    soc_temp_c: float | None = volatile()
    section_errors: list[str] = volatile(factory=list)
