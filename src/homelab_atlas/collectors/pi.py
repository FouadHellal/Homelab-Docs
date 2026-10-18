"""pi collector: SoC temperature and throttling via the probe `pi` section (vcgencmd)."""

import re
from typing import Final

from homelab_atlas.collectors.base import CollectContext, CollectorResult
from homelab_atlas.collectors.linux_ssh.frame import Frame
from homelab_atlas.collectors.probe_session import collect_section
from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.models.pi import PiFacts
from homelab_atlas.security.allowlist import Endpoint, ProbeSection

TEMP_RE: Final = re.compile(r"temp=(-?\d+(?:\.\d+)?)'C")
THROTTLED_RE: Final = re.compile(r"throttled=(0x[0-9a-fA-F]{1,8})")
STICKY: Final = {
    "under_voltage_occurred": (
        "pi.undervoltage",
        "under-voltage occurred since boot (check the PSU)",
    ),
    "throttling_occurred": ("pi.throttled", "CPU throttling occurred since boot"),
    "freq_capped_occurred": ("pi.freq_capped", "ARM frequency capping occurred since boot"),
    "soft_temp_limit_occurred": ("pi.temp_limit", "soft temperature limit reached since boot"),
}


def parse_pi(frame: Frame, errors: list[str]) -> PiFacts | None:
    model = (frame.text("model") or "").replace("\x00", "").strip() or None
    temp = None
    if m := TEMP_RE.search(frame.text("temp") or ""):
        temp = float(m.group(1))
    elif (raw := (frame.text("thermal") or "").strip()).lstrip("-").isdigit():
        temp = int(raw) / 1000  # sysfs millidegrees fallback
    flags = 0
    raw_hex = None
    if m := THROTTLED_RE.search(frame.text("throttled") or ""):
        raw_hex, flags = m.group(1).lower(), int(m.group(1), 16)
    else:
        errors.append("pi: get_throttled unreadable (vcgencmd missing?)")
    if model is None and temp is None and raw_hex is None:
        return None

    def bit(n: int) -> bool:
        return bool(flags >> n & 1)

    return PiFacts(
        model=model[:128] if model else None,
        under_voltage_now=bit(0),
        freq_capped_now=bit(1),
        throttled_now=bit(2),
        soft_temp_limit_now=bit(3),
        under_voltage_occurred=bit(16),
        freq_capped_occurred=bit(17),
        throttling_occurred=bit(18),
        soft_temp_limit_occurred=bit(19),
        throttled_raw=raw_hex,
        soc_temp_c=temp,
        section_errors=list(errors),
    )


def pi_events(key: str, name: str, changes: list[Change]) -> list[EventSpec]:
    out: list[EventSpec] = []
    for c in changes:
        if c.path[0] in STICKY and c.new is True:
            etype, text = STICKY[c.path[0]]
            out.append(EventSpec(key, etype, "warning", f"{name}: {text}", c.dotted, c.old, c.new))
        elif c.path == ("model",):
            out.append(
                EventSpec(
                    key,
                    "pi.model_changed",
                    "notice",
                    f"{name}: board {c.old} -> {c.new}",
                    c.dotted,
                    c.old,
                    c.new,
                )
            )
    return out


class PiCollector:
    name = "pi"
    requires = frozenset({ProbeSection.OS, ProbeSection.PI})
    endpoints: frozenset[Endpoint] = frozenset()

    def targets(self, inventory: Inventory) -> list[str]:
        return [h.name for h in inventory.hosts if self.name in h.collectors]

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]:
        return pi_events(key, name, changes)

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult:
        return await collect_section(
            ctx,
            target,
            collector=self.name,
            section=ProbeSection.PI,
            requires=self.requires,
            build=parse_pi,
        )
