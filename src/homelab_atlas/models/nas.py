"""UniFi UNAS facts: from the (undocumented, community-described) Drive API or manual YAML."""

from typing import Literal

from homelab_atlas.models.base import Fact, keyed, volatile


class NasPool(Fact):
    id: str
    raid: str | None = None
    status: str | None = None  # "fullyOperational" when healthy
    capacity_bytes: int | None = None
    used_bytes: int | None = volatile()


class NasDisk(Fact):
    slot: str
    model: str | None = None
    serial: str | None = None
    size_bytes: int | None = None
    pool_id: str | None = None
    state: str | None = None  # "optimal" when healthy
    health_score: int | None = None
    bad_sectors: int | None = None
    temperature_c: float | None = volatile()
    power_on_hours: int | None = volatile()


class NasShare(Fact):
    name: str
    protocol: str | None = None


class NasFacts(Fact):
    source: Literal["drive-api", "manual"]
    name: str
    model: str | None = None
    mac: str | None = None
    firmware: str | None = None
    drive_version: str | None = None
    pools: list[NasPool] = keyed("id")
    disks: list[NasDisk] = keyed("slot")
    shares: list[NasShare] = keyed("name")
    section_errors: list[str] = volatile(factory=list)
