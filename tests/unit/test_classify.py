"""Infrastructure vs phones/TVs/IoT, and VM IPs from UniFi by MAC (ADR-027)."""

from pathlib import Path

import pytest
from sqlalchemy import select

from homelab_atlas.engine.classify import classify
from homelab_atlas.runtime import Runtime
from homelab_atlas.store.tables import Entity, Facet
from tests.helpers import scanned_lab


@pytest.mark.parametrize(
    ("mac", "name", "wired", "network", "category"),
    [
        ("bc:24:11:aa:bb:cc", None, True, None, "vm"),  # Proxmox VM NIC
        ("52:54:00:12:34:56", "", None, None, "vm"),  # QEMU
        ("02:42:ac:11:00:02", None, True, None, "container"),  # Docker bridge
        ("dc:a6:32:01:02:03", "kitchen-thing", False, None, "pi"),  # Raspberry Pi 4
        ("2c:cf:67:01:02:03", None, True, None, "pi"),  # Raspberry Pi 5
        ("00:11:32:aa:bb:cc", "DiskStation", True, None, "nas"),
        ("a4:83:e7:11:22:33", "Alexs-iPhone", False, "Home", "personal"),
        ("3a:1f:22:33:44:55", None, False, "Home", "personal"),  # randomized MAC
        ("3a:1f:22:33:44:55", "pve3", True, "Servers", "server"),  # name beats random MAC
        ("f0:f5:bd:11:22:33", "LivingRoom-TV", False, "Home", "iot"),
        ("ec:fa:bc:11:22:33", "esp32-c3-5f2a", False, "IoT", "iot"),
        ("ec:fa:bc:11:22:33", "HP-LaserJet", True, "Home", "iot"),
        ("00:1b:21:11:22:33", "truenas", True, "Home", "server"),
        ("00:1b:21:11:22:33", None, True, "Servers", "server"),  # wired on a server VLAN
        ("00:1b:21:11:22:33", None, True, "Home", "unknown"),  # wired, no hint: keep it
        ("00:1b:21:11:22:33", None, False, "Home", "personal"),  # wireless, no hint
        ("00:1b:21:11:22:33", None, False, "Guest", "iot"),
    ],
)
def test_classify(mac: str, name: str | None, wired: bool | None, network: str | None,
                  category: str) -> None:  # fmt: skip
    v = classify(mac, name, wired=wired, network=network)
    assert v.category == category, v.reasons
    assert v.reasons
    assert v.infrastructure == (category in {"vm", "container", "pi", "nas", "server", "network"})


def test_guests_get_ip_vlan_uplink_from_unifi(tmp_path: Path) -> None:
    rt: Runtime = scanned_lab(tmp_path / "d")
    with rt.sessions() as s:
        rows = {
            e.display_name: f.data
            for e, f in s.execute(
                select(Entity, Facet)
                .join(Facet, Facet.entity_key == Entity.key)
                .where(Facet.collector == "reconcile", Entity.kind.in_(["pve-vm", "pve-lxc"]))
            )
        }
        unknown = {
            e.display_name: f.data
            for e, f in s.execute(
                select(Entity, Facet)
                .join(Facet, Facet.entity_key == Entity.key)
                .where(Facet.collector == "reconcile", Entity.kind == "unknown-device")
            )
        }
    hass = rows["homeassistant (VM 111)"]
    assert (hass["ip"], hass["network"], hass["vlan"], hass["uplink"]) == (
        "10.0.30.20",
        "IoT",
        30,
        "sw-rack",
    )
    assert rows["docker01 (VM 101)"]["ip"] == "10.0.20.11"
    assert len(rows) >= 8
    assert unknown["android-7f3a"]["category"] == "personal"
    assert unknown["android-7f3a"]["infrastructure"] is False
    assert unknown["esp32-c3-5f2a"]["category"] == "iot"
