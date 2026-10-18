"""NAS (drive + manual), Pi throttle decoding, and post-scan reconciliation."""

import shutil
from pathlib import Path

import pytest
from sqlalchemy import select

from homelab_atlas.collectors.base import CollectContext
from homelab_atlas.collectors.linux_ssh.frame import Frame, Part
from homelab_atlas.collectors.nas import NasCollector, from_manual, nas_events
from homelab_atlas.collectors.pi import parse_pi, pi_events
from homelab_atlas.engine.diff import Change
from homelab_atlas.inventory.hosts import load_inventory
from homelab_atlas.lab import load_api_recordings, load_lab
from homelab_atlas.models.nas import NasFacts
from homelab_atlas.runtime import Inputs, Runtime, replay_http
from homelab_atlas.security.allowlist import ProbeSection
from homelab_atlas.security.ssh import SshRunner
from homelab_atlas.store.tables import Entity
from tests.helpers import MemoryAudit

REPO = Path(__file__).resolve().parents[2]
LAB = REPO / "fixtures" / "demo-lab"


# ------------------------------------------------------------------ pi


def pi_frame(**parts: str | tuple[str, int]) -> Frame:
    f = Frame(section=ProbeSection.PI, complete=True)
    for k, v in parts.items():
        content, rc = v if isinstance(v, tuple) else (v, 0)
        f.parts[k] = Part(k, content, rc)
    return f


def test_pi_decodes_0x50005() -> None:
    errors: list[str] = []
    facts = parse_pi(
        pi_frame(
            model="Raspberry Pi 4 Model B\x00", temp="temp=48.2'C", throttled="throttled=0x50005"
        ),
        errors,
    )
    assert facts is not None
    assert facts.model == "Raspberry Pi 4 Model B"
    assert (facts.under_voltage_now, facts.throttled_now, facts.freq_capped_now) == (
        True,
        True,
        False,
    )
    assert (facts.under_voltage_occurred, facts.throttling_occurred) == (True, True)
    assert facts.soc_temp_c == 48.2
    assert errors == []


def test_pi_without_vcgencmd_uses_sysfs() -> None:
    errors: list[str] = []
    facts = parse_pi(
        pi_frame(model="x", temp=("", 127), throttled=("", 127), thermal="51234"), errors
    )
    assert facts is not None
    assert facts.soc_temp_c == pytest.approx(51.234)
    assert errors == ["pi: get_throttled unreadable (vcgencmd missing?)"]
    assert parse_pi(pi_frame(temp=("", 127), throttled=("", 127)), []) is None


def test_pi_events_only_on_new_incidents() -> None:
    up = [Change(("under_voltage_occurred",), "changed", False, True)]
    down = [Change(("under_voltage_occurred",), "changed", True, False)]  # reboot clears it
    assert [e.type for e in pi_events("k", "pi", up)] == ["pi.undervoltage"]
    assert pi_events("k", "pi", down) == []


# ------------------------------------------------------------------ nas


async def test_nas_drive_api_from_lab() -> None:
    inv, ssh = load_lab("B", LAB)
    audit = MemoryAudit()
    ctx = CollectContext(
        inventory=inv,
        ssh=SshRunner(transport=ssh, audit=audit),
        http=replay_http(load_api_recordings("B", LAB))(audit),
    )
    result = await NasCollector().collect("unas", ctx)
    assert result.status == "ok"
    facts = result.facets[0].model
    assert isinstance(facts, NasFacts)
    assert (facts.model, facts.firmware, facts.drive_version) == ("UNAS Pro", "5.1.19", "4.3.6")
    assert result.facets[0].entity_key == "nas:e4:38:83:00:00:10"
    assert {d.slot: d.state for d in facts.disks}["3"] == "degraded"
    assert all(e.op.startswith("GET ") for e in audit.events)


def test_nas_manual_yaml(tmp_path: Path) -> None:
    f = tmp_path / "unas.yaml"
    f.write_text(
        "model: UNAS Pro\nfirmware: 5.1.19\npools: [{id: '1', raid: raid5}]\n"
        "disks: [{slot: '1', model: WD80EFPX, size_bytes: 8001563222016}]\n"
        "shares: [{name: media, protocol: nfs}]\n",
        encoding="utf-8",
    )
    facts = from_manual("unas", f)
    assert facts.source == "manual"
    assert [s.name for s in facts.shares] == ["media"]
    f.write_text("model: x\npassword: nope\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown keys"):
        from_manual("unas", f)
    f.write_text("- not a mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        from_manual("unas", f)


def test_nas_events() -> None:
    changes = [
        Change(("pools", "1", "status"), "changed", "fullyOperational", "degraded"),
        Change(("disks", "3", "bad_sectors"), "changed", 0, 12),
        Change(("disks", "3", "bad_sectors"), "changed", 12, 0),  # counter reset: not news
        Change(("disks", "5"), "added", None, {}),
        Change(("firmware",), "changed", "5.1.19", "5.1.33"),
    ]
    assert [e.type for e in nas_events("k", "unas", changes)] == [
        "nas.pool_status",
        "nas.disk_bad_sectors",
        "nas.disk_added",
        "nas.upgraded",
    ]


# ------------------------------------------------------------------ reconcile


def lab_copy(tmp_path: Path) -> Path:
    lab = tmp_path / "lab"
    shutil.copytree(LAB, lab)
    return lab


async def scan(rt: Runtime, lab: Path, state: str) -> list[tuple[str, str]]:
    inv, ssh = load_lab(state, lab)
    summary = await rt.scan_engine(
        Inputs(inv, ssh, replay_http(load_api_recordings(state, lab)), lab)
    ).run()
    return [(e.type, e.summary) for e in summary.events]


async def test_correlation_links(tmp_path: Path) -> None:
    rt = Runtime.open(tmp_path / "d", mode="demo")
    await scan(rt, LAB, "A")
    with rt.sessions() as s:
        links = {
            e.display_name: e.same_as
            for e in s.scalars(select(Entity).where(Entity.kind == "linux-host"))
        }
    assert links["web01"] == "pve:vm:homelab/103"
    assert links["mediatheque"] == "pve:lxc:homelab/201"
    assert links["pve1"] == "pve:node:homelab/pve1"
    assert links["pi-garage"] is None


async def test_unknown_then_identified_via_hosts_yaml(tmp_path: Path) -> None:
    lab = lab_copy(tmp_path)
    rt = Runtime.open(tmp_path / "d", mode="demo")
    events = await scan(rt, lab, "A")
    assert [t for t, _ in events if t == "device.unknown_seen"] == ["device.unknown_seen"]
    hosts = lab / "hosts.yaml"
    hosts.write_text(
        hosts.read_text("utf-8")
        + (
            '  - name: phone\n    address: "10.0.1.57"\n    type: manual\n'
            '    match: { mac: "a2:11:22:33:44:55" }\n'
        ),
        encoding="utf-8",
    )
    assert load_inventory(hosts).host("phone").match.mac == "a2:11:22:33:44:55"
    events = await scan(rt, lab, "A")
    assert ("device.identified", "android-7f3a: now matches the inventory") in events


async def test_arp_only_unknown(tmp_path: Path) -> None:
    lab = lab_copy(tmp_path)
    rec = lab / "state-A" / "docker01" / "net.out"
    rec.write_bytes(
        rec.read_bytes().replace(
            b'"dst": "10.0.20.99", "dev": "eth0", "lladdr": "aa:bb:cc:00:00:99"',
            b'"dst": "10.0.20.77", "dev": "eth0", "lladdr": "de:ad:be:ef:00:77"',
        )
    )
    rt = Runtime.open(tmp_path / "d", mode="demo")
    events = await scan(rt, lab, "A")
    arp = [s for t, s in events if t == "device.unknown_seen" and "de:ad:be:ef:00:77" in s]
    assert arp
    assert "Servers (VLAN 20)" in arp[0]
    assert "arp@docker01" in arp[0]


async def test_missing_after_three_failures(tmp_path: Path) -> None:
    rt = Runtime.open(tmp_path / "d", mode="demo")
    await scan(rt, LAB, "A")
    for _ in range(3):
        await scan(rt, LAB, "B")  # legacy01 is down in B
    with rt.sessions() as s:
        legacy = next(e for e in s.scalars(select(Entity)) if e.display_name == "legacy01")
    assert legacy.status == "missing"
    await scan(rt, LAB, "A")
    with rt.sessions() as s:
        assert s.get(Entity, legacy.key).status == "known"  # type: ignore[union-attr]
