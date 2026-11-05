"""ADR-043: incidents for failing API sources, stopped guests, broken containers, full disks."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from homelab_atlas.engine import incidents
from homelab_atlas.lab import load_lab
from homelab_atlas.runtime import Runtime
from homelab_atlas.store.tables import CollectorRun, Scan
from tests.helpers import scanned_lab

LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    return scanned_lab(tmp_path_factory.mktemp("more"))


def keys(rt: Runtime) -> dict[str, incidents.Condition]:
    inv, _ = load_lab("B", LAB)
    with rt.sessions() as s:
        return {c.key: c for c in incidents.conditions(s, inv, {}, datetime.now(UTC))}


def test_demo_lab_problems_become_conditions(rt: Runtime) -> None:
    found = keys(rt)
    kuma = found["container.down:docker02/uptime-kuma"]
    assert "unhealthy" in kuma.title and kuma.entity_key
    assert "exited with code 137" in found["container.down:docker02/adhoc-test"].title
    guest = found["guest.stopped:pve:vm:homelab/105"]
    assert "legacy01" in guest.title and guest.severity == "warning"
    # Running, healthy containers and guests not set to start at boot are not incidents.
    assert not [k for k in found if k.startswith("container.down:docker01/")]


def _fail(rt: Runtime, target: str, collector: str, n: int, error: str) -> None:
    with rt.sessions() as s:
        for _ in range(n):
            scan = Scan(mode="demo", status="done")
            s.add(scan)
            s.flush()
            s.add(CollectorRun(scan_id=scan.id, target=target, collector=collector, status="failed",
                               errors=[error]))  # fmt: skip
        s.commit()


def test_a_failing_api_source_is_an_incident_and_its_stale_facts_are_not(rt: Runtime) -> None:
    with rt.sessions() as s:
        pve = s.scalars(select(CollectorRun).where(CollectorRun.collector == "proxmox")).first()
        assert pve is not None
        target = pve.target
    _fail(rt, target, "proxmox", 1, "HTTP 403: the token lacks permission")
    assert f"source.failed:proxmox:{target}" not in keys(rt)  # one failure is not yet a pattern
    _fail(rt, target, "proxmox", 1, "HTTP 403: the token lacks permission")
    found = keys(rt)
    c = found[f"source.failed:proxmox:{target}"]
    assert "Proxmox API source" in c.title and "403" in c.title
    assert c.evidence == ("HTTP 403: the token lacks permission",)
    # Guest state from the failing API is stale: no stopped-guest incident from it.
    assert "guest.stopped:pve:vm:homelab/105" not in found


def test_full_mounts_ignores_pseudo_filesystems() -> None:
    gib = 1 << 30
    mounts = [
        {"target": "/", "fstype": "ext4", "size_bytes": 100 * gib, "used_bytes": 93 * gib},
        {"target": "/data", "fstype": "xfs", "size_bytes": 100 * gib, "used_bytes": 50 * gib},
        {"target": "/snap/core22/1380", "fstype": "squashfs", "size_bytes": gib, "used_bytes": gib},
        {"target": "/run", "fstype": "tmpfs", "size_bytes": gib, "used_bytes": gib},
        {"target": "/var/lib/docker/overlay2/x/merged", "fstype": "overlay", "size_bytes": gib,
         "used_bytes": gib},
        {"target": "/mnt/odd", "fstype": "ext4", "size_bytes": 0, "used_bytes": 0},
        "junk",
    ]  # fmt: skip
    assert incidents.full_mounts(mounts) == [("/", 93)]
