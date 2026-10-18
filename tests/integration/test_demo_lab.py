"""M2 acceptance: scan the demo lab in state A then B; the diff is exactly the golden set."""

import json
from pathlib import Path

import pytest
from sqlalchemy import func, select

from homelab_atlas.collectors.linux_ssh.collector import LinuxSshCollector
from homelab_atlas.engine.scan import ScanEngine, ScanLockedError, ScanSummary
from homelab_atlas.lab import load_lab
from homelab_atlas.runtime import Runtime
from homelab_atlas.security.audit import verify
from homelab_atlas.store.tables import Blob, Entity, Event, Facet, Snapshot

REPO = Path(__file__).resolve().parents[2]
LAB = REPO / "fixtures" / "demo-lab"
GOLDEN = [tuple(x) for x in json.loads((LAB / "expected-diff-A-B.json").read_text("utf-8"))]


def engine(rt: Runtime, state: str) -> ScanEngine:
    inventory, transport = load_lab(state, LAB)
    return rt.scan_engine(inventory, transport)


@pytest.fixture
def rt(tmp_path: Path) -> Runtime:
    return Runtime.open(tmp_path / "data", mode="demo")


async def scan(rt: Runtime, state: str) -> ScanSummary:
    return await engine(rt, state).run(label=f"demo:{state}")


async def test_a_then_b_matches_golden(rt: Runtime) -> None:
    first = await scan(rt, "A")
    assert {e.type for e in first.events} == {"entity.added"}
    assert len(first.events) == 11
    assert first.counts == {"ok": 10, "partial": 1, "failed": 1}

    second = await scan(rt, "B")
    got = sorted((e.type, e.summary) for e in second.events)
    assert got == sorted(GOLDEN)

    with rt.sessions() as s:
        stored = sorted(
            s.execute(select(Event.type, Event.summary).where(Event.scan_id == 2)).all()
        )
    assert [tuple(r) for r in stored] == sorted(GOLDEN)


async def test_rescan_same_state_is_quiet_and_deduplicated(rt: Runtime) -> None:
    await scan(rt, "A")
    again = await scan(rt, "A")
    assert again.events == []
    with rt.sessions() as s:
        assert s.scalar(select(func.count()).select_from(Blob)) == 11  # one body per host
        assert s.scalar(select(func.count()).select_from(Snapshot)) == 22


async def test_no_secret_reaches_storage_or_audit(rt: Runtime) -> None:
    await scan(rt, "A")
    await scan(rt, "B")
    db = (rt.data_dir / "atlas.db").read_bytes()
    with rt.sessions() as s:
        dumped = json.dumps(
            [b.body for b in s.scalars(select(Blob))] + [f.data for f in s.scalars(select(Facet))]
        )
    for leak in ("ATLASFAKE", "rp-ATLASFAKE", "pg-ATLASFAKE", "hc-ATLASFAKE"):
        assert leak not in dumped
        assert leak.encode() not in db
    audit_text = "".join(p.read_text("utf-8") for p in (rt.data_dir / "audit").glob("*.jsonl"))
    assert "ATLASFAKE" not in audit_text
    assert verify(rt.data_dir / "audit").ok


async def test_entities_identity_and_unicode(rt: Runtime) -> None:
    await scan(rt, "A")
    with rt.sessions() as s:
        keys = {e.display_name: e.key for e in s.scalars(select(Entity))}
        media = s.get(Facet, (keys["mediatheque"], "linux-ssh"))
    assert keys["web01"].startswith("host:")
    assert len(keys["web01"]) == 37  # host:<machine-id>
    assert "ghost01" not in keys
    assert media is not None
    assert media.data["os"]["hostname"] == "médiathèque"
    assert media.data["section_errors"] == {"storage": ["lsblk: invalid JSON"]}


async def test_partial_results_and_audit_ops(rt: Runtime) -> None:
    summary = await scan(rt, "A")
    by = {r.target: r for r in summary.runs}
    assert by["ghost01"].status == "failed"
    assert by["mediatheque"].status == "partial"
    assert by["web01"].status == "ok"
    ops = {
        json.loads(line)["op"]
        for p in (rt.data_dir / "audit").glob("*.jsonl")
        for line in p.read_text("utf-8").splitlines()
    }
    allowed = {f"atlas-probe {s.value}" for s in LinuxSshCollector.requires}
    assert ops <= {"connect"} | allowed


async def test_recovery_event(rt: Runtime) -> None:
    await scan(rt, "A")
    await scan(rt, "B")
    back = await scan(rt, "A")
    types = {(e.type, e.summary.split(":")[0]) for e in back.events}
    assert ("host.recovered", "legacy01") in types


async def test_scan_lock(rt: Runtime) -> None:
    e = engine(rt, "A")
    lock = e._lock
    lock.acquire()
    try:
        with pytest.raises(ScanLockedError):
            await engine(rt, "A").run()
    finally:
        lock.release()


async def test_host_and_collector_filters(rt: Runtime) -> None:
    summary = await engine(rt, "A").run(hosts=["web01", "db01"])
    assert sorted(r.target for r in summary.runs) == ["db01", "web01"]
    none = await engine(rt, "A").run(collectors=["docker"])
    assert none.runs == []
