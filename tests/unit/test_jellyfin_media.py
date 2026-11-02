"""Jellyfin collector, media diagnosis and incidents (ADR-039/040). Demo lab + mocks only."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from homelab_atlas.collectors.base import CollectContext
from homelab_atlas.collectors.jellyfin import (
    JellyfinCollector,
    counts,
    libraries,
    pseudonym,
    recent,
    session,
    sessions,
    tasks,
)
from homelab_atlas.engine import incidents, media
from homelab_atlas.engine.media import Check, _storage, _verdict, mount_for
from homelab_atlas.engine.notify import Notification
from homelab_atlas.lab import load_api_recordings, load_lab
from homelab_atlas.runtime import Inputs, Runtime, replay_http
from homelab_atlas.security.ssh import SshRunner
from homelab_atlas.store.tables import Entity, Facet, Incident, Scan
from tests.helpers import MemoryAudit

LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"
INTERVALS = {"jellyfin": 300, "linux-ssh": 3600, "docker": 3600, "nas": 21600}


# ------------------------------------------------------------------ parsing


def test_session_parsing_direct_and_transcode() -> None:
    direct = session(
        "srv",
        {
            "UserId": "u1",
            "UserName": "alice",
            "NowPlayingItem": {"Name": "Film", "Type": "Movie", "RunTimeTicks": 72_000_000_000},
            "PlayState": {"PlayMethod": "DirectPlay", "PositionTicks": 36_000_000_000},
        },
    )
    assert direct is not None
    assert (direct.play_method, direct.position_s, direct.runtime_s) == ("DirectPlay", 3600, 7200)
    assert direct.hw_accel is None and direct.video_direct is None  # no TranscodingInfo
    assert "alice" not in direct.model_dump_json()  # never the user name
    assert direct.viewer == pseudonym("srv", "u1")
    tc = session(
        "srv",
        {
            "UserId": "u2",
            "NowPlayingItem": {"Name": "Ep"},
            "PlayState": {"PlayMethod": "Transcode"},
            "TranscodingInfo": {
                "HardwareAccelerationType": "None",
                "IsVideoDirect": False,
                "CompletionPercentage": 150,
                "TranscodeReasons": ["A", 3],
            },
        },
    )
    assert tc is not None
    assert tc.hw_accel == "none"  # reported, and reported as software
    assert tc.transcode_pct is None  # out of range: not trusted
    assert tc.transcode_reasons == ["A"]
    assert session("srv", {"UserId": "u3"}) is None  # idle


def test_pseudonyms_are_stable_and_per_server() -> None:
    assert pseudonym("a", "u") == pseudonym("a", "u") != pseudonym("b", "u")
    assert pseudonym("a", None).startswith("viewer-")


def test_parsers_ignore_junk() -> None:
    assert sessions("s", "nope") == []
    assert sessions("s", [1, None, {"NowPlayingItem": "x"}]) == []
    assert [x.name for x in libraries([{"Name": "Movies", "Locations": ["/m", 3]}, {"x": 1}])] == [
        "Movies"
    ]
    assert libraries([{"Name": "M", "Locations": ["/m", 3]}])[0].locations == ["/m"]
    assert [t.name for t in tasks([{"Name": "T", "IsHidden": True}, {"Name": "U"}])] == ["U"]
    assert counts({"MovieCount": 3, "SeriesCount": -1, "SongCount": True}) == {"movies": 3}
    assert recent({"Items": [{"Name": "x", "Type": "Movie"}, "y"]})[0].name == "x"
    assert recent([]) == []


async def _collect(state: str, mutate: Any = None) -> Any:
    inv, ssh = load_lab(state, LAB)
    recs = load_api_recordings(state, LAB)
    if mutate:
        mutate(recs["media"])
    audit = MemoryAudit()
    ctx = CollectContext(inv, SshRunner(transport=ssh, audit=audit), replay_http(recs)(audit))
    return await JellyfinCollector().collect("media", ctx), audit


async def test_demo_collection() -> None:
    res, audit = await _collect("A")
    assert res.status == "ok"
    (f,) = res.facets
    assert f.entity_key == "jellyfin:media"
    data = f.model.model_dump()
    assert data["version"] == "10.11.2"
    assert {s["play_method"] for s in data["sessions"]} == {"DirectPlay", "Transcode"}
    assert "ATLASFAKE" not in json.dumps(data)  # fixture user names never stored
    assert all(e.op.startswith("GET ") for e in audit.events)
    assert {e.op for e in audit.events} == {e.op for e in JellyfinCollector.endpoints}


async def test_401_is_explained_and_optional_calls_degrade() -> None:
    def deny(r: dict[str, Any]) -> None:
        r["/System/Info"] = (401, b"{}")

    res, _ = await _collect("A", deny)
    assert res.status == "failed" and "API key was refused" in res.errors[0]

    def no_tasks(r: dict[str, Any]) -> None:
        r["/ScheduledTasks"] = (403, b"{}")

    res, _ = await _collect("A", no_tasks)
    assert res.status == "partial"
    assert res.errors == ["scheduled tasks: HTTP 403"]


# ------------------------------------------------------------------ diagnosis


def test_mount_for_picks_the_longest_prefix() -> None:
    mounts = [{"target": "/"}, {"target": "/mnt"}, {"target": "/mnt/media"}]
    assert mount_for("/mnt/media/movies", mounts) == {"target": "/mnt/media"}
    assert mount_for("/mnt/mediathek", mounts) == {"target": "/mnt"}
    assert mount_for("/srv", mounts) == {"target": "/"}


def test_storage_unmounted_share_is_a_failure_not_a_pass() -> None:
    jf = {"libraries": [{"name": "M", "locations": ["/mnt/media/movies"]}]}
    local = {"mounts": [{"target": "/", "fstype": "ext4", "size_bytes": 10, "avail_bytes": 5}]}
    rows, state, detail = _storage(jf, local, 10)
    assert state == "fail" and "not on a network share" in detail
    nfs = {
        "mounts": [
            *local["mounts"],
            {"target": "/mnt/media", "fstype": "nfs4", "size_bytes": 100, "avail_bytes": 5},
        ]
    }
    rows, state, _ = _storage(jf, nfs, 10)
    assert state == "pass" and rows[0]["low"] is True and rows[0]["free_pct"] == 5
    hung = {"mounts": [{"target": "/mnt/media", "fstype": "nfs4"}]}
    assert _storage(jf, hung, 10)[1] == "warn"
    assert _storage({}, nfs, 10)[1] == "unknown"
    assert _storage(jf, {}, 10)[1] == "unknown"


def _checks(**states: str) -> list[Check]:
    return [Check(k, k, v, f"{k} detail") for k, v in states.items()]  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("states", "cond", "status"),
    [
        ({"api": "fail", "vm": "fail", "host": "fail"}, 2, "down"),
        ({"api": "fail", "vm": "pass", "host": "fail"}, 6, "down"),
        ({"api": "fail", "vm": "unknown", "host": "fail"}, 2, "down"),
        ({"api": "fail", "host": "pass", "service": "fail"}, 3, "down"),
        ({"api": "fail", "host": "pass", "service": "pass"}, 1, "down"),
        ({"api": "fail", "host": "unknown"}, 1, "down"),
        ({"api": "pass", "host": "pass", "mounts": "fail", "nas": "pass"}, 4, "degraded"),
        ({"api": "pass", "host": "pass", "mounts": "fail", "nas": "fail"}, 5, "degraded"),
        ({"api": "warn", "host": "pass", "mounts": "pass"}, 7, "stale"),
        ({"api": "unknown", "host": "pass"}, 8, "unknown"),
        ({"api": "pass", "host": "pass", "mounts": "pass", "nas": "pass"}, 0, "healthy"),
        ({"api": "pass", "host": "unknown", "mounts": "unknown"}, 0, "healthy"),
    ],
)
def test_verdict_table(states: dict[str, str], cond: int, status: str) -> None:
    d = _verdict("jf", _checks(**states))
    assert (d.condition, d.status) == (cond, status), d.headline


def test_verdict_does_not_claim_storage_it_did_not_check() -> None:
    d = _verdict("jf", _checks(api="pass", mounts="unknown"))
    assert "not verified" in d.headline


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    rt = Runtime.open(tmp_path_factory.mktemp("media"), mode="demo")
    return rt


def _scan(rt: Runtime, state: str) -> None:
    inv, ssh = load_lab(state, LAB)
    engine = rt.scan_engine(Inputs(inv, ssh, replay_http(load_api_recordings(state, LAB)), LAB))
    asyncio.run(engine.run())


def test_demo_a_healthy_then_b_storage_incident(rt: Runtime) -> None:
    _scan(rt, "A")
    inv, _ = load_lab("A", LAB)
    src = inv.sources.jellyfin[0]
    with rt.sessions() as s:
        d = media.diagnose(s, inv, src, INTERVALS)
        assert d.status == "healthy" and d.condition == 0, d.headline
        assert d.host == "media01"
        assert all(r["network"] for r in d.storage)
        assert incidents.open_incidents(s) == []
    _scan(rt, "B")
    inv, _ = load_lab("B", LAB)
    with rt.sessions() as s:
        d = media.diagnose(s, inv, inv.sources.jellyfin[0], INTERVALS)
        assert (d.status, d.condition) == ("degraded", 4), d.headline
        api = next(c for c in d.checks if c.id == "api")
        assert api.state == "pass"  # storage problem, NOT "Jellyfin down"
        assert any(c.id == "library" and c.state == "warn" for c in d.checks)
        keys = {i.key for i in incidents.open_incidents(s)}
        assert "media.storage:media" in keys and "media.down:media" not in keys
        assert "host.unreachable:ghost01" in keys  # failed in A and B
    _scan(rt, "B")
    with rt.sessions() as s:
        open_ = [i for i in incidents.open_incidents(s) if i.key == "media.storage:media"]
        assert len(open_) == 1  # deduplicated across scans


# ------------------------------------------------------------------ incidents lifecycle


def _fake_conditions(monkeypatch: pytest.MonkeyPatch, keys: list[str]) -> None:
    def fake(*_a: Any, **_k: Any) -> list[incidents.Condition]:
        return [incidents.Condition(k, "x", f"title {k}", "warning", None, ("ev",)) for k in keys]

    monkeypatch.setattr(incidents, "conditions", fake)


def test_open_notify_resolve_and_flap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rt = Runtime.open(tmp_path, mode="demo")
    inv, _ = load_lab("A", LAB)
    t0 = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)
    with rt.sessions() as s:
        _fake_conditions(monkeypatch, ["k"])
        incidents.evaluate(s, inv, {}, t0)
        s.commit()
        assert incidents.due_notifications(s, t0 + timedelta(minutes=1)) == []  # not sustained yet
        incidents.evaluate(s, inv, {}, t0 + timedelta(minutes=6))
        ((row, note),) = incidents.due_notifications(s, t0 + timedelta(minutes=6))
        assert note.kind == "incident.opened" and note.evidence == ["ev"]
        incidents.mark_sent(row, note, t0 + timedelta(minutes=6))
        _fake_conditions(monkeypatch, [])
        incidents.evaluate(s, inv, {}, t0 + timedelta(minutes=10))
        ((row, note),) = incidents.due_notifications(s, t0 + timedelta(minutes=10))
        assert note.kind == "incident.resolved" and note.title.startswith("Resolved")
        incidents.mark_sent(row, note)
        # Comes back within the cooldown: same incident, no second "opened" or "resolved".
        _fake_conditions(monkeypatch, ["k"])
        incidents.evaluate(s, inv, {}, t0 + timedelta(minutes=20))
        _fake_conditions(monkeypatch, [])
        incidents.evaluate(s, inv, {}, t0 + timedelta(minutes=25))
        assert incidents.due_notifications(s, t0 + timedelta(hours=1)) == []
        assert len(list(s.scalars(select(Incident)))) == 1
        # Much later: a new incident.
        _fake_conditions(monkeypatch, ["k"])
        incidents.evaluate(s, inv, {}, t0 + timedelta(hours=3))
        assert len(list(s.scalars(select(Incident)))) == 2


def test_unannounced_incidents_resolve_silently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rt = Runtime.open(tmp_path, mode="demo")
    inv, _ = load_lab("A", LAB)
    t0 = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)
    with rt.sessions() as s:
        _fake_conditions(monkeypatch, ["blip"])
        incidents.evaluate(s, inv, {}, t0)
        _fake_conditions(monkeypatch, [])
        incidents.evaluate(s, inv, {}, t0 + timedelta(minutes=2))
        assert incidents.due_notifications(s, t0 + timedelta(hours=1)) == []


class FakeNotifier:
    def __init__(self, ok: bool = True) -> None:
        self.sent: list[Notification] = []
        self.ok = ok

    async def send(self, note: Notification) -> tuple[bool, str]:
        self.sent.append(note)
        return self.ok, "delivered" if self.ok else "n8n unreachable"


def test_scan_engine_sends_due_notifications_and_retries(tmp_path: Path) -> None:
    rt = Runtime.open(tmp_path, mode="demo")
    with rt.sessions() as s:
        s.add(
            Incident(
                key="k",
                kind="x",
                title="disk",
                severity="warning",
                opened_at=datetime.now(UTC) - timedelta(minutes=30),
            )
        )
        s.commit()
    inv, ssh = load_lab("A", LAB)
    engine = rt.scan_engine(Inputs(inv, ssh, replay_http(load_api_recordings("A", LAB)), LAB))
    down = FakeNotifier(ok=False)
    engine._notifier = down  # type: ignore[assignment]
    asyncio.run(engine.notify_due())
    assert len(down.sent) == 1
    up = FakeNotifier()
    engine._notifier = up  # type: ignore[assignment]
    asyncio.run(engine.notify_due())
    asyncio.run(engine.notify_due())
    assert [n.title for n in up.sent] == ["disk"]  # once, after the failed attempt


def test_incidents_table_is_migrated(tmp_path: Path) -> None:
    rt = Runtime.open(tmp_path, mode="demo")
    with rt.sessions() as s:
        assert s.execute(select(Incident)).all() == []
        version = s.connection().exec_driver_sql("select version_num from alembic_version").scalar()
    assert version == "0005"


def test_pool_without_redundancy_is_not_an_incident(tmp_path: Path) -> None:
    rt = Runtime.open(tmp_path, mode="demo")
    inv, _ = load_lab("A", LAB)
    with rt.sessions() as s:
        s.add(Scan(mode="demo"))
        s.flush()
        s.add(Entity(key="nas:x", kind="nas", display_name="unas"))
        s.flush()
        for pid, status in (("1", "noDataProtectionYet"), ("2", "degraded")):
            s.merge(
                Facet(
                    entity_key="nas:x",
                    collector="nas",
                    target="unas",
                    scan_id=1,
                    data={"pools": [{"id": pid, "status": status}]},
                )
            )
            s.flush()
            keys = {c.key for c in incidents.conditions(s, inv, {}, datetime.now(UTC))}
            assert ("nas.pool:unas:2" in keys) is (pid == "2")
