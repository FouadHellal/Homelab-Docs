"""Scheduler (intervals, backoff, lock handling, manual trigger) and snapshot retention."""

import asyncio
import re
import threading
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from homelab_atlas.collectors.base import CollectorResult
from homelab_atlas.engine.scan import ScanEngine, ScanLockedError, ScanSummary
from homelab_atlas.runtime import Runtime
from homelab_atlas.scheduler import (
    DEFAULT_INTERVALS_S,
    MAX_BACKOFF_S,
    Scheduler,
    intervals_from_env,
)
from homelab_atlas.store.retention import prune
from homelab_atlas.store.tables import Blob, Scan, Snapshot
from homelab_atlas.web import auth
from homelab_atlas.web.app import WebConfig, create_app
from tests.helpers import scanned_lab

PASSWORD = "test-only-ATLASFAKE-pw"


class FakeEngine:
    def __init__(self, statuses: Sequence[str] = ("ok",), *, locked: bool = False) -> None:
        self.statuses, self.locked = list(statuses), locked
        self.calls: list[tuple[list[str] | None, str | None]] = []
        self.gate: threading.Event | None = None  # scans run on a worker thread

    async def run(
        self,
        hosts: Sequence[str] | None = None,
        collectors: Sequence[str] | None = None,
        label: str | None = None,
    ) -> ScanSummary:
        self.calls.append((list(collectors) if collectors else None, label))
        if self.gate is not None:  # a threading.Event: the scan runs on a worker thread
            await asyncio.to_thread(self.gate.wait, 5)
        if self.locked:
            raise ScanLockedError("another scan is running")
        runs = [CollectorResult("unifi", f"t{i}", st) for i, st in enumerate(self.statuses)]  # type: ignore[arg-type]
        return ScanSummary(scan_id=1, runs=runs)


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def make(engine: FakeEngine, clock: Clock | None = None, **kw: Any) -> Scheduler:
    return Scheduler(
        lambda: cast(ScanEngine, engine),
        intervals={"unifi": 900, "docker": 3600},
        clock=clock or Clock(),
        **kw,
    )


# ------------------------------------------------------------------ intervals


def test_intervals_defaults_and_env() -> None:
    assert intervals_from_env({}) == dict(DEFAULT_INTERVALS_S)
    got = intervals_from_env({"ATLAS_INTERVAL_LINUX_SSH": "7200", "ATLAS_INTERVAL_NAS": "0"})
    assert got["linux-ssh"] == 7200
    assert got["nas"] == 0
    for bad in ("30", "abc", "-5"):
        with pytest.raises(ValueError, match=r"interval|integer"):
            intervals_from_env({"ATLAS_INTERVAL_UNIFI": bad})


def test_disabled_collector_has_no_job() -> None:
    s = Scheduler(lambda: cast(ScanEngine, FakeEngine()), intervals={"unifi": 900, "nas": 0})
    assert set(s.status.collectors) == {"unifi"}


# ------------------------------------------------------------------ backoff


def test_success_runs_only_that_collector() -> None:
    eng = FakeEngine(["ok", "ok"])
    s = make(eng)
    summary = asyncio.run(s.run_collector("unifi"))
    assert summary is not None
    assert eng.calls == [(["unifi"], "sched:unifi")]
    st = s.status.collectors["unifi"]
    assert (st.failures, st.backoff_until, st.last_status) == (0, None, "ok")


def test_partial_failure_does_not_back_off() -> None:
    s = make(FakeEngine(["ok", "failed"]))
    asyncio.run(s.run_collector("unifi"))
    st = s.status.collectors["unifi"]
    assert (st.failures, st.last_status) == (0, "partial")


def test_total_failure_backs_off_exponentially_and_caps() -> None:
    clock = Clock()
    eng = FakeEngine(["failed", "failed"])
    s = make(eng, clock)
    st = s.status.collectors["unifi"]
    expected = [1800, 3600, 7200, 14400, MAX_BACKOFF_S, MAX_BACKOFF_S]
    for want in expected:
        asyncio.run(s.run_collector("unifi"))
        assert st.backoff_until == clock.now + timedelta(seconds=want)
        # Inside the window: skipped without touching the engine.
        calls = len(eng.calls)
        clock.now += timedelta(seconds=want - 1)
        assert asyncio.run(s.run_collector("unifi")) is None
        assert len(eng.calls) == calls
        clock.now += timedelta(seconds=1)
    eng.statuses = ["ok"]
    asyncio.run(s.run_collector("unifi"))
    assert (st.failures, st.backoff_until) == (0, None)


def test_crashed_scan_counts_as_failure() -> None:
    class Boom(FakeEngine):
        async def run(self, *a: Any, **kw: Any) -> ScanSummary:
            raise RuntimeError("database is locked")

    s = make(Boom())
    assert asyncio.run(s.run_collector("unifi")) is not None
    st = s.status.collectors["unifi"]
    assert st.failures == 1
    assert st.last_status == "failed"
    assert st.backoff_until is not None


def test_scan_runs_off_the_event_loop_thread() -> None:
    seen: list[int] = []

    class Where(FakeEngine):
        async def run(self, *a: Any, **kw: Any) -> ScanSummary:
            seen.append(threading.get_ident())
            return await super().run(*a, **kw)

    s = make(Where())
    asyncio.run(s.run_collector("unifi"))
    assert seen
    assert seen[0] != threading.get_ident()


def test_external_lock_is_not_a_failure() -> None:
    s = make(FakeEngine(locked=True))
    assert asyncio.run(s.run_collector("unifi")) is None
    st = s.status.collectors["unifi"]
    assert (st.failures, st.last_run) == (0, None)


def test_retention_runs_after_scan_and_errors_are_contained() -> None:
    ran: list[int] = []

    def boom() -> None:
        ran.append(1)
        raise RuntimeError("disk full")

    s = make(FakeEngine(), retention=boom)
    assert asyncio.run(s.run_collector("unifi")) is not None
    assert ran == [1]


# ------------------------------------------------------------------ trigger / APScheduler


def test_manual_trigger_is_exclusive() -> None:
    async def scenario() -> None:
        eng = FakeEngine()
        eng.gate = threading.Event()
        s = make(eng)
        assert s.trigger() is True
        await asyncio.sleep(0.05)
        assert s.status.running == "manual"
        assert s.trigger() is False  # already running
        eng.gate.set()
        for _ in range(100):
            await asyncio.sleep(0.01)
            if getattr(s.status, "running") is None:  # noqa: B009 - defeats mypy narrowing
                break
        assert getattr(s.status, "running") is None  # noqa: B009 - defeats mypy narrowing
        assert eng.calls == [(None, "manual")]

    asyncio.run(scenario())


def test_apscheduler_jobs() -> None:
    async def scenario() -> None:
        s = make(FakeEngine())
        s.start()
        try:
            assert s._aps is not None
            jobs = {j.id: j for j in s._aps.get_jobs()}
            assert set(jobs) == {"collector:unifi", "collector:docker"}
            for j in jobs.values():
                assert j.max_instances == 1
                assert j.coalesce is True
            assert set(s.next_runs()) == {"unifi", "docker"}
        finally:
            s.shutdown()
        assert s.next_runs() == {}

    asyncio.run(scenario())


# ------------------------------------------------------------------ retention


@pytest.fixture
def lab(tmp_path: Path) -> Runtime:
    return scanned_lab(tmp_path / "data")


def test_prune_keeps_newest_per_entity_and_drops_orphans(lab: Runtime) -> None:
    with lab.sessions() as s:
        before_groups = set(s.execute(select(Snapshot.entity_key, Snapshot.collector)).all())
        first = s.scalars(select(Scan).order_by(Scan.id)).first()
        assert first is not None
        first.started_at = datetime.now(UTC) - timedelta(days=120)
        s.add(Blob(sha256="0" * 64, body={"orphan": True}))
        s.commit()
        n_scan1 = s.scalar(select(func.count()).where(Snapshot.scan_id == first.id))
        res = prune(s, days=90)
        assert 0 < res.snapshots <= (n_scan1 or 0)
        assert res.blobs >= 1
        # Every (entity, collector) keeps a baseline.
        after_groups = set(s.execute(select(Snapshot.entity_key, Snapshot.collector)).all())
        assert after_groups == before_groups
        # No snapshot points at a missing blob; no blob is unreferenced.
        referenced = set(s.scalars(select(Snapshot.sha256)))
        blobs = set(s.scalars(select(Blob.sha256)))
        assert referenced <= blobs
        assert blobs <= referenced
        assert prune(s, days=90).snapshots == 0  # idempotent


def test_prune_rejects_zero_days(lab: Runtime) -> None:
    with lab.sessions() as s, pytest.raises(ValueError, match="at least one day"):
        prune(s, days=0)


# ------------------------------------------------------------------ web "Scan now"


def _client(lab: Runtime, tmp_path: Path, sched: Scheduler | None) -> TestClient:
    with lab.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    app = create_app(
        WebConfig(
            sessions=lab.sessions,
            annotations_dir=tmp_path / "ann",
            allowed_hosts=["testserver"],
            scheduler=sched,
        )
    )
    c = TestClient(app, base_url="https://testserver")
    token = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").text)
    assert token is not None
    r = c.post(
        "/login",
        data={"username": "admin", "password": PASSWORD, "csrf_token": token.group(1)},
        follow_redirects=False,
    )
    assert r.status_code == 303
    return c


def _csrf(c: TestClient) -> str:
    m = re.search(r'"X-CSRF-Token": "([^"]+)"', c.get("/").text)
    assert m is not None
    return m.group(1)


def test_scan_now_requires_csrf_and_scheduler(lab: Runtime, tmp_path: Path) -> None:
    eng = FakeEngine()
    sched = make(eng)
    with _client(lab, tmp_path, sched) as c:
        assert "Scan now" in c.get("/").text
        assert c.post("/scan", headers={"hx-request": "true"}).status_code == 403
        r = c.post("/scan", headers={"hx-request": "true", "X-CSRF-Token": _csrf(c)})
        assert r.status_code == 202
        assert "Scan started" in r.text


def test_scan_now_404_without_scheduler(lab: Runtime, tmp_path: Path) -> None:
    with _client(lab, tmp_path, None) as c:
        assert "Scan now" not in c.get("/").text
        r = c.post("/scan", headers={"hx-request": "true", "X-CSRF-Token": _csrf(c)})
        assert r.status_code == 404
