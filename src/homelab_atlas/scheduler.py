"""Periodic scans (ADR-015): one APScheduler job per collector, serialised, with backoff.

* Interval per collector (defaults below, `ATLAS_INTERVAL_<COLLECTOR>` seconds override),
  ±10 % jitter so targets are not polled in lockstep.
* Jobs run one at a time in-process (asyncio lock) and across processes (the engine's
  file lock); a job that finds the file lock held by `atlas scan` retries shortly.
* A collector whose every target failed backs off exponentially (interval * 2^n, at most 6 h)
  so an unreachable target is not hammered; one success resets it.
* `trigger()` is the manual "scan now" (full scan, or some hosts). Requests are queued and
  merged, never dropped, so clicking Scan on five machines scans all five.
* Retention runs after each scheduled scan.
Nothing here reaches a target directly: every scan goes through ScanEngine and so through
the same read-only choke points as `atlas scan`.
"""

import asyncio
import os
import random
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from homelab_atlas.collectors.base import CollectorResult
from homelab_atlas.engine.scan import ScanEngine, ScanLockedError, ScanSummary

log = structlog.get_logger()

DEFAULT_INTERVALS_S: Final[Mapping[str, int]] = {
    "unifi": 900,
    "proxmox": 900,
    "linux-ssh": 3600,
    "docker": 3600,
    "pi": 3600,
    "nas": 21600,
}
MIN_INTERVAL_S: Final = 60
MAX_BACKOFF_S: Final = 6 * 3600
LOCKED_RETRY_S: Final = 120
JITTER: Final = 0.1


def intervals_from_env(env: Mapping[str, str] | None = None) -> dict[str, int]:
    env = os.environ if env is None else env
    out = dict(DEFAULT_INTERVALS_S)
    for name in out:
        raw = env.get(f"ATLAS_INTERVAL_{name.upper().replace('-', '_')}")
        if raw is None:
            continue
        try:
            value = int(raw)
        except ValueError:
            raise ValueError(f"ATLAS_INTERVAL for {name} must be an integer") from None
        if value != 0 and value < MIN_INTERVAL_S:
            raise ValueError(f"interval for {name} must be 0 (disabled) or >= {MIN_INTERVAL_S}s")
        out[name] = value
    return out


@dataclass(slots=True)
class CollectorState:
    name: str
    interval_s: int
    failures: int = 0
    backoff_until: datetime | None = None
    last_run: datetime | None = None
    last_status: str | None = None

    def backoff_s(self) -> int:
        return min(self.interval_s * (1 << self.failures), MAX_BACKOFF_S)


@dataclass(slots=True)
class ScanStatus:
    running: str | None = None  # label of the scan in progress
    queued: list[str] = field(default_factory=list)  # manual requests waiting their turn
    last_manual: datetime | None = None
    collectors: dict[str, CollectorState] = field(default_factory=dict)


class Scheduler:
    def __init__(
        self,
        engine: Callable[[], ScanEngine],
        *,
        intervals: Mapping[str, int] | None = None,
        retention: Callable[[], Any] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        locked_retry_s: float = 30.0,
    ) -> None:
        self._engine = engine
        self._retention = retention
        self._clock = clock
        self._lock = asyncio.Lock()
        self._aps: AsyncIOScheduler | None = None
        self._tasks: set[asyncio.Task[Any]] = set()
        self._worker: asyncio.Task[Any] | None = None
        self._queue_full = False
        self._queue_hosts: set[str] = set()
        self._locked_retry_s = locked_retry_s
        chosen = intervals_from_env() if intervals is None else dict(intervals)
        self.status = ScanStatus(
            collectors={n: CollectorState(n, s) for n, s in chosen.items() if s > 0}
        )

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        aps = AsyncIOScheduler(timezone=UTC)
        for st in self.status.collectors.values():
            aps.add_job(
                self.run_collector,
                IntervalTrigger(seconds=st.interval_s, jitter=int(st.interval_s * JITTER)),
                args=[st.name],
                id=f"collector:{st.name}",
                max_instances=1,
                coalesce=True,
                misfire_grace_time=st.interval_s,
                # First runs staggered over the first minute rather than all at boot.
                next_run_time=self._clock() + timedelta(seconds=random.uniform(5, 60)),  # noqa: S311
            )
        aps.start()
        self._aps = aps
        intervals = {n: c.interval_s for n, c in self.status.collectors.items()}
        log.info("scheduler.start", intervals=intervals)

    def shutdown(self) -> None:
        if self._aps is not None:
            self._aps.shutdown(wait=False)
            self._aps = None
        for t in self._tasks:
            t.cancel()

    def next_runs(self) -> dict[str, datetime | None]:
        if self._aps is None:
            return {}
        return {
            job.id.removeprefix("collector:"): job.next_run_time for job in self._aps.get_jobs()
        }

    # ------------------------------------------------------------------ jobs

    async def run_collector(self, name: str) -> ScanSummary | None:
        st = self.status.collectors[name]
        now = self._clock()
        if st.backoff_until and now < st.backoff_until:
            log.info("scheduler.backoff_skip", collector=name, until=st.backoff_until.isoformat())
            return None
        try:
            summary = await self._run(collectors=[name], label=f"sched:{name}")
        except Exception as exc:  # noqa: BLE001 - a crashed scan is a failed run, not a dead job
            log.warning("scheduler.scan_error", collector=name, error=type(exc).__name__)
            summary = ScanSummary(scan_id=0, runs=[CollectorResult(name, "*", "failed")])
        if summary is None:
            self._retry_later(name)
            return None
        st.last_run = self._clock()
        counts = summary.counts
        if summary.runs and counts.get("failed", 0) == len(summary.runs):
            st.failures += 1
            st.backoff_until = st.last_run + timedelta(seconds=st.backoff_s())
            st.last_status = "failed"
            log.warning("scheduler.backoff", collector=name, failures=st.failures,
                        until=st.backoff_until.isoformat())  # fmt: skip
        else:
            st.failures, st.backoff_until = 0, None
            st.last_status = "ok" if not counts.get("failed") else "partial"
        if self._retention is not None:
            try:
                self._retention()
            except Exception as exc:  # noqa: BLE001 - retention must not stop scanning
                log.warning("retention.failed", error=type(exc).__name__)
        return summary

    def trigger(self, hosts: list[str] | None = None) -> str:
        """Queue a manual scan (all targets, or just `hosts`) and return "started" or "queued".

        Nothing is dropped: requests made while a scan runs are merged (a full scan absorbs
        host scans) and run as soon as the current scan ends.
        """
        busy = self._lock.locked() or self._draining()
        if hosts:
            self._queue_hosts.update(hosts)
        else:
            self._queue_full = True
        self.status.last_manual = self._clock()
        self._publish_queue()
        if not self._draining():
            task = asyncio.get_running_loop().create_task(self._drain())
            self._worker = task
            self._tasks.add(task)
            task.add_done_callback(self._done)
        return "queued" if busy else "started"

    def _draining(self) -> bool:
        return self._worker is not None and not self._worker.done()

    def _publish_queue(self) -> None:
        self.status.queued = ["everything"] if self._queue_full else sorted(self._queue_hosts)

    async def _drain(self) -> None:
        while self._queue_full or self._queue_hosts:
            hosts = None if self._queue_full else sorted(self._queue_hosts)
            self._queue_full = False
            self._queue_hosts.clear()
            self._publish_queue()
            label = "manual" if not hosts else f"manual:{','.join(hosts)}"[:64]
            if await self._run(label=label, hosts=hosts) is None:
                # `atlas scan` holds the file lock: put the work back and try again shortly.
                if hosts is None:
                    self._queue_full = True
                else:
                    self._queue_hosts.update(hosts)
                self._publish_queue()
                await asyncio.sleep(self._locked_retry_s)

    def _done(self, task: "asyncio.Task[Any]") -> None:
        self._tasks.discard(task)
        if not task.cancelled() and (exc := task.exception()) is not None:
            log.warning("scheduler.manual_error", error=type(exc).__name__)

    async def _run(
        self, *, collectors: list[str] | None = None, label: str, hosts: list[str] | None = None
    ) -> ScanSummary | None:
        async with self._lock:
            self.status.running = label
            try:
                # The engine's DB work is synchronous: run the whole scan on a worker thread
                # with its own loop so the web UI's loop never blocks (or deadlocks on a
                # SQLite write lock held by a request session).
                return await asyncio.to_thread(self._scan_in_thread, collectors, label, hosts)
            except ScanLockedError:
                log.info("scheduler.locked", label=label)
                return None
            finally:
                self.status.running = None

    def _scan_in_thread(
        self, collectors: list[str] | None, label: str, hosts: list[str] | None = None
    ) -> ScanSummary:
        return asyncio.run(self._engine().run(hosts=hosts, collectors=collectors, label=label))

    def _retry_later(self, name: str) -> None:
        if self._aps is None:
            return
        self._aps.add_job(
            self.run_collector,
            "date",
            run_date=self._clock() + timedelta(seconds=LOCKED_RETRY_S),
            args=[name],
            id=f"retry:{name}",
            replace_existing=True,
        )
