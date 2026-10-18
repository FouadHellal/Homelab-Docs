"""Scan orchestration: collect → redact → snapshot → diff → events → persist."""

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
from filelock import FileLock, Timeout
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from homelab_atlas.collectors.base import CollectContext, Collector, CollectorResult
from homelab_atlas.engine.diff import body_sha256, diff
from homelab_atlas.engine.events import EventSpec, linux_events
from homelab_atlas.inventory.hosts import HostEntry
from homelab_atlas.models.base import canonical
from homelab_atlas.redact import Redactor
from homelab_atlas.store.tables import (
    Blob,
    CollectorRun,
    Entity,
    Event,
    Facet,
    Scan,
    Snapshot,
    utcnow,
)

log = structlog.get_logger()

DEFAULT_CONCURRENCY = 8
DEFAULT_COLLECTOR_TIMEOUT_S = 300.0


class ScanLockedError(RuntimeError):
    pass


@dataclass(slots=True)
class ScanSummary:
    scan_id: int
    runs: list[CollectorResult] = field(default_factory=list)
    events: list[EventSpec] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.runs:
            out[r.status] = out.get(r.status, 0) + 1
        return out


class ScanEngine:
    def __init__(
        self,
        *,
        sessions: sessionmaker[Session],
        ctx: CollectContext,
        collectors: Sequence[Collector],
        redactor: Redactor,
        lock_path: Path,
        mode: str,
        concurrency: int = DEFAULT_CONCURRENCY,
        collector_timeout_s: float = DEFAULT_COLLECTOR_TIMEOUT_S,
    ) -> None:
        self._sessions = sessions
        self._ctx = ctx
        self._collectors = {c.name: c for c in collectors}
        self._redactor = redactor
        self._lock = FileLock(lock_path)
        self._mode = mode
        self._sem = asyncio.Semaphore(concurrency)
        self._timeout = collector_timeout_s

    def plan(
        self, hosts: Sequence[str] | None = None, collectors: Sequence[str] | None = None
    ) -> list[tuple[HostEntry, Collector]]:
        jobs = []
        for host in self._ctx.inventory.hosts:
            if hosts and host.name not in hosts:
                continue
            for name in host.collectors:
                if collectors and name not in collectors:
                    continue
                if (collector := self._collectors.get(name)) is not None:
                    jobs.append((host, collector))
        return jobs

    async def run(
        self,
        hosts: Sequence[str] | None = None,
        collectors: Sequence[str] | None = None,
        label: str | None = None,
    ) -> ScanSummary:
        try:
            self._lock.acquire(timeout=0)
        except Timeout:
            raise ScanLockedError("another scan is running") from None
        try:
            return await self._run_locked(hosts, collectors, label)
        finally:
            self._lock.release()

    async def _run_locked(
        self, hosts: Sequence[str] | None, collectors: Sequence[str] | None, label: str | None
    ) -> ScanSummary:
        with self._sessions() as s:
            scan = Scan(mode=self._mode, label=label)
            s.add(scan)
            s.commit()
            scan_id = scan.id
        jobs = self.plan(hosts, collectors)
        results = await asyncio.gather(*(self._collect(h, c) for h, c in jobs))
        summary = ScanSummary(scan_id=scan_id)
        with self._sessions() as s:
            for result in results:
                summary.runs.append(result)
                summary.events.extend(self._persist(s, scan_id, result))
            scan_row = s.get_one(Scan, scan_id)
            scan_row.finished_at = utcnow()
            scan_row.status = "done"
            for spec in summary.events:
                s.add(
                    Event(
                        scan_id=scan_id,
                        entity_key=spec.entity_key,
                        type=spec.type,
                        severity=spec.severity,
                        path=spec.path[:512],
                        old=spec.old,
                        new=spec.new,
                        summary=spec.summary[:512],
                    )
                )
            s.commit()
        log.info("scan.done", scan_id=scan_id, runs=summary.counts, events=len(summary.events))
        return summary

    async def _collect(self, host: HostEntry, collector: Collector) -> CollectorResult:
        async with self._sem:
            try:
                async with asyncio.timeout(self._timeout):
                    result = await collector.collect(host, self._ctx)
            except TimeoutError:
                result = CollectorResult(
                    collector.name,
                    host.name,
                    "failed",
                    collector.kind,
                    display_name=host.name,
                    errors=["collector timeout"],
                )
        if result.model is not None:
            result.model = self._redactor.model(result.model)
        result.errors = [self._redactor.text(e) for e in result.errors]
        return result

    # ------------------------------------------------------------------ persistence

    def _persist(self, s: Session, scan_id: int, r: CollectorResult) -> list[EventSpec]:
        prev_run = s.scalars(
            select(CollectorRun)
            .where(CollectorRun.target == r.target, CollectorRun.collector == r.collector)
            .order_by(CollectorRun.scan_id.desc())
            .limit(1)
        ).first()
        known_key = r.entity_key or (prev_run.entity_key if prev_run else None)
        s.add(
            CollectorRun(
                scan_id=scan_id,
                target=r.target,
                collector=r.collector,
                entity_key=known_key,
                status=r.status,
                errors=r.errors,
                duration_ms=r.duration_ms,
            )
        )
        events: list[EventSpec] = []
        was_down = prev_run is not None and prev_run.status in ("failed", "refused")
        if r.model is None:
            if prev_run is not None and not was_down and known_key:
                why = r.errors[0] if r.errors else r.status
                events.append(
                    EventSpec(
                        known_key,
                        "host.unreachable",
                        "warning",
                        f"{r.target}: {r.collector} {r.status}: {why}"[:512],
                    )
                )
            return events
        key = r.entity_key
        if key is None:  # pragma: no cover - collectors always set a key with a model
            return events
        if was_down:
            events.append(EventSpec(key, "host.recovered", "info", f"{r.target}: reachable again"))

        now = utcnow()
        entity = s.get(Entity, key)
        if entity is None:
            entity = Entity(key=key, kind=r.kind, display_name=r.display_name, first_seen=now)
            s.add(entity)
        entity.last_seen, entity.last_scan_id, entity.display_name = now, scan_id, r.display_name

        body = canonical(r.model)
        sha = body_sha256(body)
        if s.get(Blob, sha) is None:
            s.add(Blob(sha256=sha, body=body))
        prev = s.execute(
            select(Blob.body)
            .join(Snapshot, Snapshot.sha256 == Blob.sha256)
            .where(Snapshot.entity_key == key, Snapshot.collector == r.collector)
            .order_by(Snapshot.scan_id.desc())
            .limit(1)
        ).scalar_one_or_none()
        s.add(Snapshot(scan_id=scan_id, entity_key=key, collector=r.collector, sha256=sha))
        facet = s.get(Facet, (key, r.collector))
        data: dict[str, Any] = r.model.model_dump(mode="json")
        if facet is None:
            s.add(Facet(entity_key=key, collector=r.collector, scan_id=scan_id, data=data))
        else:
            facet.scan_id, facet.data = scan_id, data
        s.flush()

        if prev is None:
            events.append(
                EventSpec(
                    key,
                    "entity.added",
                    "info",
                    f"{r.target}: new {r.kind} discovered ({r.collector})",
                )
            )
        elif body_sha256(prev) != sha:
            events.extend(linux_events(key, r.target, diff(prev, body)))
        return events
