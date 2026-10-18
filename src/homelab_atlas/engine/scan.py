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

from homelab_atlas.collectors.base import CollectContext, Collector, CollectorResult, FacetResult
from homelab_atlas.engine.diff import body_sha256, diff
from homelab_atlas.engine.events import EventSpec
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
        self, targets: Sequence[str] | None = None, collectors: Sequence[str] | None = None
    ) -> list[tuple[str, Collector]]:
        jobs = []
        for name, collector in self._collectors.items():
            if collectors and name not in collectors:
                continue
            for target in collector.targets(self._ctx.inventory):
                if not targets or target in targets:
                    jobs.append((target, collector))
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
        results = await asyncio.gather(*(self._collect(t, c) for t, c in jobs))
        summary = ScanSummary(scan_id=scan_id)
        with self._sessions() as s:
            for result in sorted(results, key=lambda r: (r.collector, r.target)):
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

    async def _collect(self, target: str, collector: Collector) -> CollectorResult:
        async with self._sem:
            try:
                async with asyncio.timeout(self._timeout):
                    result = await collector.collect(target, self._ctx)
            except TimeoutError:
                result = CollectorResult(
                    collector.name, target, "failed", errors=["collector timeout"]
                )
        for facet in result.facets:
            if facet.model is not None:
                facet.model = self._redactor.model(facet.model)
            facet.display_name = self._redactor.text(facet.display_name)
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
        known_key = r.primary_key or (prev_run.entity_key if prev_run else None)
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
        if not r.facets:
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
        if was_down and known_key:
            events.append(
                EventSpec(known_key, "host.recovered", "info", f"{r.target}: reachable again")
            )
        collector = self._collectors[r.collector]
        seen: set[str] = set()
        for facet in r.facets:
            if facet.entity_key in seen:
                continue  # first report wins; collectors should not duplicate keys
            seen.add(facet.entity_key)
            events.extend(self._persist_facet(s, scan_id, r, facet, collector))
        if r.complete:
            events.extend(self._removed(s, r, seen))
        return events

    def _persist_facet(
        self, s: Session, scan_id: int, r: CollectorResult, f: FacetResult, collector: Collector
    ) -> list[EventSpec]:
        now = utcnow()
        key = f.entity_key
        entity = s.get(Entity, key)
        is_new = entity is None
        if entity is None:
            entity = Entity(key=key, kind=f.kind, display_name=f.display_name, first_seen=now)
            s.add(entity)
        entity.last_seen, entity.last_scan_id = now, scan_id
        entity.display_name, entity.status = f.display_name, "known"
        if f.parent_key is not None:
            entity.parent_key = f.parent_key
        data: dict[str, Any] = f.model.model_dump(mode="json") if f.model is not None else {}
        facet = s.get(Facet, (key, r.collector))
        if facet is None:
            s.add(
                Facet(
                    entity_key=key,
                    collector=r.collector,
                    target=r.target,
                    scan_id=scan_id,
                    data=data,
                )
            )
        else:
            facet.scan_id, facet.data, facet.target = scan_id, data, r.target
        if f.model is None:
            s.flush()
            return []

        body = canonical(f.model)
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
        s.flush()
        if prev is None:
            if not is_new:
                return []  # a new facet (e.g. docker) on an entity we already know
            return [
                EventSpec(
                    key,
                    "entity.added",
                    "info",
                    f"{f.display_name}: new {f.kind} discovered ({r.collector})",
                )
            ]
        if body_sha256(prev) != sha:
            return collector.events(key, f.display_name, diff(prev, body))
        return []

    def _removed(self, s: Session, r: CollectorResult, seen: set[str]) -> list[EventSpec]:
        events: list[EventSpec] = []
        stale = s.scalars(
            select(Facet).where(
                Facet.collector == r.collector,
                Facet.target == r.target,
                Facet.entity_key.not_in(seen),
            )
        ).all()
        for facet in stale:
            entity = s.get(Entity, facet.entity_key)
            if facet.data and entity is not None:
                events.append(
                    EventSpec(
                        facet.entity_key,
                        "entity.removed",
                        "notice",
                        f"{entity.display_name}: {entity.kind} no longer reported by {r.collector}",
                    )
                )
            if (
                entity is not None
                and not s.scalars(
                    select(Facet).where(
                        Facet.entity_key == facet.entity_key, Facet.collector != r.collector
                    )
                ).first()
            ):
                entity.status = "gone"
            s.delete(facet)
        s.flush()
        return events
