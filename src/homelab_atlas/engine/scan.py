"""Scan orchestration: collect → redact → snapshot → diff → events → persist."""

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

import structlog
from filelock import FileLock, Timeout
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from homelab_atlas.collectors.base import CollectContext, Collector, CollectorResult, FacetResult
from homelab_atlas.engine import incidents
from homelab_atlas.engine.diff import body_sha256, diff
from homelab_atlas.engine.events import EventSpec
from homelab_atlas.engine.notify import Notification, WebhookNotifier
from homelab_atlas.engine.reconcile import reconcile
from homelab_atlas.models.base import canonical
from homelab_atlas.redact import Redactor
from homelab_atlas.security.errors import SecurityRefusal
from homelab_atlas.store.facets import PVE_FACETS, PVE_SSH_PEER
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


DIGEST_MAX: Final = 15
#: SSH collectors whose host facet carries the machine-id identity (SPEC §5).
HOST_COLLECTORS: Final = frozenset({"linux-ssh", "docker", "pi"})


def _machine_key(key: str) -> bool:
    return key.startswith("host:") and not key.startswith("host:name:")


def separate_shared_ids(
    s: Session, results: Sequence[CollectorResult], targets: Sequence[str]
) -> None:
    """Cloned VMs often keep the template's /etc/machine-id, so several targets report the
    same `host:<machine-id>` and all but one would be dropped. One target owns the key: the
    one that already does (if it is still configured), else the first by name. The others are
    identified by name (`host:name:<target>`, as for hosts without a machine-id), with their
    containers and compose projects, and their run says why (ADR-044)."""
    reporters: dict[str, set[str]] = {}
    for r in results:
        if r.collector in HOST_COLLECTORS:
            for f in r.facets:
                if f.kind == "linux-host" and _machine_key(f.entity_key):
                    reporters.setdefault(f.entity_key, set()).add(r.target)
    configured = set(targets)
    owners: dict[str, str] = {}
    for key, who in reporters.items():
        stored = s.scalars(
            select(Facet.target).where(
                Facet.entity_key == key, Facet.collector.in_(HOST_COLLECTORS)
            )
        ).all()
        known = [t for t in stored if t and t in configured]
        if known and (len(who) > 1 or known[0] not in who):
            owners[key] = known[0]
        elif len(who) > 1:
            owners[key] = min(who)
    for r in results:
        if r.collector not in HOST_COLLECTORS:
            continue
        for key, owner in owners.items():
            if owner == r.target or not any(f.entity_key == key for f in r.facets):
                continue
            alias = f"host:name:{r.target}"
            for f in r.facets:
                f.entity_key = f.entity_key.replace(key, alias, 1)
                if f.parent_key:
                    f.parent_key = f.parent_key.replace(key, alias, 1)
            note = (
                f"machine-id shared with {owner} (a cloned VM?): identified by name instead. "
                "To fix it on this machine: "
                "sudo rm /etc/machine-id && sudo systemd-machine-id-setup"
            )
            if note not in r.errors:
                r.errors.append(note)


#: First discovery is not news: these only describe what atlas found, not what changed.
DIGEST_SKIP: Final = frozenset({"entity.added"})


def change_digest(events: Sequence[EventSpec], level: str) -> Notification | None:
    """One message per scan with its notable changes, or None (ADR-041)."""
    if level == "off":
        return None
    wanted = {"warning"} if level == "warning" else {"warning", "notice"}
    picked = [e for e in events if e.severity in wanted and e.type not in DIGEST_SKIP]
    if not picked:
        return None
    worst: Literal["warning", "notice"] = (
        "warning" if any(e.severity == "warning" for e in picked) else "notice"
    )
    n = len(picked)
    lines = [f"[{e.severity}] {e.summary}"[:400] for e in picked[:DIGEST_MAX]]
    if n > DIGEST_MAX:
        lines.append(f"... and {n - DIGEST_MAX} more on the Changes page")
    return Notification(
        kind="changes.digest",
        title=f"{n} notable change{'s' if n != 1 else ''} in your homelab",
        severity=worst,
        evidence=lines[:20],
        summary={"changes": n, "warnings": sum(1 for e in picked if e.severity == "warning")},
    )


def incident_link(key: str) -> str:
    return "/media" if key.startswith("media.") else "/incidents"


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
        intervals: Mapping[str, int] | None = None,
        notifier: WebhookNotifier | None = None,
    ) -> None:
        self._sessions = sessions
        self._ctx = ctx
        self._collectors = {c.name: c for c in collectors}
        self._redactor = redactor
        self._lock = FileLock(lock_path)
        self._mode = mode
        self._sem = asyncio.Semaphore(concurrency)
        self._timeout = collector_timeout_s
        self._intervals = dict(intervals or {})
        self._notifier = notifier

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
        # (entity, facet store) pairs already written by this scan: two targets may report the
        # same fact (two SSH nodes of a 3+ node cluster both see a third node as a peer).
        written: set[tuple[str, str]] = set()
        with self._sessions() as s:
            separate_shared_ids(s, results, [h.name for h in self._ctx.inventory.hosts])
            for result in sorted(results, key=lambda r: (r.collector, r.target)):
                summary.runs.append(result)
                summary.events.extend(self._persist(s, scan_id, result, written))
            summary.events.extend(reconcile(s, scan_id, self._ctx.inventory))
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
            try:  # incidents never break a scan (ADR-040)
                incidents.evaluate(s, self._ctx.inventory, self._intervals)
                s.commit()
            except Exception:
                s.rollback()
                log.exception("incidents.evaluate_failed")
        await self.notify_due(summary.events)
        log.info("scan.done", scan_id=scan_id, runs=summary.counts, events=len(summary.events))
        return summary

    async def notify_due(self, events: Sequence[EventSpec] = ()) -> None:
        """Send due incident notifications and this scan's change digest (if a webhook is
        configured), following the owner's rules; record what went (ADR-040/041)."""
        if self._notifier is None:
            return
        rules = self._notifier.rules
        now = utcnow()
        with self._sessions() as s:
            for row, due in incidents.due_notifications(s, now, rules.reminder_hours):
                if not rules.allows(due, now):
                    continue  # held: quiet hours or switched off (retried after next scan)
                note = due.model_copy(update={"link": rules.link(incident_link(row.key))})
                ok, msg = await self._notifier.send(note)
                if ok:
                    incidents.mark_sent(row, note, now)
                else:
                    log.warning("notify.failed", key=row.key, reason=msg)
                    break  # n8n down: try again after the next scan, in order
            s.commit()
        digest = change_digest(events, rules.changes)
        if digest is not None and rules.allows(digest, now):
            digest = digest.model_copy(update={"link": rules.link("/changes")})
            ok, msg = await self._notifier.send(digest)
            if not ok:
                log.warning("notify.digest_failed", reason=msg)

    async def _collect(self, target: str, collector: Collector) -> CollectorResult:
        async with self._sem:
            try:
                async with asyncio.timeout(self._timeout):
                    result = await collector.collect(target, self._ctx)
            except TimeoutError:
                result = CollectorResult(
                    collector.name, target, "failed", errors=["collector timeout"]
                )
            except SecurityRefusal as exc:  # collectors usually map these themselves
                result = CollectorResult(
                    collector.name, target, "refused", errors=[f"refused: {exc.reason.value}"]
                )
            except Exception as exc:  # noqa: BLE001 - one broken target must not sink the scan
                log.warning(
                    "collector.crashed",
                    collector=collector.name,
                    target=target,
                    error=type(exc).__name__,
                )
                result = CollectorResult(
                    collector.name, target, "failed", errors=[f"crashed: {type(exc).__name__}"]
                )
        for facet in result.facets:
            if facet.model is not None:
                facet.model = self._redactor.model(facet.model)
            facet.display_name = self._redactor.text(facet.display_name)
        result.errors = [self._redactor.text(e) for e in result.errors]
        return result

    # ------------------------------------------------------------------ persistence

    def _persist(
        self, s: Session, scan_id: int, r: CollectorResult, written: set[tuple[str, str]]
    ) -> list[EventSpec]:
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
        seen: set[tuple[str, str]] = set()
        for facet in r.facets:
            pair = (facet.entity_key, facet.store_as or r.collector)
            if pair in seen:
                continue  # first report wins; collectors should not duplicate keys
            seen.add(pair)
            if pair in written:
                continue  # another target of this scan already reported it: first wins
            written.add(pair)
            events.extend(self._persist_facet(s, scan_id, r, facet, collector))
        if r.complete:
            stores = {r.collector} | set(getattr(collector, "extra_facets", ()))
            events.extend(self._removed(s, r, seen, stores))
        return events

    def _persist_facet(
        self, s: Session, scan_id: int, r: CollectorResult, f: FacetResult, collector: Collector
    ) -> list[EventSpec]:
        now = utcnow()
        key = f.entity_key
        store = f.store_as or r.collector
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
        facet = s.get(Facet, (key, store))
        if facet is None:
            s.add(
                Facet(
                    entity_key=key,
                    collector=store,
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
            .where(Snapshot.entity_key == key, Snapshot.collector == store)
            .order_by(Snapshot.scan_id.desc())
            .limit(1)
        ).scalar_one_or_none()
        s.add(Snapshot(scan_id=scan_id, entity_key=key, collector=store, sha256=sha))
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
        if body_sha256(prev) != sha and self._speaks_for(s, key, store):
            return collector.events(key, f.display_name, diff(prev, body))
        return []

    @staticmethod
    def _speaks_for(s: Session, key: str, store: str) -> bool:
        """Changes are reported by the strongest source of a Proxmox fact only, so a guest
        seen by the API and over SSH does not raise every event twice (ADR-031)."""
        if store not in PVE_FACETS:
            return True
        if store == PVE_SSH_PEER:
            return False  # a peer's view: running state unknown, the owner node reports
        stronger = PVE_FACETS[: PVE_FACETS.index(store)]
        return not any(s.get(Facet, (key, c)) is not None for c in stronger)

    def _removed(
        self, s: Session, r: CollectorResult, seen: set[tuple[str, str]], stores: set[str]
    ) -> list[EventSpec]:
        events: list[EventSpec] = []
        stale = [
            f
            for f in s.scalars(
                select(Facet).where(Facet.collector.in_(stores), Facet.target == r.target)
            ).all()
            if (f.entity_key, f.collector) not in seen
        ]
        still_reported = {key for key, _ in seen}
        for facet in stale:
            entity = s.get(Entity, facet.entity_key)
            # Moved to another facet name by this same run (e.g. linux-ssh -> pve-ssh): quiet.
            if (
                facet.data
                and entity is not None
                and facet.entity_key not in still_reported
                and self._speaks_for(s, facet.entity_key, facet.collector)
            ):
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
                        Facet.entity_key == facet.entity_key, Facet.collector != facet.collector
                    )
                ).first()
            ):
                entity.status = "gone"
            s.delete(facet)
        s.flush()
        return events
