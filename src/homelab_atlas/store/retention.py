"""Snapshot retention (SPEC §8): events are kept forever, snapshots for N days.

The newest snapshot per (entity, collector) is always kept, whatever its age, so the diff
baseline survives. Blobs no snapshot references any more are deleted.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import CursorResult, Result, delete, func, select
from sqlalchemy.orm import Session

from homelab_atlas.store.tables import Blob, Scan, Snapshot

DEFAULT_SNAPSHOT_DAYS = 90


@dataclass(frozen=True, slots=True)
class PruneResult:
    snapshots: int
    blobs: int


def prune(
    s: Session, *, days: int = DEFAULT_SNAPSHOT_DAYS, now: datetime | None = None
) -> PruneResult:
    if days < 1:
        raise ValueError("retention must be at least one day")
    cutoff = (now or datetime.now(UTC)) - timedelta(days=days)
    newest = (
        select(func.max(Snapshot.id))
        .group_by(Snapshot.entity_key, Snapshot.collector)
        .scalar_subquery()
    )
    old_scans = select(Scan.id).where(Scan.started_at < cutoff).scalar_subquery()
    snaps = _count(
        s.execute(
            delete(Snapshot).where(Snapshot.scan_id.in_(old_scans), Snapshot.id.not_in(newest))
        )
    )
    blobs = _count(
        s.execute(delete(Blob).where(Blob.sha256.not_in(select(Snapshot.sha256).distinct())))
    )
    s.commit()
    return PruneResult(snapshots=snaps, blobs=blobs)


def _count(result: Result[Any]) -> int:
    return int(result.rowcount) if isinstance(result, CursorResult) else 0
