"""Daily homelab summary (ADR-040), sent to the n8n webhook once a day when configured.

Counts only, from stored data: scan health, open incidents, the last day's changes, storage
filling up, guests without backups, and the media diagnosis. No names of people, no secrets.
"""

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from homelab_atlas.engine import media
from homelab_atlas.engine.incidents import open_incidents
from homelab_atlas.engine.notify import Notification
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.store.facets import facet_views
from homelab_atlas.store.tables import CollectorRun, Event, Facet

FULL_PCT = 90


def daily_summary(
    s: Session, inv: Inventory, intervals: Mapping[str, int], now: datetime | None = None
) -> Notification:
    now = now or datetime.now(UTC)
    newest = (
        select(CollectorRun.target, CollectorRun.collector, func.max(CollectorRun.id).label("id"))
        .group_by(CollectorRun.target, CollectorRun.collector)
        .subquery()
    )
    runs = list(s.scalars(select(CollectorRun).join(newest, CollectorRun.id == newest.c.id)))
    failing = sorted(
        {f"{r.target} ({r.collector})" for r in runs if r.status in ("failed", "refused")}
    )
    events = dict(
        s.execute(
            select(Event.severity, func.count())
            .where(Event.created_at >= now - timedelta(hours=24))
            .group_by(Event.severity)
        ).all()
    )
    views = list(facet_views(s.scalars(select(Facet))))
    full = 0
    for v in views:
        for m in v.data.get("mounts") or [] if v.collector == "linux-ssh" else []:
            size, used = m.get("size_bytes"), m.get("used_bytes")
            if (
                isinstance(size, int)
                and size > 0
                and isinstance(used, int)
                and used * 100 >= size * FULL_PCT
            ):
                full += 1
    no_backup = sum(
        1
        for v in views
        if v.collector == "proxmox"
        and "vmid" in v.data
        and v.data.get("backed_up") is False
        and not v.data.get("template")
    )
    incidents = open_incidents(s)
    media_states = [media.diagnose(s, inv, src, intervals, now) for src in inv.sources.jellyfin]
    evidence = [f"failing: {', '.join(failing[:8])}"] if failing else []
    evidence += [f"incident: {i.title}" for i in incidents[:8]]
    evidence += [f"media {d.source}: {d.headline}" for d in media_states]
    worst: Literal["warning", "info"] = "warning" if failing or incidents else "info"
    return Notification(
        kind="summary.daily",
        title=(
            f"Homelab daily summary: {len(incidents)} open incidents, {len(failing)} failing scans"
        ),
        severity=worst,
        summary={
            "targets": len({r.target for r in runs}),
            "failing_scans": len(failing),
            "open_incidents": len(incidents),
            "changes_24h": sum(events.values()),
            "warnings_24h": int(events.get("warning", 0)),
            "storage_over_90pct": full,
            "guests_without_backup": no_backup,
        },
        evidence=evidence[:20],
    )
