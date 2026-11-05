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
from homelab_atlas.engine.incidents import full_mounts, open_incidents
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
    full: list[str] = []
    for v in views:
        if v.collector == "linux-ssh":
            full += [
                f"{t} on {v.target} ({pct}%)" for t, pct in full_mounts(v.data.get("mounts") or [])
            ]
    no_backup = sorted(
        str(v.data.get("name"))
        for v in views
        if v.collector == "proxmox"
        and "vmid" in v.data
        and v.data.get("backed_up") is False
        and not v.data.get("template")
    )
    warnings = list(
        s.scalars(
            select(Event.summary)
            .where(Event.created_at >= now - timedelta(hours=24), Event.severity == "warning")
            .order_by(Event.id.desc())
            .limit(6)
        )
    )
    incidents = open_incidents(s)
    media_states = [media.diagnose(s, inv, src, intervals, now) for src in inv.sources.jellyfin]
    evidence = [f"failing scans: {', '.join(failing[:8])}"] if failing else []
    evidence += [f"open incident: {i.title}" for i in incidents[:6]]
    evidence += [f"media {d.source}: {d.headline}" for d in media_states]
    evidence += [f"storage nearly full: {x}" for x in full[:4]]
    if no_backup:
        evidence.append(f"no backup job covers: {', '.join(no_backup[:10])}")
    evidence += [f"change (warning): {w}" for w in warnings]
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
            "storage_over_90pct": len(full),
            "guests_without_backup": len(no_backup),
        },
        evidence=evidence[:20],
    )
