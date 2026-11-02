"""Incidents (ADR-040): ongoing conditions, deduplicated, with recovery and notifications.

Evaluated after every scan from data atlas already holds:

* `media.down:<jellyfin>`     the Jellyfin diagnosis says down (API or machine)
* `media.storage:<jellyfin>`  library folders not on mounted network storage, or NAS down
* `media.space:<jellyfin>`    a media mount below its free-space threshold
* `host.unreachable:<target>` a machine's SSH scan failed twice in a row
* `nas.pool:<nas>:<pool>`     a NAS pool not fully operational

One open incident per key. A condition that clears resolves it; one that comes back within
COOLDOWN reopens the same incident instead of starting a new one (no flapping spam).
Notifications: "opened" once the condition has lasted NOTIFY_AFTER (sustained, not a blip),
"resolved" only for incidents whose opening was announced.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from homelab_atlas.engine import media
from homelab_atlas.engine.notify import Notification
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.models.nas import POOL_NOTE, POOL_OK
from homelab_atlas.store.tables import CollectorRun, Facet, Incident

COOLDOWN: Final = timedelta(minutes=30)
NOTIFY_AFTER: Final = timedelta(minutes=5)
HOST_FAILURES: Final = 2


@dataclass(frozen=True, slots=True)
class Condition:
    key: str
    kind: str
    title: str
    severity: str
    entity_key: str | None
    evidence: tuple[str, ...]


def conditions(
    s: Session, inv: Inventory, intervals: Mapping[str, int], now: datetime
) -> list[Condition]:
    out: list[Condition] = []
    for src in inv.sources.jellyfin:
        d = media.diagnose(s, inv, src, intervals, now)
        ev = tuple(f"{c.label}: {c.state} - {c.detail}" for c in d.checks if c.state != "pass")
        if d.status == "down":
            out.append(
                Condition(
                    f"media.down:{src.name}",
                    "media.down",
                    d.headline,
                    "warning",
                    f"jellyfin:{src.name}",
                    ev,
                )
            )
        if d.condition in (4, 5) and any(c.id == "mounts" and c.state == "fail" for c in d.checks):
            out.append(
                Condition(
                    f"media.storage:{src.name}",
                    "media.storage",
                    d.headline,
                    "warning",
                    f"jellyfin:{src.name}",
                    ev,
                )
            )
        low = [x for x in d.storage if x.get("low")]
        if low:
            out.append(
                Condition(
                    f"media.space:{src.name}",
                    "media.space",
                    f"Media storage for {src.name} below {src.min_free_pct}% free",
                    "notice",
                    f"jellyfin:{src.name}",
                    tuple(f"{x['mount']}: {x['free_pct']}% free" for x in low),
                )
            )
    for h in inv.hosts:
        if "linux-ssh" not in h.collectors:
            continue
        runs = list(
            s.scalars(
                select(CollectorRun)
                .where(CollectorRun.target == h.name, CollectorRun.collector == "linux-ssh")
                .order_by(CollectorRun.id.desc())
                .limit(HOST_FAILURES)
            )
        )
        if len(runs) == HOST_FAILURES and all(r.status == "failed" for r in runs):
            errs = tuple(str(e) for e in (runs[0].errors or [])[:3])
            out.append(
                Condition(
                    f"host.unreachable:{h.name}",
                    "host.unreachable",
                    f"{h.name} does not answer SSH",
                    "warning",
                    None,
                    errs,
                )
            )
    for f in s.scalars(select(Facet).where(Facet.collector == "nas")):
        for p in f.data.get("pools") or []:
            if p.get("status") and p["status"] not in POOL_OK | POOL_NOTE:
                out.append(
                    Condition(
                        f"nas.pool:{f.target}:{p.get('id')}",
                        "nas.pool",
                        f"NAS pool {p.get('id')} is {p['status']}",
                        "warning",
                        f.entity_key,
                        (),
                    )
                )
    return out


def evaluate(
    s: Session, inv: Inventory, intervals: Mapping[str, int], now: datetime | None = None
) -> None:
    """Open, update, reopen or resolve incidents. The caller commits."""
    now = now or datetime.now(UTC)
    current = {c.key: c for c in conditions(s, inv, intervals, now)}
    open_rows = {
        i.key: i for i in s.scalars(select(Incident).where(Incident.resolved_at.is_(None)))
    }
    for key, c in current.items():
        row = open_rows.get(key)
        if row is None:
            recent = s.scalars(
                select(Incident)
                .where(Incident.key == key, Incident.resolved_at >= now - COOLDOWN)
                .order_by(Incident.id.desc())
                .limit(1)
            ).first()
            if recent is not None:  # flapping: reopen, keep its notification history
                recent.resolved_at = None
                row = recent
            else:
                row = Incident(
                    key=key,
                    kind=c.kind,
                    title=c.title[:256],
                    severity=c.severity,
                    entity_key=c.entity_key,
                    opened_at=now,
                )
                s.add(row)
        row.title = c.title[:256]
        row.severity = c.severity
        row.evidence = list(c.evidence)[:20]
        row.last_seen_at = now
    for key, row in open_rows.items():
        if key not in current:
            row.resolved_at = now  # cleared, or its source/host no longer exists


def _quiet(i: Incident, now: datetime) -> bool:
    """Acknowledged (no announcements or reminders) or snoozed (none until it ends)."""
    return i.acknowledged_at is not None or (i.snoozed_until is not None and i.snoozed_until > now)


def due_notifications(
    s: Session, now: datetime | None = None, reminder_hours: int = 24
) -> list[tuple[Incident, Notification]]:
    now = now or datetime.now(UTC)
    out: list[tuple[Incident, Notification]] = []
    for i in s.scalars(select(Incident).where(Incident.resolved_at.is_(None))):
        if _quiet(i, now):
            continue
        if i.notified_open_at is None:
            if now - i.opened_at >= NOTIFY_AFTER:
                out.append((i, _note("incident.opened", i)))
        elif reminder_hours > 0:
            last = i.last_reminded_at or i.notified_open_at
            if now - last >= timedelta(hours=reminder_hours):
                out.append((i, _note("incident.reminder", i)))
    for i in s.scalars(
        select(Incident).where(
            Incident.resolved_at.is_not(None),
            Incident.notified_open_at.is_not(None),
            Incident.notified_resolved_at.is_(None),
        )
    ):
        out.append((i, _note("incident.resolved", i)))
    return out


def mark_sent(i: Incident, note: Notification, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    if note.kind == "incident.opened":
        i.notified_open_at = now
    elif note.kind == "incident.reminder":
        i.last_reminded_at = now
    else:
        i.notified_resolved_at = now


def acknowledge(s: Session, incident_id: int, who: str, now: datetime | None = None) -> bool:
    i = s.get(Incident, incident_id)
    if i is None or i.resolved_at is not None:
        return False
    i.acknowledged_at, i.acknowledged_by = now or datetime.now(UTC), who[:64]
    return True


def snooze(s: Session, incident_id: int, hours: int, now: datetime | None = None) -> bool:
    """Silence an open incident for `hours` (0 = wake it up again)."""
    i = s.get(Incident, incident_id)
    if i is None or i.resolved_at is not None or not 0 <= hours <= 24 * 7:
        return False
    i.snoozed_until = (now or datetime.now(UTC)) + timedelta(hours=hours) if hours else None
    return True


def _note(kind: Any, i: Incident) -> Notification:
    prefix = {"incident.resolved": "Resolved: ", "incident.reminder": "Still open: "}
    return Notification(
        kind=kind,
        title=prefix.get(kind, "") + i.title,
        severity="info" if kind == "incident.resolved" else i.severity,  # type: ignore[arg-type]
        key=i.key,
        entity=i.entity_key,
        opened_at=i.opened_at.isoformat(),
        resolved_at=i.resolved_at.isoformat() if i.resolved_at else None,
        evidence=[str(e)[:400] for e in i.evidence or []][:20],
    )


def open_incidents(s: Session) -> list[Incident]:
    return list(
        s.scalars(
            select(Incident).where(Incident.resolved_at.is_(None)).order_by(Incident.opened_at)
        )
    )


def recent_incidents(s: Session, prefix: str | None = None, limit: int = 30) -> list[Incident]:
    stmt = select(Incident).order_by(Incident.id.desc()).limit(limit)
    if prefix:
        stmt = stmt.where(Incident.key.startswith(prefix))
    return list(s.scalars(stmt))
