"""Database schema (SQLAlchemy 2). Portable types only, so Postgres stays an option (ADR-012).

Every JSON body stored here has already been through the Redactor.
"""

from datetime import UTC, datetime
from typing import Any, ClassVar

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator[datetime]):
    """Store naive UTC, return aware UTC (SQLite has no timezone support)."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return value.replace(tzinfo=UTC) if value is not None else None


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    type_annotation_map: ClassVar[dict[Any, Any]] = {
        datetime: UTCDateTime(),
        dict[str, Any]: JSON,
        list[Any]: JSON,
    }


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    mode: Mapped[str] = mapped_column(String(16))  # demo | live
    label: Mapped[str | None] = mapped_column(String(64), default=None)
    status: Mapped[str] = mapped_column(String(16), default="running")


class CollectorRun(Base):
    __tablename__ = "collector_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    target: Mapped[str] = mapped_column(String(128))
    collector: Mapped[str] = mapped_column(String(32))
    entity_key: Mapped[str | None] = mapped_column(String(256), default=None)
    status: Mapped[str] = mapped_column(String(16))  # ok | partial | failed | refused
    errors: Mapped[list[Any]] = mapped_column(default=list)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (Index("ix_collector_runs_target", "target", "collector", "scan_id"),)


class Entity(Base):
    __tablename__ = "entities"
    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    display_name: Mapped[str] = mapped_column(String(256))
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)
    status: Mapped[str] = mapped_column(String(16), default="known")
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), default=None)
    #: Topology parent: container -> host, guest -> node, node -> cluster.
    parent_key: Mapped[str | None] = mapped_column(String(256), default=None, index=True)


class Blob(Base):
    """Content-addressed canonical snapshot bodies (volatile fields stripped)."""

    __tablename__ = "blobs"
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    body: Mapped[dict[str, Any]] = mapped_column()


class Snapshot(Base):
    __tablename__ = "snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    entity_key: Mapped[str] = mapped_column(ForeignKey("entities.key"))
    collector: Mapped[str] = mapped_column(String(32))
    sha256: Mapped[str] = mapped_column(ForeignKey("blobs.sha256"))
    __table_args__ = (
        UniqueConstraint("scan_id", "entity_key", "collector"),
        Index("ix_snapshots_entity", "entity_key", "collector", "scan_id"),
    )


class Facet(Base):
    """Latest full (redacted, volatile included) state per entity and collector."""

    __tablename__ = "facets"
    entity_key: Mapped[str] = mapped_column(ForeignKey("entities.key"), primary_key=True)
    collector: Mapped[str] = mapped_column(String(32), primary_key=True)
    #: The collector target that reports this entity (host name or API source name).
    target: Mapped[str] = mapped_column(String(128), default="", server_default="", index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    data: Mapped[dict[str, Any]] = mapped_column()


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    entity_key: Mapped[str] = mapped_column(String(256), index=True)
    type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(String(512), default="")
    old: Mapped[Any] = mapped_column(JSON, default=None, nullable=True)
    new: Mapped[Any] = mapped_column(JSON, default=None, nullable=True)
    summary: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
