from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, select, text

from homelab_atlas.store.db import make_engine, migrate, session_factory
from homelab_atlas.store.tables import Base, Scan


def test_migrations_match_models(tmp_path: Path) -> None:
    engine = make_engine(tmp_path / "atlas.db")
    migrate(engine)
    with engine.connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diffs == []
    assert set(inspect(engine).get_table_names()) >= {
        "scans", "collector_runs", "entities", "blobs", "snapshots", "facets", "events",
        "alembic_version",
    }  # fmt: skip


def test_migrate_is_idempotent_and_wal(tmp_path: Path) -> None:
    engine = make_engine(tmp_path / "atlas.db")
    migrate(engine)
    migrate(engine)
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_utc_roundtrip_and_naive_rejected(tmp_path: Path) -> None:
    engine = make_engine(tmp_path / "atlas.db")
    migrate(engine)
    sf = session_factory(engine)
    ts = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)
    with sf() as s:
        s.add(Scan(mode="demo", started_at=ts))
        s.commit()
        got = s.scalars(select(Scan)).one()
    assert got.started_at == ts
    assert got.started_at.tzinfo is not None
    with sf() as s:
        s.add(Scan(mode="demo", started_at=datetime(2026, 1, 1)))
        with pytest.raises(Exception, match="naive"):
            s.commit()
