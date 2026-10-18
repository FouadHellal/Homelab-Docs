"""Engine setup (SQLite WAL) and programmatic Alembic migrations."""

import os
from importlib.resources import files
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker


def _sqlite_pragmas(dbapi_conn: Any, _record: Any) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.close()


def make_engine(db_path: Path) -> Engine:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite+pysqlite:///{db_path.as_posix()}", future=True)
    event.listen(engine, "connect", _sqlite_pragmas)
    if os.name == "posix":
        db_path.touch(mode=0o600, exist_ok=True)
        db_path.chmod(0o600)  # the DB is a map of the network (THREAT-MODEL A3)
    return engine


def alembic_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(files("homelab_atlas.store") / "migrations"))
    return cfg


def migrate(engine: Engine) -> None:
    cfg = alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
