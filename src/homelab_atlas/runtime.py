"""Wire config, storage, security and collectors into a runnable scan engine."""

import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from homelab_atlas.collectors.base import CollectContext, Collector
from homelab_atlas.collectors.linux_ssh.collector import LinuxSshCollector
from homelab_atlas.engine.scan import ScanEngine
from homelab_atlas.inventory.hosts import Inventory, load_inventory
from homelab_atlas.lab import load_lab
from homelab_atlas.redact import Redactor
from homelab_atlas.security.audit import AuditLog
from homelab_atlas.security.secrets import DEFAULT_DIRS, SecretResolver
from homelab_atlas.security.ssh import AsyncSshTransport, SshRunner, SshTransport
from homelab_atlas.store.db import make_engine, migrate, session_factory

LAB_DATA_DIR = Path("data/demo-lab")
COLLECTORS: tuple[Collector, ...] = (LinuxSshCollector(),)


def default_data_dir(*, lab: bool) -> Path:
    if lab:
        return LAB_DATA_DIR
    return Path(os.environ.get("ATLAS_DATA_DIR", "data"))


def config_dir() -> Path:
    return Path(os.environ.get("ATLAS_CONFIG_DIR", "config"))


def load_redaction_key(path: Path) -> bytes:
    """Per-installation HMAC key for redaction markers (created on first use, 0600)."""
    if path.is_file():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def wipe_lab_data(data_dir: Path) -> None:
    """--fresh: only ever deletes the lab data directory."""
    if data_dir.resolve() != LAB_DATA_DIR.resolve():
        raise ValueError("--fresh is only allowed for the demo lab data directory")
    shutil.rmtree(data_dir, ignore_errors=True)


@dataclass(slots=True)
class Runtime:
    data_dir: Path
    sessions: sessionmaker[Session]
    audit: AuditLog
    redactor: Redactor
    mode: str

    @classmethod
    def open(cls, data_dir: Path, *, mode: str) -> "Runtime":
        engine = make_engine(data_dir / "atlas.db")
        migrate(engine)
        return cls(
            data_dir=data_dir,
            sessions=session_factory(engine),
            audit=AuditLog(data_dir / "audit"),
            redactor=Redactor(load_redaction_key(data_dir / "redaction.key")),
            mode=mode,
        )

    def scan_engine(self, inventory: Inventory, transport: SshTransport) -> ScanEngine:
        runner = SshRunner(transport=transport, audit=self.audit)
        return ScanEngine(
            sessions=self.sessions,
            ctx=CollectContext(inventory=inventory, ssh=runner),
            collectors=COLLECTORS,
            redactor=self.redactor,
            lock_path=self.data_dir / "scan.lock",
            mode=self.mode,
        )


def lab_inputs(state: str) -> tuple[Inventory, SshTransport]:
    return load_lab(state)


def live_inputs() -> tuple[Inventory, SshTransport]:
    cfg = config_dir()
    inventory = load_inventory(cfg / "hosts.yaml")
    return inventory, AsyncSshTransport(SecretResolver(DEFAULT_DIRS))
