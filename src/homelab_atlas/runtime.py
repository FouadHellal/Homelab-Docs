"""Wire config, storage, security and collectors into a runnable scan engine."""

import os
import re
import secrets
import shutil
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import SecretStr
from sqlalchemy.orm import Session, sessionmaker

from homelab_atlas.collectors.base import (
    ApiSource,
    AuthScheme,
    CollectContext,
    Collector,
    HttpFactory,
)
from homelab_atlas.collectors.docker.collector import DockerCollector
from homelab_atlas.collectors.linux_ssh.collector import LinuxSshCollector
from homelab_atlas.collectors.nas import NasCollector
from homelab_atlas.collectors.pi import PiCollector
from homelab_atlas.collectors.proxmox.collector import ProxmoxCollector
from homelab_atlas.collectors.unifi.collector import UnifiCollector
from homelab_atlas.engine.scan import ScanEngine
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.inventory.managed import CA_DIR, effective_inventory
from homelab_atlas.lab import lab_root, load_api_recordings, load_lab
from homelab_atlas.probe.render import render_probe
from homelab_atlas.redact import Redactor
from homelab_atlas.security.allowlist import Endpoint
from homelab_atlas.security.audit import AuditLog, AuditSink
from homelab_atlas.security.errors import RefusalReason, SecurityRefusal
from homelab_atlas.security.http import AuthHeader, ReadOnlyHttpClient, TlsPolicy, replay_transport
from homelab_atlas.security.secrets import DEFAULT_DIRS, SecretResolver
from homelab_atlas.security.ssh import AsyncSshTransport, SecretSource, SshRunner, SshTransport
from homelab_atlas.security.vault import ChainedSecrets, Vault, load_master_key
from homelab_atlas.store.db import make_engine, migrate, session_factory

LAB_DATA_DIR = Path("data/demo-lab")
VAULT_FILE = "vault.json"
COLLECTORS: tuple[Collector, ...] = (
    LinuxSshCollector(),
    DockerCollector(),
    PiCollector(),
    ProxmoxCollector(),
    UnifiCollector(),
    NasCollector(),
)


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

    def scan_engine(self, inputs: "Inputs") -> ScanEngine:
        runner = SshRunner(transport=inputs.ssh, audit=self.audit)
        return ScanEngine(
            sessions=self.sessions,
            ctx=CollectContext(
                inventory=inputs.inventory,
                ssh=runner,
                http=inputs.http(self.audit),
                config_dir=inputs.config_dir,
            ),
            collectors=COLLECTORS,
            redactor=self.redactor,
            lock_path=self.data_dir / "scan.lock",
            mode=self.mode,
        )


@dataclass(frozen=True, slots=True)
class Inputs:
    inventory: Inventory
    ssh: SshTransport
    #: Given the audit sink, returns the factory that builds API clients.
    http: Callable[[AuditSink], HttpFactory]
    config_dir: Path | None = None


PVE_TOKEN_RE = re.compile(
    r"[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,64}![A-Za-z0-9._-]{1,64}=[0-9a-fA-F-]{36}"
)
CA_FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def auth_header(scheme: AuthScheme, secret: SecretStr) -> AuthHeader:
    if scheme == "pve-token":
        token = secret.get_secret_value()
        if not PVE_TOKEN_RE.fullmatch(token):
            raise SecurityRefusal(
                RefusalReason.CONFIG, "PVE token must look like user@realm!id=<uuid>"
            )
        return AuthHeader("Authorization", SecretStr(f"PVEAPIToken={token}"))
    return AuthHeader("X-API-KEY", secret)


def live_http(secrets: SecretSource, ca_dirs: Sequence[Path]) -> Callable[[AuditSink], HttpFactory]:
    def bind(audit: AuditSink) -> HttpFactory:
        def make(source: ApiSource, endpoints: Iterable[Endpoint]) -> ReadOnlyHttpClient:
            if source.tls.ca_file is None or not CA_FILE_RE.fullmatch(source.tls.ca_file):
                raise SecurityRefusal(
                    RefusalReason.TLS_POLICY,
                    f"{source.name}: tls.ca_file (a file in the config dir) is required",
                )
            tls = TlsPolicy(
                ca_file=_find_ca(ca_dirs, source.tls.ca_file),
                check_hostname=source.tls.check_hostname,
                sha256_pin=source.tls.sha256_pin,
            )
            return ReadOnlyHttpClient(
                target=source.name,
                base_url=source.url,
                endpoints=endpoints,
                audit=audit,
                tls=tls,
                auth=auth_header(source.auth, secrets.resolve(source.credential)),
            )

        return make

    return bind


def replay_http(
    recordings: Mapping[str, Mapping[str, tuple[int, bytes]]],
) -> Callable[[AuditSink], HttpFactory]:
    def bind(audit: AuditSink) -> HttpFactory:
        def make(source: ApiSource, endpoints: Iterable[Endpoint]) -> ReadOnlyHttpClient:
            return ReadOnlyHttpClient(
                target=source.name,
                base_url=source.url,
                endpoints=endpoints,
                audit=audit,
                tls=None,
                auth=AuthHeader("Authorization", SecretStr("PVEAPIToken=demo")),
                transport=replay_transport(recordings.get(source.name, {})),
            )

        return make

    return bind


def lab_inputs(state: str) -> Inputs:
    inventory, transport = load_lab(state)
    return Inputs(inventory, transport, replay_http(load_api_recordings(state)), lab_root())


def _find_ca(dirs: Sequence[Path], name: str) -> Path:
    """hosts.yaml CA files live in the config dir, UI-pinned ones in <data>/ca (ADR-025)."""
    for d in dirs:
        if (d / name).is_file():
            return d / name
    return dirs[0] / name


def live_secrets(data_dir: Path) -> ChainedSecrets:
    """Docker secrets / secrets dir first, then the encrypted UI vault."""
    operator = SecretResolver(DEFAULT_DIRS)
    vault = Vault(data_dir / VAULT_FILE, load_master_key(data_dir, operator))
    return ChainedSecrets(operator, vault)


def live_inputs(data_dir: Path | None = None) -> Inputs:
    cfg = config_dir()
    ddir = data_dir or default_data_dir(lab=False)
    inventory, _ = effective_inventory(cfg, ddir)
    secrets = live_secrets(ddir)
    return Inputs(
        inventory,
        AsyncSshTransport(secrets, render_probe()),
        live_http(secrets, [cfg, ddir / CA_DIR]),
        cfg,
    )


async def test_ssh_login(data_dir: Path, audit: AuditSink, name: str) -> tuple[bool, str]:
    """Targets page "Test login": one SSH connection running the `version` section."""
    from homelab_atlas.collectors.linux_ssh.frame import FrameError, parse_frame  # noqa: PLC0415
    from homelab_atlas.security.allowlist import ProbeSection  # noqa: PLC0415
    from homelab_atlas.security.errors import TransportError  # noqa: PLC0415

    try:
        inputs = live_inputs(data_dir)
        host = inputs.inventory.host(name)
    except KeyError:
        return False, f"{name}: not in the inventory"
    except (ValueError, OSError) as exc:
        return False, f"inventory or secrets unreadable: {type(exc).__name__}"
    if not {"linux-ssh", "docker", "pi"} & set(host.collectors):
        return False, f"{name}: no SSH collectors selected"
    target = inputs.inventory.ssh_target(host, frozenset({ProbeSection.VERSION}))
    runner = SshRunner(transport=inputs.ssh, audit=audit)
    try:
        out = await runner.run(target, ProbeSection.VERSION)
    except SecurityRefusal as exc:
        return False, f"refused: {exc.reason.value}"
    except TransportError as exc:
        return False, str(exc)[:200]
    if out.exit_status != 0:
        return False, f"logged in, but the probe exited {out.exit_status}"
    try:
        frame = parse_frame(out.stdout, ProbeSection.VERSION)
    except FrameError as exc:
        return False, f"logged in, but the output was not understood: {exc}"[:200]
    version = (frame.text("version") or "?").strip()
    mode = "streamed, nothing installed" if target.auth == "password" else "installed probe"
    return True, f"logged in as {target.username}; probe {version[:16]} ({mode})"
