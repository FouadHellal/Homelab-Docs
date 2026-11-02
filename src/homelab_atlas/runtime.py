"""Wire config, storage, security and collectors into a runnable scan engine."""

import os
import re
import secrets
import shutil
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import structlog
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
from homelab_atlas.collectors.jellyfin import SYSTEM_INFO as JF_SYSTEM_INFO
from homelab_atlas.collectors.jellyfin import JellyfinCollector
from homelab_atlas.collectors.linux_ssh.collector import LinuxSshCollector
from homelab_atlas.collectors.nas import NasCollector
from homelab_atlas.collectors.pi import PiCollector
from homelab_atlas.collectors.proxmox.collector import ProxmoxCollector
from homelab_atlas.collectors.unifi.collector import UnifiCollector
from homelab_atlas.collectors.unifi.sitemanager import CLOUD_MIN_INTERVAL_S
from homelab_atlas.engine.notify import (
    TOKEN_SECRET,
    WebhookNotifier,
    notify_rules,
    webhook_from_env,
    webhook_settings,
)
from homelab_atlas.engine.scan import ScanEngine
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.inventory.managed import CA_DIR, effective_inventory
from homelab_atlas.lab import lab_root, load_api_recordings, load_lab
from homelab_atlas.probe.render import render_probe
from homelab_atlas.redact import Redactor
from homelab_atlas.security.allowlist import Endpoint
from homelab_atlas.security.audit import AuditLog, AuditSink
from homelab_atlas.security.errors import RefusalReason, SecurityRefusal
from homelab_atlas.security.http import (
    AuthHeader,
    HttpLimits,
    ReadOnlyHttpClient,
    TlsPolicy,
    replay_transport,
)
from homelab_atlas.security.secrets import DEFAULT_DIRS, SecretResolver
from homelab_atlas.security.ssh import AsyncSshTransport, SecretSource, SshRunner, SshTransport
from homelab_atlas.security.vault import ChainedSecrets, Vault, load_master_key
from homelab_atlas.store.db import make_engine, migrate, session_factory

log = structlog.get_logger()
LAB_DATA_DIR = Path("data/demo-lab")
VAULT_FILE = "vault.json"
COLLECTORS: tuple[Collector, ...] = (
    LinuxSshCollector(),
    DockerCollector(),
    PiCollector(),
    ProxmoxCollector(),
    UnifiCollector(),
    NasCollector(),
    JellyfinCollector(),
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
            intervals=safe_intervals(),
            notifier=self.notifier(),
        )

    def notifier(self) -> WebhookNotifier | None:
        """The n8n webhook notifier when ATLAS_N8N_WEBHOOK_URL is set (live mode only)."""
        if self.mode != "live":
            return None
        try:
            cfg = webhook_from_env(os.environ, [config_dir()]) or webhook_settings(self.data_dir)
        except ValueError as exc:
            log.warning("notify.config_invalid", reason=str(exc))
            return None
        if cfg is None:
            return None
        token = None
        try:
            token = live_secrets(self.data_dir).resolve(TOKEN_SECRET)
        except (KeyError, OSError, ValueError):
            log.warning("notify.no_token", secret=TOKEN_SECRET)
        return WebhookNotifier(
            cfg, token, self.audit, redactor=self.redactor, rules=notify_rules(self.data_dir)
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
JELLYFIN_KEY_RE = re.compile(r"[0-9a-fA-F]{32}")


def auth_header(scheme: AuthScheme, secret: SecretStr) -> AuthHeader:
    if scheme == "pve-token":
        token = secret.get_secret_value()
        if not PVE_TOKEN_RE.fullmatch(token):
            raise SecurityRefusal(
                RefusalReason.CONFIG, "PVE token must look like user@realm!id=<uuid>"
            )
        return AuthHeader("Authorization", SecretStr(f"PVEAPIToken={token}"))
    if scheme == "jellyfin-token":
        key = secret.get_secret_value().strip()
        if not JELLYFIN_KEY_RE.fullmatch(key):
            raise SecurityRefusal(RefusalReason.CONFIG, "Jellyfin API key must be 32 hex digits")
        # The documented scheme (Jellyfin OpenAPI securitySchemes: header Authorization).
        return AuthHeader("Authorization", SecretStr(f'MediaBrowser Token="{key}"'))
    if scheme == "bearer":
        return AuthHeader("Authorization", SecretStr(f"Bearer {secret.get_secret_value().strip()}"))
    return AuthHeader("X-API-KEY", secret)


def live_http(secrets: SecretSource, ca_dirs: Sequence[Path]) -> Callable[[AuditSink], HttpFactory]:
    def bind(audit: AuditSink) -> HttpFactory:
        def make(source: ApiSource, endpoints: Iterable[Endpoint]) -> ReadOnlyHttpClient:
            limits = None
            tls: TlsPolicy | None
            if source.plain_http_lan:  # owner opt-in, private IP literal only (ADR-039)
                tls = None
            elif source.tls.public_pki:  # UniFi cloud connector only (validated by the model)
                tls = TlsPolicy(ca_file=None, public_pki=True)
                limits = HttpLimits(min_interval_s=CLOUD_MIN_INTERVAL_S)
            else:
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
                limits=limits,
                plain_http_lan=source.plain_http_lan,
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
                plain_http_lan=source.plain_http_lan,
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


def safe_intervals() -> dict[str, int]:
    from homelab_atlas.scheduler import DEFAULT_INTERVALS_S, intervals_from_env  # noqa: PLC0415

    try:
        return intervals_from_env()
    except ValueError:
        return dict(DEFAULT_INTERVALS_S)


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


async def test_source(data_dir: Path, audit: AuditSink, kind: str, name: str) -> tuple[bool, str]:
    """Targets page "Test connection" for Proxmox / UniFi: one GET of the version endpoint."""
    from homelab_atlas.collectors.proxmox import endpoints as pve_ep  # noqa: PLC0415
    from homelab_atlas.collectors.unifi import endpoints as unifi_ep  # noqa: PLC0415
    from homelab_atlas.security.errors import HttpStatusError, TransportError  # noqa: PLC0415

    try:
        inputs = live_inputs(data_dir)
        if kind == "proxmox":
            source, ep = ProxmoxCollector.source(inputs.inventory, name), pve_ep.VERSION
        elif kind == "unifi":
            source, ep = UnifiCollector.source(inputs.inventory, name), unifi_ep.INFO
        elif kind == "jellyfin":
            source, ep = JellyfinCollector.source(inputs.inventory, name), JF_SYSTEM_INFO
        else:
            return False, "no connection test for this kind yet; use Scan"
    except StopIteration:
        return False, f"{name}: not in the inventory"
    except (KeyError, ValueError, OSError) as exc:
        return False, f"{name}: not usable ({type(exc).__name__})"
    visible: int | None = None
    try:
        if kind == "proxmox":
            async with inputs.http(audit)(source, {ep, pve_ep.RESOURCES}) as client:
                res = await client.get(ep)
                rows = (await client.get(pve_ep.RESOURCES)).json()
            data_rows = rows.get("data") if isinstance(rows, dict) else None
            visible = sum(
                1
                for r in data_rows or []
                if isinstance(r, dict) and r.get("type") in ("node", "qemu", "lxc")
            )
        else:
            async with inputs.http(audit)(source, {ep}) as client:
                res = await client.get(ep)
    except SecurityRefusal as exc:
        return False, f"refused: {exc.reason.value} {exc.detail or ''}"[:200]
    except HttpStatusError as exc:
        hint = " (key/token refused)" if exc.status in (401, 403) else ""
        return False, f"HTTP {exc.status}{hint}"
    except TransportError as exc:
        return False, str(exc)[:200]
    body = res.json()
    data = body.get("data", body) if isinstance(body, dict) else {}
    version = (
        (data.get("version") or data.get("applicationVersion") or data.get("Version") or "?")
        if isinstance(data, dict)
        else "?"
    )
    if visible == 0:
        from homelab_atlas.collectors.proxmox.collector import NO_VISIBILITY  # noqa: PLC0415

        return False, f"connected (version {str(version)[:24]}), but {NO_VISIBILITY}"
    seen = f"; sees {visible} nodes and guests" if visible else ""
    return True, f"connected; {kind} version {str(version)[:24]}{seen}"


async def jellyfin_live(
    inputs: Inputs, audit: AuditSink, name: str, *, show_names: bool = False
) -> dict[str, object]:
    """Media page live view: one GET /Sessions through the read-only client. Never stored.

    Real user names leave this function only when the owner enabled them
    (ATLAS_MEDIA_SHOW_USERS=1); otherwise sessions carry the same pseudonyms as stored facts.
    """
    from homelab_atlas.collectors import jellyfin as jf  # noqa: PLC0415
    from homelab_atlas.security.errors import HttpStatusError, TransportError  # noqa: PLC0415

    try:
        source = jf.JellyfinCollector.source(inputs.inventory, name)
    except StopIteration:
        return {"ok": False, "error": f"{name}: not configured"}
    try:
        async with inputs.http(audit)(source, {jf.SYSTEM_INFO, jf.SESSIONS}) as client:
            info = (await client.get(jf.SYSTEM_INFO)).json()
            raw = (
                await client.get(jf.SESSIONS, None, {"activeWithinSeconds": jf.ACTIVE_WITHIN_S})
            ).json()
    except SecurityRefusal as exc:
        return {"ok": False, "error": f"refused: {exc.reason.value}"}
    except HttpStatusError as exc:
        return {"ok": False, "error": jf.http_hint(exc.status)}
    except TransportError as exc:
        return {"ok": False, "error": f"unreachable: {exc}"[:200]}
    except ValueError:
        return {"ok": False, "error": "Jellyfin did not answer with JSON"}
    server = str(info.get("Id") or name) if isinstance(info, dict) else name
    sessions = jf.sessions(server, raw)
    names: dict[str, str] = {}
    if show_names and isinstance(raw, list):
        for r in raw:
            if isinstance(r, dict) and isinstance(r.get("UserName"), str):
                names[jf.pseudonym(server, r.get("UserId"))] = r["UserName"][:64]
    return {"ok": True, "sessions": [x.model_dump() for x in sessions], "names": names}
