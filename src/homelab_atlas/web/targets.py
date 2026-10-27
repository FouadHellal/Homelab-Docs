"""Targets page backend (ADR-025): add VMs, Proxmox, UniFi and UNAS from the UI.

* Entries go to the app-managed `<data>/inventory.yaml`; hosts.yaml entries are shown
  read-only. Validation is the same strict model the loader uses.
* Credentials go straight into the encrypted vault and are never rendered back: the form
  only says "set" / "not set", and an empty field keeps the stored value.
* Host keys and TLS certificates are fetched from the target, shown as fingerprints and only
  pinned after the owner ticks "I checked this fingerprint".
* Every change is written to the audit log (names only, never values).
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from pydantic import SecretStr, ValidationError

from homelab_atlas.collectors.unifi import endpoints as unifi_ep
from homelab_atlas.collectors.unifi import sitemanager as sm
from homelab_atlas.inventory.hosts import (
    HostEntry,
    Inventory,
    InventoryError,
    ProxmoxSource,
    SshSettings,
    TlsSettings,
    UnasSource,
    UnifiSource,
)
from homelab_atlas.inventory.managed import (
    SOURCE_MODELS,
    ManagedInventory,
    SourceKind,
    effective_inventory,
    secret_name,
)
from homelab_atlas.security import discover
from homelab_atlas.security.audit import AuditEvent, AuditSink
from homelab_atlas.security.errors import HttpStatusError, TransportError
from homelab_atlas.security.http import AuthHeader, HttpLimits, ReadOnlyHttpClient, TlsPolicy
from homelab_atlas.security.ssh_keys import ATLAS_KEY_SECRET, generate_client_key, public_line
from homelab_atlas.security.vault import Vault

HOST_TYPES: Final = ("linux", "pi", "proxmox-node", "nas", "manual")
HOST_COLLECTORS: Final = ("linux-ssh", "docker", "pi")
PVE_TOKEN_RE: Final = re.compile(
    r"[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,64}![A-Za-z0-9._-]{1,64}=[0-9a-fA-F-]{36}"
)
HOSTPORT_RE: Final = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}(:\d{1,5})?|\[[0-9A-Fa-f:.]{2,45}\](:\d{1,5})?"
)


class TargetError(ValueError):
    """A user-facing validation message (safe to show; never contains secret values)."""


@dataclass(slots=True)
class HostForm:
    name: str
    address: str
    type: str = "linux"
    collectors: list[str] = field(default_factory=lambda: ["linux-ssh", "docker"])
    user: str = ""
    port: int = 22
    #: password | key (atlas key, nothing installed) | key-installed (forced-command probe)
    auth: Literal["password", "key", "key-installed"] = "password"
    sudo: bool = True
    key_name: str = ""
    host_key: str = ""
    host_key_confirmed: bool = False
    original: str = ""


@dataclass(slots=True)
class SourceForm:
    kind: SourceKind
    name: str
    url: str
    cert_pem: str = ""
    cert_sha256: str = ""
    cert_confirmed: bool = False
    original: str = ""
    #: UniFi only: "local" (gateway API) or "cloud" (unifi.ui.com key via the connector)
    connection: Literal["local", "cloud"] = "local"
    console_id: str = ""


def normalize_url(kind: str, value: str) -> str:
    """Accept a bare IP/host name and fill in the API path, or a full https:// URL."""
    value = value.strip()
    if not value:
        raise TargetError("address or URL is required")
    if "://" not in value:
        host = value.strip("/")
        if not HOSTPORT_RE.fullmatch(host):
            raise TargetError("enter an IP, a host name or a full https:// URL")
        if kind == "proxmox":
            return f"https://{host}{'' if re.search(r':\d+$', host) else ':8006'}/api2/json"
        if kind == "unifi":
            return f"https://{host}/proxy/network/integration"
        return f"https://{host}"
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname:
        raise TargetError("the URL must start with https://")
    return value.rstrip("/")


def _errors(exc: ValidationError) -> str:
    msgs = []
    for e in exc.errors()[:3]:
        loc = ".".join(str(x) for x in e["loc"] if not isinstance(x, int))
        msgs.append(f"{loc}: {e['msg']}" if loc else str(e["msg"]))
    return "; ".join(msgs)


class TargetsService:
    def __init__(
        self,
        *,
        config_dir: Path,
        data_dir: Path,
        vault: Vault | None,
        audit: AuditSink,
        readonly_inventory: Inventory | None = None,
        transport: Any = None,
    ) -> None:
        self._config_dir = config_dir
        self._store = ManagedInventory(data_dir)
        self._vault = vault
        self._audit = audit
        #: Demo lab: show its inventory, refuse edits.
        self._readonly = readonly_inventory
        #: Tests only: an httpx transport (security.http.replay_transport) for cloud calls.
        self._transport = transport

    @property
    def editable(self) -> bool:
        return self._readonly is None and self._vault is not None

    # ------------------------------------------------------------------ read

    def inventory(self) -> tuple[Inventory, set[str]]:
        if self._readonly is not None:
            inv = self._readonly
            names = {h.name for h in inv.hosts}
            for kind in SOURCE_MODELS:
                names |= {f"{kind}:{s.name}" for s in getattr(inv.sources, kind)}
            return inv, names
        return effective_inventory(self._config_dir, self._store.path.parent)

    def has_secret(self, name: str | None) -> bool:
        if not name or self._vault is None:
            return False
        try:
            return self._vault.has(name)
        except Exception:  # noqa: BLE001 - a status hint only
            return False

    def atlas_public_key(self, *, create: bool = False) -> str | None:
        """Public half of atlas's own SSH key (generated into the vault on first use)."""
        if self._vault is None:
            return None
        if not self._vault.has(ATLAS_KEY_SECRET):
            if not create or not self.editable:
                return None
            self._vault.put(ATLAS_KEY_SECRET, SecretStr(generate_client_key().decode()))
            self._record("ui.secret.set", ATLAS_KEY_SECRET)
        return public_line(self._vault.resolve_bytes(ATLAS_KEY_SECRET))

    def view(self) -> dict[str, Any]:
        inv, fixed = self.inventory()
        hosts = [
            {
                "entry": h,
                "auth": inv.auth_of(h),
                "fixed": h.name in fixed,
                "secret_set": self.has_secret(h.ssh.password)
                if inv.auth_of(h) == "password"
                else bool(h.ssh.key or inv.defaults.ssh.key),
                "pinned": bool(h.ssh.host_keys),
            }
            for h in sorted(inv.hosts, key=lambda h: h.name.lower())
        ]
        sources = {
            kind: [
                {
                    "source": s,
                    "fixed": f"{kind}:{s.name}" in fixed,
                    "secret_set": self.has_secret(s.credential) or f"{kind}:{s.name}" in fixed,
                }
                for s in getattr(inv.sources, kind)
            ]
            for kind in SOURCE_MODELS
        }
        return {"hosts": hosts, "sources": sources, "editable": self.editable}

    def host(self, name: str) -> HostEntry | None:
        inv, _ = self.inventory()
        return next((h for h in inv.hosts if h.name == name), None)

    def source(self, kind: SourceKind, name: str) -> Any:
        inv, _ = self.inventory()
        return next((s for s in getattr(inv.sources, kind) if s.name == name), None)

    # ------------------------------------------------------------------ write

    def _require_editable(self, name: str, kind: str = "host") -> None:
        if not self.editable:
            raise TargetError("read-only here (demo lab, or no vault)")
        _, fixed = self.inventory()
        if (name if kind == "host" else f"{kind}:{name}") in fixed:
            raise TargetError(f"{name} comes from hosts.yaml; edit it there")

    def _record(self, op: str, target: str) -> None:
        self._audit.record(
            AuditEvent(target=target[:128], transport="ui", op=op, outcome="ok", duration_ms=0)
        )

    def _refuse_taken(self, names: Iterable[str], name: str, original: str) -> None:
        """Adding, or renaming onto, an existing name would silently replace that target."""
        if name.lower() != original.lower() and name.lower() in {n.lower() for n in names}:
            raise TargetError(f"{name} already exists; pick another name or edit that one")

    def save_host(self, form: HostForm, password: SecretStr | None) -> HostEntry:
        self._require_editable(form.name)
        if form.original and form.original != form.name:
            self._require_editable(form.original)
        inv, _ = self.inventory()
        self._refuse_taken((h.name for h in inv.hosts), form.name, form.original)
        existing = self.host(form.original or form.name)
        keys = existing.ssh.host_keys if existing else ()
        collectors = [c for c in form.collectors if c in HOST_COLLECTORS]
        if form.host_key:
            if not form.host_key_confirmed:
                raise TargetError("tick “I checked this fingerprint” to pin the host key")
            keys = (form.host_key.strip(),)
        if collectors and not keys:
            raise TargetError("fetch and confirm the SSH host key first")
        pw_name = secret_name("ssh", form.name)
        key_mode = form.auth in ("key", "key-installed")
        if collectors and key_mode and not form.key_name:
            self.atlas_public_key(create=True)
        if collectors and form.auth == "password":
            have = self.has_secret(pw_name) or (
                existing is not None and self.has_secret(existing.ssh.password)
            )
            if password is None and not have:
                raise TargetError("enter the SSH password")
        try:
            ssh = SshSettings(
                user=form.user or None,
                auth="key" if key_mode else "password",
                password=pw_name if form.auth == "password" else None,
                key=(form.key_name or ATLAS_KEY_SECRET) if key_mode else None,
                probe=("installed" if form.auth == "key-installed" else "streamed")
                if key_mode
                else None,
                sudo=form.sudo if form.auth == "password" else None,
                port=form.port if form.port != 22 else None,
                host_keys=keys,
            )
            entry = HostEntry(
                name=form.name,
                address=form.address,
                type=form.type,  # type: ignore[arg-type]
                collectors=tuple(collectors),  # type: ignore[arg-type]
                ssh=ssh,
            )
        except ValidationError as exc:
            raise TargetError(_errors(exc)) from None
        assert self._vault is not None  # noqa: S101 - editable implies a vault
        moved_from = None
        if form.auth == "password" and password is not None:
            self._vault.put(pw_name, password)
            self._record("ui.secret.set", pw_name)
        elif (
            form.auth == "password"
            and existing is not None
            and existing.ssh.password
            and existing.ssh.password != pw_name
            and self.has_secret(existing.ssh.password)
        ):
            # Renamed host: copy the stored password to the new name (old one dropped below).
            self._vault.put(pw_name, self._vault.resolve(existing.ssh.password))
            moved_from = existing.ssh.password
        try:
            self._store.upsert_host(entry, replaces=form.original or None)
        except (ValueError, InventoryError) as exc:
            msg = _errors(exc) if isinstance(exc, ValidationError) else str(exc)
            raise TargetError(msg) from None
        if moved_from is not None:
            self._vault.delete(moved_from)
        if key_mode and self.has_secret(pw_name):
            self._vault.delete(pw_name)
        self._record("ui.host.save", form.name)
        return entry

    def delete_host(self, name: str) -> None:
        self._require_editable(name)
        self._store.delete_host(name)
        assert self._vault is not None  # noqa: S101
        self._vault.delete(secret_name("ssh", name))
        self._record("ui.host.delete", name)

    def save_source(self, form: SourceForm, credential: SecretStr | None) -> Any:
        self._require_editable(form.name, form.kind)
        if form.original and form.original != form.name:
            self._require_editable(form.original, form.kind)
        inv, _ = self.inventory()
        taken = (s.name for s in getattr(inv.sources, form.kind))
        self._refuse_taken(taken, form.name, form.original)
        cloud = form.kind == "unifi" and form.connection == "cloud"
        url = form.url if cloud else normalize_url(form.kind, form.url)
        existing = self.source(form.kind, form.original or form.name)
        tls = existing.tls if existing and not cloud else TlsSettings()
        if cloud:
            if not form.console_id or not url.startswith("https://api.ui.com/"):
                raise TargetError("click “Find my consoles” and pick your gateway first")
            tls = TlsSettings(public_pki=True)
        elif tls.public_pki:
            tls = TlsSettings()
        if form.cert_pem and not cloud:
            if not form.cert_confirmed:
                raise TargetError("tick “I checked this fingerprint” to pin the certificate")
            if not re.fullmatch(r"[0-9a-f]{64}", form.cert_sha256):
                raise TargetError("certificate fingerprint missing; fetch it again")
            ca_file = self._store.save_certificate(form.name, form.cert_pem)
            tls = TlsSettings(ca_file=ca_file, check_hostname=False, sha256_pin=form.cert_sha256)
        if tls.ca_file is None and not tls.public_pki:
            raise TargetError("fetch and confirm the server certificate first")
        cred_name = secret_name(form.kind, form.name)
        if credential is not None:
            value = credential.get_secret_value().strip()
            if form.kind == "proxmox" and not PVE_TOKEN_RE.fullmatch(value):
                raise TargetError("Proxmox token must look like user@realm!tokenid=<uuid>")
            credential = SecretStr(value)
        elif not self.has_secret(cred_name) and not (
            existing and self.has_secret(existing.credential)
        ):
            raise TargetError("enter the API token / key")
        try:
            model = SOURCE_MODELS[form.kind]
            extra: dict[str, Any] = {"drive_api": True} if form.kind == "unas" else {}
            if cloud:
                extra = {"connection": "cloud", "console_id": form.console_id}
            source = model(name=form.name, url=url, credential=cred_name, tls=tls, **extra)
        except ValidationError as exc:
            raise TargetError(_errors(exc)) from None
        assert self._vault is not None  # noqa: S101
        moved_from = None
        if credential is not None:
            self._vault.put(cred_name, credential)
            self._record("ui.secret.set", cred_name)
        elif existing is not None and existing.credential and existing.credential != cred_name:
            self._vault.put(cred_name, self._vault.resolve(existing.credential))
            moved_from = existing.credential
        try:
            self._store.upsert_source(form.kind, source)
        except (ValueError, InventoryError) as exc:
            raise TargetError(str(exc)[:300]) from None
        # Only once the new entry is stored: drop the renamed one and its old credential.
        if form.original and form.original != form.name:
            self._store.delete_source(form.kind, form.original)
        if moved_from is not None:
            self._vault.delete(moved_from)
        self._record(f"ui.{form.kind}.save", form.name)
        return source

    def delete_source(self, kind: SourceKind, name: str) -> None:
        self._require_editable(name, kind)
        self._store.delete_source(kind, name)
        assert self._vault is not None  # noqa: S101
        self._vault.delete(secret_name(kind, name))
        self._record(f"ui.{kind}.delete", name)

    # ------------------------------------------------------------------ UniFi cloud

    def stored_credential(self, kind: SourceKind, name: str) -> SecretStr | None:
        src = self.source(kind, name) if name else None
        if src is None or self._vault is None or not self.has_secret(src.credential):
            return None
        return self._vault.resolve(src.credential)

    async def find_unifi_consoles(self, key: SecretStr) -> list[dict[str, str]]:
        """Consoles the unifi.ui.com key can reach (Site Manager GET /v1/hosts)."""
        if not self.editable:
            raise TargetError("read-only here")
        async with self._site_manager(key) as client:
            res = await client.get(sm.HOSTS, query={"pageSize": 100})
        found = sm.consoles(res.json())
        if not found:
            raise TargetError("this key sees no UniFi consoles with the Network app")
        return found

    async def cloud_url(self, key: SecretStr, console_id: str) -> str:
        """The connector base that answers GET /v1/info for this console (docs disagree)."""
        if not re.fullmatch(sm.CONSOLE_ID_RE, console_id):
            raise TargetError("pick a console from the list")
        last = "no answer"
        for template in sm.CONNECTOR_BASES:
            base = template.format(id=console_id)
            client = ReadOnlyHttpClient(
                target="unifi-cloud",
                base_url=base,
                endpoints={unifi_ep.INFO},
                audit=self._audit,
                tls=TlsPolicy(ca_file=None, public_pki=True),
                auth=AuthHeader("X-API-KEY", key),
                limits=HttpLimits(min_interval_s=sm.CLOUD_MIN_INTERVAL_S),
                transport=self._transport,
            )
            try:
                async with client:
                    await client.get(unifi_ep.INFO)
            except HttpStatusError as exc:
                last = f"HTTP {exc.status}"
                if exc.status in (401, 403):
                    raise TargetError(
                        "the key was refused (401/403): check it at unifi.ui.com"
                    ) from None
            except TransportError as exc:
                last = type(exc).__name__
            else:
                return base
        raise TargetError(f"the console did not answer through the cloud connector ({last})")

    def _site_manager(self, key: SecretStr) -> ReadOnlyHttpClient:
        return ReadOnlyHttpClient(
            target="unifi-site-manager",
            base_url=sm.SITE_MANAGER,
            endpoints={sm.HOSTS},
            audit=self._audit,
            tls=TlsPolicy(ca_file=None, public_pki=True),
            auth=AuthHeader("X-API-KEY", key),
            transport=self._transport,
        )

    # ------------------------------------------------------------------ identity fetch

    async def fetch_host_key(self, name: str, address: str, port: int) -> discover.HostKey:
        if not self.editable:
            raise TargetError("read-only here")
        return await discover.fetch_host_key(name or "new-host", address, port, self._audit)

    async def fetch_certificate(self, kind: str, name: str, url: str) -> discover.PeerCertificate:
        if not self.editable:
            raise TargetError("read-only here")
        return await discover.fetch_certificate(name or kind, normalize_url(kind, url), self._audit)


def host_form_from(entry: HostEntry | None, inv: Inventory | None = None) -> HostForm:
    if entry is None:
        return HostForm(name="", address="")
    base = inv.auth_of(entry) if inv else (entry.ssh.auth or "key")
    auth: Literal["password", "key", "key-installed"] = "password"
    if base == "key":
        auth = "key" if entry.ssh.probe == "streamed" else "key-installed"
    return HostForm(
        name=entry.name,
        address=entry.address,
        type=entry.type,
        collectors=list(entry.collectors),
        user=entry.ssh.user or "",
        port=entry.ssh.port or 22,
        auth=auth,
        sudo=entry.ssh.sudo if entry.ssh.sudo is not None else True,
        key_name="" if entry.ssh.key == ATLAS_KEY_SECRET else (entry.ssh.key or ""),
        original=entry.name,
    )


def source_form_from(
    kind: SourceKind, src: ProxmoxSource | UnifiSource | UnasSource | None
) -> SourceForm:
    if src is None:
        return SourceForm(kind=kind, name="", url="")
    if isinstance(src, UnifiSource) and src.connection == "cloud":
        return SourceForm(
            kind=kind,
            name=src.name,
            url=src.url,
            original=src.name,
            connection="cloud",
            console_id=src.console_id or "",
        )
    return SourceForm(kind=kind, name=src.name, url=src.url or "", original=src.name)
