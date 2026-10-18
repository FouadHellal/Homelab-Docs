"""hosts.yaml: the owner-maintained inventory (SPEC §4.1).

Strict: unknown keys, duplicate YAML keys, duplicate host names and secret *values* (anything
that is not a secret name) are errors. Only safe YAML is accepted.
"""

import ipaddress
from collections.abc import Hashable
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from homelab_atlas.security.allowlist import ProbeSection
from homelab_atlas.security.secrets import SECRET_NAME_RE
from homelab_atlas.security.ssh import HOST_RE, TARGET_NAME_RE, USER_RE, SshTarget

MAX_BYTES: Final = 1024 * 1024
Collector = Literal["linux-ssh", "docker", "pi", "nas"]
HostType = Literal["linux", "pi", "nas", "proxmox-node", "unifi-device", "manual"]


class InventoryError(ValueError):
    pass


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[Hashable, Any]:
    seen: set[Hashable] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node)
        if key in seen:
            raise InventoryError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return loader.construct_mapping(node)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _secret_name(v: str | None) -> str | None:
    if v is not None and not SECRET_NAME_RE.fullmatch(v):
        raise ValueError("must be a secret NAME (file under secrets/), not a value")
    return v


class SshSettings(_Strict):
    user: str | None = None
    key: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    host_keys: tuple[str, ...] = ()

    _key = field_validator("key")(_secret_name)

    @field_validator("user")
    @classmethod
    def _user(cls, v: str | None) -> str | None:
        if v is not None and (not USER_RE.fullmatch(v) or v == "root"):
            raise ValueError("invalid or root ssh user")
        return v

    @field_validator("host_keys")
    @classmethod
    def _keys(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for line in v:
            parts = line.split()
            if len(parts) < 2 or parts[0] not in ("ssh-ed25519", "ecdsa-sha2-nistp256"):
                raise ValueError("host_keys entries must be 'ssh-ed25519 AAAA...' lines")
        return v


class Defaults(_Strict):
    ssh: SshSettings = SshSettings()


class TlsSettings(_Strict):
    ca_file: str | None = None
    check_hostname: bool = True
    sha256_pin: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ProxmoxSource(_Strict):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    url: str = Field(pattern=r"^https://")
    credential: str
    tls: TlsSettings = TlsSettings()
    _cred = field_validator("credential")(_secret_name)


class UnifiSource(_Strict):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    url: str = Field(pattern=r"^https://")
    credential: str
    legacy_enrichment: bool = False
    legacy_credential: str | None = None
    tls: TlsSettings = TlsSettings()
    _cred = field_validator("credential", "legacy_credential")(_secret_name)


class Sources(_Strict):
    proxmox: tuple[ProxmoxSource, ...] = ()
    unifi: tuple[UnifiSource, ...] = ()


class Match(_Strict):
    mac: str | None = Field(default=None, pattern=r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


class HostEntry(_Strict):
    name: str
    address: str
    type: HostType
    collectors: tuple[Collector, ...] = ()
    ssh: SshSettings = SshSettings()
    match: Match = Match()
    tags: tuple[str, ...] = ()

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not TARGET_NAME_RE.fullmatch(v):
            raise ValueError("name: letters, digits, . _ - (max 64)")
        return v

    @field_validator("address")
    @classmethod
    def _address(cls, v: str) -> str:
        try:
            return ipaddress.ip_address(v).compressed
        except ValueError:
            if not HOST_RE.fullmatch(v):
                raise ValueError("address must be an IP or DNS name") from None
            return v.lower()


class Inventory(_Strict):
    version: Literal[1]
    defaults: Defaults = Defaults()
    sources: Sources = Sources()
    hosts: tuple[HostEntry, ...] = ()

    @model_validator(mode="after")
    def _unique_and_complete(self) -> "Inventory":
        names = [h.name for h in self.hosts]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"duplicate host names: {', '.join(dupes)}")
        for h in self.hosts:
            if set(h.collectors) & {"linux-ssh", "docker", "pi"}:
                if not h.ssh.host_keys:
                    raise ValueError(f"{h.name}: SSH collectors need pinned ssh.host_keys")
                if (h.ssh.key or self.defaults.ssh.key) is None:
                    raise ValueError(f"{h.name}: no ssh key secret name (host or defaults)")
        return self

    def host(self, name: str) -> HostEntry:
        for h in self.hosts:
            if h.name == name:
                return h
        raise KeyError(name)

    def ssh_target(self, host: HostEntry, sections: frozenset[ProbeSection]) -> SshTarget:
        d = self.defaults.ssh
        key = host.ssh.key or d.key
        if key is None:  # pragma: no cover - guaranteed by validation
            raise InventoryError(f"{host.name}: no ssh key")
        return SshTarget(
            name=host.name,
            host=host.address,
            port=host.ssh.port or d.port or 22,
            username=host.ssh.user or d.user or "atlas-ro",
            host_keys=host.ssh.host_keys,
            key_secret=key,
            sections=sections,
        )


def load_inventory(path: Path) -> Inventory:
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        raise InventoryError(f"{path.name}: larger than {MAX_BYTES} bytes")
    try:
        raw = yaml.load(data, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise InventoryError(f"{path.name}: invalid YAML: {exc}") from None
    if not isinstance(raw, dict):
        raise InventoryError(f"{path.name}: top level must be a mapping")
    try:
        return Inventory.model_validate(raw)
    except ValueError as exc:
        raise InventoryError(f"{path.name}: {exc}") from None
