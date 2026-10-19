"""Inventory managed from the web UI (ADR-025).

`<data>/inventory.yaml` is written by the app only (atomically, validated with the same strict
models as hosts.yaml). The effective inventory is hosts.yaml (owner-maintained, read-only to
the app) merged with this file; on a name clash hosts.yaml wins and the UI shows the entry as
read-only. Pinned CA/leaf certificates fetched from the UI live in `<data>/ca/`.

Secret *values* never appear here: hosts and sources reference vault names `ui-<kind>-<name>`.
"""

import os
import re
import secrets
from pathlib import Path
from typing import Any, Final, Literal

import yaml

from homelab_atlas.inventory.hosts import (
    Defaults,
    HostEntry,
    Inventory,
    InventoryError,
    ProxmoxSource,
    Sources,
    UnasSource,
    UnifiSource,
    load_inventory,
)

MANAGED_FILE: Final = "inventory.yaml"
CA_DIR: Final = "ca"
SourceKind = Literal["proxmox", "unifi", "unas"]
SOURCE_MODELS: Final = {"proxmox": ProxmoxSource, "unifi": UnifiSource, "unas": UnasSource}
_SLUG_RE: Final = re.compile(r"[^a-z0-9_.-]+")


def secret_name(kind: str, name: str) -> str:
    """Vault name for a UI-entered credential, e.g. ui-ssh-docker01."""
    slug = _SLUG_RE.sub("-", name.lower()).strip("-.")[:48] or "x"
    return f"ui-{kind}-{slug}"


def _dump(inv: Inventory) -> bytes:
    data = inv.model_dump(mode="json", exclude_defaults=True)
    data["version"] = 1
    header = (
        b"# Managed by the atlas web UI. Edit hosts.yaml instead for hand-maintained entries.\n"
    )
    return header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True).encode()


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    tmp.replace(path)


class ManagedInventory:
    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / MANAGED_FILE
        self.ca_dir = data_dir / CA_DIR

    def load(self) -> Inventory:
        if not self.path.is_file():
            return Inventory(version=1)
        return load_inventory(self.path)

    def save(self, inv: Inventory) -> None:
        # Round-trip through the strict loader's model so what we write is what we can read.
        Inventory.model_validate(inv.model_dump())
        _write_atomic(self.path, _dump(inv))

    # ------------------------------------------------------------------ hosts

    def upsert_host(self, host: HostEntry, *, replaces: str | None = None) -> Inventory:
        inv = self.load()
        drop = {host.name.lower(), (replaces or host.name).lower()}
        hosts = [h for h in inv.hosts if h.name.lower() not in drop]
        new = inv.model_copy(update={"hosts": (*hosts, host)})
        new = Inventory.model_validate(new.model_dump())
        self.save(new)
        return new

    def delete_host(self, name: str) -> Inventory:
        inv = self.load()
        new = inv.model_copy(update={"hosts": tuple(h for h in inv.hosts if h.name != name)})
        self.save(new)
        return new

    # ------------------------------------------------------------------ sources

    def upsert_source(
        self, kind: SourceKind, source: ProxmoxSource | UnifiSource | UnasSource
    ) -> Inventory:
        inv = self.load()
        current = getattr(inv.sources, kind)
        kept = tuple(s for s in current if s.name.lower() != source.name.lower())
        sources = inv.sources.model_copy(update={kind: (*kept, source)})
        new = Inventory.model_validate(inv.model_copy(update={"sources": sources}).model_dump())
        self.save(new)
        return new

    def delete_source(self, kind: SourceKind, name: str) -> Inventory:
        inv = self.load()
        kept = tuple(s for s in getattr(inv.sources, kind) if s.name != name)
        new = inv.model_copy(update={"sources": inv.sources.model_copy(update={kind: kept})})
        self.save(new)
        return new

    # ------------------------------------------------------------------ certificates

    def save_certificate(self, source_name: str, pem: str) -> str:
        """Store a pinned certificate; returns the `tls.ca_file` value (a bare file name)."""
        if "-----BEGIN CERTIFICATE-----" not in pem or len(pem) > 64 * 1024:
            raise InventoryError("not a PEM certificate")
        name = f"{secret_name('ca', source_name)}.pem"
        _write_atomic(self.ca_dir / name, pem.encode())
        return name


def merged(base: Inventory | None, managed: Inventory) -> Inventory:
    """hosts.yaml (base) + UI-managed entries; base wins on name clashes (case-insensitive)."""
    if base is None:
        return managed
    taken = {h.name.lower() for h in base.hosts}
    hosts = (*base.hosts, *(h for h in managed.hosts if h.name.lower() not in taken))
    src: dict[str, Any] = {}
    for kind in SOURCE_MODELS:
        have = getattr(base.sources, kind)
        names = {s.name.lower() for s in have}
        src[kind] = (
            *have,
            *(s for s in getattr(managed.sources, kind) if s.name.lower() not in names),
        )
    defaults = base.defaults if base.defaults != Defaults() else managed.defaults
    return Inventory.model_validate(
        {
            "version": 1,
            "defaults": defaults.model_dump(),
            "sources": Sources(**src).model_dump(),
            "hosts": [h.model_dump() for h in hosts],
        }
    )


def effective_inventory(config_dir: Path, data_dir: Path) -> tuple[Inventory, set[str]]:
    """The inventory scans use, plus the names that come from hosts.yaml (read-only in UI)."""
    path = config_dir / "hosts.yaml"
    base = load_inventory(path) if path.is_file() else None
    inv = merged(base, ManagedInventory(data_dir).load())
    fixed: set[str] = set()
    if base is not None:
        fixed |= {h.name for h in base.hosts}
        for kind in SOURCE_MODELS:
            fixed |= {f"{kind}:{s.name}" for s in getattr(base.sources, kind)}
    return inv, fixed
