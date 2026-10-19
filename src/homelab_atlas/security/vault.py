"""Credentials entered in the web UI (ADR-025): an encrypted, write-only secret store.

* AES-256-GCM per secret, the secret's name bound as associated data (a ciphertext cannot
  be moved to another name). One JSON file, rewritten atomically, 0600.
* Master key: Docker secret `atlas_master_key` (32+ random bytes, recommended) or, failing
  that, `<data>/master.key` created on first use (0600). With the generated key, the vault
  only protects against leaks of the vault file alone (a copied backup of one file, logs).
* Write-only from the UI: values can be set, replaced or deleted, never read back out. Only
  the transports resolve them, exactly like Docker secrets.
"""

import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretStr

from homelab_atlas.security.errors import SecretError
from homelab_atlas.security.secrets import MAX_SECRET_BYTES, SecretResolver, validate_secret_name

MASTER_KEY_SECRET: Final = "atlas_master_key"  # noqa: S105 - a secret *name*
VAULT_VERSION: Final = 1


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    tmp.replace(path)


def load_master_key(data_dir: Path, resolver: SecretResolver | None = None) -> bytes:
    """Docker secret first; else a generated per-installation key file."""
    if resolver is not None:
        try:
            raw = resolver.resolve_bytes(MASTER_KEY_SECRET).strip()
        except SecretError:
            raw = b""
        if raw:
            if len(raw) < 32:
                raise SecretError(f"{MASTER_KEY_SECRET}: needs at least 32 bytes")
            return hashlib.sha256(b"atlas-vault/1\0" + raw).digest()
    path = data_dir / "master.key"
    if not path.is_file():
        data_dir.mkdir(parents=True, exist_ok=True)
        _write_private(path, secrets.token_bytes(32))
    key = path.read_bytes()
    if len(key) != 32:
        raise SecretError("master.key is corrupt (expected 32 bytes)")
    return key


@dataclass(frozen=True, slots=True)
class VaultEntry:
    name: str
    nonce: bytes
    ciphertext: bytes


class Vault:
    def __init__(self, path: Path, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("vault key must be 32 bytes")
        self._path = path
        self._aead = AESGCM(key)

    # ------------------------------------------------------------------ storage

    def _load(self) -> dict[str, VaultEntry]:
        if not self._path.is_file():
            return {}
        try:
            doc = json.loads(self._path.read_bytes())
            if doc.get("version") != VAULT_VERSION:
                raise SecretError("vault: unsupported version")
            return {
                name: VaultEntry(
                    name, base64.b64decode(e["nonce"]), base64.b64decode(e["ciphertext"])
                )
                for name, e in doc["secrets"].items()
            }
        except (ValueError, KeyError, TypeError, AttributeError):
            raise SecretError("vault file is corrupt") from None

    def _save(self, entries: dict[str, VaultEntry]) -> None:
        doc = {
            "version": VAULT_VERSION,
            "secrets": {
                e.name: {
                    "nonce": base64.b64encode(e.nonce).decode(),
                    "ciphertext": base64.b64encode(e.ciphertext).decode(),
                }
                for e in sorted(entries.values(), key=lambda e: e.name)
            },
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        _write_private(self._path, json.dumps(doc, indent=1).encode())

    # ------------------------------------------------------------------ API

    def names(self) -> list[str]:
        return sorted(self._load())

    def has(self, name: str) -> bool:
        return validate_secret_name(name) in self._load()

    def put(self, name: str, value: SecretStr) -> None:
        name = validate_secret_name(name)
        raw = value.get_secret_value().encode()
        if not raw or len(raw) > MAX_SECRET_BYTES:
            raise SecretError(f"{name}: secret empty or too large")
        entries = self._load()
        nonce = secrets.token_bytes(12)
        entries[name] = VaultEntry(name, nonce, self._aead.encrypt(nonce, raw, name.encode()))
        self._save(entries)

    def delete(self, name: str) -> None:
        entries = self._load()
        if entries.pop(validate_secret_name(name), None) is not None:
            self._save(entries)

    def resolve_bytes(self, name: str) -> bytes:
        name = validate_secret_name(name)
        entry = self._load().get(name)
        if entry is None:
            raise SecretError(f"{name}: not found")
        try:
            return self._aead.decrypt(entry.nonce, entry.ciphertext, name.encode())
        except InvalidTag:
            raise SecretError(f"{name}: cannot decrypt (wrong master key or tampered)") from None

    def resolve(self, name: str) -> SecretStr:
        return SecretStr(self.resolve_bytes(name).decode("utf-8").strip())


class ChainedSecrets:
    """Docker secrets / dev dir first (operator-managed), then the UI vault."""

    def __init__(self, resolver: SecretResolver, vault: Vault | None) -> None:
        self._resolver, self._vault = resolver, vault

    @property
    def vault(self) -> Vault | None:
        return self._vault

    def resolve_bytes(self, name: str) -> bytes:
        try:
            return self._resolver.resolve_bytes(name)
        except SecretError:
            if self._vault is None:
                raise
            return self._vault.resolve_bytes(name)

    def resolve(self, name: str) -> SecretStr:
        return SecretStr(self.resolve_bytes(name).decode("utf-8").strip())
