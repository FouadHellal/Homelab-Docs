"""atlas's own SSH client key for UI-added machines in key mode (ADR-026).

Generated once (ed25519) and stored in the encrypted vault; only the public half is ever
shown, so the owner can paste it into `~/.ssh/authorized_keys` on each machine.
"""

from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ATLAS_KEY_SECRET: Final = "ui-atlas-ssh-key"  # noqa: S105 - a vault name
COMMENT: Final = "atlas-collector"


def generate_client_key() -> bytes:
    """A new ed25519 private key in OpenSSH format (unencrypted: the vault encrypts it)."""
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )


def public_line(private_openssh: bytes) -> str:
    """`ssh-ed25519 AAAA... atlas-collector` for authorized_keys."""
    key = serialization.load_ssh_private_key(private_openssh, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("atlas key must be ed25519")
    pub = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    return f"{pub.decode()} {COMMENT}"
