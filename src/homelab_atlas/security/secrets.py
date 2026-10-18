"""Resolve secrets by name from Docker secrets or a local dev directory (ADR-018).

Config only ever holds secret *names*. Values are returned as `SecretStr` and unwrapped
only inside the transport call that needs them.
"""

import os
import re
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import SecretStr

from homelab_atlas.security.errors import RefusalReason, SecretError, SecurityRefusal

SECRET_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
MAX_SECRET_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class SecretDir:
    path: Path
    # Docker compose bind-mounts file secrets 0444 and ignores `mode`, so only the dev
    # directory gets the 0600 check; /run/secrets relies on container isolation.
    enforce_private_mode: bool


DEFAULT_DIRS: tuple[SecretDir, ...] = (
    SecretDir(Path("/run/secrets"), enforce_private_mode=False),
    SecretDir(Path("secrets"), enforce_private_mode=True),
)


def validate_secret_name(name: object) -> str:
    if not isinstance(name, str) or not SECRET_NAME_RE.fullmatch(name) or ".." in name:
        raise SecurityRefusal(RefusalReason.SECRET_NAME, "invalid secret name")
    return name


class SecretResolver:
    """Looks a secret name up in an ordered list of directories (first hit wins)."""

    def __init__(self, dirs: Sequence[SecretDir] = DEFAULT_DIRS) -> None:
        self._dirs = tuple(dirs)

    def resolve(self, name: str) -> SecretStr:
        return SecretStr(self.resolve_bytes(name).decode("utf-8").strip())

    def resolve_bytes(self, name: str) -> bytes:
        name = validate_secret_name(name)
        for d in self._dirs:
            path = d.path / name
            try:
                st = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(st.st_mode):  # refuses symlinks, dirs, devices, FIFOs
                raise SecurityRefusal(RefusalReason.SECRET_NAME, f"{name}: not a regular file")
            if (
                d.enforce_private_mode
                and os.name == "posix"
                and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            ):
                raise SecurityRefusal(
                    RefusalReason.SECRET_PERMISSIONS, f"{name}: group/world permissions set"
                )
            if st.st_size > MAX_SECRET_BYTES:
                raise SecretError(f"{name}: secret file too large")
            return path.read_bytes()
        raise SecretError(f"{name}: not found")
