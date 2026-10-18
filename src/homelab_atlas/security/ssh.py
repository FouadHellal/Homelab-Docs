"""SSH runner: the single choke point for target command execution (ADR-002/003).

Callers pass a `ProbeSection` enum member, never a string. The exec string comes from the
constant `PROBE_COMMANDS` table. On the target, a forced command re-checks the request
against its own fixed list, so a bug here still cannot run arbitrary commands.
"""

import asyncio
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Protocol, cast

import asyncssh

from homelab_atlas.security.allowlist import PROBE_COMMAND_RE, PROBE_COMMANDS, ProbeSection
from homelab_atlas.security.audit import AuditEvent, AuditSink, Outcome
from homelab_atlas.security.errors import (
    RefusalReason,
    SecurityRefusal,
    TargetTimeout,
    TransportError,
)
from homelab_atlas.security.secrets import SecretResolver, validate_secret_name

TARGET_NAME_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
HOST_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}|\[?[0-9A-Fa-f:.]{2,45}\]?")
USER_RE: Final = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
CLIENT_KEY_ALGS: Final = frozenset({"ssh-ed25519"})
HOST_KEY_ALGS: Final = frozenset({"ssh-ed25519", "ecdsa-sha2-nistp256"})


@dataclass(frozen=True, slots=True)
class SshLimits:
    connect_s: float = 10.0
    command_s: float = 60.0
    max_stdout: int = 8 * 1024 * 1024
    max_stderr: int = 64 * 1024


@dataclass(frozen=True, slots=True)
class SshTarget:
    """A probe target. `host_keys` are pinned OpenSSH public key lines (no TOFU)."""

    name: str
    host: str
    host_keys: tuple[str, ...]
    key_secret: str
    sections: frozenset[ProbeSection]
    port: int = 22
    username: str = "atlas-ro"

    def __post_init__(self) -> None:
        if not TARGET_NAME_RE.fullmatch(self.name):
            raise SecurityRefusal(RefusalReason.CONFIG, "bad target name")
        if not HOST_RE.fullmatch(self.host):
            raise SecurityRefusal(RefusalReason.CONFIG, f"{self.name}: bad host")
        if not USER_RE.fullmatch(self.username) or self.username == "root":
            raise SecurityRefusal(RefusalReason.CONFIG, f"{self.name}: bad or root username")
        if not 1 <= self.port <= 65535:
            raise SecurityRefusal(RefusalReason.CONFIG, f"{self.name}: bad port")
        if not self.host_keys:
            raise SecurityRefusal(RefusalReason.HOST_KEY, f"{self.name}: no pinned host key")
        validate_secret_name(self.key_secret)
        if not all(isinstance(s, ProbeSection) for s in self.sections):
            raise SecurityRefusal(RefusalReason.BAD_TYPE, f"{self.name}: sections must be enum")
        object.__setattr__(self, "sections", frozenset(self.sections))


@dataclass(frozen=True, slots=True)
class ProbeOutput:
    target: str
    section: ProbeSection
    exit_status: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)


class SshTransport(Protocol):
    """Executes one already-validated command string. Never called with caller input."""

    name: str

    async def exec(self, target: SshTarget, command: str, limits: SshLimits) -> ProbeOutput: ...


class SshRunner:
    def __init__(
        self, *, transport: SshTransport, audit: AuditSink, limits: SshLimits | None = None
    ) -> None:
        self._transport = transport
        self._audit = audit
        self._limits = limits or SshLimits()

    async def run(self, target: SshTarget, section: ProbeSection) -> ProbeOutput:
        start = time.monotonic()
        ok_type = isinstance(cast(object, section), ProbeSection)
        op = f"atlas-probe {section.value}" if ok_type else "<invalid>"
        try:
            command = self._authorize(target, section)
        except SecurityRefusal as exc:
            self._record(target, op, "refused", start, reason=exc.reason.value, detail=exc.detail)
            raise
        try:
            out = await self._transport.exec(target, command, self._limits)
        except SecurityRefusal as exc:
            self._record(target, op, "refused", start, reason=exc.reason.value, detail=exc.detail)
            raise
        except TransportError as exc:
            self._record(target, op, "error", start, reason=type(exc).__name__)
            raise
        self._record(target, op, "ok", start, status=out.exit_status, nbytes=len(out.stdout))
        return out

    @staticmethod
    def _authorize(target: SshTarget, section: ProbeSection) -> str:
        if type(target) is not SshTarget:
            raise SecurityRefusal(RefusalReason.BAD_TYPE, "target must be an SshTarget")
        # Enum identity, not string equality: StrEnum members compare equal to plain str.
        if type(section) is not ProbeSection or ProbeSection(section.value) is not section:
            raise SecurityRefusal(RefusalReason.BAD_TYPE, "section must be a ProbeSection")
        if section not in target.sections:
            raise SecurityRefusal(
                RefusalReason.NOT_ALLOWLISTED, f"{target.name}: {section.value} not enabled"
            )
        command = PROBE_COMMANDS[section]
        if not PROBE_COMMAND_RE.fullmatch(command):  # pragma: no cover - invariant
            raise SecurityRefusal(RefusalReason.NOT_ALLOWLISTED, "command table corrupted")
        return command

    def _record(
        self,
        target: SshTarget,
        op: str,
        outcome: Outcome,
        start: float,
        *,
        status: int | None = None,
        nbytes: int = 0,
        reason: str | None = None,
        detail: str | None = None,
    ) -> None:
        name = target.name if type(target) is SshTarget else "<invalid>"
        self._audit.record(
            AuditEvent(
                target=name,
                transport="replay" if self._transport.name == "replay" else "ssh",
                op=op,
                outcome=outcome,
                status=status,
                duration_ms=int((time.monotonic() - start) * 1000),
                bytes=nbytes,
                reason=reason,
                detail=detail,
            )
        )


# --------------------------------------------------------------------------- transports


async def _read_capped(stream: asyncssh.SSHReader[bytes], cap: int, *, strict: bool) -> bytes:
    buf = bytearray()
    while chunk := await stream.read(65536):
        buf += chunk
        if len(buf) > cap:
            if strict:
                raise SecurityRefusal(RefusalReason.OUTPUT_TOO_LARGE, f"output over {cap} bytes")
            return bytes(buf[:cap])
    return bytes(buf)


class AsyncSshTransport:
    """Real SSH via asyncssh, configured so nothing is inherited from the environment."""

    name = "ssh"

    def __init__(self, secrets: SecretResolver) -> None:
        self._secrets = secrets

    def _client_key(self, target: SshTarget) -> asyncssh.SSHKey:
        try:
            key = asyncssh.import_private_key(self._secrets.resolve_bytes(target.key_secret))
        except (asyncssh.KeyImportError, ValueError):
            raise SecurityRefusal(RefusalReason.CLIENT_KEY, "client key unreadable") from None
        if key.get_algorithm() not in CLIENT_KEY_ALGS:
            raise SecurityRefusal(RefusalReason.CLIENT_KEY, "client key must be ed25519")
        return key

    @staticmethod
    def _host_keys(target: SshTarget) -> list[asyncssh.SSHKey]:
        keys: list[asyncssh.SSHKey] = []
        for line in target.host_keys:
            try:
                key = asyncssh.import_public_key(line)
            except (asyncssh.KeyImportError, ValueError):
                raise SecurityRefusal(RefusalReason.HOST_KEY, "pinned host key invalid") from None
            if key.get_algorithm() not in HOST_KEY_ALGS:
                raise SecurityRefusal(RefusalReason.HOST_KEY, "pinned host key algorithm")
            keys.append(key)
        return keys

    def options(self, target: SshTarget, limits: SshLimits) -> asyncssh.SSHClientConnectionOptions:
        pins = self._host_keys(target)
        return asyncssh.SSHClientConnectionOptions(
            username=target.username,
            client_keys=[self._client_key(target)],
            # Exact keys, no hostname matching, no CAs, no TOFU.
            known_hosts=(pins, [], []),
            server_host_key_algs=sorted({k.get_algorithm() for k in pins}),
            agent_path=None,
            agent_forwarding=False,
            x11_forwarding=False,
            preferred_auth="publickey",
            public_key_auth=True,
            password_auth=False,
            kbdint_auth=False,
            gss_auth=False,
            gss_kex=False,
            host_based_auth=False,
            request_pty=False,
            send_env=None,
            env=None,
            connect_timeout=limits.connect_s,
            login_timeout=limits.connect_s,
            keepalive_interval=0,
        )

    async def exec(self, target: SshTarget, command: str, limits: SshLimits) -> ProbeOutput:
        options = self.options(target, limits)
        section = ProbeSection(command.removeprefix("atlas-probe "))
        try:
            async with asyncio.timeout(limits.connect_s + limits.command_s):
                conn = await asyncssh.connect(
                    target.host, target.port, options=options, config=None
                )
                async with conn:
                    proc = await conn.create_process(
                        command, stdin=asyncssh.DEVNULL, encoding=None, request_pty=False
                    )
                    try:
                        stdout, stderr = await asyncio.gather(
                            _read_capped(proc.stdout, limits.max_stdout, strict=True),
                            _read_capped(proc.stderr, limits.max_stderr, strict=False),
                        )
                        result = await proc.wait(check=False)
                    finally:
                        proc.close()
        except TimeoutError:
            raise TargetTimeout(f"{target.name}: timeout") from None
        except asyncssh.HostKeyNotVerifiable:
            raise SecurityRefusal(RefusalReason.HOST_KEY, f"{target.name}: host key") from None
        except asyncssh.PermissionDenied:
            raise TransportError(f"{target.name}: authentication refused") from None
        except (OSError, asyncssh.Error) as exc:
            raise TransportError(f"{target.name}: {type(exc).__name__}") from None
        return ProbeOutput(
            target=target.name,
            section=section,
            exit_status=result.exit_status if result.exit_status is not None else -1,
            stdout=stdout,
            stderr=stderr,
        )


class ReplayTransport:
    """`demo:` transport: returns recorded outputs. Same runner, same allowlist checks."""

    name = "replay"

    def __init__(self, recordings: Mapping[tuple[str, str], bytes]) -> None:
        self._recordings = dict(recordings)

    async def exec(self, target: SshTarget, command: str, limits: SshLimits) -> ProbeOutput:
        try:
            data = self._recordings[(target.name, command)]
        except KeyError:
            raise TransportError(f"{target.name}: no recording") from None
        if len(data) > limits.max_stdout:
            raise SecurityRefusal(RefusalReason.OUTPUT_TOO_LARGE, "recording over cap")
        return ProbeOutput(
            target=target.name,
            section=ProbeSection(command.removeprefix("atlas-probe ")),
            exit_status=0,
            stdout=data,
            stderr=b"",
        )
