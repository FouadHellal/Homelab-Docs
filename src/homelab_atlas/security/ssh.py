"""SSH runner: the single choke point for target command execution (ADR-002/003).

Callers pass a `ProbeSection` enum member, never a string. The exec string comes from the
constant `PROBE_COMMANDS` table. On the target, a forced command re-checks the request
against its own fixed list, so a bug here still cannot run arbitrary commands.
"""

import asyncio
import re
import time
from collections.abc import AsyncIterator, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
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


class SshSession(Protocol):
    """An open connection to one target. `exec` only ever gets constant probe commands."""

    async def exec(self, command: str) -> ProbeOutput: ...


class SshTransport(Protocol):
    """Opens sessions. Never called with caller input."""

    name: str

    def open(
        self, target: SshTarget, limits: SshLimits
    ) -> AbstractAsyncContextManager[SshSession]: ...


def _section_of(command: str) -> ProbeSection:
    return ProbeSection(command.removeprefix("atlas-probe "))


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


class SshRunner:
    def __init__(
        self, *, transport: SshTransport, audit: AuditSink, limits: SshLimits | None = None
    ) -> None:
        self._transport = transport
        self._audit = audit
        self._limits = limits or SshLimits()

    async def run(self, target: SshTarget, section: ProbeSection) -> ProbeOutput:
        """One-shot: connect, run one section, disconnect."""
        start = time.monotonic()
        try:
            _authorize(target, section)  # refuse before opening a connection
        except SecurityRefusal as exc:
            self.record(target, _op(section), "refused", start, reason=exc.reason.value,
                        detail=exc.detail)  # fmt: skip
            raise
        async with self.session(target) as session:
            return await session.run(section)

    @asynccontextmanager
    async def session(self, target: SshTarget) -> AsyncIterator["RunnerSession"]:
        """Reuse one connection for several sections; every run is still checked and audited."""
        start = time.monotonic()
        if type(target) is not SshTarget:
            exc = SecurityRefusal(RefusalReason.BAD_TYPE, "target must be an SshTarget")
            self.record(target, "connect", "refused", start, reason=exc.reason.value)
            raise exc
        ctx = self._transport.open(target, self._limits)
        try:
            session = await ctx.__aenter__()
        except SecurityRefusal as exc:
            self.record(target, "connect", "refused", start, reason=exc.reason.value,
                        detail=exc.detail)  # fmt: skip
            raise
        except TransportError as exc:
            self.record(target, "connect", "error", start, reason=type(exc).__name__)
            raise
        try:
            yield RunnerSession(self, target, session)
        except BaseException as exc:
            if not await ctx.__aexit__(type(exc), exc, exc.__traceback__):
                raise
        else:
            await ctx.__aexit__(None, None, None)

    def record(
        self,
        target: object,
        op: str,
        outcome: Outcome,
        start: float,
        *,
        status: int | None = None,
        nbytes: int = 0,
        reason: str | None = None,
        detail: str | None = None,
    ) -> None:
        name = target.name if isinstance(target, SshTarget) else "<invalid>"
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


def _op(section: object) -> str:
    if isinstance(section, ProbeSection):
        return f"atlas-probe {section.value}"
    return "<invalid>"


class RunnerSession:
    def __init__(self, runner: SshRunner, target: SshTarget, session: SshSession) -> None:
        self._runner = runner
        self._target = target
        self._session = session

    async def run(self, section: ProbeSection) -> ProbeOutput:
        start = time.monotonic()
        op = _op(cast(object, section))
        record = self._runner.record
        try:
            command = _authorize(self._target, section)
        except SecurityRefusal as exc:
            record(self._target, op, "refused", start, reason=exc.reason.value, detail=exc.detail)
            raise
        try:
            out = await self._session.exec(command)
        except SecurityRefusal as exc:
            record(self._target, op, "refused", start, reason=exc.reason.value, detail=exc.detail)
            raise
        except TransportError as exc:
            record(self._target, op, "error", start, reason=type(exc).__name__)
            raise
        record(self._target, op, "ok", start, status=out.exit_status, nbytes=len(out.stdout))
        return out


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


class _AsyncSshSession:
    def __init__(
        self, target: SshTarget, conn: asyncssh.SSHClientConnection, limits: SshLimits
    ) -> None:
        self._target, self._conn, self._limits = target, conn, limits

    async def exec(self, command: str) -> ProbeOutput:
        limits, name = self._limits, self._target.name
        try:
            async with asyncio.timeout(limits.command_s):
                proc = await self._conn.create_process(
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
            raise TargetTimeout(f"{name}: command timeout") from None
        except (OSError, asyncssh.Error) as exc:
            raise TransportError(f"{name}: {type(exc).__name__}") from None
        return ProbeOutput(
            target=name,
            section=_section_of(command),
            exit_status=result.exit_status if result.exit_status is not None else -1,
            stdout=stdout,
            stderr=stderr,
        )


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

    @asynccontextmanager
    async def open(self, target: SshTarget, limits: SshLimits) -> AsyncIterator[SshSession]:
        options = self.options(target, limits)
        try:
            async with asyncio.timeout(limits.connect_s):
                conn = await asyncssh.connect(
                    target.host, target.port, options=options, config=None
                )
        except TimeoutError:
            raise TargetTimeout(f"{target.name}: connect timeout") from None
        except asyncssh.HostKeyNotVerifiable:
            raise SecurityRefusal(RefusalReason.HOST_KEY, f"{target.name}: host key") from None
        except asyncssh.PermissionDenied:
            raise TransportError(f"{target.name}: authentication refused") from None
        except (OSError, asyncssh.Error) as exc:
            raise TransportError(f"{target.name}: {type(exc).__name__}") from None
        async with conn:
            yield _AsyncSshSession(target, conn, limits)


class _ReplaySession:
    def __init__(self, target: SshTarget, data: Mapping[str, bytes], limits: SshLimits) -> None:
        self._target, self._data, self._limits = target, data, limits

    async def exec(self, command: str) -> ProbeOutput:
        try:
            out = self._data[command]
        except KeyError:
            raise TransportError(f"{self._target.name}: no recording") from None
        if len(out) > self._limits.max_stdout:
            raise SecurityRefusal(RefusalReason.OUTPUT_TOO_LARGE, "recording over cap")
        return ProbeOutput(self._target.name, _section_of(command), 0, out, b"")


class ReplayTransport:
    """`demo:` transport: returns recorded outputs. Same runner, same allowlist checks.

    A target with no recordings at all behaves as unreachable.
    """

    name = "replay"

    def __init__(self, recordings: Mapping[tuple[str, str], bytes]) -> None:
        self._by_target: dict[str, dict[str, bytes]] = {}
        for (target, command), data in recordings.items():
            self._by_target.setdefault(target, {})[command] = data

    @asynccontextmanager
    async def open(self, target: SshTarget, limits: SshLimits) -> AsyncIterator[SshSession]:
        data = self._by_target.get(target.name)
        if data is None:
            raise TransportError(f"{target.name}: unreachable (no recordings)")
        yield _ReplaySession(target, data, limits)
