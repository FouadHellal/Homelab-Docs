"""AsyncSshTransport against an in-process asyncssh server (no real targets)."""

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh
import pytest

from homelab_atlas.security.allowlist import ProbeSection
from homelab_atlas.security.errors import (
    RefusalReason,
    SecurityRefusal,
    TargetTimeout,
    TransportError,
)
from homelab_atlas.security.secrets import SecretDir, SecretResolver
from homelab_atlas.security.ssh import AsyncSshTransport, SshLimits, SshRunner, SshTarget
from tests.helpers import MemoryAudit

pytestmark = pytest.mark.security


@dataclass
class Seen:
    commands: list[str | None] = field(default_factory=list)
    terms: list[str | None] = field(default_factory=list)
    envs: list[dict[str, str]] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    connections: int = 0


@dataclass
class Lab:
    port: int
    host_key: asyncssh.SSHKey
    client_key: asyncssh.SSHKey
    resolver: SecretResolver
    seen: Seen
    behaviour: dict[str, object]

    def target(self, **kw: object) -> SshTarget:
        args: dict[str, object] = {
            "name": "lab",
            "host": "127.0.0.1",
            "port": self.port,
            "host_keys": (self.host_key.export_public_key().decode().strip(),),
            "key_secret": "client_key",
            "sections": frozenset(ProbeSection),
        }
        args.update(kw)
        return SshTarget(**args)  # type: ignore[arg-type]


@pytest.fixture
async def lab(tmp_path: Path) -> AsyncIterator[Lab]:
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    (tmp_path / "client_key").write_bytes(client_key.export_private_key())
    seen = Seen()
    behaviour: dict[str, object] = {"stdout": b"ID=debian\n", "sleep": 0.0, "accept": True}

    class Server(asyncssh.SSHServer):
        def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
            seen.connections += 1

        def begin_auth(self, username: str) -> bool:
            seen.users.append(username)
            return True

        def public_key_auth_supported(self) -> bool:
            return True

        def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
            return bool(behaviour["accept"]) and key.public_data == client_key.public_data

        def password_auth_supported(self) -> bool:
            return True  # offered by the server; the client must not use it

        def validate_password(self, username: str, password: str) -> bool:
            raise AssertionError("client attempted password auth")

    async def handle(process: asyncssh.SSHServerProcess[bytes]) -> None:
        seen.commands.append(process.command)
        seen.terms.append(process.get_terminal_type())
        seen.envs.append(dict(process.env))
        await asyncio.sleep(float(behaviour["sleep"]))  # type: ignore[arg-type]
        data = behaviour["stdout"]
        assert isinstance(data, bytes)
        process.stdout.write(data)
        process.exit(0)

    server = await asyncssh.create_server(
        Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=handle,
        encoding=None,
    )  # fmt: skip
    port = server.sockets[0].getsockname()[1]
    yield Lab(
        port, host_key, client_key, SecretResolver([SecretDir(tmp_path, False)]), seen, behaviour
    )
    server.close()
    await server.wait_closed()


def _runner(lab: Lab, audit: MemoryAudit, limits: SshLimits | None = None) -> SshRunner:
    return SshRunner(transport=AsyncSshTransport(lab.resolver), audit=audit, limits=limits)


async def test_happy_path_exact_command_no_pty_no_env(lab: Lab, audit: MemoryAudit) -> None:
    out = await _runner(lab, audit).run(lab.target(), ProbeSection.OS)
    assert out.stdout == b"ID=debian\n"
    assert out.exit_status == 0
    assert lab.seen.commands == ["atlas-probe os"]
    assert lab.seen.terms == [None]
    assert lab.seen.envs == [{}]
    assert lab.seen.users == ["atlas-ro"]
    assert audit.events[-1].outcome == "ok"


async def test_wrong_pinned_host_key(lab: Lab, audit: MemoryAudit) -> None:
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    with pytest.raises(SecurityRefusal) as exc:
        await _runner(lab, audit).run(lab.target(host_keys=(other,)), ProbeSection.OS)
    assert exc.value.reason is RefusalReason.HOST_KEY
    assert lab.seen.commands == []
    assert audit.outcomes == ["refused"]


async def test_rsa_pinned_host_key_refused(lab: Lab, audit: MemoryAudit) -> None:
    rsa = asyncssh.generate_private_key("ssh-rsa", key_size=2048).export_public_key().decode()
    with pytest.raises(SecurityRefusal) as exc:
        await _runner(lab, audit).run(lab.target(host_keys=(rsa.strip(),)), ProbeSection.OS)
    assert exc.value.reason is RefusalReason.HOST_KEY


async def test_garbage_pinned_host_key_refused(lab: Lab, audit: MemoryAudit) -> None:
    with pytest.raises(SecurityRefusal):
        await _runner(lab, audit).run(lab.target(host_keys=("not a key",)), ProbeSection.OS)


async def test_rsa_client_key_refused(lab: Lab, audit: MemoryAudit, tmp_path: Path) -> None:
    rsa = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    (tmp_path / "rsa_key").write_bytes(rsa.export_private_key())
    with pytest.raises(SecurityRefusal) as exc:
        await _runner(lab, audit).run(lab.target(key_secret="rsa_key"), ProbeSection.OS)
    assert exc.value.reason is RefusalReason.CLIENT_KEY
    assert lab.seen.commands == []


async def test_unreadable_client_key(lab: Lab, audit: MemoryAudit, tmp_path: Path) -> None:
    (tmp_path / "junk_key").write_bytes(b"-----BEGIN NOPE-----\nATLASFAKE\n")
    with pytest.raises(SecurityRefusal) as exc:
        await _runner(lab, audit).run(lab.target(key_secret="junk_key"), ProbeSection.OS)
    assert exc.value.reason is RefusalReason.CLIENT_KEY


async def test_server_rejects_key(lab: Lab, audit: MemoryAudit) -> None:
    lab.behaviour["accept"] = False
    with pytest.raises(TransportError):
        await _runner(lab, audit).run(lab.target(), ProbeSection.OS)
    assert audit.events[-1].outcome == "error"


async def test_output_cap(lab: Lab, audit: MemoryAudit) -> None:
    lab.behaviour["stdout"] = b"z" * 300_000
    with pytest.raises(SecurityRefusal) as exc:
        await _runner(lab, audit, SshLimits(max_stdout=100_000)).run(lab.target(), ProbeSection.OS)
    assert exc.value.reason is RefusalReason.OUTPUT_TOO_LARGE


async def test_command_timeout(lab: Lab, audit: MemoryAudit) -> None:
    lab.behaviour["sleep"] = 5.0
    limits = SshLimits(connect_s=2.0, command_s=0.5)
    with pytest.raises(TargetTimeout):
        await _runner(lab, audit, limits).run(lab.target(), ProbeSection.OS)


async def test_connection_refused(lab: Lab, audit: MemoryAudit) -> None:
    with pytest.raises(TransportError):
        await _runner(lab, audit, SshLimits(connect_s=2.0)).run(lab.target(port=1), ProbeSection.OS)


async def test_environment_not_inherited(
    lab: Lab, audit: MemoryAudit, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No agent, no ~/.ssh/config, no default keys, no known_hosts file."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    # If this config were read, the connection would go through a failing ProxyCommand.
    (home / ".ssh" / "config").write_text("Host *\n  ProxyCommand nonexistent-binary %h\n")
    # A known_hosts entry with a *different* key must not override the pin.
    bogus = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    (home / ".ssh" / "known_hosts").write_text(f"[127.0.0.1]:{lab.port} {bogus}\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("SSH_AUTH_SOCK", str(home / "agent.sock"))
    out = await _runner(lab, audit).run(lab.target(), ProbeSection.VERSION)
    assert out.stdout == b"ID=debian\n"
    assert lab.seen.commands == ["atlas-probe version"]


def test_options_are_locked_down(lab: Lab) -> None:
    opts = AsyncSshTransport(lab.resolver).options(lab.target(), SshLimits())
    assert opts.agent_path == ""  # resolved: no agent
    assert opts.agent_forward_path is None
    assert opts.request_pty is False
    assert opts.x11_forwarding is False
    assert opts.password_auth is False
    assert opts.kbdint_auth is False
    assert opts.gss_auth is False
    assert opts.host_based_auth is False
    assert opts.client_keys is not None
    assert [k.get_algorithm() for k in opts.client_keys] == ["ssh-ed25519"]


async def test_session_reuses_one_connection(lab: Lab, audit: MemoryAudit) -> None:
    runner = _runner(lab, audit)
    async with runner.session(lab.target()) as session:
        for section in (ProbeSection.VERSION, ProbeSection.OS, ProbeSection.NET):
            await session.run(section)
    assert lab.seen.connections == 1
    assert lab.seen.commands == ["atlas-probe version", "atlas-probe os", "atlas-probe net"]
    assert audit.outcomes == ["ok", "ok", "ok"]


async def test_key_mode_streamed_probe_sends_constant_loader(lab: Lab, audit: MemoryAudit) -> None:
    from homelab_atlas.security.ssh import INLINE_COMMANDS  # noqa: PLC0415

    runner = SshRunner(transport=AsyncSshTransport(lab.resolver, b"PROBE"), audit=audit)
    await runner.run(lab.target(probe="streamed"), ProbeSection.OS)
    assert lab.seen.commands == [INLINE_COMMANDS[ProbeSection.OS]]
