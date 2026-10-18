"""SshRunner refusals: only enum members reach a transport, only as constant strings."""

import asyncio
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from enum import StrEnum

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from homelab_atlas.security.allowlist import PROBE_COMMANDS, ProbeSection
from homelab_atlas.security.errors import RefusalReason, SecurityRefusal, TransportError
from homelab_atlas.security.ssh import (
    ProbeOutput,
    ReplayTransport,
    SshLimits,
    SshRunner,
    SshTarget,
)
from tests.helpers import MemoryAudit

pytestmark = pytest.mark.security

HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATLASFAKEATLASFAKEATLASFAKEATLASFAKE00 pin"


def target(**kw: object) -> SshTarget:
    args: dict[str, object] = {
        "name": "docker01",
        "host": "10.0.20.11",
        "host_keys": (HOST_KEY,),
        "key_secret": "ssh_atlas_docker",
        "sections": frozenset({ProbeSection.OS, ProbeSection.DOCKER}),
    }
    args.update(kw)
    return SshTarget(**args)  # type: ignore[arg-type]


class SpyTransport:
    name = "spy"

    def __init__(self) -> None:
        self.commands: list[str] = []

    @asynccontextmanager
    async def open(self, target: SshTarget, limits: SshLimits) -> AsyncIterator["SpyTransport"]:
        self._target = target
        yield self

    async def exec(self, command: str) -> ProbeOutput:
        self.commands.append(command)
        return ProbeOutput(self._target.name, ProbeSection(command.split()[1]), 0, b"ok", b"")


def runner(audit: MemoryAudit) -> tuple[SshRunner, SpyTransport]:
    spy = SpyTransport()
    return SshRunner(transport=spy, audit=audit), spy


def test_command_table_is_constant_and_total() -> None:
    assert set(PROBE_COMMANDS) == set(ProbeSection)
    for section, cmd in PROBE_COMMANDS.items():
        assert cmd == f"atlas-probe {section.value}"
        assert re.fullmatch(r"atlas-probe [a-z]+", cmd)
    with pytest.raises(TypeError):
        PROBE_COMMANDS[ProbeSection.OS] = "rm -rf /"  # type: ignore[index]


async def test_enabled_section_runs(audit: MemoryAudit) -> None:
    r, spy = runner(audit)
    out = await r.run(target(), ProbeSection.DOCKER)
    assert out.stdout == b"ok"
    assert spy.commands == ["atlas-probe docker"]
    assert audit.events[0].op == "atlas-probe docker"
    assert audit.events[0].outcome == "ok"


async def test_section_not_enabled_for_target(audit: MemoryAudit) -> None:
    r, spy = runner(audit)
    with pytest.raises(SecurityRefusal) as exc:
        await r.run(target(), ProbeSection.CRON)
    assert exc.value.reason is RefusalReason.NOT_ALLOWLISTED
    assert spy.commands == []
    assert audit.outcomes == ["refused"]


class FakeSection(StrEnum):
    OS = "os"


class StrSub(str):
    value = "os"


INJECTIONS: list[object] = [
    "os", "atlas-probe os", "os; id", "os && id", "os || id", "os | sh", "$(id)", "`id`",
    "os\nid", "os\r\nid", "os\x00", "os #", "os &", "os > /etc/passwd", "../os", "оs",
    "OS", " os", "os ", "docker --format {{.Config.Env}}", "docker; docker rm -f x",
    b"os", 1, None, ["os"], ("os",), {"os"}, FakeSection.OS, StrSub("os"),
]  # fmt: skip


@pytest.mark.parametrize("section", INJECTIONS, ids=repr)
async def test_non_enum_sections_refused(audit: MemoryAudit, section: object) -> None:
    r, spy = runner(audit)
    with pytest.raises(SecurityRefusal) as exc:
        await r.run(target(), section)  # type: ignore[arg-type]
    assert exc.value.reason is RefusalReason.BAD_TYPE
    assert spy.commands == []
    assert audit.events[-1].op == "<invalid>"


@settings(max_examples=300, deadline=None)
@given(st.one_of(st.text(max_size=64), st.binary(max_size=16), st.integers()))
def test_fuzz_sections_never_reach_transport(section: object) -> None:
    audit = MemoryAudit()
    r, spy = runner(audit)
    with pytest.raises(SecurityRefusal):
        asyncio.run(r.run(target(), section))  # type: ignore[arg-type]
    assert spy.commands == []


async def test_duck_typed_target_refused(audit: MemoryAudit) -> None:
    r, spy = runner(audit)
    duck = type("Duck", (), {"name": "x", "sections": frozenset(ProbeSection)})()
    with pytest.raises(SecurityRefusal) as exc:
        await r.run(duck, ProbeSection.OS)
    assert exc.value.reason is RefusalReason.BAD_TYPE
    assert spy.commands == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", "a;b"),
        ("name", ""),
        ("host", "-oProxyCommand=touch /tmp/pwn"),
        ("host", "host;id"),
        ("host", "host name"),
        ("host", ""),
        ("username", "root"),
        ("username", "-l root"),
        ("username", "Admin"),
        ("port", 0),
        ("port", 70000),
        ("host_keys", ()),
        ("key_secret", "../id_ed25519"),
        ("key_secret", "C:\\Users\\x\\.ssh\\id_ed25519"),
        ("sections", frozenset({"os"})),
    ],
)
def test_target_validation(field: str, value: object) -> None:
    with pytest.raises(SecurityRefusal):
        target(**{field: value})


def test_target_ipv6_host_ok() -> None:
    assert target(host="fd00:20::11").host == "fd00:20::11"


async def test_replay_transport_uses_same_checks(audit: MemoryAudit) -> None:
    replay = ReplayTransport({("docker01", "atlas-probe os"): b"ID=debian\n"})
    r = SshRunner(transport=replay, audit=audit)
    out = await r.run(target(), ProbeSection.OS)
    assert out.stdout == b"ID=debian\n"
    assert audit.events[-1].transport == "replay"
    with pytest.raises(TransportError):
        await r.run(target(), ProbeSection.DOCKER)  # enabled, but no recording
    with pytest.raises(SecurityRefusal):
        await r.run(target(), "os")  # type: ignore[arg-type]
    assert audit.outcomes == ["ok", "error", "refused"]


async def test_replay_output_cap(audit: MemoryAudit) -> None:
    replay = ReplayTransport({("docker01", "atlas-probe os"): b"x" * 2048})
    r = SshRunner(transport=replay, audit=audit, limits=SshLimits(max_stdout=1024))
    with pytest.raises(SecurityRefusal) as exc:
        await r.run(target(), ProbeSection.OS)
    assert exc.value.reason is RefusalReason.OUTPUT_TOO_LARGE


async def test_session_checks_every_run(audit: MemoryAudit) -> None:
    r, spy = runner(audit)
    async with r.session(target()) as session:
        await session.run(ProbeSection.OS)
        await session.run(ProbeSection.DOCKER)
        with pytest.raises(SecurityRefusal):
            await session.run(ProbeSection.CRON)
        with pytest.raises(SecurityRefusal):
            await session.run("os; id")  # type: ignore[arg-type]
    assert spy.commands == ["atlas-probe os", "atlas-probe docker"]
    assert audit.outcomes == ["ok", "ok", "refused", "refused"]


async def test_replay_unreachable_target(audit: MemoryAudit) -> None:
    r = SshRunner(transport=ReplayTransport({}), audit=audit)
    with pytest.raises(TransportError):
        await r.run(target(), ProbeSection.OS)
    assert audit.events[-1].op == "connect"
    assert audit.outcomes == ["error"]
