"""linux-ssh collector error paths: exit codes, bad frames, refusals, lost sessions."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from homelab_atlas.collectors.base import CollectContext
from homelab_atlas.collectors.linux_ssh.collector import LinuxSshCollector
from homelab_atlas.inventory.hosts import load_inventory
from homelab_atlas.lab import load_lab
from homelab_atlas.security.allowlist import ProbeSection
from homelab_atlas.security.errors import RefusalReason, SecurityRefusal, TransportError
from homelab_atlas.security.ssh import ProbeOutput, SshLimits, SshRunner, SshTarget
from tests.helpers import MemoryAudit

REPO = Path(__file__).resolve().parents[2]
LAB = REPO / "fixtures" / "demo-lab"


class ScriptedTransport:
    """Replays demo-lab web01 output, with per-section overrides."""

    name = "replay"

    def __init__(self, overrides: dict[str, object], open_error: Exception | None = None) -> None:
        _, replay = load_lab("A", LAB)
        self._replay = replay
        self._overrides = overrides
        self._open_error = open_error

    @asynccontextmanager
    async def open(
        self, target: SshTarget, limits: SshLimits
    ) -> AsyncIterator["ScriptedTransport"]:
        if self._open_error is not None:
            raise self._open_error
        async with self._replay.open(target, limits) as inner:
            self._inner, self._target = inner, target
            yield self

    async def exec(self, command: str) -> ProbeOutput:
        section = command.split()[1]
        o = self._overrides.get(section)
        if isinstance(o, Exception):
            raise o
        if isinstance(o, tuple):
            code, data = o
            return ProbeOutput(self._target.name, ProbeSection(section), code, data, b"")
        return await self._inner.exec(command)


async def collect(transport: ScriptedTransport) -> tuple[object, MemoryAudit]:
    inv = load_inventory(LAB / "hosts.yaml")
    audit = MemoryAudit()
    ctx = CollectContext(inventory=inv, ssh=SshRunner(transport=transport, audit=audit))
    return await LinuxSshCollector().collect("web01", ctx), audit


async def test_section_failures_give_partial_result() -> None:
    result, _ = await collect(
        ScriptedTransport(
            {
                "cron": (1, b""),
                "users": (64, b""),
                "packages": (127, b""),
                "storage": (0, b"not a frame"),
                "services": TransportError("channel closed"),
                "ports": SecurityRefusal(RefusalReason.OUTPUT_TOO_LARGE, "big"),
            }
        )
    )
    assert result.status == "partial"  # type: ignore[attr-defined]
    errors = "\n".join(result.errors)  # type: ignore[attr-defined]
    assert "sudo refused" in errors
    assert "gate refused" in errors
    assert "not installed" in errors
    assert "frame: missing or malformed probe header" in errors
    assert "transport: TransportError" in errors
    assert "refused: output_too_large" in errors
    facts = result.facets[0].model  # type: ignore[attr-defined]
    assert facts.os.hostname == "web01"
    assert facts.section_errors["cron"] == ["sudo refused (is /etc/sudoers.d/atlas-ro installed?)"]


async def test_all_sections_fail_means_failed() -> None:
    overrides: dict[str, object] = {s.value: (127, b"") for s in LinuxSshCollector.requires}
    result, _ = await collect(ScriptedTransport(overrides))
    assert result.status == "failed"  # type: ignore[attr-defined]
    assert result.facets == []  # type: ignore[attr-defined]


async def test_host_key_refusal_on_connect() -> None:
    result, audit = await collect(
        ScriptedTransport({}, open_error=SecurityRefusal(RefusalReason.HOST_KEY, "mismatch"))
    )
    assert result.status == "refused"  # type: ignore[attr-defined]
    assert audit.events[-1].op == "connect"
    assert audit.outcomes == ["refused"]


async def test_entity_key_falls_back_to_name_without_machine_id() -> None:
    result, _ = await collect(
        ScriptedTransport({"os": (0, b"ATLAS-PROBE 1 os " + b"0" * 24 + b"\n")})
    )
    assert result.primary_key == "host:name:web01"  # type: ignore[attr-defined]
