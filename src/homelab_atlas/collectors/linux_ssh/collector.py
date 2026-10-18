"""linux-ssh collector: one SSH session per host, one probe section at a time."""

import time
from collections.abc import Callable
from typing import Final

from homelab_atlas.collectors.base import CollectContext, CollectorResult, FacetResult
from homelab_atlas.collectors.linux_ssh import parse
from homelab_atlas.collectors.linux_ssh.frame import Frame, FrameError, parse_frame
from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec, linux_events
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.models.linux import LinuxHostFacts
from homelab_atlas.probe.render import probe_sha256
from homelab_atlas.security.allowlist import Endpoint, ProbeSection
from homelab_atlas.security.errors import SecurityRefusal, TransportError

S = ProbeSection
EXIT_HINTS: Final = {
    1: "sudo refused (is /etc/sudoers.d/atlas-ro installed?)",
    3: "section not implemented by the installed probe",
    64: "gate refused the request (gate or probe out of date?)",
    126: "probe not executable",
    127: "probe or gate not installed",
}


def _parsers(expected_sha: str) -> list[tuple[ProbeSection, Callable[[Frame], parse.Parsed]]]:
    return [
        (S.VERSION, lambda f: parse.parse_version(f, expected_sha)),
        (S.OS, parse.parse_os),
        (S.NET, parse.parse_net),
        (S.PORTS, parse.parse_ports),
        (S.STORAGE, parse.parse_storage),
        (S.SERVICES, parse.parse_services),
        (S.CRON, parse.parse_cron),
        (S.USERS, parse.parse_users),
        (S.PACKAGES, parse.parse_packages),
    ]


def host_key(machine_id: str | None, name: str) -> str:
    """Stable host identity shared by every SSH collector (SPEC §5)."""
    return f"host:{machine_id}" if machine_id else f"host:name:{name}"


class LinuxSshCollector:
    name = "linux-ssh"
    kind = "linux-host"
    requires = frozenset(
        {S.VERSION, S.OS, S.NET, S.PORTS, S.STORAGE, S.SERVICES, S.CRON, S.USERS, S.PACKAGES}
    )
    endpoints: frozenset[Endpoint] = frozenset()

    def targets(self, inventory: Inventory) -> list[str]:
        return [h.name for h in inventory.hosts if self.name in h.collectors]

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]:
        return linux_events(key, name, changes)

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult:
        start = time.monotonic()
        host = ctx.inventory.host(target)
        result = CollectorResult(self.name, host.name, "failed")
        values: dict[str, object] = {}
        section_errors: dict[str, list[str]] = {}
        try:
            ssh_target = ctx.inventory.ssh_target(host, self.requires)
            async with ctx.ssh.session(ssh_target) as session:
                for section, parser in _parsers(probe_sha256()):
                    errs = section_errors.setdefault(section.value, [])
                    try:
                        out = await session.run(section)
                    except SecurityRefusal as exc:
                        errs.append(f"refused: {exc.reason.value}")
                        continue
                    except TransportError as exc:
                        errs.append(f"transport: {type(exc).__name__}")
                        continue
                    if out.exit_status != 0:
                        errs.append(EXIT_HINTS.get(out.exit_status, f"exit {out.exit_status}"))
                        continue
                    try:
                        frame = parse_frame(out.stdout, section)
                    except FrameError as exc:
                        errs.append(f"frame: {exc}")
                        continue
                    parsed = parser(frame)
                    values.update(parsed.values)
                    errs.extend(frame.errors + parsed.errors)
        except SecurityRefusal as exc:
            result.status = "refused"
            result.errors = [f"refused: {exc.reason.value}: {exc.detail}"]
            return self._done(result, start)
        except TransportError as exc:
            result.errors = [f"unreachable: {exc}"]
            return self._done(result, start)

        section_errors = {k: v for k, v in section_errors.items() if v}
        if not values:
            result.errors = [f"{k}: {'; '.join(v)}" for k, v in sorted(section_errors.items())]
            return self._done(result, start)
        facts = LinuxHostFacts.model_validate({**values, "section_errors": section_errors})
        mid = facts.os.machine_id if facts.os else None
        key = host_key(mid, host.name)
        result.facets = [FacetResult(key, self.kind, host.name, facts)]
        result.complete = True
        result.status = "partial" if section_errors else "ok"
        result.errors = [f"{k}: {'; '.join(v)}" for k, v in sorted(section_errors.items())]
        return self._done(result, start)

    @staticmethod
    def _done(result: CollectorResult, start: float) -> CollectorResult:
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result
