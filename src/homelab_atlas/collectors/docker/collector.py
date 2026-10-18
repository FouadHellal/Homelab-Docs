"""docker collector: probe `os` (identity) + `docker` sections over one SSH session."""

import time

from homelab_atlas.collectors.base import CollectContext, CollectorResult, FacetResult
from homelab_atlas.collectors.docker.events import docker_events
from homelab_atlas.collectors.docker.parse import parse_docker
from homelab_atlas.collectors.linux_ssh.collector import EXIT_HINTS, host_key
from homelab_atlas.collectors.linux_ssh.frame import FrameError, parse_frame
from homelab_atlas.collectors.linux_ssh.parse import parse_os
from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.models.docker import DockerHostFacts
from homelab_atlas.security.allowlist import Endpoint, ProbeSection
from homelab_atlas.security.errors import SecurityRefusal, TransportError


class DockerCollector:
    name = "docker"
    kind = "linux-host"
    requires = frozenset({ProbeSection.OS, ProbeSection.DOCKER})
    endpoints: frozenset[Endpoint] = frozenset()

    def targets(self, inventory: Inventory) -> list[str]:
        return [h.name for h in inventory.hosts if self.name in h.collectors]

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]:
        return docker_events(key, name, changes)

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult:
        start = time.monotonic()
        host = ctx.inventory.host(target)
        result = CollectorResult(self.name, host.name, "failed")
        errors: list[str] = []
        machine_id: str | None = None
        values: dict[str, object] = {}
        try:
            ssh_target = ctx.inventory.ssh_target(host, self.requires)
            async with ctx.ssh.session(ssh_target) as session:
                for section in (ProbeSection.OS, ProbeSection.DOCKER):
                    try:
                        out = await session.run(section)
                    except (SecurityRefusal, TransportError) as exc:
                        errors.append(f"{section.value}: {type(exc).__name__}")
                        continue
                    if out.exit_status != 0:
                        hint = EXIT_HINTS.get(out.exit_status, f"exit {out.exit_status}")
                        errors.append(f"{section.value}: {hint}")
                        continue
                    try:
                        frame = parse_frame(out.stdout, section)
                    except FrameError as exc:
                        errors.append(f"{section.value}: frame: {exc}")
                        continue
                    if section is ProbeSection.OS:
                        os_info = parse_os(frame).values.get("os")
                        machine_id = getattr(os_info, "machine_id", None)
                    else:
                        parsed = parse_docker(frame)
                        values.update(parsed.values)
                        errors.extend(f"docker: {e}" for e in frame.errors + parsed.errors)
        except SecurityRefusal as exc:
            result.status, result.errors = "refused", [f"refused: {exc.reason.value}"]
            return self._done(result, start)
        except TransportError as exc:
            result.errors = [f"unreachable: {exc}"]
            return self._done(result, start)

        result.errors = errors
        if "engine_version" not in values:
            return self._done(result, start)
        facts = DockerHostFacts.model_validate({**values, "section_errors": {"docker": errors}})
        hkey = host_key(machine_id, host.name)
        result.facets = [FacetResult(hkey, self.kind, host.name, facts)]
        for c in facts.containers:
            result.facets.append(
                FacetResult(f"ctr:{hkey}/{c.key}", "container", f"{host.name}/{c.key}", None, hkey)
            )
        for p in facts.compose_projects:
            result.facets.append(
                FacetResult(
                    f"compose:{hkey}/{p.name}",
                    "compose-project",
                    f"{host.name}/{p.name}",
                    None,
                    hkey,
                )
            )
        result.complete = True
        result.status = "partial" if errors else "ok"
        return self._done(result, start)

    @staticmethod
    def _done(result: CollectorResult, start: float) -> CollectorResult:
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result
