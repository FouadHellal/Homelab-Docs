"""docker collector: probe `os` (identity) + `docker` sections over one SSH session."""

from pydantic import BaseModel

from homelab_atlas.collectors.base import CollectContext, CollectorResult, FacetResult
from homelab_atlas.collectors.docker.events import docker_events
from homelab_atlas.collectors.docker.parse import parse_docker
from homelab_atlas.collectors.linux_ssh.frame import Frame
from homelab_atlas.collectors.probe_session import collect_section
from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.models.docker import DockerHostFacts
from homelab_atlas.security.allowlist import Endpoint, ProbeSection


def _build(frame: Frame, errors: list[str]) -> DockerHostFacts | None:
    parsed = parse_docker(frame)
    errors.extend(f"docker: {e}" for e in parsed.errors)
    if "engine_version" not in parsed.values:
        return None
    return DockerHostFacts.model_validate({**parsed.values, "section_errors": {"docker": errors}})


def _children(hkey: str, host: str, model: BaseModel) -> list[FacetResult]:
    assert isinstance(model, DockerHostFacts)  # noqa: S101 - built by _build above
    out = [
        FacetResult(f"ctr:{hkey}/{c.key}", "container", f"{host}/{c.key}", None, hkey)
        for c in model.containers
    ]
    out += [
        FacetResult(f"compose:{hkey}/{p.name}", "compose-project", f"{host}/{p.name}", None, hkey)
        for p in model.compose_projects
    ]
    return out


class DockerCollector:
    name = "docker"
    requires = frozenset({ProbeSection.OS, ProbeSection.DOCKER})
    endpoints: frozenset[Endpoint] = frozenset()

    def targets(self, inventory: Inventory) -> list[str]:
        return [h.name for h in inventory.hosts if self.name in h.collectors]

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]:
        return docker_events(key, name, changes)

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult:
        return await collect_section(
            ctx,
            target,
            collector=self.name,
            section=ProbeSection.DOCKER,
            requires=self.requires,
            build=_build,
            children=_children,
        )
