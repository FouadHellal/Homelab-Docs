"""Facts collected by the docker collector (probe `docker` section)."""

from pydantic import Field

from homelab_atlas.models.base import Fact, keyed, volatile


class PublishedPort(Fact):
    container_port: int
    proto: str
    host_ip: str
    host_port: int


class ContainerMount(Fact):
    destination: str
    type: str
    source: str | None = None
    name: str | None = None
    rw: bool = True


class ContainerNetwork(Fact):
    network: str
    ip: str | None = volatile()  # dynamic on bridge networks
    ip6: str | None = volatile()
    mac: str | None = volatile()


class Container(Fact):
    #: Stable identity: <compose project>/<service>/<replica>, or name/<container name>.
    key: str
    name: str
    compose_project: str | None = None
    compose_service: str | None = None
    image: str
    image_id: str
    status: str
    health: str | None = None
    restart_count: int = 0
    restart_policy: str | None = None
    user: str | None = None
    privileged: bool = False
    readonly_rootfs: bool = False
    network_mode: str | None = None
    docker_socket: bool = False  # /var/run/docker.sock mounted: root-equivalent
    cap_add: list[str] = Field(default_factory=list)
    env_names: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    cmd: list[str] = Field(default_factory=list)
    entrypoint: list[str] = Field(default_factory=list)
    healthcheck: list[str] = Field(default_factory=list)
    ports: list[PublishedPort] = keyed("proto", "host_ip", "host_port", "container_port")
    mounts: list[ContainerMount] = keyed("destination")
    networks: list[ContainerNetwork] = keyed("network")
    container_id: str = volatile("")  # changes on every recreate
    started_at: str | None = volatile()
    exit_code: int | None = volatile()


class Image(Fact):
    id: str
    tags: list[str] = Field(default_factory=list)
    digests: list[str] = Field(default_factory=list)
    created: str | None = None
    size_bytes: int | None = None
    arch: str | None = None


class DockerNetwork(Fact):
    name: str
    driver: str | None = None
    scope: str | None = None
    internal: bool = False
    ipv6: bool = False
    subnets: list[str] = Field(default_factory=list)
    id: str = volatile("")


class Volume(Fact):
    name: str
    driver: str | None = None
    mountpoint: str | None = None


class ComposeProject(Fact):
    name: str
    config_files: list[str] = Field(default_factory=list)
    status: str | None = volatile()  # "running(4)" style counts


class DockerHostFacts(Fact):
    engine_version: str | None = None
    api_version: str | None = None
    containers: list[Container] = keyed("key")
    images: list[Image] = keyed("id")
    networks: list[DockerNetwork] = keyed("name")
    volumes: list[Volume] = keyed("name")
    compose_projects: list[ComposeProject] = keyed("name")
    section_errors: dict[str, list[str]] = volatile(factory=dict)
