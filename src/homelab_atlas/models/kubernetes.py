"""Kubernetes / k3s cluster facts (ADR-048). Pods churn: volatile, never diffed."""

from pydantic import Field

from homelab_atlas.models.base import Fact, keyed, volatile


class KubeNode(Fact):
    name: str
    ready: bool | None = None
    roles: list[str] = Field(default_factory=list)
    kubelet: str | None = None
    os_image: str | None = None
    kernel: str | None = None
    runtime: str | None = None
    arch: str | None = None
    internal_ip: str | None = None
    cpu: str | None = None
    memory_bytes: int | None = None
    unschedulable: bool = False
    #: Conditions other than Ready that are True (MemoryPressure, DiskPressure, ...).
    problems: list[str] = volatile(factory=list)


class KubeWorkload(Fact):
    kind: str  # Deployment | DaemonSet | StatefulSet
    namespace: str
    name: str
    images: list[str] = Field(default_factory=list)
    desired: int | None = volatile()
    ready: int | None = volatile()


class KubeService(Fact):
    namespace: str
    name: str
    type: str | None = None
    cluster_ip: str | None = None
    ports: list[str] = Field(default_factory=list)
    external: list[str] = Field(default_factory=list)


class KubePod(Fact):
    namespace: str
    name: str
    phase: str | None = None
    ready: bool = False
    containers: int = 0
    ready_containers: int = 0
    restarts: int = 0
    reason: str | None = None
    node: str | None = None
    ip: str | None = None
    owner: str | None = None  # "Deployment/web" (ReplicaSets resolved to their owner name)
    images: list[str] = Field(default_factory=list)
    started_at: str | None = None
    qos: str | None = None


class KubeClusterFacts(Fact):
    version: str | None = None
    platform: str | None = None
    namespaces: list[str] = Field(default_factory=list)
    nodes: list[KubeNode] = keyed("name")
    workloads: list[KubeWorkload] = keyed("kind", "namespace", "name")
    services: list[KubeService] = keyed("namespace", "name")
    pods: list[KubePod] = volatile(factory=list)
    truncated: list[str] = volatile(factory=list)
    section_errors: list[str] = volatile(factory=list)
