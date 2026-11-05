"""kubernetes collector (ADR-048): nodes, workloads, services and pods of a Kubernetes / k3s
cluster, read over the API with a read-only ServiceAccount token.

Sources: the Kubernetes API reference (kubernetes.io/docs/reference/kubernetes-api, Pod v1,
Node v1, Deployment v1, read 2026-11-05; current docs, v1.37 menu): list endpoints
`GET /api/v1/{nodes,namespaces,pods,services}` and `GET /apis/apps/v1/{deployments,
daemonsets,statefulsets}` with the `limit` query parameter; PodStatus `phase`, `podIP`,
`startTime`, `qosClass`, `containerStatuses` (`state.waiting.reason`,
`state.terminated.reason`), PodSpec `nodeName`; NodeStatus `conditions` (True/False/Unknown),
`nodeInfo` (`kubeletVersion`, `osImage`, `kernelVersion`, `containerRuntimeVersion`,
`architecture`), `capacity`, `addresses` (InternalIP), NodeSpec `unschedulable`;
DeploymentSpec `replicas`, status `readyReplicas`. Every field is read as optional.

GET only, seven fixed list endpoints. Secrets, ConfigMaps, logs, exec, attach, port-forward
and proxy are not registered, so the client cannot reach them even if the token could; the
RBAC in docs/targets/kubernetes-readonly.yaml does not grant them either. Pod environment
variables, commands and volumes are never read.
"""

import time
from collections.abc import Mapping
from typing import Any, Final

from homelab_atlas.collectors.base import ApiSource, CollectContext, CollectorResult, FacetResult
from homelab_atlas.collectors.linux_ssh.parse import norm_ip
from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec, Severity
from homelab_atlas.inventory.hosts import Inventory, K8sSource
from homelab_atlas.models.kubernetes import (
    KubeClusterFacts,
    KubeNode,
    KubePod,
    KubeService,
    KubeWorkload,
)
from homelab_atlas.security.allowlist import Endpoint, ProbeSection
from homelab_atlas.security.errors import HttpStatusError, SecurityRefusal, TransportError
from homelab_atlas.security.http import ReadOnlyHttpClient

LIMIT: Final = 2000
_Q: Final = {"limit": r"[1-9][0-9]{0,3}"}
VERSION = Endpoint("k8s.version", "GET", "/version")
NODES = Endpoint("k8s.nodes", "GET", "/api/v1/nodes", query=_Q)
NAMESPACES = Endpoint("k8s.namespaces", "GET", "/api/v1/namespaces", query=_Q)
PODS = Endpoint("k8s.pods", "GET", "/api/v1/pods", query=_Q)
SERVICES = Endpoint("k8s.services", "GET", "/api/v1/services", query=_Q)
DEPLOYMENTS = Endpoint("k8s.deployments", "GET", "/apis/apps/v1/deployments", query=_Q)
DAEMONSETS = Endpoint("k8s.daemonsets", "GET", "/apis/apps/v1/daemonsets", query=_Q)
STATEFULSETS = Endpoint("k8s.statefulsets", "GET", "/apis/apps/v1/statefulsets", query=_Q)
ENDPOINTS: Final = frozenset(
    {VERSION, NODES, NAMESPACES, PODS, SERVICES, DEPLOYMENTS, DAEMONSETS, STATEFULSETS}
)
#: Waiting/terminated reasons that mean "broken", not "starting".
BAD_REASONS: Final = frozenset(
    {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "CreateContainerConfigError",
        "InvalidImageName",
        "OOMKilled",
        "Error",
        "ContainerCannotRun",
        "RunContainerError",
    }
)


def _s(v: Any, limit: int = 253) -> str | None:
    return v[:limit] if isinstance(v, str) and v else None


def _d(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _l(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _items(body: Any) -> tuple[list[dict[str, Any]], bool]:
    """Items of a List answer, and whether the server cut it short (`metadata.continue`)."""
    b = _d(body)
    return [i for i in _l(b.get("items")) if isinstance(i, dict)], bool(
        _d(b.get("metadata")).get("continue")
    )


def _mem(q: Any) -> int | None:
    """Kubernetes quantity for memory ("16Gi", "16384Mi", "17179869184") -> bytes."""
    if not isinstance(q, str) or not q:
        return None
    units = {
        "Ki": 1 << 10,
        "Mi": 1 << 20,
        "Gi": 1 << 30,
        "Ti": 1 << 40,
        "K": 10**3,
        "M": 10**6,
        "G": 10**9,
    }
    for suffix, mult in units.items():
        if q.endswith(suffix) and q[: -len(suffix)].isdigit():
            return int(q[: -len(suffix)]) * mult
    return int(q) if q.isdigit() else None


def node(n: dict[str, Any]) -> KubeNode | None:
    meta, st, spec = _d(n.get("metadata")), _d(n.get("status")), _d(n.get("spec"))
    name = _s(meta.get("name"))
    if name is None:
        return None
    conds = {
        str(c.get("type")): c.get("status") for c in _l(st.get("conditions")) if isinstance(c, dict)
    }
    info, cap = _d(st.get("nodeInfo")), _d(st.get("capacity"))
    roles = sorted(
        k.removeprefix("node-role.kubernetes.io/")
        for k in _d(meta.get("labels"))
        if k.startswith("node-role.kubernetes.io/")
    )
    ip = next(
        (a.get("address") for a in _l(st.get("addresses")) if _d(a).get("type") == "InternalIP"),
        None,
    )
    return KubeNode(
        name=name,
        ready={"True": True, "False": False}.get(str(conds.get("Ready"))),
        roles=[r[:64] for r in roles][:10],
        kubelet=_s(info.get("kubeletVersion"), 64),
        os_image=_s(info.get("osImage"), 128),
        kernel=_s(info.get("kernelVersion"), 64),
        runtime=_s(info.get("containerRuntimeVersion"), 64),
        arch=_s(info.get("architecture"), 16),
        internal_ip=norm_ip(ip) if isinstance(ip, str) else None,
        cpu=_s(cap.get("cpu"), 16),
        memory_bytes=_mem(cap.get("memory")),
        unschedulable=spec.get("unschedulable") is True,
        problems=sorted(k for k, v in conds.items() if k != "Ready" and v == "True")[:10],
    )


def pod(p: dict[str, Any], rs_owner: Mapping[tuple[str, str], str]) -> KubePod | None:
    meta, st, spec = _d(p.get("metadata")), _d(p.get("status")), _d(p.get("spec"))
    ns, name = _s(meta.get("namespace"), 63), _s(meta.get("name"))
    if ns is None or name is None:
        return None
    owner = None
    for ref in _l(meta.get("ownerReferences")):
        kind, oname = _s(_d(ref).get("kind"), 32), _s(_d(ref).get("name"))
        if kind and oname:
            owner = rs_owner.get((ns, oname)) if kind == "ReplicaSet" else f"{kind}/{oname}"
            owner = owner or f"{kind}/{oname}"
            break
    statuses = [c for c in _l(st.get("containerStatuses")) if isinstance(c, dict)]
    reason = None
    for c in statuses:
        for key in ("state", "lastState"):
            for phase in ("waiting", "terminated"):
                r = _s(_d(_d(c.get(key)).get(phase)).get("reason"), 64)
                if r in BAD_REASONS and (key == "state" or not c.get("ready")):
                    reason = reason or r
    restarts = sum(c["restartCount"] for c in statuses if isinstance(c.get("restartCount"), int))
    ready = sum(1 for c in statuses if c.get("ready") is True)
    return KubePod(
        namespace=ns,
        name=name,
        phase=_s(st.get("phase"), 16),
        ready=bool(statuses) and ready == len(statuses),
        containers=len(statuses),
        ready_containers=ready,
        restarts=restarts,
        reason=reason,
        node=_s(spec.get("nodeName")),
        ip=_s(st.get("podIP"), 64),
        owner=owner,
        images=sorted({i for c in statuses if (i := _s(c.get("image"), 256))})[:10],
        started_at=_s(st.get("startTime"), 32),
        qos=_s(st.get("qosClass"), 16),
    )


def workload(kind: str, w: dict[str, Any]) -> KubeWorkload | None:
    meta, spec, st = _d(w.get("metadata")), _d(w.get("spec")), _d(w.get("status"))
    ns, name = _s(meta.get("namespace"), 63), _s(meta.get("name"))
    if ns is None or name is None:
        return None
    containers = _l(_d(_d(_d(spec.get("template")).get("spec"))).get("containers"))
    if kind == "DaemonSet":
        desired, ready = st.get("desiredNumberScheduled"), st.get("numberReady")
    else:
        desired, ready = spec.get("replicas"), st.get("readyReplicas", 0)
    return KubeWorkload(
        kind=kind,
        namespace=ns,
        name=name,
        images=sorted({i for c in containers if (i := _s(_d(c).get("image"), 256))})[:10],
        desired=desired if isinstance(desired, int) else None,
        ready=ready if isinstance(ready, int) else None,
    )


def service(sv: dict[str, Any]) -> KubeService | None:
    meta, spec = _d(sv.get("metadata")), _d(sv.get("spec"))
    ns, name = _s(meta.get("namespace"), 63), _s(meta.get("name"))
    if ns is None or name is None:
        return None
    ports = []
    for raw in _l(spec.get("ports")):
        p = _d(raw)
        port, proto, node_port = p.get("port"), _s(p.get("protocol"), 8) or "TCP", p.get("nodePort")
        if isinstance(port, int):
            ports.append(
                f"{port}/{proto.lower()}" + (f"→{node_port}" if isinstance(node_port, int) else "")
            )
    ingress = _l(_d(_d(sv.get("status")).get("loadBalancer")).get("ingress"))
    external = [
        x for x in (_s(_d(i).get("ip"), 64) or _s(_d(i).get("hostname")) for i in ingress) if x
    ]
    return KubeService(
        namespace=ns,
        name=name,
        type=_s(spec.get("type"), 16),
        cluster_ip=_s(spec.get("clusterIP"), 64),
        ports=ports[:20],
        external=(external + [x for x in _l(spec.get("externalIPs")) if isinstance(x, str)])[:10],
    )


async def collect_cluster(client: ReadOnlyHttpClient) -> KubeClusterFacts:
    ver = _d((await client.get(VERSION)).json())  # the only fatal call
    errors: list[str] = []
    truncated: list[str] = []

    async def lst(ep: Endpoint) -> list[dict[str, Any]]:
        try:
            items, cut = _items((await client.get(ep, None, {"limit": LIMIT})).json())
        except HttpStatusError as exc:
            hint = " (the token's ClusterRole does not allow it)" if exc.status == 403 else ""
            errors.append(f"{ep.path_template}: HTTP {exc.status}{hint}")
            return []
        except (TransportError, ValueError) as exc:
            errors.append(f"{ep.path_template}: {type(exc).__name__}")
            return []
        if cut:
            truncated.append(ep.path_template)
        return items

    rs_owner: dict[tuple[str, str], str] = {}
    workloads: list[KubeWorkload] = []
    for kind, ep in (
        ("Deployment", DEPLOYMENTS),
        ("DaemonSet", DAEMONSETS),
        ("StatefulSet", STATEFULSETS),
    ):
        for w in await lst(ep):
            wl = workload(kind, w)
            if wl is not None:
                workloads.append(wl)
                if kind == "Deployment":
                    # ReplicaSets are named <deployment>-<hash>: map them back without listing them.
                    rs_owner[(wl.namespace, wl.name)] = f"Deployment/{wl.name}"
    pods_raw = await lst(PODS)
    for p in pods_raw:
        for ref in _l(_d(p.get("metadata")).get("ownerReferences")):
            rname, ns = _s(_d(ref).get("name")), _s(_d(p.get("metadata")).get("namespace"), 63)
            if _d(ref).get("kind") == "ReplicaSet" and rname and ns and "-" in rname:
                base = rname.rsplit("-", 1)[0]
                if (ns, base) in rs_owner:
                    rs_owner[(ns, rname)] = rs_owner[(ns, base)]
    return KubeClusterFacts(
        version=_s(ver.get("gitVersion"), 64),
        platform=_s(ver.get("platform"), 32),
        namespaces=sorted(
            ns for i in await lst(NAMESPACES) if (ns := _s(_d(i.get("metadata")).get("name"), 63))
        )[:500],
        nodes=sorted((kn for i in await lst(NODES) if (kn := node(i))), key=lambda n: n.name),
        workloads=sorted(workloads, key=lambda w: (w.namespace, w.kind, w.name))[:2000],
        services=sorted(
            (sv for i in await lst(SERVICES) if (sv := service(i))),
            key=lambda s: (s.namespace, s.name),
        )[:2000],
        pods=sorted(
            (x for p in pods_raw if (x := pod(p, rs_owner))), key=lambda p: (p.namespace, p.name)
        )[:LIMIT],
        truncated=truncated,
        section_errors=errors,
    )


def _wl(key: str) -> str:
    """`Deployment|apps|whoami` -> `apps/whoami` (the workload's identity in the diff)."""
    parts = key.split("|")
    return f"{parts[1]}/{parts[2]}" if len(parts) == 3 else key


def k8s_events(key: str, name: str, changes: list[Change]) -> list[EventSpec]:
    out: list[EventSpec] = []

    def ev(t: str, sev: Severity, summary: str, c: Change) -> None:
        out.append(EventSpec(key, t, sev, f"{name}: {summary}", c.dotted, c.old, c.new))

    for c in changes:
        p = c.path
        if p[0] == "workloads" and len(p) == 2:
            ev(f"k8s.workload_{c.kind}", "info", f"workload {_wl(p[1])} {c.kind}", c)
        elif p[0] == "workloads" and len(p) >= 3 and p[2] == "images" and c.kind == "added":
            ev("k8s.image_changed", "notice", f"{_wl(p[1])} now runs {p[-1]}", c)
        elif p[0] == "nodes" and len(p) == 2:
            ev(f"k8s.node_{c.kind}", "notice", f"node {p[1]} {c.kind}", c)
        elif p == ("version",):
            ev("k8s.upgraded", "notice", f"Kubernetes {c.old} -> {c.new}", c)
    return out


class KubernetesCollector:
    name = "kubernetes"
    requires: frozenset[ProbeSection] = frozenset()
    endpoints = ENDPOINTS

    def targets(self, inventory: Inventory) -> list[str]:
        return [s.name for s in inventory.sources.k8s]

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]:
        return k8s_events(key, name, changes)

    @staticmethod
    def source(inventory: Inventory, name: str) -> ApiSource:
        src: K8sSource = next(s for s in inventory.sources.k8s if s.name == name)
        return ApiSource(src.name, src.url, src.credential, src.tls, "bearer")

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult:
        start = time.monotonic()
        result = CollectorResult(self.name, target, "failed")
        if ctx.http is None:
            result.errors = ["no HTTP factory configured"]
            return result
        try:
            async with ctx.http(self.source(ctx.inventory, target), self.endpoints) as client:
                facts = await collect_cluster(client)
        except SecurityRefusal as exc:
            result.status, result.errors = "refused", [f"refused: {exc.reason.value}: {exc.detail}"]
            return _done(result, start)
        except HttpStatusError as exc:
            hint = {
                401: ": the token was refused (expired or deleted?)",
                403: ": the token may not read /version",
            }.get(exc.status, "")
            result.errors = [f"HTTP {exc.status}{hint}"]
            return _done(result, start)
        except TransportError as exc:
            result.errors = [f"unreachable: {exc}"]
            return _done(result, start)
        except ValueError:
            result.errors = ["/version did not return JSON (is this the Kubernetes API?)"]
            return _done(result, start)
        key = f"k8s:{target}"
        result.facets = [FacetResult(key, "k8s-cluster", f"{target} (Kubernetes)", facts)]
        result.facets += [
            FacetResult(f"{key}/node/{n.name}", "k8s-node", f"{n.name} ({target})", None, key)
            for n in facts.nodes
        ]
        result.errors = [
            *facts.section_errors,
            *(f"{p}: more than {LIMIT} items" for p in facts.truncated),
        ]
        result.status = "partial" if result.errors else "ok"
        result.complete = True
        return _done(result, start)


def _done(result: CollectorResult, start: float) -> CollectorResult:
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
