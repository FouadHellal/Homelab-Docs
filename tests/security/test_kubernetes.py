"""ADR-048: Kubernetes collector — read-only reach, parsing, no secrets, alert rules."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from homelab_atlas.collectors import kubernetes as k8s
from homelab_atlas.engine import alerts
from homelab_atlas.lab import load_api_recordings, load_lab
from homelab_atlas.models.kubernetes import KubeClusterFacts
from homelab_atlas.runtime import Runtime
from homelab_atlas.security.allowlist import Endpoint
from homelab_atlas.security.errors import RefusalReason, SecurityRefusal
from homelab_atlas.security.http import ReadOnlyHttpClient, replay_transport
from homelab_atlas.store.facets import FacetView
from tests.helpers import MemoryAudit, scanned_lab

pytestmark = pytest.mark.security
LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"
FORBIDDEN = (
    "secret",
    "configmap",
    "exec",
    "attach",
    "log",
    "portforward",
    "proxy",
    "token",
    "eviction",
)


def _client(state: str = "B", transport: Any = None) -> ReadOnlyHttpClient:
    return ReadOnlyHttpClient(
        target="k3s",
        base_url="https://k3s.lab.example:6443",
        endpoints=k8s.ENDPOINTS,
        audit=MemoryAudit(),
        tls=None,
        transport=transport or replay_transport(load_api_recordings(state, LAB)["k3s"]),
    )


def facts(state: str) -> KubeClusterFacts:
    async def go() -> KubeClusterFacts:
        async with _client(state) as c:
            return await k8s.collect_cluster(c)

    return asyncio.run(go())


def test_only_get_list_endpoints_and_nothing_sensitive() -> None:
    for ep in k8s.ENDPOINTS:
        assert ep.method == "GET"
        path = ep.path_template.lower()
        assert not any(word in path for word in FORBIDDEN), path
    assert {e.path_template for e in k8s.ENDPOINTS} == {
        "/version", "/api/v1/nodes", "/api/v1/namespaces", "/api/v1/pods", "/api/v1/services",
        "/apis/apps/v1/deployments", "/apis/apps/v1/daemonsets", "/apis/apps/v1/statefulsets",
    }  # fmt: skip


@pytest.mark.parametrize(
    "path", ["/api/v1/secrets", "/api/v1/namespaces/default/pods/x/log", "/api/v1/configmaps"]
)
def test_secrets_logs_and_configmaps_cannot_be_reached(path: str) -> None:
    async def go() -> None:
        async with _client() as c:
            await c.get(Endpoint("k8s.x", "GET", path))

    with pytest.raises(SecurityRefusal) as exc:
        asyncio.run(go())
    assert exc.value.reason is RefusalReason.NOT_ALLOWLISTED


def test_limit_query_is_numeric_only() -> None:
    async def go() -> None:
        async with _client() as c:
            await c.get(k8s.PODS, None, {"limit": "1&fieldSelector=x"})

    with pytest.raises(SecurityRefusal):
        asyncio.run(go())


def test_demo_cluster_is_parsed_and_env_values_never_kept() -> None:
    b = facts("B")
    assert b.version == "v1.33.4+k3s1"
    assert [n.name for n in b.nodes] == ["k3s-cp1", "k3s-w1", "k3s-w2"]
    cp = b.nodes[0]
    assert cp.ready is True and "control-plane" in cp.roles and cp.internal_ip == "10.0.20.71"
    assert cp.memory_bytes == 8048140 * 1024 and cp.cpu == "4" and cp.problems == []
    assert {"apps", "monitoring", "kube-system"} <= set(b.namespaces)
    who = next(w for w in b.workloads if w.name == "whoami")
    assert (who.kind, who.desired, who.ready, who.images) == (
        "Deployment",
        2,
        2,
        ["traefik/whoami:v1.11"],
    )
    graf = next(p for p in b.pods if p.name.startswith("grafana"))
    assert (graf.reason, graf.restarts, graf.ready, graf.owner) == (
        "CrashLoopBackOff",
        12,
        False,
        "Deployment/grafana",
    )
    pg = next(p for p in b.pods if p.name.startswith("postgres"))
    assert pg.owner == "StatefulSet/postgres" and pg.node == "k3s-w2"
    lb = next(s for s in b.services if s.name == "traefik")
    assert (
        lb.type == "LoadBalancer" and lb.external == ["10.0.20.71"] and "80/tcp→31080" in lb.ports
    )
    dump = json.dumps(b.model_dump())
    assert "ATLASFAKE" not in dump and "DB_PASSWORD" not in dump


@settings(max_examples=60, deadline=None)
@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=8),
        lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=8), c, max_size=4),
        max_leaves=20,
    )
)
def test_parsers_are_total(junk: Any) -> None:
    for item in (junk, {"metadata": junk, "status": junk, "spec": junk}):
        if isinstance(item, dict):
            k8s.node(item)
            k8s.pod(item, {})
            k8s.workload("Deployment", item)
            k8s.service(item)
    k8s._items(junk)
    k8s._mem(junk)


def test_a_403_on_one_list_is_a_section_error_not_a_failure() -> None:
    rec = load_api_recordings("A", LAB)["k3s"]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v1/services":
            return httpx.Response(403, json={"kind": "Status", "reason": "Forbidden"})
        status, body = rec.get(req.url.raw_path.decode(), (404, b"{}"))
        return httpx.Response(status, content=body)

    async def go() -> KubeClusterFacts:
        async with _client(transport=httpx.MockTransport(handler)) as c:
            return await k8s.collect_cluster(c)

    f = asyncio.run(go())
    assert f.services == [] and f.nodes
    assert f.section_errors == [
        "/api/v1/services: HTTP 403 (the token's ClusterRole does not allow it)"
    ]


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    return scanned_lab(tmp_path_factory.mktemp("k8s"))


def test_crash_loop_and_not_ready_node_become_incidents(rt: Runtime) -> None:
    inv, _ = load_lab("B", LAB)
    with rt.sessions() as s:
        got = {
            c.key: c
            for c in alerts.conditions(s, inv, {}, datetime.now(UTC), alerts.builtin_rules())
        }
    pod = next(c for k, c in got.items() if k.startswith("k8s.pod:"))
    assert (
        "CrashLoopBackOff" in pod.title and pod.key == "k8s.pod:k3s/monitoring/Deployment/grafana"
    )
    sc = alerts.Scope(None, None, {}, datetime.now(UTC))  # type: ignore[arg-type]
    view = FacetView("k8s:x", "kubernetes", "x", 1, {"nodes": [{"name": "w9", "ready": False,
                            "problems": ["DiskPressure"]}]}, "kubernetes")  # fmt: skip
    sc._views, sc._runs = [view], {}
    assert [f.title for f in alerts.BY_TYPE["k8s.node"].detect(sc, {})] == [
        "Kubernetes node w9 is not ready"
    ]


def test_kubernetes_page_and_command_center_card(rt: Runtime, tmp_path: Path) -> None:
    from fastapi.testclient import TestClient  # noqa: PLC0415

    from homelab_atlas.web import auth, command, views  # noqa: PLC0415
    from homelab_atlas.web.app import WebConfig, create_app  # noqa: PLC0415
    from tests.web.test_v8 import PASSWORD, _login  # noqa: PLC0415

    with rt.sessions() as s:
        clusters = views.kubernetes_view(s)
        card = next(c for c in command.summary(s, views.machines(s), {}) if c["id"] == "k8s")
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    assert [c["name"] for c in clusters] == ["k3s"]  # node records are not clusters
    c = clusters[0]
    assert (c["running"], c["pods"], len(c["failing"]), len(c["nodes"])) == (10, 11, 1, 3)
    apps = next(ns for ns in c["namespaces"] if ns["name"] == "apps")
    whoami = next(w for w in apps["workloads"] if w["name"] == "whoami")
    assert len(whoami["pods"]) == 2
    assert (card["n"], card["total"]) == (10, 11) and "1 cluster(s)" in str(card["parts"])
    app = create_app(
        WebConfig(sessions=rt.sessions, annotations_dir=tmp_path, allowed_hosts=["testserver"])
    )
    with TestClient(app, base_url="https://testserver") as client:
        _login(client)
        html = client.get("/kubernetes").text
        assert "CrashLoopBackOff" in html and "k3s-cp1" in html and "80/tcp→31080" in html
        assert html.count("pods ready") == 1 and "ATLASFAKE" not in html


def test_generated_rbac_is_read_only_and_matches_the_allowlist() -> None:
    import yaml  # noqa: PLC0415

    from homelab_atlas.probe.render import render_k8s_rbac  # noqa: PLC0415

    docs = list(yaml.safe_load_all(render_k8s_rbac()))
    role = next(d for d in docs if d["kind"] == "ClusterRole")
    verbs = {v for r in role["rules"] for v in r["verbs"]}
    assert verbs == {"get", "list"}
    resources = {res for r in role["rules"] for res in r.get("resources", [])}
    assert resources == {
        "namespaces",
        "nodes",
        "pods",
        "services",
        "daemonsets",
        "deployments",
        "statefulsets",
    }
    assert not any(
        word in str(role) for word in ("secrets", "configmaps", "pods/log", "pods/exec", "*")
    )
    sa = next(d for d in docs if d["kind"] == "ServiceAccount")
    assert sa["automountServiceAccountToken"] is False
