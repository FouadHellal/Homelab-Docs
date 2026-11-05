"""Synthetic k3s cluster for the demo lab (ADR-048): Kubernetes API list answers.

State B: grafana crash-loops (CrashLoopBackOff, 12 restarts) and whoami moves to a new image.
Pod specs carry an env value with ATLASFAKE so tests can prove atlas never stores it.
"""

from typing import Any

NODES = [
    ("k3s-cp1", "10.0.20.71", ["control-plane", "master"]),
    ("k3s-w1", "10.0.20.72", []),
    ("k3s-w2", "10.0.20.73", []),
]


def _ok(body: Any) -> dict[str, Any]:
    return {"status": 200, "body": body}


def _list(kind: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return _ok({"kind": f"{kind}List", "apiVersion": "v1", "metadata": {"resourceVersion": "4242"},
                "items": items})  # fmt: skip


def _meta(ns: str | None, name: str, **extra: Any) -> dict[str, Any]:
    m: dict[str, Any] = {"name": name, "uid": f"uid-{name}", "creationTimestamp": "2026-10-01T10:00:00Z", **extra}
    if ns:
        m["namespace"] = ns
    return m


def render(state: str) -> dict[str, Any]:
    whoami = "traefik/whoami:v1.11" if state == "B" else "traefik/whoami:v1.10"
    workloads = [
        # (kind, ns, name, image, replicas, node list)
        ("Deployment", "kube-system", "coredns", "rancher/mirrored-coredns-coredns:1.12.1", 1, ["k3s-cp1"]),
        ("Deployment", "kube-system", "traefik", "rancher/mirrored-library-traefik:3.3.6", 1, ["k3s-cp1"]),
        ("Deployment", "kube-system", "metrics-server", "rancher/mirrored-metrics-server:v0.8.0", 1, ["k3s-w1"]),
        ("Deployment", "apps", "whoami", whoami, 2, ["k3s-w1", "k3s-w2"]),
        ("Deployment", "apps", "vaultwarden", "vaultwarden/server:1.34.1", 1, ["k3s-w2"]),
        ("Deployment", "monitoring", "grafana", "grafana/grafana:12.1.0", 1, ["k3s-w1"]),
        ("StatefulSet", "apps", "postgres", "postgres:17.5", 1, ["k3s-w2"]),
        ("DaemonSet", "kube-system", "svclb-traefik", "rancher/klipper-lb:v0.4.13", 3, [n for n, _, _ in NODES]),
    ]  # fmt: skip
    rec: dict[str, Any] = {}
    rec["/version"] = _ok({"major": "1", "minor": "33", "gitVersion": "v1.33.4+k3s1", "platform": "linux/amd64"})
    rec["/api/v1/nodes?limit=2000"] = _list("Node", [
        {"metadata": _meta(None, n, labels={"kubernetes.io/hostname": n,
                                            **{f"node-role.kubernetes.io/{r}": "true" for r in roles}}),
         "spec": {"podCIDR": "10.42.0.0/24"},
         "status": {"conditions": [
             {"type": "MemoryPressure", "status": "False"}, {"type": "DiskPressure", "status": "False"},
             {"type": "PIDPressure", "status": "False"}, {"type": "Ready", "status": "True"}],
             "addresses": [{"type": "InternalIP", "address": ip}, {"type": "Hostname", "address": n}],
             "capacity": {"cpu": "4", "memory": "8048140Ki", "pods": "110"},
             "nodeInfo": {"kubeletVersion": "v1.33.4+k3s1", "osImage": "Debian GNU/Linux 12 (bookworm)",
                          "kernelVersion": "6.1.0-37-amd64", "containerRuntimeVersion": "containerd://2.0.5-k3s2",
                          "architecture": "amd64"}}}
        for n, ip, roles in NODES])  # fmt: skip
    rec["/api/v1/namespaces?limit=2000"] = _list("Namespace", [
        {"metadata": _meta(None, ns), "status": {"phase": "Active"}}
        for ns in ("default", "kube-system", "kube-public", "apps", "monitoring")])  # fmt: skip
    deps, dss, sts, pods = [], [], [], []
    for kind, ns, name, image, replicas, nodes in workloads:
        broken = state == "B" and name == "grafana"
        spec = {"replicas": replicas, "template": {"spec": {"containers": [
            {"name": name, "image": image, "env": [{"name": "DB_PASSWORD", "value": "kube-env-ATLASFAKE"}]}]}}}
        if kind == "Deployment":
            deps.append({"metadata": _meta(ns, name), "spec": spec,
                         "status": {"replicas": replicas, "readyReplicas": 0 if broken else replicas}})
        elif kind == "StatefulSet":
            sts.append({"metadata": _meta(ns, name), "spec": spec, "status": {"readyReplicas": replicas}})
        else:
            dss.append({"metadata": _meta(ns, name), "spec": spec,
                        "status": {"desiredNumberScheduled": replicas, "numberReady": replicas}})
        owner_kind = {"Deployment": "ReplicaSet", "StatefulSet": "StatefulSet", "DaemonSet": "DaemonSet"}[kind]
        owner_name = f"{name}-7d9c5b{len(name)}f" if kind == "Deployment" else name
        for i in range(replicas):
            node = nodes[i % len(nodes)]
            cs: dict[str, Any] = {"name": name, "image": image, "ready": not broken,
                                  "restartCount": 12 if broken else 0, "state": {"running": {}}}
            if broken:
                cs["state"] = {"waiting": {"reason": "CrashLoopBackOff", "message": "back-off 5m0s"}}
                cs["lastState"] = {"terminated": {"reason": "Error", "exitCode": 1}}
            pods.append({
                "metadata": _meta(ns, f"{owner_name}-{'abcde'[i]}x{i}",
                                  ownerReferences=[{"kind": owner_kind, "name": owner_name, "controller": True}]),
                "spec": {"nodeName": node, "containers": spec["template"]["spec"]["containers"]},
                "status": {"phase": "Running", "podIP": f"10.42.{i}.{10 + len(name)}",
                           "startTime": "2026-11-01T08:00:00Z", "qosClass": "BestEffort",
                           "conditions": [{"type": "Ready", "status": "False" if broken else "True"}],
                           "containerStatuses": [cs]}})
    rec["/apis/apps/v1/deployments?limit=2000"] = _list("Deployment", deps)
    rec["/apis/apps/v1/daemonsets?limit=2000"] = _list("DaemonSet", dss)
    rec["/apis/apps/v1/statefulsets?limit=2000"] = _list("StatefulSet", sts)
    rec["/api/v1/pods?limit=2000"] = _list("Pod", pods)
    rec["/api/v1/services?limit=2000"] = _list("Service", [
        {"metadata": _meta("kube-system", "traefik"),
         "spec": {"type": "LoadBalancer", "clusterIP": "10.43.20.10",
                  "ports": [{"port": 80, "protocol": "TCP", "nodePort": 31080},
                            {"port": 443, "protocol": "TCP", "nodePort": 31443}]},
         "status": {"loadBalancer": {"ingress": [{"ip": "10.0.20.71"}]}}},
        {"metadata": _meta("apps", "whoami"),
         "spec": {"type": "ClusterIP", "clusterIP": "10.43.30.5", "ports": [{"port": 80, "protocol": "TCP"}]}},
    ])  # fmt: skip
    return rec
