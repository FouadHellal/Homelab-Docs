"""Parse the probe `docker` section. Total: hostile or partial output never raises."""

import json
import re
from typing import Any, Final

from homelab_atlas.collectors.linux_ssh.frame import Frame
from homelab_atlas.collectors.linux_ssh.parse import MAX_ITEMS, Parsed, norm_ip, norm_mac
from homelab_atlas.models.docker import (
    ComposeProject,
    Container,
    ContainerMount,
    ContainerNetwork,
    DockerNetwork,
    Image,
    PublishedPort,
    Volume,
)

PORT_KEY_RE: Final = re.compile(r"(\d{1,5})/(tcp|udp|sctp)")
DOCKER_SOCKETS: Final = frozenset({"/var/run/docker.sock", "/run/docker.sock"})
COMPOSE_PROJECT = "com.docker.compose.project"
COMPOSE_SERVICE = "com.docker.compose.service"
COMPOSE_NUMBER = "com.docker.compose.container-number"


def _lines(frame: Frame, part: str, out: Parsed) -> list[dict[str, Any]]:
    text = frame.text(part)
    if text is None:
        rc = frame.parts[part].rc if part in frame.parts else None
        out.errors.append(f"{part}: {'docker not installed' if rc == 127 else 'missing or failed'}")
        return []
    items = []
    for raw in text.splitlines()[:MAX_ITEMS]:
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            out.errors.append(f"{part}: invalid JSON line")
            continue
        if isinstance(obj, dict):
            items.append(obj)
    return items


def _str(v: Any, limit: int = 512) -> str | None:
    return v[:limit] if isinstance(v, str) and v else None


def _strs(v: Any, limit: int = 64) -> list[str]:
    if not isinstance(v, list):
        return []
    return [x[:1024] for x in v[:limit] if isinstance(x, str)]


def _labels(v: Any) -> dict[str, str]:
    if not isinstance(v, dict):
        return {}
    return {str(k)[:256]: str(val)[:1024] for k, val in list(v.items())[:256] if val is not None}


def _ports(v: Any) -> list[PublishedPort]:
    ports: list[PublishedPort] = []
    if not isinstance(v, dict):
        return ports
    for key, bindings in v.items():
        m = PORT_KEY_RE.fullmatch(str(key))
        if m is None or not isinstance(bindings, list):
            continue  # exposed but not published -> null
        for b in bindings:
            if isinstance(b, dict) and str(b.get("HostPort", "")).isdigit():
                ports.append(
                    PublishedPort(
                        container_port=int(m.group(1)),
                        proto=m.group(2),
                        host_ip=norm_ip(str(b.get("HostIp") or "0.0.0.0")),  # noqa: S104
                        host_port=int(b["HostPort"]),
                    )
                )
    return ports


def container_key(labels: dict[str, str], name: str) -> str:
    project, service = labels.get(COMPOSE_PROJECT), labels.get(COMPOSE_SERVICE)
    if project and service:
        number = labels.get(COMPOSE_NUMBER, "1")
        return f"{project}/{service}/{number if number.isdigit() else '1'}"
    return f"name/{name}"


def _container(c: dict[str, Any]) -> Container | None:
    name = (_str(c.get("name"), 256) or "").lstrip("/")
    cid = _str(c.get("id"), 64)
    if not name or not cid:
        return None
    labels = _labels(c.get("labels"))
    mounts = [
        ContainerMount(
            destination=m["destination"][:512],
            type=_str(m.get("type"), 16) or "?",
            source=_str(m.get("source"), 512),
            name=_str(m.get("name"), 256),
            rw=bool(m.get("rw", True)),
        )
        for m in (c.get("mounts") or [])[:256]
        if isinstance(m, dict) and isinstance(m.get("destination"), str)
    ]
    raw_nets = c.get("networks")
    nets: dict[str, Any] = raw_nets if isinstance(raw_nets, dict) else {}
    networks = [
        ContainerNetwork(
            network=str(k)[:128],
            ip=_str(v.get("ip"), 64),
            ip6=_str(v.get("ip6"), 64),
            mac=norm_mac(v.get("mac")),
        )
        for k, v in list(nets.items())[:64]
        if k != "_" and isinstance(v, dict)
    ]
    return Container(
        key=container_key(labels, name),
        name=name,
        compose_project=labels.get(COMPOSE_PROJECT),
        compose_service=labels.get(COMPOSE_SERVICE),
        image=_str(c.get("image"), 256) or "?",
        image_id=_str(c.get("image_id"), 128) or "?",
        status=_str(c.get("status"), 16) or "?",
        health=_str(c.get("health"), 16),
        restart_count=c["restart_count"] if isinstance(c.get("restart_count"), int) else 0,
        restart_policy=_str(c.get("restart_policy"), 32),
        user=_str(c.get("user"), 64),
        privileged=c.get("privileged") is True,
        readonly_rootfs=c.get("readonly_rootfs") is True,
        network_mode=_str(c.get("network_mode"), 128),
        docker_socket=any(m.source in DOCKER_SOCKETS for m in mounts),
        cap_add=sorted(_strs(c.get("cap_add"))),
        env_names=sorted({n[:128] for n in c.get("env_names") or [] if isinstance(n, str)}),
        labels=labels,
        cmd=_strs(c.get("cmd")),
        entrypoint=_strs(c.get("entrypoint")),
        healthcheck=_strs(c.get("healthcheck")),
        ports=_ports(c.get("ports")),
        mounts=mounts,
        networks=networks,
        container_id=cid,
        started_at=_str(c.get("started_at"), 64),
        exit_code=c.get("exit_code") if isinstance(c.get("exit_code"), int) else None,
    )


def parse_docker(frame: Frame) -> Parsed:
    out = Parsed()
    engine = (frame.text("engine") or "").split()
    if not engine:
        rc = frame.parts["engine"].rc if "engine" in frame.parts else None
        out.errors.append("engine: docker not installed" if rc == 127 else "engine: unreadable")
        return out
    out.values["engine_version"] = engine[0][:32]
    out.values["api_version"] = engine[1][:16] if len(engine) > 1 else None

    containers: dict[str, Container] = {}
    for raw in _lines(frame, "containers", out):
        c = _container(raw)
        if c is not None and c.key not in containers:
            containers[c.key] = c
    out.values["containers"] = list(containers.values())

    out.values["images"] = [
        Image(
            id=i["id"][:80],
            tags=sorted(_strs(i.get("tags"))),
            digests=sorted(_strs(i.get("digests"))),
            created=_str(i.get("created"), 64),
            size_bytes=i.get("size") if isinstance(i.get("size"), int) else None,
            arch=_str(i.get("arch"), 16),
        )
        for i in _lines(frame, "images", out)
        if isinstance(i.get("id"), str)
    ]
    out.values["networks"] = [
        DockerNetwork(
            name=n["name"][:128],
            driver=_str(n.get("driver"), 32),
            scope=_str(n.get("scope"), 16),
            internal=n.get("internal") is True,
            ipv6=n.get("ipv6") is True,
            subnets=sorted(
                norm_ip(s["subnet"])
                for s in n.get("subnets") or []
                if isinstance(s, dict) and isinstance(s.get("subnet"), str)
            ),
            id=_str(n.get("id"), 64) or "",
        )
        for n in _lines(frame, "networks", out)
        if isinstance(n.get("name"), str)
    ]
    out.values["volumes"] = [
        Volume(
            name=v["Name"][:256],
            driver=_str(v.get("Driver"), 32),
            mountpoint=_str(v.get("Mountpoint"), 512),
        )
        for v in _lines(frame, "volumes", out)
        if isinstance(v.get("Name"), str)
    ]
    projects: list[ComposeProject] = []
    text = frame.text("compose")
    if text is not None:
        try:
            data = json.loads(text) if text.strip() else []
        except json.JSONDecodeError:
            data = []
            out.errors.append("compose: invalid JSON")
        for p in data if isinstance(data, list) else []:
            if isinstance(p, dict) and isinstance(p.get("Name"), str):
                files = str(p.get("ConfigFiles") or "")
                projects.append(
                    ComposeProject(
                        name=p["Name"][:128],
                        config_files=sorted(f[:512] for f in files.split(",") if f),
                        status=_str(p.get("Status"), 64),
                    )
                )
    out.values["compose_projects"] = projects
    return out
