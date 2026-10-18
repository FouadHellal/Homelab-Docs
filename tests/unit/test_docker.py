import json

from hypothesis import given, settings
from hypothesis import strategies as st

from homelab_atlas.collectors.docker.events import docker_events
from homelab_atlas.collectors.docker.parse import container_key, parse_docker
from homelab_atlas.collectors.linux_ssh.frame import Frame, Part
from homelab_atlas.engine.diff import diff
from homelab_atlas.models.base import canonical
from homelab_atlas.models.docker import DockerHostFacts
from homelab_atlas.security.allowlist import ProbeSection

CTR = {
    "id": "a" * 64,
    "name": "/immich_server",
    "image": "ghcr.io/immich-app/immich-server:release",
    "image_id": "sha256:" + "1" * 64,
    "status": "running",
    "exit_code": 0,
    "health": "healthy",
    "restart_count": 0,
    "restart_policy": "unless-stopped",
    "labels": {
        "com.docker.compose.project": "immich",
        "com.docker.compose.service": "server",
        "com.docker.compose.container-number": "1",
    },
    "env_names": ["DB_PASSWORD", "TZ", None],
    "cmd": None,
    "ports": {
        "2283/tcp": [{"HostIp": "0.0.0.0", "HostPort": "2283"}],
        "3000/tcp": None,
        "443/tcp": [{"HostIp": "::", "HostPort": "443"}],
    },
    "networks": {
        "immich_default": {"ip": "172.18.0.4", "ip6": "", "mac": "02:42:ac:12:00:04"},
        "_": None,
    },
    "mounts": [
        {
            "type": "bind",
            "source": "/var/run/docker.sock",
            "destination": "/var/run/docker.sock",
            "name": "",
            "rw": False,
        },
        None,
    ],
    "privileged": False,
}


def frame(**parts: str | tuple[str, int]) -> Frame:
    f = Frame(section=ProbeSection.DOCKER, complete=True)
    for name, v in parts.items():
        content, rc = v if isinstance(v, tuple) else (v, 0)
        f.parts[name] = Part(name, content, rc)
    return f


def facts(**ctr: object) -> DockerHostFacts:
    parsed = parse_docker(
        frame(
            engine="27.3.1 1.47",
            containers=json.dumps({**CTR, **ctr}),
            images="",
            networks="",
            volumes="",
            compose="[]",
        )
    )
    return DockerHostFacts.model_validate(parsed.values)


def test_container_parse() -> None:
    (c,) = facts().containers
    assert c.key == "immich/server/1"
    assert c.env_names == ["DB_PASSWORD", "TZ"]
    assert c.docker_socket is True
    assert {(p.host_ip, p.host_port, p.container_port) for p in c.ports} == {
        ("0.0.0.0", 2283, 2283),
        ("::", 443, 443),
    }
    assert [n.network for n in c.networks] == ["immich_default"]


def test_container_key_without_compose() -> None:
    assert container_key({}, "watchtower") == "name/watchtower"
    assert container_key({"com.docker.compose.project": "p", "com.docker.compose.service": "s",
                          "com.docker.compose.container-number": "x"}, "n") == "p/s/1"  # fmt: skip


def test_docker_not_installed() -> None:
    out = parse_docker(frame(engine=("", 127)))
    assert out.errors == ["engine: docker not installed"]
    assert "containers" not in out.values


def test_volatile_ids_and_ips_ignored() -> None:
    a = canonical(facts())
    b = canonical(
        facts(
            id="b" * 64,
            started_at="later",
            networks={"immich_default": {"ip": "172.18.0.99", "ip6": "", "mac": None}, "_": None},
        )
    )
    assert a == b


def test_events() -> None:
    a = canonical(facts())
    b = canonical(
        facts(
            image_id="sha256:" + "2" * 64,
            status="exited",
            health="unhealthy",
            restart_count=3,
            env_names=["DB_PASSWORD", "NEW_TOKEN", None],
            privileged=True,
        )
    )
    got = {(e.type, e.severity) for e in docker_events("host:x", "docker01", diff(a, b))}
    assert got == {
        ("image.updated", "notice"),
        ("container.stopped", "warning"),
        ("container.unhealthy", "warning"),
        ("container.restarted", "notice"),
        ("container.env_changed", "notice"),
        ("container.risky", "warning"),
    }


@settings(max_examples=150, deadline=None)
@given(st.text(max_size=300))
def test_parser_total(junk: str) -> None:
    parse_docker(
        frame(engine="1 1", containers=junk, images=junk, networks=junk, volumes=junk, compose=junk)
    )
