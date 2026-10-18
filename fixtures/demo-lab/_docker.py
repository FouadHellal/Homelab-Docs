"""Docker part of the synthetic demo lab: what the probe's `docker` section would print.

Records mirror the probe's inspect templates exactly (env NAMES only, sentinel-terminated
lists/maps). Fake secrets in labels/cmd/healthchecks carry ATLASFAKE.
"""

import copy
import hashlib
import json
from typing import Any


def h64(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def ctr(
    host: str,
    name: str,
    image: str,
    *,
    project: str | None = None,
    service: str | None = None,
    env: tuple[str, ...] = (),
    ports: dict[str, list[tuple[str, str]] | None] | None = None,
    status: str = "running",
    health: str | None = None,
    restarts: int = 0,
    labels: dict[str, str] | None = None,
    cmd: list[str] | None = None,
    healthcheck: list[str] | None = None,
    mounts: list[dict[str, Any]] | None = None,
    networks: tuple[str, ...] = ("bridge",),
    privileged: bool = False,
    image_tag: str = "1",
) -> dict[str, Any]:
    lab = dict(labels or {})
    if project:
        lab |= {
            "com.docker.compose.project": project,
            "com.docker.compose.service": service or name,
            "com.docker.compose.container-number": "1",
            "com.docker.compose.project.config_files": f"/srv/{project}/compose.yaml",
            "com.docker.compose.config-hash": h64(f"{project}{service}cfg"),
        }
    return {
        "id": h64(f"{host}/{name}/id"),
        "name": f"/{name}",
        "image": image,
        "image_id": "sha256:" + h64(f"{image}@{image_tag}"),
        "status": status,
        "exit_code": 0 if status == "running" else 137,
        "started_at": "2026-10-10T08:00:00.000000000Z",
        "health": health,
        "restart_count": restarts,
        "restart_policy": "unless-stopped",
        "labels": lab,
        "env_names": [*env, "PATH", None],
        "cmd": cmd,
        "entrypoint": None,
        "healthcheck": healthcheck,
        "user": "",
        "privileged": privileged,
        "network_mode": networks[0],
        "cap_add": None,
        "readonly_rootfs": False,
        "ports": {k: ([{"HostIp": hip, "HostPort": hp} for hip, hp in v] if v else None)
                  for k, v in (ports or {}).items()},
        "networks": {**{n: {"ip": f"172.18.0.{(int(h64(name + n)[:2], 16) % 200) + 2}",
                            "ip6": "", "mac": "02:42:ac:12:00:02"} for n in networks}, "_": None},
        "mounts": [*(mounts or []), None],
    }  # fmt: skip


def vol(name: str) -> dict[str, Any]:
    return {"Driver": "local", "Labels": "", "Mountpoint": f"/var/lib/docker/volumes/{name}/_data",
            "Name": name, "Scope": "local"}  # fmt: skip


def net(name: str, subnet: str, driver: str = "bridge") -> dict[str, Any]:
    return {"id": h64(f"net/{name}"), "name": name, "driver": driver, "scope": "local",
            "internal": False, "ipv6": False,
            "subnets": [{"subnet": subnet, "gateway": subnet.rsplit(".", 2)[0] + ".0.1"}, None]}  # fmt: skip


SOCK = {"type": "bind", "source": "/var/run/docker.sock", "destination": "/var/run/docker.sock",
        "name": "", "rw": False}  # fmt: skip


def docker01() -> dict[str, Any]:
    h = "docker01"
    return {
        "engine": "27.3.1 1.47",
        "containers": [
            ctr(h, "immich_server", "ghcr.io/immich-app/immich-server:release", project="immich",
                service="immich-server", env=("DB_HOSTNAME", "DB_PASSWORD", "REDIS_HOSTNAME", "TZ"),
                ports={"2283/tcp": [("0.0.0.0", "2283")]}, health="healthy",
                networks=("immich_default",),
                mounts=[{"type": "bind", "source": "/srv/photos", "destination": "/usr/src/app/upload",
                         "name": "", "rw": True}]),
            ctr(h, "immich_machine_learning", "ghcr.io/immich-app/immich-machine-learning:release",
                project="immich", service="immich-machine-learning", networks=("immich_default",),
                mounts=[{"type": "volume", "source": "/var/lib/docker/volumes/immich_model-cache/_data",
                         "destination": "/cache", "name": "immich_model-cache", "rw": True}]),
            ctr(h, "immich_redis", "docker.io/valkey/valkey:8-bookworm", project="immich",
                service="redis", networks=("immich_default",), health="healthy",
                healthcheck=["CMD-SHELL", "redis-cli -a rd-ATLASFAKE-pw ping || exit 1"]),
            ctr(h, "immich_postgres", "ghcr.io/immich-app/postgres:14-vectorchord0.4.3",
                project="immich", service="database",
                env=("POSTGRES_PASSWORD", "POSTGRES_USER", "POSTGRES_DB"), networks=("immich_default",),
                mounts=[{"type": "bind", "source": "/srv/immich/pg", "destination": "/var/lib/postgresql/data",
                         "name": "", "rw": True}]),
            ctr(h, "traefik", "traefik:v3.2", project="edge", service="traefik",
                ports={"80/tcp": [("0.0.0.0", "80")], "443/tcp": [("0.0.0.0", "443"), ("::", "443")]},
                env=("CF_DNS_API_TOKEN",), mounts=[SOCK], networks=("edge",),
                labels={"traefik.http.middlewares.auth.basicauth.users":
                        "admin:$apr1$ATLASFAK$abcdefghijklmnopqrstuv"},
                cmd=["--api.dashboard=true", "--providers.docker=true",
                     "--certificatesresolvers.le.acme.email=ops@lab.example"]),
            ctr(h, "watchtower", "containrrr/watchtower:1.7.1",
                env=("WATCHTOWER_NOTIFICATION_URL", "WATCHTOWER_HTTP_API_TOKEN"), mounts=[SOCK],
                cmd=["--http-api-token", "wt-ATLASFAKE-0001", "--schedule", "0 0 4 * * *"]),
            ctr(h, "portainer_agent", "portainer/agent:2.21.4", mounts=[SOCK], privileged=True,
                ports={"9001/tcp": [("10.0.20.11", "9001")]}),
        ],
        "images": [],
        "networks": [net("bridge", "172.17.0.0/16"), net("immich_default", "172.18.0.0/16"),
                     net("edge", "172.19.0.0/16"), net("host", "", "host")],
        "volumes": [vol("immich_model-cache")],
        "compose": [{"Name": "edge", "Status": "running(1)", "ConfigFiles": "/srv/edge/compose.yaml"},
                    {"Name": "immich", "Status": "running(4)", "ConfigFiles": "/srv/immich/compose.yaml"}],
    }  # fmt: skip


def docker02() -> dict[str, Any]:
    h = "docker02"
    return {
        "engine": "27.3.1 1.47",
        "containers": [
            ctr(h, "homepage", "ghcr.io/gethomepage/homepage:v0.9.13", project="apps", service="homepage",
                env=("HOMEPAGE_ALLOWED_HOSTS", "PUID", "PGID"), ports={"3000/tcp": [("0.0.0.0", "3000")]}),
            ctr(h, "uptime-kuma", "louislam/uptime-kuma:1.23.15", project="apps", service="uptime-kuma",
                ports={"3001/tcp": [("0.0.0.0", "3001")]}, health="healthy"),
            ctr(h, "paperless-webserver", "ghcr.io/paperless-ngx/paperless-ngx:2.13", project="paperless",
                service="webserver", env=("PAPERLESS_SECRET_KEY", "PAPERLESS_DBPASS", "PAPERLESS_URL"),
                ports={"8000/tcp": [("0.0.0.0", "8000")]}, health="healthy",
                healthcheck=["CMD", "curl", "-fs", "-H", "Authorization: Bearer pl-ATLASFAKE-0123456789",
                             "http://localhost:8000"]),
            ctr(h, "paperless-broker", "docker.io/library/redis:7", project="paperless", service="broker"),
            ctr(h, "adhoc-test", "alpine:3.20", status="exited", cmd=["sleep", "3600"]),
        ],
        "images": [],
        "networks": [net("bridge", "172.17.0.0/16"), net("apps_default", "172.20.0.0/16")],
        "volumes": [vol("paperless_data"), vol("uptime-kuma")],
        "compose": [{"Name": "apps", "Status": "running(2)", "ConfigFiles": "/srv/apps/compose.yaml"},
                    {"Name": "paperless", "Status": "running(2)",
                     "ConfigFiles": "/srv/paperless/compose.yaml"}],
    }  # fmt: skip


def media01() -> dict[str, Any]:
    h = "media01"
    return {
        "engine": "26.1.5 1.45",
        "containers": [
            ctr(h, "jellyfin", "jellyfin/jellyfin:10.10.3", project="media", service="jellyfin",
                ports={"8096/tcp": [("0.0.0.0", "8096")]}, health="healthy",
                mounts=[{"type": "bind", "source": "/mnt/media", "destination": "/media", "name": "",
                         "rw": False}]),
        ],
        "images": [],
        "networks": [net("bridge", "172.17.0.0/16")],
        "volumes": [],
        "compose": [{"Name": "media", "Status": "running(1)", "ConfigFiles": "/srv/media/compose.yaml"}],
    }  # fmt: skip


def finish(d: dict[str, Any]) -> dict[str, Any]:
    """Derive the image list from the containers, like `docker image ls` would."""
    seen: dict[str, dict[str, Any]] = {}
    for c in d["containers"]:
        img = c["image"] if ":" in c["image"].rsplit("/", 1)[-1] else c["image"] + ":latest"
        seen.setdefault(c["image_id"], {"id": c["image_id"], "tags": [img],
                                         "digests": [img.split(":")[0] + "@sha256:" + h64(c["image_id"])],
                                         "created": "2026-10-01T00:00:00Z", "size": 123456789,
                                         "arch": "amd64"})  # fmt: skip
    d["images"] = list(seen.values())
    return d


def state_a() -> dict[str, dict[str, Any]]:
    return {"docker01": finish(docker01()), "docker02": finish(docker02()), "media01": finish(media01())}


def state_b(a: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    b = copy.deepcopy(a)
    for host in b.values():  # volatile churn: container IPs and start times
        for c in host["containers"]:
            c["started_at"] = "2026-10-17T03:00:00.000000000Z"
            for v in c["networks"].values():
                if v:
                    v["ip"] = v["ip"].rsplit(".", 1)[0] + ".250"
            c["id"] = h64(c["id"])  # recreated containers get new ids
    d1 = {c["name"]: c for c in b["docker01"]["containers"]}
    d1["/immich_server"]["image_id"] = "sha256:" + h64("ghcr.io/immich-app/immich-server:release@2")
    d1["/immich_redis"]["restart_count"] = 2
    d1["/traefik"]["ports"]["8443/tcp"] = [{"HostIp": "0.0.0.0", "HostPort": "8443"}]
    b["docker01"]["containers"] = [c for c in b["docker01"]["containers"] if c["name"] != "/watchtower"]
    b["docker01"]["containers"].append(
        ctr("docker01", "vaultwarden", "vaultwarden/server:1.32.5", project="vault", service="vaultwarden",
            env=("ADMIN_TOKEN", "DOMAIN", "SIGNUPS_ALLOWED"), ports={"80/tcp": [("127.0.0.1", "8081")]},
            health="healthy"))  # fmt: skip
    b["docker01"]["containers"].append(
        ctr("docker01", "dozzle", "amir20/dozzle:v8.7", mounts=[SOCK], ports={"8080/tcp": [("0.0.0.0", "8888")]}))
    b["docker01"]["compose"].append({"Name": "vault", "Status": "running(1)",
                                     "ConfigFiles": "/srv/vault/compose.yaml"})  # fmt: skip
    d2 = {c["name"]: c for c in b["docker02"]["containers"]}
    d2["/paperless-webserver"]["status"] = "exited"
    d2["/uptime-kuma"]["health"] = "unhealthy"
    d2["/homepage"]["env_names"].insert(0, "HOMEPAGE_VAR_GRAFANA_TOKEN")
    for host in ("docker01", "docker02"):
        finish(b[host])
    return b


def render(host: str, d: dict[str, Any], frame: Any) -> bytes:
    return frame(host, "docker", [
        ("engine", d["engine"], 0),
        ("containers", "\n".join(json.dumps(c, separators=(",", ":")) for c in d["containers"]), 0),
        ("images", "\n".join(json.dumps(i, separators=(",", ":")) for i in d["images"]), 0),
        ("networks", "\n".join(json.dumps(n, separators=(",", ":")) for n in d["networks"]), 0),
        ("volumes", "\n".join(json.dumps(v, separators=(",", ":")) for v in d["volumes"]), 0),
        ("compose", json.dumps(d["compose"]), 0),
    ])  # fmt: skip
