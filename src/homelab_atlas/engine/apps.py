"""Recognise the applications a machine runs (ADR-029).

Evidence, from data atlas already collects: running systemd services, processes, Docker
containers (image names) and listening ports. Each catalog entry lists matchers; an app is
reported once per machine with every piece of evidence that matched. Computed on read, never
stored, so improving the catalog improves old scans too.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Final


@dataclass(frozen=True, slots=True)
class App:
    name: str
    category: str
    units: tuple[str, ...] = ()  # systemd unit name prefixes (without .service)
    procs: tuple[str, ...] = ()  # process names (exact, case-insensitive)
    images: tuple[str, ...] = ()  # substrings of container image names
    ports: tuple[int, ...] = ()  # well-known listening ports (weak evidence: needs a 2nd hint)
    web: int | None = None  # port of its web UI, for an "open" link


CATALOG: Final[tuple[App, ...]] = (
    # DNS / network
    App("Pi-hole", "dns", ("pihole-ftl",), ("pihole-ftl",), ("pihole/pihole",), (53, 4711), 80),
    App(
        "AdGuard Home",
        "dns",
        ("adguardhome",),
        ("adguardhome",),
        ("adguard/adguardhome",),
        (3000,),
        3000,
    ),
    App("Unbound", "dns", ("unbound",), ("unbound",), ("unbound",), (5335,)),
    App("Bind9", "dns", ("named", "bind9"), ("named",), ("bind9",)),
    App("dnsmasq", "dns", ("dnsmasq",), ("dnsmasq",)),
    App("Tailscale", "vpn", ("tailscaled",), ("tailscaled",), ("tailscale/tailscale",), (41641,)),
    App("WireGuard", "vpn", ("wg-quick",), (), ("wireguard", "wg-easy"), (51820,)),
    App("OpenVPN", "vpn", ("openvpn",), ("openvpn",), ("openvpn",), (1194,)),
    App(
        "RustDesk",
        "remote",
        ("rustdesk-hbbs", "rustdesk-hbbr", "hbbs", "hbbr"),
        ("hbbs", "hbbr"),
        ("rustdesk",),
        (21115, 21116, 21117),
    ),
    App("Traefik", "proxy", ("traefik",), ("traefik",), ("traefik",), (), 8080),
    App("Caddy", "proxy", ("caddy",), ("caddy",), ("caddy",)),
    App("Nginx", "web", ("nginx",), ("nginx",), ("nginx",)),
    App("Nginx Proxy Manager", "proxy", (), (), ("jc21/nginx-proxy-manager",), (81,), 81),
    App("Apache", "web", ("apache2", "httpd"), ("apache2", "httpd"), ("httpd",)),
    App("lighttpd", "web", ("lighttpd",), ("lighttpd",)),
    # Virtualisation / containers
    App(
        "Proxmox VE",
        "hypervisor",
        ("pveproxy", "pvedaemon", "pve-cluster"),
        ("pveproxy",),
        (),
        (8006,),
        8006,
    ),
    App(
        "Proxmox Backup Server",
        "backup",
        ("proxmox-backup",),
        ("proxmox-backup-proxy",),
        (),
        (8007,),
        8007,
    ),
    App("Docker", "containers", ("docker",), ("dockerd",)),
    App("Portainer", "containers", (), (), ("portainer/portainer",), (9443, 9000), 9443),
    App("Kubernetes (k3s)", "containers", ("k3s",), ("k3s",)),
    # Home / media
    App(
        "Home Assistant",
        "home",
        ("home-assistant",),
        ("hass",),
        ("home-assistant", "homeassistant"),
        (8123,),
        8123,
    ),
    App("Jellyfin", "media", ("jellyfin",), ("jellyfin",), ("jellyfin",), (8096,), 8096),
    App(
        "Plex",
        "media",
        ("plexmediaserver",),
        ("plex media serv",),
        ("plexinc/pms", "plex"),
        (32400,),
        32400,
    ),
    App("Emby", "media", ("emby-server",), (), ("emby",), (8096,)),
    App("Sonarr", "media", ("sonarr",), (), ("sonarr",), (8989,), 8989),
    App("Radarr", "media", ("radarr",), (), ("radarr",), (7878,), 7878),
    App("Prowlarr", "media", ("prowlarr",), (), ("prowlarr",), (9696,), 9696),
    App("qBittorrent", "media", ("qbittorrent",), ("qbittorrent-nox",), ("qbittorrent",), (8080,)),
    App("Immich", "media", (), (), ("immich",), (2283,), 2283),
    App("Nextcloud", "files", (), (), ("nextcloud",)),
    App("Samba", "files", ("smbd", "smb"), ("smbd",), ("samba",), (445,)),
    App("NFS server", "files", ("nfs-server", "nfs-kernel-server"), ("nfsd",), (), (2049,)),
    App("Syncthing", "files", ("syncthing",), ("syncthing",), ("syncthing",), (8384,), 8384),
    App("MinIO", "files", ("minio",), ("minio",), ("minio/minio",), (9000, 9001), 9001),
    # Automation / dev
    App("n8n", "automation", ("n8n",), (), ("n8nio/n8n", "n8n"), (5678,), 5678),
    App("Node-RED", "automation", ("nodered",), (), ("nodered/node-red",), (1880,), 1880),
    App(
        "Mosquitto (MQTT)",
        "automation",
        ("mosquitto",),
        ("mosquitto",),
        ("eclipse-mosquitto",),
        (1883,),
    ),
    App("Zigbee2MQTT", "automation", ("zigbee2mqtt",), (), ("zigbee2mqtt",), (8080,)),
    App("Gitea", "dev", ("gitea",), ("gitea",), ("gitea/gitea",), (3000,), 3000),
    App("GitLab", "dev", ("gitlab-runsvdir",), (), ("gitlab/gitlab",)),
    App("Jenkins", "dev", ("jenkins",), (), ("jenkins/jenkins",), (8080,), 8080),
    App("Vaultwarden", "security", (), (), ("vaultwarden/server",), ()),
    App("Authentik", "security", (), (), ("goauthentik",), (9000, 9443)),
    # Monitoring / inventory
    App(
        "NetBox", "inventory", ("netbox",), (), ("netboxcommunity/netbox", "netbox"), (8080,), 8080
    ),
    App(
        "Zabbix server",
        "monitoring",
        ("zabbix-server",),
        ("zabbix_server",),
        ("zabbix/zabbix-server",),
        (10051,),
    ),
    App(
        "Zabbix agent",
        "monitoring",
        ("zabbix-agent",),
        ("zabbix_agentd", "zabbix_agent2"),
        (),
        (10050,),
    ),
    App("Zabbix web", "monitoring", (), (), ("zabbix/zabbix-web",), (), 80),
    App(
        "Grafana",
        "monitoring",
        ("grafana-server", "grafana"),
        ("grafana",),
        ("grafana/grafana",),
        (3000,),
        3000,
    ),
    App(
        "Prometheus",
        "monitoring",
        ("prometheus",),
        ("prometheus",),
        ("prom/prometheus",),
        (9090,),
        9090,
    ),
    App(
        "Node exporter",
        "monitoring",
        ("prometheus-node-exporter", "node_exporter"),
        ("node_exporter",),
        ("prom/node-exporter",),
        (9100,),
    ),
    App("Uptime Kuma", "monitoring", (), (), ("louislam/uptime-kuma",), (3001,), 3001),
    App("Netdata", "monitoring", ("netdata",), ("netdata",), ("netdata/netdata",), (19999,), 19999),
    App("Loki", "monitoring", ("loki",), ("loki",), ("grafana/loki",), (3100,)),
    App("InfluxDB", "monitoring", ("influxdb",), ("influxd",), ("influxdb",), (8086,), 8086),
    # Databases
    App("PostgreSQL", "database", ("postgresql",), ("postgres",), ("postgres",), (5432,)),
    App(
        "MariaDB / MySQL",
        "database",
        ("mariadb", "mysql"),
        ("mariadbd", "mysqld"),
        ("mariadb", "mysql"),
        (3306,),
    ),
    App(
        "Redis",
        "database",
        ("redis-server", "redis"),
        ("redis-server",),
        ("redis", "valkey"),
        (6379,),
    ),
    App("MongoDB", "database", ("mongod",), ("mongod",), ("mongo",), (27017,)),
    # System
    App("OpenSSH", "system", ("ssh", "sshd"), ("sshd",), (), (22,)),
    App("Cockpit", "system", ("cockpit",), (), (), (9090,), 9090),
    App("Webmin", "system", ("webmin",), ("miniserv.pl",), (), (10000,), 10000),
    App("Fail2ban", "security", ("fail2ban",), ("fail2ban-server",)),
    App("CrowdSec", "security", ("crowdsec",), ("crowdsec",), ("crowdsecurity/crowdsec",)),
    App("Chrony / NTP", "system", ("chrony", "ntp", "ntpsec"), ("chronyd", "ntpd")),
    App("CUPS (printing)", "system", ("cups",), ("cupsd",), (), (631,)),
    App("Postfix", "mail", ("postfix",), ("master",), (), (25,)),
)

CATEGORY_LABELS: Final = {
    "dns": "DNS",
    "vpn": "VPN",
    "remote": "Remote access",
    "proxy": "Reverse proxy",
    "web": "Web server",
    "hypervisor": "Hypervisor",
    "backup": "Backup",
    "containers": "Containers",
    "home": "Home automation",
    "media": "Media",
    "files": "Files & storage",
    "automation": "Automation",
    "dev": "Dev tools",
    "security": "Security",
    "inventory": "Inventory",
    "monitoring": "Monitoring",
    "database": "Database",
    "system": "System",
    "mail": "Mail",
}


@dataclass(slots=True)
class Found:
    app: App
    evidence: list[str] = field(default_factory=list)
    ports: set[int] = field(default_factory=set)
    containers: list[str] = field(default_factory=list)
    web_port: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.app.name,
            "category": self.app.category,
            "category_label": CATEGORY_LABELS.get(self.app.category, self.app.category),
            "evidence": self.evidence[:6],
            "ports": sorted(self.ports),
            "containers": self.containers,
            "web_port": self.web_port,
        }


def _unit_base(unit: str) -> str:
    return re.sub(r"(@.*)?\.service$", "", unit.lower())


def detect(
    services: Iterable[dict[str, Any]] = (),
    processes: Iterable[dict[str, Any]] = (),
    containers: Iterable[dict[str, Any]] = (),
    ports: Iterable[dict[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Apps on one machine, from facet dicts (services, processes, docker containers, sockets)."""
    running_units = {
        _unit_base(str(s.get("unit") or "")) for s in services if s.get("active") == "active"
    }
    procs = {str(p.get("comm") or "").lower() for p in processes}
    listening: dict[int, str] = {}
    for p in ports:
        if isinstance(p.get("port"), int):
            listening.setdefault(p["port"], str(p.get("process") or ""))
    found: dict[str, Found] = {}
    for app in CATALOG:
        f = Found(app)
        for u in app.units:
            if any(r == u or r.startswith(u + "-") or r.startswith(u + "@") for r in running_units):
                f.evidence.append(f"service {u}")
                break
        for pn in app.procs:
            if pn.lower() in procs:
                f.evidence.append(f"process {pn}")
                break
        for c in containers:
            image = str(c.get("image") or "").lower()
            if any(i in image for i in app.images):
                f.evidence.append(f"container {c.get('name') or image}")
                f.containers.append(str(c.get("name") or image))
        f.ports = {p for p in app.ports if p in listening}
        # Offer the web UI when its port listens, or when we have no socket list at all.
        if app.web is not None and (not listening or app.web in listening):
            f.web_port = app.web
        strong = bool(f.evidence)
        if strong:
            if f.ports:
                f.evidence.append("port " + ", ".join(str(p) for p in sorted(f.ports)))
            found[app.name] = f
    # Docker is implied by containers; don't list it twice when it's obvious.
    return sorted(
        (f.as_dict() for f in found.values()),
        key=lambda a: (a["category"] == "system", a["name"].lower()),
    )
