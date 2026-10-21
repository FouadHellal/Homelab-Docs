"""Recognise the applications a machine runs (ADR-029).

Evidence, from data atlas already collects: running systemd services, processes, Docker
containers (image names) and listening ports. Each catalog entry lists matchers; an app is
reported once per machine with every piece of evidence that matched. Computed on read, never
stored, so improving the catalog improves old scans too.

Owners extend the catalog from the UI ("name this port", ADR-034): rules are kept in
`custom-apps.yaml` in the data directory and merged in on read.
"""

import os
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import structlog
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

log = structlog.get_logger()


@dataclass(frozen=True, slots=True)
class App:
    name: str
    category: str
    units: tuple[str, ...] = ()  # systemd unit name prefixes (without .service)
    procs: tuple[str, ...] = ()  # process names (exact, case-insensitive)
    images: tuple[str, ...] = ()  # substrings of container image names
    ports: tuple[int, ...] = ()  # well-known listening ports (weak evidence: needs a 2nd hint)
    web: int | None = None  # port of its web UI, for an "open" link
    #: Owner rules only: a listening port alone is evidence (generic processes like python3).
    strong_ports: bool = False
    #: Owner rules only: limit the rule to these machines (lower-case names); empty = any.
    hosts: tuple[str, ...] = ()
    custom: bool = False


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
    "custom": "Your apps",
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
    host: str | None = None,
) -> list[dict[str, Any]]:
    """Apps on one machine, from facet dicts (services, processes, docker containers, sockets).
    `host` is the machine's name, for owner rules limited to some machines."""
    running_units = {
        _unit_base(str(s.get("unit") or "")) for s in services if s.get("active") == "active"
    }
    procs = {str(p.get("comm") or "").lower() for p in processes}
    listening: dict[int, str] = {}
    for p in ports:
        if isinstance(p.get("port"), int):
            listening.setdefault(p["port"], str(p.get("process") or ""))
    found: dict[str, Found] = {}
    here = (host or "").lower()
    for app in catalog():
        if app.hosts and here not in app.hosts:
            continue
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
        if app.strong_ports and f.ports and not f.evidence:
            f.evidence.append("port " + ", ".join(str(p) for p in sorted(f.ports)))
            found[app.name] = f
            continue
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


def app_for_unit(unit: str) -> App | None:
    """The catalog app a systemd unit belongs to (`pihole-FTL.service` -> Pi-hole), if any."""
    base = _unit_base(unit)
    for app in catalog():
        if any(base == u or base.startswith((u + "-", u + "@")) for u in app.units):
            return app
    return None


# ------------------------------------------------------------------ owner rules (ADR-034)

CUSTOM_FILE: Final = "custom-apps.yaml"
MAX_RULES: Final = 300
MATCHER_RE: Final = r"^[A-Za-z0-9._@/+:-]{1,96}$"


class CustomRule(BaseModel):
    """One owner-defined app. Strict: this file is data, edited from the UI."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64, pattern=r"^[^\x00-\x1f<>]{1,64}$")
    category: str = "custom"
    units: list[str] = Field(default_factory=list, max_length=8)
    procs: list[str] = Field(default_factory=list, max_length=8)
    images: list[str] = Field(default_factory=list, max_length=8)
    ports: list[int] = Field(default_factory=list, max_length=8)
    web: int | None = Field(default=None, ge=1, le=65535)
    strong_ports: bool = False
    hosts: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("category")
    @classmethod
    def _category(cls, v: str) -> str:
        if v not in CATEGORY_LABELS:
            raise ValueError("unknown category")
        return v

    @field_validator("units", "procs", "images", "hosts")
    @classmethod
    def _tokens(cls, v: list[str]) -> list[str]:
        out = []
        for raw in v:
            item = raw.strip().lower()
            if not re.fullmatch(MATCHER_RE, item):
                raise ValueError(f"not allowed: {item[:40]!r}")
            out.append(item)
        return out

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(not 1 <= p <= 65535 for p in v):
            raise ValueError("ports are 1-65535")
        return sorted(set(v))

    def as_app(self) -> App:
        return App(self.name, self.category, tuple(self.units), tuple(self.procs),
                   tuple(self.images), tuple(self.ports), self.web, self.strong_ports,
                   tuple(self.hosts), custom=True)  # fmt: skip


class _RuleStore:
    """Where owner rules live and their parsed form, re-read when the file changes."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.path: Path | None = None
        self.mtime = -1.0
        self.apps: tuple[App, ...] = ()


_store = _RuleStore()


def configure_custom(path: Path | None) -> None:
    """Where owner rules live (None: none). Called once by the web app."""
    with _store.lock:
        _store.path, _store.mtime, _store.apps = path, -1.0, ()


def load_rules(path: Path | None = None) -> list[CustomRule]:
    path = path or _store.path
    if path is None or not path.is_file():
        return []
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    items = raw.get("apps") if isinstance(raw, dict) else None
    rules = []
    for item in (items or [])[:MAX_RULES]:
        try:
            rules.append(CustomRule.model_validate(item))
        except ValidationError as exc:
            log.warning("custom_apps.invalid_rule", error=str(exc.errors()[0]["msg"])[:120])
    return rules


def custom_apps() -> tuple[App, ...]:
    """Owner rules as catalog entries, re-read when the file changes."""
    path = _store.path
    if path is None:
        return ()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return ()
    with _store.lock:
        if _store.mtime != mtime:
            try:
                parsed = tuple(r.as_app() for r in load_rules(path))
            except (OSError, yaml.YAMLError) as exc:
                log.warning("custom_apps.unreadable", error=type(exc).__name__)
                parsed = ()
            _store.mtime, _store.apps = mtime, parsed
        return _store.apps


def catalog() -> tuple[App, ...]:
    """Built-in apps plus the owner's rules. An owner rule with a built-in name wins."""
    mine = custom_apps()
    names = {a.name.lower() for a in mine}
    return tuple(a for a in CATALOG if a.name.lower() not in names) + mine


def save_rule(rule: CustomRule) -> None:
    """Add or replace (by name) one owner rule. Atomic write, 0600."""
    path = _store.path
    if path is None:
        raise RuntimeError("custom app rules are not enabled here")
    with _store.lock:
        rules = [r for r in load_rules(path) if r.name.lower() != rule.name.lower()]
        if len(rules) >= MAX_RULES:
            raise ValueError(f"at most {MAX_RULES} rules")
        rules.append(rule)
        _write(path, rules)


def delete_rule(name: str) -> bool:
    path = _store.path
    if path is None:
        return False
    with _store.lock:
        rules = load_rules(path)
        keep = [r for r in rules if r.name.lower() != name.lower()]
        if len(keep) == len(rules):
            return False
        _write(path, keep)
        return True


def _write(path: Path, rules: list[CustomRule]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "# atlas: your own app rules (edited from the Apps page). ADR-034.\n" + yaml.safe_dump(
        {"apps": [{"name": r.name, **r.model_dump(exclude_defaults=True)} for r in rules]},
        sort_keys=False, allow_unicode=True, width=100,
    )  # fmt: skip
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, body.encode())
    finally:
        os.close(fd)
    tmp.replace(path)
    _store.mtime = -1.0
