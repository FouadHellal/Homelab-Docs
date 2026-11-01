"""What an app or service *is*: a short built-in reference shown on the app pages (ADR-038).

atlas never goes online to look things up (the server stays read-only and offline). The
reference ships with atlas; for anything it doesn't know, the page offers search links that
open in the owner's own browser, and shows the evidence atlas collected (unit description,
package version, ports, which machines).
"""

from dataclasses import dataclass
from typing import Final
from urllib.parse import quote_plus


@dataclass(frozen=True, slots=True)
class About:
    summary: str
    by: str
    url: str
    #: What to check or keep in mind about it in a homelab (optional).
    note: str = ""


def _a(summary: str, by: str, url: str, note: str = "") -> About:
    return About(summary, by, url, note)


ABOUT: Final[dict[str, About]] = {
    # DNS / network
    "Pi-hole": _a(
        "Network-wide ad and tracker blocking DNS server with a web dashboard.",
        "Pi-hole LLC (open source)",
        "https://pi-hole.net",
        "Clients only benefit if DHCP hands out this machine as their DNS server.",
    ),
    "AdGuard Home": _a(
        "Network-wide DNS server that blocks ads and trackers, with DoH/DoT upstreams.",
        "AdGuard (open source)",
        "https://adguard.com/adguard-home/overview.html",
    ),
    "Unbound": _a(
        "Validating, recursive, caching DNS resolver; often paired with Pi-hole.",
        "NLnet Labs",
        "https://nlnetlabs.nl/projects/unbound/about/",
    ),
    "Bind9": _a(
        "Authoritative and recursive DNS server, the reference DNS implementation.",
        "ISC",
        "https://www.isc.org/bind/",
    ),
    "dnsmasq": _a(
        "Lightweight DNS forwarder and DHCP server.",
        "Simon Kelley (open source)",
        "https://thekelleys.org.uk/dnsmasq/doc.html",
    ),
    "Tailscale": _a(
        "WireGuard-based mesh VPN that connects devices without opening ports.",
        "Tailscale Inc.",
        "https://tailscale.com",
        "Check which subnet routes and exit nodes this machine advertises.",
    ),
    "WireGuard": _a(
        "Fast, modern kernel VPN using public-key tunnels.",
        "Jason A. Donenfeld (open source)",
        "https://www.wireguard.com",
        "An exposed UDP port (51820 by default) is expected; keep keys out of backups you share.",
    ),
    "OpenVPN": _a(
        "TLS-based VPN server and client.",
        "OpenVPN Inc. (open source)",
        "https://openvpn.net/community/",
    ),
    "RustDesk": _a(
        "Self-hosted remote desktop: hbbs (ID/rendezvous) and hbbr (relay) servers.",
        "RustDesk (open source)",
        "https://rustdesk.com",
        "Ports 21115-21119 are its own; expose only what your clients need.",
    ),
    "Traefik": _a(
        "Reverse proxy and load balancer that configures itself from Docker labels.",
        "Traefik Labs (open source)",
        "https://traefik.io/traefik/",
    ),
    "Caddy": _a(
        "Web server and reverse proxy with automatic HTTPS.",
        "Caddy (open source)",
        "https://caddyserver.com",
    ),
    "Nginx": _a(
        "High-performance web server and reverse proxy.",
        "F5 / nginx (open source)",
        "https://nginx.org",
    ),
    "Nginx Proxy Manager": _a(
        "Web UI on top of Nginx to manage proxy hosts and Let's Encrypt certificates.",
        "jc21 (open source)",
        "https://nginxproxymanager.com",
        "The admin UI on port 81 should not be reachable from the internet.",
    ),
    "Apache": _a(
        "The Apache HTTP Server.", "Apache Software Foundation", "https://httpd.apache.org"
    ),
    "lighttpd": _a(
        "Small, fast web server (Pi-hole's classic web UI used it).",
        "lighttpd (open source)",
        "https://www.lighttpd.net",
    ),
    # Virtualisation / containers
    "Proxmox VE": _a(
        "Open-source virtualisation platform for KVM VMs and LXC containers, with clustering.",
        "Proxmox Server Solutions",
        "https://www.proxmox.com/en/proxmox-virtual-environment/overview",
        "Web UI on port 8006.",
    ),
    "Proxmox Backup Server": _a(
        "Deduplicating, incremental backup server for Proxmox VMs, containers and hosts.",
        "Proxmox Server Solutions",
        "https://www.proxmox.com/en/proxmox-backup-server/overview",
        "Web UI on port 8007.",
    ),
    "Docker": _a(
        "Container engine (Docker Engine) that builds and runs containers.",
        "Docker Inc. (open source engine)",
        "https://docs.docker.com/engine/",
        "Anyone in the docker group is effectively root on this machine.",
    ),
    "Portainer": _a(
        "Web UI to manage Docker, Swarm and Kubernetes environments.",
        "Portainer.io",
        "https://www.portainer.io",
    ),
    "Kubernetes (k3s)": _a(
        "Lightweight, certified Kubernetes distribution.",
        "SUSE / Rancher (open source)",
        "https://k3s.io",
    ),
    "Watchtower": _a(
        "Container that updates other containers when their image changes.",
        "containrrr (open source)",
        "https://containrrr.dev/watchtower/",
        "Updates happen without review: pin images you can't afford to change.",
    ),
    # Home / media / files
    "Home Assistant": _a(
        "Open-source home automation hub with thousands of integrations.",
        "Open Home Foundation",
        "https://www.home-assistant.io",
    ),
    "Jellyfin": _a(
        "Free media server for movies, shows and music.",
        "Jellyfin (open source)",
        "https://jellyfin.org",
    ),
    "Plex": _a("Media server with apps for most devices.", "Plex Inc.", "https://www.plex.tv"),
    "Emby": _a("Media server for personal libraries.", "Emby LLC", "https://emby.media"),
    "Sonarr": _a(
        "Monitors and downloads TV series (an *arr app).",
        "Sonarr (open source)",
        "https://sonarr.tv",
    ),
    "Radarr": _a(
        "Monitors and downloads movies (an *arr app).",
        "Radarr (open source)",
        "https://radarr.video",
    ),
    "Prowlarr": _a(
        "Indexer manager for the *arr apps.",
        "Prowlarr (open source)",
        "https://prowlarr.com",
    ),
    "qBittorrent": _a(
        "BitTorrent client with a web UI.",
        "qBittorrent (open source)",
        "https://www.qbittorrent.org",
    ),
    "Immich": _a(
        "Self-hosted photo and video backup, a Google Photos alternative.",
        "FUTO / Immich (open source)",
        "https://immich.app",
    ),
    "Nextcloud": _a(
        "Self-hosted file sync, sharing and collaboration.",
        "Nextcloud GmbH (open source)",
        "https://nextcloud.com",
    ),
    "Samba": _a(
        "SMB/CIFS file sharing for Windows, macOS and Linux clients.",
        "Samba Team",
        "https://www.samba.org",
    ),
    "NFS server": _a(
        "Linux kernel NFS file server.",
        "Linux kernel / nfs-utils",
        "https://linux-nfs.org",
        "Check /etc/exports: who may mount what, and with root_squash.",
    ),
    "Syncthing": _a(
        "Continuous peer-to-peer file synchronisation.",
        "Syncthing Foundation",
        "https://syncthing.net",
    ),
    "MinIO": _a("S3-compatible object storage server.", "MinIO Inc.", "https://min.io"),
    # Automation / dev
    "n8n": _a(
        "Workflow automation tool with a visual editor.",
        "n8n GmbH (fair-code)",
        "https://n8n.io",
    ),
    "Node-RED": _a(
        "Flow-based programming for wiring devices, APIs and services.",
        "OpenJS Foundation",
        "https://nodered.org",
    ),
    "Mosquitto (MQTT)": _a(
        "MQTT message broker used by IoT and home automation.",
        "Eclipse Foundation",
        "https://mosquitto.org",
    ),
    "Zigbee2MQTT": _a(
        "Bridges Zigbee devices to MQTT without vendor hubs.",
        "Koen Kanters (open source)",
        "https://www.zigbee2mqtt.io",
    ),
    "Gitea": _a(
        "Lightweight self-hosted Git service.", "Gitea (open source)", "https://about.gitea.com"
    ),
    "GitLab": _a(
        "DevOps platform: Git, CI/CD, registry.", "GitLab Inc.", "https://about.gitlab.com"
    ),
    "Jenkins": _a(
        "Automation server for CI/CD.", "Jenkins project (CDF)", "https://www.jenkins.io"
    ),
    # Security / identity / inventory
    "Vaultwarden": _a(
        "Lightweight Bitwarden-compatible password manager server.",
        "dani-garcia (open source)",
        "https://github.com/dani-garcia/vaultwarden",
        "Holds every password: keep it patched and backed up off this machine.",
    ),
    "Authentik": _a(
        "Identity provider: SSO, OAuth2/OIDC, SAML, LDAP.",
        "Authentik Security",
        "https://goauthentik.io",
    ),
    "NetBox": _a(
        "Network source of truth: IPAM and DCIM.",
        "NetBox Labs (open source)",
        "https://netboxlabs.com/oss/netbox/",
    ),
    "Fail2ban": _a(
        "Bans IPs that show malicious signs in logs (e.g. SSH brute force).",
        "Fail2ban (open source)",
        "https://github.com/fail2ban/fail2ban",
    ),
    "CrowdSec": _a(
        "Collaborative intrusion detection and IP reputation engine.",
        "CrowdSec SAS (open source)",
        "https://www.crowdsec.net",
    ),
    "Wazuh agent": _a(
        "Endpoint agent of the Wazuh security platform (SIEM/XDR): logs, integrity, inventory.",
        "Wazuh Inc. (open source)",
        "https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html",
        "Reports to a Wazuh manager; check which one in /var/ossec/etc/ossec.conf.",
    ),
    # Monitoring
    "Zabbix server": _a(
        "Enterprise monitoring server collecting metrics from agents and SNMP.",
        "Zabbix LLC (open source)",
        "https://www.zabbix.com",
    ),
    "Zabbix agent": _a(
        "Agent that reports this machine's metrics to a Zabbix server (port 10050).",
        "Zabbix LLC (open source)",
        "https://www.zabbix.com/documentation/current/en/manual/concepts/agent",
        "Check Server= in zabbix_agentd.conf: only your Zabbix server should be allowed.",
    ),
    "Zabbix web": _a(
        "Zabbix front end (PHP web UI).", "Zabbix LLC (open source)", "https://www.zabbix.com"
    ),
    "Grafana": _a(
        "Dashboards and alerting over Prometheus, Loki, InfluxDB and more.",
        "Grafana Labs (open source)",
        "https://grafana.com/oss/grafana/",
    ),
    "Prometheus": _a(
        "Time-series database and monitoring system that scrapes metrics.",
        "CNCF",
        "https://prometheus.io",
    ),
    "Node exporter": _a(
        "Exposes Linux host metrics for Prometheus on port 9100.",
        "Prometheus project",
        "https://github.com/prometheus/node_exporter",
    ),
    "Uptime Kuma": _a(
        "Self-hosted uptime monitoring with status pages.",
        "louislam (open source)",
        "https://github.com/louislam/uptime-kuma",
    ),
    "Netdata": _a(
        "Real-time, per-second infrastructure monitoring.",
        "Netdata Inc. (open source)",
        "https://www.netdata.cloud",
    ),
    "Loki": _a(
        "Log aggregation system indexed by labels.",
        "Grafana Labs (open source)",
        "https://grafana.com/oss/loki/",
    ),
    "InfluxDB": _a("Time-series database.", "InfluxData", "https://www.influxdata.com"),
    "Telegraf": _a(
        "Plugin-driven agent that collects and sends metrics.",
        "InfluxData (open source)",
        "https://www.influxdata.com/time-series-platform/telegraf/",
    ),
    "Promtail": _a(
        "Ships local logs to Loki.",
        "Grafana Labs (open source)",
        "https://grafana.com/docs/loki/latest/send-data/promtail/",
    ),
    "Checkmk agent": _a(
        "Agent queried by a Checkmk server (port 6556, or the agent controller).",
        "Checkmk GmbH",
        "https://docs.checkmk.com/latest/en/agent_linux.html",
    ),
    "Datadog agent": _a(
        "Sends metrics, logs and traces to Datadog's SaaS.",
        "Datadog Inc.",
        "https://docs.datadoghq.com/agent/",
        "Data leaves your network to Datadog.",
    ),
    # Remote management agents
    "Action1 agent": _a(
        "Agent of Action1, a cloud RMM / patch-management platform: patching, software "
        "inventory, scripts and remote access from Action1's console.",
        "Action1 Corporation",
        "https://www.action1.com/documentation/",
        "It is remote management with root rights from a cloud console: whoever controls "
        "that Action1 account controls this machine. Logs: /tmp/action1_agent.log.",
    ),
    "Tactical RMM agent": _a(
        "Agent of Tactical RMM, a self-hosted remote monitoring and management platform.",
        "AmidaWare (open source)",
        "https://docs.tacticalrmm.com",
        "Runs commands as root when asked by the Tactical RMM server.",
    ),
    "MeshCentral agent": _a(
        "Agent of MeshCentral, self-hosted remote desktop and management.",
        "Ylian Saint-Hilaire (open source)",
        "https://meshcentral.com",
    ),
    "Cloudflare Tunnel": _a(
        "cloudflared: exposes local services through Cloudflare without opening ports.",
        "Cloudflare",
        "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/",
        "Whatever it routes is reachable from the internet through Cloudflare.",
    ),
    "ZeroTier": _a(
        "Virtual network (SD-WAN) that joins devices into one LAN.",
        "ZeroTier Inc.",
        "https://www.zerotier.com",
    ),
    "NetBird": _a(
        "WireGuard-based zero-trust mesh VPN.",
        "NetBird (open source)",
        "https://netbird.io",
    ),
    # Databases
    "PostgreSQL": _a(
        "Relational database.", "PostgreSQL Global Development Group", "https://www.postgresql.org"
    ),
    "MariaDB / MySQL": _a(
        "Relational database.", "MariaDB Foundation / Oracle", "https://mariadb.org"
    ),
    "Redis": _a("In-memory key-value store and cache.", "Redis Ltd. / Valkey", "https://redis.io"),
    "MongoDB": _a("Document database.", "MongoDB Inc.", "https://www.mongodb.com"),
    # System
    "OpenSSH": _a(
        "Secure shell server: remote logins and file transfer.",
        "OpenBSD project",
        "https://www.openssh.com",
        "Prefer keys, disable root password logins (PermitRootLogin prohibit-password).",
    ),
    "Cockpit": _a(
        "Web console for Linux servers (port 9090).",
        "Red Hat (open source)",
        "https://cockpit-project.org",
    ),
    "Webmin": _a(
        "Web-based Linux system administration (port 10000).",
        "Webmin (open source)",
        "https://webmin.com",
    ),
    "Chrony / NTP": _a(
        "Keeps the system clock in sync.", "chrony / NTP projects", "https://chrony-project.org"
    ),
    "CUPS (printing)": _a("Print server.", "OpenPrinting", "https://openprinting.github.io/cups/"),
    "Postfix": _a("Mail transfer agent.", "Wietse Venema (open source)", "https://www.postfix.org"),
    "QEMU guest agent": _a(
        "Lets Proxmox talk to the VM: IPs, clean shutdown, consistent backups (fs-freeze).",
        "QEMU project",
        "https://pve.proxmox.com/wiki/Qemu-guest-agent",
        "Also enable 'QEMU Guest Agent' in the VM's Options in Proxmox.",
    ),
}


def about(name: str) -> About | None:
    return ABOUT.get(name)


def search_links(term: str) -> list[tuple[str, str]]:
    """Links the owner's browser opens; atlas itself never queries the internet."""
    q = quote_plus(term)
    return [
        ("Search the web", f"https://duckduckgo.com/?q={q}"),
        ("Google", f"https://www.google.com/search?q={q}"),
        ("GitHub", f"https://github.com/search?q={q}&type=repositories"),
    ]
