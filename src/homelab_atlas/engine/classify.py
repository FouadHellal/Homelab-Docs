"""Tell infrastructure (VMs, servers, Raspberry Pis, NAS) from phones/TVs/IoT (ADR-027).

A UniFi site sees every device on the network. atlas documents infrastructure, so each
unexplained device gets a category plus the reasons, and the UI shows infrastructure first.
Signals, strongest first:

* MAC vendor prefix (OUI) of virtualisation platforms, Raspberry Pi and NAS vendors.
* Locally administered ("randomized") MACs: phones/tablets/laptops use them for privacy;
  servers practically never do (Docker's 02:42 prefix is handled separately).
* Device names (UniFi client name / hostname): server-ish vs consumer words.
* Wired on a server/lab/management VLAN vs wireless on a guest/IoT VLAN.

Purely local heuristics on data atlas already has: no lookups, no packets.
"""

import re
from dataclasses import dataclass
from typing import Final, Literal

Category = Literal[
    "vm", "container", "pi", "nas", "server", "network", "personal", "iot", "unknown"
]
INFRASTRUCTURE: Final = frozenset({"vm", "container", "pi", "nas", "server", "network"})

#: OUI prefixes (first three octets, lowercase).
OUI: Final[dict[str, tuple[Category, str]]] = {
    "bc:24:11": ("vm", "Proxmox VM MAC prefix"),
    "52:54:00": ("vm", "QEMU/KVM MAC prefix"),
    "00:50:56": ("vm", "VMware MAC prefix"),
    "00:0c:29": ("vm", "VMware MAC prefix"),
    "00:15:5d": ("vm", "Hyper-V MAC prefix"),
    "08:00:27": ("vm", "VirtualBox MAC prefix"),
    "00:16:3e": ("vm", "Xen MAC prefix"),
    "b8:27:eb": ("pi", "Raspberry Pi MAC prefix"),
    "dc:a6:32": ("pi", "Raspberry Pi MAC prefix"),
    "e4:5f:01": ("pi", "Raspberry Pi MAC prefix"),
    "28:cd:c1": ("pi", "Raspberry Pi MAC prefix"),
    "d8:3a:dd": ("pi", "Raspberry Pi MAC prefix"),
    "2c:cf:67": ("pi", "Raspberry Pi MAC prefix"),
    "00:11:32": ("nas", "Synology MAC prefix"),
    "24:5e:be": ("nas", "QNAP MAC prefix"),
    "00:08:9b": ("nas", "QNAP MAC prefix"),
}

_INFRA_WORDS: Final = re.compile(
    r"(?<![a-z])(srv|server|pve|proxmox|esxi|hyperv|nas|truenas|unraid|synology|qnap|docker|"
    r"k8s|k3s|kube|node\d*|vm\d*|lxc|ct\d*|pi|rpi|raspberry|raspberrypi|homeassistant|hass|"
    r"pihole|pi-hole|adguard|plex|jellyfin|nextcloud|db\d*|sql|postgres|mysql|web\d*|"
    r"proxy|nginx|traefik|caddy|gitlab|gitea|backup|pbs|minio|grafana|prometheus)(?![a-z])",
    re.IGNORECASE,
)
_PERSONAL_WORDS: Final = re.compile(
    r"(iphone|ipad|android|galaxy|pixel|oneplus|xiaomi|redmi|huawei|macbook|laptop|"
    r"desktop-[a-z0-9]+|surface|watch|airpods)",
    re.IGNORECASE,
)
_IOT_WORDS: Final = re.compile(
    r"(tv|chromecast|roku|firetv|fire-tv|echo|alexa|sonos|nest|hue|shelly|tasmota|esp|"
    r"tuya|printer|epson|canon|brother|hp[a-z0-9]*|camera|cam\d*|doorbell|xbox|playstation|"
    r"ps[45]|nintendo|vacuum|roborock)",
    re.IGNORECASE,
)
_INFRA_NET: Final = re.compile(r"(server|srv|lab|mgmt|manage|infra|dmz|core|storage|k8s)", re.I)
_ENDPOINT_NET: Final = re.compile(r"(guest|iot|kids|family|media|camera|wifi)", re.I)


@dataclass(frozen=True, slots=True)
class Verdict:
    category: Category
    reasons: tuple[str, ...]

    @property
    def infrastructure(self) -> bool:
        return self.category in INFRASTRUCTURE


def classify(
    mac: str | None,
    name: str | None = None,
    *,
    wired: bool | None = None,
    network: str | None = None,
) -> Verdict:
    mac = (mac or "").lower()
    name = name or ""
    reasons: list[str] = []
    if mac.startswith("02:42:"):
        return Verdict("container", ("Docker MAC prefix",))
    if (hit := OUI.get(mac[:8])) is not None:
        return Verdict(hit[0], (hit[1],))
    randomized = (
        len(mac) >= 2 and bool(int(mac[1], 16) & 0x2) if re.match(r"^[0-9a-f]{2}:", mac) else False
    )
    infra_name = bool(_INFRA_WORDS.search(name))
    if _PERSONAL_WORDS.search(name):
        return Verdict("personal", (f"name “{name[:40]}” looks like a personal device",))
    if _IOT_WORDS.search(name) and not infra_name:
        return Verdict("iot", (f"name “{name[:40]}” looks like a TV/IoT/printer",))
    if infra_name:
        reasons.append(f"name “{name[:40]}” looks like a server")
        return Verdict("server", tuple(reasons))
    if randomized:
        return Verdict(
            "personal", ("randomized (private) MAC address, typical of phones and laptops",)
        )
    if network and _ENDPOINT_NET.search(network):
        return Verdict("iot" if wired is False else "unknown", (f"on the “{network}” network",))
    if wired and network and _INFRA_NET.search(network):
        return Verdict("server", (f"wired on the “{network}” network",))
    if wired:
        return Verdict("unknown", ("wired device with no name hint",))
    if wired is False:
        return Verdict("personal", ("wireless device with no server hint",))
    return Verdict("unknown", ("no hint",))
