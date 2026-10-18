"""UniFi part of the synthetic demo lab: Integration API responses (OpenAPI v10.6.106 shapes).

UCG Ultra gateway, 2 switches, 3 APs; 5 networks (VLAN 40 added in B); SSIDs whose
securityConfiguration carries a fake passphrase that must never reach storage; zone-based
firewall; clients for every lab machine plus unknown devices.
"""

import copy
import uuid
from typing import Any

BASE = "/proxy/network/integration/v1"
NS = uuid.UUID("8f2c1d9e-0000-4000-8000-a71a5000000a")
PAGE = "?offset=0&limit=200"


def uid(name: str) -> str:
    return str(uuid.uuid5(NS, name))


def gw_mac(n: int) -> str:
    return f"e4:38:83:00:00:{n:02x}"


SITE = uid("site/default")
DEVICES: list[dict[str, Any]] = [
    {"name": "ucg-ultra", "model": "UCG-Ultra", "n": 1, "ip": "10.0.10.1", "fw": "4.3.9",
     "features": ["gateway", "switching"], "uplink": None, "ports": 5, "radios": []},
    {"name": "sw-core", "model": "USW-Pro-24-PoE", "n": 2, "ip": "10.0.10.2", "fw": "7.1.26",
     "features": ["switching"], "uplink": "ucg-ultra", "ports": 26, "radios": []},
    {"name": "sw-rack", "model": "USW-Lite-8-PoE", "n": 3, "ip": "10.0.10.3", "fw": "7.1.26",
     "features": ["switching"], "uplink": "sw-core", "ports": 8, "radios": []},
    {"name": "ap-living", "model": "U7-Pro", "n": 4, "ip": "10.0.10.4", "fw": "8.0.19",
     "features": ["accessPoint"], "uplink": "sw-core", "ports": 1, "radios": ["2.4", "5", "6"]},
    {"name": "ap-office", "model": "U7-Pro", "n": 5, "ip": "10.0.10.5", "fw": "8.0.19",
     "features": ["accessPoint"], "uplink": "sw-core", "ports": 1, "radios": ["2.4", "5", "6"]},
    {"name": "ap-garden", "model": "U6-Mesh", "n": 6, "ip": "10.0.10.6", "fw": "6.6.77",
     "features": ["accessPoint"], "uplink": "ap-living", "ports": 1, "radios": ["2.4", "5"]},
]  # fmt: skip
NETWORKS = [("Default", 1, "10.0.1.1"), ("Management", 10, "10.0.10.1"), ("Servers", 20, "10.0.20.1"),
            ("IoT", 30, "10.0.30.1")]  # fmt: skip


def state_a(mac: Any) -> dict[str, Any]:
    """`mac` is the lab's host MAC function, so clients line up with SSH/Proxmox data."""
    wired = ["docker01", "docker02", "web01", "db01", "mediatheque", "backup01", "legacy01",
             "media01", "adguard"]  # fmt: skip
    ips = {"docker01": "10.0.20.11", "docker02": "10.0.20.12", "web01": "10.0.20.21",
           "db01": "10.0.20.31", "mediatheque": "10.0.20.50", "backup01": "10.0.20.40",
           "legacy01": "10.0.20.70", "media01": "10.0.20.55", "adguard": "10.0.20.53"}  # fmt: skip
    clients = [{"name": n, "mac": mac(n), "ip": ips[n], "type": "WIRED", "via": "sw-rack"} for n in wired]
    clients += [
        {"name": "pve1", "mac": mac("pve1"), "ip": "10.0.10.11", "type": "WIRED", "via": "sw-core"},
        {"name": "pve2", "mac": mac("pve2"), "ip": "10.0.10.12", "type": "WIRED", "via": "sw-core"},
        {"name": "ipv6only01", "mac": mac("ipv6only01"), "ip": "2001:db8:20::80", "type": "WIRED", "via": "sw-rack"},
        {"name": "homeassistant", "mac": mac("homeassistant"), "ip": "10.0.30.20", "type": "WIRED", "via": "sw-rack"},
        {"name": "unas", "mac": gw_mac(0x10), "ip": "10.0.10.20", "type": "WIRED", "via": "sw-core"},
        {"name": "pi-garage", "mac": mac("pi-garage"), "ip": "10.0.20.60", "type": "WIRELESS", "via": "ap-garden"},
        {"name": "android-7f3a", "mac": "a2:11:22:33:44:55", "ip": "10.0.1.57", "type": "WIRELESS", "via": "ap-living"},
    ]  # fmt: skip
    return {
        "version": "10.6.106",
        "devices": copy.deepcopy(DEVICES),
        "networks": list(NETWORKS),
        "ssids": [
            {"name": "atlas-home", "sec": "WPA2_WPA3_PERSONAL", "net": "Default", "psk": "home-ATLASFAKE-psk"},
            {"name": "atlas-iot", "sec": "WPA2_PERSONAL", "net": "IoT", "psk": "iot-ATLASFAKE-psk"},
        ],
        "zones": {"Internal": ["Default", "Management", "Servers"], "External": [], "Gateway": [],
                  "IoT": ["IoT"], "Hotspot": [], "DMZ": []},
        "policies": [
            {"name": "Block IoT to Internal", "action": "BLOCK", "src": "IoT", "dst": "Internal", "enabled": True},
            {"name": "Allow Internal to IoT", "action": "ALLOW", "src": "Internal", "dst": "IoT", "enabled": True},
        ],
        "clients": clients,
    }  # fmt: skip


def state_b(a: dict[str, Any]) -> dict[str, Any]:
    b = copy.deepcopy(a)
    devs = {d["name"]: d for d in b["devices"]}
    devs["ap-living"]["fw"] = "8.0.26"
    devs["ap-garden"]["state"] = "OFFLINE"
    b["networks"].append(("Lab", 40, "10.0.40.1"))
    b["ssids"].append({"name": "atlas-guest", "sec": "OPEN", "net": "Default", "psk": None})
    b["policies"][0]["enabled"] = False
    b["policies"].append({"name": "Allow IoT DNS to adguard", "action": "ALLOW", "src": "IoT",
                          "dst": "Internal", "enabled": True})  # fmt: skip
    b["clients"] = [c for c in b["clients"] if c["name"] != "legacy01"]
    for c in b["clients"]:
        if c["name"] == "pi-garage":
            c["via"] = "ap-living"  # garden AP is down
    b["clients"].append({"name": "esp32-c3-5f2a", "mac": "84:f7:03:5f:2a:01", "ip": "10.0.30.41",
                         "type": "WIRELESS", "via": "ap-office"})  # fmt: skip
    b["clients"].append({"name": "win11", "mac": "", "ip": "10.0.20.110", "type": "WIRED", "via": "sw-rack"})
    return b


def _page(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"status": 200, "body": {"offset": 0, "limit": 200, "count": len(items),
                                    "totalCount": len(items), "data": items}}  # fmt: skip


def render(s: dict[str, Any], mac: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {}
    rec[f"{BASE}/info"] = {"status": 200, "body": {"applicationVersion": s["version"]}}
    rec[f"{BASE}/sites{PAGE}"] = _page([{"id": SITE, "internalReference": "default", "name": "Default"}])
    by_name = {d["name"]: d for d in s["devices"]}
    overview = []
    for d in s["devices"]:
        did = uid(f"dev/{d['name']}")
        ov = {"id": did, "name": d["name"], "model": d["model"], "macAddress": gw_mac(d["n"]),
              "ipAddress": d["ip"], "state": d.get("state", "ONLINE"), "supported": True,
              "firmwareVersion": d["fw"], "firmwareUpdatable": d["name"] == "ap-office",
              "features": d["features"], "interfaces": ["ports"] + (["radios"] if d["radios"] else [])}  # fmt: skip
        overview.append(ov)
        ports = [{"idx": i, "state": "UP" if i <= 3 else "DOWN", "connector": "SFPPLUS" if i > 24 else "RJ45",
                  "maxSpeedMbps": 10000 if i > 24 else 2500 if d["model"] == "UCG-Ultra" and i == 5 else 1000,
                  "speedMbps": 1000 if i <= 3 else None,
                  "poe": {"standard": "802.3bt", "type": 3, "enabled": "PoE" in d["model"], "state": "UP"}}
                 for i in range(1, d["ports"] + 1)]  # fmt: skip
        radios = [{"wlanStandard": "802.11be" if d["model"] == "U7-Pro" else "802.11ax",
                   "frequencyGHz": float(f) if f == "2.4" else int(f), "channelWidthMHz": 20 if f == "2.4" else 80,
                   "channel": 6 if f == "2.4" else 36} for f in d["radios"]]  # fmt: skip
        up = {"deviceId": uid(f"dev/{d['uplink']}")} if d["uplink"] and d["uplink"] in by_name else None
        rec[f"{BASE}/sites/{SITE}/devices/{did}"] = {"status": 200, "body": {
            **ov, "adoptedAt": "2025-03-01T10:00:00Z", "provisionedAt": "2026-10-01T10:00:00Z",
            "configurationId": uid(f"cfg/{d['name']}"), "uplink": up,
            "interfaces": {"ports": ports, "radios": radios}}}  # fmt: skip
    rec[f"{BASE}/sites/{SITE}/devices{PAGE}"] = _page(overview)
    clients = [
        {"type": c["type"], "id": uid(f"client/{c['name']}"), "name": c["name"],
         "connectedAt": "2026-10-17T06:00:00Z", "ipAddress": c["ip"], "access": {"type": "DEFAULT"},
         "macAddress": c["mac"] or mac(c["name"]), "uplinkDeviceId": uid(f"dev/{c['via']}")}
        for c in s["clients"]
    ]  # fmt: skip
    rec[f"{BASE}/sites/{SITE}/clients{PAGE}"] = _page(clients)
    nets = []
    zone_of = {n: z for z, ns in s["zones"].items() for n in ns}
    for name, vlan, gw in s["networks"]:
        nid = uid(f"net/{name}")
        ov = {"id": nid, "name": name, "management": "GATEWAY", "enabled": True, "vlanId": vlan,
              "default": vlan == 1, "metadata": {"origin": "USER_DEFINED"}}  # fmt: skip
        nets.append(ov)
        rec[f"{BASE}/sites/{SITE}/networks/{nid}"] = {"status": 200, "body": {
            **ov, "zoneId": uid(f"zone/{zone_of.get(name, 'Internal')}"), "isolationEnabled": name == "IoT",
            "internetAccessEnabled": True, "mdnsForwardingEnabled": name == "IoT",
            "ipv4Configuration": {"hostIpAddress": gw, "prefixLength": 24, "autoScaleEnabled": False,
                                  "dhcpConfiguration": {"mode": "SERVER", "leaseTimeSeconds": 86400,
                                                        "ipAddressRange": {"start": gw[:-1] + "100",
                                                                           "stop": gw[:-1] + "254"}}}}}  # fmt: skip
    rec[f"{BASE}/sites/{SITE}/networks{PAGE}"] = _page(nets)
    rec[f"{BASE}/sites/{SITE}/wifi/broadcasts{PAGE}"] = _page([
        {"id": uid(f"wifi/{w['name']}"), "type": "STANDARD", "name": w["name"], "enabled": True,
         "metadata": {"origin": "USER_DEFINED"}, "network": {"type": "SPECIFIC", "networkId": uid(f"net/{w['net']}")},
         "securityConfiguration": {"type": w["sec"], **({"passphrase": w["psk"]} if w["psk"] else {})},
         "broadcastingFrequenciesGHz": [2.4, 5], "hideName": False, "clientIsolationEnabled": w["net"] == "IoT"}
        for w in s["ssids"]
    ])  # fmt: skip
    rec[f"{BASE}/sites/{SITE}/firewall/zones{PAGE}"] = _page([
        {"id": uid(f"zone/{z}"), "name": z, "networkIds": [uid(f"net/{n}") for n in ns],
         "metadata": {"origin": "SYSTEM_DEFINED" if z != "IoT" else "USER_DEFINED"}}
        for z, ns in s["zones"].items()
    ])  # fmt: skip
    rec[f"{BASE}/sites/{SITE}/firewall/policies{PAGE}"] = _page([
        {"id": uid(f"pol/{p['name']}"), "name": p["name"], "enabled": p["enabled"], "index": 10000 + i,
         "action": {"type": p["action"], **({"allowReturnTraffic": True} if p["action"] == "ALLOW" else {})},
         "source": {"zoneId": uid(f"zone/{p['src']}")}, "destination": {"zoneId": uid(f"zone/{p['dst']}")},
         "ipProtocolScope": {"ipVersion": "IPV4_AND_IPV6"}, "loggingEnabled": False,
         "metadata": {"origin": "USER_DEFINED"}}
        for i, p in enumerate(s["policies"])
    ])  # fmt: skip
    rec[f"{BASE}/sites/{SITE}/acl-rules{PAGE}"] = _page([])
    rec[f"{BASE}/sites/{SITE}/wans{PAGE}"] = _page([{"id": uid("wan/1"), "name": "Internet 1"}])
    return rec


def unas(state: str) -> dict[str, Any]:
    disks = [{"slotId": i, "poolId": "1", "type": "HDD", "rpm": 5400, "model": "WD80EFPX-68C4ZN0",
              "serial": f"WD-ATLAS{i:04d}", "firmware": "81.00A81", "size": 8001563222016,
              "state": "optimal", "temperature": 34 + i, "powerOnHours": 9000 + i,
              "healthScore": 5, "badSectorCount": 0, "uncorrectableSectorCount": 0}
             for i in range(1, 5)]  # fmt: skip
    pool_status = "fullyOperational"
    if state == "B":
        disks[2] |= {"state": "degraded", "healthScore": 3, "badSectorCount": 12, "temperature": 41}
        pool_status = "degraded"
    return {
        "/api/system": {"status": 200, "body": {"hardware": {"shortname": "UNASPRO"}, "name": "unas",
                                                "mac": gw_mac(0x10), "deviceState": "connected"}},
        "/proxy/drive/api/v2/storage": {"status": 200, "body": {
            "pools": [{"id": "1", "number": 1, "type": "raid", "status": pool_status,
                       "capacity": 23998206115840, "usage": 9300000000000,
                       "raidGroups": [{"currentLevel": "raid5", "configLevel": "raid5"}]}],
            "disks": disks}},
        "/proxy/drive/api/v2/systems/device-info": {"status": 200, "body": {
            "model": "UNAS Pro", "version": "4.3.6", "firmwareVersion": "5.1.19", "status": "ok"}},
    }  # fmt: skip
