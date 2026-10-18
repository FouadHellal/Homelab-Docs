"""Parse Integration API objects into facts. Fields per OpenAPI v10.6.106; tolerant of absence."""

from typing import Any

from homelab_atlas.collectors.linux_ssh.parse import norm_ip, norm_mac
from homelab_atlas.models.unifi import (
    AclRule,
    FirewallPolicy,
    FirewallZone,
    UnifiClient,
    UnifiDeviceFacts,
    UnifiNetwork,
    UnifiPort,
    UnifiRadio,
    UnifiSsid,
    Wan,
)


def _s(v: Any, limit: int = 256) -> str | None:
    if isinstance(v, int | float) and not isinstance(v, bool):
        v = str(v)
    return v[:limit] if isinstance(v, str) and v else None


def _i(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _d(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _l(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def version_tuple(text: str | None) -> tuple[int, ...]:
    parts = []
    for p in (text or "").split("."):
        if not p.isdigit():
            break
        parts.append(int(p))
    return tuple(parts)


def network(overview: dict[str, Any], details: dict[str, Any] | None) -> UnifiNetwork | None:
    n = {**overview, **(details or {})}
    nid, name = _s(n.get("id"), 64), _s(n.get("name"), 128)
    if nid is None or name is None:
        return None
    v4 = _d(n.get("ipv4Configuration"))
    host, plen = _s(v4.get("hostIpAddress"), 64), _i(v4.get("prefixLength"))
    subnet = norm_ip(f"{host}/{plen}") if host and plen is not None else None
    if subnet:
        import ipaddress  # noqa: PLC0415

        subnet = str(ipaddress.ip_interface(subnet).network)
    return UnifiNetwork(
        id=nid,
        name=name,
        vlan_id=_i(n.get("vlanId")),
        management=_s(n.get("management"), 16),
        enabled=n.get("enabled") is not False,
        subnet=subnet,
        gateway_ip=host,
        dhcp_mode=_s(_d(v4.get("dhcpConfiguration")).get("mode"), 16),
        zone_id=_s(n.get("zoneId"), 64),
        isolation=n.get("isolationEnabled") is True,
        internet_access=n.get("internetAccessEnabled") is not False,
    )


def ssid(w: dict[str, Any]) -> UnifiSsid | None:
    wid, name = _s(w.get("id"), 64), _s(w.get("name"), 64)
    if wid is None or name is None:
        return None
    # Only the security *type* is read. securityConfiguration may carry `passphrase`.
    sec = _d(w.get("securityConfiguration")).get("type")
    net = _d(w.get("network"))
    return UnifiSsid(
        id=wid,
        name=name,
        enabled=w.get("enabled") is not False,
        hidden=w.get("hideName") is True,
        security=_s(sec, 32),
        network_id=_s(net.get("networkId") or net.get("id"), 64),
        bands_ghz=sorted(str(b) for b in _l(w.get("broadcastingFrequenciesGHz"))),
        client_isolation=w.get("clientIsolationEnabled") is True,
    )


def zone(z: dict[str, Any]) -> FirewallZone | None:
    zid, name = _s(z.get("id"), 64), _s(z.get("name"), 128)
    if zid is None or name is None:
        return None
    return FirewallZone(
        id=zid, name=name, network_ids=sorted(str(n) for n in _l(z.get("networkIds")))
    )


def policy(p: dict[str, Any]) -> FirewallPolicy | None:
    pid, name = _s(p.get("id"), 64), _s(p.get("name"), 128)
    if pid is None or name is None:
        return None
    return FirewallPolicy(
        id=pid,
        name=name,
        enabled=p.get("enabled") is True,
        action=_s(_d(p.get("action")).get("type"), 16),
        source_zone=_s(_d(p.get("source")).get("zoneId"), 64),
        destination_zone=_s(_d(p.get("destination")).get("zoneId"), 64),
        logging=p.get("loggingEnabled") is True,
        description=_s(p.get("description"), 512),
        index=_i(p.get("index")),
    )


def acl_rule(a: dict[str, Any]) -> AclRule | None:
    aid, name = _s(a.get("id"), 64), _s(a.get("name"), 128)
    if aid is None or name is None:
        return None
    action = a.get("action")
    return AclRule(
        id=aid,
        name=name,
        enabled=a.get("enabled") is True,
        action=_s(action if isinstance(action, str) else _d(action).get("type"), 16),
        index=_i(a.get("index")),
    )


def wan(w: dict[str, Any]) -> Wan | None:
    wid, name = _s(w.get("id"), 64), _s(w.get("name"), 128)
    return Wan(id=wid, name=name) if wid and name else None


def client(c: dict[str, Any], mac_by_id: dict[str, str]) -> UnifiClient | None:
    mac = norm_mac(c.get("macAddress"))
    if mac is None:
        return None
    ip = _s(c.get("ipAddress"), 64)
    return UnifiClient(
        mac=mac,
        name=_s(c.get("name"), 128),
        ip=norm_ip(ip) if ip else None,
        type=_s(c.get("type"), 16),
        uplink_mac=mac_by_id.get(str(c.get("uplinkDeviceId"))),
        connected_at=_s(c.get("connectedAt"), 64),
    )


def device(
    overview: dict[str, Any], details: dict[str, Any] | None, mac_by_id: dict[str, str]
) -> UnifiDeviceFacts | None:
    d = {**overview, **(details or {})}
    mac = norm_mac(d.get("macAddress"))
    if mac is None:
        return None
    ifaces = _d(d.get("interfaces"))
    ports = [
        UnifiPort(
            idx=p["idx"],
            connector=_s(p.get("connector"), 16),
            max_speed_mbps=_i(p.get("maxSpeedMbps")),
            poe=bool(_d(p.get("poe")).get("enabled")),
            state=_s(p.get("state"), 16),
            speed_mbps=_i(p.get("speedMbps")),
        )
        for p in _l(ifaces.get("ports"))
        if isinstance(p, dict) and _i(p.get("idx")) is not None
    ]
    radios = [
        UnifiRadio(
            frequency_ghz=str(r.get("frequencyGHz")),
            standard=_s(r.get("wlanStandard"), 32),
            channel_width_mhz=_i(r.get("channelWidthMHz")),
            channel=_i(r.get("channel")),
        )
        for r in _l(ifaces.get("radios"))
        if isinstance(r, dict) and r.get("frequencyGHz") is not None
    ]
    ip = _s(d.get("ipAddress"), 64)
    return UnifiDeviceFacts(
        id=_s(d.get("id"), 64) or "",
        name=_s(d.get("name"), 128) or mac,
        model=_s(d.get("model"), 64),
        mac=mac,
        ip=norm_ip(ip) if ip else None,
        state=_s(d.get("state"), 32),
        firmware=_s(d.get("firmwareVersion"), 64),
        features=sorted(str(f) for f in _l(d.get("features"))),
        uplink_mac=mac_by_id.get(str(_d(d.get("uplink")).get("deviceId"))),
        ports=ports,
        radios=radios,
        firmware_updatable=d.get("firmwareUpdatable")
        if isinstance(d.get("firmwareUpdatable"), bool)
        else None,
    )
