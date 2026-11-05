"""Parse Integration API objects into facts. Fields per OpenAPI v10.6.106; tolerant of absence."""

from datetime import UTC, datetime
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


def client(
    c: dict[str, Any],
    mac_by_id: dict[str, str],
    ports: dict[str, int] | None = None,
    details: dict[str, dict[str, Any]] | None = None,
) -> UnifiClient | None:
    mac = norm_mac(c.get("macAddress"))
    if mac is None:
        return None
    ip = _s(c.get("ipAddress"), 64)
    return UnifiClient(
        **(details or {}).get(mac, {}),
        mac=mac,
        name=_s(c.get("name"), 128),
        ip=norm_ip(ip) if ip else None,
        type=_s(c.get("type"), 16),
        uplink_mac=mac_by_id.get(str(c.get("uplinkDeviceId"))),
        uplink_port=(ports or {}).get(mac),
        connected_at=_s(c.get("connectedAt"), 64),
    )


def _int(v: Any, lo: int, hi: int) -> int | None:
    if isinstance(v, bool) or not isinstance(v, int | float):
        return None
    n = int(v)
    return n if lo <= n <= hi else None


def _epoch(v: Any) -> str | None:
    n = _int(v, 946684800, 4102444800)  # 2000..2100
    return datetime.fromtimestamp(n, UTC).isoformat() if n is not None else None


def classic_details(body: Any) -> dict[str, dict[str, Any]]:
    """MAC -> what the UniFi UI shows about a client, from a classic `stat/sta` answer
    (ADR-046). Typed, range-checked and capped; free-text notes are never kept."""
    data = body.get("data") if isinstance(body, dict) else None
    out: dict[str, dict[str, Any]] = {}
    big = 1 << 62
    for c in data if isinstance(data, list) else []:
        if not isinstance(c, dict) or (mac := norm_mac(c.get("mac"))) is None:
            continue
        wired = c.get("is_wired") is True
        fixed = _s(c.get("fixed_ip"), 64) if c.get("use_fixedip") is True else None
        row: dict[str, Any] = {
            "hostname": _s(c.get("hostname"), 128),
            "vendor": _s(c.get("oui"), 64),
            "network": _s(c.get("network"), 64),
            "vlan": _int(c.get("vlan"), 0, 4094),
            "ssid": None if wired else _s(c.get("essid"), 64),
            "ap_mac": None if wired else norm_mac(c.get("ap_mac")),
            "radio": None if wired else _s(c.get("radio"), 8),
            "channel": None if wired else _int(c.get("channel"), 1, 233),
            "signal_dbm": None if wired else _int(c.get("signal"), -120, 0),
            "satisfaction": _int(c.get("satisfaction"), 0, 100),
            "tx_rate_kbps": _int(c.get("tx_rate"), 0, 100_000_000),
            "rx_rate_kbps": _int(c.get("rx_rate"), 0, 100_000_000),
            "wired_rate_mbps": _int(c.get("wired_rate_mbps"), 0, 400_000) if wired else None,
            "tx_bytes": _int(c.get("tx_bytes"), 0, big),
            "rx_bytes": _int(c.get("rx_bytes"), 0, big),
            "uptime_s": _int(c.get("uptime"), 0, 1 << 40),
            "first_seen": _epoch(c.get("first_seen")),
            "last_seen": _epoch(c.get("last_seen")),
            "fixed_ip": norm_ip(fixed) if fixed else None,
            "guest": c.get("is_guest") if isinstance(c.get("is_guest"), bool) else None,
        }
        out[mac] = {k: v for k, v in row.items() if v is not None}  # port: classic_ports
    return out


def classic_ports(body: Any) -> dict[str, int]:
    """Wired client MAC -> switch port, from a classic `stat/sta` answer
    ({"meta": {"rc": "ok"}, "data": [{"mac", "is_wired", "sw_mac", "sw_port", ...}]})."""
    data = body.get("data") if isinstance(body, dict) else None
    out: dict[str, int] = {}
    for c in data if isinstance(data, list) else []:
        if not isinstance(c, dict) or c.get("is_wired") is False:
            continue
        mac, port = norm_mac(c.get("mac")), c.get("sw_port")
        if mac and isinstance(port, int) and not isinstance(port, bool) and 0 < port < 1000:
            out[mac] = port
    return out


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
