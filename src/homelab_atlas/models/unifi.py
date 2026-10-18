"""UniFi facts from the official Network Integration API (OpenAPI v10.6.106 schemas).

Wi-Fi security is reduced to its `type`; `securityConfiguration.passphrase` is never parsed.
"""

from pydantic import Field

from homelab_atlas.models.base import Fact, keyed, volatile


class UnifiNetwork(Fact):
    id: str
    name: str
    vlan_id: int | None = None
    management: str | None = None  # GATEWAY | SWITCH | UNMANAGED
    enabled: bool = True
    subnet: str | None = None  # hostIpAddress/prefixLength, normalised to the network
    gateway_ip: str | None = None
    dhcp_mode: str | None = None
    zone_id: str | None = None
    isolation: bool = False
    internet_access: bool = True


class UnifiSsid(Fact):
    id: str
    name: str
    enabled: bool = True
    hidden: bool = False
    security: str | None = None  # OPEN, WPA2_PERSONAL, WPA3_PERSONAL, ...
    network_id: str | None = None
    bands_ghz: list[str] = Field(default_factory=list)
    client_isolation: bool = False


class FirewallZone(Fact):
    id: str
    name: str
    network_ids: list[str] = Field(default_factory=list)


class FirewallPolicy(Fact):
    id: str
    name: str
    enabled: bool
    action: str | None = None  # ALLOW | BLOCK | REJECT
    source_zone: str | None = None
    destination_zone: str | None = None
    logging: bool = False
    description: str | None = None
    index: int | None = volatile()  # reordering is not a change in meaning


class AclRule(Fact):
    id: str
    name: str
    enabled: bool
    action: str | None = None
    index: int | None = volatile()


class Wan(Fact):
    id: str
    name: str


class UnifiClient(Fact):
    mac: str
    name: str | None = None
    ip: str | None = None
    type: str | None = None  # WIRED | WIRELESS | VPN | TELEPORT
    uplink_mac: str | None = None  # resolved from uplinkDeviceId
    connected_at: str | None = None


class UnifiSiteFacts(Fact):
    name: str
    reference: str | None = None
    app_version: str | None = None
    networks: list[UnifiNetwork] = keyed("name")  # names keep event text readable
    ssids: list[UnifiSsid] = keyed("name")
    zones: list[FirewallZone] = keyed("name")
    policies: list[FirewallPolicy] = keyed("name")
    acl_rules: list[AclRule] = keyed("name")
    wans: list[Wan] = keyed("name")
    #: Clients churn constantly: kept for reconciliation and the UI, never diffed.
    clients: list[UnifiClient] = volatile(factory=list)


class UnifiPort(Fact):
    idx: int
    connector: str | None = None
    max_speed_mbps: int | None = None
    poe: bool = False
    state: str | None = volatile()  # UP/DOWN flaps
    speed_mbps: int | None = volatile()


class UnifiRadio(Fact):
    frequency_ghz: str
    standard: str | None = None
    channel_width_mhz: int | None = None
    channel: int | None = volatile()  # auto channel selection


class UnifiDeviceFacts(Fact):
    id: str = volatile("")  # Integration API uuid; identity is the MAC
    name: str
    model: str | None = None
    mac: str
    ip: str | None = None
    state: str | None = None
    firmware: str | None = None
    features: list[str] = Field(default_factory=list)
    uplink_mac: str | None = None
    ports: list[UnifiPort] = keyed("idx")
    radios: list[UnifiRadio] = keyed("frequency_ghz")
    firmware_updatable: bool | None = volatile()
