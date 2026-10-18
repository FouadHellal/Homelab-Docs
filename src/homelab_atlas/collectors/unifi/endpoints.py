"""UniFi Network Integration API allowlist (ADR-005).

Verified against the official OpenAPI spec, Network v10.6.106
(https://developer.ui.com/network/v10.6.106/openapi.json, read 2026-10-18):
* local server `https://{consoleIP}/proxy/network/integration`, header `X-API-KEY`;
* list endpoints take `offset` (>=0) and `limit` (<=200) and return
  `{offset, limit, count, totalCount, data}`;
* everything here is GET. The same API has POST/PUT/PATCH/DELETE and `.../actions` paths
  for writes; none are registered, and `actions` is a denied segment anyway.

Deliberately NOT registered: `wifi/broadcasts/{id}` (details carry
`securityConfiguration.passphrase`), `hotspot/vouchers` (guest codes), statistics (volatile),
`pending-devices` (adoption flow).
"""

from typing import Final

from homelab_atlas.security.allowlist import Endpoint

UUID: Final = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
PAGE: Final = {"offset": r"\d{1,6}", "limit": r"[1-9]\d{0,2}"}
PAGE_LIMIT: Final = 200
MAX_PAGES: Final = 50
_SITE = {"site_id": UUID}

INFO = Endpoint("unifi.info", "GET", "/v1/info")
SITES = Endpoint("unifi.sites", "GET", "/v1/sites", query=PAGE)
DEVICES = Endpoint("unifi.devices", "GET", "/v1/sites/{site_id}/devices", _SITE, PAGE)
DEVICE = Endpoint(
    "unifi.device", "GET", "/v1/sites/{site_id}/devices/{device_id}", {**_SITE, "device_id": UUID}
)
CLIENTS = Endpoint("unifi.clients", "GET", "/v1/sites/{site_id}/clients", _SITE, PAGE)
NETWORKS = Endpoint("unifi.networks", "GET", "/v1/sites/{site_id}/networks", _SITE, PAGE)
NETWORK = Endpoint(
    "unifi.network",
    "GET",
    "/v1/sites/{site_id}/networks/{network_id}",
    {**_SITE, "network_id": UUID},
)
WIFI = Endpoint("unifi.wifi", "GET", "/v1/sites/{site_id}/wifi/broadcasts", _SITE, PAGE)
ZONES = Endpoint("unifi.zones", "GET", "/v1/sites/{site_id}/firewall/zones", _SITE, PAGE)
POLICIES = Endpoint("unifi.policies", "GET", "/v1/sites/{site_id}/firewall/policies", _SITE, PAGE)
ACL_RULES = Endpoint("unifi.acl", "GET", "/v1/sites/{site_id}/acl-rules", _SITE, PAGE)
WANS = Endpoint("unifi.wans", "GET", "/v1/sites/{site_id}/wans", _SITE, PAGE)

COLLECT: Final = frozenset(
    {
        INFO,
        SITES,
        DEVICES,
        DEVICE,
        CLIENTS,
        NETWORKS,
        NETWORK,
        WIFI,
        ZONES,
        POLICIES,
        ACL_RULES,
        WANS,
    }
)
DOCTOR: Final = frozenset({INFO, SITES})
#: Integration API with the endpoints above exists from Network 9.3 (developer.ui.com index).
MIN_VERSION: Final = (9, 3)
