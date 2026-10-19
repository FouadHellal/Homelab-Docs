"""UniFi Site Manager (cloud) helpers for keys created at unifi.ui.com (ADR-026).

Sources (read 2026-10-19):
* Site Manager OpenAPI v1.0.0, https://developer.ui.com/site-manager/v1.0.0/openapi.json:
  server `https://api.ui.com`, `GET /v1/hosts` (query `pageSize`, `nextToken`), header
  `X-API-KEY`; each host has `id` (the console id), `type`, `ipAddress`, `reportedState`.
* Network v10.6.106 "Connector - GET" page: `GET /v1/connector/consoles/{id}/*path` proxies
  to `http://127.0.0.1/proxy/<path>` on the console (firmware >= 5.0.3, 100 requests per
  minute per console, 25 s timeout, 10 MB bodies). Its example uses
  `/v1/connector/consoles/{id}/network/integration/v1/sites`; the Network OpenAPI `servers`
  entry instead says `.../consoles/{consoleId}/proxy/network/integration`. The connection
  test tries the connector page's form first and falls back to the other.
"""

from typing import Any, Final

from homelab_atlas.security.allowlist import Endpoint

SITE_MANAGER: Final = "https://api.ui.com"
CONSOLE_ID_RE: Final = r"[0-9A-Za-z]{1,128}:[0-9]{1,20}"
HOSTS = Endpoint(
    "sitemanager.hosts",
    "GET",
    "/v1/hosts",
    query={"pageSize": r"[1-9]\d{0,2}", "nextToken": r"[A-Za-z0-9_=+/.-]{1,512}"},
)
#: Candidate connector bases, most likely first (see module docstring).
CONNECTOR_BASES: Final = (
    "https://api.ui.com/v1/connector/consoles/{id}/network/integration",
    "https://api.ui.com/v1/connector/consoles/{id}/proxy/network/integration",
)
#: The connector allows 100 requests/min/console; stay comfortably under it.
CLOUD_MIN_INTERVAL_S: Final = 0.75


def consoles(payload: Any) -> list[dict[str, str]]:
    """Network-capable consoles from a /v1/hosts page: id, name, type, public IP."""
    out: list[dict[str, str]] = []
    data = payload.get("data") if isinstance(payload, dict) else None
    for h in data if isinstance(data, list) else []:
        if not isinstance(h, dict) or not isinstance(h.get("id"), str):
            continue
        rs_raw, ud_raw = h.get("reportedState"), h.get("userData")
        rs: dict[str, Any] = rs_raw if isinstance(rs_raw, dict) else {}
        ud: dict[str, Any] = ud_raw if isinstance(ud_raw, dict) else {}
        apps = {
            str(a)
            for a in (ud.get("controllers") or rs.get("controllers") or [])
            if isinstance(a, str)
        }
        if apps and "network" not in apps:
            continue
        name = rs.get("name") or rs.get("hostname") or h.get("hardwareId") or h["id"]
        out.append(
            {
                "id": h["id"][:160],
                "name": str(name)[:80],
                "type": str(h.get("type") or "")[:32],
                "ip": str(h.get("ipAddress") or "")[:64],
            }
        )
    return out
