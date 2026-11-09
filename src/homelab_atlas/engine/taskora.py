"""Taskora service desk integration (ADR-042).

atlas pushes; Taskora never connects to atlas. Three flows, all through ReadOnlyHttpClient:

* **Incidents → tickets.** Each incident has a `TaskoraLink`: a monotonic `revision`, the digest
  of what was last staged, and its delivery state. `stage()` bumps the revision when something
  meaningful changed; `deliver()` POSTs the incident's *current* full state for every link
  whose `sent_revision` lags (a per-incident latest-state outbox: Taskora takes full states,
  so intermediate ones are never needed, and revisions make retries/replays harmless).
  Retries back off with jitter; state lives in the database, so a restart loses nothing.
* **Ticket lifecycle → atlas.** `poll_feed()` reads Taskora's ticket-events feed from a stored
  cursor. A technician assigning the ticket or moving it out of *New* acknowledges the
  incident (`acknowledged_by = "Taskora: <name>"`, never echoed back). A ticket resolved while
  atlas still sees the problem makes the next delivery say `persisting`; only atlas declares
  recovery.
* **Inventory → CMDB.** `inventory_sync()` sends atlas's machines and UniFi devices with
  placement and network relations, as a preview (writes nothing) or an apply.

Nothing here writes to monitored infrastructure. Payloads are typed, size-capped and built
from redacted facts, redacted once more on the way out. The token lives in the vault.
"""

import hashlib
import json
import random
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from homelab_atlas.engine import alerts, media
from homelab_atlas.engine.notify import clean_token
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.redact import Redactor
from homelab_atlas.security.allowlist import Endpoint
from homelab_atlas.security.audit import AuditSink
from homelab_atlas.security.errors import (
    HttpStatusError,
    SecurityRefusal,
    TargetTimeout,
    TransportError,
)
from homelab_atlas.security.http import (
    AuthHeader,
    HttpLimits,
    ReadOnlyHttpClient,
    TlsPolicy,
    lan_ip_literal,
)
from homelab_atlas.store.tables import (
    Entity,
    Event,
    Facet,
    Incident,
    Scan,
    TaskoraLink,
    TaskoraState,
    utcnow,
)

TOKEN_SECRET: Final = "taskora_token"  # noqa: S105 - a secret *name*, not a value
SETTINGS_FILE: Final = "taskora.yaml"
API: Final = "/api/v1/integrations/atlas/v1"
INSTANCE_RE: Final = r"^[a-z0-9][a-z0-9._-]{0,63}$"
KEY_RE: Final = r"[a-z0-9][a-z0-9._-]{0,63}:[0-9]{1,18}"
LIMITS: Final = HttpLimits(connect_s=5.0, read_s=15.0, total_s=30.0, max_bytes=4 * 1024 * 1024)
#: An incident becomes a ticket once it has lasted this long (a blip is not a ticket).
SEND_AFTER: Final = timedelta(minutes=5)
#: Resolved incidents keep being considered this long (late recovery delivery).
KEEP_RESOLVED: Final = timedelta(days=7)
BACKOFF_MAX_S: Final = 3600
CONFIG_RETRY: Final = timedelta(minutes=30)
PER_TICK: Final = 25
FEED_PAGES: Final = 5
#: Kinds atlas sends to the CMDB: infrastructure, never clients (phones, TVs, IoT).
CMDB_KINDS: Final = (
    "pve-node",
    "pve-vm",
    "pve-lxc",
    "linux-host",
    "nas",
    "unifi-switch",
    "unifi-ap",
    "unifi-gateway",
)
MAC_RE: Final = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
TICKET_PATH_RE: Final = re.compile(r"^/tickets/[0-9]{1,12}$")
ErrorKind = Literal["retry", "config", "permanent"]


# --------------------------------------------------------------------------- settings


class TaskoraSettings(BaseModel):
    """Integrations page → Taskora (`<data>/taskora.yaml`). The token is in the vault."""

    model_config = ConfigDict(extra="forbid")
    url: str = Field(max_length=200, pattern=r"^https?://[A-Za-z0-9.\-]+(:[0-9]{1,5})?/?$")
    #: This atlas's id in Taskora: incident keys are `<instance>:<id>`.
    instance: str = Field(default="atlas", pattern=INSTANCE_RE)
    allow_http: bool = False
    #: PEM anchor for a self-signed Taskora (file name in the config dir).
    ca_file: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    #: Send incidents (tickets). Off = nothing is sent; links are kept.
    incidents: bool = False
    #: After each scan, apply a complete inventory sync (CMDB). Preview stays manual.
    cmdb_auto: bool = False

    @property
    def base(self) -> str:
        return self.url.rstrip("/")


def load_settings(data_dir: Path | None) -> TaskoraSettings | None:
    if data_dir is None:
        return None
    path = data_dir / SETTINGS_FILE
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None
        return TaskoraSettings.model_validate(raw) if isinstance(raw, dict) else None
    except (OSError, yaml.YAMLError, ValidationError):
        return None


def save_settings(data_dir: Path, settings: TaskoraSettings) -> None:
    host = urlsplit(settings.url).hostname or ""
    if settings.url.startswith("http://") and not (settings.allow_http and lan_ip_literal(host)):
        raise ValueError("http:// only to a private LAN IP, with “plain HTTP on my LAN” ticked")
    data_dir.mkdir(parents=True, exist_ok=True)
    tmp = data_dir / f".{SETTINGS_FILE}.tmp"
    tmp.write_text(yaml.safe_dump(settings.model_dump(), sort_keys=False), encoding="utf-8")
    tmp.replace(data_dir / SETTINGS_FILE)


# --------------------------------------------------------------------------- payloads
# Nested parts are validated with their own model, then sent as plain dicts: the HTTP client
# serialises only top-level fields, and optional nested fields must be absent, not null.


class EntityRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(max_length=48)
    hostname: str | None = Field(default=None, max_length=255)
    ips: list[str] = Field(default_factory=list, max_length=16)
    macs: list[str] = Field(default_factory=list, max_length=16)
    pveCluster: str | None = Field(default=None, max_length=64)  # noqa: N815 - wire name
    pveNode: str | None = Field(default=None, max_length=64)  # noqa: N815
    vmid: int | None = Field(default=None, gt=0, lt=1_000_000_000)
    network: str | None = Field(default=None, max_length=64)
    vlan: int | None = Field(default=None, ge=0, le=4094)
    uplink: str | None = Field(default=None, max_length=128)


class InventoryEntity(EntityRef):
    status: Literal["running", "stopped", "online", "offline", "unknown", "missing"] = "unknown"
    os: str | None = Field(default=None, max_length=120)
    serial: str | None = Field(default=None, max_length=120)
    manufacturer: str | None = Field(default=None, max_length=120)
    model: str | None = Field(default=None, max_length=120)
    observedAt: str  # noqa: N815
    apps: list[dict[str, str]] = Field(default_factory=list, max_length=80)


class Relation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    from_: str = Field(alias="from", max_length=256)
    to: str = Field(max_length=256)
    type: Literal["hosted_on", "connected_to", "depends_on", "runs_on"]
    detail: str | None = Field(default=None, max_length=120)


def _plain(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json", exclude_none=True, by_alias=True)


class IncidentEvent(BaseModel):
    """Taskora's `atlasIncidentEventSchema` (contract v1)."""

    model_config = ConfigDict(extra="forbid")
    instance: str = Field(pattern=INSTANCE_RE)
    incidentId: int = Field(gt=0)  # noqa: N815
    revision: int = Field(gt=0)
    fingerprint: str = Field(min_length=1, max_length=128)
    kind: str = Field(min_length=1, max_length=48)
    title: str = Field(min_length=1, max_length=250)
    summary: str = Field(default="", max_length=4000)
    severity: Literal["info", "notice", "warning"]
    state: Literal["open", "acknowledged", "resolved"]
    persisting: bool = False
    firstObservedAt: str  # noqa: N815
    lastObservedAt: str  # noqa: N815
    resolvedAt: str | None = None  # noqa: N815
    acknowledgedBy: str | None = Field(default=None, max_length=64)  # noqa: N815
    lastHealthyAt: str | None = None  # noqa: N815
    entity: dict[str, Any] | None = None
    checks: list[dict[str, str]] = Field(default_factory=list, max_length=20)
    evidence: list[str] = Field(default_factory=list, max_length=20)
    recentChanges: list[str] = Field(default_factory=list, max_length=15)  # noqa: N815
    link: str | None = Field(default=None, max_length=512)
    test: bool = False


class InventorySync(BaseModel):
    model_config = ConfigDict(extra="forbid")
    instance: str = Field(pattern=INSTANCE_RE)
    mode: Literal["preview", "apply"]
    complete: bool = True
    entities: list[dict[str, Any]] = Field(max_length=500)
    relations: list[dict[str, Any]] = Field(default_factory=list, max_length=2000)


class TicketSnapshot(BaseModel):
    """What Taskora says about a ticket. Untrusted: validated, capped, never rendered raw."""

    model_config = ConfigDict(extra="ignore")
    id: int = Field(gt=0)
    number: str = Field(max_length=32)
    status: str = Field(max_length=64)
    statusCategory: Literal["new", "open", "waiting", "resolved", "closed"]  # noqa: N815
    priority: str = Field(default="", max_length=64)
    assignee: str | None = Field(default=None, max_length=128)
    path: str = Field(max_length=32)


# --------------------------------------------------------------------------- client

JUSTIFICATION: Final = (
    "Writes only to the owner's own Taskora service desk (tickets/CMDB records) through its "
    "scoped integration API: a typed, redacted payload. Changes nothing on monitored targets."
)
HEALTH: Final = Endpoint("taskora.health", "GET", f"{API}/health")
INCIDENT_GET: Final = Endpoint(
    "taskora.incident.get", "GET", f"{API}/incidents/{{key}}", path_vars={"key": KEY_RE}
)
INCIDENT_PUT: Final = Endpoint(
    "taskora.incident.upsert",
    "POST",
    f"{API}/incidents/{{key}}",
    path_vars={"key": KEY_RE},
    body_model=IncidentEvent,
    read_only_justification=JUSTIFICATION,
)
FEED: Final = Endpoint(
    "taskora.ticket_events",
    "GET",
    f"{API}/ticket-events",
    query={"after": r"[0-9]{1,18}", "limit": r"[0-9]{1,3}"},
)
INVENTORY: Final = Endpoint(
    "taskora.inventory",
    "POST",
    f"{API}/inventory",
    body_model=InventorySync,
    read_only_justification=JUSTIFICATION,
)
ENDPOINTS: Final = frozenset({HEALTH, INCIDENT_GET, INCIDENT_PUT, FEED, INVENTORY})


class TaskoraError(Exception):
    def __init__(self, kind: ErrorKind, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.kind: ErrorKind = kind
        self.status = status


def classify(status: int) -> ErrorKind:
    """429/408/5xx: try again soon; 401/403/404/409: a setting to fix in Taskora or atlas
    (retried slowly); anything else (400, 413…): this payload will not succeed as is."""
    if status in (408, 425, 429) or status >= 500:
        return "retry"
    if status in (401, 403, 404, 409):
        return "config"
    return "permanent"


HINTS: Final = {
    401: "token refused (revoked or wrong?)",
    403: "token lacks the scope",
    404: "not found (Taskora 0.3.0 or later? right address?)",
    409: "integration disabled or no company chosen in Taskora",
    413: "payload too large",
    429: "rate limited",
}


class TaskoraClient:
    """Typed calls to Taskora's atlas API. Raises TaskoraError, never anything else."""

    def __init__(
        self,
        settings: TaskoraSettings,
        token: SecretStr | None,
        audit: AuditSink,
        *,
        config_dirs: Sequence[Path] = (),
        redactor: Redactor | None = None,
        transport: object | None = None,
    ) -> None:
        self.settings = settings
        self._token = clean_token(token)
        self._audit = audit
        self._redactor = redactor
        self._transport = transport
        self._ca: Path | None = None
        if settings.ca_file:
            self._ca = next(
                (d / settings.ca_file for d in config_dirs if (d / settings.ca_file).is_file()),
                None,
            )
            if self._ca is None:
                raise ValueError(f"Taskora CA file {settings.ca_file} not found in the config dir")

    @property
    def has_token(self) -> bool:
        return self._token is not None

    def _client(self) -> ReadOnlyHttpClient:
        parts = urlsplit(self.settings.url)
        tls = None
        public_host = None
        if parts.scheme == "https":
            if self._ca is not None:
                tls = TlsPolicy(ca_file=self._ca)
            else:
                tls = TlsPolicy(ca_file=None, public_pki=True)
                public_host = parts.hostname
        if self._token is None:
            raise TaskoraError("config", "no Taskora token saved")
        return ReadOnlyHttpClient(
            target="taskora",
            base_url=f"{parts.scheme}://{parts.netloc}",
            endpoints=ENDPOINTS,
            audit=self._audit,
            tls=tls,
            auth=AuthHeader("Authorization", SecretStr(f"Bearer {self._token.get_secret_value()}")),
            limits=LIMITS,
            transport=self._transport,  # type: ignore[arg-type]
            plain_http_lan=self.settings.allow_http,
            public_pki_host=public_host,
        )

    async def _call(
        self,
        ep: Endpoint,
        *,
        body: BaseModel | None = None,
        path_vars: Mapping[str, str] | None = None,
        query: Mapping[str, str | int | bool] | None = None,
    ) -> Any:
        try:
            async with self._client() as client:
                if body is not None:
                    res = await client.post(ep, body, path_vars)
                else:
                    res = await client.get(ep, path_vars, query)
            return res.json()
        except TaskoraError:
            raise
        except SecurityRefusal as exc:
            raise TaskoraError(
                "config", f"refused: {exc.reason.value} {exc.detail or ''}".strip()[:200]
            ) from None
        except HttpStatusError as exc:
            hint = HINTS.get(exc.status, "")
            raise TaskoraError(
                classify(exc.status),
                f"Taskora answered HTTP {exc.status} {hint}".strip(),
                exc.status,
            ) from None
        except (TransportError, TargetTimeout) as exc:
            raise TaskoraError("retry", f"Taskora unreachable: {exc}"[:200]) from None
        except ValueError:
            raise TaskoraError("retry", "Taskora answered something that is not JSON") from None

    async def health(self) -> dict[str, Any]:
        data = await self._call(HEALTH)
        if not isinstance(data, dict) or data.get("integration") != "atlas":
            raise TaskoraError("config", "this address does not answer like Taskora's atlas API")
        return {
            k: data.get(k)
            for k in (
                "enabled",
                "companyConfigured",
                "autoCreateTickets",
                "cmdbMode",
                "scopes",
                "apiVersion",
            )
        }

    async def upsert(self, ev: IncidentEvent) -> dict[str, Any]:
        if self._redactor is not None:
            r = self._redactor
            ev = ev.model_copy(
                update={
                    "title": r.text(ev.title)[:250],
                    "summary": r.text(ev.summary)[:4000],
                    "evidence": [r.text(e)[:400] for e in ev.evidence],
                    "recentChanges": [r.text(e)[:300] for e in ev.recentChanges],
                }
            )
        data = await self._call(
            INCIDENT_PUT, body=ev, path_vars={"key": f"{ev.instance}:{ev.incidentId}"}
        )
        return data if isinstance(data, dict) else {}

    async def lookup(self, instance: str, incident_id: int) -> dict[str, Any]:
        data = await self._call(INCIDENT_GET, path_vars={"key": f"{instance}:{incident_id}"})
        return data if isinstance(data, dict) else {}

    async def feed(self, after: int, limit: int = 100) -> dict[str, Any]:
        data = await self._call(FEED, query={"after": after, "limit": limit})
        return data if isinstance(data, dict) else {}

    async def inventory(self, body: InventorySync) -> dict[str, Any]:
        data = await self._call(INVENTORY, body=body)
        return data if isinstance(data, dict) else {}


# --------------------------------------------------------------------------- observations


@dataclass(slots=True)
class Observed:
    entities: dict[str, InventoryEntity]
    relations: list[Relation]


def _mac(value: object) -> str | None:
    m = str(value or "").strip().lower().replace("-", ":")
    if not MAC_RE.fullmatch(m) or m in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return m


def _locally_administered(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 0x02)


def _unifi_kind(data: Mapping[str, Any]) -> str | None:
    features = {str(f).lower() for f in data.get("features") or []}
    if "gateway" in features:
        return "unifi-gateway"
    if "accesspoint" in features:
        return "unifi-ap"
    if "switching" in features:
        return "unifi-switch"
    return None


def observe(s: Session, now: datetime | None = None) -> Observed:
    """atlas's infrastructure as CMDB entities and relations (machines + UniFi devices)."""
    from homelab_atlas.web.views import INTERNAL_IFACE_RE, machines, short_name  # noqa: PLC0415

    when = (now or utcnow()).isoformat()
    ents = {e.key: e for e in s.scalars(select(Entity)) if e.status != "gone"}
    twins: dict[str, list[str]] = defaultdict(list)
    for e in ents.values():
        if e.same_as and e.same_as in ents:
            twins[e.same_as].append(e.key)
    facets: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for f in s.scalars(select(Facet)):
        facets[f.entity_key][f.collector] = f.data

    def macs_for(key: str) -> list[str]:
        out: list[str] = []
        for k in (key, *twins.get(key, [])):
            fc = facets.get(k, {})
            for n in (fc.get("proxmox") or {}).get("nics") or []:
                if (m := _mac(n.get("mac"))) and m not in out:
                    out.append(m)
            for i in (fc.get("linux-ssh") or {}).get("interfaces") or []:
                name = str(i.get("name") or "")
                m = _mac(i.get("mac"))
                if (
                    not m
                    or name == "lo"
                    or INTERNAL_IFACE_RE.match(name)
                    or _locally_administered(m)
                ):
                    continue
                if m not in out:
                    out.append(m)
            for src in ("nas", "reconcile"):
                if (m := _mac((fc.get(src) or {}).get("mac"))) and m not in out:
                    out.append(m)
        return out[:16]

    out: dict[str, InventoryEntity] = {}
    relations: list[Relation] = []
    names: dict[str, str] = {}  # UniFi device name -> key, for uplinks
    for key, e in ents.items():
        if e.kind != "unifi-device":
            continue
        d = facets.get(key, {}).get("unifi") or {}
        kind = _unifi_kind(d)
        if kind is None:
            continue
        name = str(d.get("name") or e.display_name)[:200]
        names[name.lower()] = key
        out[key] = InventoryEntity(
            key=key,
            name=name,
            kind=kind,
            ips=[str(d["ip"])] if d.get("ip") else [],
            macs=[mac] if (mac := _mac(d.get("mac"))) else [],
            status="online" if str(d.get("state") or "").upper() == "ONLINE" else "offline",
            manufacturer="Ubiquiti",
            model=str(d.get("model"))[:120] if d.get("model") else None,
            os=f"UniFi {d['firmware']}"[:120] if d.get("firmware") else None,
            observedAt=when,
        )
        if (up := _mac(d.get("uplink_mac"))) and f"unifi:dev:{up}" in ents:
            relations.append(
                Relation.model_validate(
                    {"from": key, "to": f"unifi:dev:{up}", "type": "connected_to"}
                )
            )

    for m in machines(s):
        key = m["key"]
        if (facets.get(key, {}).get("proxmox") or {}).get("template"):
            continue  # a Proxmox template is not a machine
        node = m.get("node")
        cluster = (
            key.split(":")[2].split("/")[0]
            if key.startswith("pve:") and key.count(":") >= 2
            else None
        )
        raw_status = str(m.get("status") or "unknown")
        status: Literal["running", "stopped", "online", "offline", "unknown"] = (
            raw_status if raw_status in ("running", "stopped", "online", "offline") else "unknown"  # type: ignore[assignment]
        )
        lx_os = None
        for k in (key, *twins.get(key, [])):
            lx_os = lx_os or ((facets.get(k, {}).get("linux-ssh") or {}).get("os") or {}).get(
                "hostname"
            )
        name = short_name(m["name"])[:200]
        out[key] = InventoryEntity(
            key=key,
            name=name,
            kind=m["kind"],
            hostname=(lx_os or name)[:255],
            ips=[ip for ip in m.get("ips") or [] if ":" not in ip][:16],
            macs=macs_for(key),
            pveCluster=cluster[:64] if cluster else None,
            pveNode=str(node)[:64] if node else None,
            vmid=m["vmid"] if isinstance(m.get("vmid"), int) and m["vmid"] > 0 else None,
            network=str(m["network"])[:64] if m.get("network") else None,
            vlan=m["vlan"] if isinstance(m.get("vlan"), int) and 0 <= m["vlan"] <= 4094 else None,
            uplink=str(m["uplink"])[:128] if m.get("uplink") else None,
            status=status,
            os=str(m["os"])[:120] if m.get("os") else None,
            observedAt=when,
            apps=[
                {"name": str(a["name"])[:120]}
                for a in m.get("apps") or []
                if a.get("category") != "system"
            ][:80],
        )
        parent = ents[key].parent_key if key in ents else None
        if parent and parent in ents and ents[parent].kind == "pve-node":
            relations.append(
                Relation.model_validate({"from": key, "to": parent, "type": "hosted_on"})
            )
        uplink = str(m.get("uplink") or "")
        if uplink:
            dev, _, port = uplink.partition(" · ")
            to = names.get(dev.strip().lower())
            if to:
                relations.append(
                    Relation.model_validate(
                        {
                            "from": key,
                            "to": to,
                            "type": "connected_to",
                            "detail": port.strip()[:120] or None,
                        }
                    )
                )
    keys = set(out)
    return Observed(out, [r for r in relations if r.from_ in keys and r.to in keys][:2000])


def incident_entity(s: Session, inv: Inventory, inc: Incident) -> str | None:
    """The machine an incident is about, as a CMDB entity key (machine cards' keys)."""
    target: str | None = None
    if inc.kind.startswith("media.") and inc.entity_key and inc.entity_key.startswith("jellyfin:"):
        src = next(
            (x for x in inv.sources.jellyfin if x.name == inc.entity_key.split(":", 1)[1]), None
        )
        target = media.jellyfin_host(inv, src) if src is not None else None
    elif inc.kind == "host.unreachable":
        target = inc.key.split(":", 1)[1]
    key = inc.entity_key
    if target is not None:
        f = s.scalars(
            select(Facet).where(Facet.collector == "linux-ssh", Facet.target == target).limit(1)
        ).first()
        key = f.entity_key if f is not None else None
    if key is None:
        return None
    e = s.get(Entity, key)
    if e is not None and e.same_as and s.get(Entity, e.same_as) is not None:
        return e.same_as
    return key


# --------------------------------------------------------------------------- staging


def _state(s: Session) -> TaskoraState:
    st = s.get(TaskoraState, 1)
    if st is None:
        st = TaskoraState(id=1, feed_cursor=0)
        s.add(st)
        s.flush()
    return st


def build_event(  # noqa: PLR0917 - one call site per flow, all arguments required
    s: Session,
    inv: Inventory,
    inc: Incident,
    link: TaskoraLink,
    settings: TaskoraSettings,
    observed: Mapping[str, InventoryEntity],
    atlas_url: str | None,
) -> IncidentEvent:
    key = incident_entity(s, inv, inc)
    ent = observed.get(key) if key else None
    ref = (
        EntityRef.model_validate(ent.model_dump(include=set(EntityRef.model_fields)))
        if ent
        else None
    )
    resolved = inc.resolved_at is not None
    atlas_ack = inc.acknowledged_at is not None and link.ack_source != "taskora"
    keys = [k for k in (key, inc.entity_key) if k]
    changes = (
        [
            f"{e.created_at:%Y-%m-%d %H:%M} {e.summary}"[:300]
            for e in s.scalars(
                select(Event)
                .where(Event.entity_key.in_(keys), Event.severity.in_(("warning", "notice")))
                .order_by(Event.id.desc())
                .limit(10)
            )
        ]
        if keys
        else []
    )
    where = f" on {ref.name}" if ref else ""
    return IncidentEvent(
        instance=settings.instance,
        incidentId=inc.id,
        revision=max(1, link.revision),
        fingerprint=inc.key[:128],
        kind=inc.kind[:48],
        title=inc.title[:250],
        summary=f"atlas has observed this{where} since {inc.opened_at:%Y-%m-%d %H:%M} UTC.",
        severity=inc.severity if inc.severity in ("info", "notice", "warning") else "warning",  # type: ignore[arg-type]
        state="resolved" if resolved else ("acknowledged" if atlas_ack else "open"),
        persisting=bool(link.persisting) and not resolved,
        firstObservedAt=inc.opened_at.isoformat(),
        lastObservedAt=inc.last_seen_at.isoformat(),
        resolvedAt=inc.resolved_at.isoformat() if inc.resolved_at else None,
        acknowledgedBy=(inc.acknowledged_by or "")[:64] or None if atlas_ack else None,
        entity=_plain(ref) if ref else None,
        evidence=[str(e)[:400] for e in inc.evidence or []][:20],
        recentChanges=changes,
        link=f"{atlas_url.rstrip('/')}/incidents" if atlas_url else None,
    )


def digest(ev: IncidentEvent) -> str:
    """What makes a new revision worth sending (not the heartbeat, not context)."""
    keep = ev.model_dump(exclude={"revision", "lastObservedAt", "recentChanges", "summary"})
    return hashlib.sha256(json.dumps(keep, sort_keys=True, default=str).encode()).hexdigest()


def stage(
    s: Session,
    inv: Inventory,
    settings: TaskoraSettings,
    *,
    atlas_url: str | None = None,
    now: datetime | None = None,
) -> int:
    """Bump the revision of every incident whose meaningful state changed. Returns how many.

    New incidents are considered once they have lasted SEND_AFTER; resolved incidents only if
    Taskora already knows them (no ticket for something that ended before it was sent)."""
    now = now or utcnow()
    links = {lk.incident_id: lk for lk in s.scalars(select(TaskoraLink))}
    # Rules with "create a ticket" off (ADR-047); incidents already linked keep updating.
    no_ticket = {r.id for r in alerts.load_rules() if not r.ticket}
    candidates = [
        i
        for i in s.scalars(
            select(Incident).where(
                (Incident.resolved_at.is_(None)) | (Incident.resolved_at >= now - KEEP_RESOLVED)
            )
        )
        if (i.id in links)
        or (
            i.resolved_at is None
            and now - i.opened_at >= SEND_AFTER
            and i.key.split(":", 1)[0] not in no_ticket
        )
    ]
    if not candidates:
        return 0
    observed = observe(s, now).entities
    bumped = 0
    for inc in candidates:
        link = links.get(inc.id)
        if link is None:
            link = TaskoraLink(incident_id=inc.id, revision=0, sent_revision=0)
            s.add(link)
        if inc.resolved_at is not None and link.revision == 0:
            continue
        ev = build_event(s, inv, inc, link, settings, observed, atlas_url)
        d = digest(ev)
        if d != link.digest:
            link.revision += 1
            link.digest = d
            link.attempts = 0
            link.next_attempt_at = now
            link.error_kind = None
            link.last_error = None
            bumped += 1
    return bumped


# --------------------------------------------------------------------------- delivery


def backoff(attempts: int, rng: random.Random | None = None) -> timedelta:
    base = min(BACKOFF_MAX_S, 30 * 2 ** max(0, attempts - 1))
    jitter = (rng or random).uniform(0.8, 1.2)
    return timedelta(seconds=base * jitter)


def _remember_ticket(link: TaskoraLink, raw: object, now: datetime) -> None:
    try:
        t = TicketSnapshot.model_validate(raw)
    except ValidationError:
        return
    if not TICKET_PATH_RE.fullmatch(t.path):
        return
    link.ticket_id, link.ticket_number, link.ticket_path = t.id, t.number, t.path
    link.ticket_status, link.ticket_category = t.status, t.statusCategory
    link.ticket_priority, link.ticket_assignee = t.priority or None, t.assignee
    link.synced_at = now


def _persisting(inc: Incident, link: TaskoraLink) -> None:
    """A ticket resolved by a person while atlas still sees the problem: say so once."""
    if inc.resolved_at is None and link.ticket_category in ("resolved", "closed"):
        link.persisting = True
    elif link.ticket_category in ("new", "open", "waiting") or inc.resolved_at is not None:
        link.persisting = False


async def deliver(
    s: Session,
    inv: Inventory,
    client: TaskoraClient,
    *,
    atlas_url: str | None = None,
    now: datetime | None = None,
) -> tuple[int, int]:
    """Send due revisions, oldest first. Returns (delivered, failed). The caller commits."""
    now = now or utcnow()
    due = list(
        s.scalars(
            select(TaskoraLink)
            .where(TaskoraLink.sent_revision < TaskoraLink.revision)
            .where((TaskoraLink.next_attempt_at.is_(None)) | (TaskoraLink.next_attempt_at <= now))
            .order_by(TaskoraLink.incident_id)
            .limit(PER_TICK)
        )
    )
    if not due:
        return 0, 0
    observed = observe(s, now).entities
    st = _state(s)
    ok = failed = 0
    for link in due:
        inc = s.get(Incident, link.incident_id)
        if inc is None:
            link.sent_revision = link.revision  # incident gone (retention): nothing to send
            continue
        ev = build_event(s, inv, inc, link, client.settings, observed, atlas_url)
        try:
            res = await client.upsert(ev)
        except TaskoraError as exc:
            failed += 1
            link.attempts += 1
            link.error_kind = exc.kind
            link.last_error = str(exc)[:256]
            if exc.kind == "retry":
                link.next_attempt_at = now + backoff(link.attempts)
            elif exc.kind == "config":
                link.next_attempt_at = now + CONFIG_RETRY
            else:
                link.next_attempt_at = None  # held until the next revision or a manual retry
                link.sent_revision = link.revision
            st.last_error = link.last_error
            if exc.kind != "permanent":
                break  # Taskora down or misconfigured: keep order, try again later
            continue
        ok += 1
        link.sent_revision = ev.revision
        link.attempts = 0
        link.error_kind = link.last_error = None
        link.next_attempt_at = None
        link.delivered_at = now
        _remember_ticket(link, res.get("ticket"), now)
        # A ticket resolved while atlas still sees the problem changes `persisting`, hence the
        # digest: the next stage() sends "still failing" (or that it stopped).
        _persisting(inc, link)
        st.last_ok_at, st.last_error = now, None
        if inc.resolved_at is None and res.get("ticket") is None:
            # Accepted, but no ticket (automatic creation off in Taskora, or the ticket was
            # deleted): say why, and send it again later; Taskora 0.3.3+ then creates it.
            why = re.sub(r"[^\w .,:;()'/-]", "", str(res.get("note") or ""))[:160]
            link.ticket_id = link.ticket_number = link.ticket_path = None
            link.sent_revision = ev.revision - 1
            link.error_kind = "config"
            link.last_error = f"Taskora created no ticket{f': {why}' if why else ''}"[:256]
            link.next_attempt_at = now + CONFIG_RETRY
            st.last_error = link.last_error
    return ok, failed


def retry_held(s: Session, now: datetime | None = None) -> int:
    """Owner's "Retry now": every held or waiting delivery becomes due again."""
    now = now or utcnow()
    n = 0
    for link in s.scalars(select(TaskoraLink).where(TaskoraLink.error_kind.is_not(None))):
        if link.error_kind == "permanent":
            link.sent_revision = max(0, link.revision - 1)
        link.next_attempt_at, link.attempts = now, 0
        n += 1
    return n


def replay_all(s: Session, now: datetime | None = None) -> int:
    """Re-send the current state of every linked incident (after a Taskora restore). Safe:
    Taskora ignores revisions it already has, so only what it lost is applied."""
    now = now or utcnow()
    n = 0
    for link in s.scalars(select(TaskoraLink).where(TaskoraLink.revision > 0)):
        link.sent_revision = link.revision - 1
        link.next_attempt_at, link.attempts, link.error_kind = now, 0, None
        n += 1
    return n


# --------------------------------------------------------------------------- feed

ACK_TYPES: Final = frozenset({"assigned", "status_changed"})


def apply_feed(s: Session, settings: TaskoraSettings, events: Iterable[Any], now: datetime) -> int:
    """Technician activity → incident acknowledgement and ticket state. Returns how many
    events concerned this atlas's incidents."""
    n = 0
    for raw in events:
        if not isinstance(raw, dict):
            continue
        key = str(raw.get("externalKey") or "")
        instance, _, ident = key.partition(":")
        if instance != settings.instance or not ident.isdigit():
            continue
        link = s.get(TaskoraLink, int(ident))
        inc = s.get(Incident, int(ident))
        if link is None or inc is None:
            continue
        n += 1
        _remember_ticket(link, raw.get("ticket"), now)
        human = not raw.get("automation") and str(raw.get("actor") or "") not in ("", "Automation")
        moved = raw.get("type") == "assigned" or link.ticket_category not in (None, "new")
        if (
            human
            and raw.get("type") in ACK_TYPES
            and moved
            and inc.resolved_at is None
            and inc.acknowledged_at is None
        ):
            actor = re.sub(r"[^\w .@'-]", "", str(raw.get("actor")))[:50]
            inc.acknowledged_at, inc.acknowledged_by = now, f"Taskora: {actor}"[:64]
            link.ack_source = "taskora"
        _persisting(inc, link)  # restaged by the digest when it changed
    return n


async def poll_feed(s: Session, client: TaskoraClient, now: datetime | None = None) -> int:
    now = now or utcnow()
    st = _state(s)
    seen = 0
    for _ in range(FEED_PAGES):
        data = await client.feed(st.feed_cursor or 0)
        events = data.get("events")
        cursor = data.get("nextCursor")
        if (
            not isinstance(events, list)
            or not isinstance(cursor, int)
            or cursor < (st.feed_cursor or 0)
        ):
            raise TaskoraError("retry", "unexpected ticket-events answer")
        seen += apply_feed(s, client.settings, events, now)
        st.feed_cursor = cursor
        st.last_feed_at = now
        if not data.get("more"):
            break
    return seen


# --------------------------------------------------------------------------- inventory


def inventory_body(
    s: Session, settings: TaskoraSettings, mode: Literal["preview", "apply"]
) -> InventorySync:
    obs = observe(s)
    ents = sorted(
        obs.entities.values(),
        key=lambda e: CMDB_KINDS.index(e.kind) if e.kind in CMDB_KINDS else 99,
    )
    return InventorySync(
        instance=settings.instance,
        mode=mode,
        complete=len(ents) <= 500,
        entities=[_plain(e) for e in ents[:500]],
        relations=[_plain(r) for r in obs.relations],
    )


async def inventory_sync(
    s: Session,
    client: TaskoraClient,
    mode: Literal["preview", "apply"],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Send the inventory; remember the result for the Integrations page."""
    now = now or utcnow()
    res = await client.inventory(inventory_body(s, client.settings, mode))
    plan = [
        {k: str(p.get(k) or "")[:200] for k in ("key", "name", "action", "ciNumber", "note")}
        for p in (res.get("plan") or [])[:500]
        if isinstance(p, dict)
    ]
    stats = {str(k)[:32]: int(v) for k, v in (res.get("stats") or {}).items() if isinstance(v, int)}
    st = _state(s)
    # What Taskora actually did: an "apply" is only a preview while its CMDB mode is off.
    done = res.get("mode")
    st.inventory_at = now
    st.inventory_mode = done if done in ("preview", "apply") else mode
    st.inventory_result = {
        "stats": stats,
        "plan": plan,
        "cmdbMode": str(res.get("cmdbMode") or "")[:32],
    }
    st.last_ok_at = now
    return st.inventory_result


# --------------------------------------------------------------------------- one tick


async def tick(
    s: Session,
    inv: Inventory,
    client: TaskoraClient,
    *,
    atlas_url: str | None = None,
    now: datetime | None = None,
) -> dict[str, int]:
    """Stage, deliver, read the feed. Commits as it goes; never raises TaskoraError."""
    now = now or utcnow()
    out = {"staged": 0, "delivered": 0, "failed": 0, "feed": 0}
    _state(s).last_tick_at = now
    s.commit()
    if client.settings.incidents:
        out["staged"] = stage(s, inv, client.settings, atlas_url=atlas_url, now=now)
        s.commit()
        out["delivered"], out["failed"] = await deliver(
            s, inv, client, atlas_url=atlas_url, now=now
        )
        s.commit()
    if s.scalars(select(TaskoraLink).limit(1)).first() is not None:
        try:
            out["feed"] = await poll_feed(s, client, now)
        except TaskoraError as exc:
            _state(s).last_error = str(exc)[:256]
        s.commit()
        if client.settings.incidents:  # what the feed changed (persisting) goes out next tick
            stage(s, inv, client.settings, atlas_url=atlas_url, now=now)
            s.commit()
    if client.settings.cmdb_auto:
        out["inventory"] = await _auto_inventory(s, client, now)
    return out


async def _auto_inventory(s: Session, client: TaskoraClient, now: datetime) -> int:
    """Apply a complete inventory sync once after each finished scan. A failure waits for
    the next scan (no retry storm); the Integrations page shows it."""
    st = _state(s)
    last = s.scalar(select(func.max(Scan.finished_at)).where(Scan.status == "done"))
    if last is None or (st.inventory_at is not None and st.inventory_at >= last):
        return 0
    try:
        await inventory_sync(s, client, "apply", now)
    except TaskoraError as exc:
        st.inventory_at, st.inventory_mode = now, "failed"
        st.last_error = f"inventory: {exc}"[:256]
        s.commit()
        return 0
    s.commit()
    return 1


def status(s: Session) -> dict[str, Any]:
    """Integrations / Incidents pages: delivery state per incident and overall."""
    st = s.get(TaskoraState, 1)
    rows: list[dict[str, Any]] = []
    for link, inc in s.execute(
        select(TaskoraLink, Incident)
        .join(Incident, Incident.id == TaskoraLink.incident_id)
        .order_by(Incident.id.desc())
        .limit(50)
    ).all():
        rows.append(
            {
                "incident": inc,
                "link": link,
                "pending": link.sent_revision < link.revision,
            }
        )
    waiting = [
        i
        for i in s.scalars(select(Incident).where(Incident.resolved_at.is_(None)))
        if i.id not in {r["link"].incident_id for r in rows}
    ]
    return {
        "state": st,
        "open_unsent": waiting,
        "send_after_min": int(SEND_AFTER.total_seconds() // 60),
        "links": rows,
        "pending": sum(1 for r in rows if r["pending"]),
        "failing": sum(1 for r in rows if r["link"].error_kind),
    }


def links_by_incident(s: Session, ids: Iterable[int]) -> dict[int, TaskoraLink]:
    wanted = list(ids)
    if not wanted:
        return {}
    return {
        lk.incident_id: lk
        for lk in s.scalars(select(TaskoraLink).where(TaskoraLink.incident_id.in_(wanted)))
    }
