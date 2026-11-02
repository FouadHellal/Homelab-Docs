"""Optional notifications to an n8n webhook (ADR-040).

n8n is an automation layer, never a source of truth: atlas works the same without it. The
only data atlas sends out is a fixed, typed payload (incident opened/resolved, daily summary,
diagnostic request) built from already-redacted facts and redacted once more here. It goes
through the same ReadOnlyHttpClient as everything else: one POST endpoint, the exact webhook
path, a typed body, timeouts, the audit log; no redirects, no other URL.

Configuration (environment, nothing in the browser):
    ATLAS_N8N_WEBHOOK_URL        https://n8n.lan:5678/webhook/atlas  (or http://<LAN IP>/...)
    ATLAS_N8N_ALLOW_HTTP=1       needed for plain http://, private LAN IPs only
    ATLAS_N8N_CA_FILE            PEM anchor for a self-signed https n8n (in the config dir);
                                 without it, https uses public CAs for that host name only
    secret `n8n_webhook_token`   sent as `Authorization: Bearer <token>` (n8n "Header Auth")
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from homelab_atlas.redact import Redactor
from homelab_atlas.security.allowlist import Endpoint
from homelab_atlas.security.audit import AuditSink
from homelab_atlas.security.errors import (
    HttpStatusError,
    SecurityRefusal,
    TransportError,
)
from homelab_atlas.security.http import (
    AuthHeader,
    HttpLimits,
    ReadOnlyHttpClient,
    TlsPolicy,
    lan_ip_literal,
)

TOKEN_SECRET: Final = "n8n_webhook_token"  # noqa: S105 - a secret *name*, not a value
WEBHOOK_PATH_RE: Final = re.compile(r"/webhook(-test)?/[A-Za-z0-9_-]{1,128}")
LIMITS: Final = HttpLimits(connect_s=5.0, read_s=10.0, total_s=15.0, max_bytes=64 * 1024)
NotificationKind = Literal[
    "incident.opened", "incident.resolved", "summary.daily", "diagnostic.requested", "test"
]


class Notification(BaseModel):
    """The one shape atlas ever sends. Strings are capped; evidence is a short list."""

    model_config = ConfigDict(extra="forbid")
    source: Literal["atlas"] = "atlas"
    kind: NotificationKind
    title: str = Field(max_length=256)
    severity: Literal["info", "notice", "warning"] = "info"
    key: str | None = Field(default=None, max_length=128)
    entity: str | None = Field(default=None, max_length=256)
    opened_at: str | None = None
    resolved_at: str | None = None
    evidence: list[str] = Field(default_factory=list, max_length=20)
    summary: dict[str, int | str] = Field(default_factory=dict)
    link: str | None = Field(default=None, max_length=512)


@dataclass(frozen=True, slots=True)
class WebhookConfig:
    url: str
    allow_http: bool = False
    ca_file: Path | None = None

    @property
    def path(self) -> str:
        return urlsplit(self.url).path


SETTINGS_FILE: Final = "n8n.yaml"


def webhook_settings(data_dir: Path | None) -> WebhookConfig | None:
    """The webhook saved from the Integrations page (`<data dir>/n8n.yaml`), if any."""
    if data_dir is None:
        return None
    path = data_dir / SETTINGS_FILE
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("url"), str):
        return None
    allow = "1" if raw.get("allow_http") else ""
    return webhook_from_env({"ATLAS_N8N_WEBHOOK_URL": raw["url"], "ATLAS_N8N_ALLOW_HTTP": allow})


def save_webhook_settings(data_dir: Path, url: str, allow_http: bool) -> WebhookConfig:
    """Validate and store the webhook URL (never the token: that goes to the vault)."""
    allow = "1" if allow_http else ""
    cfg = webhook_from_env({"ATLAS_N8N_WEBHOOK_URL": url, "ATLAS_N8N_ALLOW_HTTP": allow})
    if cfg is None:
        raise ValueError("enter the n8n webhook URL")
    host = urlsplit(cfg.url).hostname or ""
    if cfg.url.startswith("http://") and not (allow_http and lan_ip_literal(host)):
        raise ValueError("http:// only to a private LAN IP, with “plain HTTP on my LAN” ticked")
    data_dir.mkdir(parents=True, exist_ok=True)
    tmp = data_dir / f".{SETTINGS_FILE}.tmp"
    body = yaml.safe_dump({"url": cfg.url, "allow_http": cfg.allow_http})
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(data_dir / SETTINGS_FILE)
    return cfg


def webhook_from_env(
    env: Mapping[str, str], config_dirs: Sequence[Path] = ()
) -> WebhookConfig | None:
    url = env.get("ATLAS_N8N_WEBHOOK_URL", "").strip()
    if not url:
        return None
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.query or parts.username:
        raise ValueError("ATLAS_N8N_WEBHOOK_URL must be http(s)://host[:port]/webhook/<path>")
    if not WEBHOOK_PATH_RE.fullmatch(parts.path):
        raise ValueError("ATLAS_N8N_WEBHOOK_URL path must be /webhook/<name> (n8n production URL)")
    ca = env.get("ATLAS_N8N_CA_FILE", "").strip()
    ca_path = None
    if ca:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", ca):
            raise ValueError("ATLAS_N8N_CA_FILE: a file name in the config dir")
        ca_path = next((d / ca for d in config_dirs if (d / ca).is_file()), None)
        if ca_path is None:
            raise ValueError(f"ATLAS_N8N_CA_FILE {ca} not found")
    return WebhookConfig(url, env.get("ATLAS_N8N_ALLOW_HTTP", "") in ("1", "true", "yes"), ca_path)


class WebhookNotifier:
    """POSTs `Notification`s to one n8n webhook. Never raises: returns (ok, message)."""

    def __init__(
        self,
        cfg: WebhookConfig,
        token: SecretStr | None,
        audit: AuditSink,
        redactor: Redactor | None = None,
        transport: object | None = None,
    ) -> None:
        self.cfg = cfg
        self._token = token
        self._audit = audit
        self._redactor = redactor
        self._transport = transport
        self.endpoint = Endpoint(
            "n8n.webhook",
            "POST",
            cfg.path,
            body_model=Notification,
            read_only_justification=(
                "Outbound notification to the owner's own n8n: a fixed, typed, redacted "
                "payload to one configured webhook. Changes nothing on any monitored target."
            ),
        )

    @property
    def has_token(self) -> bool:
        return self._token is not None

    def _client(self) -> ReadOnlyHttpClient:
        parts = urlsplit(self.cfg.url)
        base = f"{parts.scheme}://{parts.netloc}"
        tls = None
        public_host = None
        if parts.scheme == "https":
            if self.cfg.ca_file is not None:
                tls = TlsPolicy(ca_file=self.cfg.ca_file)  # pinned anchor (self-signed n8n)
            else:
                # A normal public certificate (e.g. Let's Encrypt behind a reverse proxy):
                # public CAs for this one configured host name, host name checked (ADR-040).
                tls = TlsPolicy(ca_file=None, public_pki=True)
                public_host = parts.hostname
        return ReadOnlyHttpClient(
            target="n8n",
            base_url=base,
            endpoints={self.endpoint},
            audit=self._audit,
            tls=tls,
            auth=AuthHeader("Authorization", SecretStr(f"Bearer {self._token.get_secret_value()}"))
            if self._token is not None
            else None,
            limits=LIMITS,
            transport=self._transport,  # type: ignore[arg-type]
            plain_http_lan=self.cfg.allow_http,
            public_pki_host=public_host,
        )

    async def send(self, note: Notification) -> tuple[bool, str]:
        if self._redactor is not None:
            note = note.model_copy(
                update={
                    "title": self._redactor.text(note.title),
                    "evidence": [self._redactor.text(e) for e in note.evidence],
                }
            )
        try:
            async with self._client() as client:
                res = await client.post(self.endpoint, note)
        except SecurityRefusal as exc:
            return False, f"refused: {exc.reason.value} {exc.detail or ''}".strip()[:200]
        except HttpStatusError as exc:
            hint = (
                " (token refused?)"
                if exc.status in (401, 403)
                else (" (webhook not active? publish the workflow)" if exc.status == 404 else "")
            )
            return False, f"n8n answered HTTP {exc.status}{hint}"
        except TransportError as exc:
            return False, f"n8n unreachable: {exc}"[:200]
        return True, f"delivered (HTTP {res.status})"
