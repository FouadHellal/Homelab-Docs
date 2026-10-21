"""FastAPI app: server-rendered pages + HTMX partials (ADR-013).

Security model: every route except /login and /static requires a session; every
state-changing request needs the session's CSRF token (header or form field) and a
same-origin Origin header when one is sent; responses carry a strict nonce CSP. Templates
autoescape and never mark target data safe (a test greps for `|safe`).
"""

import hashlib
import io
import platform
import re
import secrets
import time
import zipfile
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Annotated, Any, Final
from urllib.parse import quote, urlencode, urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import SecretStr, ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from homelab_atlas import __version__
from homelab_atlas.engine import apps
from homelab_atlas.export import build as export_build
from homelab_atlas.export.build import csv_table
from homelab_atlas.inventory import annotations as ann
from homelab_atlas.inventory.managed import SourceKind
from homelab_atlas.scheduler import Scheduler
from homelab_atlas.security.audit import verify as audit_verify
from homelab_atlas.security.errors import HttpStatusError, SecurityRefusal, TransportError
from homelab_atlas.store.tables import Annotation, CollectorRun, Entity, Event, Facet, Scan
from homelab_atlas.store.tables import User as UserRow
from homelab_atlas.web import auth, queries, topology, views
from homelab_atlas.web.targets import (
    HOST_COLLECTORS,
    HOST_TYPES,
    HostForm,
    SourceForm,
    TargetError,
    TargetsService,
    host_form_from,
    source_form_from,
)

SESSION_COOKIE: Final = "__Host-atlas"
LOGIN_COOKIE: Final = "__Host-atlas-login"
LOGIN_RATE: Final = (20, 600.0)  # attempts per window (seconds) per client address
PKG: Final = files("homelab_atlas.web")
#: cytoscape.min.js 3.34.4 injects one fixed <style> element; allow exactly that, nothing else.
CYTOSCAPE_STYLE_HASH: Final = "'sha256-pgvDUBa4IjFA2yuSJ2cqcyxmNYJMborsd0ORcRv9vw8='"


@dataclass(slots=True)
class WebConfig:
    sessions: Callable[[], Session]
    annotations_dir: Path
    allowed_hosts: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    hsts: bool = False  # set when served behind a TLS reverse proxy
    lab: bool = False
    #: Periodic scans + "Scan now"; None = read-only viewer (scans run via `atlas scan`).
    scheduler: Scheduler | None = None
    #: Start the periodic jobs (else the scheduler only serves "Scan now").
    schedule: bool = True
    #: Targets page (ADR-025); None hides it.
    targets: TargetsService | None = None
    #: First-run setup (ADR-026): while no account exists, /setup creates one with this token.
    setup_token_file: Path | None = None
    #: Connection test for one API source: (kind, name) -> (ok, message).
    source_tester: Callable[[str, str], Awaitable[tuple[bool, str]]] | None = None
    #: Quick SSH login test for one host: name -> (ok, message).
    tester: Callable[[str], Awaitable[tuple[bool, str]]] | None = None
    #: Data directory (Diagnostics: database size, audit log check).
    data_dir: Path | None = None
    #: Key for --sanitize style pseudonymised exports from the Exports page (None: not offered).
    export_key: bytes | None = None


class LoginThrottle:
    def __init__(self, limit: int, window: float) -> None:
        self.limit, self.window = limit, window
        self.hits: dict[str, deque[float]] = {}

    def allow(self, who: str) -> bool:
        now = time.monotonic()
        q = self.hits.setdefault(who, deque())
        while q and q[0] < now - self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


def csp(nonce: str) -> str:
    return "; ".join(
        [
            "default-src 'none'",
            f"script-src 'self' 'nonce-{nonce}'",
            f"style-src 'self' {CYTOSCAPE_STYLE_HASH}",
            "img-src 'self' data:",
            "connect-src 'self'",
            "font-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "object-src 'none'",
        ]
    )


def safe_next(target: str | None) -> str:
    """Only local absolute paths: no scheme, host, protocol-relative or backslash tricks."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return "/"
    parts = urlsplit(target)
    return "/" if parts.scheme or parts.netloc else target


PALETTE_PAGES: Final = (
    ("/", "Dashboard"),
    ("/topology", "Topology: Proxmox"),
    ("/topology?view=physical", "Topology: network"),
    ("/topology?view=vlan", "Topology: VLANs"),
    ("/entities", "Inventory"),
    ("/services", "Services"),
    ("/services?state=failed", "Failed services"),
    ("/running", "Apps"),
    ("/ips", "IP addresses"),
    ("/vlans", "VLANs"),
    ("/ports", "Ports"),
    ("/unknown", "Unknown devices"),
    ("/changes", "Changes"),
    ("/targets", "Targets"),
    ("/targets/host", "Add a VM / host"),
    ("/exports", "Exports"),
    ("/diagnostics", "Diagnostics"),
    ("/docs", "Documentation"),
)


EXPORT_FORMATS: Final = ("md", "json", "csv", "mermaid")


def _finalize(value: Any) -> Any:
    """How bare values print in templates: no "None", "True" or "False" on any page."""
    if value is None:
        return ""
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return value


def _asset_version(static: Traversable) -> str:
    h = hashlib.sha256()
    for f in sorted((x for x in static.iterdir() if x.is_file()), key=lambda x: x.name):
        h.update(f.name.encode())
        h.update(f.read_bytes())
    return h.hexdigest()[:10]


def _ago(when: datetime | None, now: datetime | None = None) -> str:
    """'3 min ago' for a UTC timestamp (naive values from SQLite are UTC)."""
    if when is None:
        return "never"
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    secs = int(((now or datetime.now(UTC)) - when).total_seconds())
    if secs < 60:
        return "just now"
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if secs >= size:
            return f"{secs // size} {unit} ago"
    return "just now"  # pragma: no cover - unreachable


def _safe_error(exc: Exception) -> str:
    """Errors from the security layer are already secret-free; keep them short."""
    if isinstance(exc, SecurityRefusal):
        return f"refused: {exc.reason.value}"
    return str(exc)[:200] or type(exc).__name__


def create_app(cfg: WebConfig) -> FastAPI:
    templates = Jinja2Templates(directory=str(PKG / "templates"))
    templates.env.autoescape = True
    templates.env.globals["version"] = __version__
    # Cache-busting token for /static URLs: changes whenever an asset changes, so a browser
    # never keeps an old app.js/topology.js after an update.
    templates.env.globals["asset_v"] = _asset_version(PKG / "static")
    templates.env.filters["ago"] = _ago
    templates.env.finalize = _finalize  # None -> "", True/False -> yes/no, everywhere
    apps.configure_custom(cfg.data_dir / apps.CUSTOM_FILE if cfg.data_dir else None)
    throttle = LoginThrottle(*LOGIN_RATE)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        with cfg.sessions() as s:
            errors = ann.sync(s, cfg.annotations_dir)
            s.commit()
        _app.state.annotation_errors = errors
        if cfg.scheduler is not None and cfg.schedule:
            cfg.scheduler.start()
        try:
            yield
        finally:
            if cfg.scheduler is not None:
                cfg.scheduler.shutdown()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.annotation_errors = []
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=cfg.allowed_hosts)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.nonce = secrets.token_urlsafe(16)
        response = await call_next(request)
        h = response.headers
        h["Content-Security-Policy"] = csp(request.state.nonce)
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = (
            "same-origin"  # no-referrer would make browsers send Origin: null on form POSTs
        )
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), usb=(), payment=()"
        if cfg.hsts:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if not request.url.path.startswith("/static/"):
            h["Cache-Control"] = "no-store"  # the inventory is sensitive (THREAT-MODEL A3)
        return response

    app.mount("/static", StaticFiles(directory=str(PKG / "static")), name="static")

    # ------------------------------------------------------------------ plumbing

    def db() -> Any:
        with cfg.sessions() as s:
            yield s
            s.commit()

    DB = Annotated[Session, Depends(db)]

    def current(request: Request, s: DB) -> auth.CurrentUser:
        user = auth.resolve(s, request.cookies.get(SESSION_COOKIE))
        if user is None:
            is_api = request.url.path.startswith("/api/")
            if request.method == "GET" and "hx-request" not in request.headers and not is_api:
                raise HTTPException(303, headers={"Location": f"/login?next={request.url.path}"})
            raise HTTPException(401, "login required")
        return user

    User = Annotated[auth.CurrentUser, Depends(current)]

    async def csrf(request: Request, user: User) -> auth.CurrentUser:
        origin = request.headers.get("origin")
        if origin is not None and urlsplit(origin).netloc != request.url.netloc:
            raise HTTPException(403, "cross-origin request")
        supplied = request.headers.get("x-csrf-token")
        if supplied is None:
            form = await request.form(max_fields=64, max_part_size=16 * 1024)
            value = form.get("csrf_token")
            supplied = value if isinstance(value, str) else None
        if not auth.csrf_ok(user.csrf, supplied):
            raise HTTPException(403, "CSRF token missing or invalid")
        return user

    Csrf = Annotated[auth.CurrentUser, Depends(csrf)]

    def page(
        request: Request, name: str, user: auth.CurrentUser | None, status: int = 200, **ctx: Any
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            name,
            {
                "user": user,
                "csrf": user.csrf if user else "",
                "nonce": request.state.nonce,
                "lab": cfg.lab,
                "path": request.url.path,
                **ctx,
            },
            status_code=status,
        )

    def partial(request: Request) -> bool:
        return request.headers.get("hx-request") == "true"

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> Response:
        """Liveness for the container healthcheck: no auth, no data, no DB."""
        return Response("ok", media_type="text/plain")

    # ------------------------------------------------------------------ auth

    def setup_open(s: Session) -> bool:
        f = cfg.setup_token_file
        return (
            f is not None
            and f.is_file()
            and not s.scalar(select(func.count()).select_from(UserRow))
        )

    def login_cookie_page(
        request: Request, name: str, status: int = 200, **ctx: Any
    ) -> HTMLResponse:
        token = secrets.token_urlsafe(32)
        resp = page(request, name, None, status, login_csrf=token, **ctx)
        resp.set_cookie(
            LOGIN_COOKIE,
            token,
            max_age=600,
            secure=True,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return resp

    @app.get("/setup", response_class=HTMLResponse)
    def setup_form(request: Request, s: DB) -> Response:
        if not setup_open(s):
            return RedirectResponse("/login", 303)
        return login_cookie_page(request, "setup.html", error=None, username="admin")

    @app.post("/setup", response_class=HTMLResponse)
    def setup_submit(
        request: Request,
        s: DB,
        setup_token: Annotated[str, Form(max_length=128)],
        username: Annotated[str, Form(max_length=64)],
        password: Annotated[str, Form(max_length=1024)],
        password2: Annotated[str, Form(max_length=1024)],
        csrf_token: Annotated[str, Form(max_length=128)],
    ) -> Response:
        if not auth.csrf_ok(request.cookies.get(LOGIN_COOKIE) or "", csrf_token):
            raise HTTPException(403, "setup CSRF token missing or invalid")
        if not setup_open(s):
            return RedirectResponse("/login", 303)
        who = request.client.host if request.client else "?"
        if not throttle.allow(who):
            raise HTTPException(429, "too many attempts")
        assert cfg.setup_token_file is not None  # noqa: S101 - setup_open checked it
        expected = cfg.setup_token_file.read_text(encoding="utf-8").strip()
        name = username.strip().lower()

        def again(msg: str, code: int) -> HTMLResponse:
            return login_cookie_page(request, "setup.html", code, error=msg, username=name)

        if not expected or not auth.csrf_ok(expected, setup_token.strip()):
            return again("setup token does not match (see the atlas startup log)", 401)
        if password != password2:
            return again("the two passwords differ", 422)
        try:
            auth.create_user(s, name, password)
        except auth.AuthError as exc:
            return again(str(exc), 422)
        s.commit()
        cfg.setup_token_file.unlink(missing_ok=True)  # one use only
        result = auth.login(s, name, password)
        resp = RedirectResponse("/targets" if cfg.targets is not None else "/", 303)
        if result.token is not None:
            resp.set_cookie(
                SESSION_COOKIE,
                result.token,
                secure=True,
                httponly=True,
                samesite="strict",
                path="/",
            )
        resp.delete_cookie(LOGIN_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return resp

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, s: DB, next: str = "/") -> Response:  # noqa: A002
        if setup_open(s):
            return RedirectResponse("/setup", 303)
        if auth.resolve(s, request.cookies.get(SESSION_COOKIE)) is not None:
            return RedirectResponse(safe_next(next), 303)
        token = secrets.token_urlsafe(32)
        resp = page(request, "login.html", None, login_csrf=token, next=safe_next(next), error=None)
        resp.set_cookie(
            LOGIN_COOKIE,
            token,
            max_age=600,
            secure=True,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return resp

    @app.post("/login", response_class=HTMLResponse)
    def login_submit(
        request: Request,
        s: DB,
        username: Annotated[str, Form(max_length=64)],
        password: Annotated[str, Form(max_length=1024)],
        csrf_token: Annotated[str, Form(max_length=128)],
        next: Annotated[str, Form(max_length=512)] = "/",  # noqa: A002
    ) -> Response:
        if not auth.csrf_ok(request.cookies.get(LOGIN_COOKIE) or "", csrf_token):
            raise HTTPException(403, "login CSRF token missing or invalid")
        who = request.client.host if request.client else "?"
        if not throttle.allow(who):
            raise HTTPException(429, "too many login attempts")
        result = auth.login(s, username.strip().lower(), password)
        if result.token is None:
            s.commit()  # persist failure counters / lockout
            token = secrets.token_urlsafe(32)
            resp = page(
                request,
                "login.html",
                None,
                401,
                login_csrf=token,
                next=safe_next(next),
                error=result.reason,
            )
            resp.set_cookie(
                LOGIN_COOKIE,
                token,
                max_age=600,
                secure=True,
                httponly=True,
                samesite="strict",
                path="/",
            )
            return resp
        ok = RedirectResponse(safe_next(next), 303)
        ok.set_cookie(
            SESSION_COOKIE, result.token, secure=True, httponly=True, samesite="strict", path="/"
        )
        ok.delete_cookie(LOGIN_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return ok

    @app.post("/logout")
    def logout(request: Request, s: DB, _user: Csrf) -> Response:
        auth.logout(s, request.cookies.get(SESSION_COOKIE))
        resp = RedirectResponse("/login", 303)
        resp.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return resp

    # ------------------------------------------------------------------ pages

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, s: DB, user: User) -> Response:
        cards = views.machines(s)
        names, addresses = _target_names()
        return page(
            request,
            "dashboard.html",
            user,
            d=queries.dashboard(s, names),
            annotation_errors=app.state.annotation_errors,
            sched=cfg.scheduler,
            scheduled=cfg.schedule,
            machines=cards,
            top_apps=views.top_apps(cards),
            health={n: queries.target_health(rs) for n, rs in queries.latest_runs(s).items()},
            target_names=names or set(),
            discovered=views.discovered_not_documented(
                s, addresses | {n.lower() for n in names or ()}
            ),
            can_add=cfg.targets is not None and cfg.targets.editable,
        )

    @app.post("/scan", response_class=HTMLResponse)
    async def scan_now(request: Request, user: Csrf) -> Response:
        """Manual full scan (same read-only engine as the schedule). Needs CSRF."""
        if cfg.scheduler is None:
            raise HTTPException(404, "scheduler disabled (start with atlas serve --schedule)")
        state = cfg.scheduler.trigger()
        if not partial(request):
            return RedirectResponse("/", 303)
        msg = "Scan started." if state == "started" else "Queued: it runs after the current scan."
        return page(
            request, "_scan_status.html", user, sched=cfg.scheduler, message=msg, status=202
        )

    @app.get("/entities", response_class=HTMLResponse)
    def entity_list(
        request: Request,
        s: DB,
        user: User,
        kind: Annotated[str | None, Query(max_length=32)] = None,
        q: Annotated[str | None, Query(max_length=64)] = None,
    ) -> Response:
        rows = queries.entities(s, kind, q)
        name = "_entity_rows.html" if partial(request) else "entities.html"
        return page(request, name, user, rows=rows, kinds=queries.kinds(s), kind=kind, q=q or "")

    @app.get("/entity", response_class=HTMLResponse)
    def entity_page(
        request: Request, s: DB, user: User, key: Annotated[str, Query(max_length=256)]
    ) -> Response:
        detail = queries.entity_detail(s, key)
        if detail is None:
            raise HTTPException(404, "no such entity")
        run = views.running(s, key) if detail["entity"].kind in views.MACHINE_KINDS else None
        has_run = run is not None and (run["services"] or run["containers"] or run["processes"])
        card = next((m for m in views.machines(s) if m["key"] == key), None)
        health = None
        if card is not None and card.get("target"):
            health = queries.target_health(queries.latest_runs(s).get(card["target"]))
        return page(
            request,
            "entity.html",
            user,
            d=detail,
            run=run if has_run else None,
            card=card,
            health=health,
            sched=cfg.scheduler,
        )

    @app.get("/ips", response_class=HTMLResponse)
    def ips(
        request: Request,
        s: DB,
        user: User,
        q: Annotated[str | None, Query(max_length=64)] = None,
        everything: bool = False,
    ) -> Response:
        groups = views.ip_groups(s, q, everything=everything)
        name = "_ip_groups_rows.html" if partial(request) else "ips.html"
        return page(request, name, user, g=groups, q=q or "", everything=everything)

    @app.get("/running", response_class=HTMLResponse)
    def running_page(
        request: Request, s: DB, user: User, q: Annotated[str | None, Query(max_length=64)] = None
    ) -> Response:
        return page(
            request,
            "running.html",
            user,
            r=views.everything_running(s, q),
            q=q or "",
            unrec=views.unrecognised_ports(s),
            rules=apps.load_rules(),
            categories=apps.CATEGORY_LABELS,
            can_name=cfg.data_dir is not None,
            msg=request.query_params.get("msg", "")[:200],
        )

    @app.post("/apps/name")
    def name_app(
        user: Csrf,
        name: Annotated[str, Form(max_length=64)],
        category: Annotated[str, Form(max_length=16)],
        kind: Annotated[str, Form(max_length=8)],
        value: Annotated[str, Form(max_length=96)],
        ports: Annotated[str, Form(max_length=64)] = "",
        machines: Annotated[str, Form(max_length=2048)] = "",
    ) -> Response:
        """Turn an unrecognised port into an app rule (ADR-034). Only atlas's own data changes."""
        if cfg.data_dir is None or kind not in ("image", "proc", "port"):
            raise HTTPException(404, "not available")
        try:
            plist = [int(p) for p in ports.split(",") if p.strip()][:8]
            rule = views.custom_rule_from(
                name=name,
                category=category,
                kind=kind,
                value=value,
                ports=plist,
                machines=[m for m in machines.split(",") if m][:32],
            )
            apps.save_rule(rule)
        except (ValueError, ValidationError) as exc:
            msg = f"Not saved: {str(exc).splitlines()[0][:150]}"
            return RedirectResponse(f"/running?msg={quote(msg)}#unrecognised", 303)
        msg = f"{rule.name} saved: it is recognised from now on, on every page"
        return RedirectResponse(f"/running?msg={quote(msg)}#unrecognised", 303)

    @app.post("/apps/forget")
    def forget_app(user: Csrf, name: Annotated[str, Form(max_length=64)]) -> Response:
        done = apps.delete_rule(name)
        msg = f"{name} removed" if done else f"{name}: no such rule"
        return RedirectResponse(f"/running?msg={quote(msg)}#yours", 303)

    ServiceFilters = tuple[str | None, str, str | None, str | None]

    def service_filters(
        machine: Annotated[str | None, Query(max_length=64)] = None,
        state: Annotated[str, Query(max_length=10)] = "running",
        kind: Annotated[str | None, Query(max_length=10)] = None,
        q: Annotated[str | None, Query(max_length=64)] = None,
    ) -> ServiceFilters:
        state = state if state in views.SERVICE_STATES else "running"
        return machine or None, state, kind if kind in ("systemd", "container") else None, q

    Filters = Annotated[ServiceFilters, Depends(service_filters)]

    @app.get("/services", response_class=HTMLResponse)
    def services_page(request: Request, s: DB, user: User, f: Filters) -> Response:
        machine, state, kind, q = f
        t = views.service_table(s, machine=machine, state=state, kind=kind, q=q)
        name = "_services_rows.html" if partial(request) else "services.html"
        query = urlencode(
            {k: v for k, v in zip(("machine", "state", "kind", "q"), f, strict=True) if v}
        )
        return page(
            request,
            name,
            user,
            t=t,
            machine=machine or "",
            state=state,
            kind=kind or "",
            q=q or "",
            query=query,
        )

    @app.get("/docs", response_class=HTMLResponse)
    def docs_page(request: Request, s: DB) -> Response:
        """The guide is public (it holds no inventory data): reachable from the login page."""
        return page(request, "docs.html", auth.resolve(s, request.cookies.get(SESSION_COOKIE)))

    # ------------------------------------------------------------------ exports, diagnostics

    @app.get("/exports", response_class=HTMLResponse)
    def exports_page(request: Request, s: DB, user: User) -> Response:
        counts: dict[str, int] = {
            str(k): int(n)
            for k, n in s.execute(select(Entity.kind, func.count()).group_by(Entity.kind))
        }
        return page(
            request, "exports.html", user, counts=counts, can_sanitize=cfg.export_key is not None
        )

    @app.get("/export/{fmt}")
    def export_download(s: DB, _user: User, fmt: str, sanitize: bool = False) -> Response:
        """The CLI's exports, from the browser. Data was redacted at scan time; `sanitize`
        also pseudonymises names, IPs and MACs for sharing (same key as `atlas export`)."""
        if fmt not in EXPORT_FORMATS:
            raise HTTPException(404, "unknown export format")
        if sanitize and cfg.export_key is None:
            raise HTTPException(400, "sanitized exports are not available here")
        doc = export_build.build(s)
        if sanitize and cfg.export_key is not None:
            doc = export_build.sanitize(doc, cfg.export_key)
        suffix = "-sanitized" if sanitize else ""
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
        if fmt == "json":
            body, mime, name = export_build.to_json(doc).encode(), "application/json", "json"
        elif fmt == "md":
            body, mime, name = export_build.to_markdown(doc).encode(), "text/markdown", "md"
        elif fmt == "mermaid":
            text = "%% physical\n" + export_build.to_mermaid(doc["topology"]["physical"])
            text += "\n%% logical\n" + export_build.to_mermaid(doc["topology"]["logical"])
            body, mime, name = text.encode(), "text/plain", "mmd"
        else:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for fname, text in export_build.to_csv(doc).items():
                    z.writestr(fname, text)
            body, mime, name = buf.getvalue(), "application/zip", "csv.zip"
        return Response(
            body,
            media_type=mime,
            headers={"Content-Disposition": f'attachment; filename="atlas{suffix}-{stamp}.{name}"'},
        )

    @app.get("/diagnostics", response_class=HTMLResponse)
    def diagnostics_page(request: Request, s: DB, user: User) -> Response:
        return page(request, "diagnostics.html", user, x=_diagnostics(s, audit=False))

    @app.get("/diagnostics/report")
    def diagnostics_report(s: DB, _user: User) -> Response:
        """A text report to paste into an issue: versions, scheduler, per-target errors.
        No secrets (they never reach the DB), but target names and IPs: review before sharing."""
        x = _diagnostics(s, audit=True)
        lines = [f"# atlas diagnostics ({x['now']})", "", "## Versions"]
        lines += [f"- {k}: {v}" for k, v in x["versions"].items()]
        lines += ["", "## Database"] + [f"- {k}: {v}" for k, v in x["db"].items()]
        lines += ["", "## Audit log", f"- {x['audit']}"]
        lines += ["", "## Scheduler"] + [f"- {c}" for c in x["scheduler"]]
        lines += ["", "## Targets"]
        for t in x["targets"]:
            lines.append(f"- {t['name']}: {t['health']}")
            lines += [
                f"  - {r['collector']} {r['status']}: {e}" for r in t["runs"] for e in r["errors"]
            ]
        lines += ["", "## Recent scans"] + [f"- {r}" for r in x["scans"]]
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
        return Response(
            "\n".join(lines) + "\n",
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="atlas-diagnostics-{stamp}.md"'},
        )

    def _diagnostics(s: Session, *, audit: bool) -> dict[str, Any]:
        names, _ = _target_names()
        latest = queries.latest_runs(s)
        targets = [
            {"name": n, "health": queries.target_health(latest.get(n)), "runs": latest.get(n, [])}
            for n in sorted(names if names is not None else latest)
        ]
        scans = [
            f"#{sc.id} {sc.label or ''} {sc.status} {sc.started_at:%Y-%m-%d %H:%M}"
            for sc in s.scalars(select(Scan).order_by(Scan.id.desc()).limit(10))
        ]
        db: dict[str, Any] = {
            k: s.scalar(select(func.count()).select_from(tbl))
            for k, tbl in (
                ("entities", Entity),
                ("facets", Facet),
                ("events", Event),
                ("scans", Scan),
                ("collector runs", CollectorRun),
            )
        }
        audit_line = "not checked (press Download report)"
        if cfg.data_dir is not None:
            dbf = cfg.data_dir / "atlas.db"
            if dbf.is_file():
                db["file size"] = f"{dbf.stat().st_size / 1e6:.1f} MB"
            if audit:
                rep = audit_verify(cfg.data_dir / "audit")
                audit_line = f"{'ok' if rep.ok else 'BROKEN'}: {rep.records} records" + (
                    f", {rep.error}" if rep.error else ""
                )
        sched = []
        if cfg.scheduler is not None:
            st = cfg.scheduler.status
            nxt = cfg.scheduler.next_runs()
            for name, c in st.collectors.items():
                when = nxt.get(name)
                sched.append(
                    f"{name}: every {c.interval_s // 60} min, last {c.last_status or '-'}"
                    + (f", backoff x{c.failures}" if c.backoff_until else "")
                    + (f", next {when:%H:%M} UTC" if when else "")
                )
            if st.running:
                sched.append(f"running: {st.running}")
            if st.queued:
                sched.append(f"queued: {', '.join(st.queued)}")
        else:
            sched.append("no scheduler (scans only with `atlas scan`)")
        return {
            "now": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            "versions": {
                "atlas": __version__,
                "python": platform.python_version(),
                "platform": platform.platform(terse=True),
                "lab": cfg.lab,
            },
            "db": db,
            "audit": audit_line,
            "scheduler": sched,
            "targets": targets,
            "scans": scans,
        }

    @app.get("/api/palette")
    def palette(s: DB, _user: User) -> JSONResponse:
        """Quick-find entries: pages, machines and recognised apps (labels are data)."""
        items: list[dict[str, str]] = [
            {"label": label, "hint": "page", "href": href} for href, label in PALETTE_PAGES
        ]
        cards = views.machines(s)
        for m in cards:
            hint = " · ".join(
                x for x in (views.KIND_LABELS.get(m["kind"], m["kind"]), (m["ips"] or [""])[0]) if x
            )
            items.append(
                {
                    "label": m["short"],
                    "hint": hint,
                    "href": f"/entity?key={quote(m['key'], safe='')}",
                }
            )
        apps = sorted({a["name"] for m in cards for a in m["apps"]})
        items += [
            {"label": a, "hint": "app", "href": f"/services?state=all&q={quote(a)}"} for a in apps
        ]
        return JSONResponse({"items": items[:800]})

    @app.get("/services.csv")
    def services_csv(s: DB, _user: User, f: Filters) -> Response:
        """The Services table as CSV, with the same filters (values were redacted at scan)."""
        machine, state, kind, q = f
        t = views.service_table(s, machine=machine, state=state, kind=kind, q=q)
        body = csv_table(t["rows"], list(views.SERVICE_COLUMNS))
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
        return Response(
            body,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="atlas-services-{stamp}.csv"'},
        )

    @app.get("/vlans", response_class=HTMLResponse)
    def vlans(request: Request, s: DB, user: User) -> Response:
        return page(request, "vlans.html", user, rows=queries.vlan_table(s))

    @app.get("/ports", response_class=HTMLResponse)
    def ports(
        request: Request, s: DB, user: User, q: Annotated[str | None, Query(max_length=64)] = None
    ) -> Response:
        name = "_port_rows.html" if partial(request) else "ports.html"
        return page(request, name, user, rows=queries.port_table(s, q), q=q or "")

    @app.get("/changes", response_class=HTMLResponse)
    def changes(
        request: Request,
        s: DB,
        user: User,
        severity: Annotated[str | None, Query(max_length=16)] = None,
        q: Annotated[str | None, Query(max_length=64)] = None,
        before: Annotated[int | None, Query(ge=1)] = None,
        since: Annotated[str | None, Query(max_length=8)] = None,
        machine: Annotated[str | None, Query(max_length=256)] = None,
    ) -> Response:
        keys = queries.related_keys(s, machine) if machine else None
        rows = queries.changes(s, severity, q, before, since=since, keys=keys)
        ctx: dict[str, Any] = {
            "rows": rows,
            "severity": severity or "",
            "q": q or "",
            "since": since or "",
            "machine": machine or "",
        }
        if partial(request) and before:
            return page(request, "_change_rows.html", user, **ctx)
        ctx["summary"] = queries.changes_summary(s, since, keys)
        ctx["machines"] = views.machines(s)
        ctx["query"] = urlencode(
            {
                k: v
                for k, v in (
                    ("severity", severity),
                    ("q", q),
                    ("since", since),
                    ("machine", machine),
                )
                if v
            }
        )
        name = "_changes_results.html" if partial(request) else "changes.html"
        return page(request, name, user, **ctx)

    @app.get("/changes.csv")
    def changes_csv(
        s: DB,
        _user: User,
        severity: Annotated[str | None, Query(max_length=16)] = None,
        q: Annotated[str | None, Query(max_length=64)] = None,
        since: Annotated[str | None, Query(max_length=8)] = None,
        machine: Annotated[str | None, Query(max_length=256)] = None,
    ) -> Response:
        keys = queries.related_keys(s, machine) if machine else None
        rows = queries.changes(s, severity, q, since=since, keys=keys, limit=20000)
        flat = [
            {
                "time": r["event"].created_at.isoformat(timespec="seconds"),
                "severity": r["event"].severity,
                "type": r["event"].type,
                "entity": r["name"],
                "summary": r["event"].summary,
                "path": r["event"].path,
                "scan": r["event"].scan_id,
            }
            for r in rows
        ]
        body = csv_table(flat, ["time", "severity", "type", "entity", "summary", "path", "scan"])
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
        return Response(
            body,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="atlas-changes-{stamp}.csv"'},
        )

    @app.get("/unknown", response_class=HTMLResponse)
    def unknown(
        request: Request,
        s: DB,
        user: User,
        all: bool = False,  # noqa: A002 - query parameter name
        everything: bool = False,
    ) -> Response:
        rows = queries.unknown_devices(s, include_ack=all)
        # Infrastructure first: phones, TVs and IoT only on request (classify.py, ADR-027).
        hidden = [r for r in rows if r.get("category") in ("personal", "iot")]
        shown = rows if everything else [r for r in rows if r not in hidden]
        return page(
            request,
            "unknown.html",
            user,
            rows=shown,
            all=all,
            everything=everything,
            hidden=len(hidden),
            can_add=cfg.targets is not None and cfg.targets.editable,
        )

    @app.post("/unknown/ack", response_class=HTMLResponse)
    def acknowledge(
        request: Request, s: DB, user: Csrf, key: Annotated[str, Form(max_length=256)]
    ) -> Response:
        entity = s.get(Entity, key)
        if entity is None or entity.kind != "unknown-device":
            raise HTTPException(404, "no such unknown device")
        current_doc = _doc_for(s, key)
        ann.save(cfg.annotations_dir, current_doc.model_copy(update={"acknowledged": True}))
        entity.status = "acknowledged"
        ann.sync(s, cfg.annotations_dir)
        if partial(request):
            return HTMLResponse("")  # row removed client-side by hx-swap="outerHTML"
        return RedirectResponse("/unknown", 303)

    @app.get("/topology", response_class=HTMLResponse)
    def topology_page(request: Request, s: DB, user: User, view: str = "logical") -> Response:
        view = view if view in ("physical", "logical", "vlan") else "logical"
        pve = views.proxmox_summary(views.machines(s)) if view == "logical" else None
        return page(request, "topology.html", user, view=view, pve=pve)

    @app.get("/api/topology")
    def topology_json(s: DB, _user: User, view: str = "logical") -> JSONResponse:
        if view not in ("physical", "logical", "vlan"):
            raise HTTPException(400, "unknown view")
        return JSONResponse({"elements": topology.build(s, view)})  # type: ignore[arg-type]

    # ------------------------------------------------------------------ annotations

    def _doc_for(s: Session, key: str) -> ann.AnnotationDoc:
        row = s.get(Annotation, key)
        if row is None:
            return ann.AnnotationDoc(entity=key)
        return ann.AnnotationDoc(
            entity=key,
            owner=row.owner,
            purpose=row.purpose,
            criticality=row.criticality,  # type: ignore[arg-type]
            tags=row.tags,
            links=[ann.Link(**x) for x in row.links],
            notes=row.notes,
            acknowledged=row.acknowledged,
        )

    @app.get("/entity/annotation", response_class=HTMLResponse)
    def annotation_form(
        request: Request, s: DB, user: User, key: Annotated[str, Query(max_length=256)]
    ) -> Response:
        if s.get(Entity, key) is None:
            raise HTTPException(404, "no such entity")
        return page(
            request, "_annotation_form.html", user, key=key, doc=_doc_for(s, key), error=None
        )

    @app.post("/entity/annotation", response_class=HTMLResponse)
    def annotation_save(
        request: Request,
        s: DB,
        user: Csrf,
        key: Annotated[str, Form(max_length=256)],
        owner: Annotated[str, Form(max_length=128)] = "",
        purpose: Annotated[str, Form(max_length=512)] = "",
        criticality: Annotated[str, Form(max_length=16)] = "",
        tags: Annotated[str, Form(max_length=1024)] = "",
        links: Annotated[str, Form(max_length=8192)] = "",
        notes: Annotated[str, Form(max_length=8192)] = "",
    ) -> Response:
        if s.get(Entity, key) is None:
            raise HTTPException(404, "no such entity")
        previous = _doc_for(s, key)
        try:
            parsed_links = []
            for line in links.splitlines():
                if line.strip():
                    title, sep, url = line.partition("|")
                    if not sep:
                        raise ValueError("links: one per line as 'Title | https://...'")
                    parsed_links.append(ann.Link(title=title.strip(), url=url.strip()))
            doc = ann.AnnotationDoc(
                entity=key,
                owner=owner.strip() or None,
                purpose=purpose.strip() or None,
                criticality=criticality or None,  # type: ignore[arg-type]
                tags=[t.strip() for t in tags.split(",") if t.strip()],
                links=parsed_links,
                notes=notes.strip() or None,
                acknowledged=previous.acknowledged,
            )
        except ValueError as exc:
            msg = str(exc).splitlines()
            return page(
                request,
                "_annotation_form.html",
                user,
                422,
                key=key,
                doc=previous,
                error=next((m for m in msg if m and not m.startswith(" ")), "invalid input")[:300],
            )
        ann.save(cfg.annotations_dir, doc)
        ann.sync(s, cfg.annotations_dir)
        return page(request, "_annotation.html", user, a=s.get(Annotation, key), key=key)

    # ------------------------------------------------------------------ targets (ADR-025)

    def targets_svc() -> TargetsService:
        if cfg.targets is None:
            raise HTTPException(404, "targets page disabled")
        return cfg.targets

    def _target_names() -> tuple[set[str] | None, set[str]]:
        """Configured target names (hosts and sources) and host addresses."""
        if cfg.targets is None:
            return None, set()
        inv, _ = cfg.targets.inventory()
        names = {h.name for h in inv.hosts}
        for kind in ("proxmox", "unifi", "unas"):
            names |= {src.name for src in getattr(inv.sources, kind)}
        return names, {h.address for h in inv.hosts}

    def _kind(kind: str) -> SourceKind:
        if kind not in ("proxmox", "unifi", "unas"):
            raise HTTPException(404, "unknown source kind")
        return kind  # type: ignore[return-value]

    def _secret(value: str) -> SecretStr | None:
        return SecretStr(value) if value.strip() else None

    @app.get("/targets", response_class=HTMLResponse)
    def targets_page(
        request: Request, s: DB, user: User, msg: Annotated[str, Query(max_length=200)] = ""
    ) -> Response:
        svc = targets_svc()
        runs = queries.latest_runs(s)
        health = {name: queries.target_health(rs) for name, rs in runs.items()}
        names, _ = _target_names()
        tally: dict[str, int] = {}
        for n in sorted(names or ()):
            h = health.get(n, "never")
            tally[h] = tally.get(h, 0) + 1
        return page(
            request,
            "targets.html",
            user,
            v=svc.view(),
            message=msg,
            sched=cfg.scheduler,
            runs=runs,
            health=health,
            tally=tally,
        )

    @app.post("/targets/scan-many", response_class=HTMLResponse)
    async def target_scan_many(
        request: Request, s: DB, user: Csrf, which: Annotated[str, Form(max_length=16)] = "failed"
    ) -> Response:
        """Queue a scan of every target that failed or was never scanned (or of all of them)."""
        if cfg.scheduler is None:
            raise HTTPException(404, "scheduler disabled")
        names, _ = _target_names()
        latest = queries.latest_runs(s)
        todo = sorted(
            n
            for n in names or ()
            if which == "all" or queries.target_health(latest.get(n)) in ("failed", "never")
        )
        if todo:
            cfg.scheduler.trigger(hosts=todo)
        msg = f"Queued {len(todo)} target(s): {', '.join(todo)}" if todo else "Nothing to rescan."
        return RedirectResponse(f"/targets?msg={quote(msg[:190])}", 303)

    @app.get("/targets/host", response_class=HTMLResponse)
    def target_host_form(
        request: Request,
        user: User,
        name: Annotated[str, Query(max_length=64)] = "",
        prefill_name: Annotated[str, Query(max_length=64)] = "",
        prefill_address: Annotated[str, Query(max_length=255)] = "",
        prefill_type: Annotated[str, Query(max_length=16)] = "",
    ) -> Response:
        svc = targets_svc()
        inv, _ = svc.inventory()
        entry = svc.host(name) if name else None
        if name and entry is None:
            raise HTTPException(404, "no such host")
        form = host_form_from(entry, inv)
        if entry is None:  # "Add as target" from the Unknown devices page
            form.name = re.sub(r"[^A-Za-z0-9._-]+", "-", prefill_name).strip("-.")[:64]
            form.address = prefill_address.strip()
            if prefill_type in HOST_TYPES:
                form.type = prefill_type
                if prefill_type == "pi":
                    form.collectors = ["linux-ssh", "pi"]
        return page(
            request,
            "target_host.html",
            user,
            f=form,
            editable=svc.editable,
            types=HOST_TYPES,
            collectors=HOST_COLLECTORS,
            error=None,
            secret_set=bool(entry and svc.has_secret(entry.ssh.password)),
            pinned=entry.ssh.host_keys if entry else (),
            atlas_key=svc.atlas_public_key(create=True),
        )

    @app.post("/targets/host", response_class=HTMLResponse)
    async def target_host_save(
        request: Request,
        user: Csrf,
        name: Annotated[str, Form(max_length=64)],
        address: Annotated[str, Form(max_length=255)],
        type: Annotated[str, Form(max_length=16)] = "linux",  # noqa: A002
        collectors: Annotated[list[str] | None, Form()] = None,
        ssh_user: Annotated[str, Form(max_length=32)] = "",
        ssh_port: Annotated[int, Form(ge=1, le=65535)] = 22,
        auth: Annotated[str, Form(max_length=16)] = "password",
        password: Annotated[str, Form(max_length=1024)] = "",
        sudo: Annotated[str, Form(max_length=4)] = "",
        key_name: Annotated[str, Form(max_length=64)] = "",
        host_key: Annotated[str, Form(max_length=2048)] = "",
        host_key_confirmed: Annotated[str, Form(max_length=4)] = "",
        original: Annotated[str, Form(max_length=64)] = "",
    ) -> Response:
        svc = targets_svc()
        form = HostForm(
            name=name.strip(),
            address=address.strip(),
            type=type,
            collectors=list(collectors or []),
            user=ssh_user.strip(),
            port=ssh_port,
            auth=auth if auth in ("key", "key-installed") else "password",  # type: ignore[arg-type]
            sudo=bool(sudo),
            key_name=key_name.strip(),
            host_key=host_key.strip(),
            host_key_confirmed=bool(host_key_confirmed),
            original=original,
        )
        try:
            svc.save_host(form, _secret(password))
        except TargetError as exc:
            entry = svc.host(original or form.name)
            return page(
                request,
                "target_host.html",
                user,
                422,
                f=form,
                editable=svc.editable,
                types=HOST_TYPES,
                collectors=HOST_COLLECTORS,
                error=str(exc)[:300],
                secret_set=bool(entry and svc.has_secret(entry.ssh.password)),
                pinned=entry.ssh.host_keys if entry else (),
                atlas_key=svc.atlas_public_key(create=True),
            )
        msg = f"{form.name} saved"
        if cfg.scheduler is not None and form.collectors:
            cfg.scheduler.trigger(hosts=[form.name])  # first scan right away, not in an hour
            msg += "; its first scan is queued"
        return RedirectResponse(f"/targets?msg={quote(msg)}", 303)

    @app.post("/targets/host/delete")
    def target_host_delete(user: Csrf, name: Annotated[str, Form(max_length=64)]) -> Response:
        try:
            targets_svc().delete_host(name)
        except TargetError as exc:
            return RedirectResponse(f"/targets?msg={quote(str(exc)[:150])}", 303)
        return RedirectResponse(f"/targets?msg={quote(name + ' removed')}", 303)

    @app.post("/targets/hostkey", response_class=HTMLResponse)
    async def target_hostkey(
        request: Request,
        user: Csrf,
        address: Annotated[str, Form(max_length=255)],
        ssh_port: Annotated[int, Form(ge=1, le=65535)] = 22,
        name: Annotated[str, Form(max_length=64)] = "",
    ) -> Response:
        try:
            hk = await targets_svc().fetch_host_key(name.strip(), address.strip(), ssh_port)
        except (TargetError, SecurityRefusal, TransportError) as exc:
            return page(request, "_hostkey.html", user, hk=None, error=_safe_error(exc))
        return page(request, "_hostkey.html", user, hk=hk, error=None)

    @app.get("/targets/source", response_class=HTMLResponse)
    def target_source_form(
        request: Request,
        user: User,
        kind: Annotated[str, Query(max_length=8)],
        name: Annotated[str, Query(max_length=64)] = "",
    ) -> Response:
        svc = targets_svc()
        k = _kind(kind)
        src = svc.source(k, name) if name else None
        if name and src is None:
            raise HTTPException(404, "no such source")
        return page(
            request,
            "target_source.html",
            user,
            f=source_form_from(k, src),
            editable=svc.editable,
            error=None,
            secret_set=bool(src and svc.has_secret(src.credential)),
            pinned=src.tls if src else None,
        )

    @app.post("/targets/source", response_class=HTMLResponse)
    async def target_source_save(
        request: Request,
        user: Csrf,
        kind: Annotated[str, Form(max_length=8)],
        name: Annotated[str, Form(max_length=64)],
        url: Annotated[str, Form(max_length=512)] = "",
        credential: Annotated[str, Form(max_length=4096)] = "",
        cert_pem: Annotated[str, Form(max_length=65536)] = "",
        cert_sha256: Annotated[str, Form(max_length=64)] = "",
        cert_confirmed: Annotated[str, Form(max_length=4)] = "",
        original: Annotated[str, Form(max_length=64)] = "",
        connection: Annotated[str, Form(max_length=8)] = "local",
        console_id: Annotated[str, Form(max_length=160)] = "",
    ) -> Response:
        svc = targets_svc()
        form = SourceForm(
            kind=_kind(kind),
            name=name.strip(),
            url=url.strip(),
            cert_pem=cert_pem,
            cert_sha256=cert_sha256.strip(),
            cert_confirmed=bool(cert_confirmed),
            original=original,
            connection="cloud" if connection == "cloud" and kind == "unifi" else "local",
            console_id=console_id.strip(),
        )
        try:
            if form.connection == "cloud":
                key = _secret(credential) or svc.stored_credential(form.kind, original or form.name)
                if key is None:
                    raise TargetError("enter the API key from unifi.ui.com")
                form.url = await svc.cloud_url(key, form.console_id)
            svc.save_source(form, _secret(credential))
        except TargetError as exc:
            src = svc.source(form.kind, original or form.name)
            return page(
                request,
                "target_source.html",
                user,
                422,
                f=form,
                editable=svc.editable,
                error=str(exc)[:300],
                secret_set=bool(src and svc.has_secret(src.credential)),
                pinned=src.tls if src else None,
            )
        msg = f"{form.name} saved"
        if cfg.scheduler is not None:
            cfg.scheduler.trigger(hosts=[form.name])
            msg += "; its first scan is queued"
        return RedirectResponse(f"/targets?msg={quote(msg)}", 303)

    @app.post("/targets/unifi/consoles", response_class=HTMLResponse)
    async def target_unifi_consoles(
        request: Request,
        user: Csrf,
        credential: Annotated[str, Form(max_length=4096)] = "",
        name: Annotated[str, Form(max_length=64)] = "",
        original: Annotated[str, Form(max_length=64)] = "",
    ) -> Response:
        svc = targets_svc()
        key = _secret(credential) or svc.stored_credential("unifi", original or name)
        if key is None:
            return page(
                request, "_consoles.html", user, consoles=[], error="enter the API key first"
            )
        try:
            found = await svc.find_unifi_consoles(key)
        except (TargetError, SecurityRefusal, TransportError, HttpStatusError) as exc:
            msg = (
                "the key was refused"
                if isinstance(exc, HttpStatusError) and exc.status in (401, 403)
                else _safe_error(exc)
            )
            return page(request, "_consoles.html", user, consoles=[], error=msg)
        return page(request, "_consoles.html", user, consoles=found, error=None)

    @app.post("/targets/source/test", response_class=HTMLResponse)
    async def target_source_test(
        request: Request,
        user: Csrf,
        kind: Annotated[str, Form(max_length=8)],
        name: Annotated[str, Form(max_length=64)],
    ) -> Response:
        targets_svc()
        if cfg.source_tester is None:
            return page(
                request,
                "_test_result.html",
                user,
                ok=False,
                text="testing is not available in the demo lab",
            )
        ok, text = await cfg.source_tester(_kind(kind), name)
        return page(request, "_test_result.html", user, ok=ok, text=text)

    @app.post("/targets/source/delete")
    def target_source_delete(
        user: Csrf,
        kind: Annotated[str, Form(max_length=8)],
        name: Annotated[str, Form(max_length=64)],
    ) -> Response:
        try:
            targets_svc().delete_source(_kind(kind), name)
        except TargetError as exc:
            return RedirectResponse(f"/targets?msg={quote(str(exc)[:150])}", 303)
        return RedirectResponse(f"/targets?msg={quote(name + ' removed')}", 303)

    @app.post("/targets/cert", response_class=HTMLResponse)
    async def target_cert(
        request: Request,
        user: Csrf,
        kind: Annotated[str, Form(max_length=8)],
        url: Annotated[str, Form(max_length=512)],
        name: Annotated[str, Form(max_length=64)] = "",
    ) -> Response:
        try:
            cert = await targets_svc().fetch_certificate(_kind(kind), name.strip(), url.strip())
        except (TargetError, SecurityRefusal, TransportError) as exc:
            return page(request, "_cert.html", user, cert=None, error=_safe_error(exc))
        return page(request, "_cert.html", user, cert=cert, error=None)

    @app.post("/targets/test", response_class=HTMLResponse)
    async def target_test(
        request: Request, user: Csrf, name: Annotated[str, Form(max_length=64)]
    ) -> Response:
        targets_svc()
        if cfg.tester is None:
            return page(
                request,
                "_test_result.html",
                user,
                ok=False,
                text="testing is not available in the demo lab",
            )
        ok, text = await cfg.tester(name)
        return page(request, "_test_result.html", user, ok=ok, text=text)

    @app.post("/targets/scan", response_class=HTMLResponse)
    async def target_scan(
        request: Request, user: Csrf, name: Annotated[str, Form(max_length=64)]
    ) -> Response:
        targets_svc()
        if cfg.scheduler is None:
            return page(
                request,
                "_test_result.html",
                user,
                ok=False,
                text="scanning from the UI is off (atlas serve without a scheduler)",
            )
        state = cfg.scheduler.trigger(hosts=[name])
        text = (
            f"Scan of {name} started; this row updates when it is done."
            if state == "started"
            else f"{name} is queued: it is scanned right after the current scan."
        )
        return page(request, "_test_result.html", user, ok=True, text=text)

    return app
