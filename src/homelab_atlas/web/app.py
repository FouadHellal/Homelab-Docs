"""FastAPI app: server-rendered pages + HTMX partials (ADR-013).

Security model: every route except /login and /static requires a session; every
state-changing request needs the session's CSRF token (header or form field) and a
same-origin Origin header when one is sent; responses carry a strict nonce CSP. Templates
autoescape and never mark target data safe (a test greps for `|safe`).
"""

import secrets
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Any, Final
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from homelab_atlas import __version__
from homelab_atlas.inventory import annotations as ann
from homelab_atlas.store.tables import Annotation, Entity
from homelab_atlas.web import auth, queries, topology

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


def create_app(cfg: WebConfig) -> FastAPI:
    templates = Jinja2Templates(directory=str(PKG / "templates"))
    templates.env.autoescape = True
    templates.env.globals["version"] = __version__
    throttle = LoginThrottle(*LOGIN_RATE)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        with cfg.sessions() as s:
            errors = ann.sync(s, cfg.annotations_dir)
            s.commit()
        _app.state.annotation_errors = errors
        yield

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
        h["Referrer-Policy"] = "no-referrer"
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

    # ------------------------------------------------------------------ auth

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, s: DB, next: str = "/") -> Response:  # noqa: A002
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
        return page(
            request,
            "dashboard.html",
            user,
            d=queries.dashboard(s),
            annotation_errors=app.state.annotation_errors,
        )

    @app.get("/entities", response_class=HTMLResponse)
    def entity_list(request: Request, s: DB, user: User,
                    kind: Annotated[str | None, Query(max_length=32)] = None,
                    q: Annotated[str | None, Query(max_length=64)] = None) -> Response:  # fmt: skip
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
        return page(request, "entity.html", user, d=detail)

    @app.get("/ips", response_class=HTMLResponse)
    def ips(
        request: Request, s: DB, user: User, q: Annotated[str | None, Query(max_length=64)] = None
    ) -> Response:
        name = "_ip_rows.html" if partial(request) else "ips.html"
        return page(request, name, user, rows=queries.ip_table(s, q), q=q or "")

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
    def changes(request: Request, s: DB, user: User,
                severity: Annotated[str | None, Query(max_length=16)] = None,
                q: Annotated[str | None, Query(max_length=64)] = None,
                before: Annotated[int | None, Query(ge=1)] = None) -> Response:  # fmt: skip
        rows = queries.changes(s, severity, q, before)
        name = "_change_rows.html" if partial(request) else "changes.html"
        return page(request, name, user, rows=rows, severity=severity or "", q=q or "")

    @app.get("/unknown", response_class=HTMLResponse)
    def unknown(request: Request, s: DB, user: User, all: bool = False) -> Response:  # noqa: A002
        return page(
            request, "unknown.html", user, rows=queries.unknown_devices(s, include_ack=all), all=all
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
    def topology_page(request: Request, user: User, view: str = "logical") -> Response:
        view = view if view in ("physical", "logical", "vlan") else "logical"
        return page(request, "topology.html", user, view=view)

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
        request: Request, s: DB, user: Csrf,
        key: Annotated[str, Form(max_length=256)],
        owner: Annotated[str, Form(max_length=128)] = "",
        purpose: Annotated[str, Form(max_length=512)] = "",
        criticality: Annotated[str, Form(max_length=16)] = "",
        tags: Annotated[str, Form(max_length=1024)] = "",
        links: Annotated[str, Form(max_length=8192)] = "",
        notes: Annotated[str, Form(max_length=8192)] = "",
    ) -> Response:  # fmt: skip
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

    return app
