"""CLI: `atlas serve` and `atlas user add|passwd`."""

import functools
import os
import secrets
import shutil
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from sqlalchemy import func, select

from homelab_atlas.engine.scan import ScanEngine
from homelab_atlas.lab import load_lab
from homelab_atlas.runtime import (
    LAB_DATA_DIR,
    Runtime,
    config_dir,
    default_data_dir,
    lab_inputs,
    live_inputs,
    live_secrets,
    test_source,
    test_ssh_login,
)
from homelab_atlas.scheduler import Scheduler
from homelab_atlas.store.retention import DEFAULT_SNAPSHOT_DAYS, prune
from homelab_atlas.store.tables import User
from homelab_atlas.web import auth
from homelab_atlas.web.targets import TargetsService
from homelab_atlas.web.tls import ensure_self_signed, fingerprint

console = Console()
user_app = typer.Typer(help="Local web accounts (argon2id).", no_args_is_help=True)

LabFlag = Annotated[
    str | None, typer.Option("--lab", help="Demo lab, e.g. demo (uses its data dir).")
]
DataOpt = Annotated[Path | None, typer.Option("--data-dir")]
LAB_SEED_ANNOTATIONS = Path("fixtures/demo-lab/annotations")


def _runtime(lab: str | None, data_dir: Path | None) -> Runtime:
    return Runtime.open(data_dir or default_data_dir(lab=bool(lab)), mode="demo" if lab else "live")


def _ask_password() -> str:
    pw: str = typer.prompt("Password (12+ characters)", hide_input=True, confirmation_prompt=True)
    return pw


EOL = "\r\n"
PasswordStdin = Annotated[
    bool, typer.Option("--password-stdin", help="Read the password from stdin (scripts).")
]


@user_app.command("add")
def user_add(
    username: str,
    lab: LabFlag = None,
    data_dir: DataOpt = None,
    password_stdin: PasswordStdin = False,
) -> None:
    """Create a local web user (prompts for the password; never pass it as an argument)."""
    rt = _runtime(lab, data_dir)
    password = sys.stdin.readline().rstrip(EOL) if password_stdin else _ask_password()
    with rt.sessions() as s:
        try:
            auth.create_user(s, username, password)
        except auth.AuthError as exc:
            console.print(f"[red]error:[/] {exc}")
            raise typer.Exit(2) from None
        s.commit()
    console.print(f"user {username} created")


@user_app.command("passwd")
def user_passwd(username: str, lab: LabFlag = None, data_dir: DataOpt = None) -> None:
    """Change a password; ends that user's sessions."""
    rt = _runtime(lab, data_dir)
    password = _ask_password()
    with rt.sessions() as s:
        try:
            auth.set_password(s, username, password)
        except auth.AuthError as exc:
            console.print(f"[red]error:[/] {exc}")
            raise typer.Exit(2) from None
        s.commit()
    console.print(f"password for {username} changed; existing sessions ended")


def ensure_demo_login(rt: Runtime) -> Path | None:
    """Lab only: create user 'demo' with a random password, written to a 0600 file."""
    with rt.sessions() as s:
        if s.scalar(select(func.count()).select_from(User)):
            return None
        password = secrets.token_urlsafe(18)
        auth.create_user(s, "demo", password)
        s.commit()
    path = rt.data_dir / "demo-login.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"username: demo\npassword: {password}\n")
    return path


def make_targets(
    rt: Runtime, *, lab: bool
) -> tuple[TargetsService, Callable[[str], Awaitable[tuple[bool, str]]] | None]:
    """Targets page: editable in live mode (encrypted vault), read-only on the demo lab."""
    if lab:
        inventory, _ = load_lab("B")
        svc = TargetsService(config_dir=config_dir(), data_dir=rt.data_dir, vault=None,
                             audit=rt.audit, readonly_inventory=inventory)  # fmt: skip
        return svc, None
    secrets = live_secrets(rt.data_dir)
    svc = TargetsService(config_dir=config_dir(), data_dir=rt.data_dir, vault=secrets.vault,
                         audit=rt.audit)  # fmt: skip

    async def tester(name: str) -> tuple[bool, str]:
        return await test_ssh_login(rt.data_dir, rt.audit, name)

    return svc, tester


async def _source_tester(rt: Runtime, kind: str, name: str) -> tuple[bool, str]:
    return await test_source(rt.data_dir, rt.audit, kind, name)


def make_scheduler(rt: Runtime, *, lab: bool) -> Scheduler:
    """Each run rebuilds inputs, so hosts.yaml edits apply without a restart."""
    days = int(os.environ.get("ATLAS_SNAPSHOT_DAYS", str(DEFAULT_SNAPSHOT_DAYS)))

    def engine() -> ScanEngine:
        return rt.scan_engine(lab_inputs("B") if lab else live_inputs(rt.data_dir))

    def retention() -> None:
        with rt.sessions() as s:
            prune(s, days=days)

    return Scheduler(engine, retention=retention)


def serve(
    lab: LabFlag = None,
    data_dir: DataOpt = None,
    host: Annotated[str, typer.Option(help="Bind address (keep it private).")] = "127.0.0.1",
    port: int = 8080,
    allowed_host: Annotated[list[str] | None, typer.Option(help="Accepted Host header(s).")] = None,
    forwarded_allow_ips: Annotated[str, typer.Option(help="Reverse proxy IPs.")] = "127.0.0.1",
    hsts: Annotated[bool, typer.Option(help="Send HSTS (behind a TLS proxy).")] = False,
    schedule: Annotated[
        bool, typer.Option(help="Run periodic scans + 'Scan now' (ATLAS_INTERVAL_<COLLECTOR>).")
    ] = False,
    self_signed_tls: Annotated[
        bool, typer.Option(help="Serve HTTPS with a generated certificate (LAN, no proxy).")
    ] = False,
    tls_cert: Annotated[Path | None, typer.Option(help="PEM certificate for HTTPS.")] = None,
    tls_key: Annotated[Path | None, typer.Option(help="PEM private key for HTTPS.")] = None,
) -> None:
    """Run the web UI (read-only towards targets)."""
    import uvicorn  # noqa: PLC0415

    from homelab_atlas.web.app import WebConfig, create_app  # noqa: PLC0415

    rt = _runtime(lab, data_dir)
    if lab:
        annotations = (data_dir or LAB_DATA_DIR) / "annotations"
        if not annotations.exists() and LAB_SEED_ANNOTATIONS.is_dir():
            shutil.copytree(LAB_SEED_ANNOTATIONS, annotations)
        if (login_file := ensure_demo_login(rt)) is not None:
            console.print(f"demo login written to {login_file}")
    else:
        annotations = config_dir() / "annotations"
    # Loopback names are always accepted (container healthcheck, SSH tunnels); they cannot
    # be used for DNS rebinding from a browser on another machine.
    given = [h.strip() for value in (allowed_host or []) for h in value.split(",") if h.strip()]
    hosts = list(dict.fromkeys([*given, "localhost", "127.0.0.1"]))
    setup_file = None if lab else first_run_setup(rt)
    if self_signed_tls and not (tls_cert or tls_key):
        tls_cert, tls_key = ensure_self_signed(rt.data_dir, [h for h in given if h != "*"])
        console.print(f"self-signed HTTPS certificate {tls_cert} (SHA-256 {fingerprint(tls_cert)})")
    if bool(tls_cert) != bool(tls_key):
        console.print("[red]error:[/] --tls-cert and --tls-key go together")
        raise typer.Exit(2)
    # The scheduler always exists so "Scan now" works; --schedule adds the periodic jobs.
    scheduler = make_scheduler(rt, lab=bool(lab))
    targets, tester = make_targets(rt, lab=bool(lab))
    app = create_app(
        WebConfig(
            sessions=rt.sessions,
            annotations_dir=annotations,
            allowed_hosts=hosts,
            hsts=hsts,
            lab=bool(lab),
            scheduler=scheduler,
            schedule=schedule,
            targets=targets,
            tester=tester,
            source_tester=None if lab else functools.partial(_source_tester, rt),
            setup_token_file=setup_file,
        )
    )
    scheme = "https" if tls_cert else "http"
    console.print(f"atlas UI on {scheme}://{host}:{port} (annotations: {annotations})")
    if scheme == "http" and host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            "[yellow]note:[/] login cookies are Secure: over plain HTTP only localhost works. "
            "Use --self-signed-tls or put a TLS reverse proxy in front."
        )
    uvicorn.run(
        app,
        host=host,
        port=port,
        proxy_headers=True,
        forwarded_allow_ips=forwarded_allow_ips,
        server_header=False,
        date_header=False,
        log_level="warning",
        ssl_certfile=str(tls_cert) if tls_cert else None,
        ssl_keyfile=str(tls_key) if tls_key else None,
    )


def first_run_setup(rt: Runtime) -> Path | None:
    """No account yet: write a one-time setup token (0600) and print where to use it."""
    path = rt.data_dir / "setup-token.txt"
    with rt.sessions() as s:
        if s.scalar(select(func.count()).select_from(User)):
            path.unlink(missing_ok=True)
            return None
    if not path.is_file():
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600
        )
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(secrets.token_urlsafe(18) + "\n")
    token = path.read_text(encoding="utf-8").strip()
    console.print(
        f"[bold]First run:[/] no account yet. Open /setup in your browser and enter the setup "
        f"token {token} (also in {path}), or run: atlas user add <name>"
    )
    return path


def register(app: typer.Typer) -> None:
    app.command("serve")(serve)
    app.add_typer(user_app, name="user")
