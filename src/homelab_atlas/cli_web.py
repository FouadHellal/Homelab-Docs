"""CLI: `atlas serve` and `atlas user add|passwd`."""

import os
import secrets
import shutil
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from sqlalchemy import func, select

from homelab_atlas.runtime import LAB_DATA_DIR, Runtime, config_dir, default_data_dir
from homelab_atlas.store.tables import User
from homelab_atlas.web import auth

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


@user_app.command("add")
def user_add(username: str, lab: LabFlag = None, data_dir: DataOpt = None) -> None:
    """Create a local web user (prompts for the password; never pass it as an argument)."""
    rt = _runtime(lab, data_dir)
    password = _ask_password()
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


def serve(
    lab: LabFlag = None,
    data_dir: DataOpt = None,
    host: Annotated[str, typer.Option(help="Bind address (keep it private).")] = "127.0.0.1",
    port: int = 8080,
    allowed_host: Annotated[list[str] | None, typer.Option(help="Accepted Host header(s).")] = None,
    forwarded_allow_ips: Annotated[str, typer.Option(help="Reverse proxy IPs.")] = "127.0.0.1",
    hsts: Annotated[bool, typer.Option(help="Send HSTS (behind a TLS proxy).")] = False,
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
    hosts = allowed_host or ["localhost", "127.0.0.1"]
    app = create_app(
        WebConfig(
            sessions=rt.sessions,
            annotations_dir=annotations,
            allowed_hosts=hosts,
            hsts=hsts,
            lab=bool(lab),
        )
    )
    console.print(f"atlas UI on http://{host}:{port} (annotations: {annotations})")
    uvicorn.run(
        app,
        host=host,
        port=port,
        proxy_headers=True,
        forwarded_allow_ips=forwarded_allow_ips,
        server_header=False,
        date_header=False,
        log_level="warning",
    )


def register(app: typer.Typer) -> None:
    app.command("serve")(serve)
    app.add_typer(user_app, name="user")
