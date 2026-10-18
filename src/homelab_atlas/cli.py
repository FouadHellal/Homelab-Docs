"""`atlas` command-line entry point."""

import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from homelab_atlas import __version__

app = typer.Typer(
    name="atlas",
    help="Read-only homelab discovery and documentation.",
    no_args_is_help=True,
    add_completion=False,
)
selftest_app = typer.Typer(help="Offline self-tests.", no_args_is_help=True)
audit_app = typer.Typer(help="Audit log tools.", no_args_is_help=True)
app.add_typer(selftest_app, name="selftest")
app.add_typer(audit_app, name="audit")

console = Console()


def _default_audit_dir() -> Path:
    return Path(os.environ.get("ATLAS_DATA_DIR", "data")) / "audit"


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"atlas {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_print_version,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
    verbose: Annotated[bool, typer.Option("-v", "--verbose", help="Log at INFO.")] = False,
) -> None:
    """Read-only homelab discovery and documentation."""
    from homelab_atlas.log import configure_logging  # noqa: PLC0415

    configure_logging("INFO" if verbose else "WARNING", json=False)


@app.command("version")
def version_cmd() -> None:
    """Show the version."""
    typer.echo(f"atlas {__version__}")


@selftest_app.command("security")
def selftest_security() -> None:
    """Exercise every security guard offline (no network, no targets)."""
    from homelab_atlas.security.selftest import run_selftest  # noqa: PLC0415

    checks = run_selftest()
    table = Table(title="atlas security self-test")
    for col in ("group", "check", "result", "detail"):
        table.add_column(col)
    for c in checks:
        result = "[green]PASS[/]" if c.ok else "[red]FAIL[/]"
        table.add_row(c.group, c.name, result, c.detail)
    console.print(table)
    failed = sum(not c.ok for c in checks)
    console.print(f"{len(checks) - failed}/{len(checks)} checks passed")
    if failed:
        raise typer.Exit(1)


@audit_app.command("verify")
def audit_verify(
    directory: Annotated[
        Path | None, typer.Option("--dir", help="Audit directory (default $ATLAS_DATA_DIR/audit)")
    ] = None,
) -> None:
    """Recompute the audit hash chain and report the first break."""
    from homelab_atlas.security.audit import verify  # noqa: PLC0415

    report = verify(directory or _default_audit_dir())
    if report.ok:
        console.print(f"[green]OK[/] {report.records} records, head {report.head[:16]}…")
        return
    console.print(f"[red]BROKEN[/] after {report.records} good records: {report.error}")
    raise typer.Exit(1)


def _register_scan_commands() -> None:
    from homelab_atlas.cli_scan import register  # noqa: PLC0415

    register(app)


_register_scan_commands()
