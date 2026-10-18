"""`atlas` command-line entry point."""

from typing import Annotated

import typer

from homelab_atlas import __version__

app = typer.Typer(
    name="atlas",
    help="Read-only homelab discovery and documentation.",
    no_args_is_help=True,
    add_completion=False,
)


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
) -> None:
    """Read-only homelab discovery and documentation."""


@app.command("version")
def version_cmd() -> None:
    """Show the version."""
    typer.echo(f"atlas {__version__}")
