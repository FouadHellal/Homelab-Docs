"""Read-only, agentless auto-discovery and documentation of a homelab."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("homelab-atlas")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
