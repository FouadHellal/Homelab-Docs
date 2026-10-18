# Homelab-Docs (`atlas`)

Read-only, agentless auto-discovery and documentation of a Proxmox + UniFi + Docker homelab.
Status: **M0**, scaffolding only. See [docs/SPEC.md](docs/SPEC.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/DECISIONS.md](docs/DECISIONS.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Dev quickstart (Windows or Linux)
```
uv sync
uv run pre-commit install
uv run poe check        # lint, mypy --strict, pytest, gitleaks
uv run atlas --version
```
