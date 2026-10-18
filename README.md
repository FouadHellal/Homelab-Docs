# Homelab-Docs (`atlas`)

Read-only, agentless auto-discovery and documentation of a Proxmox + UniFi + Docker homelab.
Status: **M2** (security core, linux-ssh collector, snapshots, diff, CLI). See [docs/SPEC.md](docs/SPEC.md),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DECISIONS.md](docs/DECISIONS.md) and
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). Target setup artifacts: [docs/targets/](docs/targets/).

## Dev quickstart (Windows or Linux)
```
uv sync
uv run pre-commit install
uv run poe check                       # lint, mypy --strict, pytest, gitleaks
uv run atlas selftest security         # every guard, offline
```

## Demo lab (synthetic, no real targets)
```
uv run atlas scan --lab demo:A --fresh
uv run atlas scan --lab demo:B
uv run atlas diff --lab demo           # 17 typed change events
uv run atlas doctor --lab demo:A       # flags db01's outdated probe and unreachable ghost01
```
