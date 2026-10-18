# Homelab-Docs (`atlas`)

Read-only, agentless auto-discovery and documentation of a Proxmox + UniFi + Docker homelab.
Status: **M4** (security core; linux-ssh, docker, Pi, Proxmox, UniFi and UNAS collectors; correlation; unknown devices; snapshots, diff, CLI). See [docs/SPEC.md](docs/SPEC.md),
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
uv run atlas diff --lab demo           # 59 typed change events (hosts, containers, VMs, network, NAS)
uv run atlas unknown --lab demo        # devices on the network nothing in the inventory explains
uv run atlas doctor --lab demo:A       # flags db01's outdated probe and unreachable ghost01;
                                       # checks the Proxmox token holds *.Audit privileges only
```
