# Homelab-Docs (`atlas`)

Read-only, agentless auto-discovery and documentation of a Proxmox + UniFi + Docker homelab.
Status: **M6** (security core; linux-ssh, docker, Pi, Proxmox, UniFi and UNAS collectors; correlation; unknown devices; snapshots, diff, CLI; web UI with topology and annotations; scheduler; exports with `--sanitize`; read-only MCP server). See [docs/SPEC.md](docs/SPEC.md),
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
uv run atlas serve --lab demo          # web UI on http://127.0.0.1:8080, login in data/demo-lab/demo-login.txt
uv run atlas doctor --lab demo:A       # flags db01's outdated probe and unreachable ghost01;
                                       # checks the Proxmox token holds *.Audit privileges only
uv run atlas serve --lab demo --schedule   # + periodic scans and a "Scan now" button
uv run atlas export mkdocs --sanitize --lab demo   # exports/mkdocs-sanitized/ (also json, csv, md, mermaid)
uv run atlas mcp --lab demo            # read-only MCP server on stdio (add --http for Streamable HTTP + bearer)
```

### MCP client config (stdio)
```json
{ "mcpServers": { "atlas": { "command": "uv", "args": ["run", "--directory", "C:/Homelab-Docs", "atlas", "mcp", "--lab", "demo"] } } }
```
Tools: `list_hosts`, `get_host`, `list_containers`, `search_ip`, `find_service`, `what_changed`,
`list_unknown_devices`. All are read-only: no tool can trigger a scan or write anything.
