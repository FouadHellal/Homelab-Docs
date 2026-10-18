# SPEC — Homelab-Docs (`atlas`)

Status: draft for approval (M0a). Date: 2026-10-18.

## 1. Purpose
Auto-discover a homelab (Proxmox, UniFi, Linux, Docker, UNAS, Raspberry Pi), keep a normalized, change-tracked inventory, and expose it through a web UI, exports, a CLI and a read-only MCP server. A thin human-annotation layer sits on top. Human maintenance should be limited to `hosts.yaml` and optional annotations.

## 2. Scope
### In
Inventory, topology, change tracking, unknown-device detection, exports, MCP Q&A, target-setup artifact generation, setup verification (`atlas doctor`).

### Out (non-goals)
Writes of any kind to targets, remediation, metrics time series, alerting, cloud services, internet exposure, agents/daemons on targets, active network scanning (decided: passive only), Proxmox Backup Server (not deployed), non-Debian/Ubuntu Linux (v1), Windows targets (stretch, post-v1).

## 3. Environment (owner-provided)
| Item | Value |
|---|---|
| Proxmox | 2 PVE nodes, PVE 9.x; cluster membership auto-detected; no PBS, no backup jobs configured |
| UniFi | UniFi Cloud Gateway (UCG), current UniFi OS / Network 9.3+ (Integration API) |
| Linux | Debian / Ubuntu (systemd, dpkg, iproute2), Raspberry Pi OS |
| Docker | Docker Engine + Compose v2 plugin, rootful |
| NAS | Ubiquiti UNAS (UniFi Drive) |
| Dev | Windows 11 + Docker Desktop |
| Prod | Small VM/LXC on Proxmox, docker compose, image from GHCR, behind owner's reverse proxy |

## 4. Inputs
### 4.1 `hosts.yaml` (owner-maintained, git-friendly)
```yaml
version: 1
defaults:
  ssh: { user: atlas-ro, key: ssh_atlas_default, port: 22 }
sources:                       # API seeds
  proxmox:
    - name: pve
      url: https://pve1.lan:8006
      credential: proxmox_auditor        # → secret file name, never the value
      ca_bundle: pve-ca.pem              # or fingerprint pin
  unifi:
    - name: ucg
      url: https://ucg.lan
      credential: unifi_api_key
      legacy_enrichment: false           # opt-in, see ADR-005
hosts:
  - name: docker01
    address: 10.0.20.11
    type: linux                           # linux | pi | nas | proxmox-node | unifi-device | manual
    collectors: [linux-ssh, docker]
    ssh: { key: ssh_atlas_docker }        # override
    match: { mac: "bc:24:11:aa:bb:cc" }   # optional reconciliation hint
```
Validated by Pydantic; unknown keys are an error. `credential`/`key` are names resolved from `/run/secrets/<name>` (prod) or `./secrets/<name>` (dev). Values never appear in config, logs or DB.

### 4.2 `annotations/*.yaml`
One file per entity or group, keyed by stable entity key:
```yaml
entity: "pve:vm:homelab/105"
owner: fouad
purpose: "Reverse proxy"
criticality: high      # low | medium | high | critical
tags: [edge, prod]
links: [{ title: Runbook, url: "https://wiki.lan/rp" }]
notes: |
  Markdown allowed.
```
Annotations never get overwritten by scans. UI edits write back to YAML (atomic replace, stable key order) and to the DB. Orphaned annotations (entity gone) are kept and flagged.

## 5. Entities and identity
| Kind | Stable key |
|---|---|
| Proxmox node | `pve:node:<cluster-or-standalone-name>/<node>` |
| VM / LXC | `pve:vm:<cluster>/<vmid>` / `pve:lxc:<cluster>/<vmid>` |
| Storage | `pve:storage:<cluster>/<node or "shared">/<storage>` |
| UniFi device | `unifi:dev:<mac>` |
| Client (seen) | `net:mac:<mac>` |
| Network / VLAN | `unifi:net:<site>/<network-id>`, plus VLAN id attribute |
| SSID | `unifi:wlan:<site>/<id>` |
| Linux host | `host:<machine-id>`; falls back to `host:name:<hosts.yaml name>` |
| Container | `ctr:<host-key>/<compose-project>/<service>/<replica>`, or `ctr:<host-key>/name/<container-name>` without compose |
| Image | `img:<repo>@<digest>`, with tag(s) as attributes |
| Compose project | `compose:<host-key>/<project>` |
| Listening socket | `sock:<host-key>/<proto>/<addr>/<port>` |
| NAS | `nas:<mac>` |

Host identity correlation: machine-id ↔ Proxmox VMID (via guest-agent MAC/IP and the PVE MAC in config) ↔ UniFi client MAC. A VM and its Linux host are the same logical node with two facets.

## 6. Collectors
Common contract: `name`, `requires` (commands/endpoints declared statically), `async collect(target, ctx) -> CollectorResult` (Pydantic models + per-section errors). Each runs with a timeout, fails independently, and partial results are kept with an error list.

| Collector | Source | Data |
|---|---|---|
| `proxmox` | PVE API token, GET only | cluster status, nodes, VMs/LXCs (config, status, resources), guest-agent interfaces/OS, storage, bridges/VLANs/SDN, backup jobs + "not backed up" guests, HA |
| `unifi` | Integration API (`X-API-KEY`) | site, devices (model, fw, ports, uplink device), clients, networks/VLANs, Wi-Fi broadcasts (PSK never requested/stored), firewall zones + policies, ACL rules, WANs, LAGs, VPN servers/tunnels |
| `unifi` (legacy enrichment, opt-in) | Classic API, view-only local user | uplink port numbers, LLDP, client→switch port mapping, port VLAN profiles |
| `linux-ssh` | forced-command probe | OS, kernel, machine-id, interfaces/IPs/routes (v4/v6), neighbours (ARP/NDP), listening sockets + owning process, disks/mounts, systemd services, cron (redacted), local users (passwd/group only), packages (filtered to key list for display; full list hashed) |
| `docker` | same probe, `docker` section | containers (allowlisted inspect fields), images/tags/digests, compose projects, networks, volumes, published ports, restart policy, health. Env NAMES only, stripped on target |
| `pi` | probe `pi` section | linux-ssh + SoC temp, throttling flags (decoded), model |
| `nas` | best-effort: UniFi device record + undocumented Drive GET API (feature flag) + manual YAML | model, fw, pools, disks, shares (if available) |
| `windows` (stretch) | WinRM, read-only PowerShell, JEA endpoint | out of v1 |

## 7. Reconciliation
Candidates = Proxmox guests ∪ UniFi devices ∪ UniFi clients ∪ ARP/NDP neighbours from probed hosts.
- **known**: matched to a hosts.yaml entry or seeded entity (by MAC, then IP+name, then name).
- **unknown**: seen on the network, not in inventory. Shows first/last seen, VLAN, switch port/AP, vendor OUI.
- **missing**: in inventory, not seen and unreachable for N consecutive scans.
Owners can mark an unknown as "acknowledged" (an annotation), which suppresses it without adding it to inventory.

## 8. Change tracking
- Each scan writes per-(entity, collector) **snapshots**: canonical JSON (sorted keys, normalized), redacted, SHA-256 content-addressed. If the hash is unchanged, it records a pointer only.
- **Diff** compares normalized models and ignores volatile fields (uptime, counters, load, temps, last_seen, timestamps). Set-like lists are diffed by identity key, not position.
- **Events** (typed, with severity info/notice/warning): `entity.added/removed`, `host.unreachable/recovered`, `image.updated` (digest change), `container.restarted`… (from restart count, not uptime), `port.opened/closed`, `service.enabled/disabled/failed`, `package.upgraded` (key packages), `device.new_on_vlan`, `vlan.added/removed`, `firewall.policy_changed`, `guest.not_backed_up`, `fw.upgraded`, `annotation.changed`.
- Retention: events forever, snapshots 90 days (configurable). The latest snapshot per entity is always kept.

## 9. Scheduler
APScheduler in-process. Per-collector interval (defaults: unifi 15 m, proxmox 15 m, linux/docker 60 m, nas 6 h), ±10 % jitter, global and per-target concurrency limits, per-call timeouts, exponential backoff on failure (cap 6 h), single scan lock (DB advisory row + file lock), manual trigger from UI/CLI. Disabled in CLI one-shot mode.

## 10. Interfaces
### CLI
`atlas scan [--host H] [--collector C] [--lab demo:A]`, `atlas diff [--since T] [--entity K]`, `atlas export {md,mkdocs,json,csv,mermaid} [--sanitize] [-o DIR]`, `atlas doctor [--host H]`, `atlas unknown`, `atlas targets render` (generate docs/targets/), `atlas audit verify`, `atlas serve`, `atlas mcp [--http]`, `atlas user add|passwd`, `atlas selftest security`.

### Web UI (FastAPI + Jinja2 + HTMX, vendored Cytoscape.js)
Dashboard (counts, last scan per collector, recent changes, offline/unknown), host page (facets, containers, sockets, annotations, history), global tables (IPs, VLANs, ports/services) with search, topology (physical: gateway → switches → APs/hosts; logical: node → VM/LXC → containers; VLAN membership overlay), changelog timeline, unknown devices, annotation editor, light/dark. Auth: local admin (argon2id); OIDC later. CSRF on all state-changing routes (annotations, manual scan, login). The UI is read-only toward targets.

### Exports
Markdown, MkDocs site (mkdocs.yml + pages), JSON (full model, versioned schema), CSV (hosts, IPs, ports, containers, VLANs), Mermaid (physical, logical). `--sanitize`: deterministic per-export pseudonymisation of IPs (mapped into a documentation range while preserving subnet structure), MACs (keep OUI optional, default off), hostnames, SSIDs, domain names; also strips notes and links.

### MCP (official Python SDK)
Read-only tools: `list_hosts`, `get_host`, `list_containers`, `search_ip`, `find_service`, `what_changed`, `list_unknown_devices`. Transports: stdio; Streamable HTTP with bearer token (constant-time compare), bound to a private address. Optional `mcp.sanitize: true` returns sanitized data (see THREAT-MODEL T-MCP). No tool triggers scans or writes.

## 11. Non-functional
- Runs on Windows (dev) and Linux (prod). CI matrix ubuntu + windows.
- ~25–200 entities, a full scan in < 2 min for the demo lab offline.
- No runtime internet access. JS/CSS vendored with pinned hashes.
- Container: non-root, read-only root FS, `cap_drop: [ALL]`, `no-new-privileges`, tmpfs `/tmp`, secrets via Docker secrets, SSH keys mounted read-only.
- Audit log of every SSH command and API request (target, command/endpoint template, duration, status, bytes). No secrets, no query values beyond the allowlisted template.

## 12. Demo lab (`fixtures/demo-lab/`)
About 25 hosts: 2 PVE nodes, 8 Linux VMs, 4 LXCs, 4 Docker hosts (one with containers outside compose), 1 Pi, UCG + 2 switches + 3 APs, UNAS, a few unknown clients. Two states, A and B. Nasty cases: secrets in env/labels/cmdline/cron/healthchecks, unicode and emoji hostnames, offline host, IPv6-only service, trunked VLANs, duplicate hostnames, container names with shell metacharacters, oversized output, malformed JSON, probe version mismatch. The `demo:` transport replays recorded probe and API responses through the real parsers and the real security wrappers (fake transport underneath).

## 13. Acceptance per milestone
Every milestone: tests green, ruff + mypy clean, one demo command, a summary, then a stop.
| M | Scope | Demo |
|---|---|---|
| M0 | Docs approved; scaffolding, CI, pre-commit | `uv run atlas --version`, `uv run poe check` |
| M1 | Security core: SshRunner, ReadOnlyHttpClient, Redactor, AuditLog | `atlas selftest security` |
| M2 | Models, hosts.yaml, linux-ssh, SQLite, snapshots, diff, CLI | `atlas scan --lab demo:A --fresh && atlas scan --lab demo:B && atlas diff --lab demo` emits exactly `fixtures/demo-lab/expected-diff-A-B.json` |
| M3 | docker, proxmox collectors; full demo lab | `atlas scan --lab demo:A --collector docker` |
| M4 | unifi, nas, pi; unknown devices | `atlas scan --lab demo:A` then `atlas unknown` |
| M5 | Web UI, topology, annotations, auth | `atlas serve --lab demo:B` |
| M6 | Scheduler, exports, sanitize, MCP | `atlas export mkdocs --sanitize`, `atlas mcp` |
| M7 | Docs, GHCR release, security review | `docker compose up` with the demo lab |
