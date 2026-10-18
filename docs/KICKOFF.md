# Homelab-Docs: automatic, read-only infrastructure documentation platform

## 0. Setup and working rules
- Working folder: C:\Homelab-Docs (already a git repo, cloned from my private GitHub repo). It already contains .gitignore, .gitattributes and docs/claude-settings.json. FIRST STEP: copy docs/claude-settings.json to .claude/settings.json (it denies reads of .env, secrets/ and ~/.ssh, and denies git push). Tell me if anything is missing.
- Start in plan mode. Write no code until I approve the plan.
- Read this whole brief, then ask me at most 6 clarifying questions in ONE batch. Only ask what you can't decide yourself; pick sensible defaults and record them.
- Then produce and get my approval on: CLAUDE.md (short: rules, commands, conventions), docs/SPEC.md, docs/ARCHITECTURE.md (Mermaid diagrams), docs/DECISIONS.md (short ADRs with rejected alternatives), docs/THREAT-MODEL.md.
- Don't rely on memory for vendor APIs (UniFi, Proxmox, Docker, Ubiquiti NAS). Check current official docs online and cite source and version in DECISIONS.md. UniFi's APIs have changed a lot recently.
- Work in milestones (section 8). Each ends with: tests green, ruff and mypy clean, a demo command I can run, and a short summary. Then STOP and wait for my go-ahead.
- Small commits, Conventional Commits. Never push; I push with GitHub Desktop.
- Never ask for, read, print or store real credentials. Don't read .env, secrets/ or ~/.ssh. Develop against mocks and a synthetic demo lab (section 7).
- I'm a network engineer / MSP admin and a PhD researcher in AI. Be technical and skip basic explanations. Keep status updates short.

## 1. Goal
A tool that AUTOMATICALLY discovers and documents my homelab and keeps it current, so I never maintain docs by hand. NetBox is a manual source of truth; this is auto-discovery first, with a thin human-annotation layer on top. Outputs: a web UI with topology views, exportable Markdown/MkDocs/JSON/CSV, and a read-only MCP server so Claude can answer questions about my lab.

## 2. Environment to discover
- Proxmox VE (ask: cluster or standalone), many VMs and LXCs, mostly Linux, many running Docker Compose.
- UniFi network (gateway, switches, APs) managed from a UniFi OS console; a Ubiquiti UNAS; Raspberry Pi(s); possibly Windows VMs (stretch goal).
- Dev: Windows workstation, Docker Desktop. Prod: a small dedicated VM/LXC on Proxmox running docker compose, with the image built by GitHub Actions to GHCR from this private repo.

## 3. Non-goals
No changes to any target, ever. No remediation. No metrics time-series or alerting (inventory and change tracking only). No cloud dependency. No internet exposure. No agent daemons on targets.

## 4. Security requirements (non-negotiable)
1. Read-only by construction, enforced in TWO layers: in code (HTTP client wrapper allows only GET plus an explicit list of documented read-only POST queries; SSH runner allows only allowlisted commands as fixed argv, never shell=True, never string interpolation) AND on the target (least-privilege account). Tests must prove refusals and try bypasses (injection, chaining, encoding tricks).
2. SSH: dedicated user and dedicated ed25519 key per target or group, pinned host keys, StrictHostKeyChecking on. WARNING: docker-group membership is root-equivalent, so do NOT use it. Evaluate and recommend one option in an ADR: (a) a root-owned read-only probe script on each target, invoked via a forced command, emitting JSON; (b) sudoers restricted to exact read-only docker commands; (c) a read-only docker-socket-proxy bound to a private interface. Generate the setup artifacts (script, sudoers file, authorized_keys line) under docs/targets/ for ME to review and install. You never touch targets.
3. Proxmox: API token with PVEAuditor, privilege separation on. UniFi: LOCAL controller API only (no cloud key). If the key cannot be scoped read-only, say so explicitly in SECURITY.md, rely on the GET-only wrapper, and recommend a dedicated limited account.
4. Redaction before anything is stored or logged: env var VALUES, command-line secrets, tokens, passwords, keys, Wi-Fi PSKs. Store env var NAMES only. Raw collector output is never persisted unredacted. Test with nasty fixtures.
5. No secrets in git: .env.example only, Docker secrets, gitleaks in pre-commit and CI, SSH keys mounted read-only.
6. Web UI requires auth (local admin with argon2, OIDC optional later), CSRF protection, secure headers, runs behind a reverse proxy. MCP server is read-only (stdio, plus HTTP with bearer token).
7. Append-only audit log of every SSH command and API request (target, command/endpoint, duration, status). No secrets in it.
8. The database is a full map of my network, so treat it as sensitive. Exports have a `--sanitize` mode (fake IPs, MACs, hostnames) for public screenshots and the demo.
9. Supply chain: lockfile with pinned deps, non-root container, minimal base image, read-only root FS where possible, pip-audit and Dependabot in CI.

## 5. Functional requirements
Discovery and inventory
- Seed candidates from Proxmox (VMs/LXCs, guest-agent IPs) and UniFi (devices, clients). Reconcile with a hosts.yaml I maintain (name, address, type, collectors, credential reference). Show an "unknown devices" page: seen on the network, not in inventory.
- Stable entity identities (cluster+vmid, MAC, compose project+service, etc.) so diffs are meaningful.

Collectors (plugin interface; Pydantic output models; each declares the commands/endpoints it needs; each fails independently and partial results are OK)
- proxmox: nodes, VMs, LXCs, resources, storage, bridges/VLANs, backup jobs and status.
- unifi: devices, ports, VLANs/networks, SSIDs, clients, firewall rules, uplinks/links.
- linux-ssh: OS, kernel, interfaces/IPs/routes, listening ports with owning process, disks/mounts, systemd services, cron, local users (no secrets), key packages.
- docker: containers, images and tags, compose projects, networks, volumes, published ports, restart policy, health. Env NAMES only.
- nas (UNAS): research what's available; best-effort, fallback to manual YAML.
- raspberry-pi: linux-ssh plus temperature and throttling.
- stretch: Windows via read-only WinRM/PowerShell.

Annotations: owner, purpose, criticality, tags, notes, links per entity, stored separately from discovered data, surviving rescans, editable in the UI or as git-friendly YAML (annotations/*.yaml).

Change tracking: normalized current state plus redacted snapshots; diff ignoring volatile fields (uptime, counters, load, timestamps); events like "image updated", "port opened", "new device on VLAN 20", "host unreachable".

Scheduler: per-collector intervals, jitter, concurrency limits, timeouts, backoff, one scan lock, manual trigger.

UI: dashboard (counts, last scan, recent changes, offline/unknown), host pages, global IP/VLAN/port tables with search, interactive topology (physical: gateway > switches > APs/hosts; logical: node > VM > containers; VLAN membership), changelog timeline, annotation editor, light/dark.
Exports: Markdown/MkDocs site, JSON, CSV, Mermaid.
MCP tools: list_hosts, get_host, list_containers, search_ip, find_service, what_changed, list_unknown_devices.
CLI: `atlas scan [--host] [--collector]`, `atlas diff`, `atlas export [--sanitize]`, `atlas doctor` (checks target setup).

## 6. Tech defaults (propose changes via ADR if you disagree)
Python 3.12 + uv, FastAPI, SQLAlchemy 2 + Alembic, SQLite (WAL) for v1 but Postgres-compatible, Pydantic v2, asyncssh, httpx, APScheduler, Jinja2 + HTMX + Cytoscape.js (no Node build step; vendor JS locally, no CDN at runtime), official MCP Python SDK, pytest, ruff, mypy (strict on security modules), multi-stage Dockerfile, docker-compose.yml, GitHub Actions (lint, test, gitleaks, build, push to GHCR). Make sure everything runs on Windows for dev and Linux for prod.

## 7. Develop without my real lab
Build a synthetic demo lab in fixtures/demo-lab/ (about 25 hosts: Proxmox node, Linux VMs, Docker hosts, a Pi, UniFi gear, a NAS) with realistic recorded/mocked API and command outputs, including nasty cases: secrets in env vars, unicode hostnames, an offline host, containers without compose, IPv6, trunked VLANs. It drives tests, UI development and README screenshots.

## 8. Milestones
- M0: Plan approved, repo scaffolding (pyproject, CI, pre-commit, Makefile, CLAUDE.md), docs skeleton.
- M1: SECURITY CORE FIRST: SSH allowlist runner, read-only HTTP client, redaction, audit log, with exhaustive tests before any collector exists.
- M2: Data model, hosts.yaml loader, linux-ssh collector, SQLite, snapshots, diff engine, CLI. Acceptance: scan the demo lab in state A and B, then `atlas diff` shows the right changes.
- M3: docker and proxmox collectors.
- M4: unifi, nas, pi collectors; unknown-device reconciliation.
- M5: Web UI, topology, annotations, auth.
- M6: Scheduler, exports, sanitize mode, MCP server.
- M7: Hardening and release: README with architecture diagram, SECURITY.md, docs/SETUP-TARGETS.md (step-by-step for me to create the read-only accounts), docs/DEPLOY.md (Proxmox VM + compose + backup + upgrade), CI to GHCR, then an independent security review pass of the whole repo.

## 9. First action
Do the settings copy, enter plan mode, then summarize your understanding in at most 10 lines, list your assumptions, ask your single batch of questions, and propose the milestone plan. Do not write code yet.
