# Changelog

All notable changes. Versions follow [SemVer](https://semver.org/); dates are UTC.

## 0.8.0 (2026-11-02)

### Added
- **Command Center** is the new home page (the old dashboard is now *Overview*): overall health,
  open incidents, clickable summary cards, what needs attention, recent changes with filters,
  every recognised app with an evidence-based state (healthy, degraded, down, stale, unknown),
  resources at the last scan, quick access to web UIs and data source freshness.
- **Jellyfin** as a target (Targets → Jellyfin): server health, live sessions with direct
  play / transcoding and hardware acceleration when reported, libraries, failed scheduled
  tasks, recently added. User names are never stored.
- **Media** page: a diagnosis that tells "Jellyfin down" from "VM down", "service stopped",
  "NAS share not mounted" (folder on the local disk), "NAS down", "network?" and "stale data",
  with a checklist and the dependency chain.
- **Incidents**: deduplicated, with recovery; **n8n notifications** (incident opened/resolved,
  daily summary, diagnosis on request) configured on the new Integrations page. Importable
  workflow in `docs/integrations/n8n/`.
- MCP: `media_status`.
- Plain `http://` is accepted for Jellyfin and n8n only when you opt in, and only to a private
  LAN IP address (ADR-039).

## 0.7.0 (2026-11-01)

### Added
- A new look: left sidebar with icons, a real logo, the Geist font, a violet-to-cyan theme in
  dark and light, and a phone layout (menu drawer, stacked cards, tables that scroll inside
  their card).
- App pages: click any app, chip or service (for example the Action1 agent) to see what it is,
  who makes it, what to watch out for, every machine it runs on with version and state, and
  search buttons that open in your browser. Also in Ctrl+K and for Claude (`describe_app`).
- Recognises more agents: Action1, Tactical RMM, MeshCentral, Wazuh, Checkmk, Datadog,
  Telegraf, Promtail, Cloudflare Tunnel, ZeroTier, NetBird, Watchtower, QEMU guest agent.

### Fixed
- Proxmox view: a node scanned over SSH could appear twice (the node with its VMs, plus an
  empty box for the same machine), so nodes and VMs looked mixed up.
- Saved passwords: the login form now uses the fields password managers look for.
- VLAN members, long target URLs and docs tables no longer spill out of their cards.
- A machine without Docker no longer shows *docker: failed*; unreadable Docker and refused
  Proxmox tokens say what to do.

## 0.6.0 (2026-11-01)

### Added
- Switch ports: the network view labels every wired link with its port, and machine cards, the
  machine page, the Proxmox side panel and MCP (`plugged_into`) say "sw-rack · port 5". Read
  from UniFi's classic client list with the same key; left out if the key is refused there
  (ADR-037).
- `sudo atlas update` follows a rewritten upstream history (the old one is kept as an
  `atlas-backup-<date>` branch) instead of failing on `git pull`; `--reset` also drops commits
  made on the server.
- MCP machine rows include `network` and `vlan`.

### Changed
- The repository is public. The README is shorter; setup per target, pages, settings and
  troubleshooting moved to `docs/GUIDE.md`.
- Docs no longer assume a private repository or a private GHCR package.
- `atlas mcp --http --allow-scan` is refused: live scans stay on stdio (ADR-036).

### Fixed
- `--sanitize` exports and MCP answers let all-caps names (`DC01`, `NAS-01`) through.
- Sanitized MCP `get_host` still returned annotation tags and criticality.
- The MCP size cap could recurse until `RecursionError` on one oversized item.
- One crashing collector (e.g. a proxy's HTML page instead of JSON) aborted the whole scan;
  it is now a failed run for that target only.
- A Proxmox cluster of 3+ nodes with 2+ nodes scanned over SSH rolled back every scan
  (both nodes reported the same peer).
- API-only Proxmox nodes were listed as unknown devices.
- `HttpLimits.total_s` was never enforced, so a slow drip of data never timed out.
- `atlas serve` and a CLI or MCP scan in the same container forked the audit chain;
  appends now take a file lock.
- A failing manual scan stopped the queue, leaving the rest stuck as "queued".
- Logging in after following a link dropped its query string (422 on `/entity?key=…`).
- Adding a target with an existing name, or renaming onto one, silently replaced it and
  its stored credential.
- Malformed manual UNAS YAML and an `apps:` mapping in `custom-apps.yaml` crashed instead
  of being reported or ignored.
- `atlas backup` failed if an interrupted earlier backup left `/data/backup.db` behind.

## 0.5.1 (2026-10-22)

### Fixed
- `./deploy/atlas.sh` and the `sudo atlas` shortcut failed with "command not found" on Linux:
  the scripts were committed without the executable bit. They are executable in git now, and the
  shortcut sets the bit itself. If an old clone still says "command not found", run
  `sudo bash deploy/atlas.sh update --no-pull` once.

## 0.5.0 (2026-10-22)

### Added
- **Ask Claude about your homelab.** The MCP server gains machine-level tools:
  - `whats_running`: apps, running and failed services, containers, ports, top processes, timers;
  - `list_machines`, `list_services`, `proxmox_overview`, `scan_status`, `unrecognised_ports`;
  - `what_changed` now takes `machine`;
  - machines resolve by name, IP or key, and every answer carries the last scan time and result.
- **Live checks, opt-in.** `atlas mcp --allow-scan` adds `scan_machine`: Claude can ask for a
  fresh read-only scan of one machine (at most once a minute per machine), then read the result.
- **Two-command setup over SSH.** `sudo atlas mcp-allow <user> [--allow-scan]` writes a
  `visudo`-checked rule for exactly `atlas mcp`, and prints the `claude mcp add` line.
  `sudo atlas mcp` runs the server inside the atlas container. No port, token or certificate is
  needed. Guide: `docs/MCP.md` (Claude Code, Claude Desktop, HTTP, privacy).

### Fixed
- Logs go to stderr instead of stdout, so they can no longer break an MCP stdio session.

## 0.4.1 (2026-10-21)

### Security
- certifi 2026.10.19: the 2026.10.18 bundle shipped emSign root CAs whose intermediate keys
  were compromised ([GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2),
  PYSEC-2026-4320). atlas uses that bundle only to verify `api.ui.com` (UniFi cloud keys).
  certifi is now a declared dependency, with that version as its minimum.

## 0.4.0 (2026-10-21)

Ideas from a review of similar tools (Homelable, Scanopy) and of the UI.

### Added
- **Unrecognised listening ports, and naming them.**
  - The Apps page lists every listening port no app explains, grouped by what would identify it:
    a container image, a process, or, for generic processes like `python3` or `docker-proxy`,
    the port on that machine.
  - **Name it** once, and it is recognised from then on everywhere: machine cards, topology,
    Services, exports.
  - Your rules are kept in `custom-apps.yaml` in the data volume, listed under *Your app rules*,
    and can be removed.
- **Changes page:** time range (24 h / 7 days / 30 days), a per-machine filter (the machine, its
  VM/host twin and its containers), a summary by severity and type with one-click filters, and
  **CSV export** of what you filtered.
- **Exports page:** download the Markdown report, CSV tables (zip), JSON or Mermaid diagrams
  from the browser, each optionally **sanitized** (names, IPs and MACs pseudonymised) for sharing.
- **Diagnostics page:** versions, database, audit-log check, scheduler, every target's latest
  errors, and a downloadable **support report** for issues.
- **Machine page summary:** IP, OS, node, size, network and last scan at the top, with
  *Show on topology* (opens the topology focused on it), *All services*, *Open <app>*,
  *Copy SSH* and *Scan now*.
- **Topology:**
  - drag nodes and the layout is kept, per view and per browser;
  - *Lock layout* and *Reset my layout* in the background menu;
  - containers follow their moved machine;
  - `?focus=<machine>` links.
- **Targets:** a status summary (ok / partial / failed / not scanned), **Scan failed & new**, and
  **Scan everything**.

### Fixed
- Pages no longer print `None`, `True` or `False`: they show blank, yes or no.
- The docs page opens without logging in. It is linked from the login page and holds no inventory
  data.
- A NAS (or any target read through an API) no longer shows "waiting for its first scan".
- The "Contains" list on machine pages is collapsed instead of repeating the container table.

## 0.3.1 (2026-10-19)

### Fixed
- **`sudo atlas update` could change nothing.** git ran as root, which has no GitHub login for a
  private repository, so the pull failed, only a warning was printed, and the old code was rebuilt.
  git now runs as the clone's owner. A failed pull stops the update with the exact commands to run.
  The container is always recreated, and the update prints `updated: <old> -> <new>`, or a warning
  if nothing changed.
- Browsers kept old JavaScript and CSS after an update: static URLs now carry a content hash.
- `atlas version` also shows the clone's last commit.

## 0.3.0 (2026-10-19)

### Fixed
- **Machines that were added but never documented.** Pressing *Scan* while another scan was
  running was silently dropped. Scans are now queued and merged, so nothing is lost, and saving
  a target queues its first scan right away.
- **Hidden failures.** "Needs attention" only looked at the very last scan, which was often a
  small scheduled UniFi or Proxmox one. The dashboard and the new *Last scan* column on Targets
  now show every target's latest result, with the reason when it failed.
- **No Proxmox data with an API source configured.** Reading `/etc/pve` over SSH is now always
  on. The API wins where it answers, and SSH fills in when the token is missing or can't see
  anything.
- **A Proxmox token that sees nothing** (privilege separation without a token permission) is now
  explained, both in *Test connection* and on the scan, and no longer marks guests as removed.

### Added
- **Proxmox topology, node first:**
  - one box per node, holding the node, its bridges, and its VMs and LXCs, each wired to the
    bridge its NIC uses, with traffic pulses on running guests;
  - one node is enough to see the whole cluster;
  - summary cards: guests, vCPU and RAM allocated;
  - richer right-click menus: scan this machine, copy IP or MAC or SSH command, show only this,
    show containers of all guests;
  - keyboard shortcuts.
- **Services page:** every systemd unit and container on every machine, filtered by machine,
  state, type or text, with **CSV export** of exactly what you see.
- In-app **documentation** at `/docs`, grouped menus, a **Ctrl+K quick find**, and a star
  favicon.
- Proxmox `ostype` codes are shown as words (`l26` → Linux).
- MIT license, contributing guide, code of conduct, and issue and PR templates.

## 0.2.0 (2026-10-19)
- Probe 1.4.0: processes, Proxmox VE over SSH (`/etc/pve`), and a text fallback for services.
- App recognition (about 70 apps), the Running page, a host Running panel, grouped IP table,
  new dashboard and Proxmox topology.
- One-command `sudo atlas update` that keeps all data (pre-update backups, the last 5 kept).

## 0.1.0
- First version:
  - read-only collectors for Proxmox, UniFi (local and cloud keys), Linux, Docker, Pi and UNAS;
  - a web UI with Targets onboarding and an encrypted vault;
  - exports, MCP, scheduler;
  - a Docker image and installer.
