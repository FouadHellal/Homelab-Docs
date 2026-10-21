# Changelog

All notable changes. Versions follow [SemVer](https://semver.org/); dates are UTC.

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
