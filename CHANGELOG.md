# Changelog

All notable changes. Versions follow [SemVer](https://semver.org/); dates are UTC.

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
