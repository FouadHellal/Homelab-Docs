# atlas

[![CI](https://github.com/FouadHellal/Homelab-Docs/actions/workflows/ci.yml/badge.svg)](https://github.com/FouadHellal/Homelab-Docs/actions/workflows/ci.yml)
[![Image](https://github.com/FouadHellal/Homelab-Docs/actions/workflows/image.yml/badge.svg)](https://github.com/FouadHellal/Homelab-Docs/actions/workflows/image.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

I got tired of homelab docs going stale the week after I wrote them, so I wrote something that
figures it out on its own. atlas logs in to your Proxmox, your UniFi gateway and your VMs,
looks at what's there, and keeps an up-to-date picture of it. It only ever reads.

What it collects:

- **Proxmox**: nodes, bridges, every VM and LXC, and how they're wired together.
- **UniFi**: switches, APs, clients, VLANs, and the IP and switch port of each VM (matched by MAC).
- **Each machine** over SSH: OS, systemd services, processes, listening ports, Docker
  containers, packages, disks, users and cron jobs. About 70 common apps (Pi-hole, Home
  Assistant, Jellyfin, NetBox…) are recognised from that.

From that you get a topology view, searchable tables, a change history ("port 8080 opened on
docker01", "image updated", "new device on VLAN 20"), and exports to Markdown, MkDocs, JSON, CSV
and Mermaid. There's also a read-only [MCP server](docs/MCP.md), so an assistant like Claude
can answer "what's running on that VM?" from your actual inventory.

It's beta. I run it on my own lab (two Proxmox nodes, UniFi, about a dozen VMs and Pis) and
every change is tested against a synthetic demo lab. Read the
[known limitations](SECURITY.md#known-limitations-read-these) before pointing it at anything you
care about.

## Read-only, for real

That's the main design constraint, and it's enforced in code, not just promised:

- The HTTP client only sends GET (plus a short list of documented read-only queries). The SSH
  runner only runs a fixed allowlist of commands as argv; no shell, no string building.
- TLS certificates and SSH host keys are pinned when you add a target.
- Secrets in collected output (env values, tokens, passwords, keys) are redacted before
  anything is stored, logged or exported.
- Credentials you enter are encrypted at rest and never shown again. `root` logins are refused.
- For the strictest setup, a small probe on each host plus a sudoers file make the host itself
  refuse anything else ([docs/targets/](docs/targets/)).

Details and the threat model are in [SECURITY.md](SECURITY.md).

## Deploy

You need a small Linux VM or LXC (1 vCPU, 1 GB RAM is plenty) with Docker and the compose
plugin, and network access to Proxmox (8006), the UniFi gateway (443) and your VMs (22).

```bash
git clone https://github.com/FouadHellal/Homelab-Docs.git
cd Homelab-Docs
sudo ./deploy/atlas.sh install
```

The installer sets up `/opt/atlas`, generates the key that encrypts your credentials, asks you
to create a login, and prints the HTTPS address and certificate fingerprint. Then open
**Targets** in the web UI and add your Proxmox, UniFi and machines. The
[user guide](docs/GUIDE.md) walks through each one.

Day to day:

```bash
sudo atlas update     # pull, back up the DB, new image, restart
sudo atlas status     # health, address, certificate fingerprint
sudo atlas logs
sudo atlas backup     # DB + config to a .tar.gz
```

Back up `/opt/atlas/secrets/atlas_master_key` somewhere safe. Backups leave it out on purpose,
and without it the stored credentials can't be decrypted.

Running behind your own reverse proxy, MCP setup and the rest are in
[docs/DEPLOY.md](docs/DEPLOY.md).

## Try it without a homelab

The repo ships a fake lab in two states, so you can see everything without touching real
machines. You'll need [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run atlas scan --lab demo:A --fresh && uv run atlas scan --lab demo:B
uv run atlas serve --lab demo    # http://127.0.0.1:8080, login in data/demo-lab/demo-login.txt
uv run atlas diff --lab demo     # the changes between the two states
```

## Development

```bash
uv sync && uv run pre-commit install
uv run poe check                  # ruff, mypy --strict, pytest, gitleaks
uv run atlas selftest security    # every read-only and redaction guard, offline
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the ground rules. The design docs are
[ARCHITECTURE](docs/ARCHITECTURE.md), [SPEC](docs/SPEC.md), [DECISIONS](docs/DECISIONS.md) and
[THREAT-MODEL](docs/THREAT-MODEL.md).

## License

[MIT](LICENSE). The Proxmox "flow" view was inspired by
[ProxMenux](https://github.com/MacRimi/ProxMenux); no code from it is included.
