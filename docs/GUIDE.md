# User guide

How to add your machines, what each page shows, how updates work, and what to do when
something goes wrong. Installation is in the [README](../README.md#deploy); the details behind
it are in [DEPLOY.md](DEPLOY.md). The same guide is built into the app at `/docs`.

## First login

Open the address the installer printed. Your browser warns about the self-signed certificate
once: compare it with the fingerprint the installer showed, then accept it. Log in with the
account you created during install.

There is no default password. If you installed with `--no-user`, the first visit shows a setup
page that asks for a one-time token from `sudo atlas logs`.

```bash
sudo atlas user add alice      # another account
sudo atlas user passwd admin   # reset a password
```

## Adding your homelab

Everything is added from the **Targets** page.

### Proxmox

Targets → Proxmox VE → **+ add**. Give it a node's IP and a read-only API token. On any node:

```bash
pveum user add atlas@pve
pveum acl modify / --users atlas@pve --roles PVEAuditor
pveum user token add atlas@pve collector --privsep 1      # copy the secret it prints
pveum acl modify / --tokens 'atlas@pve!collector' --roles PVEAuditor
```

Paste the token as `atlas@pve!collector=<secret>`, click **Fetch certificate**, check the
fingerprint, tick the box and save. Then **Test connection**.

Don't skip the last `pveum` line: with privilege separation on, the token needs its own role, or
atlas connects fine but sees no nodes.

No token? Add a Proxmox node as a machine of type `proxmox-node` (with sudo) instead. atlas
then reads `/etc/pve` over SSH, which gives the cluster members and every guest's config. One
node is enough to see the whole cluster; add them all to also get each guest's running state.
`/etc/pve/priv` is never read.

### UniFi

Targets → UniFi gateway → **+ add**, then pick the kind of key you have:

| Key from | Choose | Then |
|---|---|---|
| The Network app on the gateway (Integrations / API key) | **Local key** (no internet needed) | Gateway IP, key, **Fetch certificate**, tick, save |
| unifi.ui.com → Settings → API Keys | **unifi.ui.com key** | Key, **Find my consoles**, pick the gateway, save |

The cloud option goes through Ubiquiti's connector at api.ui.com, which allows 100 requests a
minute; atlas paces itself. Either way atlas only sends GET requests and never reads Wi-Fi
passwords.

UniFi gives you switches, APs and clients with the port or AP each one is on, and the IP, VLAN
and switch of every Proxmox VM, matched by MAC (no guest agent needed). Devices you haven't
added show up under **Unknown**: servers, Pis and NAS boxes first, with an **Add as target**
button; phones, TVs and IoT stay hidden behind *show everything*.

### VMs, servers and Raspberry Pis

Targets → Machines → **+ add a VM / host**. Enter the IP and pick what to collect: Linux
(services, ports, packages, users, disks, cron), Docker (containers, images, networks, volumes,
compose projects) and Raspberry Pi where it applies. Then choose how atlas logs in:

| Login | What you do | Notes |
|---|---|---|
| Password | SSH username and password | Nothing installed. Tick *use for sudo* to get Docker and process details. |
| SSH key | Add the key line shown on the page to the user's `~/.ssh/authorized_keys` | Nothing installed, no password stored. |
| SSH key + probe | Install the read-only probe from `docs/targets/` ([SETUP-TARGETS](SETUP-TARGETS.md) §2) | The VM itself enforces read-only. |

Click **Fetch host key** and compare it with
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the VM before saving. Then **Test login**
and **Scan**.

`root` logins are refused; use a normal user, with sudo if you want Docker details. Passwords
and keys are stored encrypted and never shown again. Process command lines are redacted before
they're stored.

## Pages

| Page | What's there |
|---|---|
| Dashboard | Proxmox nodes and guests, one card per machine with the apps found on it, targets that need attention, undocumented devices, recent changes, **Scan now** |
| Topology | Proxmox view (node → bridges → VMs/LXCs), network view (gateway → switches → APs → hosts) and VLANs. Click for details, right-click for actions, PNG export. Keys: `/` `F` `R` `C` |
| Services | Every systemd unit and container on every machine, filterable, with CSV export |
| Apps | Recognised apps (Pi-hole, Home Assistant, Jellyfin, NetBox, Grafana…) and where they run. Unrecognised listening ports are listed too; name one once and it's recognised everywhere |
| Inventory | Every machine: OS, network, ports, what's running, disks, users, notes, history |
| IPs, VLANs, Ports | Searchable tables |
| Changes | Port opened, image updated, container restarted, new device on a VLAN, VM not backed up… with filters and CSV export |
| Unknown | Devices on the network you haven't added |
| Targets | Add and edit targets; each shows its last scan result and why it failed |
| Exports | Markdown, CSV (zip), JSON, Mermaid, each also available sanitised for sharing |
| Diagnostics | Versions, database, audit-log check, scheduler, recent errors, and a support report for bug reports |

**Ctrl+K** jumps to any page, machine or app.

UniFi and Proxmox are scanned every 15 minutes, machines every hour, and a new target right
after you save it. Manual scans are queued, so pressing Scan on five machines scans all five in
turn.

## Updating

```bash
sudo atlas update
```

This fast-forwards your clone (`git pull --ff-only`, as the clone's owner), writes a backup to
`/opt/atlas/backups/pre-update-<date>.tar.gz` (the last 5 are kept), pulls or rebuilds the
image and restarts. It prints the old and new version. If the pull fails it stops and tells you
why rather than reinstalling the old code. Options: `--no-pull`, `--no-backup`, `--build`.

Targets, credentials, accounts, notes and history live in the data volume and in `/opt/atlas`
(`.env`, `secrets/`, `config/`). Updates never touch them, and database migrations run on start.

**Back up `/opt/atlas/secrets/atlas_master_key` yourself.** The backup archive leaves it out on
purpose. Without it the stored credentials can't be decrypted; the inventory survives but you'd
have to re-enter them.

## Settings

Settings live in `/opt/atlas/.env`. Run `sudo atlas start` after editing.

| Setting | Meaning |
|---|---|
| `ATLAS_HOSTS` | Names and IPs you open atlas with, comma-separated. Add your DNS name here. |
| `ATLAS_PORT` | Published port (default `8443`) |
| `ATLAS_INTERVAL_UNIFI`, `…_PROXMOX`, `…_LINUX_SSH`, `…_DOCKER` | Scan intervals in seconds; `0` turns one off |
| `ATLAS_SNAPSHOT_DAYS` | How long detailed snapshots are kept (default 90; the change history is kept forever) |
| `ATLAS_MODE=proxy` | Serve plain HTTP on 127.0.0.1:8080 behind your own reverse proxy ([DEPLOY.md](DEPLOY.md)) |

## Troubleshooting

| Symptom | Fix |
|---|---|
| Login page reloads without logging in | Use `https://`. The session cookie is HTTPS-only. |
| "Invalid host header" | Add the name or IP you used to `ATLAS_HOSTS`, then `sudo atlas start`. |
| `install` builds the image instead of pulling it | The registry pull failed (network, or no access to the package). Building from the clone works just as well. |
| VM test login: *authentication refused* | Wrong credentials, or the VM has `PasswordAuthentication no`. Use the SSH key option. |
| VM scan is *partial* | No sudo, so Docker details, port owners and root crontabs are missing. Tick *use for sudo*. |
| UniFi cloud: *the key was refused* | A unifi.ui.com key entered as Local, or the other way round. |
| UniFi local: certificate error | The gateway's certificate changed (often after an update). Fetch and confirm it again. |
| No Proxmox nodes or VMs anywhere | The token lacks PVEAuditor itself; run the last `pveum acl modify … --tokens` line above. Or add a node as `proxmox-node`. |
| `sudo atlas update` changed nothing | Check `sudo atlas version`. If the commit is old, `git pull` failed: run it yourself in the clone, then `sudo atlas update --no-pull`, then Ctrl+F5. |
| A machine never gets documented | Check its last scan on Targets. *Not scanned yet*: press Scan. *Failed*: open it for the reason. |
| A box shows no services | It isn't a target yet. Add it as a machine and scan it. |
