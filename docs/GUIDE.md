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

UniFi gives you switches, APs and clients with the port or AP each one is on, and the IP, VLAN,
switch and switch port of every Proxmox VM, matched by MAC (no guest agent needed). Switch ports
come from the Network app's older client list; if your key isn't allowed there, everything else
still works and ports are just left out. Devices you haven't
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

### Jellyfin

Targets → Jellyfin → **+ add**: a name, the address, and an API key created in Jellyfin under
*Dashboard → API Keys → +* (call it "atlas" so you can revoke it alone). If Jellyfin answers on
plain `http://<LAN IP>:8096`, tick *Plain HTTP on my LAN*; HTTPS (port 8920 or a reverse proxy)
is better because the key then never crosses the network in clear text. Set *Machine running
Jellyfin* to its atlas target (or leave it empty to match by IP): that machine's SSH scan tells
whether the library folders are really on the NAS.

The key can do anything in Jellyfin (keys are not scoped), so atlas only lets itself make six GET
calls: server info, sessions, item counts, libraries, scheduled tasks and recently added items.

### n8n notifications (optional)

1. In n8n, import `docs/integrations/n8n/atlas-notifications.json`. Give its *atlas webhook* node
   a Header Auth credential: name `Authorization`, value `Bearer <a long random token>`. Replace
   the last node with Telegram, Discord, email or anything else, then **activate** the workflow
   and copy its production URL (`…/webhook/atlas`).
2. In atlas: Integrations → paste the URL and the token (the part after `Bearer `), tick
   *Plain HTTP on my LAN* only if n8n runs on `http://<LAN IP>:5678`, Save, **Send a test
   notification**. An `https://` name with a normal certificate (Let's Encrypt, a reverse
   proxy) works as is; for a self-signed one put its PEM in the config dir and set
   `ATLAS_N8N_CA_FILE`.

atlas then posts one JSON message when an incident opens (after it has lasted 5 minutes) and
when it resolves, a reminder every day while it stays open and unacknowledged, one digest per
scan with the notable changes (new unknown device, VM stopped, container unhealthy…), a daily
summary at 07:00 UTC, and a diagnosis when you press *Send diagnosis to n8n* on the Media page.

Choose what you get under **Integrations → What to send**: incidents, recoveries, reminder
interval, digest level (warnings only, warnings and notices, off), daily summary, quiet hours
(only warnings get through) and the address you open atlas with, so every email has an
*Open in atlas* button. **Send the daily summary now** sends one immediately.

On **Incidents**, *Acknowledge* stops announcements and reminders for one incident (you still
hear when it is resolved) and *Snooze* silences it for 4 hours, a day or a week. Fields: `kind`, `title`, `severity`, `key`, `entity`, `opened_at`,
`resolved_at`, `evidence` (list of strings), `summary` (daily counts).

### Taskora tickets and CMDB (optional)

With [Taskora](https://github.com/FouadHellal/Taskora) 0.3.0 or later, incidents become
tickets, technicians' acknowledgements come back to atlas, and atlas's machines reconcile with
Taskora's CMDB. Setup and operations: [integrations/taskora.md](integrations/taskora.md).

## Pages

| Page | What's there |
|---|---|
| Command Center | The home page: overall health, open incidents, cards (nodes, VMs, LXCs, containers, network devices, apps, storage, unknown devices) that open the matching list, what needs attention, recent changes with filters, every recognised app with its state (healthy / degraded / down / stale / unknown), resources at the last scan, quick access to web UIs, data sources |
| Overview | Proxmox nodes and guests, one card per machine with the apps found on it, **Scan now** |
| Media | Jellyfin: a diagnosis (API, machine, VM, service, NAS mounts, NAS) with a checklist, now playing (direct play / transcoding, hardware acceleration when Jellyfin reports it), libraries and where their folders really are, failed tasks, media incidents |
| Integrations | Data sources and their freshness; n8n notifications (set up and test here) |
| Topology | Proxmox view (node → bridges → VMs/LXCs), network view (gateway → switches → APs → hosts) and VLANs. Click for details, right-click for actions, PNG export. Keys: `/` `F` `R` `C` |
| Services | Every systemd unit and container on every machine, filterable, with CSV export |
| Apps | Recognised apps and agents (Pi-hole, Home Assistant, Jellyfin, Action1, Zabbix, Wazuh…) and where they run. Click any app, chip or service name for its page: what it is, who makes it, caveats, every machine it runs on with version and state, and search buttons that open in your browser. Unrecognised listening ports are listed too; name one once and it's recognised everywhere |
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
why rather than reinstalling the old code. Options: `--no-pull`, `--no-backup`, `--build`,
`--reset`. If the project's history was rewritten upstream, the update follows it by itself and
keeps the old history as an `atlas-backup-<date>` branch; it refuses only when your clone has
commits of its own, and `--reset` drops those too (still kept in that branch).

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
| `ATLAS_INTERVAL_JELLYFIN` | Jellyfin scan interval (default 300 s) |
| `ATLAS_MEDIA_SHOW_USERS=1` | Show Jellyfin user names on the live Media page (never stored; default: pseudonyms) |
| `ATLAS_DAILY_SUMMARY_HOUR` | Hour (UTC) of the daily n8n summary, default 7; empty turns it off |
| `ATLAS_N8N_WEBHOOK_URL`, `ATLAS_N8N_ALLOW_HTTP`, `ATLAS_N8N_CA_FILE` | n8n webhook set by environment instead of the Integrations page |
| `ATLAS_MODE=proxy` | Serve plain HTTP on 127.0.0.1:8080 behind your own reverse proxy ([DEPLOY.md](DEPLOY.md)) |

## Troubleshooting

| Symptom | Fix |
|---|---|
| Login page reloads without logging in | Use `https://`. The session cookie is HTTPS-only. |
| "Invalid host header" | Add the name or IP you used to `ATLAS_HOSTS`, then `sudo atlas start`. |
| `install` builds the image instead of pulling it | The registry pull failed (network, or no access to the package). Building from the clone works just as well. |
| VM test login: *authentication refused* | Wrong credentials, or the VM has `PasswordAuthentication no`. Use the SSH key option. |
| VM scan is *partial* | No sudo, so Docker details, port owners and root crontabs are missing. Tick *use for sudo*. |
| docker: *failed*, "could not be read" | Docker is installed but the login can't read it. Tick *use for sudo* (or add the login to the `docker` group). Machines without Docker now show *ok*. |
| Proxmox: *HTTP 401* | The token id or secret is wrong: the id is `user@realm!name`, the secret is the UUID shown once. *HTTP 403*: give the token PVEAuditor on `/`. |
| The browser doesn't fill in the saved password | Browsers only auto-fill on `https://` pages; on plain HTTP click the username field and pick the saved login. |
| UniFi cloud: *the key was refused* | A unifi.ui.com key entered as Local, or the other way round. |
| UniFi local: certificate error | The gateway's certificate changed (often after an update). Fetch and confirm it again. |
| Media says *storage not mounted* but Jellyfin plays | The library folder exists on the machine's own disk: the NAS share is not mounted there (files may be cached or partly present). Check `findmnt /mnt/…` and the share on the NAS; atlas never remounts it. |
| Media checks show *unknown* | atlas has no SSH scan of the Jellyfin machine. Add it on Targets and set *Machine running Jellyfin*. |
| n8n test: *HTTP 404* | The workflow is not active, or you pasted the test URL (`/webhook-test/…`) instead of the production one. |
| No Proxmox nodes or VMs anywhere | The token lacks PVEAuditor itself; run the last `pveum acl modify … --tokens` line above. Or add a node as `proxmox-node`. |
| `sudo atlas update` changed nothing | Check `sudo atlas version`. If the commit is old, `git pull` failed: it says why. History rewritten upstream and you never commit on the server: `sudo atlas update --reset`. Otherwise run `git pull` yourself in the clone, then `sudo atlas update --no-pull`, then Ctrl+F5. |
| A machine never gets documented | Check its last scan on Targets. *Not scanned yet*: press Scan. *Failed*: open it for the reason. |
| A box shows no services | It isn't a target yet. Add it as a machine and scan it. |
