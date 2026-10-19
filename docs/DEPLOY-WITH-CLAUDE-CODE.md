# Deploy atlas on a VM with Claude Code

Paste the prompt below into Claude Code running **on the VM that will host atlas**. Your Proxmox,
UniFi and VMs only need to be reachable from that VM. Claude Code installs atlas there and nowhere
else.

What you do yourself, and never paste into the chat:
- your GitHub login/token (clone and `docker login ghcr.io`);
- the atlas account password;
- the Proxmox token, UniFi API key and SSH passwords. You type those in atlas's web UI.

---

```text
You are deploying "atlas" (repo FouadHellal/Homelab-Docs), a read-only homelab documentation
tool, on THIS machine using Docker. Work step by step, explain briefly what you do, and stop to
ask me whenever a step needs my credentials or changes system configuration.

Hard rules:
- Only change THIS machine. Never SSH into, configure or install anything on my other machines,
  my Proxmox, or my UniFi gateway. atlas itself only reads them; you don't touch them at all.
- Never ask me to paste passwords, tokens or API keys into this chat, and never print or read
  files under /opt/atlas/secrets. Where a credential is needed, tell me the exact command or
  page and let me type it myself.
- Ask before installing packages, changing the firewall, or running anything with --purge.

Steps:

1. Check the machine. Report OS/version, CPU/RAM/disk (need ~1 vCPU, 1 GB RAM, 10 GB free),
   the LAN IP(s), whether docker and the docker compose plugin are installed (`docker compose
   version`), and whether git is installed. If Docker is missing, propose installing it from
   Docker's official apt repository (https://docs.docker.com/engine/install/) and wait for my OK.
   Check that I can reach the VM on port 8443 from my LAN (ufw/nftables status). If a firewall
   blocks it, propose a rule that allows 8443 only from my LAN subnet and wait for my OK.

2. Get the code. The repo is private. If `gh` is installed, ask me to run `gh auth login`;
   otherwise tell me to create a fine-grained GitHub token (Contents: read, Packages: read) and
   run the clone myself:
     git clone https://github.com/FouadHellal/Homelab-Docs.git ~/Homelab-Docs
   Then read ~/Homelab-Docs/README.md (sections "Deploy", "First login", "Add your homelab",
   "Troubleshooting") and follow it as the source of truth.

3. Let the image be pulled instead of built. Ask me to run this myself (it asks for my token):
     sudo docker login ghcr.io -u FouadHellal
   If I skip it, the installer builds the image from the clone instead (a few minutes), which is
   fine too.

4. Install. Run:
     cd ~/Homelab-Docs && sudo ./deploy/atlas.sh install --no-user
   (--no-user because you can't type a hidden password for me.) Wait for "healthy". Then show me
   `sudo ./deploy/atlas.sh status` and `cat /opt/atlas/.env` (not secrets/). Make sure
   ATLAS_HOSTS contains the VM's LAN IP and any DNS name I'll use. If I give you a name, add it
   (comma-separated) and run `sudo ./deploy/atlas.sh start`.

5. Verify:
     curl -sk https://127.0.0.1:8443/healthz      -> must print ok
     sudo docker compose --project-directory /opt/atlas ps   -> atlas "healthy"
   Fix anything that fails, using README "Troubleshooting" and `sudo ./deploy/atlas.sh logs`.

6. First account. Tell me to EITHER run, in my own terminal on this VM:
     cd ~/Homelab-Docs && sudo ./deploy/atlas.sh user add admin
   OR open https://<VM-IP>:8443/setup in my browser and use the one-time setup token shown by:
     sudo ./deploy/atlas.sh logs     (line "First run: ... setup token ...")
   Tell me the certificate fingerprint printed by `atlas.sh status`, so I can compare it when the
   browser warns about the self-signed certificate.

7. Walk me through adding my homelab in the web UI (Targets page). I type every credential
   myself:
   a) Proxmox: show me the 4 `pveum` commands from README "1. Proxmox" so I can create a
      read-only PVEAuditor token ON PROXMOX MYSELF. Then: Targets → Proxmox VE → + add → node IP
      → token → Fetch certificate → tick → Save → Test connection.
   b) UniFi: ask which key I have. A key from the UniFi Network app on the gateway = "Local key"
      (gateway IP, Fetch certificate). A key from unifi.ui.com → Settings → API Keys =
      "unifi.ui.com key" (Find my consoles, pick the gateway). Save → Test connection → Scan.
   c) VMs/servers/Raspberry Pis: Targets → Machines → + add, or "Add as target" on the Unknown
      page (it pre-fills IP and name). SSH username + password (tick "use for sudo" for Docker
      details), or the SSH-key option. Fetch host key, and tell me to compare the fingerprint
      on the VM's console with: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
      Then Test login → Scan.
   After each Scan, read `sudo ./deploy/atlas.sh logs` and help me fix any failed or partial
   result (wrong key type, SSH password login disabled, missing sudo, certificate changed...).

8. Wrap up. Show me how to update (git pull && sudo ./deploy/atlas.sh update), back up
   (sudo ./deploy/atlas.sh backup), and remind me to store /opt/atlas/secrets/atlas_master_key
   somewhere safe OFF this VM (I copy it myself; don't display it). Finish with a short summary
   of what is running, the URL, and anything still failing.
```
