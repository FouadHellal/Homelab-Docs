# Deploying atlas

One small VM or LXC on Proxmox runs the stack with `docker compose`, behind your existing
TLS reverse proxy. atlas is a LAN tool: **never publish it to the internet**.

```
┌───────────────── atlas VM/LXC ─────────────────┐
│ reverse proxy (TLS) ──► atlas :8080  (UI, scheduler)
│                        mcp   :8765  (optional, bearer)
│ volume atlas-data: atlas.db (WAL), audit/, redaction.key
│ ./config (ro): hosts.yaml, CA files; ./config/annotations (rw)
│ ./secrets → /run/secrets (Docker secrets, uid 10001, 0400)
└────────────────────────────────────────────────┘
```

## 1. Host

- **Size:** Debian 13 (or Ubuntu 24.04) VM/LXC with 1 vCPU, 1 GB RAM and 10 GB disk is plenty for about 100 targets.
- **Docker:** Docker Engine with the compose plugin. For an LXC: unprivileged, with `nesting=1`.
- **Placement:** a management VLAN that can reach the Proxmox API (8006), the UCG (443) and SSH (22) on the targets. Nothing needs to reach atlas except your proxy.
- **Firewall:** allow inbound only from the proxy (or put the proxy on the same host). Outbound is only to targets: atlas has no cloud or telemetry dependency, and pulls happen only when you run `docker compose pull`.

## 2. Files

```bash
mkdir -p /opt/atlas && cd /opt/atlas
curl -fsSLO https://raw.githubusercontent.com/FouadHellal/Homelab-Docs/main/docker-compose.yml   # or copy it
mkdir -p config/annotations secrets && chmod 700 secrets
```

- **Targets:** follow [SETUP-TARGETS.md](SETUP-TARGETS.md). It covers the SSH key, the Proxmox token, the UniFi key, `config/hosts.yaml` and the CA files.
- **Ownership:** the container runs as **uid 10001**:
  ```bash
  sudo chown -R 10001:10001 secrets config/annotations && sudo chmod 0400 secrets/*
  ```
  Compose file secrets are bind mounts, so `mode:` in the compose file is ignored; host permissions are what count.
- **Environment:** create `.env` next to the compose file (it is never committed):
  ```
  ATLAS_HOSTNAME=atlas.home.arpa
  ATLAS_PROXY_IP=10.0.10.5
  ATLAS_BIND=10.0.10.50
  ```
  - `ATLAS_HOSTNAME` is the name your proxy serves; it is also the Host-header allowlist.
  - `ATLAS_PROXY_IP` is the proxy address, so X-Forwarded-* headers are trusted only from it.
  - `ATLAS_BIND` is the interface to publish on. The default `127.0.0.1` is right when the proxy runs on this host.
- **Unused secrets:** remove any secret you don't use from `docker-compose.yml` (`secrets:` under the service and at the bottom).

## 3. Image

The CI builds `ghcr.io/fouadhellal/homelab-docs` from `main` and from `v*` tags, with an SBOM and provenance attestations, after the Trivy gate passes. The package is private by default:

```bash
echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u <github-user> --password-stdin   # PAT with read:packages only
docker compose pull
```

Pin a version in `.env` (`ATLAS_VERSION=0.1.0`, or a `sha-xxxxxxx` tag) rather than running `latest`. To check the provenance, run `docker buildx imagetools inspect ghcr.io/fouadhellal/homelab-docs:<tag> --format '{{json .Provenance}}'`.

## 4. First start

```bash
docker compose run --rm atlas atlas user add admin     # prompts; argon2id; 12+ characters
docker compose run --rm atlas atlas doctor --live      # fix everything it reports first
docker compose up -d
docker compose ps                                     # atlas should become "healthy"
```

The schedule starts by itself (`--schedule`): UniFi and Proxmox every 15 min, SSH hosts hourly, the NAS every 6 h, with jitter and backoff. The dashboard's **Scan now** runs a full scan immediately. You can tune the intervals with `ATLAS_INTERVAL_<COLLECTOR>` (seconds; `0` disables a collector).

## 5. Reverse proxy (TLS required)

The session cookie uses the `__Host-` prefix and is `Secure`, so login only works over HTTPS. Plain HTTP works only on `localhost`, e.g. through an SSH tunnel.

**Caddy**
```caddyfile
atlas.home.arpa {
    tls internal                     # or your ACME/DNS setup
    reverse_proxy 10.0.10.50:8080
}
```

**Traefik (labels on a proxy-network service, or file provider)**
```yaml
http:
  routers:
    atlas: { rule: "Host(`atlas.home.arpa`)", entryPoints: [websecure], service: atlas, tls: {} }
  services:
    atlas: { loadBalancer: { servers: [{ url: "http://10.0.10.50:8080" }] } }
```

**nginx**
```nginx
server {
    listen 443 ssl; server_name atlas.home.arpa;
    # ssl_certificate ...;
    location / {
        proxy_pass http://10.0.10.50:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

atlas sets CSP, HSTS (`--hsts`, already in the compose file), `X-Frame-Options`, `no-store` and the related headers itself. The proxy doesn't need to add any. Restricting it to your LAN or VPN source ranges is still a good idea.

## 6. MCP (optional)

```bash
openssl rand -base64 36 | tr -d '\n' > secrets/mcp_token && sudo chown 10001 secrets/mcp_token && sudo chmod 0400 secrets/mcp_token
echo "ATLAS_MCP_HOST=atlas.home.arpa:8765" >> .env    # Host header(s) clients use
docker compose --profile mcp up -d
```

- **Client config:** point the client at `http://<host>:8765/mcp` with the header `Authorization: Bearer <token>`. Put TLS in front of it, the same as for the UI, if the client isn't on the same host.
- **stdio:** no network listener at all, e.g. `docker compose exec -T atlas atlas mcp`. Configure your client to run that command.
- **Sanitising:** add `--sanitize` to the `mcp` command in compose if the client sends context to a hosted LLM and you don't want real names and addresses in it (THREAT-MODEL T-MCP).

## 7. Backups and upgrades

- **Back up:**
  - the `atlas-data` volume: DB, audit log and `redaction.key`;
  - `config/`, ideally a private git repo for `hosts.yaml` and `annotations/`;
  - `secrets/`, offline.

  The DB contains redacted but still sensitive topology: encrypt your backups.

  For a consistent DB copy while the stack is running:
  ```bash
  docker compose exec atlas python -c "import sqlite3; s=sqlite3.connect('/data/atlas.db'); s.execute(\"VACUUM INTO '/data/atlas-backup.db'\")"
  ```
- **Upgrade:** `docker compose pull && docker compose up -d`. Migrations run automatically at start. Read the release notes for probe-version bumps: `atlas doctor` then lists the targets whose probe needs reinstalling.
- **Retention:** snapshots are kept for 90 days (`ATLAS_SNAPSHOT_DAYS`). The newest snapshot per entity is always kept, and events are kept forever. To prune manually: `docker compose exec atlas atlas db prune --days 30`.

## 8. Uninstall

On each target: `userdel -r atlas-ro`, and remove `/usr/local/libexec/atlas-probe*` and `/etc/sudoers.d/atlas-ro`.
In Proxmox: `pveum user delete atlas@pve`, which also removes the token.
In UniFi: delete the API key and the `atlas-view` admin.
Then `docker compose down -v` and remove `/opt/atlas`.
