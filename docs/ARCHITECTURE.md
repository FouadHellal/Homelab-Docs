# ARCHITECTURE — Homelab-Docs (`atlas`)

Status: draft for approval (M0a). Rationale lives in DECISIONS.md (ADR-nnn), threats in THREAT-MODEL.md.

## 1. Context and trust boundaries
```mermaid
flowchart LR
  subgraph Owner["Owner workstation / LAN"]
    browser[Browser]
    claude[Claude client<br/>MCP stdio/HTTP]
    git[(git repo<br/>hosts.yaml, annotations/)]
  end
  subgraph Prod["atlas VM/LXC (docker compose)"]
    rp[Reverse proxy<br/>TLS]
    app[atlas app<br/>UI + API + scheduler + MCP]
    db[(SQLite WAL<br/>sensitive)]
    audit[(audit.jsonl<br/>hash chain)]
    secrets[/Docker secrets<br/>API tokens, SSH keys ro/]
  end
  subgraph Targets["Targets (never written)"]
    pve[Proxmox VE x2<br/>:8006 API]
    ucg[UniFi UCG<br/>Integration API]
    linux[Debian/Ubuntu hosts<br/>sshd + forced-command probe]
    pi[Raspberry Pi]
    unas[UNAS<br/>Drive API, best-effort]
  end
  browser -- HTTPS, session+CSRF --> rp --> app
  claude -- bearer / stdio --> app
  git -- mounted ro --> app
  app --> db & audit
  secrets -. read at use .-> app
  app == "GET-only HTTPS (B2)" ==> pve & ucg & unas
  app == "SSH ed25519, pinned host key (B3)" ==> linux & pi
```
Boundaries: **B1** user→app (auth), **B2** app→HTTP APIs (ReadOnlyHttpClient), **B3** app→SSH (SshRunner + target-side forced command), **B4** app→storage/exports/MCP (Redactor, sanitize).

## 2. Components
```mermaid
flowchart TB
  cli[cli<br/>Typer] --> core
  web[web<br/>FastAPI, Jinja2, HTMX] --> query
  mcp[mcp<br/>official SDK] --> query
  sched[scheduler<br/>APScheduler] --> core
  subgraph core[scan engine]
    inv[inventory<br/>hosts.yaml loader] --> plan[scan planner]
    plan --> run[collector runner<br/>timeouts, limits, partial results]
    run --> coll[collectors<br/>proxmox, unifi, linux-ssh, docker, pi, nas]
    coll --> redact[Redactor]
    redact --> norm[normalizer + identity]
    norm --> snap[snapshot store]
    snap --> diff[diff engine → events]
    norm --> recon[reconciler<br/>known/unknown/missing]
  end
  subgraph security[security — strict mypy, no other module does I/O]
    http[ReadOnlyHttpClient]
    ssh[SshRunner]
    auditlog[AuditLog]
    secretres[SecretResolver]
  end
  coll --> http & ssh
  http & ssh --> auditlog
  http & ssh --> secretres
  query[query/read models] --> store[(SQLAlchemy 2 / SQLite)]
  snap & diff & recon --> store
  export[exporters + sanitizer] --> query
  ann[annotations<br/>YAML ⇄ DB] --> store
```

## 3. Scan sequence
```mermaid
sequenceDiagram
  autonumber
  participant S as Scheduler/CLI
  participant R as Runner
  participant C as Collector
  participant X as SshRunner / HttpClient
  participant A as AuditLog
  participant D as Redactor
  participant N as Normalizer+Diff
  S->>R: scan(targets, collectors) [acquire scan lock]
  R->>C: collect(target) with timeout
  C->>X: run(ProbeSection.NET) / get(Endpoint.VM_LIST, vars)
  X->>X: allowlist check (refuse ⇒ SecurityRefusal)
  X->>A: append {target, op-template, start}
  X-->>C: bytes (bounded size)
  X->>A: append {status, duration, bytes}
  C->>C: parse → Pydantic models (raw kept in memory only)
  C-->>R: CollectorResult(models, errors)
  R->>D: redact(models)
  D-->>R: redacted models (+ redaction counts)
  R->>N: normalize, identity, snapshot hash, diff vs previous
  N-->>S: events, summary
```

## 4. SSH read-only enforcement (defence in depth, ADR-002/003)
```mermaid
flowchart LR
  a[Collector asks for<br/>ProbeSection.DOCKER] --> b{SshRunner:<br/>enum member in<br/>collector.requires?}
  b -- no --> x1[[refuse + audit]]
  b -- yes --> c["exec string = 'atlas-probe docker'<br/>(constant, from enum)"]
  c --> d[asyncssh: ed25519 key,<br/>known_hosts pinned, no agent/pty/fwd]
  d --> e["sshd: authorized_keys<br/>restrict,from=collector,<br/>command=/usr/local/libexec/atlas-probe-gate"]
  e --> f{gate: SSH_ORIGINAL_COMMAND<br/>∈ fixed list?}
  f -- no --> x2[[exit 64, logger -t atlas]]
  f -- yes --> g["sudo -n /usr/local/libexec/atlas-probe docker<br/>(sudoers: exact argv per section)"]
  g --> h[probe: read-only commands,<br/>allowlisted docker fields,<br/>env NAMES only]
```
The client string is not trusted on the target. The gate ignores everything except an exact match. The probe takes no free-form arguments.

## 5. Data model (simplified)
```mermaid
erDiagram
  ENTITY ||--o{ FACET : has
  ENTITY ||--o{ SNAPSHOT : versions
  ENTITY ||--o{ EVENT : emits
  ENTITY ||--o| ANNOTATION : "annotated by"
  ENTITY ||--o{ RELATION : "src/dst"
  SCAN ||--o{ SNAPSHOT : produced
  SCAN ||--o{ COLLECTOR_RUN : contains
  ENTITY { string key PK "e.g. pve:vm:homelab/105"
           string kind
           string display_name
           datetime first_seen
           datetime last_seen
           string status "known|unknown|missing" }
  FACET { string entity_key FK
          string collector
          json current "redacted normalized model" }
  SNAPSHOT { string sha256 PK
             string entity_key FK
             string collector
             int scan_id FK
             json body "redacted canonical JSON" }
  RELATION { string src_key
             string dst_key
             string type "runs_on|uplink|member_of_vlan|publishes|uses_image" }
  EVENT { int id PK
          int scan_id
          string entity_key
          string type
          string severity
          json detail }
  ANNOTATION { string entity_key PK
               string owner
               string criticality
               json tags
               text notes }
  COLLECTOR_RUN { int scan_id
                  string target
                  string collector
                  string status "ok|partial|failed|skipped"
                  json errors }
```
The Postgres-compatible subset: SQLAlchemy `JSON` type, no SQLite-only SQL, Alembic migrations from day one.

## 6. Repository layout
```
src/homelab_atlas/
  security/    http.py (ReadOnlyHttpClient) ssh.py (SshRunner) allowlist.py audit.py secrets.py
               errors.py selftest.py    <- the only package allowed to import httpx/asyncssh
  redact/      rules.py redactor.py
  models/      pydantic models per domain, volatile()/keyed() markers
  collectors/  base.py probe_session.py proxmox/ unifi/ linux_ssh/ docker/ nas.py pi.py
  probe/       render.py templates/{atlas-probe.sh, atlas-probe-gate.sh}
  engine/      scan.py (orchestration, lock) diff.py events.py reconcile.py
  store/       db.py tables.py retention.py migrations/ (Alembic)
  inventory/   hosts.py annotations.py
  web/         app.py auth.py queries.py topology.py templates/ static/vendor/
  export/      build.py (document + md/mkdocs/json/csv/mermaid) sanitize.py
  mcp_server.py scheduler.py runtime.py lab.py cli.py cli_scan.py cli_web.py cli_export.py
fixtures/demo-lab/  hosts.yaml state-A/ state-B/ annotations/ (recorded probe + API responses)
docs/targets/       generated by `atlas targets render`: probe, gate, sudoers, authorized_keys
tests/              security/ unit/ integration/ web/
Dockerfile docker-compose.yml .github/workflows/{ci,image}.yml
```

## 7. Deployment
```mermaid
flowchart LR
  gh[GitHub Actions] -- build, scan, push --> ghcr[(GHCR private)]
  ghcr -- docker compose pull --> vm
  subgraph vm[Proxmox VM/LXC: atlas]
    direction TB
    rp2[reverse proxy] --> c1[atlas container<br/>uid 10001, ro rootfs,<br/>cap_drop ALL, tmpfs /tmp]
    c1 --- v1[(volume: data/<br/>db, audit, snapshots)]
    c1 --- v2[/secrets: tokens, ssh keys ro/]
    c1 --- v3[/config: hosts.yaml ro, annotations rw/]
    rp2 -. optional .-> c2[mcp container<br/>bearer, same hardening]
    c2 --- v1
  end
```
The `atlas` service runs the web UI and the scheduler in one process. MCP over HTTP is an optional second service from the same image (`--profile mcp`, bearer token; ADR-023 amends ADR-015). The MCP stdio transport needs no listener: the client runs `docker compose exec -T atlas atlas mcp`. CI builds the image, smoke-tests it under the production hardening flags and gates it on Trivy before pushing to GHCR with an SBOM and provenance (ADR-024). Step by step: [DEPLOY.md](DEPLOY.md).

## 8. Cross-cutting
- **Errors**: `SecurityRefusal` (never retried, always audited), `TargetUnreachable`, `CollectorParseError` (section-level, partial result kept).
- **Logging**: structlog JSON; a redaction processor runs last; no raw payloads at any level.
- **Config**: `atlas.toml` + env (`ATLAS_*`), Pydantic Settings; secrets only via SecretResolver.
- **Time**: UTC everywhere, tz-aware.
