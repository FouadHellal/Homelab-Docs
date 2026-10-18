# Security

atlas inventories a homelab by **reading** it. This page covers what that guarantee means, how
it is enforced, where its limits are, and how to report a problem. Threats are analysed per
trust boundary in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md); design decisions are in
[docs/DECISIONS.md](docs/DECISIONS.md).

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository (Security → Report a
vulnerability). Do not open a public issue. Include the version (`atlas --version`), what you
did, and what happened. Never include real credentials, tokens or unredacted scan output.

## Guarantees and how they are enforced

| Guarantee | Enforced in code | Enforced on the target |
|---|---|---|
| **No changes to any target** | `ReadOnlyHttpClient`: GET plus a few registered POSTs, each with a schema-checked body (only UniFi Classic login/logout, opt-in), checked against an endpoint-template allowlist. Paths are canonicalised (`..`, `%2e`, `;`, double encoding and backslashes are refused), method-override headers are refused, redirects are off, and `DENIED_SEGMENTS` blocks every `/actions`, `exec`, `file-write`… path. `SshRunner` accepts only `ProbeSection` enum members and sends constant strings with no interpolation, no shell on our side, no agent, no PTY. A ruff `banned-api` rule keeps `subprocess`, `socket`, `httpx` and `asyncssh` out of everything except `homelab_atlas.security`. | Proxmox token with **PVEAuditor** only (`atlas doctor` fails on any non-Audit privilege). SSH user `atlas-ro`: forced command plus an exact-string gate, `restrict`, `from=`, sudo for exactly `atlas-probe <section>`, no docker group. UniFi key minted by a view-only admin (see Limitations). |
| **No secrets at rest** | The Redactor runs between collector and anything durable: DB, logs, audit, exports, MCP. It covers env values (names only), command-line flags, URL user-info, bearer/basic/PVE tokens, about 20 vendor token formats, PEM keys, WireGuard keys, password hashes, Wi-Fi PSKs and query secrets, with a high-entropy fallback. Markers are keyed HMACs, so equal secrets can be correlated without being stored. A hypothesis-fuzzed corpus guards it. | The probe strips Docker env **values on the target**: only names cross the wire. |
| **Credentials never leave their secret file** | `SecretResolver` takes secret **names**, which validation enforces in `hosts.yaml`. It reads `/run/secrets` (or a 0600 dev dir) and returns `SecretStr`, which is unwrapped only inside the transport call. Nothing logs or audits values. | |
| **Pinned identities** | TLS is always verified, against a CA you pin, optionally plus a SHA-256 leaf pin, and `trust_env=False` ignores proxy env vars. SSH accepts exactly the `host_keys` in `hosts.yaml`: no TOFU, no `known_hosts`, no `~/.ssh/config`. | |
| **Every outbound call is accountable** | Append-only JSONL audit log, SHA-256 hash chained; `atlas audit verify` detects edits, insertions and truncation. It records the endpoint template or section, target, outcome and size, never query values or payloads. | `atlas-probe-gate` logs every refused command to syslog. |
| **UI is not a way in** | argon2id local accounts, lockout (5 failures / 15 min), login throttle, server-side sessions (30 min idle / 12 h absolute), `__Host-` Secure HttpOnly SameSite=Strict cookies, synchronizer CSRF token plus Origin check on every POST, strict nonce CSP (no inline script, no `unsafe-*`), TrustedHost, `no-store`, autoescaped templates (a test fails on `\|safe`), vendored JS pinned by SHA-256. | — |
| **MCP is read-only** | Seven query tools annotated read-only/idempotent/closed-world. No scan, write or SQL tool. Results are capped. HTTP uses a constant-time bearer check plus DNS-rebinding protection; `--sanitize` is optional. | — |

Refusals (`SecurityRefusal`) are never retried and are always audited. Tests in
`tests/security/` prove each one: path tricks, method overrides, unregistered POSTs, redirects,
oversized bodies, unknown sections, injected strings, unpinned host keys, agent use, and
symlinked or world-readable secrets. `atlas selftest security` runs the same guards offline on
any install.

## Known limitations (read these)

1. **UniFi API keys have no read-only scope.** A key inherits the permissions of the admin who
   created it. Mint it while signed in as a local **Network View Only** admin
   ([SETUP-TARGETS §5](docs/SETUP-TARGETS.md#5-unifi-gateway-ucg-integration-api-key)). If your
   firmware does not allow that, the key is admin-capable. Then the only controls are atlas's
   GET-only allowlist and keeping the key in a Docker secret. `atlas doctor` **cannot verify** key
   scope and says so.
2. **The database is sensitive.** It is redacted, but it is still a full map of your network:
   hosts, IPs, MACs, open ports, firewall policies and container images. It is not encrypted at
   rest. Protect the `atlas-data` volume and its backups like credentials.
3. **MCP sends topology to your LLM provider** (THREAT-MODEL T-MCP). This is by design, since
   answering questions is the point. Secrets never reach the DB, so they can't reach MCP. Use
   `atlas mcp --sanitize` when you don't want real names and addresses in a hosted model's
   context.
4. **Unverified against real devices.** These are pinned to vendor docs but not yet exercised on
   hardware, so treat the first live scan as a test (`atlas doctor`, then one scan, then review):
   - the Docker inspect template (ADR-007);
   - UniFi port fields from the v9.3.43 sample (ADR-005);
   - the UNAS Drive endpoints, which are community-documented only (ADR-006);
   - Pi `vcgencmd` output;
   - the probe on every Debian/Ubuntu release.
5. **The UCG's self-signed certificate** usually lacks its hostname, so `check_hostname: false`
   is common there. A pinned CA file (`tls.ca_file`) is always required and an API source
   without one is refused. Adding `sha256_pin` binds the exact leaf certificate too.
6. **The probe runs as root** (via exact-argv sudo) for the sections that need it: process owners
   on ports, Docker, root crontabs. It is a short bash script that writes nothing, makes no
   network calls and takes no free-form arguments. Review it before installing it
   (`docs/targets/atlas-probe`); its SHA-256 is pinned and checked by `atlas doctor`.
7. **Single-owner design.** Every UI account has the same rights: read everything, edit
   annotations, trigger scans. There are no roles.

## Operating it safely

- **Network:** LAN or VPN only, behind your TLS reverse proxy. Never port-forward it.
- **Updates:** pin image tags, rotate the Proxmox token and the UniFi key yearly, and keep the
  collector's SSH key on the deploy host only (`from=` in `authorized_keys`).
- **Doctor:** run `atlas doctor --live` after every target change. It flags excess privilege,
  outdated probes and changed host keys.
- **Audit:** check `atlas audit verify` periodically and keep the audit log with your backups.

## Supply chain

- **Dependencies:** `uv.lock` with hashes, `uv sync --frozen` in CI and the image,
  `pip-audit --strict` in CI, and Dependabot for uv, GitHub Actions and Docker.
- **CI:** Actions are pinned by commit SHA with `persist-credentials: false` and least-privilege
  `permissions`. gitleaks scans the full history.
- **Image:** multi-stage build on digest-pinned `python:3.12-slim-trixie`. It runs as non-root
  uid 10001 with code that uid cannot write, and is designed for `read_only`, `cap_drop: [ALL]`
  and `no-new-privileges`. CI smoke-tests it under exactly those flags.
- **Release gate:** Trivy fails the build on fixable HIGH/CRITICAL vulnerabilities, secrets or
  misconfigurations. Images are pushed to GHCR with an SBOM and `mode=max` provenance
  attestations.
- **Vendored JS:** htmx 2.0.11 and cytoscape 3.34.4 are verified against the npm registry
  integrity hash and pinned by SHA-256 in tests. They are excluded from the whitespace hooks and
  marked `-text`, so they stay byte-exact.
