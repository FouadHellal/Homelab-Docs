# THREAT MODEL — Homelab-Docs (`atlas`)

Status: draft for approval (M0a). Method: assets → trust boundaries (ARCHITECTURE §1) → STRIDE per boundary → controls → residual risk. Each control maps to a test or a doctor check where possible.

## 1. Assets
| ID | Asset | Why it matters |
|---|---|---|
| A1 | Target integrity (PVE, UCG, hosts, NAS) | atlas must never change them |
| A2 | Collector credentials (PVE token, UniFi key/account, SSH keys) | read access to everything; UniFi key may be write-capable (ADR-005) |
| A3 | Inventory DB + snapshots + exports | full network map: IPs, VLANs, firewall policy, services, versions |
| A4 | Secrets present on targets (env, cmdline, cron) | must never be collected verbatim |
| A5 | Audit log | evidence of what atlas did |
| A6 | UI/MCP access | gateway to A3 |
| A7 | Build pipeline / image | supply chain into a box holding A2 |

## 2. Adversaries
- **T-LAN**: a device on the LAN or IoT VLAN (compromised or hostile) that can reach the atlas UI or the targets.
- **T-TARGET**: a compromised target returning malicious data (container names, hostnames, labels crafted for injection or XSS).
- **T-APP**: an attacker with code execution in the atlas container (a dependency vuln, say).
- **T-SUPPLY**: a malicious dependency, action or base image.
- **T-LEAK**: accidental disclosure (screenshots, git, logs, LLM context).
- **T-SELF**: owner or Claude mistakes (wrong config, committing secrets, a bug that issues a write).

## 3. STRIDE by boundary

### B3: atlas → SSH targets
| Threat | Example | Controls | Test / check |
|---|---|---|---|
| T (tamper target) | bug or injection makes atlas run `docker rm` | enum-only `SshRunner`; constant exec strings; target gate exact-match; sudoers exact argv; probe takes no free args | `tests/security/test_ssh_refusals.py`: injection (`;`, `&&`, `$()`, backticks, newline, NUL, unicode homoglyphs, `IFS` tricks), unknown enum, string instead of enum; gate script tested with bats-style cases on Linux CI |
| E (privilege) | `atlas-ro` escalates via sudo | sudoers lists one root-owned, non-writable binary with exact args; `restrict`; `from=`; no docker group | `atlas doctor` checks probe hash, version, file owner and mode report |
| S (MITM) | rogue host impersonates a target | pinned `known_hosts`, StrictHostKeyChecking semantics, ed25519 only | refusal test on changed/unknown host key |
| I (secret exfil) | env values collected | env names only on target; Redactor collector-side | nasty fixtures (ADR-009) must yield 0 leaks: a test scans all persisted output for the fixture secret corpus |
| T (malicious output) | container named `<script>` or `\x1b]…` or a forged section header | random per-run boundary; strict parsers with size caps; Jinja autoescape; control chars stripped on render | fuzz parsers with hypothesis; XSS fixture renders escaped |
| D | huge output / slowloris | byte, line and time caps; per-target concurrency | tests with oversized fixtures |
| R | can't tell what atlas did | audit log hash chain | `atlas audit verify` test with a tampered line |

### B2: atlas → HTTP APIs (PVE, UniFi, Drive)
| Threat | Example | Controls | Test / check |
|---|---|---|---|
| T | POST to `/devices/{id}/actions`, DELETE policy | endpoint registry; GET only (+ registered Classic login/logout POSTs); explicit deny of `/actions`; no method-override headers; redirects off | refusal tests for every method and override header; path-trick fuzz (`..`, `%2e%2e`, `%252e`, `;`, `//`, `\`, unicode full-stop U+FF0E, trailing dot, case variants) |
| E | UniFi key inherits full admin | create the key as a view-only local admin; SECURITY.md states the residual risk if UniFi won't allow that | `atlas doctor` reports the key owner's role where the API exposes it |
| E | PVE token over-privileged | PVEAuditor + privsep; doctor fails on any non-`*.Audit` privilege via `/access/permissions` | doctor unit test against fixture permission sets |
| S | MITM on self-signed certs | CA/fingerprint pinning, verify never off | test: mismatched fingerprint ⇒ refusal |
| I | token in logs or URL | header-only auth; logs carry templates only; structlog redaction processor | log-capture test greps for fixture tokens |

### B1: user → atlas (UI, MCP HTTP)
| Threat | Example | Controls | Test |
|---|---|---|---|
| S | password guessing | argon2id, rate limit + lockout, no default creds (`atlas user add` required) | auth tests |
| T | CSRF edits annotations / triggers scans | synchronizer token, SameSite=Strict, `__Host-` cookie | CSRF negative tests |
| I | XSS via target data | autoescape, strict CSP with nonce, no `safe` filter on target data (lint rule) | XSS fixture snapshot test |
| I | MCP bearer brute force / leak | 256-bit token, constant-time compare, private bind, rate limit | tests |
| E | path traversal in annotation editor | entity key → filename by allowlisted slug + hash; writes only under `annotations/` | traversal tests |
| D | expensive queries | pagination caps; MCP result caps | tests |

### B4: atlas → storage, exports, LLM
| Threat | Example | Controls |
|---|---|---|
| I | DB copied off the VM | encrypted VM disk, 0600 files, non-root uid, no published DB port, backups encrypted (DEPLOY.md) |
| I | public screenshot or demo leaks topology | `--sanitize` pseudonymisation (IPs → doc ranges, MAC/host/SSID/domain mapping; notes/links stripped); demo lab is synthetic |
| I (**T-MCP**) | MCP answers send the network map into an LLM provider's context | accepted by design (owner's goal); secrets never reach the DB so they can't reach MCP; optional `mcp.sanitize: true`; result-size caps; no raw-snapshot tool |
| R | audit log edited | hash chain, head mirrored in DB, optional off-box shipping |

### Repo and supply chain (T-SUPPLY, T-SELF)
| Threat | Controls |
|---|---|
| secrets committed | `.gitignore` for secrets/env/keys/data; gitleaks in pre-commit and CI; Claude deny rules for `.env*`, `secrets/`, `~/.ssh`, keys, `git push` |
| malicious or vulnerable deps | `uv.lock` with hashes, pip-audit, Dependabot, minimal deps, Actions pinned by SHA, Trivy, SBOM |
| compromised image | GHCR private, provenance attestation, digest-pinned base, non-root, ro rootfs, cap_drop ALL |
| a future dev bypasses the wrappers | ruff `banned-api` for `httpx`, `asyncssh`, `subprocess`, `os.system`, `socket` outside `security/`; an architecture test walks imports |
| Claude touches real targets | no credentials in dev; the `demo:` transport is the default; real transports need `--live` and a config outside the repo |

## 4. Residual risks (owner to accept)
1. **UniFi API key may be write-capable** if UniFi OS can't mint keys for a view-only admin. The mitigation is code-level only (GET-only wrapper) plus secret storage.
2. **Probe runs as root** via sudo. Its surface is a reviewed script with fixed commands, but a bug in it runs as root. Mitigations: small script, shellcheck in CI, hash pinning, owner review before install.
3. **Classic UniFi login** (opt-in) stores a password-equivalent credential.
4. **Inventory concentration**: atlas is a high-value target on the LAN. Mitigations: bind private, reverse proxy, auth, keep it off IoT/guest VLANs, firewall it to the mgmt VLAN.
5. **LLM exposure via MCP** of non-secret topology data (T-MCP), by design.
6. **Undocumented UNAS API** may change behaviour across firmware. It's GET-only, but the semantics are unverified.
7. **Redaction is heuristic outside known formats.** A short, low-entropy secret in free text that has no recognisable name or flag (e.g. `run.sh hunter2`) passes. Mitigations: env values stripped on the target, key-name rules on structured data, the corpus grows with every miss, and OpenSSH public-key blobs are exempt from the entropy rule by design.

## 5. Security test inventory (built in M1, extended per milestone)
`tests/security/` (M1): `test_ssh_allowlist.py` (enum-only, injections, homoglyphs, fuzz), `test_ssh_transport.py` (in-process sshd: pinning, key types, caps, timeouts, no inherited env/agent/config), `test_http_client.py` (methods, lookalike/mutated endpoints, path/query tricks, redirects, caps, headers), `test_http_tls.py` (real TLS: anchor, partial chain, leaf pin, hostname), `test_http_fuzz.py` (hypothesis), `test_redaction.py` (corpus in `corpus/redaction.json`, false positives, structures, properties, logging), `test_audit.py` (tamper, truncation, restart, rotation, concurrency), `test_secrets.py`, `test_no_raw_io_outside_security.py`. M2 adds `test_probe_gate` (Linux CI). M5 adds web auth/CSRF/XSS. An independent review pass happens in M7.
