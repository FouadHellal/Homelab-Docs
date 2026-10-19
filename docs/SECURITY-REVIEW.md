# Security review (M7, 2026-10-19)

A focused pass over everything added after the M1 security core: web auth internals, exports
and `--sanitize`, the MCP server, the scheduler, the container/compose/CI setup, and the M7
onboarding (Targets page, vault, password SSH). Method: read the code against THREAT-MODEL.md,
then write a failing test or a reproduction for each suspected issue before fixing it. This
was done by the same assistant that wrote the code; it is a structured self-review, not an
independent third-party audit.

## Findings

| # | Severity | Area | Finding | Status |
|---|---|---|---|---|
| F1 | Medium | MCP `--sanitize` | Only entity display names were pseudonymised, so `get_host` leaked SSID names, OS hostnames, client names and search domains (reproduced on the demo lab: 7 names). | **Fixed** `ec01ea5`: export and MCP share `register_names()`; leak test covers facet names. |
| F2 | Medium | Exports | CSV cells starting with `= + - @` were written as-is (spreadsheet formula injection). The first test passed only because CSV quoting hid the payload. | **Fixed**: cells get a leading `'`; the test parses the CSV back. |
| F3 | Medium | Exports | Markdown/MkDocs output carried target strings raw. MkDocs renders inline HTML, so a container label like `<script>` or `[x](javascript:…)` would run on a published site. | **Fixed**: HTML escaped, Markdown metacharacters backslashed, newlines folded; YAML nav labels filtered. |
| F4 | Medium | Web | `Referrer-Policy: no-referrer` makes browsers send `Origin: null` on plain form POSTs. The CSRF Origin check (correctly) rejected them, which broke non-htmx forms (logout, Targets save). Found by driving the real UI. | **Fixed**: `same-origin`; the Origin check stays strict and a test asserts `Origin: null` is refused. |
| F5 | Medium | Scheduler | A manual scan ran synchronous DB work on the web event loop and deadlocked on SQLite's write lock held by the request session ("database is locked"). | **Fixed**: scans run on a worker thread with their own loop; crashes count as failures with backoff. |
| F6 | Low | MCP HTTP | The bearer guard checked only `http` scopes; `websocket` scopes passed through. The SDK's app serves no websockets today. | **Fixed**: websocket scopes are checked and closed with 1008. |
| F7 | Low | MCP | String tool arguments had no length limit. | **Fixed**: 128 characters, enforced by the SDK's argument validation. |
| F8 | Low | MCP | Tool calls left no trace. | **Fixed**: one log line per call with the tool name only (arguments may be search terms about the network). |
| F9 | Low | Supply chain | `end-of-file-fixer` rewrote the vendored `htmx.min.js` at commit time, breaking its pinned SHA-256. | **Fixed**: vendor files excluded from whitespace hooks and marked `-text`. |
| F10 | Info | SSH password mode | A refusal raised after `asyncssh.connect` left the connection open (it hung a test). | **Fixed**: every refusal happens before connecting. |

## Checked and found sound

- **Login:** argon2id with a dummy hash for unknown users (no timing oracle).
- **Sessions:** tokens stored hashed (SHA-256); new token on login; idle and absolute expiry.
- **CSRF:** `hmac.compare_digest`, synchronizer token plus Origin check, on every state-changing route including the new Targets routes.
- **Vault:** AES-GCM with a random 96-bit nonce per write and the name as AAD, so a moved ciphertext fails. Tampered or wrong-key data fails closed. Writes are atomic with 0600.
- **Targets UI:** stored values are never rendered, and an empty field keeps the stored value. Pinning requires explicit confirmation of the fingerprint. `hosts.yaml` entries can't be edited from the UI. Inputs go through the same strict models as the file loader (no root user, secret *names* only, ed25519/ECDSA host keys).
- **Password mode:** the password is never in argv, env, logs or the audit log (asserted in tests and by grepping the data dir after a real UI run). The host key is checked before the password is offered.
- **Identity fetch:** host/port validated; certificate fetch is TLS-only and sends no request.

## Residual risks (accepted, documented in SECURITY.md)

- Password-mode SSH has no target-side enforcement (SECURITY.md #7).
- Vault security depends on keeping `atlas_master_key` outside the data volume (#8).
- UniFi API keys can't be scoped read-only (#1).
- The `sudo -S` path, the Docker inspect template and the UniFi port fields still need their first run against real devices (#4).
