# CLAUDE.md — Homelab-Docs (`atlas`)

Read-only, agentless auto-discovery and documentation of a homelab. Spec: docs/SPEC.md. Design: docs/ARCHITECTURE.md, docs/DECISIONS.md, docs/THREAT-MODEL.md.

## Hard rules
- **Never touch real targets.** Develop against `fixtures/demo-lab/` and mocks only. Target-side artifacts go in `docs/targets/` for the owner to review and install.
- **Never read, print or store real credentials.** Don't open `.env*`, `secrets/`, `~/.ssh`, `*.pem`, `*.key`. Use `.env.example` and fake fixture values only.
- **Never `git push`.** Small commits, Conventional Commits (`feat(ssh): …`, `test(redact): …`). The owner pushes.
- All outbound I/O goes through `homelab_atlas.security` (`ReadOnlyHttpClient`, `SshRunner`). No direct `httpx`/`asyncssh`/`subprocess` use anywhere else (enforced by a ruff banned-api rule plus a test).
- Collector output passes through `Redactor` before it reaches the DB, logs, audit log, exports or MCP. Never persist raw output.
- Env vars: store NAMES only, never values.
- New command/endpoint ⇒ declare it in the collector's `requires`, add a refusal test, and regenerate `docs/targets/`.
- Milestone ends: tests green, ruff + mypy clean, demo command, summary, then STOP for go-ahead.

## Commands (Windows and Linux; `uv run poe <task>`)
- `poe check`: ruff, mypy, pytest, gitleaks (everything CI runs)
- `poe test` / `poe lint` / `poe type` / `poe fmt`
- `uv run atlas --help`
- Demo lab: `uv run atlas scan --lab demo:A --fresh`, `uv run atlas scan --lab demo:B`, `uv run atlas diff --lab demo`
- After changing the probe/gate templates or `ProbeSection`: `uv run atlas targets render` (a test fails on drift).
- After changing `fixtures/demo-lab/generate.py`: rerun it and update `expected-diff-A-B.json` deliberately.
- `make <task>` is a thin wrapper over poe on Linux.

## Conventions
- Python 3.12, src layout, package `homelab_atlas`, CLI `atlas` (Typer).
- Pydantic v2 models for all collector output; volatile fields marked `Field(json_schema_extra={"volatile": True})`.
- mypy `strict = true` for the whole repo (src and tests), which covers the security modules' requirement. No bare `# type: ignore`.
- Fake secrets in fixtures/tests must contain `ATLASFAKE` (gitleaks allowlist marker); anything else is treated as real.
- Tests: `tests/unit`, `tests/security` (refusal/bypass/fuzz, hypothesis), `tests/integration` (demo lab). Security code needs a test for every refusal path.
- Vendor API facts come from docs cited in DECISIONS.md, not memory. Record the version.
- Paths: use `pathlib`; no POSIX-only assumptions in collector-side code (dev is on Windows).
