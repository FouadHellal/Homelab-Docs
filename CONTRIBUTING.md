# Contributing to atlas

Thanks for helping. atlas documents homelabs and **only reads**, so contributions are judged
first on whether they keep that promise. Then they're judged on whether they make the docs
better.

## Ground rules

- **Never touch real targets during development.** Work against the synthetic demo lab
  (`fixtures/demo-lab/`) and the mocks in `tests/`. Anything that must run on a target goes in
  `docs/targets/` for its owner to review.
- **No real credentials anywhere.** A fake secret in a test or fixture must contain
  `ATLASFAKE` (the gitleaks allowlist marker). Anything else that looks like a secret fails CI.
- **All outbound I/O goes through `homelab_atlas.security`** (`ReadOnlyHttpClient`,
  `SshRunner`). A ruff rule and a test reject direct `httpx`, `asyncssh` or `subprocess`
  use anywhere else.
- **Collector output goes through the `Redactor`** before it reaches the database, logs,
  exports or MCP.
- **A new command or endpoint** must be declared in the collector's `requires`, come with a
  refusal test, and be followed by `uv run atlas targets render` to regenerate `docs/targets/`.

## Setup

```bash
git clone https://github.com/FouadHellal/Homelab-Docs.git && cd Homelab-Docs
uv sync
uv run poe check        # ruff, mypy (strict), pytest, gitleaks: exactly what CI runs
uv run atlas scan --lab demo:A --fresh && uv run atlas scan --lab demo:B
uv run atlas serve --lab demo     # login in data/demo-lab/demo-login.txt
```

Other tasks: `uv run poe test`, `poe lint`, `poe type`, `poe fmt`. On Linux, `make <task>`
does the same.

## Pull requests

- Keep them small and focused. Use [Conventional Commits](https://www.conventionalcommits.org/)
  messages: `feat(ssh): …`, `fix(web): …`, `test(redact): …`.
- Add or update tests. Security code needs a test for every refusal path, and coverage must
  stay at 90 % or more.
- Record decisions in `docs/DECISIONS.md` (a short ADR). Facts about vendor APIs come from
  their docs, cited with a version, not from memory.
- If you change `fixtures/demo-lab/generate.py`, regenerate the lab and update
  `expected-diff-A-B.json` on purpose.
- UI changes: no inline scripts or styles (strict CSP), and every value from a target is
  rendered as text.

## Reporting bugs and security issues

Open an issue with the version (`atlas --version`), what you did and what you saw.
**Never paste real credentials, tokens or unredacted scan output.** Report security problems
privately (see [SECURITY.md](SECURITY.md)).
