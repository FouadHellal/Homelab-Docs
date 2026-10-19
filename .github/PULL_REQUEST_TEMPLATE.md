## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `uv run poe check` passes (ruff, mypy strict, pytest, gitleaks)
- [ ] Tests added or updated; security code has a test for every refusal path
- [ ] Still read-only: new commands or endpoints are declared in `requires`, have a refusal test, and `docs/targets/` is regenerated
- [ ] No real secrets; fake ones contain `ATLASFAKE`
- [ ] Decision recorded in `docs/DECISIONS.md` if there was one to make
- [ ] UI: no inline scripts or styles; target data rendered as text
