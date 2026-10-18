# Thin wrapper over poe tasks (the single source, see ADR-001). On Windows use: uv run poe <task>
.PHONY: sync check lint fmt type test secrets audit hooks
sync:    ; uv sync
check:   ; uv run poe check
lint:    ; uv run poe lint
fmt:     ; uv run poe fmt
type:    ; uv run poe type
test:    ; uv run poe test
secrets: ; uv run poe secrets
audit:   ; uv run poe audit
hooks:   ; uv run pre-commit install
