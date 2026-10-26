# syntax=docker/dockerfile:1.7
# atlas: multi-stage, digest-pinned, non-root, read-only-rootfs friendly (ADR-017).
# Digests resolved 2026-10-18 from registry-1.docker.io and ghcr.io; Dependabot (docker) bumps them.

FROM ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

# ---------------------------------------------------------------- build
FROM python:3.12-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/atlas
WORKDIR /src
# Dependencies first (cached layer), exactly as locked (hashes in uv.lock), no dev group.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# ---------------------------------------------------------------- runtime
FROM python:3.12-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
LABEL org.opencontainers.image.title="atlas" \
      org.opencontainers.image.description="Read-only, agentless homelab inventory" \
      org.opencontainers.image.source="https://github.com/FouadHellal/Homelab-Docs"
RUN groupadd --system --gid 10001 atlas \
 && useradd --system --uid 10001 --gid atlas --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin atlas \
 && mkdir -p /data /config \
 && chown atlas:atlas /data \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build --chown=root:root /opt/atlas /opt/atlas
ENV PATH=/opt/atlas/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ATLAS_DATA_DIR=/data \
    ATLAS_CONFIG_DIR=/config
# Code is root-owned and read-only to the app user; only /data (volume) is writable.
WORKDIR /app
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8443 8080
# Probes /healthz on 127.0.0.1 over HTTPS (8443) or HTTP (8080), whichever the UI serves.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["atlas", "healthcheck"]
# LAN default: built-in HTTPS with a generated certificate (docs/DEPLOY.md). Behind your own
# TLS reverse proxy instead: serve --port 8080 --hsts --allowed-host ... --forwarded-allow-ips ...
CMD ["atlas", "serve", "--host", "0.0.0.0", "--port", "8443", "--self-signed-tls", "--schedule"]
