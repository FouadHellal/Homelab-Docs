# syntax=docker/dockerfile:1.7
# atlas: multi-stage, digest-pinned, non-root, read-only-rootfs friendly (ADR-017).
# Digests resolved 2026-10-18 from registry-1.docker.io and ghcr.io; Dependabot (docker) bumps them.

FROM ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

# ---------------------------------------------------------------- build
FROM python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS build
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
FROM python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
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
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request as u; sys.exit(u.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status != 200)"]
# Behind your TLS reverse proxy: set --allowed-host and --forwarded-allow-ips (see docs/DEPLOY.md).
CMD ["atlas", "serve", "--host", "0.0.0.0", "--port", "8080", "--schedule"]
