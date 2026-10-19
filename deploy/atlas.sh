#!/usr/bin/env bash
# atlas deploy helper: install / update / accounts / status / backup for the docker compose stack.
#
#   git clone https://github.com/FouadHellal/Homelab-Docs.git && cd Homelab-Docs
#   sudo ./deploy/atlas.sh install            # pulls the image (or builds it), creates an account, starts
#   sudo ./deploy/atlas.sh user add alice     # more accounts at any time
#
# Everything lives in $ATLAS_DIR (default /opt/atlas): docker-compose.yml, .env, secrets/, config/.
# The script never touches your homelab targets; it only manages this host's atlas containers.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATLAS_DIR="${ATLAS_DIR:-/opt/atlas}"
IMAGE_DEFAULT="ghcr.io/fouadhellal/homelab-docs"
APP_UID=10001

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: atlas.sh <command> [options]

  install [--build] [--no-user]   set up $ATLAS_DIR, get the image, create an account, start
  update  [--build]               newer image (or rebuild from this clone), restart
  user add <name>                 create a web account (asks for the password)
  user passwd <name>              change a password (ends that user's sessions)
  status                          containers, health, URL, certificate fingerprint
  logs                            follow atlas logs
  backup [file.tar.gz]            consistent DB copy + config (NOT the master key)
  stop | start                    stop / start the stack
  uninstall [--purge]             remove containers (--purge also deletes the data volume)

Environment: ATLAS_DIR (default /opt/atlas).
EOF
}

compose() {
    local files=(-f "$ATLAS_DIR/docker-compose.yml")
    if [ "$(env_get ATLAS_MODE)" = "proxy" ]; then
        files+=(-f "$ATLAS_DIR/docker-compose.proxy.yml")
    fi
    docker compose --project-directory "$ATLAS_DIR" "${files[@]}" "$@"
}

env_get() {  # env_get KEY -> value from $ATLAS_DIR/.env (empty if unset)
    [ -f "$ATLAS_DIR/.env" ] || return 0
    sed -n "s/^$1=//p" "$ATLAS_DIR/.env" | tail -n 1
}

env_set() {  # env_set KEY VALUE (replace or append)
    local file="$ATLAS_DIR/.env"
    touch "$file"
    if grep -q "^$1=" "$file"; then
        sed -i.bak "s|^$1=.*|$1=$2|" "$file" && rm -f "$file.bak"
    else
        printf '%s=%s\n' "$1" "$2" >> "$file"
    fi
}

own() {  # give the container user its files (skipped when not root, e.g. in tests)
    if [ "$(id -u)" -eq 0 ]; then
        chown -R "$APP_UID:$APP_UID" "$@"
    else
        warn "not root: skipping chown of $* to uid $APP_UID (run with sudo on the server)"
    fi
}

preflight() {
    command -v docker >/dev/null 2>&1 || die "docker is not installed (https://docs.docker.com/engine/install/)"
    docker compose version >/dev/null 2>&1 || die "the docker compose plugin is missing (apt install docker-compose-plugin)"
    [ -f "$REPO_DIR/docker-compose.yml" ] || die "run this from a clone of the repository"
}

detect_hosts() {  # this machine's IPs + names, comma-separated, for the Host allowlist / cert
    local list=() ip name
    for ip in $(hostname -I 2>/dev/null || true); do
        case "$ip" in *:*) ;; *) list+=("$ip") ;; esac  # IPv4 only (IPv6 needs [brackets] in URLs)
    done
    name="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
    [ -n "$name" ] && list+=("$name")
    [ -n "$(hostname -s 2>/dev/null || true)" ] && list+=("$(hostname -s)")
    list+=("localhost")
    local IFS=,
    printf '%s' "${list[*]}" | awk -F, '{for (i=1;i<=NF;i++) if (!seen[$i]++) printf "%s%s", (n++?",":""), $i}'
}

get_image() {  # get_image <build:0|1>
    local build="$1" image tag
    image="$(env_get ATLAS_IMAGE)"; image="${image:-$IMAGE_DEFAULT}"
    tag="$(env_get ATLAS_VERSION)"; tag="${tag:-latest}"
    if [ "$build" = 0 ]; then
        say "pulling $image:$tag"
        if compose pull atlas; then
            return 0
        fi
        warn "could not pull $image:$tag (private package? run: docker login ghcr.io). Building locally instead."
    fi
    say "building the image from $REPO_DIR (takes a few minutes the first time)"
    docker build -t atlas:local "$REPO_DIR"
    env_set ATLAS_IMAGE atlas
    env_set ATLAS_VERSION local
}

read_password() {  # read_password <var>: asks twice, 12+ characters
    local p1 p2
    while true; do
        read -r -s -p "Password (12+ characters): " p1; echo
        read -r -s -p "Repeat password: " p2; echo
        p1="${p1%$'\r'}"; p2="${p2%$'\r'}"   # tolerate CRLF input
        if [ "$p1" != "$p2" ]; then warn "the passwords differ"; continue; fi
        if [ "${#p1}" -lt 12 ]; then warn "too short"; continue; fi
        printf -v "$1" '%s' "$p1"
        return 0
    done
}

user_cmd() {  # user_cmd add|passwd <name>
    local action="$1" name="${2:-}" pw
    [ -n "$name" ] || die "usage: atlas.sh user $action <name>"
    case "$name" in *[!a-z0-9._-]*) die "names use lowercase letters, digits, . _ -" ;; esac
    read_password pw
    printf '%s\n' "$pw" | compose run --rm -T --no-deps atlas atlas user "$action" "$name" --password-stdin
}

wait_healthy() {
    local id status
    id="$(compose ps -q atlas)"
    for _ in $(seq 1 60); do
        status="$(docker inspect -f '{{.State.Health.Status}}' "$id" 2>/dev/null || echo starting)"
        [ "$status" = healthy ] && return 0
        [ "$status" = unhealthy ] && break
        sleep 2
    done
    compose logs --tail 40 atlas >&2
    die "atlas did not become healthy (status: ${status:-unknown})"
}

print_access() {
    local port host mode fp
    mode="$(env_get ATLAS_MODE)"
    port="$(env_get ATLAS_PORT)"; port="${port:-8443}"
    host="$(env_get ATLAS_HOSTS | cut -d, -f1)"
    if [ "$mode" = proxy ]; then
        port="$(env_get ATLAS_PORT)"
        say "atlas listens on http://127.0.0.1:${port:-8080} for your reverse proxy"
        return
    fi
    fp="$(compose logs atlas 2>/dev/null | grep -o 'SHA-256 [0-9A-F:]*' | tail -n 1 || true)"
    say "open https://$host:$port  (self-signed certificate${fp:+, $fp}; accept it once)"
    if compose logs atlas 2>/dev/null | grep -q "First run:"; then
        say "first run: no account yet. Create one with: $0 user add admin  (or use /setup with the token from: $0 logs)"
    fi
}

cmd_install() {
    local build=0 make_user=1
    for a in "$@"; do
        case "$a" in --build) build=1 ;; --no-user) make_user=0 ;; *) die "unknown option $a" ;; esac
    done
    preflight
    say "installing into $ATLAS_DIR"
    mkdir -p "$ATLAS_DIR/config/annotations" "$ATLAS_DIR/secrets"
    chmod 700 "$ATLAS_DIR/secrets"
    cp "$REPO_DIR/docker-compose.yml" "$REPO_DIR/docker-compose.proxy.yml" "$ATLAS_DIR/"
    # The compose file's `build: .` context: point it at this clone.
    sed -i.bak "s|^    build: \\.|    build: $REPO_DIR|" "$ATLAS_DIR/docker-compose.yml" && rm -f "$ATLAS_DIR/docker-compose.yml.bak"
    if [ ! -s "$ATLAS_DIR/secrets/atlas_master_key" ]; then
        say "generating the master key (encrypts the passwords and API keys you enter in the UI)"
        (umask 077; head -c 48 /dev/urandom | base64 > "$ATLAS_DIR/secrets/atlas_master_key")
    fi
    chmod 0400 "$ATLAS_DIR/secrets/atlas_master_key"
    [ -s "$ATLAS_DIR/secrets/mcp_token" ] || (umask 077; head -c 36 /dev/urandom | base64 | tr -d '\n=' > "$ATLAS_DIR/secrets/mcp_token")
    own "$ATLAS_DIR/secrets" "$ATLAS_DIR/config/annotations"
    if [ ! -f "$ATLAS_DIR/.env" ]; then
        (umask 077; : > "$ATLAS_DIR/.env")
        env_set ATLAS_MODE lan
        env_set ATLAS_HOSTS "$(detect_hosts)"
        env_set ATLAS_PORT 8443
        env_set ATLAS_VERSION latest
        say "wrote $ATLAS_DIR/.env (ATLAS_HOSTS=$(env_get ATLAS_HOSTS)); edit it to add names you use"
    fi
    get_image "$build"
    if [ "$make_user" = 1 ]; then
        say "create your atlas login (stored with argon2id in the database)"
        read -r -p "Username [admin]: " name || true
        name="${name%$'\r'}"
        user_cmd add "${name:-admin}"
    fi
    compose up -d
    wait_healthy
    print_access
    say "next: log in, open Targets, add Proxmox / UniFi / your VMs. Back up $ATLAS_DIR/secrets/atlas_master_key somewhere safe."
}

cmd_update() {
    local build=0
    [ "${1:-}" = "--build" ] && build=1
    preflight
    [ -f "$ATLAS_DIR/.env" ] || die "not installed in $ATLAS_DIR (run install first)"
    cp "$REPO_DIR/docker-compose.yml" "$REPO_DIR/docker-compose.proxy.yml" "$ATLAS_DIR/"
    sed -i.bak "s|^    build: \\.|    build: $REPO_DIR|" "$ATLAS_DIR/docker-compose.yml" && rm -f "$ATLAS_DIR/docker-compose.yml.bak"
    if [ "$(env_get ATLAS_VERSION)" = local ]; then build=1; fi
    get_image "$build"
    compose up -d
    wait_healthy
    print_access
}

cmd_backup() {
    local out="${1:-atlas-backup-$(date +%Y%m%d-%H%M%S).tar.gz}" tmp
    tmp="$(mktemp -d)"
    compose exec -T atlas python -c "import sqlite3; c=sqlite3.connect('/data/atlas.db'); c.execute(\"VACUUM INTO '/data/backup.db'\")"
    docker cp "$(compose ps -q atlas):/data/backup.db" "$tmp/atlas.db"
    compose exec -T atlas rm -f /data/backup.db
    docker cp "$(compose ps -q atlas):/data/inventory.yaml" "$tmp/inventory.yaml" 2>/dev/null || true
    docker cp "$(compose ps -q atlas):/data/vault.json" "$tmp/vault.json" 2>/dev/null || true
    cp -r "$ATLAS_DIR/config" "$ATLAS_DIR/.env" "$tmp/"
    tar -czf "$out" -C "$tmp" .
    rm -rf "$tmp"
    say "wrote $out (encrypt it: it maps your network). The master key is NOT in it; keep $ATLAS_DIR/secrets/atlas_master_key separately."
}

main() {
    local cmd="${1:-}"
    [ $# -gt 0 ] && shift
    case "$cmd" in
        install) cmd_install "$@" ;;
        update) cmd_update "$@" ;;
        user)
            case "${1:-}" in
                add|passwd) user_cmd "$1" "${2:-}" ;;
                *) die "usage: atlas.sh user add|passwd <name>" ;;
            esac ;;
        status) compose ps; print_access ;;
        logs) compose logs -f atlas ;;
        backup) cmd_backup "$@" ;;
        stop) compose stop ;;
        start) compose up -d && wait_healthy && print_access ;;
        uninstall)
            if [ "${1:-}" = "--purge" ]; then compose down -v; else compose down; fi ;;
        ""|-h|--help|help) usage ;;
        *) usage; exit 2 ;;
    esac
}

main "$@"
