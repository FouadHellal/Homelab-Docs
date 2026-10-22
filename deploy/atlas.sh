#!/usr/bin/env bash
# atlas deploy helper: install / update / accounts / status / backup for the docker compose stack.
#
#   git clone https://github.com/FouadHellal/Homelab-Docs.git && cd Homelab-Docs
#   sudo ./deploy/atlas.sh install            # pulls the image (or builds it), creates an account, starts
#   sudo atlas update                         # later: one command, keeps your data (see cmd_update)
#   sudo atlas user add alice                 # more accounts at any time
#
# install puts an `atlas` shortcut in /usr/local/bin pointing at this script.
# Everything lives in $ATLAS_DIR (default /opt/atlas): docker-compose.yml, .env, secrets/, config/.
# The script never touches your homelab targets; it only manages this host's atlas containers.
set -euo pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
REPO_DIR="$(cd "$(dirname "$SELF")/.." && pwd)"
BIN_LINK="${ATLAS_BIN_LINK:-/usr/local/bin/atlas}"
KEEP_BACKUPS="${ATLAS_KEEP_BACKUPS:-5}"
GIT="${ATLAS_GIT:-git}"
SUDOERS_FILE="${ATLAS_SUDOERS_FILE:-/etc/sudoers.d/atlas-mcp}"
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
  update  [--build] [--no-pull] [--no-backup]
                                  git pull this clone, back up the DB, newer image, restart.
                                  Keeps .env, secrets/, config/ and the data volume (targets,
                                  passwords, accounts, history).
  user add <name>                 create a web account (asks for the password)
  user passwd <name>              change a password (ends that user's sessions)
  status                          containers, health, URL, certificate fingerprint
  logs                            follow atlas logs
  backup [file.tar.gz]            consistent DB copy + config (NOT the master key)
  version                         running atlas version
  mcp [--allow-scan] [--sanitize] MCP server on stdin/stdout, for Claude over SSH (see docs)
  mcp-allow <user> [--allow-scan] let <user> start `atlas mcp` with sudo, no password (SSH)
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
    link_cli
    print_access
    say "update later with: sudo atlas update"
    say "next: log in, open Targets, add Proxmox / UniFi / your VMs. Back up $ATLAS_DIR/secrets/atlas_master_key somewhere safe."
}

link_cli() {  # `atlas` on PATH, so updates are one command
    [ "$(id -u)" -eq 0 ] || return 0
    [ -d "$(dirname "$BIN_LINK")" ] || return 0
    if [ -e "$BIN_LINK" ] && [ ! -L "$BIN_LINK" ]; then
        warn "$BIN_LINK exists and is not our shortcut; leaving it alone"
        return 0
    fi
    chmod 0755 "$REPO_DIR/deploy/atlas.sh"  # a clone made where git kept no exec bit
    ln -sfn "$REPO_DIR/deploy/atlas.sh" "$BIN_LINK"
}

repo_git() {  # git in the clone, as the clone's owner: their credentials reach a private
              # GitHub repo, root's (under sudo) usually don't
    local owner
    owner="$(stat -c %U "$REPO_DIR" 2>/dev/null || echo root)"
    if [ "$(id -u)" -eq 0 ] && [ "$owner" != root ] && [ "$owner" != UNKNOWN ] \
        && command -v sudo >/dev/null 2>&1; then
        sudo -u "$owner" -H "$GIT" -c safe.directory="$REPO_DIR" -C "$REPO_DIR" "$@"
    else
        "$GIT" -c safe.directory="$REPO_DIR" -C "$REPO_DIR" "$@"
    fi
}

git_pull() {  # fast-forward this clone; never discards local edits; stops loudly on failure
    [ -d "$REPO_DIR/.git" ] || { warn "$REPO_DIR is not a git clone; skipping the code update"; return 1; }
    command -v "$GIT" >/dev/null 2>&1 || die "git is not installed (apt install git), or run: $0 update --no-pull"
    local before after changed
    before="$(repo_git rev-parse HEAD 2>/dev/null || true)"
    changed="$(repo_git status --porcelain --untracked-files=no 2>/dev/null || true)"
    say "updating the code in $REPO_DIR"
    if ! repo_git pull --ff-only; then
        [ -z "$changed" ] || warn "files changed in the clone (git refuses to overwrite them):
$changed"
        die "git pull failed, so nothing was updated (atlas still runs the old version).
  Private repository? git must log in as the clone's owner: run   git -C $REPO_DIR pull   yourself.
  Local edits? keep them with   git -C $REPO_DIR stash   (or drop them with   git -C $REPO_DIR checkout -- .).
  Then run   sudo atlas update --no-pull"
    fi
    after="$(repo_git rev-parse HEAD 2>/dev/null || true)"
    if [ "$before" != "$after" ]; then
        say "code: ${before:0:7} -> ${after:0:7}"
    else
        say "code already up to date (${after:0:7})"
    fi
    return 0
}

prune_backups() {  # keep the newest $KEEP_BACKUPS pre-update backups (names sort by date)
    local files=("$ATLAS_DIR/backups"/pre-update-*.tar.gz) i n
    [ -e "${files[0]}" ] || return 0
    n=$(( ${#files[@]} - KEEP_BACKUPS ))
    for (( i = 0; i < n; i++ )); do rm -f -- "${files[i]}"; done
}

cmd_update() {
    local build=0 pull=1 backup=1 a
    for a in "$@"; do
        case "$a" in
            --build) build=1 ;; --no-pull) pull=0 ;; --no-backup) backup=0 ;;
            *) die "unknown option $a" ;;
        esac
    done
    [ -f "$ATLAS_DIR/.env" ] || die "not installed in $ATLAS_DIR (run install first)"
    if [ "$pull" = 1 ] && [ -z "${ATLAS_UPDATE_REEXEC:-}" ] && git_pull; then
        # Run the freshly pulled script, so a fixed update procedure applies to this update.
        ATLAS_UPDATE_REEXEC=1 exec bash "$REPO_DIR/deploy/atlas.sh" update --no-pull "$@"
    fi
    preflight
    local was
    was="$(running_version)"
    if [ "$backup" = 1 ] && [ -n "$(compose ps -q atlas 2>/dev/null || true)" ]; then
        mkdir -p "$ATLAS_DIR/backups" && chmod 700 "$ATLAS_DIR/backups"
        cmd_backup "$ATLAS_DIR/backups/pre-update-$(date +%Y%m%d-%H%M%S).tar.gz"
        prune_backups
    fi
    cp "$REPO_DIR/docker-compose.yml" "$REPO_DIR/docker-compose.proxy.yml" "$ATLAS_DIR/"
    sed -i.bak "s|^    build: \\.|    build: $REPO_DIR|" "$ATLAS_DIR/docker-compose.yml" && rm -f "$ATLAS_DIR/docker-compose.yml.bak"
    if [ "$(env_get ATLAS_VERSION)" = local ]; then build=1; fi
    get_image "$build"
    compose up -d --force-recreate  # a new container even if compose thinks nothing changed
    wait_healthy
    link_cli
    local now
    now="$(running_version)"
    if [ -n "$was" ] && [ "$was" = "$now" ]; then
        warn "still running ${now:-an unknown version}: the code and the image did not change"
    else
        say "updated: ${was:-unknown} -> ${now:-unknown}"
    fi
    print_access
    say "your targets, passwords, accounts and history are kept (data volume + $ATLAS_DIR)"
    say "reload the page in your browser (Ctrl+F5) to get the new interface"
}

running_version() {  # "atlas 0.3.0" from the running container, empty if none
    compose exec -T atlas atlas --version 2>/dev/null | tail -n 1 | tr -d '\r' || true
}

cmd_version() {
    local v
    v="$(running_version)"
    say "running: ${v:-unknown}"
    if [ -d "$REPO_DIR/.git" ] && command -v "$GIT" >/dev/null 2>&1; then
        say "code in $REPO_DIR: $(repo_git log -1 --format='%h %s (%cr)' 2>/dev/null || echo unknown)"
    fi
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
    (umask 077; tar -czf - -C "$tmp" . > "$out")  # stdout: a "C:" path is not a remote host
    rm -rf "$tmp"
    say "wrote $out (encrypt it: it maps your network). The master key is NOT in it; keep $ATLAS_DIR/secrets/atlas_master_key separately."
}

cmd_mcp() {  # stdio MCP inside the atlas container: stdout is the protocol, print nothing else
    local a
    for a in "$@"; do
        case "$a" in --allow-scan|--sanitize) ;; *) die "unknown option $a" ;; esac
    done
    [ -f "$ATLAS_DIR/.env" ] || die "not installed in $ATLAS_DIR"
    [ -n "$(compose ps -q atlas 2>/dev/null || true)" ] || die "atlas is not running (sudo atlas start)"
    exec docker compose --project-directory "$ATLAS_DIR" -f "$ATLAS_DIR/docker-compose.yml" \
        exec -T atlas atlas mcp "$@"
}

cmd_mcp_allow() {  # sudoers rule for exactly `atlas mcp` (and optionally --allow-scan)
    local user="${1:-}" scan="${2:-}" rule tmp host
    [ -n "$user" ] || die "usage: atlas.sh mcp-allow <user> [--allow-scan]"
    case "$user" in *[!a-z0-9._-]*|root) die "a normal user name, please (not root)" ;; esac
    [ -z "$scan" ] || [ "$scan" = "--allow-scan" ] || die "unknown option $scan"
    [ "$(id -u)" -eq 0 ] || die "run with sudo"
    id "$user" >/dev/null 2>&1 || die "no such user: $user"
    command -v visudo >/dev/null 2>&1 || die "visudo is missing (apt install sudo)"
    # Exact command lines only. --sanitize is always allowed (it can only hide more).
    rule="$user ALL=(root) NOPASSWD: $BIN_LINK mcp, $BIN_LINK mcp --sanitize"
    if [ "$scan" = "--allow-scan" ]; then
        rule="$rule, $BIN_LINK mcp --allow-scan, $BIN_LINK mcp --allow-scan --sanitize"
        rule="$rule, $BIN_LINK mcp --sanitize --allow-scan"
    fi
    tmp="$(mktemp)"
    printf '# atlas: %s may start the MCP server over SSH (atlas.sh mcp-allow)\n%s\n' \
        "$user" "$rule" > "$tmp"
    visudo -cf "$tmp" >/dev/null || { rm -f "$tmp"; die "sudoers rule did not validate"; }
    install -m 0440 -o root -g root "$tmp" "$SUDOERS_FILE"
    rm -f "$tmp"
    link_cli
    host="$(hostname -I 2>/dev/null | awk '{print $1}')"
    say "done: $user can run 'sudo atlas mcp${scan:+ $scan}' without a password"
    say "Claude Code, on your PC:"
    printf '  claude mcp add --transport stdio --scope user atlas -- ssh -T %s@%s sudo atlas mcp%s\n' \
        "$user" "${host:-<this-vm>}" "${scan:+ $scan}"
    say "Claude Desktop: see https://github.com/FouadHellal/Homelab-Docs/blob/main/docs/MCP.md"
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
        version) cmd_version ;;
        mcp) cmd_mcp "$@" ;;
        mcp-allow) cmd_mcp_allow "$@" ;;
        stop) compose stop ;;
        start) compose up -d && wait_healthy && print_access ;;
        uninstall)
            if [ "${1:-}" = "--purge" ]; then compose down -v; else compose down; fi ;;
        ""|-h|--help|help) usage ;;
        *) usage; exit 2 ;;
    esac
}

main "$@"
