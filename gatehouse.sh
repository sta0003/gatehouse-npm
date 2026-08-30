#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

green='\033[0;32m'
cyan='\033[0;36m'
yellow='\033[0;33m'
red='\033[0;31m'
reset='\033[0m'

info() { printf '%b%s%b\n' "$cyan" "$*" "$reset"; }
success() { printf '%b%s%b\n' "$green" "$*" "$reset"; }
warn() { printf '%b%s%b\n' "$yellow" "$*" "$reset"; }
fail() { printf '%bError: %s%b\n' "$red" "$*" "$reset" >&2; exit 1; }

usage() {
  cat <<'EOF'
Gatehouse Docker helper

Usage: ./gatehouse.sh COMMAND

  install   First-time setup, build, and start Gatehouse
  start     Start the existing installation
  stop      Stop Gatehouse without deleting its data
  restart   Restart Gatehouse
  rebuild   Rebuild the image and apply local code changes
  update    Pull the latest Git version, rebuild, and start
  status    Show container and health status
  logs      Follow the Gatehouse logs (Ctrl+C to exit)
  help      Show this help

No command opens an interactive menu when run in a terminal.
EOF
}

require_docker() {
  command -v docker >/dev/null 2>&1 || fail "Docker is not installed. Install Docker Engine and the Compose plugin first."
  docker compose version >/dev/null 2>&1 || fail "The Docker Compose plugin is not installed."
  docker info >/dev/null 2>&1 || fail "Docker is not running, or this user cannot access it."
}

write_password() {
  local password confirmation
  if [[ ! -t 0 ]]; then
    fail "No usable .env file exists. Run ./gatehouse.sh install in a terminal to choose the admin password."
  fi
  printf '\nCreate the Gatehouse administrator password.\n'
  printf 'Use at least 12 characters. Letters, numbers, and . _ @ %% + = : , / - are supported.\n\n'
  while true; do
    read -r -s -p 'Admin password: ' password
    printf '\n'
    read -r -s -p 'Confirm password: ' confirmation
    printf '\n'
    [[ "$password" == "$confirmation" ]] || { warn "Passwords do not match. Try again."; continue; }
    (( ${#password} >= 12 )) || { warn "Password must be at least 12 characters."; continue; }
    (( ${#password} <= 1024 )) || { warn "Password is too long."; continue; }
    [[ "$password" =~ ^[A-Za-z0-9._@%+=:,/-]+$ ]] || { warn "The password contains characters that are unsafe in a Docker .env file."; continue; }
    break
  done
  umask 077
  printf 'ADMIN_PASSWORD=%s\n' "$password" > .env
  chmod 600 .env
  unset password confirmation
}

ensure_environment() {
  mkdir -p data letsencrypt
  if [[ ! -f .env ]] || grep -q '^ADMIN_PASSWORD=replace-this-' .env; then
    write_password
  else
    chmod 600 .env
    grep -q '^ADMIN_PASSWORD=.' .env || fail ".env does not contain ADMIN_PASSWORD."
  fi
}

wait_for_health() {
  local state='starting'
  for _ in {1..45}; do
    state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' gatehouse 2>/dev/null || true)"
    [[ "$state" == 'healthy' ]] && break
    [[ "$state" == 'unhealthy' || "$state" == 'exited' ]] && break
    sleep 1
  done
  if [[ "$state" != 'healthy' ]]; then
    docker compose ps
    docker compose logs --tail 40 gatehouse
    fail "Gatehouse did not become healthy (state: ${state:-unknown})."
  fi
}

show_address() {
  local lan_ip=''
  if command -v hostname >/dev/null 2>&1; then
    lan_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  printf '\n'
  success "Gatehouse is running and healthy."
  printf 'Dashboard: %bhttp://%s:8080%b\n' "$cyan" "${lan_ip:-localhost}" "$reset"
  printf 'Username:  admin\n'
  printf 'Data:      %s/data\n' "$SCRIPT_DIR"
  printf 'TLS state: %s/letsencrypt\n\n' "$SCRIPT_DIR"
  warn "Keep port 8080 private. Only forward ports 80 and 443 from your router."
}

install_gatehouse() {
  require_docker
  ensure_environment
  info "Building and starting Gatehouse…"
  docker compose up -d --build
  wait_for_health
  show_address
}

start_gatehouse() {
  require_docker
  ensure_environment
  info "Starting Gatehouse…"
  docker compose up -d
  wait_for_health
  show_address
}

stop_gatehouse() {
  require_docker
  info "Stopping Gatehouse…"
  docker compose stop
  success "Gatehouse stopped. Persistent data was not removed."
}

restart_gatehouse() {
  require_docker
  ensure_environment
  info "Restarting Gatehouse…"
  docker compose restart
  wait_for_health
  show_address
}

rebuild_gatehouse() {
  require_docker
  ensure_environment
  info "Rebuilding Gatehouse and applying local changes…"
  docker compose up -d --build
  wait_for_health
  show_address
}

update_gatehouse() {
  require_docker
  ensure_environment
  command -v git >/dev/null 2>&1 || fail "Git is required for updates."
  [[ -d .git ]] || fail "This installation was not cloned with Git. Download the new files, then run ./gatehouse.sh rebuild."
  if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    fail "Local tracked files have changes. Commit or resolve them before updating; no files were overwritten."
  fi
  warn "Create a dashboard backup before major upgrades."
  info "Downloading the latest Gatehouse version…"
  git pull --ff-only
  rebuild_gatehouse
}

show_status() {
  require_docker
  docker compose ps
  if docker inspect gatehouse >/dev/null 2>&1; then
    printf '\nHealth: %s\n' "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' gatehouse)"
  fi
}

show_logs() {
  require_docker
  docker compose logs --tail 100 -f gatehouse
}

menu() {
  printf '\n%bGatehouse Docker Manager%b\n\n' "$cyan" "$reset"
  printf '  1) Install / start\n  2) Status\n  3) Rebuild local changes\n  4) Update from GitHub\n  5) Restart\n  6) Stop\n  7) View logs\n  8) Exit\n\n'
  read -r -p 'Choose an option: ' choice
  case "$choice" in
    1) install_gatehouse ;;
    2) show_status ;;
    3) rebuild_gatehouse ;;
    4) update_gatehouse ;;
    5) restart_gatehouse ;;
    6) stop_gatehouse ;;
    7) show_logs ;;
    8) exit 0 ;;
    *) fail "Unknown menu option." ;;
  esac
}

command_name="${1:-}"
if [[ -z "$command_name" ]]; then
  [[ -t 0 ]] && menu || usage
else
  case "$command_name" in
    install) install_gatehouse ;;
    start) start_gatehouse ;;
    stop) stop_gatehouse ;;
    restart) restart_gatehouse ;;
    rebuild) rebuild_gatehouse ;;
    update) update_gatehouse ;;
    status) show_status ;;
    logs) show_logs ;;
    help|-h|--help) usage ;;
    *) usage; fail "Unknown command: $command_name" ;;
  esac
fi
