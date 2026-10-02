#!/usr/bin/env bash
set -Eeuo pipefail

LOCK_FILE="/run/lock/piervuln-mhomolog-sync.lock"
PAUSE_FILE="/var/lib/piervuln-mhomolog-sync.paused"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute como root: sudo $0" >&2
  exit 1
fi

install -o root -g root -m 0600 /dev/null "$PAUSE_FILE"
if [[ -e "$LOCK_FILE" ]]; then
  exec 9>"$LOCK_FILE"
  if ! flock -w 200 9; then
    echo "A execução não terminou dentro do limite; a pausa segue ativa." >&2
    exit 1
  fi
  flock -u 9
  exec 9>&-
fi

mapfile -t containers < <(docker ps \
  --filter label=com.docker.compose.project=piervuln-mhomolog-sync \
  --filter label=com.docker.compose.service=wazuh-connector \
  --format '{{.ID}}')

if [[ "${#containers[@]}" -gt 0 ]]; then
  docker stop --time 180 "${containers[@]}"
fi

echo "Worker pausado. Retome com sudo bash $SCRIPT_DIR/resume-sync.sh."
