#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
ENV_FILE="$SCRIPT_DIR/.env"
LOCK_FILE="/run/lock/piervuln-mhomolog-sync.lock"
PAUSE_FILE="/var/lib/piervuln-mhomolog-sync.paused"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute como root: sudo $0" >&2
  exit 1
fi

if [[ -e "$PAUSE_FILE" ]]; then
  echo "[$(date --iso-8601=seconds)] Worker pausado; atualização e inicialização ignoradas."
  exit 0
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Arquivo de ambiente global não encontrado: $ENV_FILE" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[$(date --iso-8601=seconds)] Outra atualização do worker já está em execução."
  exit 0
fi

bash "$SCRIPT_DIR/prepare-image.sh"
if [[ -e "$PAUSE_FILE" ]]; then
  echo "[$(date --iso-8601=seconds)] Pausa solicitada; o container não será iniciado."
  exit 0
fi

docker compose \
  --project-name piervuln-mhomolog-sync \
  --project-directory "$SCRIPT_DIR" \
  --env-file "$ENV_FILE" \
  --file "$COMPOSE_FILE" \
  up --detach --no-build --remove-orphans wazuh-connector
