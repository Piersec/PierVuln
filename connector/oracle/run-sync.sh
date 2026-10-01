#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
CONNECTIONS_DIR="$SCRIPT_DIR/connections"
LOCK_FILE="/run/lock/piervuln-wazuh-sync.lock"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute este job como root para usar Docker e validar a VPN do host." >&2
  exit 1
fi

if ! systemctl is-active --quiet openvpn-client@wazuh; then
  echo "A VPN openvpn-client@wazuh não está ativa; nenhuma conexão foi sincronizada." >&2
  exit 1
fi

mkdir -p "$(dirname -- "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "Já existe um job Wazuh em execução; esta chamada foi ignorada."
  exit 0
fi

shopt -s nullglob
env_files=("$CONNECTIONS_DIR"/*/.env)
if [[ "${#env_files[@]}" -eq 0 ]]; then
  echo "Nenhuma configuração encontrada em $CONNECTIONS_DIR/<conexão>/.env." >&2
  exit 1
fi

failed=0
for env_file in "${env_files[@]}"; do
  connection_name="$(basename -- "$(dirname -- "$env_file")")"
  echo "[$(date --iso-8601=seconds)] Iniciando snapshot da conexão $connection_name."
  if ! CONNECTOR_ENV_FILE="$env_file" docker compose \
    --project-name piervuln-wazuh-sync \
    --project-directory "$SCRIPT_DIR" \
    --env-file "$env_file" \
    --file "$COMPOSE_FILE" \
    run --rm --no-deps wazuh-connector; then
    echo "[$(date --iso-8601=seconds)] Falha na conexão $connection_name; as próximas serão tentadas." >&2
    failed=1
  fi
done

exit "$failed"
