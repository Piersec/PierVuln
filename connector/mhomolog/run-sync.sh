#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
CONNECTIONS_DIR="$SCRIPT_DIR/connections"
LOCK_FILE="/run/lock/piervuln-mhomolog-sync.lock"
PAUSE_FILE="/var/lib/piervuln-mhomolog-sync.paused"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute como root: sudo $0" >&2
  exit 1
fi

if [[ "${SCRIPT_DIR}" =~ [^A-Za-z0-9_./-] ]]; then
  echo "Instale o projeto em um caminho sem espaços ou caracteres especiais, por exemplo /opt/piervuln." >&2
  exit 1
fi

if [[ -e "$PAUSE_FILE" ]]; then
  echo "[$(date --iso-8601=seconds)] Sincronização pausada; nenhuma conexão iniciada."
  exit 0
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Engine com o plugin Docker Compose não está disponível." >&2
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

first_env_file="${env_files[0]}"
bash "$SCRIPT_DIR/prepare-image.sh" "$first_env_file"

failed=0
for env_file in "${env_files[@]}"; do
  if [[ -e "$PAUSE_FILE" ]]; then
    echo "[$(date --iso-8601=seconds)] Pausa solicitada; próximas conexões não serão iniciadas."
    break
  fi

  connection_name="$(basename -- "$(dirname -- "$env_file")")"
  echo "[$(date --iso-8601=seconds)] Iniciando snapshot da conexão $connection_name."
  if ! CONNECTOR_ENV_FILE="$env_file" docker compose \
    --project-name piervuln-mhomolog-sync \
    --project-directory "$SCRIPT_DIR" \
    --env-file "$env_file" \
    --file "$COMPOSE_FILE" \
    run --rm --no-deps wazuh-connector; then
    if [[ -e "$PAUSE_FILE" ]]; then
      echo "[$(date --iso-8601=seconds)] Conexão interrompida pela pausa; nenhuma próxima conexão será iniciada."
      break
    fi
    echo "[$(date --iso-8601=seconds)] Falha na conexão $connection_name; as próximas serão tentadas." >&2
    failed=1
  fi
done

exit "$failed"
