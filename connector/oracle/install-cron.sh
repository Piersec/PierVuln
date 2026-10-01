#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONNECTIONS_DIR="$SCRIPT_DIR/connections"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
SYNC_SCRIPT="$SCRIPT_DIR/run-sync.sh"
CRON_FILE="/etc/cron.d/piervuln-wazuh-sync"
LOG_FILE="/var/log/piervuln-wazuh-sync.log"
SYNC_EVERY_MINUTES="${SYNC_EVERY_MINUTES:-60}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute como root: sudo $0" >&2
  exit 1
fi

if [[ "$SCRIPT_DIR" =~ [^A-Za-z0-9_./-] ]]; then
  echo "Instale o projeto em um caminho sem espaços ou caracteres especiais, por exemplo /opt/piervuln." >&2
  exit 1
fi

if [[ ! "$SYNC_EVERY_MINUTES" =~ ^([1-9]|[1-5][0-9]|60)$ ]]; then
  echo "SYNC_EVERY_MINUTES deve ser um inteiro entre 1 e 60." >&2
  exit 1
fi
if (( 60 % SYNC_EVERY_MINUTES != 0 )); then
  echo "SYNC_EVERY_MINUTES deve dividir uma hora sem resto (por exemplo, 15, 20 ou 30)." >&2
  exit 1
fi

if ! systemctl is-active --quiet openvpn-client@wazuh; then
  echo "Configure e inicie openvpn-client@wazuh antes de instalar o cron." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Engine com o plugin Docker Compose não está disponível." >&2
  exit 1
fi

if ! command -v crontab >/dev/null 2>&1; then
  apt-get update
  apt-get install -y cron
fi
systemctl enable --now cron

shopt -s nullglob
env_files=("$CONNECTIONS_DIR"/*/.env)
if [[ "${#env_files[@]}" -eq 0 ]]; then
  echo "Crie ao menos uma configuração em $CONNECTIONS_DIR/<conexão>/.env antes de instalar." >&2
  exit 1
fi

for env_file in "${env_files[@]}"; do
  chmod 600 "$env_file"
done

first_env_file="${env_files[0]}"
CONNECTOR_ENV_FILE="$first_env_file" docker compose \
  --project-name piervuln-wazuh-sync \
  --project-directory "$SCRIPT_DIR" \
  --env-file "$first_env_file" \
  --file "$COMPOSE_FILE" \
  build wazuh-connector

touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
cron_temp="$(mktemp /tmp/piervuln-wazuh-sync.XXXXXX)"
trap 'rm -f "$cron_temp"' EXIT
if [[ "$SYNC_EVERY_MINUTES" -eq 60 ]]; then
  cron_schedule="0 * * * *"
else
  cron_schedule="*/$SYNC_EVERY_MINUTES * * * *"
fi
printf '%s root /bin/bash %s >> %s 2>&1\n' "$cron_schedule" "$SYNC_SCRIPT" "$LOG_FILE" > "$cron_temp"
install -o root -g root -m 0644 "$cron_temp" "$CRON_FILE"

echo "Job instalado para rodar a cada $SYNC_EVERY_MINUTES minuto(s). Log: $LOG_FILE"
