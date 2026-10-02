#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONNECTIONS_DIR="/opt/piervuln/config/connections"
CA_BUNDLE="/opt/piervuln/config/indexers-ca-bundle.pem"
CRON_FILE="/etc/cron.d/piervuln-mhomolog-sync"
LOG_FILE="/var/log/piervuln-mhomolog-sync.log"
SYNC_EVERY_MINUTES="${SYNC_EVERY_MINUTES:-5}"
ENV_FILE="$SCRIPT_DIR/.env"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute como root: sudo $0" >&2
  exit 1
fi

if [[ "$SCRIPT_DIR" =~ [^A-Za-z0-9_./-] ]]; then
  echo "Instale o projeto em um caminho sem espaços ou caracteres especiais, por exemplo /opt/piervuln/PierVuln." >&2
  exit 1
fi

if [[ ! "$SYNC_EVERY_MINUTES" =~ ^(1|2|3|4|5|6|10|12|15|20|30|60)$ ]]; then
  echo "SYNC_EVERY_MINUTES deve ser 1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30 ou 60." >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Crie $ENV_FILE a partir de worker.env.example e configure o Supabase." >&2
  exit 1
fi
if [[ ! -d "$CONNECTIONS_DIR" ]]; then
  echo "Pasta de conexões não encontrada: $CONNECTIONS_DIR" >&2
  exit 1
fi
if [[ ! -f "$CA_BUNDLE" ]]; then
  echo "Bundle de CAs dos Indexers não encontrado: $CA_BUNDLE" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Engine com o plugin Docker Compose não está disponível." >&2
  exit 1
fi

shopt -s nullglob
env_files=("$CONNECTIONS_DIR"/*/.env)
if [[ "${#env_files[@]}" -eq 0 ]]; then
  echo "Crie ao menos uma configuração em $CONNECTIONS_DIR/<nome>/.env." >&2
  exit 1
fi

chmod 600 "$ENV_FILE"
for env_file in "${env_files[@]}"; do
  chmod 600 "$env_file"
done

if ! command -v crontab >/dev/null 2>&1; then
  apt-get update
  apt-get install -y cron
fi
systemctl enable --now cron

bash "$SCRIPT_DIR/update-worker.sh"

touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
cat > /etc/logrotate.d/piervuln-mhomolog-sync <<EOF
$LOG_FILE {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    create 0600 root root
}
EOF

cron_temp="$(mktemp /tmp/piervuln-mhomolog-sync.XXXXXX)"
trap 'rm -f "$cron_temp"' EXIT
if [[ "$SYNC_EVERY_MINUTES" -eq 60 ]]; then
  cron_schedule="0 * * * *"
else
  cron_schedule="*/$SYNC_EVERY_MINUTES * * * *"
fi
printf '%s root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /bin/bash %s/update-worker.sh >> %s 2>&1\n' \
  "$cron_schedule" "$SCRIPT_DIR" "$LOG_FILE" > "$cron_temp"
install -o root -g root -m 0644 "$cron_temp" "$CRON_FILE"

echo "Worker contínuo iniciado. O Git será verificado a cada $SYNC_EVERY_MINUTES minuto(s); log: $LOG_FILE"
