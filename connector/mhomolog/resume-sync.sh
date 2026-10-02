#!/usr/bin/env bash
set -Eeuo pipefail

PAUSE_FILE="/var/lib/piervuln-mhomolog-sync.paused"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute como root: sudo $0" >&2
  exit 1
fi

rm -f "$PAUSE_FILE"
echo "Pausa removida; a próxima sincronização ocorrerá no próximo horário do cron."
