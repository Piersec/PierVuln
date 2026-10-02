#!/usr/bin/env bash
set -Eeuo pipefail

PAUSE_FILE="/var/lib/piervuln-mhomolog-sync.paused"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute como root: sudo $0" >&2
  exit 1
fi

rm -f "$PAUSE_FILE"
bash "$SCRIPT_DIR/update-worker.sh"
