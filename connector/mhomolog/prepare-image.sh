#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BRANCH="${PIERVULN_GIT_BRANCH:-master}"
BUILD_MARKER="/var/lib/piervuln-mhomolog-sync-image-commit"
ENV_FILE="${1:?Informe o caminho do .env da conexão para o build.}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute como root: sudo bash $0 <arquivo.env>" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Arquivo de conexão não encontrado: $ENV_FILE" >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1 || [[ ! -d "$REPO_ROOT/.git" ]]; then
  echo "O código precisa estar em um clone Git para acompanhar commits. Clone PierVuln em vez de extrair um ZIP." >&2
  exit 1
fi

REPO_OWNER="$(stat -c '%U' "$REPO_ROOT")"
run_repo_git() {
  if [[ "$REPO_OWNER" == "root" ]]; then
    git -C "$REPO_ROOT" "$@"
    return
  fi

  if ! command -v runuser >/dev/null 2>&1; then
    echo "O comando runuser é necessário para atualizar um clone pertencente a $REPO_OWNER." >&2
    return 1
  fi

  local owner_home
  owner_home="$(getent passwd "$REPO_OWNER" | cut -d: -f6)"
  if [[ -z "$owner_home" ]]; then
    echo "Não foi possível encontrar o diretório pessoal do proprietário do clone ($REPO_OWNER)." >&2
    return 1
  fi

  env HOME="$owner_home" USER="$REPO_OWNER" LOGNAME="$REPO_OWNER" \
    runuser -u "$REPO_OWNER" -- git -C "$REPO_ROOT" "$@"
}

CURRENT_BRANCH="$(run_repo_git branch --show-current)"
if [[ "$CURRENT_BRANCH" != "$BRANCH" ]]; then
  echo "O clone está na branch '$CURRENT_BRANCH', mas a branch configurada é '$BRANCH'; imagem não atualizada." >&2
  exit 1
fi

WORKTREE_DIRTY=0
if [[ -n "$(run_repo_git status --porcelain)" ]]; then
  WORKTREE_DIRTY=1
  echo "[$(date --iso-8601=seconds)] Clone tem alterações locais; mantendo o código e a imagem atuais, sem git pull." >&2
else
  shallow_clone="$(run_repo_git rev-parse --is-shallow-repository)"
  if [[ "$shallow_clone" == "true" ]]; then
    fetch_result=0
    run_repo_git fetch --quiet --unshallow origin "$BRANCH" || fetch_result=$?
  else
    fetch_result=0
    run_repo_git fetch --quiet origin "$BRANCH" || fetch_result=$?
  fi

  if [[ "$fetch_result" -eq 0 ]]; then
    local_commit="$(run_repo_git rev-parse HEAD)"
    remote_commit="$(run_repo_git rev-parse FETCH_HEAD)"
    if [[ "$local_commit" != "$remote_commit" ]]; then
      if run_repo_git merge-base --is-ancestor "$local_commit" "$remote_commit"; then
        if run_repo_git merge --ff-only "$remote_commit"; then
          echo "[$(date --iso-8601=seconds)] Código atualizado para $(run_repo_git rev-parse --short HEAD)."
        else
          echo "Não foi possível avançar o clone até origin/$BRANCH; mantendo a imagem atual." >&2
        fi
      else
        echo "origin/$BRANCH divergiu do clone local; mantendo o código e a imagem atuais." >&2
      fi
    fi
  else
    echo "[$(date --iso-8601=seconds)] Falha ao consultar origin/$BRANCH; continuando com a última imagem disponível." >&2
  fi
fi

SOURCE_COMMIT="$(run_repo_git rev-parse HEAD)"
SOURCE_SHORT_COMMIT="$(run_repo_git rev-parse --short HEAD)"
BUILT_COMMIT=""
if [[ -f "$BUILD_MARKER" ]]; then
  BUILT_COMMIT="$(<"$BUILD_MARKER")"
fi

if [[ "$SOURCE_COMMIT" == "$BUILT_COMMIT" ]]; then
  echo "[$(date --iso-8601=seconds)] Imagem já corresponde ao commit $SOURCE_SHORT_COMMIT; sem rebuild."
  exit 0
fi

if [[ "$WORKTREE_DIRTY" -eq 1 ]]; then
  echo "Clone com alterações locais e sem imagem para o commit atual; não vou construir código não commitado." >&2
  exit 1
fi

echo "[$(date --iso-8601=seconds)] Construindo a imagem para o commit $SOURCE_SHORT_COMMIT."
if ! CONNECTOR_ENV_FILE="$ENV_FILE" docker compose \
  --project-name piervuln-mhomolog-sync \
  --project-directory "$SCRIPT_DIR" \
  --env-file "$ENV_FILE" \
  --file "$COMPOSE_FILE" \
  build wazuh-connector; then
  echo "Build falhou; não será iniciado um job com imagem antiga." >&2
  exit 1
fi

install -d -m 0755 "$(dirname -- "$BUILD_MARKER")"
marker_temp="$(mktemp "${BUILD_MARKER}.XXXXXX")"
trap 'rm -f "$marker_temp"' EXIT
printf '%s\n' "$SOURCE_COMMIT" > "$marker_temp"
chmod 0644 "$marker_temp"
mv -f "$marker_temp" "$BUILD_MARKER"
trap - EXIT
