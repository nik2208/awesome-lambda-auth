#!/usr/bin/env bash
# Containerised Node toolchain, per gli esempi web. Stessa regola del resto del
# repo: niente installato sull'host, tutto in un'immagine pinnata.
#
#   ./scripts/node-toolchain.sh examples/angular-client npm ci
#   ./scripts/node-toolchain.sh examples/angular-client npm run build
#   ./scripts/node-toolchain.sh examples/angular-client shell
#
# node_modules vive in un volume nominato per directory di progetto, non sul
# bind mount: su /mnt/c un install con decine di migliaia di file piccoli e'
# lentissimo, e i pacchetti con binari nativi vogliono comunque un filesystem
# Linux. Solo i sorgenti attraversano il mount.
set -euo pipefail

NODE_IMAGE="${NODE_IMAGE:-node:22-slim}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

PROJECT_DIR="${1:-}"
if [[ -z "${PROJECT_DIR}" ]]; then
  echo "usage: $0 <project-dir> {npm <args...>|npx <args...>|shell}" >&2
  exit 2
fi
shift

if [[ ! -d "${REPO_ROOT}/${PROJECT_DIR}" ]]; then
  echo "no such project directory: ${PROJECT_DIR}" >&2
  exit 2
fi

# Un volume per progetto: due esempi non devono condividere node_modules.
SLUG="$(printf '%s' "${PROJECT_DIR}" | tr -c 'a-zA-Z0-9' '-')"
MODULES_VOL="awesome-lambda-auth-node${SLUG}"
NPM_CACHE_VOL="${NPM_CACHE_VOL:-awesome-lambda-auth-npmcache}"

run_in_node_image() {
  docker run --rm \
    -v "${REPO_ROOT}":/src \
    -v "${MODULES_VOL}":"/src/${PROJECT_DIR}/node_modules" \
    -v "${NPM_CACHE_VOL}":/root/.npm \
    -w "/src/${PROJECT_DIR}" \
    -e npm_config_cache=/root/.npm \
    "$@"
}

case "${1:-}" in
  npm | npx | node)
    run_in_node_image "${NODE_IMAGE}" "$@"
    ;;
  shell)
    run_in_node_image -it "${NODE_IMAGE}" bash
    ;;
  *)
    echo "unknown command: ${1:-}" >&2
    echo "usage: $0 <project-dir> {npm <args...>|npx <args...>|node <args...>|shell}" >&2
    exit 2
    ;;
esac
