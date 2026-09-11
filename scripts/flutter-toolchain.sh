#!/usr/bin/env bash
# Containerised Flutter toolchain, per l'esempio Flutter. Stessa regola del
# resto del repo: niente installato sull'host.
#
#   ./scripts/flutter-toolchain.sh examples/flutter-client pub get
#   ./scripts/flutter-toolchain.sh examples/flutter-client analyze
#   ./scripts/flutter-toolchain.sh examples/flutter-client build web --dart-define=…
#   ./scripts/flutter-toolchain.sh examples/flutter-client shell
#
# L'APK non si costruisce di qui: lo fa GitHub Actions su tag. Questa toolchain
# serve al build web e alle verifiche statiche.
set -euo pipefail

FLUTTER_IMAGE="${FLUTTER_IMAGE:-ghcr.io/cirruslabs/flutter:stable}"
PUB_CACHE_VOL="${PUB_CACHE_VOL:-awesome-lambda-auth-pubcache}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

PROJECT_DIR="${1:-}"
if [[ -z "${PROJECT_DIR}" || ! -d "${REPO_ROOT}/${PROJECT_DIR}" ]]; then
  echo "usage: $0 <project-dir> {<flutter-args...>|shell}" >&2
  exit 2
fi
shift

run_in_flutter_image() {
  # L'immagine gira come root e Flutter rifiuta di operare su un checkout di
  # cui non si fida: --git-dir non serve qui perche' /src e' l'intero repo.
  docker run --rm \
    -v "${REPO_ROOT}":/src \
    -v "${PUB_CACHE_VOL}":/root/.pub-cache \
    -w "/src/${PROJECT_DIR}" \
    -e PUB_CACHE=/root/.pub-cache \
    "$@"
}

if [[ "${1:-}" == "shell" ]]; then
  run_in_flutter_image -it "${FLUTTER_IMAGE}" bash
else
  run_in_flutter_image "${FLUTTER_IMAGE}" flutter "$@"
fi
