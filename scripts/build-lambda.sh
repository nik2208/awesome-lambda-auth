#!/usr/bin/env bash
# Build the deployable Lambda artifact for cmd/auth, reproducibly.
#
#   ./scripts/build-lambda.sh                 # dist/auth-arm64.zip
#   ARCH=amd64 ./scripts/build-lambda.sh      # dist/auth-amd64.zip
#   OUT_DIR=/tmp/x ./scripts/build-lambda.sh
#
# The arch-suffixed name is canonical, and the default build is also copied to
# dist/auth-lambda.zip, which is the CodeUri infra/sam/template.yaml resolves.
# Two names rather than one arch-less name: `aws cloudformation package` needs a
# fixed path, and a build that silently overwrote the arm64 artifact with an
# amd64 one under the same name would be deployed without anyone noticing.
#
# The target runtime is provided.al2023, which starts the executable it finds at
# the root of the archive named exactly `bootstrap` — not cmd/auth, not auth.
#
# Reproducibility, in the sense that matters here (the same source produces a
# byte-identical zip):
#   - The compiler runs in a pinned image, so the Go version is fixed.
#   - CGO is off, so nothing links against the build host's libc.
#   - -trimpath removes the build directory from the binary, and
#     -buildvcs=false keeps the VCS stamp (commit, dirty flag, build time) out
#     of it, since a stamp differs between two builds of the same tree.
#   - -ldflags "-s -w" drops the symbol table and DWARF: smaller cold starts,
#     and one less source of variation.
#   - The zip entry is written with a fixed timestamp and fixed permissions,
#     because zip stores the file mtime and would otherwise change on every run.
set -euo pipefail

GO_IMAGE="${GO_IMAGE:-golang:1.25-trixie}"
MOD_CACHE_VOL="${MOD_CACHE_VOL:-awesome-lambda-auth-gomod}"
BUILD_CACHE_VOL="${BUILD_CACHE_VOL:-awesome-lambda-auth-gobuild}"

# arm64 is the default: Graviton is cheaper per GB-second and this workload is
# not instruction-set sensitive. It is also what infra/sam/template.yaml
# declares in Architectures.
DEFAULT_ARCH=arm64
ARCH="${ARCH:-${DEFAULT_ARCH}}"
case "${ARCH}" in
  arm64|amd64) ;;
  *) echo "ARCH must be arm64 or amd64, got ${ARCH}" >&2; exit 2 ;;
esac

# The parent workspace directory contains a literal ${lang}. Every expansion of
# a path below is quoted, and none of them is ever built by string interpolation
# into a shell -c argument.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dist}"

mkdir -p "${OUT_DIR}"

# SOURCE_DATE_EPOCH is the reproducible-builds convention. 2020-01-01T00:00:00Z
# is an arbitrary fixed point; the value only has to be stable, and zip cannot
# store anything before 1980 anyway.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1577836800}"

docker run --rm \
  -v "${REPO_ROOT}":/src \
  -v "${OUT_DIR}":/out \
  -v "${MOD_CACHE_VOL}":/go/pkg/mod \
  -v "${BUILD_CACHE_VOL}":/root/.cache/go-build \
  -w /src \
  -e GOFLAGS \
  -e GOPROXY \
  -e "ARCH=${ARCH}" \
  -e "DEFAULT_ARCH=${DEFAULT_ARCH}" \
  -e "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
  "${GO_IMAGE}" \
  bash -euo pipefail -c '
    # The Go image ships no archiver. Installed quietly, and non-interactively:
    # there is no tty here and debconf will otherwise write pages of fallback
    # chatter into the build log.
    if ! command -v zip >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq >/dev/null 2>&1
      apt-get install -y -qq --no-install-recommends zip unzip >/dev/null 2>&1
    fi

    workdir="$(mktemp -d)"
    trap "rm -rf ${workdir}" EXIT

    CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" \
      go build -trimpath -buildvcs=false -ldflags "-s -w" \
      -o "${workdir}/bootstrap" ./cmd/auth

    # provided.al2023 execs the file directly, so it has to be executable, and
    # the zip has to record that bit.
    chmod 0755 "${workdir}/bootstrap"
    touch -d "@${SOURCE_DATE_EPOCH}" "${workdir}/bootstrap"

    out="/out/auth-${ARCH}.zip"
    rm -f "${out}"
    # -X drops the extra field, which carries the high-resolution mtime and the
    # uid/gid of the build user; without it the archive differs per host.
    (cd "${workdir}" && zip -q -X "${out}" bootstrap)

    # The name infra/sam/template.yaml points its CodeUri at. Only the default
    # architecture claims it, so an amd64 build cannot quietly take the slot an
    # arm64 function is deployed from.
    if [ "${ARCH}" = "${DEFAULT_ARCH}" ]; then
      cp -f "${out}" "/out/auth-lambda.zip"
    fi

    echo "--- artifact ---"
    ls -l "${out}"
    unzip -l "${out}"
    echo "--- binary ---"
    go version -m "${workdir}/bootstrap" | head -3
    echo "--- checksum ---"
    sha256sum "${out}" | sed "s#/out/#${ARCH}: #"
  '

echo
echo "Built ${OUT_DIR}/auth-${ARCH}.zip"
echo "Deploy it with:"
echo "  ./scripts/deploy.sh --profile <profile> --region <region>"
echo
echo "which is a wrapper over the plain AWS CLI — there is no SAM CLI here and none"
echo "is needed, because CloudFormation applies the SAM transform server-side:"
echo "  aws cloudformation package  --template-file infra/sam/template.yaml --s3-bucket <bucket> \\"
echo "      --output-template-file dist/packaged.yaml --profile <profile> --region <region>"
echo "  aws cloudformation deploy   --template-file dist/packaged.yaml --stack-name <stack> \\"
echo "      --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --profile <profile> --region <region>"
