#!/usr/bin/env bash
# Fail when a build artifact grows past its budget.
#
#   ./scripts/check-artifact-size.sh dist/auth-arm64.zip 12582912
#
# The budget is bytes on disk of the zip, which is what Lambda downloads on
# every cold start; keeping it visible in CI is how a dependency that doubles
# the artifact gets noticed in the PR that adds it, not in a latency graph.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <artifact> <budget-bytes>" >&2
  exit 2
fi

artifact="$1"
budget="$2"

if [ ! -f "$artifact" ]; then
  echo "artifact not found: $artifact" >&2
  exit 1
fi

size="$(wc -c < "$artifact" | tr -d ' ')"
printf '%s: %s bytes (budget %s)\n' "$artifact" "$size" "$budget"
if [ "$size" -gt "$budget" ]; then
  echo "artifact exceeds its size budget by $((size - budget)) bytes" >&2
  exit 1
fi
