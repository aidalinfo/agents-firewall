#!/usr/bin/env bash
# Shared helpers for deploy/tests/*.sh. Everything runs in Docker: nothing is installed on the host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export ROOT
HELM_IMAGE="${HELM_IMAGE:-alpine/helm:3.16.2}"
SHELLCHECK_IMAGE="${SHELLCHECK_IMAGE:-koalaman/shellcheck:v0.10.0}"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"
KUBECONFORM_IMAGE="${KUBECONFORM_IMAGE:-ghcr.io/yannh/kubeconform:v0.6.7}"
YQ_IMAGE="${YQ_IMAGE:-mikefarah/yq:4.44.3}"
export HELM_IMAGE KUBECONFORM_IMAGE YQ_IMAGE

failures=0
ok() { printf '  ok    %s\n' "$*"; }
ko() { printf '  FAIL  %s\n' "$*"; failures=$((failures + 1)); }
section() { printf '\n== %s\n' "$*"; }

# check "<description>" cmd args... : runs the command, records ok/FAIL, prints output on failure.
check() {
  local desc="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then ok "$desc"; else ko "$desc"; printf '%s\n' "$out" | tail -n 30 | sed 's/^/        /'; fi
}

helm_run() { docker run --rm -v "$ROOT":/w -w /w "$HELM_IMAGE" "$@"; }

finish() {
  if [ "$failures" -gt 0 ]; then printf '\n%d check(s) failed\n' "$failures"; exit 1; fi
  printf '\nall checks passed\n'
}
