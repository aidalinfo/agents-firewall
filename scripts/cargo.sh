#!/usr/bin/env bash
# Run cargo inside a Linux container (see docs/adr/0002-environnement-de-build.md).
# Usage: scripts/cargo.sh <cargo args...>   e.g. scripts/cargo.sh test -p afw-engine
# AFW_TARGET_VOLUME isolates the target dir per worktree/lot (default: derived from the path).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
vol="${AFW_TARGET_VOLUME:-afw-target-$(printf '%s' "$root" | shasum | cut -c1-10)}"
exec docker run --rm \
  -v "$root":/w -w /w \
  -v afw-cargo-registry:/usr/local/cargo/registry \
  -v afw-cargo-git:/usr/local/cargo/git \
  -v "$vol":/w/target \
  -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}" \
  -e CARGO_TERM_COLOR=never \
  --memory "${AFW_DOCKER_MEMORY:-3g}" \
  ${AFW_DOCKER_ARGS:-} \
  rust:1.91-bookworm bash -c 'rustup component add rustfmt clippy >/dev/null 2>&1; cargo "$@"' cargo "$@"
