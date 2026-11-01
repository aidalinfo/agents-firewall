#!/usr/bin/env bash
# Builds the product images locally (never pushed). Images whose sources are not merged yet are SKIPPED.
# Usage: deploy/tests/images.sh            (from the repository root or anywhere)
#        AFW_BUILD_CONTEXT=/other/tree deploy/tests/images.sh   (build another checkout, e.g. a lot worktree)
# shellcheck source=deploy/tests/common.sh
. "$(dirname "$0")/common.sh"
CTX="${AFW_BUILD_CONTEXT:-$ROOT}"
skipped=0
skip() { printf '  SKIP  %s\n' "$*"; skipped=$((skipped + 1)); }

build() { # build <image> <dockerfile> <context> <required path>
  if [ ! -e "$4" ]; then skip "$1 ($4 missing: lot not merged)"; return; fi
  check "docker build $1" docker build -t "$1" -f "$2" "$3"
}

section "product images"
build afw-api:local "$ROOT/deploy/docker/Dockerfile.api" "$CTX" "$CTX/crates/afw-api/src/main.rs"
build afw-cli:local "$ROOT/deploy/docker/Dockerfile.cli" "$CTX" "$CTX/crates/afw-cli/src/main.rs"
build afw-gateway:local "$CTX/deploy/docker/Dockerfile.gateway" "$CTX" "$CTX/deploy/docker/Dockerfile.gateway"
build afw-console:local "$CTX/console/Dockerfile" "$CTX/console" "$CTX/console/Dockerfile"
build afw-netinit:local "$ROOT/deploy/docker/Dockerfile.netinit" "$ROOT/deploy/docker" "$ROOT/deploy/docker/Dockerfile.netinit"

if docker image inspect afw-api:local >/dev/null 2>&1; then
  section "afw-api image"
  check "runs as a non-root user" bash -c '[ "$(docker run --rm --entrypoint id afw-api:local -u)" != 0 ]'
  check "contains the afw-api binary" docker run --rm --entrypoint sh afw-api:local -c 'command -v afw-api'
fi
[ "$skipped" -gt 0 ] && printf '\n%d image(s) skipped\n' "$skipped"
finish
