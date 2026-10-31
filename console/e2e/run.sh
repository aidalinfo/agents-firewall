#!/usr/bin/env bash
# End-to-end tests of the console against the real API (lot L3b).
#   console/e2e/run.sh                 # build images, start the stack, seed, run Playwright, stop
#   AFW_E2E_SCREENSHOTS=1 console/e2e/run.sh   # same, and refresh console/docs/screenshots/
# Images are built locally and never pushed. Needs docker (with compose) only.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
console="$(cd "$here/.." && pwd)"
repo="$(cd "$console/.." && pwd)"
PLAYWRIGHT_IMAGE="${PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright:v1.64.1-noble}"
export AFW_API_IMAGE="${AFW_API_IMAGE:-afw-api:e2e}" AFW_CONSOLE_IMAGE="${AFW_CONSOLE_IMAGE:-afw-console:e2e}"
export AFW_E2E_TOKEN="${AFW_E2E_TOKEN:-afw-e2e-admin-token-0123456789}"
project=afw-console-e2e
compose=(docker compose -p "$project" -f "$here/docker-compose.yml")

if [ -z "${AFW_E2E_SKIP_BUILD:-}" ]; then
  docker build -t "$AFW_API_IMAGE" -f "$repo/deploy/docker/Dockerfile.api" "$repo"
  docker build -t "$AFW_CONSOLE_IMAGE" "$console"
fi

cleanup() { [ -n "${AFW_E2E_KEEP:-}" ] || "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
"${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${compose[@]}" up -d --wait postgres afw-api console

# Seed: demo policy through the public API (from a curl container on the stack network) + log fixtures.
api_ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$("${compose[@]}" ps -q afw-api)"; }
network="${project}_default"
docker run --rm --network "$network" -v "$repo:/repo:ro" -e TOKEN="$AFW_E2E_TOKEN" curlimages/curl:8.11.1 sh -c '
  set -e
  call() { curl -fsS -X "$1" "http://afw-api:8080/api/v1$2" -H "authorization: Bearer $TOKEN" -H "content-type: application/json" -H "x-afw-interface: api" ${3:+--data-binary "$3"}; }
  if ! call GET /revisions | grep -q "\"number\""; then
    sid=$(call POST /sessions "{\"name\":\"Import de la politique de démonstration\"}" | sed -E "s/^\{\"id\":\"([^\"]+)\".*/\1/")
    call POST "/sessions/$sid/import" @/repo/demo/policy/demo-policy.json > /dev/null
    call POST "/sessions/$sid/publish" "{\"comment\":\"Politique de démonstration\"}" > /dev/null
    echo "seed: demo policy published"
  fi'
"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -q -U afw -d afw < "$here/fixtures/logs.sql" > /dev/null
echo "seed: logs inserted"

docker run --rm --network "$network" --ipc=host \
  -v "$repo:/repo" -w /repo/console \
  -v afw-pnpm-store:/pnpm-store -e npm_config_store_dir=/pnpm-store \
  -e CI=1 -e AFW_E2E_CONSOLE=http://console:3000 -e AFW_E2E_API=http://afw-api:8080 -e AFW_E2E_TOKEN \
  -e AFW_E2E_SCREENSHOTS="${AFW_E2E_SCREENSHOTS:-}" -e HOME=/tmp \
  "$PLAYWRIGHT_IMAGE" bash -c 'corepack enable >/dev/null 2>&1 && pnpm install --frozen-lockfile --ignore-scripts >/dev/null && pnpm exec playwright test -c e2e/playwright.config.ts'
