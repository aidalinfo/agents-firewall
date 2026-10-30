#!/usr/bin/env bash
# 10 — Agent agréé sur le MCP (EF-50..52, cahier §8) : daniel-bot (zone internes, mcp_admin) administre la zone
# clients (déléguée au MCP) via afw-mcp : sa modification est publiée et apparaît dans l'audit avec
# l'interface « mcp » ; sa tentative de modifier sa propre zone est refusée.
# Tool names of afw-mcp (lot L9) can be overridden: MCP_TOOL_SESSION_OPEN, MCP_TOOL_RULE_CREATE, MCP_TOOL_PUBLISH.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 10-mcp-agree-audit "Administration par l'agent agréé via MCP, tracée ; sa propre zone refusée"
require_demo
image_exists "$AFW_CLI_IMAGE" && docker run --rm --entrypoint sh "$AFW_CLI_IMAGE" -c 'command -v afw-mcp' >/dev/null 2>&1 ||
  skip "afw-mcp not available in $AFW_CLI_IMAGE (lot L9 not merged)"
T_OPEN="${MCP_TOOL_SESSION_OPEN:-session_open}"
T_RULE="${MCP_TOOL_RULE_CREATE:-rules_create}"
T_PUB="${MCP_TOOL_PUBLISH:-session_publish}"
since="$(now_iso)"
clients="$(demo_id "$(did 402)")"; internes="$(demo_id "$(did 401)")"
allowed="$(demo_id "$(did 108)")"; https="$(demo_id "$(did 201)")"
token="$(api_token_create "demo-mcp-$(rand_hex 6)" mcp_agent "$(agent_id daniel-bot)")" || fail "cannot create the mcp_agent token"
name="Démo 10 MCP $(rand_hex 4)"

rule_args() { # rule_args <zone id>
  jqx -nc --arg z "$1" --arg n "$name" --arg d "$allowed" --arg s "$https" \
    '{name: $n, layer: {type: "zone", zone_id: $z}, position: 99, sources: [$z], destinations: [$d], services: [$s], action: "accept", track: "detailed", enabled: true}'
}
call() { jqx -nc --argjson id "$1" --arg t "$2" --argjson a "$3" '{jsonrpc: "2.0", id: $id, method: "tools/call", params: {name: $t, arguments: $a}}'; }
out="$({
  jqx -nc '{jsonrpc: "2.0", id: 1, method: "initialize", params: {protocolVersion: "2025-06-18", capabilities: {}, clientInfo: {name: "afw-demo", version: "1"}}}'
  sleep 1; jqx -nc '{jsonrpc: "2.0", method: "notifications/initialized"}'
  jqx -nc '{jsonrpc: "2.0", id: 2, method: "tools/list"}'
  call 3 "$T_OPEN" '{}'; sleep 1
  call 4 "$T_RULE" "$(rule_args "$clients")"; sleep 1
  call 5 "$T_RULE" "$(rule_args "$internes")"; sleep 1
  call 6 "$T_PUB" '{"comment": "Démo 10 : règle ajoutée par l agent agréé via MCP"}'; sleep 3
} | docker run --rm -i --network "${DEMO_PROJECT}_control" -e "$AFW_CLI_URL_ENV=$AFW_API_URL_IN_DOCKER" \
  -e "$AFW_CLI_TOKEN_ENV=$token" --entrypoint afw-mcp "$AFW_CLI_IMAGE" 2>/dev/null || true)"
resp() { printf '%s\n' "$out" | jqx -c --argjson id "$1" 'select(.id == $id)' 2>/dev/null | head -n1; }
failed() { printf '%s' "$1" | jqx -e '.error != null or .result.isError == true' >/dev/null 2>&1; }
tools="$(resp 2 | jqx -r '[.result.tools[].name] | join(", ")' 2>/dev/null || true)"
evidence "afw-mcp tools: ${tools:-none}"
case ", $tools, " in *", $T_RULE, "*) ;; *) skip "afw-mcp has no tool '$T_RULE' (set MCP_TOOL_* to the tool names of lot L9)" ;; esac
r4="$(resp 4)"; r5="$(resp 5)"; r6="$(resp 6)"
evidence "rule in delegated zone clients: $(printf '%s' "$r4" | cut -c1-200)"
evidence "rule in its own zone internes: $(printf '%s' "$r5" | cut -c1-200)"
evidence "publish: $(printf '%s' "$r6" | cut -c1-200)"
{ [ -n "$r4" ] && ! failed "$r4"; } || fail "the MCP agent could not change its delegated zone"
{ [ -n "$r5" ] && failed "$r5"; } || fail "the MCP agent was able to change its own zone (EF-51)"
printf '%s' "$r5" | grep -Eqi '403|forbidden' || fail "own-zone change refused, but not with 403 Forbidden: $r5"
{ [ -n "$r6" ] && ! failed "$r6"; } || fail "the MCP agent could not publish"

audit="$(audit_since "$since" | jqx -c 'select(.interface == "mcp")')"
[ -n "$audit" ] || fail "no audit entry with interface mcp"
evidence "audit (interface mcp): $(printf '%s\n' "$audit" | jqx -r '"#\(.seq) \(.actor.name) \(.action) \(.target)"' | tr '\n' ';')"
verify="$(api_get /audit/verify 2>/dev/null | jqx -c '{ok, checked}' || echo unavailable)"
evidence "audit chain: $verify"

# Cleanup with the admin token.
rid="$(api_get /rules | items | jqx -r --arg n "$name" 'select(.name == $n) | .id' | head -n1)"
if [ -n "$rid" ]; then session_open; delete_rule "$rid"; publish_and_install "Démo 10 : retrait de la règle MCP" >/dev/null || true; fi
pass "zone déléguée modifiée et tracée (interface mcp), propre zone refusée"
