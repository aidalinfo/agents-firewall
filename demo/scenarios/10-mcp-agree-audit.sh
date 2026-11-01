#!/usr/bin/env bash
# 10 — Agent agréé sur le MCP (EF-50..52, cahier §8) : daniel-bot (zone internes, mcp_admin) administre la zone
# clients (déléguée au MCP) via afw-mcp : sa modification est publiée et apparaît dans l'audit avec
# l'interface « mcp » ; sa tentative de modifier sa propre zone est refusée.
# Tool names of afw-mcp (lot L9) can be overridden: MCP_TOOL_SESSION_OPEN, MCP_TOOL_RULE_CREATE, MCP_TOOL_PUBLISH.
# Without a usable afw-mcp (lots L8/L9 not merged), the same calls are made over REST with the SAME mcp_agent
# token: the API enforces EF-51 and records interface "mcp" from the token's role, whatever the transport. The
# result then says "repli REST" (AFW_DEMO_MCP_FALLBACK=0 turns the fallback into a SKIP).
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 10-mcp-agree-audit "Administration par l'agent agréé via MCP, tracée ; sa propre zone refusée"
require_demo
T_OPEN="${MCP_TOOL_SESSION_OPEN:-open_session}"
T_RULE="${MCP_TOOL_RULE_CREATE:-create_resource}"
T_PUB="${MCP_TOOL_PUBLISH:-publish_session}"
since="$(now_iso)"
clients="$(demo_id "$(did 402)")"; internes="$(demo_id "$(did 401)")"
allowed="$(demo_id "$(did 108)")"; https="$(demo_id "$(did 201)")"
# A single active mcp_agent token is allowed (EF-50): revoke the one left by a previous run.
for old in $(api_get /tokens | items | jqx -r 'select(.role == "mcp_agent" and .revoked_at == null) | .id'); do
  api_delete "/tokens/$old" >/dev/null && evidence "revoked the previous mcp_agent token $old"
done
for old in $(api_get /sessions | items | jqx -r 'select(.state == "open" and .interface == "mcp") | .id'); do
  api_post "/sessions/$old/discard" >/dev/null && evidence "discarded the MCP session $old left by a previous run"
done
token="$(api_token_create "demo-mcp-$(rand_hex 6)" mcp_agent "$(agent_id daniel-bot)")" || fail "cannot create the mcp_agent token"
name="Démo 10 MCP $(rand_hex 4)"
new_uuid() { python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || uuidgen | tr 'A-Z' 'a-z'; }

rule_args() { # rule_args <zone id>
  jqx -nc --arg id "$(new_uuid)" --arg z "$1" --arg n "$name" --arg d "$allowed" --arg s "$https" \
    '{id: $id, name: $n, layer: {type: "zone", zone_id: $z}, position: 99, sources: [$z], destinations: [$d], services: [$s], data_classes: [], action: "accept", track: "detailed", enabled: true, comment: "", section: null, expires_at: null}'
}
failed() { printf '%s' "$1" | jqx -e '.error != null or .result.isError == true' >/dev/null 2>&1; }

transport=""
if image_exists "$AFW_CLI_IMAGE" && docker run --rm --entrypoint sh "$AFW_CLI_IMAGE" -c 'command -v afw-mcp' >/dev/null 2>&1; then
  call() { jqx -nc --argjson id "$1" --arg t "$2" --argjson a "$3" '{jsonrpc: "2.0", id: $id, method: "tools/call", params: {name: $t, arguments: $a}}'; }
  out="$({
    jqx -nc '{jsonrpc: "2.0", id: 1, method: "initialize", params: {protocolVersion: "2025-06-18", capabilities: {}, clientInfo: {name: "afw-demo", version: "1"}}}'
    sleep 1; jqx -nc '{jsonrpc: "2.0", method: "notifications/initialized"}'
    jqx -nc '{jsonrpc: "2.0", id: 2, method: "tools/list"}'
    call 3 "$T_OPEN" '{}'; sleep 1
    call 4 "$T_RULE" "$(rule_args "$clients" | jqx -c '{kind: "rules", resource: .}')"; sleep 1
    call 5 "$T_RULE" "$(rule_args "$internes" | jqx -c '{kind: "rules", resource: .}')"; sleep 1
    call 6 "$T_PUB" '{"comment": "Démo 10 : règle ajoutée par l agent agréé via MCP"}'; sleep 3
  } | docker run --rm -i --network "${DEMO_PROJECT}_control" -e "$AFW_CLI_URL_ENV=$AFW_API_URL_IN_DOCKER" \
    -e "$AFW_CLI_TOKEN_ENV=$token" --entrypoint afw-mcp "$AFW_CLI_IMAGE" stdio 2>/dev/null || true)"
  resp() { printf '%s\n' "$out" | jqx -c --argjson id "$1" 'select(.id == $id)' 2>/dev/null | head -n1; }
  tools="$(resp 2 | jqx -r '[.result.tools[].name] | join(", ")' 2>/dev/null || true)"
  evidence "afw-mcp tools: ${tools:-none}"
  case ", $tools, " in *", $T_RULE, "*) transport=mcp ;; esac
fi

if [ "$transport" = mcp ]; then
  r3="$(resp 3)"; r4="$(resp 4)"; r5="$(resp 5)"; r6="$(resp 6)"
  evidence "open_session: $(printf '%s' "$r3" | cut -c1-160)"
  ok4() { [ -n "$r4" ] && ! failed "$r4"; }; ko5() { [ -n "$r5" ] && failed "$r5"; }; ok6() { [ -n "$r6" ] && ! failed "$r6"; }
else
  [ "${AFW_DEMO_MCP_FALLBACK:-1}" = 1 ] || skip "afw-mcp not available in $AFW_CLI_IMAGE (lots L8/L9 not merged)"
  transport=rest
  evidence "afw-mcp not available in $AFW_CLI_IMAGE: same calls over REST with the mcp_agent token (fallback)"
  # The token's role, not the transport, makes the API apply EF-51 and audit with interface mcp.
  as_mcp() { AFW_TOKEN="$token" AFW_INTERFACE=api api "$@"; }
  sid="$(as_mcp POST /sessions | jqx -r '.id')" || fail "the mcp_agent token cannot open a session"
  r4="$(AFW_SESSION_ID="$sid" as_mcp POST /rules "$(rule_args "$clients")" 2>&1 || true)"; s4="$(last_status)"
  r5="$(AFW_SESSION_ID="$sid" as_mcp POST /rules "$(rule_args "$internes")" 2>&1 || true)"; s5="$(last_status)"
  r6="$(as_mcp POST "/sessions/$sid/publish" '{"comment":"Démo 10 : règle ajoutée par l agent agréé (jeton mcp_agent)"}' 2>&1 || true)"; s6="$(last_status)"
  r4="HTTP $s4 $r4"; r5="HTTP $s5 $r5"; r6="HTTP $s6 $r6"
  ok4() { [ "$s4" -lt 300 ]; }; ko5() { [ "$s5" -ge 400 ]; }; ok6() { [ "$s6" -lt 300 ]; }
fi
evidence "rule in delegated zone clients: $(printf '%s' "$r4" | tr '\n' ' ' | cut -c1-200)"
evidence "rule in its own zone internes: $(printf '%s' "$r5" | tr '\n' ' ' | cut -c1-200)"
evidence "publish: $(printf '%s' "$r6" | tr '\n' ' ' | cut -c1-200)"
ok4 || fail "the MCP agent could not change its delegated zone"
ko5 || fail "the MCP agent was able to change its own zone (EF-51)"
printf '%s' "$r5" | grep -Eqi '403|forbidden' || fail "own-zone change refused, but not with 403 Forbidden: $r5"
ok6 || fail "the MCP agent could not publish"

audit="$(audit_since "$since" | jqx -c 'select(.interface == "mcp")')"
[ -n "$audit" ] || fail "no audit entry with interface mcp"
evidence "audit (interface mcp): $(printf '%s\n' "$audit" | jqx -r '"#\(.seq) \(.actor.kind)/\(.actor.name) \(.action) \(.target)"' | tr '\n' ';')"
verify="$(api_get /audit/verify 2>/dev/null | jqx -c '.' || echo unavailable)"
evidence "audit chain: $verify"

# Cleanup with the admin token.
rid="$(api_get /rules | items | jqx -r --arg n "$name" 'select(.name == $n) | .id' | head -n1)"
if [ -n "$rid" ]; then session_open; delete_rule "$rid"; publish_and_install "Démo 10 : retrait de la règle MCP" >/dev/null || true; fi
if [ "$transport" = mcp ]; then
  pass "zone déléguée modifiée et tracée (interface mcp), propre zone refusée"
else
  pass "zone déléguée modifiée et tracée (interface mcp), propre zone refusée — repli REST avec le jeton mcp_agent (afw-mcp à rejouer)"
fi
