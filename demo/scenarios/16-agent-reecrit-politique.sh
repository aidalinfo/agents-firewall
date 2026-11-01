#!/usr/bin/env bash
# 16 — Un agent tente de réécrire la politique par l'API (socle « Plan de contrôle interdit ») : sans jeton
# d'administration, par le proxy ou en direct, vers l'API, l'entrée passerelle et la base ; la passerelle refuse.
# Seules les routes d'ingestion du plugin restent joignables, et seulement depuis la zone de daniel-bot.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 16-agent-reecrit-politique "Un agent ne peut pas réécrire la politique par l'API"
require_demo laurent-bot acme-bot
api_ip=10.76.0.10
before_rev="$(latest_revision)"; before_sessions="$(api_get /sessions | items | jqx -s 'length')"
denied_by_gw() { # denied_by_gw <agent> <label> <curl args>
  local out
  out="$(agent_sh "$1" "curl -sS -i --max-time 8 $3" 2>&1 || true)"
  evidence "$2: $(printf '%s' "$out" | tr -d '\r' | grep -iE '^HTTP/|^x-agents-firewall|^blocked by' | tr '\n' ' ' | cut -c1-200)"
  if printf '%s' "$out" | grep -q '^HTTP/[0-9.]* [0-9]'; then
    printf '%s' "$out" | grep -qi '^x-agents-firewall: *denied' || fail "$2 reached the API (no gateway denial)"
    evidence "$2: denied by the gateway (HTTP answer with X-Agents-Firewall: denied)"
  elif printf '%s' "$out" | grep -qiE 'curl: \((35|56)\)|SSL|TLS|handshake'; then
    evidence "$2: TLS handshake rejected, no HTTP answer ($(printf '%s' "$out" | grep -iE '^curl:' | head -n1 | cut -c1-120))"
  else
    evidence "$2: no HTTP answer ($(printf '%s' "$out" | grep -iE '^curl:' | head -n1 | cut -c1-120))"
  fi
}
denied_by_gw laurent-bot "open a session (direct)" "--noproxy '*' -X POST http://$api_ip:8080/api/v1/sessions"
denied_by_gw laurent-bot "open a session (proxy)" "-x http://$GATEWAY_IP:3128 -X POST http://$api_ip:8080/api/v1/sessions"
denied_by_gw laurent-bot "rewrite a rule" "--noproxy '*' -X PUT -H 'content-type: application/json' -d '{}' http://$api_ip:8080/api/v1/rules/$(demo_id "$(did 605)")"
# Path traversal behind an allowed prefix: denied by the gateway, or at worst not routed by the API (400/404).
out="$(agent_sh laurent-bot "curl -sS -i --max-time 8 --noproxy '*' -X POST --path-as-is http://$api_ip:8080/api/v1/ingest/tool-calls/../../sessions" 2>&1 || true)"
st="$(printf '%s' "$out" | sed -n 's/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' | tail -n1)"
evidence "path traversal: HTTP ${st:-none} $(printf '%s' "$out" | grep -i '^x-agents-firewall' | tr -d '\r')"
case "$st" in
  "" | 400 | 404) ;;
  403) printf '%s' "$out" | grep -qi '^x-agents-firewall: *denied' || fail "path traversal reached an API handler (403 from the API)" ;;
  *) fail "path traversal reached the API sessions route (HTTP $st)" ;;
esac
denied_by_gw acme-bot "ingestion from another zone" "--noproxy '*' -X POST -d '{}' http://$api_ip:8080/api/v1/ingest/tool-calls"
# The gateway endpoint: no answer at all, or the gateway's own denial (TLS terminated by the gateway).
denied_by_gw laurent-bot "gateway endpoint :8443" "-k --noproxy '*' https://$api_ip:8443/gw/v1/policy"
# Every TCP connection is accepted by the gateway's transparent listener before the decision (`nc -z` always
# "succeeds"): send a PostgreSQL SSLRequest, a reachable server answers 'S' or 'N'. Control: the LAN database
# (internal, monitored) answers.
sslreq='printf "\\000\\000\\000\\010\\004\\322\\026\\057"'
lan="$(agent_sh laurent-bot "$sslreq | nc -w 3 $INTERNAL_DB_IP 5432 | head -c 1" 2>/dev/null || true)"
[ -n "$lan" ] || fail "control: the LAN database $INTERNAL_DB_IP:5432 did not answer the SSLRequest (probe broken)"
cp="$(agent_sh laurent-bot "$sslreq | nc -w 3 10.76.0.5 5432 | head -c 1" 2>/dev/null || true)"
[ -z "$cp" ] || fail "the control-plane database is reachable from an agent (answered '$cp')"
evidence "control-plane database 10.76.0.5:5432: no answer (LAN database control answered '$lan')"
if [ -n "$(dc ps -q --status running daniel-bot 2>/dev/null)" ]; then
  denied_by_gw daniel-bot "plugin token on an admin route" "--noproxy '*' -X POST -H \"Authorization: Bearer \$AFW_AGENT_TOKEN\" http://$api_ip:8080/api/v1/sessions"
fi
# The plugin route is reachable from the zone of daniel-bot (the API answers, here 401 without a token).
code="$(agent_sh laurent-bot "curl -s -o /dev/null -w '%{http_code}' --noproxy '*' --max-time 8 -X POST -H 'content-type: application/json' -d '{\"events\":[]}' http://$api_ip:8080/api/v1/ingest/tool-calls" || true)"
evidence "plugin ingestion route without token: HTTP $code (answered by the API)"
[ "$code" = 401 ] || fail "the plugin ingestion route is not path-scoped as expected (HTTP $code)"
[ "$(latest_revision)" = "$before_rev" ] || fail "a revision was published during the attempts"
[ "$(api_get /sessions | items | jqx -s 'length')" = "$before_sessions" ] || fail "a session was opened during the attempts"
evidence "no new session, revision still $before_rev"
pass "la passerelle refuse toute écriture de la politique par un agent"
