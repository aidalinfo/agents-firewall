#!/usr/bin/env bash
# 02 — Autoriser depuis le journal en moins de deux minutes (EF-42, cahier §8) : acme-bot (zone clients) est
# refusé vers api.github.com ; depuis le flux refusé : « Autoriser » → publier → installer → nouvel essai OK.
# La règle créée est retirée à la fin (la politique de démo revient à son état).
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 02-autoriser-depuis-le-journal "Un refus légitime corrigé depuis le journal en < 2 min"
require_demo acme-bot
since="$(now_iso)"
call="$(http_code_cmd https://api.github.com/zen)"

t0="$(now_ms)"
code="$(agent_sh acme-bot "$call" || true)"
evidence "before: acme-bot -> api.github.com = HTTP $code"
[ "$code" = 403 ] || fail "expected an initial denial (403), got $code"
flow="$(find_flow "$(agent_id acme-bot)" api.github.com deny "$since")" || fail "denied flow not found in the log"
flow_id="$(printf '%s' "$flow" | jqx -r '.id')"
evidence "denied flow $flow_id"

session_open
rule="$(allow_from_log "$flow_id")" || fail "allow-from-log failed"
rule_id="$(printf '%s' "$rule" | jqx -r '.rule.id // .id')"
evidence "rule created from the log: $(printf '%s' "$rule" | jqx -c '.rule // . | {id, name, layer, destinations, action}')"
rev="$(publish "Démo 02 : autoriser api.github.com pour la zone clients (depuis le journal)")"
install "$rev"; wait_installed "$rev" 90 || fail "revision $rev not installed"
evidence "revision $rev published and installed"

code=""
for _ in $(seq 1 10); do code="$(agent_sh acme-bot "$call" || true)"; [ "$code" = 200 ] && break; sleep 1; done
elapsed=$(( ($(now_ms) - t0) / 1000 ))
evidence "after: acme-bot -> api.github.com = HTTP $code, total ${elapsed} s"

# Restore the demo policy.
session_open; delete_rule "$rule_id"; rev2="$(publish "Démo 02 : retrait de la règle de test")"
install "$rev2"; wait_installed "$rev2" 90 || warn "cleanup revision $rev2 not installed"
evidence "cleanup: revision $rev2 removes the rule"

[ "$code" = 200 ] || fail "still denied after install (HTTP $code)"
[ "$elapsed" -lt 120 ] || fail "correction took ${elapsed} s (> 120 s)"
pass "corrigé depuis le journal en ${elapsed} s"
