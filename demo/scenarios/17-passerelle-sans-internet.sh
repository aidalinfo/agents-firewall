#!/usr/bin/env bash
# 17 — La passerelle de démo ne joint pas Internet : elle n'est que sur des réseaux internes et ne résout que
# par AFW_UPSTREAM_DNS (demo-dns). Sondes lancées dans l'espace réseau de la passerelle.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 17-passerelle-sans-internet "La passerelle ne joint pas example.com"
require_demo
gw="$(dc ps -q gateway)"
probe() { docker run --rm --network "container:$gw" afw-demo-tools:local sh -c "$1"; }
probe "getent hosts example.com" >/dev/null 2>&1 && fail "the gateway namespace resolves example.com with the system resolver"
evidence "system resolver: example.com not resolved"
probe "curl -sS -o /dev/null --max-time 5 https://example.com" >/dev/null 2>&1 && fail "the gateway namespace reaches example.com"
probe "curl -sS -o /dev/null --max-time 5 -k https://93.184.215.14" >/dev/null 2>&1 && fail "the gateway namespace reaches a public IP"
probe "dig +time=2 +tries=1 @1.1.1.1 example.com" >/dev/null 2>&1 && fail "the gateway namespace reaches a public resolver"
evidence "no route to a public IP or resolver"
ans="$(probe "dig +short @$DEMO_DNS_IP example.com A; dig +short @$DEMO_DNS_IP api.anthropic.com A" 2>&1 || true)"
evidence "AFW_UPSTREAM_DNS ($DEMO_DNS_IP): example.com -> NXDOMAIN, api.anthropic.com -> $(printf '%s' "$ans" | tail -n1)"
[ "$(printf '%s\n' "$ans" | grep -c .)" = 1 ] || fail "unexpected upstream DNS answers: $ans"
pass "aucune sortie Internet depuis la passerelle ; résolution par le seul DNS amont configuré"
