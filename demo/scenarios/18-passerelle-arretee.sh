#!/usr/bin/env bash
# 18 — Passerelle arrêtée = plus de réseau (jamais d'ouverture en cas de panne, ADR 0003) : la passerelle est
# arrêtée ; les agents ne joignent plus rien (destination autorisée, LAN, IP directe, DNS) ; au redémarrage, la
# passerelle reprend avec sa révision installée, sans la console.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 18-passerelle-arretee "Passerelle arrêtée : plus aucun accès réseau pour les agents"
require_demo laurent-bot acme-bot
positive_control laurent-bot
rev="$(gateways_json | jqx -r 'select(.name == "demo-gw") | .active_revision')"
gw="$(dc ps -q gateway)"
restart_gw() { docker start "$gw" >/dev/null 2>&1 || true; }
trap restart_gw EXIT
docker stop -t 5 "$gw" >/dev/null || fail "cannot stop the gateway"
evidence "gateway container stopped (active revision was $rev)"
m="s18-$(rand_hex)"
sslreq='printf "\\000\\000\\000\\010\\004\\322\\026\\057"'
for a in laurent-bot acme-bot; do
  code="$(agent_sh "$a" "$(http_code_cmd "-d $m https://allowed.example/down")" 2>/dev/null || true)"
  evidence "$a -> allowed.example (proxy): HTTP ${code:-none}"
  [ "${code:-000}" = 000 ] || fail "$a reached allowed.example with the gateway stopped (HTTP $code)"
  code="$(agent_sh "$a" "curl -s -o /dev/null -w '%{http_code}' --noproxy '*' --max-time 5 -k -d $m https://198.18.0.12/down-ip" 2>/dev/null || true)"
  evidence "$a -> 198.18.0.12 (direct IP): HTTP ${code:-none}"
  [ "${code:-000}" = 000 ] || fail "$a reached 198.18.0.12 directly with the gateway stopped"
  lan="$(agent_sh "$a" "$sslreq | nc -w 3 $INTERNAL_DB_IP 5432 | head -c 1" 2>/dev/null || true)"
  evidence "$a -> $INTERNAL_DB_IP:5432 (LAN): '${lan}'"
  [ -z "$lan" ] || fail "$a reached the LAN database with the gateway stopped"
  dns="$(agent_sh "$a" "dig +short +time=2 +tries=1 @$DEMO_DNS_IP allowed.example A" 2>/dev/null || true)"
  printf '%s\n' "$dns" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && fail "$a resolved a name through the outside resolver"
  evidence "$a -> DNS @$DEMO_DNS_IP: no answer"
done
assert_not_received allowed-api "$m" "a request sent while the gateway was down"

t0="$(now_ms)"; restart_gw; trap - EXIT
c=""; for _ in $(seq 1 30); do c="$(agent_sh laurent-bot "$(http_code_cmd https://allowed.example/zen)" 2>/dev/null || true)"; [ "$c" = 200 ] && break; sleep 1; done
[ "$c" = 200 ] || fail "traffic did not resume after the gateway restart (HTTP $c)"
evidence "gateway restarted: traffic back in $(( ($(now_ms) - t0) / 1000 )) s"
c="$(agent_sh laurent-bot "$(http_code_cmd https://exfil.example/x)" 2>/dev/null || true)"
[ "$c" = 403 ] || fail "after restart, exfil.example is not denied (HTTP $c)"
evidence "after restart: exfil.example still denied (installed revision reloaded from the state volume)"
wait_installed "$rev" 60 || fail "gateway not back on revision $rev"
pass "passerelle arrêtée : aucun accès (proxy, IP directe, LAN, DNS) ; reprise avec la révision $rev"
