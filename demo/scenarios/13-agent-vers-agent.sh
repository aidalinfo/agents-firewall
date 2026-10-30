#!/usr/bin/env bash
# 13 — Un agent ne joint pas directement un autre agent (ADR 0003) : laurent-bot n'a aucune route directe vers
# le sous-réseau interne ; une connexion vers acme-bot passe obligatoirement par la passerelle (flux journalisé,
# « interne surveillé »), jamais par le pont Docker. Pas de chemin IPv6 lien-local, pas d'autre interface.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 13-agent-vers-agent "Un agent ne joint pas directement un autre agent"
require_demo laurent-bot acme-bot
acme_ip=10.77.0.12; since="$(now_iso)"
routes="$(agent_sh laurent-bot 'ip route')"
evidence "laurent-bot routes: $(printf '%s' "$routes" | tr '\n' ';')"
printf '%s\n' "$routes" | grep -q '^10\.77\.0\.0/24' && fail "laurent-bot has a direct route to the internal subnet"
agent_sh laurent-bot "ip route get $acme_ip" | grep -q "via $GATEWAY_IP" || fail "the path to acme-bot does not go through the gateway"
evidence "path to acme-bot: $(agent_sh laurent-bot "ip route get $acme_ip" | head -n1)"
[ -z "$(agent_sh laurent-bot 'ip -6 addr show scope link' 2>/dev/null)" ] || fail "IPv6 link-local address present (direct L2 path)"
others="$(agent_sh laurent-bot 'ip -o link show up' | grep -v -E ': (lo|eth0)[:@]' || true)"
[ -z "$others" ] || fail "another interface is up: $others"
evidence "no IPv6 link-local, no other interface up"

# A listener in acme-bot, a connection from laurent-bot: it must be seen by the gateway.
agent_sh acme-bot "(nc -l -p 7777 -w 10 >/tmp/s13.out 2>&1 &) ; true"
sleep 1
m="s13-$(rand_hex)"
attempt laurent-bot "laurent-bot -> acme-bot:7777" "echo $m | nc -w 3 $acme_ip 7777"
neigh="$(agent_sh laurent-bot 'ip neigh' 2>/dev/null || true)"
printf '%s' "$neigh" | grep -q "^$acme_ip .*lladdr" && fail "laurent-bot resolved acme-bot's MAC address (direct L2 traffic)"
evidence "neighbours of laurent-bot: $(printf '%s' "$neigh" | tr '\n' ';')"
lid="$(agent_id laurent-bot)"
if agent_sh acme-bot "grep -q $m /tmp/s13.out" 2>/dev/null; then
  # Delivered: only acceptable as an internal flow allowed and logged by the gateway.
  flow="$(find_flow "$lid" "$acme_ip" allow "$since")" ||
    fail "acme-bot received data from laurent-bot but the gateway logged no allowed flow (direct path?)"
  printf '%s' "$flow" | jqx -e '.internal == true' >/dev/null || fail "delivered flow not marked internal: $(printf '%s' "$flow" | jqx -c .)"
  evidence "delivered through the gateway: internal flow $(printf '%s' "$flow" | jqx -c '{id, internal, layer: .decision.layer, reason: .decision.reason}')"
else
  # Not delivered: only acceptable as a denial logged by the gateway.
  flow="$(find_flow "$lid" "$acme_ip" deny "$since")" ||
    fail "not delivered and no denied flow in the log (broken path rather than a decision)"
  evidence "refused by the gateway: flow $(printf '%s' "$flow" | jqx -c '{id, rule: .decision.rule_number, reason: .decision.reason}')"
fi
pass "aucun chemin direct entre agents ; tout passe par la passerelle"
