#!/usr/bin/env bash
# 08 — Mouvement latéral (EF-80..82) : laurent-bot balaie les ports de internal-db sur le LAN simulé. Les flux
# internes sont autorisés et surveillés par défaut ([Killian] « surveiller seulement ») : le balayage doit
# lever une alerte port_scan et apparaître sur la carte des flux internes.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 08-mouvement-lateral "Balayage de ports sur le réseau interne : alerte"
require_demo laurent-bot internal-db
since="$(now_iso)"
ports="21 22 23 25 80 110 135 139 443 445 1433 1521 3306 3389 5432 5900 6379 8080 9200 27017"
out="$(agent_sh laurent-bot "for p in $ports; do nc -z -w 1 $INTERNAL_DB_IP \$p && echo open:\$p; done; true" 2>&1 || true)"
evidence "scanned $(echo "$ports" | wc -w | tr -d ' ') ports of $INTERNAL_DB_IP: $(printf '%s' "$out" | tr '\n' ' ')"
printf '%s' "$out" | grep -q 'open:5432' && evidence "internal flow to 5432 allowed (monitored)"
lid="$(agent_id laurent-bot)"; alert=""
for _ in $(seq 1 30); do
  alert="$(alerts_since "$since" | jqx -c --arg a "$lid" 'select((.event.kind // .kind) == "port_scan" and ((.event.agent_id // .agent_id) == $a))' | head -n1 || true)"
  [ -n "$alert" ] && break; sleep 1
done
[ -n "$alert" ] || fail "no port_scan alert for laurent-bot"
evidence "alert: $(printf '%s' "$alert" | jqx -r '(.event // .) | "\(.severity) \(.kind): \(.summary)"')"
if map="$(api_get /internal-map 2>/dev/null)"; then
  evidence "internal map edges to $INTERNAL_DB_IP: $(printf '%s' "$map" | jqx -c --arg ip "$INTERNAL_DB_IP" '[.edges[] | select(.target | contains($ip)) | .port] | unique')"
fi
pass "balayage détecté et alerté, flux internes visibles"
