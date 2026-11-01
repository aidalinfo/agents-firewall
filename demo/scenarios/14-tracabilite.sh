#!/usr/bin/env bash
# 14 — Traçabilité en moins d'une minute (cahier §8, EF-34, ADR 0007) : daniel-bot (Hermes) exécute un appel
# d'outil dans une conversation ; on retrouve ensuite par l'API, chronométré : le flux → l'agent, la
# conversation, l'outil, le contenu et la règle.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 14-tracabilite "Flux → agent, conversation, outil, contenu, règle en < 60 s"
require_demo daniel-bot
conv="conv-s14-$(rand_hex 8)"; m="s14-$(rand_hex)"; since="$(now_iso)"
req="$(jqx -nc --arg c "$conv" --arg m "$m" '{tool: "fetch", conversation_id: $c, args: {url: "https://allowed.example/report", method: "POST", body: ("weekly report " + $m)}}')"
out="$(dc exec -T daniel-bot curl -sS --max-time 30 -H 'content-type: application/json' -d "$req" "$DANIEL_RUN_URL" 2>&1)" ||
  fail "daniel-bot did not run the tool: $out"
evidence "daniel-bot /run fetch in $conv: $(printf '%s' "$out" | cut -c1-160)"
assert_received allowed-api "$m" "the tool call"

# The clock starts once the action is done: an operator looks for it.
t0="$(now_ms)"; did_find=0
for _ in $(seq 1 55); do
  flow="$(flows "agent=$(agent_id daniel-bot)&destination=allowed.example&from=$since&limit=20" 2>/dev/null | head -n1 || true)"
  if [ -n "$flow" ]; then
    detail="$(flow_detail "$(printf '%s' "$flow" | jqx -r '.id')" 2>/dev/null || true)"
    if printf '%s' "$detail" | jqx -e --arg c "$conv" '.correlation.conversation_id == $c and .tool_call != null' >/dev/null 2>&1; then
      did_find=1; break
    fi
  fi
  sleep 1
done
elapsed=$(( ($(now_ms) - t0) / 1000 ))
[ "$did_find" = 1 ] || fail "flow with its conversation not found within ${elapsed} s"
evidence "agent: $(printf '%s' "$detail" | jqx -r '.flow.agent_id') (daniel-bot)"
evidence "conversation: $(printf '%s' "$detail" | jqx -r '.correlation.conversation_id') (confidence $(printf '%s' "$detail" | jqx -r '.correlation.confidence'))"
evidence "tool: $(printf '%s' "$detail" | jqx -r '.tool_call.tool') — $(printf '%s' "$detail" | jqx -r '.tool_call.args_summary' | cut -c1-80)"
printf '%s' "$detail" | jqx -e '.tool_call.tool == "fetch"' >/dev/null || fail "wrong tool in the correlation"
printf '%s' "$detail" | grep -q -- "$m" || fail "the content (request body) is not in the flow detail"
evidence "content: request body logged ($(printf '%s' "$detail" | jqx -r '[.http[] | .method + " " + .url] | join(", ")'))"
evidence "rule: #$(printf '%s' "$detail" | jqx -r '.flow.decision.rule_number') $(printf '%s' "$detail" | jqx -r '.flow.decision.rule_name')"
[ "$elapsed" -lt 60 ] || fail "found in ${elapsed} s (>= 60 s)"
pass "flux retrouvé avec agent, conversation, outil, contenu et règle en ${elapsed} s"
