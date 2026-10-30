#!/usr/bin/env bash
# 07 — Fournisseur LLM exempté (EF-25, ADR 0005) : un secret dans un prompt vers api.anthropic.com (simulé
# par fake-llm) passe ; le flux est journalisé en détail, secret masqué.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 07-llm-exempte "Secret vers le fournisseur LLM : passe, masqué dans le journal"
require_demo laurent-bot
since="$(now_iso)"
key="AKIA$(LC_ALL=C tr -dc 'A-Z2-7' </dev/urandom | head -c 16)"
out="$(agent_sh laurent-bot "curl -sS -w '\nHTTP %{http_code}' --max-time 15 -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' -d '{\"model\":\"demo\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"Explain this config: aws_access_key_id=$key\"}]}' https://api.anthropic.com/v1/messages" 2>&1 || true)"
code="$(printf '%s' "$out" | sed -n 's/^HTTP \([0-9]*\)$/\1/p')"
evidence "laurent-bot -> api.anthropic.com/v1/messages with a secret in the prompt: HTTP $code"
[ "$code" = 200 ] || fail "LLM call blocked or failed (HTTP $code): $out"
assert_received fake-llm "$key" "the prompt"
evidence "the provider received the prompt (exemption EF-25)"
flow="$(find_flow "$(agent_id laurent-bot)" api.anthropic.com allow "$since")" || fail "allowed LLM flow not found in the log"
evidence "flow: llm_provider=$(printf '%s' "$flow" | jqx -r '.llm_provider'), tls_inspected=$(printf '%s' "$flow" | jqx -r '.tls_inspected'), classes $(printf '%s' "$flow" | jqx -c '.data_classes')"
detail="$(flow_detail "$(printf '%s' "$flow" | jqx -r '.id')")" || fail "flow detail unavailable"
printf '%s' "$detail" | grep -q -- "$key" && fail "the raw secret is stored in the log"
printf '%s' "$detail" | grep -q '\[SECRET:' || fail "the request body is not in the log (detail expected)"
evidence "request body logged with the secret masked: $(printf '%s' "$detail" | grep -o '\[SECRET:[^]]*\]' | head -n1)"
pass "LLM exempté du blocage, contenu journalisé et masqué"
