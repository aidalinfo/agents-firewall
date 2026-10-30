#!/usr/bin/env bash
# 12 — Surcoût de latence (ENF-01, cahier §9) : p50/p95 d'une requête HTTPS vers allowed.example, à travers la
# passerelle (laurent-bot, inspection TLS) et en direct (client sur le réseau wan, sans passerelle).
# AFW_LATENCY_N (default 50) requests each; PASS if the p95 overhead is below AFW_LATENCY_MAX_P95_MS (default 100).
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 12-latence "Latence p50/p95 avec et sans passerelle"
require_demo laurent-bot
n="${AFW_LATENCY_N:-50}"; max="${AFW_LATENCY_MAX_P95_MS:-100}"
loop="i=0; while [ \$i -lt $n ]; do curl -s -o /dev/null -w '%{time_total}\n' --max-time 10 \$CA https://allowed.example/zen; i=\$((i+1)); done"
via="$(agent_sh laurent-bot "CA=; $loop")" || fail "measurement through the gateway failed"
direct="$(dc --profile tools run --rm -T direct-client sh -c "CA='--cacert /pki/demo-ca.crt --resolve allowed.example:443:198.18.0.12'; $loop")" ||
  fail "direct measurement failed"
pct() { # pct <percentile> : reads seconds on stdin, prints milliseconds
  sort -n | awk -v p="$1" '{a[NR]=$1} END {if (NR == 0) {print "nan"; exit} i = int((p/100)*NR + 0.999999); if (i < 1) i = 1; printf "%.1f", a[i]*1000}'
}
v50="$(printf '%s\n' "$via" | pct 50)"; v95="$(printf '%s\n' "$via" | pct 95)"
d50="$(printf '%s\n' "$direct" | pct 50)"; d95="$(printf '%s\n' "$direct" | pct 95)"
o50="$(awk -v a="$v50" -v b="$d50" 'BEGIN {printf "%.1f", a-b}')"; o95="$(awk -v a="$v95" -v b="$d95" 'BEGIN {printf "%.1f", a-b}')"
evidence "requests: $n each, new TLS connection per request"
evidence "through the gateway: p50 ${v50} ms, p95 ${v95} ms"
evidence "direct (no gateway): p50 ${d50} ms, p95 ${d95} ms"
evidence "overhead: p50 ${o50} ms, p95 ${o95} ms (threshold p95 < ${max} ms)"
jqx -n --argjson n "$n" --argjson v50 "$v50" --argjson v95 "$v95" --argjson d50 "$d50" --argjson d95 "$d95" \
  '{requests: $n, gateway: {p50_ms: $v50, p95_ms: $v95}, direct: {p50_ms: $d50, p95_ms: $d95}}' >"$RESULTS_DIR/latency.json"
awk -v o="$o95" -v m="$max" 'BEGIN {exit !(o < m)}' || fail "p95 overhead ${o95} ms >= ${max} ms"
pass "surcoût p50 ${o50} ms, p95 ${o95} ms"
