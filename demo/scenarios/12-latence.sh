#!/usr/bin/env bash
# 12 — Surcoût de latence (ENF-01, cahier §9) : p50/p95 d'une requête HTTPS vers allowed.example, à travers la
# passerelle (laurent-bot, proxy explicite, inspection TLS : déchiffrée, analysée, re-chiffrée) et en direct
# (client sur le réseau wan, sans passerelle), en connexion NOUVELLE (une poignée de main TLS par requête) et
# RÉUTILISÉE (keep-alive : N requêtes sur une connexion). Mesure répétée AFW_LATENCY_PASSES fois (défaut 5),
# alternant passerelle et direct ; on retient la MÉDIANE des p50/p95 des passes.
# AFW_LATENCY_N (default 50) requests per pass and mode; PASS if the median p95 overhead (new connection) is below
# AFW_LATENCY_MAX_P95_MS (default 100).
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 12-latence "Latence p50/p95 avec et sans passerelle (HTTPS inspecté, connexion nouvelle et réutilisée)"
require_demo laurent-bot
n="${AFW_LATENCY_N:-50}"; passes="${AFW_LATENCY_PASSES:-5}"; max="${AFW_LATENCY_MAX_P95_MS:-100}"
url=https://allowed.example/zen
since="$(now_iso)"
# new connection: one curl process (and one TLS handshake) per request.
new_loop="i=0; while [ \$i -lt $n ]; do curl -s -o /dev/null -w '%{time_total}\n' --max-time 10 \$CA $url; i=\$((i+1)); done"
# reused connection: one curl process, n transfers on the same connection (time of each transfer).
reuse_args="$(i=0; while [ $i -lt "$n" ]; do printf ' -o /dev/null %s' "$url"; i=$((i + 1)); done)"
reuse_loop="curl -s --max-time 60 -w '%{time_total} %{num_connects}\n' \$CA $reuse_args"
direct_ca="CA='--cacert /pki/demo-ca.crt --resolve allowed.example:443:198.18.0.12'"
direct_run() { dc --profile tools run --rm -T direct-client sh -c "$direct_ca; $1"; }
gw_run() { agent_sh laurent-bot "CA=; $1"; }
pct() { # pct <percentile> : reads seconds on stdin (first column), prints milliseconds
  awk '{print $1}' | sort -n | awk -v p="$1" '{a[NR]=$1} END {if (NR == 0) {print "nan"; exit} i = int((p/100)*NR + 0.999999); if (i < 1) i = 1; printf "%.1f", a[i]*1000}'
}
median() { sort -n | awk '{a[NR]=$1} END {if (NR % 2) printf "%.1f", a[(NR+1)/2]; else printf "%.1f", (a[NR/2]+a[NR/2+1])/2}'; }
rows="$STATE_DIR/latency-passes.tsv"; : >"$rows"
# warm-up (DNS cache of the gateway, leaf certificate of allowed.example, page cache)
gw_run "$new_loop" >/dev/null 2>&1 || true; direct_run "$new_loop" >/dev/null 2>&1 || true
for p in $(seq 1 "$passes"); do
  for mode in new reuse; do
    loop="$new_loop"; [ "$mode" = reuse ] && loop="$reuse_loop"
    via="$(gw_run "$loop")" || fail "measurement through the gateway failed (pass $p, $mode)"
    direct="$(direct_run "$loop")" || fail "direct measurement failed (pass $p, $mode)"
    [ "$(printf '%s\n' "$via" | grep -c .)" = "$n" ] || fail "pass $p $mode: expected $n samples through the gateway"
    if [ "$mode" = reuse ]; then # all transfers but the first must reuse the connection
      [ "$(printf '%s\n' "$via" | awk '$2 != 0' | wc -l | tr -d ' ')" -le 1 ] || fail "pass $p: the gateway path opened several connections in reuse mode"
      via="$(printf '%s\n' "$via" | sed 1d)"; direct="$(printf '%s\n' "$direct" | sed 1d)"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$mode" "$(printf '%s\n' "$via" | pct 50)" "$(printf '%s\n' "$via" | pct 95)" \
      "$(printf '%s\n' "$direct" | pct 50)" "$(printf '%s\n' "$direct" | pct 95)" >>"$rows"
  done
done
evidence "$passes passes x $n requests per mode (gateway path: explicit proxy + TLS inspection; reuse mode drops the first, connecting, transfer)"
while IFS="$(printf '\t')" read -r p mode v50 v95 d50 d95; do
  evidence "pass $p $mode: gateway p50 $v50 / p95 $v95 ms — direct p50 $d50 / p95 $d95 ms"
done <"$rows"
json='{}'
for mode in new reuse; do
  col() { awk -F'\t' -v m="$mode" -v c="$1" '$2 == m {print $c}' "$rows" | median; }
  v50="$(col 3)"; v95="$(col 4)"; d50="$(col 5)"; d95="$(col 6)"
  o50="$(awk -v a="$v50" -v b="$d50" 'BEGIN {printf "%.1f", a-b}')"; o95="$(awk -v a="$v95" -v b="$d95" 'BEGIN {printf "%.1f", a-b}')"
  evidence "MEDIAN $mode connection: gateway p50 ${v50} ms, p95 ${v95} ms — direct p50 ${d50} ms, p95 ${d95} ms — overhead p50 ${o50} ms, p95 ${o95} ms"
  json="$(printf '%s' "$json" | jqx -c --arg m "$mode" --argjson v50 "$v50" --argjson v95 "$v95" --argjson d50 "$d50" --argjson d95 "$d95" \
    --argjson o50 "$o50" --argjson o95 "$o95" '.[$m] = {gateway: {p50_ms: $v50, p95_ms: $v95}, direct: {p50_ms: $d50, p95_ms: $d95}, overhead: {p50_ms: $o50, p95_ms: $o95}}')"
  [ "$mode" = new ] && { new_o50="$o50"; new_o95="$o95"; }
  [ "$mode" = reuse ] && { reuse_o50="$o50"; reuse_o95="$o95"; }
done
flow="$(find_flow "$(agent_id laurent-bot)" allowed.example allow "$since" 5 || true)"
[ -n "$flow" ] && evidence "sample flow: tls_inspected=$(printf '%s' "$flow" | jqx -r '.tls_inspected'), content_inspected=$(printf '%s' "$flow" | jqx -r '.content_inspected // "n/a"')"
printf '%s' "$flow" | jqx -e '.tls_inspected == true' >/dev/null 2>&1 || fail "the measured path is not TLS-inspected"
printf '%s' "$json" | jqx --argjson n "$n" --argjson p "$passes" '{requests_per_pass: $n, passes: $p, statistic: "median over passes of per-pass percentiles"} + .' >"$RESULTS_DIR/latency.json"
awk -v o="$new_o95" -v m="$max" 'BEGIN {exit !(o < m)}' || fail "p95 overhead ${new_o95} ms >= ${max} ms"
pass "surcoût médian, connexion nouvelle : p50 ${new_o50} ms, p95 ${new_o95} ms ; connexion réutilisée : p50 ${reuse_o50} ms, p95 ${reuse_o95} ms"
