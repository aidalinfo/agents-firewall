#!/usr/bin/env bash
# Runs every acceptance scenario (demo/scenarios/NN-*.sh) and writes demo/.state/results.json and results.md.
# Usage: demo/scenarios/run-all.sh [NN ...]   (e.g. demo/scenarios/run-all.sh 01 05 to run a subset)
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
rm -f "$RESULTS_DIR"/*.json "$RESULTS_DIR"/*.evidence
rc=0
for s in "$DEMO_DIR"/scenarios/[0-9][0-9]-*.sh; do
  id="$(basename "$s" .sh)"
  if [ "$#" -gt 0 ]; then
    want=0; for n in "$@"; do case "$id" in "$n"-*) want=1 ;; esac; done
    [ "$want" = 1 ] || continue
  fi
  "$s" || rc=1
  if [ ! -f "$RESULTS_DIR/$id.json" ]; then # crashed before reporting
    jqx -n --arg id "$id" '{id: $id, title: $id, status: "FAIL", message: "scenario crashed (see output)", duration_ms: 0, evidence: []}' >"$RESULTS_DIR/$id.json"
  fi
done
jqx -s --arg at "$(now_iso)" '{generated_at: $at,
  summary: {pass: map(select(.status == "PASS")) | length, fail: map(select(.status == "FAIL")) | length,
            skip: map(select(.status == "SKIP")) | length},
  scenarios: sort_by(.id)}' "$RESULTS_DIR"/[0-9][0-9]-*.json >"$STATE_DIR/results.json.raw"
# Publishable results: fake AWS keys masked, local absolute paths made relative to the repository.
jqx --arg root "$ROOT/" 'walk(if type == "string" then (split($root) | join("")) | gsub("AKIA[A-Z2-7]{16}"; "AKIA****************") else . end)' \
  "$STATE_DIR/results.json.raw" >"$STATE_DIR/results.json" && rm -f "$STATE_DIR/results.json.raw"
jqx -r '"# Recette agents-firewall — résultats\n\nGénéré le \(.generated_at) : \(.summary.pass) PASS, \(.summary.fail) FAIL, \(.summary.skip) SKIP.\n\n| Scénario | Résultat | Durée | Détail |\n|---|---|---|---|",
  (.scenarios[] | "| \(.id) — \(.title) | \(.status) | \(.duration_ms / 1000 | floor) s | \(.message | gsub("\\|"; "/")) |"),
  "\nHors démo (production) : migration de Daniel, Laurent et Vulcain et retrait de l'"'"'egress-guard actuel (cahier §8) ; à constater sur les hôtes réels.",
  "\n## Preuves\n",
  (.scenarios[] | "### \(.id) — \(.status)\n\n\(.evidence | map("- `" + gsub("`"; "'\''") + "`") | join("\n"))\n")' \
  "$STATE_DIR/results.json" >"$STATE_DIR/results.md"
jqx -r '.summary | "\n\(.pass) PASS, \(.fail) FAIL, \(.skip) SKIP"' "$STATE_DIR/results.json"
info "results: $STATE_DIR/results.json, $STATE_DIR/results.md"
exit "$rc"
