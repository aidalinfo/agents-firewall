#!/usr/bin/env bash
# 09 — Publier, installer, retour arrière (EF-10..14, ENF-07) : une révision qui désactive la règle
# « API autorisée » de la zone clients est publiée et installée (acme-bot refusé), puis on réinstalle la
# révision précédente (acme-bot de nouveau autorisé), puis on republie l'état d'origine.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 09-publier-installer-rollback "Publication, installation et retour arrière"
require_demo acme-bot
call='curl -s -o /dev/null -w "%{http_code}" --max-time 10 https://allowed.example/zen'
probe() { local c=""; for _ in $(seq 1 10); do c="$(agent_sh acme-bot "$call" || true)"; [ "$c" = "$1" ] && break; sleep 1; done; printf '%s' "$c"; }
rule="$(demo_id "$(did 621)")"
before="$(latest_revision)"; [ -n "$before" ] || fail "no published revision"
c="$(probe 200)"; evidence "revision $before: acme-bot -> allowed.example = $c"; [ "$c" = 200 ] || fail "precondition: expected 200"

session_open; set_rule_enabled "$rule" false
rev="$(publish_and_install "Démo 09 : désactiver « API autorisée » (clients)")"
evidence "revision $rev installed: $(api_get "/revisions/$rev/diff?against=$before" 2>/dev/null | jqx -c '[.changes[] | {kind, name: .resource.name}]' || echo 'diff unavailable')"
c="$(probe 403)"; evidence "revision $rev: acme-bot -> allowed.example = $c"; [ "$c" = 403 ] || fail "new revision not applied (got $c)"

install "$before"; wait_installed "$before" 90 || fail "rollback to $before not active"
c="$(probe 200)"; evidence "rollback to revision $before: acme-bot -> allowed.example = $c"
rolled="$c"

session_open; set_rule_enabled "$rule" true
rev3="$(publish_and_install "Démo 09 : rétablir « API autorisée » (clients)")"
evidence "revision $rev3 restores the demo policy"
[ "$rolled" = 200 ] || fail "rollback did not restore the previous behaviour (got $rolled)"
pass "publication, installation et retour arrière vérifiés par le trafic"
