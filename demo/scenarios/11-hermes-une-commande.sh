#!/usr/bin/env bash
# 11 — Un nouveau bot Hermes protégé et visible en une commande (EF-60/61, cahier §8) : `afw enroll … --compose
# --hermes --publish … --apply` transforme le compose d'un nouveau bot (afw-net, proxy, CA, plugin Hermes), crée
# l'agent et son jeton de plugin, publie et démarre le bot. Il est aussitôt visible et protégé (agent inconnu de la
# passerelle tant que la révision n'est pas installée : refus) ; une fois la révision installée, il suit sa zone.
# The CLI runs in afw-cli-docker:local (afw + docker client, host socket) so that --apply can run docker compose.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 11-hermes-une-commande "Nouveau bot Hermes enrôlé en une commande"
require_demo
cli_has enroll || skip "the afw CLI has no 'enroll' command (lot L8 not merged)"
image_exists afw-hermes-demo:local || skip "afw-hermes-demo:local image missing (lot L4 not merged)"
CLI_DOCKER_IMAGE="${AFW_CLI_DOCKER_IMAGE:-afw-cli-docker:local}"
image_exists "$CLI_DOCKER_IMAGE" ||
  docker build -q -t "$CLI_DOCKER_IMAGE" -f "$DEMO_DIR/tools/Dockerfile.cli-docker" "$DEMO_DIR/tools" >/dev/null ||
  fail "cannot build $CLI_DOCKER_IMAGE"
dir="$STATE_DIR/s11"
if [ -f "$dir/docker-compose.yml" ]; then docker compose -p afw-demo-s11 -f "$dir/docker-compose.yml" down -v >/dev/null 2>&1 || true; fi
rm -rf "$dir"; mkdir -p "$dir"
agent="hermes-nouveau-$(rand_hex 4)"
cat >"$dir/docker-compose.yml" <<YAML
name: afw-demo-s11
services:
  $agent:
    image: afw-hermes-demo:local
    restart: unless-stopped
YAML
# The gateway CA certificate on the host (a production host reads it from the gateway's public directory).
docker cp "$(dc ps -q gateway):/var/lib/afw/public/gateway.crt" "$dir/gateway.crt" >/dev/null || fail "cannot read the gateway CA"
before="$(latest_revision)"
cmd="afw enroll $agent --zone clients --ip 10.77.0.13 --gateway demo-gw --compose $dir/docker-compose.yml --network ${DEMO_PROJECT}_afw-internal --ca-path $dir/gateway.crt --hermes --hermes-plugin-dir $ROOT/integrations/hermes --console-url http://10.76.0.10:8080 --env-file $dir/.env --publish 'Démo 11 : enrôlement de $agent' --apply"
t0="$(now_ms)"
# The single command. Paths are mounted at the same place so that docker compose resolves them as on the host.
out="$(docker run --rm -i --user 0 --network "${DEMO_PROJECT}_control" -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$dir:$dir" -v "$ROOT/integrations/hermes:$ROOT/integrations/hermes:ro" -w "$dir" \
  -e "$AFW_CLI_URL_ENV=$AFW_API_URL_IN_DOCKER" -e "$AFW_CLI_TOKEN_ENV=$AFW_TOKEN" --entrypoint sh "$CLI_DOCKER_IMAGE" -c "$cmd" 2>&1)" ||
  fail "afw enroll failed: $(printf '%s' "$out" | tail -n 5 | tr '\n' ' ')"
t1="$(now_ms)"
evidence "one command: $cmd"
evidence "output: $(printf '%s' "$out" | grep -v -i 'token\|afw_at_' | tail -n 4 | tr '\n' ' ' | cut -c1-300)"
grep -q "afw-net-$agent" "$dir/docker-compose.yml" || fail "no afw-net-$agent container in the enrolled compose"
id="$(agent_id "$agent")"; [ -n "$id" ] || fail "agent $agent not visible in the console"
rev="$(latest_revision)"; [ "$rev" != "$before" ] || fail "the command did not publish a revision"
evidence "agent $agent visible in the console (id $id, zone $(api_get "/agents/$id" | jqx -r '.zone_id')), revision $rev published, in $(( (t1 - t0) / 1000 )) s"
for _ in $(seq 1 60); do [ -n "$(docker compose -p afw-demo-s11 -f "$dir/docker-compose.yml" ps -q --status running "$agent" 2>/dev/null)" ] && break; sleep 1; done
in_bot() { docker compose -p afw-demo-s11 -f "$dir/docker-compose.yml" exec -T "$agent" sh -c "$1"; }
since="$(now_iso)"
c="$(in_bot "$(http_code_cmd https://exfil.example/)" 2>/dev/null || true)"
evidence "before install: $agent -> exfil.example = ${c:-none}"
case "$c" in 200) fail "the new bot reached exfil.example" ;; esac
# Applying the zone's rules is an installation (same as any policy change).
install "$rev"; wait_installed "$rev" 90 || fail "revision $rev not installed"
c=""; for _ in $(seq 1 20); do c="$(in_bot "$(http_code_cmd https://allowed.example/zen)" 2>/dev/null || true)"; [ "$c" = 200 ] && break; sleep 1; done
evidence "after install of $rev: $agent -> allowed.example = $c (zone clients)"
[ "$c" = 200 ] || fail "the new bot does not get its zone's access after install (HTTP $c)"
in_bot "$(http_code_cmd https://exfil.example/)" >/dev/null 2>&1 || true
flow="$(find_flow "$id" exfil.example deny "$since" 20)" || fail "no denied flow for the new bot (not protected?)"
evidence "new bot protected: exfil.example denied by rule $(printf '%s' "$flow" | jqx -r '.decision.rule_number // .decision.rule_name')"
pass "bot Hermes enrôlé, publié, démarré et visible en une commande ($(( (t1 - t0) / 1000 )) s), protégé"
