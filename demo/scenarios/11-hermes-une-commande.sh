#!/usr/bin/env bash
# 11 — Un nouveau bot Hermes protégé et visible en une commande (EF-60/61, cahier §8) : `afw enroll compose`
# transforme le compose d'un nouveau bot (afw-net, proxy, CA, plugin Hermes, agent créé dans la console).
# The enroll command line can be overridden with AFW_ENROLL_ARGS (lot L8/L11 syntax).
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 11-hermes-une-commande "Nouveau bot Hermes enrôlé en une commande"
require_demo
cli_has enroll compose || skip "the afw CLI has no 'enroll compose' command yet (lots L8/L11 not merged)"
image_exists afw-hermes-demo:local || skip "afw-hermes-demo:local image missing (lot L4 not merged)"
dir="$STATE_DIR/s11"; mkdir -p "$dir"
agent="hermes-nouveau-$(rand_hex 4)"
cat >"$dir/docker-compose.yml" <<YAML
services:
  $agent:
    image: afw-hermes-demo:local
    restart: unless-stopped
YAML
ca_vol="${DEMO_PROJECT}_gateway-public"
enroll_args="${AFW_ENROLL_ARGS:-enroll compose --file /work/docker-compose.yml --service $agent --agent $agent --zone clients --hermes --gateway demo-gw --network ${DEMO_PROJECT}_afw-internal --gateway-ip $GATEWAY_IP --ip 10.77.0.13 --ca-volume $ca_vol --write}"
t0="$(now_ms)"
# shellcheck disable=SC2086 # the argument list is a template
out="$(docker run --rm -i --network "${DEMO_PROJECT}_control" -v "$dir":/work \
  -e "$AFW_CLI_URL_ENV=$AFW_API_URL_IN_DOCKER" -e "$AFW_CLI_TOKEN_ENV=$AFW_TOKEN" "$AFW_CLI_IMAGE" $enroll_args 2>&1)" ||
  fail "afw enroll failed: $out"
evidence "afw $enroll_args"
evidence "$(printf '%s' "$out" | tail -n 3 | tr '\n' ' ')"
docker compose -p afw-demo-s11 -f "$dir/docker-compose.yml" up -d >&2 || fail "the enrolled compose does not start"
grep -q "afw-net-$agent" "$dir/docker-compose.yml" || fail "no afw-net-$agent container in the enrolled compose"
id="$(agent_id "$agent")"; [ -n "$id" ] || fail "agent $agent not visible in the console"
evidence "agent $agent visible in the console (id $id, zone $(api_get "/agents/$id" | jqx -r '.zone_id'))"
since="$(now_iso)"
docker compose -p afw-demo-s11 -f "$dir/docker-compose.yml" exec -T "$agent" sh -c 'curl -s -o /dev/null --max-time 10 https://allowed.example/zen; curl -s -o /dev/null --max-time 10 https://exfil.example/' >/dev/null 2>&1 || true
flow="$(find_flow "$id" exfil.example deny "$since" 20)" || fail "no denied flow for the new bot (not protected?)"
evidence "new bot protected: exfil.example denied by rule #$(printf '%s' "$flow" | jqx -r '.decision.rule_number')"
pass "bot Hermes enrôlé, protégé et visible en $(( ($(now_ms) - t0) / 1000 )) s"
