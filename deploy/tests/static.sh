#!/usr/bin/env bash
# Static checks of the deployment files: compose files, Helm chart, shell scripts, Python helpers.
# shellcheck source=deploy/tests/common.sh
. "$(dirname "$0")/common.sh"
cd "$ROOT"

section "docker compose config"
check "deploy/compose/docker-compose.yml" \
  docker compose --env-file deploy/compose/.env.example -f deploy/compose/docker-compose.yml config -q
check "deploy/compose/docker-compose.yml (profile clickhouse)" \
  docker compose --env-file deploy/compose/.env.example -f deploy/compose/docker-compose.yml --profile clickhouse config -q
check "deploy/compose/gateway.yml" \
  docker compose --env-file deploy/compose/gateway.env.example -f deploy/compose/gateway.yml config -q
check "demo/docker-compose.yml" docker compose -f demo/docker-compose.yml config -q
check "demo has no ClickHouse by default" \
  bash -c 's=$(docker compose -f demo/docker-compose.yml config --services) && ! grep -qi clickhouse <<<"$s"'

section "compose invariants (ADR 0003)"
demo_json="$(docker compose -f demo/docker-compose.yml config --format json 2>/dev/null || echo '{}')"
check "afw-internal, lan and wan networks are internal" \
  bash -c 'for n in afw-internal lan wan; do jq -e --arg n "$n" ".networks[\$n].internal == true" <<<"$1" >/dev/null || exit 1; done' _ "$demo_json"
check "agents have no NET_ADMIN and share an afw-net-* namespace" \
  bash -c 'for a in daniel-bot laurent-bot acme-bot; do jq -e --arg a "$a" "(.services[\$a].network_mode == \"service:afw-net-\" + \$a) and ((.services[\$a].cap_add // []) | index(\"NET_ADMIN\") | not)" <<<"$1" >/dev/null || { echo "$a"; exit 1; }; done' _ "$demo_json"
check "afw-net-* containers have NET_ADMIN and the enrolment labels" \
  bash -c 'for a in daniel-bot laurent-bot acme-bot; do jq -e --arg a "$a" ".services[\"afw-net-\" + \$a] | ((.cap_add | index(\"NET_ADMIN\")) != null) and .labels[\"afw.enrolled\"] == \"true\" and .labels[\"afw.agent\"] == \$a" <<<"$1" >/dev/null || { echo "$a"; exit 1; }; done' _ "$demo_json"
check "published ports bind to 127.0.0.1 only" \
  bash -c 'jq -e "[.services[] | (.ports // [])[] | .host_ip] | all(. == \"127.0.0.1\")" <<<"$1" >/dev/null' _ "$demo_json"

section "helm"
check "helm lint" helm_run lint deploy/helm/agents-firewall
check "helm lint (strict, gateway + external postgres)" \
  helm_run lint --strict deploy/helm/agents-firewall -f deploy/helm/agents-firewall/ci/gateway-values.yaml
check "helm template (defaults)" helm_run template afw deploy/helm/agents-firewall
tpl="$(helm_run template afw deploy/helm/agents-firewall -f deploy/helm/agents-firewall/ci/gateway-values.yaml 2>/dev/null || true)"
check "helm template renders a NetworkPolicy for enrolled pods" grep -q 'afw.enrolled' <<<"$tpl"
check "enrolled-pod NetworkPolicy has no open egress rule" \
  bash -c 'docker run --rm -i mikefarah/yq:4.44.3 -o=json ea "[.] | map(select(.kind == \"NetworkPolicy\" and .metadata.labels[\"app.kubernetes.io/component\"] == \"enrolled-egress\"))" - <<<"$1" | jq -e "length > 0 and all(.[]; .spec.egress | all(.[]; (.to | length) > 0))" >/dev/null' _ "$tpl"
check "no StatefulSet when postgres.enabled=false" \
  bash -c '! grep -q "kind: StatefulSet" <<<"$1"' _ "$tpl"

section "shellcheck"
# bash 3.2 (macOS) compatible: no mapfile.
scripts="$(git ls-files -co --exclude-standard '*.sh' | sort -u | tr '\n' ' ')"
# shellcheck disable=SC2086 # word splitting of the file list is intended
check "shellcheck ($(echo $scripts | wc -w | tr -d ' ') scripts)" \
  docker run --rm -v "$ROOT":/mnt -w /mnt "$SHELLCHECK_IMAGE" -x -S warning $scripts

section "python helpers"
check "demo/tools/*.py compile" \
  docker run --rm -v "$ROOT":/w -w /w "$PYTHON_IMAGE" python -m py_compile demo/tools/fake_upstream.py

section "demo policy"
check "demo-policy.json is valid JSON with the expected zones" \
  jq -e '[.zones[].name] | sort == ["clients","internes"]' demo/policy/demo-policy.json
check "demo policy references only declared ids" bash -c '
  f=demo/policy/demo-policy.json
  declared=$(jq -c "[.objects[],.services[],.data_classes[],.zones[],.agents[],.rules[],.inspection_rules[] | .id]" "$f")
  jq -e --argjson d "$declared" "[.. | strings | select(test(\"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$\"))] | all(. as \$x | \$d | index(\$x))" "$f" >/dev/null'
check "demo policy contains nothing specific to Pulse myIT" bash -c '! grep -qi "pulse" demo/policy/demo-policy.json'

finish
