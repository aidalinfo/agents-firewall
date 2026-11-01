#!/usr/bin/env bash
# Inbound path of an enrolled agent that publishes ports (issue #22), on a real Docker:
#  1. before enrollment, the published ports of test-bot answer on the host;
#  2. enrolled with afw_enroll::enroll_compose: the same host ports answer, through the afw-in-test-bot relay and
#     the gateway (the agent sees the gateway as the peer), with the explicit host address kept;
#  3. the agent namespace keeps a single interface and two routes, its holder publishes nothing, and an egress
#     that ignores the proxy still goes through the gateway (or is refused);
#  4. gateway stopped: egress and inbound are both cut (no "protected" service still reachable); restarted: back;
#  5. afw_enroll::unenroll_compose restores the original file exactly, and the restored file publishes again.
# shellcheck source=deploy/tests/common.sh
. "$(dirname "$0")/common.sh"
cd "$ROOT"

DIR=deploy/tests/ingress
PROJECT=afw-ingress-test
NET_INTERNAL=afw-it-internal
NET_INGRESS=afw-it-ingress
AGENT=test-bot
AGENT_IP=10.99.0.10
GW_IP=10.99.0.2
GW_INGRESS_IP=10.98.0.2
export AFW_IT_PORT_A="${AFW_IT_PORT_A:-18080}" AFW_IT_PORT_B="${AFW_IT_PORT_B:-18090}"
tmp="$(mktemp -d)"
dc() { docker compose -p "$PROJECT" --project-directory "$DIR" -f "$1" "${@:2}"; }
cleanup() {
  [ "${KEEP:-0}" = 1 ] && return
  for f in "$tmp/enrolled.yml" "$tmp/restored.yml" "$DIR/base.yml"; do
    [ -f "$f" ] && dc "$f" down -v --remove-orphans >/dev/null 2>&1
  done
  docker network rm "$NET_INTERNAL" "$NET_INGRESS" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT
# afw-enroll run in Docker (scripts/cargo.sh), the compose file on stdin.
tool() { AFW_DOCKER_ARGS="-i -e CARGO_TARGET_DIR=/w/target/demo-enroll" scripts/cargo.sh run -q \
  --manifest-path deploy/tools/demo-enroll/Cargo.toml -- "$@"; }
# get <port>: body served on 127.0.0.1:<port> of the host.
get() { curl -s -m 5 "http://127.0.0.1:$1/"; }
wait_for() { for _ in $(seq 1 "$1"); do "${@:2}" >/dev/null 2>&1 && return 0; sleep 1; done; "${@:2}"; }
answers() { get "$1" | grep -q "^$2 peer="; }
agent() { dc "$tmp/enrolled.yml" exec -T "$AGENT" "$@"; }

section "networks, images, original stack"
docker network rm "$NET_INTERNAL" "$NET_INGRESS" >/dev/null 2>&1 || true
check "internal network (internal: true)" docker network create --internal --subnet 10.99.0.0/24 "$NET_INTERNAL"
check "ingress network (internal: true)" docker network create --internal --subnet 10.98.0.0/24 "$NET_INGRESS"
check "build afw-netinit (ip + socat)" docker build -q -t afw-netinit:local -f deploy/docker/Dockerfile.netinit deploy/docker
check "start gateway, web and test-bot (not enrolled)" dc "$DIR/base.yml" up -d --build --wait gateway web "$AGENT"
check "before: port A answers on the host" wait_for 20 answers "$AFW_IT_PORT_A" hello-from-agent-a
check "before: port B answers on 127.0.0.1" wait_for 20 answers "$AFW_IT_PORT_B" hello-from-agent-b
dc "$DIR/base.yml" cp gateway:/var/lib/afw/public/gateway.crt "$tmp/gateway.crt" >/dev/null 2>&1 ||
  { ko "gateway CA not exported"; finish; }

section "enroll with afw-enroll"
if ! tool enroll - "$AGENT" "$AGENT_IP" "$GW_IP" "$NET_INTERNAL" "$tmp/gateway.crt" "$NET_INGRESS" "$GW_INGRESS_IP" \
  <"$DIR/base.yml" >"$tmp/enrolled.yml" 2>"$tmp/warnings"; then
  cat "$tmp/warnings"; ko "enroll_compose"; finish
fi
ok "enroll_compose"
check "the dry run states the relay mechanism" grep -q "afw-in-$AGENT, which forwards TCP 8080, 9000 to the agent through the gateway" "$tmp/warnings"
check "start the enrolled stack" dc "$tmp/enrolled.yml" up -d --wait --remove-orphans

section "inbound ports"
check "port A answers on the host (through the relay)" wait_for 30 answers "$AFW_IT_PORT_A" hello-from-agent-a
check "port B answers on 127.0.0.1 (through the relay)" wait_for 30 answers "$AFW_IT_PORT_B" hello-from-agent-b
check "the agent sees the gateway as the peer (symmetric return path)" \
  bash -c '[ "$(curl -s -m 5 "http://127.0.0.1:$1/" | sed -n "s/.* peer=//p")" = "$2" ]' _ "$AFW_IT_PORT_A" "$GW_IP"
check "port B keeps its explicit host address (127.0.0.1)" \
  bash -c '[ "$(docker compose -p "$1" --project-directory "$2" -f "$3" port "afw-in-$4" 9000)" = "127.0.0.1:$5" ]' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT" "$AFW_IT_PORT_B"
check "the namespace holder publishes nothing" \
  bash -c '[ "$(docker inspect -f "{{len .HostConfig.PortBindings}}" "$(docker compose -p "$1" --project-directory "$2" -f "$3" ps -q "afw-net-$4")")" = 0 ]' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT"
check "the relay reaches the agent through the gateway only" \
  bash -c 'docker compose -p "$1" --project-directory "$2" -f "$3" exec -T "afw-in-$4" ip route get "$5" | grep -q "via $6"' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT" "$AGENT_IP" "$GW_INGRESS_IP"

section "no egress bypass"
check "agent: a single interface up besides lo" \
  bash -c '[ "$(docker compose -p "$1" --project-directory "$2" -f "$3" exec -T "$4" ip -o link show up | grep -cv ": lo[:@]")" = 1 ]' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT"
check "agent: only the default route and the /32 to the gateway" \
  bash -c 'r=$(docker compose -p "$1" --project-directory "$2" -f "$3" exec -T "$4" ip -4 route); echo "$r"; [ "$(wc -l <<<"$r")" = 2 ] && grep -q "^default via $5 " <<<"$r" && grep -q "^$5 dev " <<<"$r"' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT" "$GW_IP"
check "agent: proxy ignored, direct IP -> 403 from the gateway" \
  agent sh -c "out=\$(curl -s -m 8 --noproxy '*' -w ' %{http_code}' http://198.18.99.20/); echo \"\$out\"; case \"\$out\" in *'blocked by agents-firewall'*403) exit 0;; *) exit 1;; esac"
check "agent: raw TCP to an arbitrary port is refused" \
  bash -c '! docker compose -p "$1" --project-directory "$2" -f "$3" exec -T "$4" sh -c "printf ping | nc -w 5 198.18.99.20 4444 | grep -q ping"' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT"
check "agent: the ingress network is only reachable through the gateway" \
  agent sh -c "ip route get $GW_INGRESS_IP | grep -q 'via $GW_IP'"
check "agent: the relay is not an exit (its own address goes through the gateway policy)" \
  bash -c 'ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$1\").IPAddress}}" "$(docker compose -p "$2" --project-directory "$3" -f "$4" ps -q "afw-in-$5")");
    out=$(docker compose -p "$2" --project-directory "$3" -f "$4" exec -T "$5" curl -s -m 8 --noproxy "*" "http://$ip:8080/"); echo "$out";
    ! grep -q hello-from-agent <<<"$out"' _ "${PROJECT}_front" "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT"

section "gateway stopped"
dc "$tmp/enrolled.yml" stop gateway >/dev/null 2>&1
check "gateway down: no egress (fail closed)" \
  bash -c '! docker compose -p "$1" --project-directory "$2" -f "$3" exec -T "$4" curl -s -m 6 --noproxy "*" http://198.18.99.20/' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT"
check "gateway down: the inbound ports are cut too (nothing answers as if protected)" \
  bash -c '! curl -s -m 6 "http://127.0.0.1:$1/" | grep -q hello-from-agent' _ "$AFW_IT_PORT_A"
dc "$tmp/enrolled.yml" start gateway >/dev/null 2>&1
check "gateway back: the inbound ports answer again" wait_for 40 answers "$AFW_IT_PORT_A" hello-from-agent-a

section "unenroll"
if ! tool unenroll - "$AGENT" <"$tmp/enrolled.yml" >"$tmp/restored.yml"; then ko "unenroll_compose"; finish; fi
tool normalize - <"$DIR/base.yml" >"$tmp/base.normalized.yml" || { ko "normalize"; finish; }
check "unenroll restores the original compose file exactly" diff -u "$tmp/base.normalized.yml" "$tmp/restored.yml"
check "restored stack starts (relay and holder removed)" dc "$tmp/restored.yml" up -d --wait --remove-orphans
check "restored: port A answers directly (peer is not the gateway)" \
  bash -c 'for _ in $(seq 1 20); do p=$(curl -s -m 5 "http://127.0.0.1:$1/" | sed -n "s/.* peer=//p"); [ -n "$p" ] && [ "$p" != "$2" ] && exit 0; sleep 1; done; exit 1' \
  _ "$AFW_IT_PORT_A" "$GW_IP"
check "restored: port B answers on 127.0.0.1" wait_for 20 answers "$AFW_IT_PORT_B" hello-from-agent-b
check "restored: no afw-in or afw-net container left" \
  bash -c '[ -z "$(docker ps -a -q --filter "label=com.docker.compose.project=$1" --filter "label=afw.agent=$2")" ]' _ "$PROJECT" "$AGENT"

finish
