#!/usr/bin/env bash
# Inbound path of an enrolled agent that publishes ports (issues #22, #24), on a real Docker:
#  0. the host filters bridged traffic (br_netfilter, enabled here if needed: Docker does the same on most hosts) and
#     Docker's isolation rules for the `internal` networks are installed: a bridged packet whose source or destination
#     is outside the network's subnet is dropped (issue #24);
#  1. before enrollment, the published ports of test-bot answer on the host;
#  2. enrolled with afw_enroll::enroll_compose: the same host ports answer, through the afw-in-test-bot relay and
#     the gateway's inbound relay listener (the SYN reaches the gateway's ingress interface, the agent sees the
#     gateway as the peer), with the explicit host address kept; the relay cannot reach the agent directly;
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
INGRESS_PORT=15002
export AFW_IT_PORT_A="${AFW_IT_PORT_A:-18080}" AFW_IT_PORT_B="${AFW_IT_PORT_B:-18090}"
tmp="$(mktemp -d)"
brnf_enabled=0
dc() { docker compose -p "$PROJECT" --project-directory "$DIR" -f "$1" "${@:2}"; }
cleanup() {
  # Put the host back as found (the next tests of the job must not depend on this one).
  [ "$brnf_enabled" = 1 ] && host sysctl -qw net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1
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

# host <cmd>: runs in the host network namespace (iptables, br_netfilter), from a throwaway image.
host() { docker run --rm --privileged --net host -v /lib/modules:/lib/modules:ro afw-it-host:local "$@"; }

section "networks, images, original stack"
docker network rm "$NET_INTERNAL" "$NET_INGRESS" >/dev/null 2>&1 || true
check "internal network (internal: true)" docker network create --internal --subnet 10.99.0.0/24 "$NET_INTERNAL"
check "ingress network (internal: true)" docker network create --internal --subnet 10.98.0.0/24 "$NET_INGRESS"

section "Docker isolation of internal networks is enforced on this host"
check "build the host inspection image (iptables, kmod)" docker build -q -t afw-it-host:local - <<'DOCKERFILE'
FROM alpine:3.20
RUN apk add --no-cache iptables iptables-legacy kmod
DOCKERFILE
if [ "$(host cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null)" != 1 ]; then
  echo "  br_netfilter off: enabling it (bridged traffic then goes through iptables, as with Docker's defaults)"
  host sh -c 'modprobe br_netfilter 2>/dev/null; sysctl -qw net.bridge.bridge-nf-call-iptables=1' && brnf_enabled=1
fi
check "host: bridged traffic goes through iptables (br_netfilter)" \
  bash -c '[ "$(docker run --rm --net host afw-it-host:local cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = 1 ]'
br_in="br-$(docker network inspect -f '{{.Id}}' "$NET_INGRESS" | cut -c1-12)"
check "host: the ingress bridge drops packets addressed outside its subnet (! -d 10.98.0.0/24 -i $br_in -j DROP)" \
  bash -c 'docker run --rm --privileged --net host afw-it-host:local sh -c "iptables-save 2>/dev/null; iptables-legacy-save 2>/dev/null" |
    grep -E -- "! -d 10\.98\.0\.0/24 -i $1 (.* )?-j DROP"' _ "$br_in"
# An unconditional ACCEPT in DOCKER-USER (seen on some desktop runtimes) is evaluated before the isolation rules and
# disables them: every result below would then be meaningless (e.g. any container could reach the agents directly).
check "host: DOCKER-USER does not accept everything before Docker's isolation rules" \
  bash -c 'for c in FORWARD DOCKER-USER; do
      first=$(docker run --rm --privileged --net host afw-it-host:local iptables -S "$c" 2>/dev/null | grep -m1 -- "^-A ");
      echo "$c: $first"; [ "$first" != "-A $c -j ACCEPT" ] || exit 1;
    done'
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
  bash -c 'p=$(curl -s -m 5 "http://127.0.0.1:$1/" | sed -n "s/.* peer=//p"); echo "peer: $p"; [ "$p" = "$2" ]' _ "$AFW_IT_PORT_A" "$GW_IP"
check "port B keeps its explicit host address (127.0.0.1)" \
  bash -c '[ "$(docker compose -p "$1" --project-directory "$2" -f "$3" port "afw-in-$4" 9000)" = "127.0.0.1:$5" ]' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT" "$AFW_IT_PORT_B"
check "the namespace holder publishes nothing" \
  bash -c '[ "$(docker inspect -f "{{len .HostConfig.PortBindings}}" "$(docker compose -p "$1" --project-directory "$2" -f "$3" ps -q "afw-net-$4")")" = 0 ]' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT"
check "the SYN reaches the gateway's ingress interface (inbound relay listener counter)" \
  bash -c 'r=$(docker compose -p "$1" --project-directory "$2" -f "$3" exec -T gateway nft list chain inet afw input); echo "$r";
    grep -Eq "dport $4 counter packets [1-9]" <<<"$r"' _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$INGRESS_PORT"
check "the gateway routes nothing between the networks (no forward accept, no masquerade)" \
  bash -c 'r=$(docker compose -p "$1" --project-directory "$2" -f "$3" exec -T gateway nft list ruleset); echo "$r";
    ! grep -Eq "masquerade|ct state new accept" <<<"$r"' _ "$PROJECT" "$DIR" "$tmp/enrolled.yml"
check "the relay cannot reach the agent directly" \
  bash -c 'out=$(docker compose -p "$1" --project-directory "$2" -f "$3" exec -T "afw-in-$4" sh -c "printf \"GET / HTTP/1.0\r\n\r\n\" | timeout 6 socat - TCP4:$5:8080,connect-timeout=5; ip -4 route get $5" 2>&1);
    echo "$out"; ! grep -q hello-from-agent <<<"$out"' _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT" "$AGENT_IP"

section "no egress bypass"
check "agent: a single interface up besides lo" \
  bash -c '[ "$(docker compose -p "$1" --project-directory "$2" -f "$3" exec -T "$4" ip -o link show up | grep -cv ": lo[:@]")" = 1 ]' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT"
check "agent: only the default route and the /32 to the gateway" \
  bash -c 'r=$(docker compose -p "$1" --project-directory "$2" -f "$3" exec -T "$4" ip -4 route); echo "$r"; [ "$(grep -c . <<<"$r")" = 2 ] && grep -q "^default via $5 " <<<"$r" && grep -q "^$5 dev " <<<"$r"' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT" "$GW_IP"
# With br_netfilter, Docker's isolation of the internal network drops this packet before the gateway (its destination
# is outside the subnet): the transparent interception never sees it. Either way the agent gets nothing from upstream.
check "agent: proxy ignored, direct IP -> 403 from the gateway or dropped by the internal network" \
  agent sh -c "out=\$(curl -s -m 8 --noproxy '*' -w ' %{http_code}' http://198.18.99.20/); echo \"\$out\"; case \"\$out\" in *'blocked by agents-firewall'*403|' 000') exit 0;; *) exit 1;; esac"
check "agent: raw TCP to an arbitrary port is refused" \
  bash -c '! docker compose -p "$1" --project-directory "$2" -f "$3" exec -T "$4" sh -c "printf ping | nc -w 5 198.18.99.20 4444 | grep -q ping"' \
  _ "$PROJECT" "$DIR" "$tmp/enrolled.yml" "$AGENT"
check "agent: the ingress network is only reachable through the gateway" \
  agent sh -c "ip route get $GW_INGRESS_IP | grep -q 'via $GW_IP'"
for gw in "$GW_INGRESS_IP" "$GW_IP"; do
  check "agent: the inbound relay listener ($gw:$INGRESS_PORT) relays nothing for it" \
    agent sh -c "! printf 'CONNECT $AGENT_IP:9000 HTTP/1.0\\r\\n\\r\\n' | nc -w 5 $gw $INGRESS_PORT | grep -q ' 200 '"
done
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
