#!/usr/bin/env bash
# Bypass tests for the afw-net "pause" container (ADR 0003):
#  1. it sets the default route of the shared namespace to the gateway;
#  2. it puts the route back if something removes it;
#  3. an agent sharing the namespace WITHOUT NET_ADMIN cannot change or delete the route;
#  4. no direct path to the other hosts of the internal subnet (other agents): only a /32 route to the gateway;
#  5. any interface other than lo and the gateway's is brought down (a later `docker network connect` too);
#  6. it builds /afw-ca/bundle.pem (system roots + gateway CA) and /afw-ca/gateway-ca.crt for the agent.
# shellcheck source=deploy/tests/common.sh
. "$(dirname "$0")/common.sh"
cd "$ROOT"

IMAGE="${NETINIT_IMAGE:-afw-netinit:local}"
NET="afw-test-netinit-$$"
SUBNET="10.199.$((RANDOM % 200 + 1)).0/24"
PREFIX="${SUBNET%.0/24}"
GW_IP="$PREFIX.2"
NETNS="afw-test-net-$$"
AGENT="afw-test-agent-$$"
PEER="afw-test-peer-$$"
NET2="afw-test-netinit2-$$"
CAVOL="afw-test-ca-$$"
SRCVOL="afw-test-gwca-$$"

cleanup() {
  docker rm -f "$AGENT" "$NETNS" "$PEER" >/dev/null 2>&1 || true
  docker network rm "$NET" "$NET2" >/dev/null 2>&1 || true
  docker volume rm "$CAVOL" "$SRCVOL" >/dev/null 2>&1 || true
}
trap cleanup EXIT

section "build $IMAGE"
check "docker build deploy/docker/Dockerfile.netinit" \
  docker build -q -t "$IMAGE" -f deploy/docker/Dockerfile.netinit deploy/docker

section "netinit behaviour"
docker network create --internal --subnet "$SUBNET" "$NET" >/dev/null
docker network create --internal "$NET2" >/dev/null
# A fake gateway CA certificate, as exported by the gateway in its public volume.
docker volume create "$SRCVOL" >/dev/null
docker run --rm -v "$SRCVOL":/src alpine:3.20 sh -c 'apk add -q --no-cache openssl >/dev/null &&
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /dev/null \
  -subj "/CN=afw test gateway CA" -days 2 -out /src/inspection-ca.crt 2>/dev/null' >/dev/null
# A peer on the same internal subnet (another agent), listening on TCP 7777.
docker run -d --name "$PEER" --network "$NET" --ip "$PREFIX.20" alpine:3.20 sh -c 'while :; do nc -l -p 7777 -e echo hi; done' >/dev/null
docker run -d --name "$NETNS" --network "$NET" --ip "$PREFIX.10" --cap-drop ALL --cap-add NET_ADMIN \
  -e AFW_GATEWAY_IP="$GW_IP" -e AFW_ROUTE_INTERVAL=2 \
  -v "$SRCVOL":/afw-gateway-ca:ro -v "$CAVOL":/afw-ca "$IMAGE" >/dev/null || true
# The agent shares the namespace, without any capability on the network (no NET_ADMIN, no NET_RAW).
docker run -d --name "$AGENT" --network "container:$NETNS" --cap-drop NET_RAW -v "$CAVOL":/afw-ca:ro \
  alpine:3.20 sleep 600 >/dev/null || true

# denied <cmd...>: the command must run in the agent and fail with EPERM (not just fail).
denied() {
  local out
  if out="$(docker exec "$AGENT" "$@" 2>&1)"; then echo "allowed: $*"; return 1; fi
  printf '%s' "$out" | grep -qi 'not permitted' || { echo "unexpected error: $out"; return 1; }
}
route_is_gw() { docker exec "$AGENT" ip route 2>/dev/null | grep -q "^default via $GW_IP "; }
wait_route() { for _ in $(seq 1 "$1"); do route_is_gw && return 0; sleep 1; done; return 1; }

check "default route points to the gateway ($GW_IP)" wait_route 10
check "agent container is running in the shared namespace" \
  bash -c '[ "$(docker inspect -f "{{.State.Running}}" "$1")" = true ]' _ "$AGENT"
check "agent cannot delete the default route (no NET_ADMIN)" denied ip route del default
check "agent cannot replace the default route" denied ip route replace default via "$PREFIX.66"
check "agent cannot add a more specific route around the gateway" denied ip route add 0.0.0.0/1 via "$PREFIX.66"
check "agent cannot change its address" denied ip addr add "$PREFIX.77/24" dev eth0
check "agent cannot bring its interface down" denied ip link set eth0 down
check "only one default route, via the gateway" \
  bash -c '[ "$(docker exec "$1" ip route | grep -c "^default")" = 1 ]' _ "$AGENT"
check "only a /32 route to the gateway, no route to the internal subnet" \
  bash -c 'r=$(docker exec "$1" ip route); grep -q "^$2 dev " <<<"$r" && ! grep -q "^$3/24 " <<<"$r"' _ "$AGENT" "$GW_IP" "${SUBNET%/24}"
check "peer reachable from a plain container (control)" \
  docker run --rm --network "$NET" alpine:3.20 sh -c "nc -w 3 $PREFIX.20 7777 </dev/null | grep -q hi"
check "agent cannot reach another host of the subnet directly (no gateway there => nothing)" \
  bash -c '! docker exec "$1" sh -c "nc -w 3 $2 7777 </dev/null | grep -q hi"' _ "$AGENT" "$PREFIX.20"
check "no IPv6 address on the gateway interface (no link-local path between agents)" \
  bash -c '[ -z "$(docker exec "$1" ip -6 addr show dev eth0)" ]' _ "$AGENT"
check "the path to another agent goes through the gateway" \
  bash -c 'docker exec "$1" ip route get "$2" | grep -q "via $3"' _ "$AGENT" "$PREFIX.20" "$GW_IP"
check "CA bundle built (system roots + gateway CA) and gateway CA alone" \
  bash -c 'for _ in $(seq 1 10); do docker exec "$1" sh -c "test -s /afw-ca/bundle.pem && test -s /afw-ca/gateway-ca.crt" && break; sleep 1; done
    n=$(docker exec "$1" grep -c "BEGIN CERTIFICATE" /afw-ca/bundle.pem); [ "$n" -gt 50 ] &&
    docker exec "$1" sh -c "grep -qF \"\$(sed -n 2p /afw-ca/gateway-ca.crt)\" /afw-ca/bundle.pem"' _ "$AGENT"
check "agent cannot write the CA bundle" \
  bash -c '! docker exec "$1" sh -c "echo x >> /afw-ca/bundle.pem" 2>/dev/null' _ "$AGENT"
check "netinit is healthy once the bundle exists" \
  bash -c 'for _ in $(seq 1 20); do [ "$(docker inspect -f "{{.State.Health.Status}}" "$1")" = healthy ] && exit 0; sleep 1; done; exit 1' _ "$NETNS"
# A second network attached later: its interface must be brought down (no way around the gateway).
docker network connect "$NET2" "$NETNS" >/dev/null 2>&1 || true
check "an extra interface is brought down by netinit" \
  bash -c 'for _ in $(seq 1 8); do n=$(docker exec "$1" sh -c "ip -o link show up | grep -v -E \": (lo|eth0)[:@]\" | wc -l"); [ "$n" = 0 ] && exit 0; sleep 1; done; docker exec "$1" ip -o link; exit 1' _ "$AGENT"
check "still a single default route via the gateway after the extra network" \
  bash -c '[ "$(docker exec "$1" ip route | grep -c "^default")" = 1 ] && docker exec "$1" ip route | grep -q "^default via $2 "' _ "$AGENT" "$GW_IP"
# Simulate tampering from a privileged process: remove the route from the afw-net container itself.
docker exec "$NETNS" ip route del default >/dev/null 2>&1 || true
check "route is restored by netinit after removal" wait_route 8
check "netinit stops quickly on SIGTERM (< 5 s)" \
  bash -c '[ "$(docker inspect -f "{{.State.Running}}" "$1")" = true ] || exit 1; s=$(date +%s); docker stop -t 10 "$1" >/dev/null; [ $(( $(date +%s) - s )) -lt 5 ]' _ "$NETNS"
check "netinit refuses to start without AFW_GATEWAY_IP" \
  bash -c 'out=$(docker run --rm --cap-add NET_ADMIN --network none "$1" 2>&1) && exit 1; grep -q AFW_GATEWAY_IP <<<"$out"' _ "$IMAGE"
check "netinit refuses an invalid AFW_GATEWAY_IP" \
  bash -c 'out=$(docker run --rm --cap-add NET_ADMIN --network none -e "AFW_GATEWAY_IP=1.2.3.4;id" "$1" 2>&1) && exit 1; grep -q "invalid" <<<"$out"' _ "$IMAGE"

finish
