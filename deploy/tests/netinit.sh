#!/usr/bin/env bash
# Bypass tests for the afw-net "pause" container (ADR 0003):
#  1. it sets the default route of the shared namespace to the gateway;
#  2. it puts the route back if something removes it;
#  3. an agent sharing the namespace WITHOUT NET_ADMIN cannot change or delete the route;
#  4. on an internal network, the agent has no other way out (no route besides the gateway).
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

cleanup() {
  docker rm -f "$AGENT" "$NETNS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

section "build $IMAGE"
check "docker build deploy/docker/Dockerfile.netinit" \
  docker build -q -t "$IMAGE" -f deploy/docker/Dockerfile.netinit deploy/docker

section "netinit behaviour"
docker network create --internal --subnet "$SUBNET" "$NET" >/dev/null
docker run -d --name "$NETNS" --network "$NET" --ip "$PREFIX.10" --cap-add NET_ADMIN \
  -e AFW_GATEWAY_IP="$GW_IP" -e AFW_ROUTE_INTERVAL=2 "$IMAGE" >/dev/null || true
# The agent shares the namespace, without any capability on the network (default caps, no NET_ADMIN).
docker run -d --name "$AGENT" --network "container:$NETNS" alpine:3.20 sleep 600 >/dev/null || true

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
