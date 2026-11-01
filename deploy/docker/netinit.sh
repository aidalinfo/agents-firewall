#!/bin/sh
# shellcheck disable=SC3013,SC2045,SC2086 # generated body (afw-enroll), run by busybox sh
# afw-netinit: network-namespace holder of an enrolled agent (ADR 0003, ADR 0023).
# The agent shares this container's network namespace (network_mode: service:afw-net-<agent>), without
# NET_ADMIN nor NET_RAW. The logic below is afw_enroll::netinit_script, the single source of truth, copied
# verbatim (checked by deploy/tests/enroll-sync.sh); only the addresses come from the environment:
#   AFW_GATEWAY_IP  gateway address on the internal network (IPv4)
#   AFW_AGENT_IP    fixed address of the agent (the holder's own address on the internal network)
# Every 10 s: other interfaces down, /32 route to the gateway then default route, every other route
# removed (no direct path to another agent), other address family flushed, CA bundle (system roots +
# gateway CA from /afw-ca-src/gateway.crt) rebuilt in /afw-ca; /tmp/afw-ready exists only while correct.
# afw-enroll writes the same script as the `command` of afw-net-<agent>; this file is the image default.
set -eu
valid_ipv4() { printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; }
for v in AFW_GATEWAY_IP AFW_AGENT_IP; do
  eval "val=\${$v:-}"
  if [ -z "$val" ]; then echo "afw-net: $v is required" >&2; exit 64; fi
  if ! valid_ipv4 "$val"; then echo "afw-net: invalid $v: $val" >&2; exit 64; fi
done
set +e
# --- BEGIN afw_enroll::netinit_script (generated, do not edit) ---
set -u
GW="$AFW_GATEWAY_IP"
ME="$AFW_AGENT_IP"
CA_SRC='/afw-ca-src/gateway.crt'
CA_DIR='/afw-ca'
READY='/tmp/afw-ready'
umask 022
log() { echo "afw-net: $*" >&2; }
build_ca() {
  [ -d "$CA_DIR" ] || return 0
  if [ ! -s "$CA_SRC" ]; then log "gateway CA missing at $CA_SRC"; return 1; fi
  if [ -s "$CA_DIR/bundle.pem" ] && [ ! "$CA_SRC" -nt "$CA_DIR/bundle.pem" ]; then return 0; fi
  cp "$CA_SRC" "$CA_DIR/gateway.crt.tmp" && mv "$CA_DIR/gateway.crt.tmp" "$CA_DIR/gateway.crt" || return 1
  { cat /etc/ssl/certs/ca-certificates.crt 2>/dev/null || log "no system CA bundle"; echo; cat "$CA_SRC"; } > "$CA_DIR/bundle.pem.tmp" \
    && mv "$CA_DIR/bundle.pem.tmp" "$CA_DIR/bundle.pem"
}
apply() {
  IFACE=$(ip -o addr show | awk -v me="$ME/" 'index($4, me) == 1 { sub(/@.*/, "", $2); print $2; exit }')
  if [ -z "$IFACE" ]; then log "no interface holds $ME"; return 1; fi
  for dev in $(ls /sys/class/net); do
    [ "$dev" = lo ] || [ "$dev" = "$IFACE" ] || ip link set dev "$dev" down 2>/dev/null || log "cannot set $dev down"
  done
  ip -4 route replace "$GW/32" dev "$IFACE" scope link || return 1
  ip -4 route replace default via "$GW" dev "$IFACE" || return 1
  ip -4 route show | while read -r dst rest; do
    case "$dst" in
      default) case "$rest" in "via $GW dev $IFACE"*) ;; *) ip -4 route del default $rest ;; esac ;;
      "$GW"|"$GW/32") ;;
      *) ip -4 route del "$dst" $rest 2>/dev/null || ip -4 route del "$dst" ;;
    esac
  done
  ip -6 route flush dev "$IFACE" 2>/dev/null
  [ "$(ip -4 route show | grep -vc -e '^default via '"$GW"' dev ' -e '^'"$GW"' ')" = 0 ] || return 1
  return 0
}
trap 'exit 0' TERM INT
while :; do
  build_ca || rm -f "$READY"
  if apply && { [ ! -d "$CA_DIR" ] || [ -s "$CA_DIR/bundle.pem" ]; }; then
    [ -f "$READY" ] || touch "$READY"
  else
    rm -f "$READY"
  fi
  sleep 10 & wait $!
done
# --- END afw_enroll::netinit_script ---
