#!/bin/sh
# afw-netinit: network "pause" container of an enrolled agent (docs/adr/0003-isolement-reseau.md).
# The agent shares this container's network namespace (network_mode: service:afw-net-<agent>) and has
# no NET_ADMIN; only this container may change routes. It points the default route to the gateway and
# puts it back every AFW_ROUTE_INTERVAL seconds (default 10). If the gateway is down, the route points to
# a silent address: the agent has no network at all (fail closed).
set -eu

log() { printf 'afw-netinit: %s\n' "$*" >&2; }

gw="${AFW_GATEWAY_IP:-}"
if [ -z "$gw" ]; then
  log "AFW_GATEWAY_IP is required (IP address of the gateway on the internal network)"
  exit 64
fi
# Strict validation: the value ends up in an `ip` command line.
if ! printf '%s' "$gw" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9A-Fa-f:]+$'; then
  log "invalid AFW_GATEWAY_IP: $gw"
  exit 64
fi
interval="${AFW_ROUTE_INTERVAL:-10}"
case "$interval" in '' | *[!0-9]*) log "invalid AFW_ROUTE_INTERVAL: $interval"; exit 64 ;; esac
[ "$interval" -ge 1 ] || interval=1

family=-4
case "$gw" in *:*) family=-6 ;; esac

# Optional: point the shared resolv.conf to the gateway DNS (default: the gateway itself).
dns="${AFW_DNS_IP:-$gw}"
if [ "${AFW_WRITE_RESOLV:-1}" = 1 ]; then
  if printf 'nameserver %s\noptions ndots:0\n' "$dns" > /etc/resolv.conf 2>/dev/null; then
    log "resolv.conf -> $dns"
  else
    log "resolv.conf is read-only, left unchanged"
  fi
fi

set_route() {
  defaults="$(ip "$family" route show default 2>/dev/null || true)"
  # Healthy: exactly one default route, via the gateway.
  if [ "$(printf '%s\n' "$defaults" | grep -c '^default')" = 1 ] &&
    printf '%s\n' "$defaults" | grep -q "^default via $gw "; then
    return 0
  fi
  while ip "$family" route del default 2>/dev/null; do :; done
  if ip "$family" route replace default via "$gw"; then
    log "default route -> $gw"
  else
    log "cannot set the default route via $gw (is NET_ADMIN granted?)"
  fi
}

trap 'log "stopping"; exit 0' TERM INT
log "gateway $gw, re-check every ${interval}s"
while :; do
  set_route
  sleep "$interval" &
  wait $! || true
done
