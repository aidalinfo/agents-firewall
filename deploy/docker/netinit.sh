#!/bin/sh
# afw-netinit: network "pause" container of an enrolled agent (docs/adr/0003-isolement-reseau.md).
# The agent shares this container's network namespace (network_mode: service:afw-net-<agent>) and has
# no NET_ADMIN; only this container may change the network. Every AFW_ROUTE_INTERVAL seconds (default 10)
# it enforces:
#   - a single default route via the gateway, and a /32 route to the gateway as the only on-link route:
#     the route of the internal subnet is removed, so the agent cannot reach the other agents directly;
#   - every interface other than lo and the gateway's one is down (a network attached later included);
#   - no IPv6 on the gateway interface (no link-local path between agents);
#   - /afw-ca/bundle.pem (system roots + gateway inspection CA) and /afw-ca/gateway-ca.crt, rebuilt when
#     the CA exported by the gateway changes. The agent mounts /afw-ca read-only.
# If the gateway is down, the route points to a silent address: the agent has no network (fail closed).
# Kept in sync with afw-enroll's `netinit_script(spec)` (lot L11), the source of truth of this logic.
set -eu

log() { printf 'afw-netinit: %s\n' "$*" >&2; }

gw="${AFW_GATEWAY_IP:-}"
if [ -z "$gw" ]; then
  log "AFW_GATEWAY_IP is required (IP address of the gateway on the internal network)"
  exit 64
fi
# Strict validation: the value ends up in `ip` command lines.
if ! printf '%s' "$gw" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9A-Fa-f:]+$'; then
  log "invalid AFW_GATEWAY_IP: $gw"
  exit 64
fi
interval="${AFW_ROUTE_INTERVAL:-10}"
case "$interval" in '' | *[!0-9]*) log "invalid AFW_ROUTE_INTERVAL: $interval"; exit 64 ;; esac
[ "$interval" -ge 1 ] || interval=1
ca_src="${AFW_GATEWAY_CA_FILE:-/afw-gateway-ca/inspection-ca.crt}"
ca_dir="${AFW_CA_DIR:-/afw-ca}"
roots="${AFW_SYSTEM_ROOTS:-/etc/ssl/certs/ca-certificates.crt}"

family=-4; host_len=32
case "$gw" in *:*) family=-6; host_len=128 ;; esac

# Interface of the gateway, found once while the subnet route still exists.
dev="$(ip "$family" -o route get "$gw" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)"
if [ -z "$dev" ]; then
  log "no interface reaches the gateway $gw (is this container on the gateway's internal network?)"
  exit 65
fi

# Optional: point the shared resolv.conf to the gateway DNS (default: the gateway itself).
dns="${AFW_DNS_IP:-$gw}"
if [ "${AFW_WRITE_RESOLV:-1}" = 1 ]; then
  if printf 'nameserver %s\noptions ndots:0\n' "$dns" > /etc/resolv.conf 2>/dev/null; then
    log "resolv.conf -> $dns"
  else
    log "resolv.conf is read-only, left unchanged"
  fi
fi

enforce_links() {
  ip -o link show | sed -n 's/^[0-9]*: \([^:@]*\)[:@].*/\1/p' | while read -r l; do
    [ "$l" = lo ] || [ "$l" = "$dev" ] && continue
    if ip -o link show dev "$l" | grep -q '[<,]UP[,>]'; then
      ip link set dev "$l" down && log "interface $l down (only $dev may be used)"
    fi
  done
  if [ "$family" = -4 ]; then
    # Best effort: IPv6 link-local would be a direct path between agents.
    ip -6 addr flush dev "$dev" 2>/dev/null || true
    ip -6 route flush dev "$dev" 2>/dev/null || true
  fi
}

enforce_routes() {
  # On-link route to the gateway only (added before the subnet route is removed).
  if ! ip "$family" route show dev "$dev" | grep -q "^$gw "; then
    ip "$family" route replace "$gw/$host_len" dev "$dev" scope link && log "route $gw/$host_len dev $dev"
  fi
  ip "$family" route show dev "$dev" scope link | while read -r prefix _; do
    [ "$prefix" = "$gw" ] && continue
    ip "$family" route del "$prefix" dev "$dev" scope link 2>/dev/null && log "route $prefix removed (no direct path to the subnet)"
  done
  defaults="$(ip "$family" route show default 2>/dev/null || true)"
  if [ "$(printf '%s\n' "$defaults" | grep -c '^default')" = 1 ] &&
    printf '%s\n' "$defaults" | grep -q "^default via $gw "; then
    return 0
  fi
  while ip "$family" route del default 2>/dev/null; do :; done
  if ip "$family" route replace default via "$gw" dev "$dev"; then
    log "default route -> $gw"
  else
    log "cannot set the default route via $gw (is NET_ADMIN granted?)"
  fi
}

enforce_ca() {
  [ -d "$ca_dir" ] && [ -s "$ca_src" ] || return 0
  grep -q 'BEGIN CERTIFICATE' "$ca_src" || { log "$ca_src is not a PEM certificate"; return 0; }
  if [ -s "$ca_dir/bundle.pem" ] && cmp -s "$ca_src" "$ca_dir/gateway-ca.crt"; then return 0; fi
  { cat "$roots" 2>/dev/null || true; printf '\n'; cat "$ca_src"; } > "$ca_dir/bundle.pem.tmp"
  cp "$ca_src" "$ca_dir/gateway-ca.crt.tmp"
  chmod 0644 "$ca_dir/bundle.pem.tmp" "$ca_dir/gateway-ca.crt.tmp"
  mv "$ca_dir/gateway-ca.crt.tmp" "$ca_dir/gateway-ca.crt"
  mv "$ca_dir/bundle.pem.tmp" "$ca_dir/bundle.pem"
  log "CA bundle updated in $ca_dir (system roots + gateway CA)"
}

trap 'log "stopping"; exit 0' TERM INT
log "gateway $gw on $dev, re-check every ${interval}s"
while :; do
  enforce_links
  enforce_routes
  enforce_ca
  sleep "$interval" &
  wait $! || true
done
