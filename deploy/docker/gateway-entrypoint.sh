#!/bin/sh
# afw-gateway entrypoint (ADR 0003): forwarding, ICMP redirects off, nftables interception, then
# exec the gateway. AFW_INTERCEPT=proxy-dns (Kubernetes) skips nftables: the NetworkPolicy isolates.
#
# Internal side: AFW_INTERNAL_IFACE, or the interface(s) holding the AFW_INTERNAL_SUBNETS (comma
# separated CIDRs). From there:
#   - TCP to the gateway's own proxy and DNS ports (3128, 53) is accepted as is; health and
#     metrics (9090) are NOT reachable from the agents (the public CA is served on
#     http://<gateway>:3128/ca.crt);
#   - every other TCP connection is redirected to the transparent listener (:15001);
#   - UDP 53 (any resolver, e.g. dig @8.8.8.8) is redirected to the gateway DNS;
#   - nothing is forwarded (chain forward policy drop): agents only get what the gateway relays.
# Any failure here stops the container: never run without interception (fail closed).
set -eu

log() { echo "gateway-entrypoint: $*" >&2; }

mode="${AFW_INTERCEPT:-transparent}"
if [ "$mode" != "transparent" ]; then
  log "intercept mode $mode: no nftables rules"
  exec /usr/local/bin/afw-gateway "$@"
fi

tport="${AFW_TRANSPARENT_PORT:-15001}"
pport="${AFW_PROXY_PORT:-3128}"
dport="${AFW_DNS_PORT:-53}"
hport="${AFW_HEALTH_PORT:-9090}"
for p in "$tport" "$pport" "$dport" "$hport"; do
  case "$p" in '' | *[!0-9]*) log "invalid port: $p"; exit 64 ;; esac
done

ifaces="${AFW_INTERNAL_IFACE:-}"
if [ -z "$ifaces" ]; then
  if [ -z "${AFW_INTERNAL_SUBNETS:-}" ]; then
    log "set AFW_INTERNAL_IFACE or AFW_INTERNAL_SUBNETS (or AFW_INTERCEPT=proxy-dns)"
    exit 64
  fi
  for net in $(printf '%s' "$AFW_INTERNAL_SUBNETS" | tr ',' ' '); do
    if ! printf '%s' "$net" | grep -Eq '^[0-9a-fA-F:.]+/[0-9]{1,3}$'; then
      log "invalid subnet: $net"
      exit 64
    fi
    dev="$(ip -o route show "$net" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)"
    if [ -z "$dev" ]; then
      log "no interface holds $net"
      exit 65
    fi
    ifaces="$ifaces $dev"
  done
fi
ifaces="$(printf '%s' "$ifaces" | tr ',' ' ' | xargs -n1 | sort -u | xargs)"
for i in $ifaces; do
  if ! printf '%s' "$i" | grep -Eq '^[A-Za-z0-9_.@-]{1,15}$'; then
    log "invalid interface name: $i"
    exit 64
  fi
done
set_list=""
for i in $ifaces; do set_list="$set_list\"$i\", "; done
set_list="{ ${set_list%, } }"

# Forwarding (also set by the compose sysctls) and no ICMP redirects towards agents: a redirect
# would tell an agent about a direct path to another agent.
sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 1 ]; then
  log "net.ipv4.ip_forward is not 1 (add sysctls: net.ipv4.ip_forward=1)"
  exit 65
fi
# (/proc/sys may be read-only in a container: the nftables output rule below drops redirects anyway.)
sysctl -qw net.ipv4.conf.all.send_redirects=0 2>/dev/null || log "send_redirects (all) not writable: relying on nftables"
for i in $ifaces; do
  sysctl -qw "net.ipv4.conf.$i.send_redirects=0" 2>/dev/null || log "send_redirects ($i) not writable: relying on nftables"
done

nft -f - <<NFT
table inet afw
delete table inet afw
table inet afw {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname $set_list fib daddr type local tcp dport { $pport, $dport } accept
    iifname $set_list udp dport 53 redirect to :$dport
    iifname $set_list meta l4proto tcp redirect to :$tport
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
  }
  chain output {
    type filter hook output priority filter; policy accept;
    oifname $set_list icmp type redirect drop
    oifname $set_list icmpv6 type nd-redirect drop
  }
  chain input {
    type filter hook input priority filter; policy accept;
    iifname $set_list meta l4proto udp udp dport != $dport drop
    iifname $set_list tcp dport $hport drop
  }
}
NFT
log "interception active on: $ifaces (tcp -> :$tport, udp/53 -> :$dport, forward drop)"
exec /usr/local/bin/afw-gateway "$@"
