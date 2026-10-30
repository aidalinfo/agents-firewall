//! Script of the `afw-net-<agent>` network-namespace holder: the single source of truth, also
//! used by the netinit image of the deployment (`deploy/docker/netinit.sh`).

use std::net::IpAddr;

use crate::spec::EnrollSpec;

/// Gateway CA mounted read-only in the holder.
pub const HOLDER_CA_SRC: &str = "/afw-ca-src/gateway.crt";
/// Directory (volume `afw-ca-<agent>`) where the holder writes `gateway.crt` and `bundle.pem`.
pub const HOLDER_CA_DIR: &str = "/afw-ca";
/// File created by the holder once the routes are in place (healthcheck).
pub const READY_FILE: &str = "/tmp/afw-ready";

/// POSIX `sh` script run by the holder (needs `ip` from iproute2 or busybox, `awk`, and the
/// system CA bundle at `/etc/ssl/certs/ca-certificates.crt`).
///
/// Every 10 s, without any window where the default route is missing:
/// 1. finds the interface holding the agent address, sets every other interface but `lo` down
///    (a network attached later, e.g. by Coolify, is cut);
/// 2. `ip route replace <gw>/32 dev <iface>` then `ip route replace default via <gw>`;
/// 3. deletes every other route, in particular the internal subnet route: an agent cannot
///    reach another agent directly, everything goes through the gateway;
/// 4. flushes the routes of the other address family;
/// 5. (re)builds `bundle.pem` (system roots + gateway CA) and `gateway.crt` in [`HOLDER_CA_DIR`].
///
/// [`READY_FILE`] exists only while the routes are correct. Before the first pass the internal
/// network has no default route at all (fail closed).
pub fn netinit_script(spec: &EnrollSpec) -> String {
    script(spec.gateway_ip, spec.agent_ip)
}

pub(crate) fn script(gateway_ip: IpAddr, agent_ip: IpAddr) -> String {
    let (fam, other, host) = if gateway_ip.is_ipv4() {
        ("-4", "-6", "32")
    } else {
        ("-6", "-4", "128")
    };
    format!(
        r#"set -u
GW='{gateway_ip}'
ME='{agent_ip}'
CA_SRC='{HOLDER_CA_SRC}'
CA_DIR='{HOLDER_CA_DIR}'
READY='{READY_FILE}'
umask 022
log() {{ echo "afw-net: $*" >&2; }}
build_ca() {{
  [ -d "$CA_DIR" ] || return 0
  if [ ! -s "$CA_SRC" ]; then log "gateway CA missing at $CA_SRC"; return 1; fi
  if [ -s "$CA_DIR/bundle.pem" ] && [ ! "$CA_SRC" -nt "$CA_DIR/bundle.pem" ]; then return 0; fi
  cp "$CA_SRC" "$CA_DIR/gateway.crt.tmp" && mv "$CA_DIR/gateway.crt.tmp" "$CA_DIR/gateway.crt" || return 1
  {{ cat /etc/ssl/certs/ca-certificates.crt 2>/dev/null || log "no system CA bundle"; echo; cat "$CA_SRC"; }} > "$CA_DIR/bundle.pem.tmp" \
    && mv "$CA_DIR/bundle.pem.tmp" "$CA_DIR/bundle.pem"
}}
apply() {{
  IFACE=$(ip -o addr show | awk -v me="$ME/" 'index($4, me) == 1 {{ sub(/@.*/, "", $2); print $2; exit }}')
  if [ -z "$IFACE" ]; then log "no interface holds $ME"; return 1; fi
  for dev in $(ls /sys/class/net); do
    [ "$dev" = lo ] || [ "$dev" = "$IFACE" ] || ip link set dev "$dev" down 2>/dev/null || log "cannot set $dev down"
  done
  ip {fam} route replace "$GW/{host}" dev "$IFACE" scope link || return 1
  ip {fam} route replace default via "$GW" dev "$IFACE" || return 1
  ip {fam} route show | while read -r dst rest; do
    case "$dst" in
      default) case "$rest" in "via $GW dev $IFACE"*) ;; *) ip {fam} route del default $rest ;; esac ;;
      "$GW"|"$GW/{host}") ;;
      *) ip {fam} route del "$dst" $rest 2>/dev/null || ip {fam} route del "$dst" ;;
    esac
  done
  ip {other} route flush dev "$IFACE" 2>/dev/null
  [ "$(ip {fam} route show | grep -vc -e '^default via '"$GW"' dev ' -e '^'"$GW"' ')" = 0 ] || return 1
  return 0
}}
trap 'exit 0' TERM INT
while :; do
  build_ca || rm -f "$READY"
  if apply && {{ [ ! -d "$CA_DIR" ] || [ -s "$CA_DIR/bundle.pem" ]; }}; then
    [ -f "$READY" ] || touch "$READY"
  else
    rm -f "$READY"
  fi
  sleep 10 & wait $!
done
"#
    )
}

/// Script of the Kubernetes init container building the CA bundle in an `emptyDir`.
pub(crate) fn k8s_bundle_script(src: &str, dir: &str) -> String {
    format!(
        "set -eu; umask 022; cp '{src}' '{dir}/gateway.crt'; \
         {{ cat /etc/ssl/certs/ca-certificates.crt 2>/dev/null || echo 'afw: no system CA bundle' >&2; echo; cat '{src}'; }} > '{dir}/bundle.pem'"
    )
}
