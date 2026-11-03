//! Inbound path of an enrolled agent that publishes ports (issues #22 and #24).
//!
//! The agent shares the namespace of `afw-net-<agent>`, which sits on the `internal` gateway
//! network only: Docker keeps `ports` there in the container metadata but creates no listener.
//! Adding a second network to that namespace is not an option (netinit sets it down, and kept up
//! it would be a way around the gateway). Instead, a separate `afw-in-<agent>` relay publishes the
//! original `ports` verbatim and forwards each container port to the agent **through the
//! gateway**: it asks the gateway's inbound relay listener, on the ingress network, for
//! `CONNECT <agent>:<port>`, and the gateway opens the connection from its internal address. Every
//! hop stays inside its own subnet, so Docker's isolation rules for `internal` networks (which
//! drop any bridged packet whose source or destination is outside the network's subnet) let it
//! through, and nothing is routed between the two networks (issue #24). The agent sees the gateway
//! as the peer and keeps one interface and two routes; stopping the gateway cuts the inbound path
//! as well.

use std::net::IpAddr;

use serde_yaml::Value;

use crate::error::EnrollError;

/// File created by the relay once its route and listeners are in place (healthcheck).
pub const INGRESS_READY_FILE: &str = "/tmp/afw-ready";

/// Port of the gateway's inbound relay listener (`AFW_INGRESS_PORT` of the gateway entrypoint).
pub const INGRESS_RELAY_PORT: u16 = 15002;

/// Maximum number of relayed ports per agent (one `socat` listener each).
pub const MAX_INGRESS_PORTS: usize = 64;

/// Container (target) ports of a compose `ports` value, sorted and deduplicated.
///
/// Short syntax `[[IP:]HOST:]CONTAINER[-END][/PROTO]` and long syntax (`target`, `protocol`) are
/// supported. Only TCP can be relayed: UDP, a non-literal container port (interpolation) or more
/// than [`MAX_INGRESS_PORTS`] ports are refused rather than silently dropped.
pub(crate) fn container_ports(service: &str, ports: &Value) -> Result<Vec<u16>, EnrollError> {
    let unsupported = |why: String| {
        EnrollError::Unsupported(format!(
            "service `{service}` publishes {why}: the inbound relay only forwards TCP to literal container ports"
        ))
    };
    let Value::Sequence(entries) = ports else {
        return Err(unsupported("`ports` that is not a list".into()));
    };
    let mut out = Vec::new();
    for entry in entries {
        let (target, proto) = match entry {
            Value::Number(n) => (n.to_string(), "tcp".to_string()),
            Value::String(s) => {
                let (spec, proto) = s.rsplit_once('/').unwrap_or((s.as_str(), "tcp"));
                let target = spec.rsplit(':').next().unwrap_or(spec);
                (target.to_string(), proto.to_string())
            }
            Value::Mapping(m) => {
                let target = match m.get("target") {
                    Some(Value::Number(n)) => n.to_string(),
                    Some(Value::String(s)) => s.clone(),
                    _ => return Err(unsupported("a long-syntax port without `target`".into())),
                };
                let proto = m
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("tcp")
                    .to_string();
                (target, proto)
            }
            other => return Err(unsupported(format!("an unreadable port entry `{other:?}`"))),
        };
        if !proto.eq_ignore_ascii_case("tcp") {
            return Err(unsupported(format!("`{target}/{proto}`")));
        }
        let (start, end) = target
            .split_once('-')
            .unwrap_or((target.as_str(), target.as_str()));
        let parse = |p: &str| p.trim().parse::<u16>().ok().filter(|&p| p > 0);
        let (Some(start), Some(end)) = (parse(start), parse(end)) else {
            return Err(unsupported(format!("container port `{target}`")));
        };
        if start > end || usize::from(end - start) >= MAX_INGRESS_PORTS {
            return Err(unsupported(format!("the port range `{target}`")));
        }
        out.extend(start..=end);
    }
    out.sort_unstable();
    out.dedup();
    if out.len() > MAX_INGRESS_PORTS {
        return Err(unsupported(format!(
            "{} ports (at most {MAX_INGRESS_PORTS})",
            out.len()
        )));
    }
    Ok(out)
}

/// POSIX `sh` script of the `afw-in-<agent>` relay (needs `socat`).
///
/// 1. one `socat` listener per container port, each connection relayed by the gateway's inbound
///    relay listener (`CONNECT <agent>:<port>` to `<gateway ingress address>:`
///    [`INGRESS_RELAY_PORT`]): the relay never reaches the agent directly (it is not on the
///    internal network and has no route to it);
/// 2. every 10 s: listeners checked (one exits → the container exits and Docker restarts it).
///    [`INGRESS_READY_FILE`] exists only while the listeners are up.
pub(crate) fn ingress_script(gateway_ip: IpAddr, agent_ip: IpAddr, ports: &[u16]) -> String {
    let bracket = |ip: IpAddr| match ip {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => format!("[{a}]"),
    };
    let (gw, target) = (bracket(gateway_ip), bracket(agent_ip));
    let ports = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"set -u
GW='{gateway_ip}'
AGENT='{agent_ip}'
PORTS='{ports}'
READY='{INGRESS_READY_FILE}'
PIDS=''
log() {{ echo "afw-in: $*" >&2; }}
trap 'kill $PIDS 2>/dev/null; exit 0' TERM INT
rm -f "$READY"
for p in $PORTS; do
  socat TCP-LISTEN:"$p",fork,reuseaddr PROXY:{gw}:{target}:"$p",proxyport={INGRESS_RELAY_PORT} &
  PIDS="$PIDS $!"
done
touch "$READY"
log "relaying $PORTS to $AGENT through the gateway $GW"
while :; do
  sleep 10 & wait $!
  for pid in $PIDS; do
    if ! kill -0 "$pid" 2>/dev/null; then log "a listener exited"; kill $PIDS 2>/dev/null; exit 1; fi
  done
done
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports(y: &str) -> Result<Vec<u16>, EnrollError> {
        container_ports("bot", &serde_yaml::from_str(y).unwrap())
    }

    #[test]
    fn short_and_long_syntax() {
        assert_eq!(
            ports(r#"["8080:80", "127.0.0.1:9000:9000/tcp", "[::1]:7000:7001", 3000, "5000-5002:6000-6002", "${P}:4000"]"#).unwrap(),
            vec![80, 3000, 4000, 6000, 6001, 6002, 7001, 9000]
        );
        assert_eq!(
            ports("[{target: 80, published: '8080', host_ip: 127.0.0.1}, {target: '81', protocol: TCP}, '80']").unwrap(),
            vec![80, 81]
        );
    }

    #[test]
    fn udp_interpolated_target_and_huge_ranges_are_refused() {
        for y in [
            r#"["53:53/udp"]"#,
            "[{target: 53, protocol: udp}]",
            r#"["8080:${PORT}"]"#,
            r#"["1-65535"]"#,
            r#"["90-80"]"#,
            r#"["0"]"#,
            "[{published: 80}]",
            "'8080:80'",
        ] {
            assert!(
                matches!(ports(y), Err(EnrollError::Unsupported(_))),
                "{y} accepted"
            );
        }
    }

    #[test]
    fn script_reaches_the_agent_through_the_gateway_listener_only() {
        let s = ingress_script(
            "10.78.0.2".parse().unwrap(),
            "10.77.0.21".parse().unwrap(),
            &[80, 9000],
        );
        assert!(s.contains("PORTS='80 9000'"));
        assert!(s.contains(r#"PROXY:10.78.0.2:10.77.0.21:"$p",proxyport=15002"#));
        // No route towards the agent: the relay only talks to the gateway's ingress address.
        assert!(!s.contains("route"), "{s}");
        assert!(!s.contains("TCP4:") && !s.contains("TCP6:"), "{s}");
        let s6 = ingress_script(
            "fd00:78::2".parse().unwrap(),
            "fd00:77::21".parse().unwrap(),
            &[80],
        );
        assert!(s6.contains(r#"PROXY:[fd00:78::2]:[fd00:77::21]:"$p",proxyport=15002"#));
        let status = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&s)
            .status()
            .expect("sh");
        assert!(status.success(), "sh -n failed");
    }
}
