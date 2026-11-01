//! Inbound path of an enrolled agent that publishes ports (issue #22).
//!
//! The agent shares the namespace of `afw-net-<agent>`, which sits on the `internal` gateway
//! network only: Docker keeps `ports` there in the container metadata but creates no listener.
//! Adding a second network to that namespace is not an option (netinit sets it down, and kept up
//! it would be a way around the gateway). Instead, a separate `afw-in-<agent>` relay publishes the
//! original `ports` verbatim and forwards each container port to the agent **through the
//! gateway**: its only route to the agent goes via the gateway's ingress network; the gateway
//! forwards ingress → internal (TCP, new connections in that direction only) and masquerades, so
//! the agent sees the gateway as the peer and answers through its single route. The agent keeps
//! one interface and two routes; stopping the gateway cuts the inbound path as well.

use std::net::IpAddr;

use serde_yaml::Value;

use crate::error::EnrollError;

/// File created by the relay once its route and listeners are in place (healthcheck).
pub const INGRESS_READY_FILE: &str = "/tmp/afw-ready";

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

/// POSIX `sh` script of the `afw-in-<agent>` relay (needs `ip` and `socat`).
///
/// 1. `ip route replace <agent>/32 via <gateway ingress address>`: the agent is only reached
///    through the gateway (never directly over the internal network, the relay is not on it);
/// 2. one `socat` listener per container port, forwarding to the same port of the agent;
/// 3. every 10 s: route put back, listeners checked (one exits → the container exits and Docker
///    restarts it). [`INGRESS_READY_FILE`] exists only while the route and listeners are up.
pub(crate) fn ingress_script(gateway_ip: IpAddr, agent_ip: IpAddr, ports: &[u16]) -> String {
    let (fam, host, connect, target) = match agent_ip {
        IpAddr::V4(a) => ("-4", "32", "TCP4", a.to_string()),
        IpAddr::V6(a) => ("-6", "128", "TCP6", format!("[{a}]")),
    };
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
route() {{ ip {fam} route replace "$AGENT/{host}" via "$GW"; }}
trap 'kill $PIDS 2>/dev/null; exit 0' TERM INT
rm -f "$READY"
until route; do log "no route to $AGENT via $GW yet"; sleep 2 & wait $!; done
for p in $PORTS; do
  socat TCP-LISTEN:"$p",fork,reuseaddr {connect}:{target}:"$p" &
  PIDS="$PIDS $!"
done
touch "$READY"
while :; do
  sleep 10 & wait $!
  if ! route; then log "cannot route $AGENT via $GW"; rm -f "$READY"; continue; fi
  for pid in $PIDS; do
    if ! kill -0 "$pid" 2>/dev/null; then log "a listener exited"; kill $PIDS 2>/dev/null; exit 1; fi
  done
  [ -f "$READY" ] || touch "$READY"
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
    fn script_routes_through_the_gateway_only() {
        let s = ingress_script(
            "10.78.0.2".parse().unwrap(),
            "10.77.0.21".parse().unwrap(),
            &[80, 9000],
        );
        assert!(s.contains(r#"ip -4 route replace "$AGENT/32" via "$GW""#));
        assert!(s.contains("PORTS='80 9000'"));
        assert!(s.contains(r#"TCP4:10.77.0.21:"$p""#));
        let s6 = ingress_script(
            "fd00:78::2".parse().unwrap(),
            "fd00:77::21".parse().unwrap(),
            &[80],
        );
        assert!(s6.contains(r#"ip -6 route replace "$AGENT/128" via "$GW""#));
        assert!(s6.contains(r#"TCP6:[fd00:77::21]:"$p""#));
        let status = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&s)
            .status()
            .expect("sh");
        assert!(status.success(), "sh -n failed");
    }
}
