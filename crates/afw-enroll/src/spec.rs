//! Input and output types shared by every enrollment target.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::EnrollError;

/// Default image of the network-namespace holder container (`afw-net-<agent>`).
pub const DEFAULT_NETINIT_IMAGE: &str = "afw-netinit:local";

/// Directory mounted read-only in the agent: `gateway.crt` (gateway CA alone, picked up by
/// `update-ca-certificates`) and `bundle.pem` (system roots + gateway CA).
pub const CA_DIR: &str = "/usr/local/share/ca-certificates/afw";
/// Full bundle (system roots + gateway CA): `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`.
pub const CA_BUNDLE_PATH: &str = "/usr/local/share/ca-certificates/afw/bundle.pem";
/// Gateway CA alone: `NODE_EXTRA_CA_CERTS` (added to Node's own roots).
pub const CA_CERT_PATH: &str = "/usr/local/share/ca-certificates/afw/gateway.crt";

/// Default directory of the Hermes plugin inside a Hermes container
/// (`$HERMES_HOME/plugins/<name>`, `HERMES_HOME=/opt/data` in the Hermes images).
pub const DEFAULT_HERMES_PLUGIN_DIR: &str = "/opt/data/plugins/agents-firewall";

/// Hosts that must never be sent to the proxy.
pub const NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// Label put on every enrolled workload.
pub const LABEL_ENROLLED: &str = "afw.enrolled";
/// Label carrying the agent name.
pub const LABEL_AGENT: &str = "afw.agent";

/// Everything needed to enroll one container agent behind a Docker gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollSpec {
    /// Agent name (`[a-z0-9][a-z0-9_.-]*`, at most 63 characters).
    pub agent_name: String,
    /// Name of the compose service running the agent.
    pub service: String,
    /// Gateway address on the internal network (default route and DNS of the agent).
    pub gateway_ip: IpAddr,
    /// Fixed address of the agent on the internal network (its identity, ADR 0003).
    pub agent_ip: IpAddr,
    /// Internal (`internal: true`) network of the gateway, declared `external` in the agent compose.
    pub network: String,
    /// Explicit proxy URL, e.g. `http://10.80.0.2:3128`.
    pub proxy_url: String,
    /// Host path of the gateway inspection CA certificate (PEM). The holder builds the full
    /// bundle (system roots + this CA) from it, see ADR 0023.
    pub ca_path_host: String,
    /// Hermes plugin installation (EF-61), `None` for a non-Hermes agent.
    pub hermes: Option<HermesSpec>,
    /// Image of the `afw-net-<agent>` container (alpine + iproute2).
    pub netinit_image: String,
}

/// Hermes plugin installation parameters (EF-61).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HermesSpec {
    /// Console URL the plugin talks to (`AFW_CONSOLE_URL`).
    pub console_url: String,
    /// Name of the environment variable, on the compose host, holding the agent token.
    /// The compose file only references it (`${VAR}`), the secret is never written in it.
    pub agent_token_env: String,
    /// Host directory containing the plugin (`integrations/hermes`).
    pub plugin_dir_host: String,
    /// Plugin directory inside the container; `None` = [`DEFAULT_HERMES_PLUGIN_DIR`].
    #[serde(default)]
    pub plugin_dir_container: Option<String>,
}

impl HermesSpec {
    /// Effective plugin directory inside the container.
    pub fn container_dir(&self) -> &str {
        self.plugin_dir_container
            .as_deref()
            .unwrap_or(DEFAULT_HERMES_PLUGIN_DIR)
    }
}

impl EnrollSpec {
    /// Name of the network-namespace holder service.
    pub fn net_service_name(&self) -> String {
        net_service_name(&self.agent_name)
    }

    /// Validate names and addresses before any transformation.
    pub fn validate(&self) -> Result<(), EnrollError> {
        validate_agent_name(&self.agent_name)?;
        if self.service.trim().is_empty() {
            return Err(EnrollError::InvalidSpec("service name is empty".into()));
        }
        if self.network.trim().is_empty() {
            return Err(EnrollError::InvalidSpec("network name is empty".into()));
        }
        if self.gateway_ip.is_ipv4() != self.agent_ip.is_ipv4() {
            return Err(EnrollError::InvalidSpec(
                "gateway_ip and agent_ip must be of the same address family".into(),
            ));
        }
        if self.gateway_ip == self.agent_ip {
            return Err(EnrollError::InvalidSpec(
                "agent_ip must differ from gateway_ip".into(),
            ));
        }
        if !(self.proxy_url.starts_with("http://") || self.proxy_url.starts_with("https://")) {
            return Err(EnrollError::InvalidSpec(format!(
                "proxy_url must be an http(s) URL, got `{}`",
                self.proxy_url
            )));
        }
        if self.ca_path_host.trim().is_empty() {
            return Err(EnrollError::InvalidSpec("ca_path_host is empty".into()));
        }
        if self.netinit_image.trim().is_empty() {
            return Err(EnrollError::InvalidSpec("netinit_image is empty".into()));
        }
        if let Some(h) = &self.hermes {
            if !is_env_name(&h.agent_token_env) {
                return Err(EnrollError::InvalidSpec(format!(
                    "agent_token_env `{}` is not a valid environment variable name",
                    h.agent_token_env
                )));
            }
            if h.console_url.trim().is_empty() || h.plugin_dir_host.trim().is_empty() {
                return Err(EnrollError::InvalidSpec(
                    "hermes console_url and plugin_dir_host are required".into(),
                ));
            }
        }
        Ok(())
    }

    /// Environment variables set on the agent container, in a stable order.
    pub fn agent_environment(&self) -> Vec<(String, String)> {
        let no_proxy = match self.hermes.as_ref().and_then(|h| url_host(&h.console_url)) {
            // The Hermes plugin talks to the console directly (not through the explicit
            // proxy). The default route still goes through the gateway, so this traffic is
            // still filtered: the baseline must allow the console (ADR 0023).
            Some(host) => format!("{NO_PROXY},{host}"),
            None => NO_PROXY.to_string(),
        };
        let mut env = proxy_environment(&self.proxy_url, &no_proxy);
        if let Some(h) = &self.hermes {
            env.push(("AFW_CONSOLE_URL".into(), h.console_url.clone()));
            env.push((
                "AFW_AGENT_TOKEN".into(),
                format!("${{{}}}", h.agent_token_env),
            ));
            env.push(("AFW_AGENT_NAME".into(), self.agent_name.clone()));
        }
        env
    }
}

/// Proxy and CA variables, upper and lower case (curl only reads lower-case `http_proxy`).
pub(crate) fn proxy_environment(proxy_url: &str, no_proxy: &str) -> Vec<(String, String)> {
    vec![
        ("HTTP_PROXY".into(), proxy_url.into()),
        ("HTTPS_PROXY".into(), proxy_url.into()),
        ("NO_PROXY".into(), no_proxy.into()),
        ("http_proxy".into(), proxy_url.into()),
        ("https_proxy".into(), proxy_url.into()),
        ("no_proxy".into(), no_proxy.into()),
        ("REQUESTS_CA_BUNDLE".into(), CA_BUNDLE_PATH.into()),
        ("SSL_CERT_FILE".into(), CA_BUNDLE_PATH.into()),
        ("CURL_CA_BUNDLE".into(), CA_BUNDLE_PATH.into()),
        ("NODE_EXTRA_CA_CERTS".into(), CA_CERT_PATH.into()),
    ]
}

/// Host part of an URL (`https://user@host:8443/x` → `host`, `http://[fd00::1]:80` → `fd00::1`).
pub(crate) fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        hostport.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Name of the network-namespace holder service of an agent.
pub fn net_service_name(agent_name: &str) -> String {
    format!("afw-net-{agent_name}")
}

/// Agent names end up in service names, labels and Kubernetes objects.
pub fn validate_agent_name(name: &str) -> Result<(), EnrollError> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.'
        });
    if ok {
        Ok(())
    } else {
        Err(EnrollError::InvalidSpec(format!(
            "invalid agent name `{name}`: expected [a-z0-9][a-z0-9_.-]*, at most 63 characters"
        )))
    }
}

fn is_env_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Non-blocking findings reported by an enrollment ([Killian]: privileged containers are not
/// refused, the limit is documented and only reported). `service` is the compose service (or
/// the Kubernetes container/workload) the finding is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnrollWarning {
    /// `privileged: true`: the container can change the network namespace and leave.
    Privileged { service: String },
    /// A capability that defeats the isolation (`NET_ADMIN`, `NET_RAW`, `SYS_ADMIN`,
    /// `SYS_MODULE`, `SYS_RAWIO`, `SYS_PTRACE`, `BPF`, `DAC_READ_SEARCH`, `ALL`).
    DangerousCapability { service: String, capability: String },
    /// A container runtime socket (Docker, Podman, containerd, CRI-O) or `/var/run` is mounted:
    /// the container can start workloads that are not enrolled.
    RuntimeSocket { service: String, mount: String },
    /// A host namespace (`pid: host`, `ipc: host`, `hostPID`, `hostIPC`…).
    HostNamespace { service: String, namespace: String },
    /// `pid`/`ipc` shared with another container (`service:`/`container:`).
    SharedNamespace {
        service: String,
        namespace: String,
        with: String,
    },
    /// `volumes_from` another container.
    VolumesFrom { service: String, from: String },
    /// Another service joins the network namespace of the agent (same egress, own privileges).
    JoinsAgentNetwork { service: String },
    /// `links` cannot be combined with `network_mode: service:`; they were removed.
    LinksRemoved { service: String },
    /// `net.*` sysctls cannot be set on a container sharing a namespace; they were removed.
    NetSysctlsRemoved { service: String, keys: Vec<String> },
    /// Ports moved to the holder sit on an `internal` network: Docker no longer publishes them.
    PortsNotPublished { service: String },
    /// Kubernetes: a `hostPath` volume.
    HostPath { service: String, path: String },
    /// Kubernetes: an existing NetworkPolicy also allows egress of enrolled pods elsewhere than
    /// the gateway (NetworkPolicies are additive: any allow rule widens the egress).
    BroadEgressPolicy { policy: String, reason: String },
}

impl std::fmt::Display for EnrollWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Privileged { service } => write!(
                f,
                "{service} is privileged: it can change its network namespace and bypass the gateway"
            ),
            Self::DangerousCapability {
                service,
                capability,
            } => write!(
                f,
                "{service} has capability {capability}: it can weaken the isolation"
            ),
            Self::RuntimeSocket { service, mount } => write!(
                f,
                "{service} mounts {mount}: it can start containers that are not enrolled"
            ),
            Self::HostNamespace { service, namespace } => {
                write!(f, "{service} shares the host {namespace} namespace")
            }
            Self::SharedNamespace {
                service,
                namespace,
                with,
            } => write!(f, "{service} shares its {namespace} namespace with {with}"),
            Self::VolumesFrom { service, from } => {
                write!(f, "{service} mounts the volumes of {from}")
            }
            Self::JoinsAgentNetwork { service } => write!(
                f,
                "{service} joins the network namespace of the agent: its own privileges apply to the agent traffic"
            ),
            Self::LinksRemoved { service } => write!(
                f,
                "{service}: `links` are incompatible with the shared network namespace and were removed"
            ),
            Self::NetSysctlsRemoved { service, keys } => write!(
                f,
                "{service}: net.* sysctls were removed ({})",
                keys.join(", ")
            ),
            Self::PortsNotPublished { service } => write!(
                f,
                "{service}: its ports were moved to the network holder, on an internal network Docker does not publish them any more"
            ),
            Self::HostPath { service, path } => {
                write!(f, "{service} mounts the host path {path}")
            }
            Self::BroadEgressPolicy { policy, reason } => write!(
                f,
                "NetworkPolicy {policy} widens the egress of enrolled pods: {reason}"
            ),
        }
    }
}

/// Capabilities reported by [`EnrollWarning::DangerousCapability`] (without the `CAP_` prefix).
pub(crate) const DANGEROUS_CAPS: &[&str] = &[
    "NET_ADMIN",
    "NET_RAW",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_PTRACE",
    "BPF",
    "DAC_READ_SEARCH",
    "ALL",
];

/// `true` for a capability in [`DANGEROUS_CAPS`] (case-insensitive, `CAP_` prefix allowed).
pub(crate) fn is_dangerous_cap(cap: &str) -> bool {
    let up = cap.to_ascii_uppercase();
    let norm = up.strip_prefix("CAP_").unwrap_or(&up);
    DANGEROUS_CAPS.contains(&norm)
}

/// Container runtime sockets and the directories holding them.
pub(crate) fn is_runtime_socket(path: &str) -> bool {
    let p = path.trim_end_matches('/');
    if matches!(p, "/var/run" | "/run" | "/var/run/docker" | "/run/docker") {
        return true;
    }
    if p.ends_with(".sock") {
        return true;
    }
    let under_run = p.starts_with("/var/run/") || p.starts_with("/run/");
    under_run
        && ["docker", "podman", "containerd", "crio", "cri-dockerd"]
            .iter()
            .any(|k| p.contains(k))
}

/// Result of a successful enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollOutcome {
    /// Transformed document (YAML).
    pub yaml: String,
    /// Non-blocking findings to show to the operator.
    pub warnings: Vec<EnrollWarning>,
}

#[cfg(test)]
mod tests {
    use super::url_host;

    #[test]
    fn url_host_extracts_the_host() {
        assert_eq!(
            url_host("https://Afw.Example.org").as_deref(),
            Some("afw.example.org")
        );
        assert_eq!(
            url_host("http://u:p@console:8443/api?x").as_deref(),
            Some("console")
        );
        assert_eq!(url_host("http://[fd00::1]:80/").as_deref(), Some("fd00::1"));
        assert_eq!(
            url_host("console.local:3000").as_deref(),
            Some("console.local")
        );
        assert_eq!(url_host("https://"), None);
    }
}
