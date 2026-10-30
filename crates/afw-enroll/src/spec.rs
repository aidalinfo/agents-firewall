//! Input and output types shared by every enrollment target.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::EnrollError;

/// Default image of the network-namespace holder container (`afw-net-<agent>`).
pub const DEFAULT_NETINIT_IMAGE: &str = "afw-netinit:local";

/// Path where the gateway inspection CA is mounted inside the agent container.
pub const CA_CONTAINER_PATH: &str = "/usr/local/share/ca-certificates/afw-gateway.crt";

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
    /// Host path of the gateway inspection CA certificate (PEM). May be a full bundle
    /// (system roots + gateway CA), see ADR 0023.
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
        let mut env = proxy_environment(&self.proxy_url, &no_proxy, CA_CONTAINER_PATH);
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
pub(crate) fn proxy_environment(
    proxy_url: &str,
    no_proxy: &str,
    ca_path: &str,
) -> Vec<(String, String)> {
    vec![
        ("HTTP_PROXY".into(), proxy_url.into()),
        ("HTTPS_PROXY".into(), proxy_url.into()),
        ("NO_PROXY".into(), no_proxy.into()),
        ("http_proxy".into(), proxy_url.into()),
        ("https_proxy".into(), proxy_url.into()),
        ("no_proxy".into(), no_proxy.into()),
        ("REQUESTS_CA_BUNDLE".into(), ca_path.into()),
        ("SSL_CERT_FILE".into(), ca_path.into()),
        ("NODE_EXTRA_CA_CERTS".into(), ca_path.into()),
        ("CURL_CA_BUNDLE".into(), ca_path.into()),
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
/// refused, the limit is documented and only reported).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnrollWarning {
    /// `privileged: true`: the agent can change its own route and leave through another path.
    Privileged,
    /// A capability that lets the agent rewrite its network namespace (`NET_ADMIN`, `SYS_ADMIN`, `ALL`).
    DangerousCapability { capability: String },
    /// The Docker socket is mounted: the agent can start an unenrolled container.
    DockerSocket { mount: String },
    /// `pid: host` or another host namespace.
    HostNamespace { namespace: String },
    /// `links` cannot be combined with `network_mode: service:`; they were removed.
    LinksRemoved,
    /// Kubernetes: a privileged container can reach the node and leave through another path.
    PodPrivileged { container: String },
}

impl std::fmt::Display for EnrollWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Privileged => write!(
                f,
                "the agent is privileged: it can change its network namespace and bypass the gateway"
            ),
            Self::DangerousCapability { capability } => write!(
                f,
                "the agent has capability {capability}: it can change its route and bypass the gateway"
            ),
            Self::DockerSocket { mount } => write!(
                f,
                "the Docker socket is mounted ({mount}): the agent can start containers that are not enrolled"
            ),
            Self::HostNamespace { namespace } => {
                write!(f, "the agent shares the host {namespace} namespace")
            }
            Self::LinksRemoved => write!(
                f,
                "`links` are incompatible with the shared network namespace and were removed"
            ),
            Self::PodPrivileged { container } => write!(
                f,
                "container {container} is privileged: it can reach the node and bypass the gateway"
            ),
        }
    }
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
