//! Enrollment errors.

/// Every way an enrollment can fail. Messages are meant to be shown as is to the operator.
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    /// The input document is not valid YAML or not a mapping.
    #[error("invalid YAML: {0}")]
    InvalidYaml(String),
    /// The enrollment parameters are invalid.
    #[error("invalid enrollment parameters: {0}")]
    InvalidSpec(String),
    /// The compose file has no such service.
    #[error("service `{0}` not found in the compose file")]
    ServiceNotFound(String),
    /// The agent (or the service) is already enrolled.
    #[error("agent `{0}` is already enrolled (run unenroll first)")]
    AlreadyEnrolled(String),
    /// Nothing to undo.
    #[error("agent `{0}` is not enrolled in this document")]
    NotEnrolled(String),
    /// `network_mode: host` shares the host network stack: isolation is impossible.
    #[error(
        "service `{0}` uses `network_mode: host`: the agent shares the host network and cannot be isolated behind the gateway"
    )]
    HostNetwork(String),
    /// Another `network_mode` (`service:`, `container:`, `none`, …) is already set.
    #[error("service `{service}` already uses `network_mode: {mode}`: enrollment is not supported")]
    UnsupportedNetworkMode { service: String, mode: String },
    /// The `x-afw-original` annotation is missing or damaged.
    #[error("enrollment annotation for `{0}` is damaged: {1}")]
    BrokenAnnotation(String, String),
    /// Coolify API transport error.
    #[error("Coolify request failed: {0}")]
    Http(String),
    /// Coolify API answered with an error status.
    #[error("Coolify API returned {status} for {path}: {body}")]
    CoolifyStatus {
        status: u16,
        path: String,
        body: String,
    },
    /// The Coolify resource has no compose file we can read.
    #[error(
        "Coolify resource `{0}` exposes no docker_compose_raw (not a compose resource, or the token lacks the read:sensitive permission)"
    )]
    NoCompose(String),
}

impl From<serde_yaml::Error> for EnrollError {
    fn from(e: serde_yaml::Error) -> Self {
        Self::InvalidYaml(e.to_string())
    }
}

impl From<reqwest::Error> for EnrollError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e.to_string())
    }
}
