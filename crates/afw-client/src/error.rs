//! Client errors.

use afw_core::api::Problem;

/// Every way an API call can fail. `Api` carries the RFC 7807 problem returned by the API
/// (403 delegation refusals, 409 conflicts, 423 locks…), untouched.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The API answered with an error status.
    #[error("{}", api_message(*status, problem))]
    Api { status: u16, problem: Problem },
    /// The API could not be reached (DNS, TCP, TLS, timeout…).
    #[error("cannot reach the agents-firewall API: {0}")]
    Transport(#[from] reqwest::Error),
    /// The API answered with a body the client does not understand.
    #[error("unexpected answer from the API (HTTP {status}): {message}")]
    Decode { status: u16, message: String },
    /// Invalid client configuration (URL, CA certificate, token…).
    #[error("invalid client configuration: {0}")]
    Config(String),
    /// A name could not be resolved to an id.
    #[error("{kind} `{name}` not found")]
    NotFound { kind: String, name: String },
    /// A name matches several resources.
    #[error("{kind} name `{name}` matches {count} resources: use its id")]
    Ambiguous {
        kind: String,
        name: String,
        count: usize,
    },
    /// The operation needs an editing session and none is active.
    #[error("no editing session is active: open one first (`afw session open`)")]
    NoSession,
}

impl ClientError {
    /// HTTP status of an API error.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. } | Self::Decode { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The problem returned by the API, if any.
    pub fn problem(&self) -> Option<&Problem> {
        match self {
            Self::Api { problem, .. } => Some(problem),
            _ => None,
        }
    }
}

fn api_message(status: u16, p: &Problem) -> String {
    match p.detail.as_deref().filter(|d| !d.is_empty()) {
        Some(d) => format!("API error {status} {}: {d}", p.title),
        None => format!("API error {status} {}", p.title),
    }
}
