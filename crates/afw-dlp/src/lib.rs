//! Data loss prevention for agents-firewall: data classes, detectors, scanning and masking.
//!
//! This crate is self-contained (no dependency on `afw-core`): callers convert [`Finding`]
//! into their own types.

mod decode;
mod detectors;
mod mask;
mod scanner;
mod stream;

pub use detectors::BUILTIN_DETECTORS;
pub use mask::{mask, mask_bytes};
pub use scanner::Scanner;
pub use stream::StreamScanner;

use serde::{Deserialize, Serialize};

/// Category of a data class. Drives the label used when masking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    Secret,
    Infra,
    Commercial,
    Personal,
    Custom,
}

/// How a class detects data: a built-in detector or a custom regular expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DetectorSpec {
    Builtin { id: String },
    Regex { name: String, pattern: String },
}

/// A data class: a named set of detectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassSpec {
    /// Class identifier (UUID as text, or a stable name for built-in classes).
    pub id: String,
    pub name: String,
    pub category: DataCategory,
    pub detectors: Vec<DetectorSpec>,
}

/// One detection. `start..end` is the byte range of the value in the scanned input
/// (for headers: in the header value).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Finding {
    pub class_id: String,
    pub class_name: String,
    pub category: DataCategory,
    /// Detector id (`aws_access_key`, ...) or custom regex name.
    pub kind: String,
    /// First 12 hex characters of the SHA-256 of the (decoded) value.
    pub fingerprint: String,
    pub start: usize,
    pub end: usize,
    /// Where the value was found: `body`, `header:authorization`, `url`, ...
    pub location: String,
}

/// Errors returned when building a [`Scanner`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DlpError {
    #[error("unknown built-in detector `{0}`")]
    UnknownDetector(String),
    #[error("invalid pattern for detector `{name}`: {reason}")]
    InvalidPattern { name: String, reason: String },
    #[error("invalid scanner options: {0}")]
    InvalidOptions(String),
}

/// Scanner options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerOptions {
    /// Host name suffixes considered internal (`internal_hostname` detector), e.g. `.internal`.
    pub internal_host_suffixes: Vec<String>,
    /// Overlap kept between two chunks by [`StreamScanner`]; also the longest value
    /// guaranteed to be detected across a chunk boundary. Default 512.
    pub max_pattern_len: usize,
}

impl Default for ScannerOptions {
    fn default() -> Self {
        Self {
            internal_host_suffixes: [
                ".internal",
                ".local",
                ".lan",
                ".corp",
                ".localdomain",
                ".home.arpa",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            max_pattern_len: 512,
        }
    }
}

fn class(id: &str, name: &str, category: DataCategory, ids: &[&str]) -> ClassSpec {
    ClassSpec {
        id: id.to_string(),
        name: name.to_string(),
        category,
        detectors: ids
            .iter()
            .map(|d| DetectorSpec::Builtin { id: d.to_string() })
            .collect(),
    }
}

/// Default data classes: `secrets`, `inventaire-infra`, `commercial`, `donnees-personnelles`.
pub fn builtin_classes() -> Vec<ClassSpec> {
    vec![
        class(
            "secrets",
            "Secrets",
            DataCategory::Secret,
            &[
                "aws_access_key",
                "aws_secret_key",
                "github_token",
                "gitlab_token",
                "anthropic_key",
                "openai_key",
                "slack_token",
                "jwt",
                "private_key_pem",
                "password_in_url",
                "generic_secret_assignment",
                "bearer_token",
            ],
        ),
        class(
            "inventaire-infra",
            "Inventaire infra",
            DataCategory::Infra,
            &["private_ip", "internal_hostname"],
        ),
        class(
            "commercial",
            "Commercial",
            DataCategory::Commercial,
            &["price_amount", "iban"],
        ),
        class(
            "donnees-personnelles",
            "Données personnelles",
            DataCategory::Personal,
            &["email", "credit_card"],
        ),
    ]
}
