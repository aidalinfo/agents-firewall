//! Data loss prevention for agents-firewall: data classes, detectors, scanning and masking.
//!
//! This crate is self-contained (no dependency on `afw-core`): callers convert [`Finding`]
//! into their own types.

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
            internal_host_suffixes: Vec::new(),
            max_pattern_len: 512,
        }
    }
}

/// Compiled set of data classes.
#[derive(Debug)]
pub struct Scanner {
    opts: ScannerOptions,
}

impl Scanner {
    pub fn new(classes: &[ClassSpec], opts: ScannerOptions) -> Result<Scanner, DlpError> {
        let _ = classes;
        Ok(Scanner { opts })
    }

    pub fn scan(&self, data: &[u8], location: &str) -> Vec<Finding> {
        let _ = (data, location);
        Vec::new()
    }

    pub fn scan_headers(&self, headers: &[(String, String)]) -> Vec<Finding> {
        let _ = headers;
        Vec::new()
    }

    pub fn scan_url(&self, url: &str) -> Vec<Finding> {
        let _ = url;
        Vec::new()
    }

    pub fn stream(&self, location: &str) -> StreamScanner<'_> {
        StreamScanner {
            scanner: self,
            location: location.to_string(),
        }
    }

    pub fn options(&self) -> &ScannerOptions {
        &self.opts
    }
}

/// Incremental scanner for a continuous stream.
#[derive(Debug)]
pub struct StreamScanner<'a> {
    scanner: &'a Scanner,
    location: String,
}

impl StreamScanner<'_> {
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Finding> {
        let _ = (chunk, self.scanner, &self.location);
        Vec::new()
    }

    pub fn finish(self) -> Vec<Finding> {
        Vec::new()
    }
}

pub fn mask(text: &str, findings: &[Finding]) -> String {
    let _ = findings;
    text.to_string()
}

pub fn mask_bytes(data: &[u8], findings: &[Finding]) -> Vec<u8> {
    let _ = findings;
    data.to_vec()
}

pub fn builtin_classes() -> Vec<ClassSpec> {
    Vec::new()
}

/// Identifiers of the built-in detectors.
pub const BUILTIN_DETECTORS: &[&str] = &[];
