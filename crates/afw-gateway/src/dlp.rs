//! Content analysis contract used by the gateway (`afw-dlp`, lot L1).
//!
//! The gateway only depends on [`ContentScanner`]. Until `afw-dlp` is merged, [`ShimScanner`]
//! implements it with the custom regular expressions of the policy plus a few built-in
//! detectors; the adapter over `afw_dlp::Scanner` replaces it at rebase time.
//!
//! Streaming ([`StreamScan`]) is built on block scanning with an overlap window: every chunk
//! is scanned together with the last `overlap` bytes already seen, so a value split across
//! two chunks is found. `safe_len` is the number of bytes that can be relayed without ever
//! relaying a value that is not complete yet (`total - overlap`).

use std::sync::Arc;

use afw_core::policy::{DataCategory, DataClass, Detector};
use regex::bytes::Regex;
use sha2::{Digest, Sha256};

/// One detection. `start..end` is the byte range of the value in the scanned input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpFinding {
    /// Data class id (UUID text).
    pub class_id: String,
    pub class_name: String,
    pub category: DataCategory,
    pub kind: String,
    /// First 12 hex characters of the SHA-256 of the value.
    pub fingerprint: String,
    pub start: usize,
    pub end: usize,
    pub location: String,
}

impl DlpFinding {
    pub fn to_event(&self) -> afw_core::events::Finding {
        afw_core::events::Finding {
            class: self.class_name.clone(),
            category: self.category,
            kind: self.kind.clone(),
            fingerprint: self.fingerprint.clone(),
            location: self.location.clone(),
        }
    }
}

/// Errors of [`ContentScanner::decode_content`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("unsupported content encoding {0:?}")]
    Unsupported(String),
    #[error("decoded content exceeds {0} bytes")]
    TooLarge(usize),
    #[error("corrupt encoded content: {0}")]
    Corrupt(String),
}

pub trait ContentScanner: Send + Sync {
    fn scan(&self, data: &[u8], location: &str) -> Vec<DlpFinding>;
    /// Longest value guaranteed to be found across a chunk boundary.
    fn max_pattern_len(&self) -> usize;
    /// Decodes a `Content-Encoding` (`identity`, `gzip`, `deflate`, `br`) within `max_out`.
    fn decode_content(&self, encoding: &str, data: &[u8], max_out: usize) -> Result<Vec<u8>, DecodeError>;

    fn scan_headers(&self, headers: &[(String, String)]) -> Vec<DlpFinding> {
        headers
            .iter()
            .flat_map(|(k, v)| self.scan(v.as_bytes(), &format!("request.header:{}", k.to_ascii_lowercase())))
            .collect()
    }

    fn scan_url(&self, url: &str) -> Vec<DlpFinding> {
        self.scan(url.as_bytes(), "url")
    }
}

/// Replaces each finding's byte range by `[<CATEGORY>:<kind>:<fingerprint>]`.
pub fn mask_bytes(data: &[u8], findings: &[DlpFinding]) -> Vec<u8> {
    let mut ranges: Vec<&DlpFinding> = findings.iter().filter(|f| f.end <= data.len() && f.start < f.end).collect();
    ranges.sort_by_key(|f| (f.start, std::cmp::Reverse(f.end)));
    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0;
    for f in ranges {
        if f.start < pos {
            if f.end > pos {
                pos = f.end;
            }
            continue;
        }
        out.extend_from_slice(&data[pos..f.start]);
        let label = match f.category {
            DataCategory::Secret => "SECRET",
            DataCategory::Infra => "INFRA",
            DataCategory::Commercial => "COMMERCIAL",
            DataCategory::Personal => "PERSONAL",
            DataCategory::Custom => "CUSTOM",
        };
        out.extend_from_slice(format!("[{label}:{}:{}]", f.kind, f.fingerprint).as_bytes());
        pos = f.end;
    }
    out.extend_from_slice(&data[pos.min(data.len())..]);
    out
}

/// Incremental scanner over a stream (request body, WebSocket messages).
pub struct StreamScan {
    scanner: Arc<dyn ContentScanner>,
    location: String,
    overlap: usize,
    window: Vec<u8>,
    /// Absolute offset of `window[0]`.
    window_start: usize,
    total: usize,
    seen: std::collections::HashSet<(usize, usize, String)>,
}

impl StreamScan {
    pub fn new(scanner: Arc<dyn ContentScanner>, location: &str) -> Self {
        let overlap = scanner.max_pattern_len();
        Self {
            scanner,
            location: location.to_string(),
            overlap,
            window: Vec::new(),
            window_start: 0,
            total: 0,
            seen: Default::default(),
        }
    }

    /// Feeds a chunk; returns new findings with absolute offsets.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<DlpFinding> {
        self.window.extend_from_slice(chunk);
        self.total += chunk.len();
        let found = self.scan_window();
        if self.window.len() > self.overlap {
            let drop = self.window.len() - self.overlap;
            self.window.drain(..drop);
            self.window_start += drop;
        }
        found
    }

    /// Bytes that may be relayed: never the last `overlap` bytes before the end of stream.
    pub fn safe_len(&self) -> usize {
        self.total.saturating_sub(self.overlap)
    }

    pub fn total(&self) -> usize {
        self.total
    }

    /// End of stream: last scan of the remaining window.
    pub fn finish(mut self) -> Vec<DlpFinding> {
        self.scan_window()
    }

    fn scan_window(&mut self) -> Vec<DlpFinding> {
        let mut out = Vec::new();
        for mut f in self.scanner.scan(&self.window, &self.location) {
            f.start += self.window_start;
            f.end += self.window_start;
            if self.seen.insert((f.start, f.end, f.kind.clone())) {
                out.push(f);
            }
        }
        out
    }
}

/// Stand-in scanner (see module docs).
pub struct ShimScanner {
    detectors: Vec<(Regex, String, DataClass)>,
}

const BUILTINS: &[(&str, &str)] = &[
    ("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai_key", r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}"),
    ("private_key_pem", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
];

impl ShimScanner {
    pub fn new(classes: &[DataClass]) -> Result<Self, String> {
        let mut detectors = Vec::new();
        for c in classes {
            for d in &c.detectors {
                let (pattern, kind) = match d {
                    Detector::Builtin { id } => match BUILTINS.iter().find(|(k, _)| k == id) {
                        Some((k, p)) => (p.to_string(), k.to_string()),
                        None => continue,
                    },
                    Detector::Regex { name, pattern } => (pattern.clone(), name.clone()),
                };
                let re = Regex::new(&pattern).map_err(|e| format!("{kind}: {e}"))?;
                detectors.push((re, kind, c.clone()));
            }
        }
        Ok(Self { detectors })
    }
}

impl ContentScanner for ShimScanner {
    fn scan(&self, data: &[u8], location: &str) -> Vec<DlpFinding> {
        let mut out = Vec::new();
        for (re, kind, class) in &self.detectors {
            for m in re.find_iter(data) {
                out.push(DlpFinding {
                    class_id: class.id.to_string(),
                    class_name: class.name.clone(),
                    category: class.category,
                    kind: kind.clone(),
                    fingerprint: hex::encode(Sha256::digest(m.as_bytes()))[..12].to_string(),
                    start: m.start(),
                    end: m.end(),
                    location: location.to_string(),
                });
            }
        }
        out
    }

    fn max_pattern_len(&self) -> usize {
        512
    }

    fn decode_content(&self, encoding: &str, data: &[u8], max_out: usize) -> Result<Vec<u8>, DecodeError> {
        match encoding.trim().to_ascii_lowercase().as_str() {
            "" | "identity" => {
                if data.len() > max_out {
                    Err(DecodeError::TooLarge(max_out))
                } else {
                    Ok(data.to_vec())
                }
            }
            other => Err(DecodeError::Unsupported(other.to_string())),
        }
    }
}

/// Builds the scanner for a policy's data classes.
pub fn build_scanner(classes: &[DataClass]) -> Result<Arc<dyn ContentScanner>, String> {
    Ok(Arc::new(ShimScanner::new(classes)?))
}
