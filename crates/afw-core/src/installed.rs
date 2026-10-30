//! Installed policy: the published revision shipped to gateways, with its fingerprint
//! (plan §3.2, ADR 0004).

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canon::{canonical_json, sha256_hex};
use crate::policy::PolicyDocument;

/// The only `InstalledPolicy::format` gateways accept.
pub const INSTALLED_POLICY_FORMAT: u32 = 1;

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct InstalledPolicy {
    pub format: u32,
    pub revision: u64,
    pub published_at: DateTime<Utc>,
    pub published_by: String,
    pub document: PolicyDocument,
    /// SHA-256 (lowercase hex) of the canonical JSON of `document`.
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyIntegrityError {
    #[error("unknown installed policy format {0}")]
    UnknownFormat(u32),
    #[error("policy fingerprint mismatch: expected {expected}, computed {actual}")]
    FingerprintMismatch { expected: String, actual: String },
}

impl InstalledPolicy {
    /// Builds a format-1 installed policy published now and computes its fingerprint.
    pub fn new(revision: u64, published_by: impl Into<String>, document: PolicyDocument) -> Self {
        let sha256 = document_sha256(&document);
        Self {
            format: INSTALLED_POLICY_FORMAT,
            revision,
            published_at: Utc::now(),
            published_by: published_by.into(),
            document,
            sha256,
        }
    }

    /// Rejects an unknown format or a wrong fingerprint. A gateway must treat any error as
    /// "no valid policy" (deny everything or keep the last valid one), never fail open.
    pub fn verify(&self) -> Result<(), PolicyIntegrityError> {
        if self.format != INSTALLED_POLICY_FORMAT {
            return Err(PolicyIntegrityError::UnknownFormat(self.format));
        }
        let actual = document_sha256(&self.document);
        if actual != self.sha256 {
            return Err(PolicyIntegrityError::FingerprintMismatch {
                expected: self.sha256.clone(),
                actual,
            });
        }
        Ok(())
    }
}

/// SHA-256 of the canonical JSON of a policy document.
pub fn document_sha256(document: &PolicyDocument) -> String {
    let value = serde_json::to_value(document).expect("policy document serializes to JSON");
    sha256_hex(canonical_json(&value).as_bytes())
}
