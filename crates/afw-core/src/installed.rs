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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InstalledPolicy {
    pub format: u32,
    pub revision: u64,
    pub published_at: DateTime<Utc>,
    pub published_by: String,
    pub document: PolicyDocument,
    /// Set by the console when it deliberately installs an older revision: only then may a
    /// gateway replace its active policy by a lower revision number (see [`Self::may_replace`]).
    #[serde(default)]
    pub rollback: bool,
    /// SHA-256 (lowercase hex) of the canonical JSON of
    /// `{"document": …, "revision": …, "rollback": …}` (see [`installed_sha256`]).
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
        let sha256 = installed_sha256(revision, false, &document);
        Self {
            format: INSTALLED_POLICY_FORMAT,
            revision,
            published_at: Utc::now(),
            published_by: published_by.into(),
            document,
            rollback: false,
            sha256,
        }
    }

    /// Marks the policy as a deliberate rollback and recomputes the fingerprint.
    pub fn as_rollback(mut self) -> Self {
        self.rollback = true;
        self.sha256 = installed_sha256(self.revision, true, &self.document);
        self
    }

    /// Anti-downgrade rule for a gateway whose active revision is `active` (call after
    /// [`Self::verify`]): a lower revision is refused unless `rollback` is set. The same
    /// revision may be reinstalled.
    pub fn may_replace(&self, active: Option<u64>) -> bool {
        match active {
            None => true,
            Some(active) => self.rollback || self.revision >= active,
        }
    }

    /// Rejects an unknown format or a wrong fingerprint. A gateway must treat any error as
    /// "no valid policy" (deny everything or keep the last valid one), never fail open.
    pub fn verify(&self) -> Result<(), PolicyIntegrityError> {
        if self.format != INSTALLED_POLICY_FORMAT {
            return Err(PolicyIntegrityError::UnknownFormat(self.format));
        }
        let actual = installed_sha256(self.revision, self.rollback, &self.document);
        if actual != self.sha256 {
            return Err(PolicyIntegrityError::FingerprintMismatch {
                expected: self.sha256.clone(),
                actual,
            });
        }
        Ok(())
    }
}

/// Fingerprint of an installed policy: covers the document, the revision number and the
/// rollback flag, so neither can be changed without breaking it.
pub fn installed_sha256(revision: u64, rollback: bool, document: &PolicyDocument) -> String {
    let value = serde_json::json!({
        "document": document,
        "revision": revision,
        "rollback": rollback,
    });
    sha256_hex(canonical_json(&value).as_bytes())
}

/// SHA-256 of the canonical JSON of a policy document (revision fingerprint).
pub fn document_sha256(document: &PolicyDocument) -> String {
    let value = serde_json::to_value(document).expect("policy document serializes to JSON");
    sha256_hex(canonical_json(&value).as_bytes())
}
