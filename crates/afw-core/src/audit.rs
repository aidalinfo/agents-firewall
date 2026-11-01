//! Hash-chained audit log helpers (plan §3.3).

use crate::canon::{canonical_json, sha256_hex};
use crate::events::AuditEntry;

/// `prev_hash` of the very first entry of the chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// `sha256_hex(prev_hash || canonical_json(entry without its "hash" field))`.
/// The `hash` field of `entry_without_hash` is ignored, whatever its value.
pub fn audit_hash(prev_hash: &str, entry_without_hash: &AuditEntry) -> String {
    let mut value = serde_json::to_value(entry_without_hash).expect("audit entry serializes");
    if let Some(obj) = value.as_object_mut() {
        obj.remove("hash");
    }
    let mut input = String::with_capacity(prev_hash.len() + 256);
    input.push_str(prev_hash);
    input.push_str(&canonical_json(&value));
    sha256_hex(input.as_bytes())
}

/// The chain is broken at entry `seq`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("audit chain broken at seq {seq}")]
pub struct ChainError {
    pub seq: i64,
}

/// Verifies a contiguous slice of the chain: consecutive `seq`, each `prev_hash` equal to the
/// previous entry's `hash`, and each `hash` recomputed. The first entry's `prev_hash` is not
/// checked here: callers compare it with [`GENESIS_HASH`] (full chain) or with a trusted
/// anchor (exported hash) when verifying a window.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), ChainError> {
    let mut previous: Option<&AuditEntry> = None;
    for entry in entries {
        if let Some(prev) = previous
            && (entry.seq != prev.seq + 1 || entry.prev_hash != prev.hash)
        {
            return Err(ChainError { seq: entry.seq });
        }
        if audit_hash(&entry.prev_hash, entry) != entry.hash {
            return Err(ChainError { seq: entry.seq });
        }
        previous = Some(entry);
    }
    Ok(())
}
