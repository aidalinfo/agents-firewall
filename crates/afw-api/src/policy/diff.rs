//! Readable differences between two policy documents.

use std::collections::BTreeMap;

use afw_core::api::{Change, ChangeKind};
use afw_core::policy::PolicyDocument;
use serde_json::Value;
use uuid::Uuid;

use super::model::{ALL_KINDS, Kind, list, resource_ref};

/// One entity difference: `(kind, id, before, after)`.
pub type EntityDiff = (Kind, Uuid, Option<Value>, Option<Value>);

/// Entity-level differences, in kind order then by id.
pub fn entity_diffs(before: &PolicyDocument, after: &PolicyDocument) -> Vec<EntityDiff> {
    let mut out = Vec::new();
    for kind in ALL_KINDS {
        let mut b: BTreeMap<Uuid, Value> = list(before, kind).into_iter().collect();
        let a: BTreeMap<Uuid, Value> = list(after, kind).into_iter().collect();
        for (id, av) in a {
            match b.remove(&id) {
                Some(bv) if bv == av => {}
                bv => out.push((kind, id, bv, Some(av))),
            }
        }
        for (id, bv) in b {
            out.push((kind, id, Some(bv), None));
        }
    }
    out
}

/// Readable changes (added / removed / modified with before and after).
pub fn diff_documents(before: &PolicyDocument, after: &PolicyDocument) -> Vec<Change> {
    entity_diffs(before, after)
        .into_iter()
        .map(|(kind, id, b, a)| Change {
            kind: match (&b, &a) {
                (None, _) => ChangeKind::Added,
                (_, None) => ChangeKind::Removed,
                _ => ChangeKind::Modified,
            },
            resource: resource_ref(kind, id, a.as_ref().or(b.as_ref())),
            before: b,
            after: a,
        })
        .collect()
}
