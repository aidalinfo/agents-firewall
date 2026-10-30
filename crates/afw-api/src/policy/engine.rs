//! Helpers over the policy graph used by the authorization checks (EF-51/52). Verification
//! (EF-11) and where-used (EF-02) come from `afw-engine` (`verify`, `where_used`).

use std::collections::{BTreeSet, HashSet};

use afw_core::policy::{Layer, NetObjectSpec, PolicyDocument};
use uuid::Uuid;

/// `object_id` and every group containing it, transitively (cycle-safe).
pub fn object_closure(doc: &PolicyDocument, object_id: Uuid) -> HashSet<Uuid> {
    let mut set = HashSet::from([object_id]);
    loop {
        let before = set.len();
        for o in &doc.objects {
            if let NetObjectSpec::Group { members } = &o.spec
                && members.iter().any(|m| set.contains(m))
            {
                set.insert(o.id);
            }
        }
        if set.len() == before {
            return set;
        }
    }
}

/// Destination objects of a rule resolved through groups (cycle-safe), groups excluded.
pub fn resolve_objects(doc: &PolicyDocument, ids: &[Uuid]) -> BTreeSet<Uuid> {
    let mut seen = HashSet::new();
    let mut out = BTreeSet::new();
    let mut stack: Vec<Uuid> = ids.to_vec();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        match doc.objects.iter().find(|o| o.id == id).map(|o| &o.spec) {
            Some(NetObjectSpec::Group { members }) => stack.extend(members.iter().copied()),
            _ => {
                out.insert(id);
            }
        }
    }
    out
}

/// Zone of a rule's layer (`None` for the baseline).
pub fn layer_zone(layer: &Layer) -> Option<Uuid> {
    match layer {
        Layer::Baseline => None,
        Layer::Zone { zone_id } => Some(*zone_id),
    }
}
