//! Pre-install verification (EF-11) and where-used (EF-02) on a raw policy document.
//!
//! Both tolerate an invalid document (dangling references, group cycles): they report what
//! they can and never loop. Shadowing detection is conservative: it only reports a rule when
//! an earlier rule of the same layer provably covers it.

use std::collections::{HashMap, HashSet};

use afw_core::api::{ResourceKind, ResourceRef, VerifyFinding};
use afw_core::policy::{
    Action, DestCategory, L4Proto, Layer, NetObjectSpec, PolicyDocument, Rule, Service,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::matching::{Leaf, Resolver, normalize_path, path_has_prefix};

/// Verification warnings that `afw_core::api::VerifyFinding` cannot express.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerifyWarning {
    /// A zone without any agent.
    ZoneWithoutAgent { zone: Uuid },
    /// No enabled baseline deny rule targets a `cloud_metadata` object (EF-04).
    NoCloudMetadataBaselineRule,
}

/// A resource that references the object asked about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub kind: ResourceKind,
    pub id: Uuid,
    pub name: String,
    /// Group through which the reference goes; `None` for a direct reference.
    pub via: Option<Uuid>,
}

impl Usage {
    pub fn to_ref(&self) -> ResourceRef {
        ResourceRef {
            kind: self.kind,
            id: self.id,
            name: self.name.clone(),
        }
    }
}

/// Findings of the pre-install verification: shadowed rules, expired rules, then unused
/// objects, services and data classes (all reported as `UnusedObject`).
pub fn verify(doc: &PolicyDocument, now: DateTime<Utc>) -> Vec<VerifyFinding> {
    let resolver = Resolver::new(&doc.objects);
    let services: HashMap<Uuid, &Service> = doc.services.iter().map(|s| (s.id, s)).collect();
    let mut findings = Vec::new();

    // Shadowed rules, per layer, among active rules.
    let active = |r: &&Rule| r.enabled && r.expires_at.is_none_or(|e| e > now);
    let mut layers: HashMap<Layer, Vec<&Rule>> = HashMap::new();
    for r in doc.rules.iter().filter(active) {
        layers.entry(r.layer).or_default().push(r);
    }
    let leaves: HashMap<Uuid, Vec<Leaf>> = doc
        .rules
        .iter()
        .map(|r| (r.id, resolver.leaves(&r.destinations)))
        .collect();
    let mut shadowed = Vec::new();
    for rules in layers.values_mut() {
        rules.sort_by_key(|r| (r.position, r.id));
        for (i, b) in rules.iter().enumerate() {
            if let Some(a) = rules[..i]
                .iter()
                .find(|a| covers_rule(a, b, &leaves, &services))
            {
                shadowed.push((b.id, a.id));
            }
        }
    }
    // Deterministic order: document order of the shadowed rule.
    let order: HashMap<Uuid, usize> = doc
        .rules
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id, i))
        .collect();
    shadowed.sort_by_key(|(b, _)| order[b]);
    findings.extend(
        shadowed
            .into_iter()
            .map(|(rule, by)| VerifyFinding::Shadowed { rule, by }),
    );

    findings.extend(
        doc.rules
            .iter()
            .filter(|r| r.expires_at.is_some_and(|e| e <= now))
            .map(|r| VerifyFinding::Expired { rule: r.id }),
    );

    // Unused objects (through groups), services and data classes.
    let mut used_objects = HashSet::new();
    for r in &doc.rules {
        resolver.closure(&r.destinations, &mut used_objects);
    }
    for r in &doc.inspection_rules {
        resolver.closure(&r.destinations, &mut used_objects);
    }
    let used_services: HashSet<Uuid> = doc
        .rules
        .iter()
        .flat_map(|r| r.services.iter().copied())
        .collect();
    let used_classes: HashSet<Uuid> = doc
        .rules
        .iter()
        .flat_map(|r| r.data_classes.iter().copied())
        .collect();
    let unused = doc
        .objects
        .iter()
        .map(|o| o.id)
        .filter(|id| !used_objects.contains(id))
        .chain(
            doc.services
                .iter()
                .map(|s| s.id)
                .filter(|id| !used_services.contains(id)),
        )
        .chain(
            doc.data_classes
                .iter()
                .map(|c| c.id)
                .filter(|id| !used_classes.contains(id)),
        );
    findings.extend(unused.map(|id| VerifyFinding::UnusedObject { id }));
    findings
}

/// Warnings outside the `VerifyFinding` contract: zones without agents and the absence of a
/// baseline rule denying cloud metadata.
pub fn verify_warnings(doc: &PolicyDocument) -> Vec<VerifyWarning> {
    let mut out: Vec<VerifyWarning> = doc
        .zones
        .iter()
        .filter(|z| !doc.agents.iter().any(|a| a.zone_id == z.id))
        .map(|z| VerifyWarning::ZoneWithoutAgent { zone: z.id })
        .collect();
    let resolver = Resolver::new(&doc.objects);
    let has_metadata_rule = doc.rules.iter().any(|r| {
        r.enabled
            && r.layer == Layer::Baseline
            && r.action == Action::Deny
            && r.data_classes.is_empty()
            && {
                let mut ids = HashSet::new();
                resolver.closure(&r.destinations, &mut ids);
                ids.iter().any(|id| {
                    resolver
                        .get(id)
                        .is_some_and(|o| o.category == Some(DestCategory::CloudMetadata))
                })
            }
    });
    if !has_metadata_rule {
        out.push(VerifyWarning::NoCloudMetadataBaselineRule);
    }
    out
}

/// Resources referencing `object_id` (object, service, data class or zone): groups containing
/// it (transitively), rules and inspection rules referencing it directly or through a group,
/// agents of a zone.
pub fn where_used(doc: &PolicyDocument, object_id: Uuid) -> Vec<Usage> {
    let mut out = Vec::new();
    // Groups containing the object, transitively: group id -> the member it contains it by.
    let mut containing: HashMap<Uuid, Option<Uuid>> = HashMap::new();
    let mut frontier = vec![object_id];
    while let Some(cur) = frontier.pop() {
        for o in &doc.objects {
            if let NetObjectSpec::Group { members } = &o.spec
                && o.id != object_id
                && !containing.contains_key(&o.id)
                && members.contains(&cur)
            {
                let via = (cur != object_id).then_some(cur);
                containing.insert(o.id, via);
                out.push(Usage {
                    kind: ResourceKind::Object,
                    id: o.id,
                    name: o.name.clone(),
                    via,
                });
                frontier.push(o.id);
            }
        }
    }
    let via_of = |dsts: &[Uuid]| -> Option<Option<Uuid>> {
        if dsts.contains(&object_id) {
            Some(None)
        } else {
            dsts.iter()
                .find(|d| containing.contains_key(d))
                .map(|d| Some(*d))
        }
    };
    for r in &doc.rules {
        let zone_ref = r.sources.contains(&object_id)
            || matches!(r.layer, Layer::Zone { zone_id } if zone_id == object_id);
        let direct =
            zone_ref || r.services.contains(&object_id) || r.data_classes.contains(&object_id);
        let via = if direct {
            Some(None)
        } else {
            via_of(&r.destinations)
        };
        if let Some(via) = via {
            out.push(Usage {
                kind: ResourceKind::Rule,
                id: r.id,
                name: r.name.clone(),
                via,
            });
        }
    }
    for r in &doc.inspection_rules {
        let via = if r.zones.contains(&object_id) {
            Some(None)
        } else {
            via_of(&r.destinations)
        };
        if let Some(via) = via {
            out.push(Usage {
                kind: ResourceKind::InspectionRule,
                id: r.id,
                name: r.name.clone(),
                via,
            });
        }
    }
    out.extend(
        doc.agents
            .iter()
            .filter(|a| a.zone_id == object_id)
            .map(|a| Usage {
                kind: ResourceKind::Agent,
                id: a.id,
                name: a.name.clone(),
                via: None,
            }),
    );
    out
}

// ------------------------------------------------------------------------------- coverage

/// Whether active rule `a` (earlier, same layer) matches every flow `b` matches.
fn covers_rule(
    a: &Rule,
    b: &Rule,
    leaves: &HashMap<Uuid, Vec<Leaf>>,
    services: &HashMap<Uuid, &Service>,
) -> bool {
    if !a.data_classes.is_empty() {
        return false;
    }
    let sources = match a.layer {
        Layer::Zone { .. } => true,
        Layer::Baseline => {
            a.sources.is_empty()
                || (!b.sources.is_empty() && b.sources.iter().all(|s| a.sources.contains(s)))
        }
    };
    sources && covers_dest(a, b, leaves) && covers_services(a, b, services)
}

fn covers_dest(a: &Rule, b: &Rule, leaves: &HashMap<Uuid, Vec<Leaf>>) -> bool {
    if a.destinations.is_empty() {
        return true;
    }
    let la = &leaves[&a.id];
    if b.destinations.is_empty() {
        return la.contains(&Leaf::Any);
    }
    leaves[&b.id]
        .iter()
        .all(|lb| la.iter().any(|x| leaf_covers(x, lb)))
}

fn leaf_covers(a: &Leaf, b: &Leaf) -> bool {
    use std::net::IpAddr;
    let same = |x: &IpAddr, y: &IpAddr| x.is_ipv4() == y.is_ipv4();
    match (a, b) {
        (Leaf::Any, _) => true,
        (_, Leaf::Any) => false,
        (Leaf::Exact(x), Leaf::Exact(y)) => x == y,
        (Leaf::Suffix(s), Leaf::Exact(y)) => y.len() > s.len() && y.ends_with(&**s),
        (Leaf::Suffix(s), Leaf::Suffix(t)) => t.ends_with(&**s),
        (Leaf::Net(n), Leaf::Net(m)) => n.contains(m),
        (Leaf::Net(n), Leaf::Range(s, e)) => n.contains(s) && n.contains(e),
        (Leaf::Range(s, e), Leaf::Net(m)) => {
            same(s, &m.network()) && *s <= m.network() && m.broadcast() <= *e
        }
        (Leaf::Range(s, e), Leaf::Range(s2, e2)) => same(s, s2) && s <= s2 && e2 <= e,
        _ => false,
    }
}

fn covers_services(a: &Rule, b: &Rule, services: &HashMap<Uuid, &Service>) -> bool {
    if a.services.is_empty() {
        return true;
    }
    let sa: Vec<&Service> = a
        .services
        .iter()
        .filter_map(|id| services.get(id).copied())
        .collect();
    if b.services.is_empty() {
        return sa
            .iter()
            .any(|s| s.protocol == L4Proto::Any && s.ports.is_empty() && s.app.is_none());
    }
    b.services.iter().all(|id| {
        services
            .get(id)
            .is_some_and(|t| sa.iter().any(|s| service_covers(s, t)))
    })
}

fn service_covers(s: &Service, t: &Service) -> bool {
    if s.protocol != L4Proto::Any && s.protocol != t.protocol {
        return false;
    }
    if !s.ports.is_empty()
        && (t.ports.is_empty()
            || !t
                .ports
                .iter()
                .all(|p| s.ports.iter().any(|q| q.start <= p.start && p.end <= q.end)))
    {
        return false;
    }
    let Some(sa) = &s.app else { return true };
    let Some(ta) = &t.app else { return false };
    if sa.proto != ta.proto {
        return false;
    }
    if !sa.methods.is_empty()
        && (ta.methods.is_empty()
            || !ta
                .methods
                .iter()
                .all(|m| sa.methods.iter().any(|x| x.eq_ignore_ascii_case(m))))
    {
        return false;
    }
    if sa.path_prefixes.is_empty() {
        return true;
    }
    let norm =
        |v: &[String]| -> Option<Vec<String>> { v.iter().map(|p| normalize_path(p)).collect() };
    match (norm(&sa.path_prefixes), norm(&ta.path_prefixes)) {
        (Some(sp), Some(tp)) if !tp.is_empty() => {
            tp.iter().all(|p| sp.iter().any(|q| path_has_prefix(p, q)))
        }
        _ => false,
    }
}
