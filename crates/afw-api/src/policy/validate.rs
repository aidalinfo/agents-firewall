//! Validation of entities (on each change) and of the whole document (at publication).

use std::collections::{HashMap, HashSet};

use afw_core::api::{ResourceKind, ResourceRef};
use afw_core::policy::{
    Agent, DataClass, InspectionRule, Layer, NetObject, NetObjectSpec, PolicyDocument,
    PolicySettings, Rule, Service, Zone,
};
use serde_json::Value;
use uuid::Uuid;

use super::model::{Kind, parse, value};
use crate::error::ApiError;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::BadRequest(msg.into())
}

fn check_name(name: &str) -> Result<(), ApiError> {
    if name.trim().is_empty() {
        return Err(bad("name must not be empty"));
    }
    Ok(())
}

/// Normalizes a domain pattern (lowercase, no trailing dot) and checks its syntax: `*` alone,
/// or labels with an optional leading `*.`.
pub fn normalize_domain(pattern: &str) -> Result<String, ApiError> {
    let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if p == "*" {
        return Ok(p);
    }
    let rest = p.strip_prefix("*.").unwrap_or(&p);
    let valid = !rest.is_empty()
        && rest.len() <= 253
        && rest.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
    if !valid {
        return Err(bad(format!("invalid domain pattern {pattern:?}")));
    }
    Ok(p)
}

/// Validates and normalizes an entity value of `kind` against the draft `doc` it goes into.
pub fn normalize(kind: Kind, id: Uuid, v: Value, doc: &PolicyDocument) -> Result<Value, ApiError> {
    Ok(match kind {
        Kind::Object => {
            let mut o: NetObject = parse(v)?;
            check_name(&o.name)?;
            match &mut o.spec {
                NetObjectSpec::Domain { pattern } => *pattern = normalize_domain(pattern)?,
                NetObjectSpec::Range { start, end } => {
                    if start.is_ipv4() != end.is_ipv4() || start > end {
                        return Err(bad("invalid address range"));
                    }
                }
                NetObjectSpec::Group { members } => {
                    if members.contains(&o.id) {
                        return Err(bad("a group cannot contain itself"));
                    }
                }
                _ => {}
            }
            value(&o)
        }
        Kind::Service => {
            let s: Service = parse(v)?;
            check_name(&s.name)?;
            if s.ports.iter().any(|p| p.start > p.end) {
                return Err(bad("invalid port range"));
            }
            value(&s)
        }
        Kind::DataClass => {
            let d: DataClass = parse(v)?;
            check_name(&d.name)?;
            value(&d)
        }
        Kind::Zone => {
            let z: Zone = parse(v)?;
            check_name(&z.name)?;
            value(&z)
        }
        Kind::Agent => {
            let a: Agent = parse(v)?;
            check_name(&a.name)?;
            if let Some(ip) = a.addresses.iter().find(|ip| {
                !doc.settings
                    .internal_networks
                    .iter()
                    .any(|n| n.contains(*ip))
            }) {
                return Err(bad(format!(
                    "agent address {ip} is outside the internal networks"
                )));
            }
            for other in doc.agents.iter().filter(|o| o.id != a.id) {
                if let Some(ip) = a.addresses.iter().find(|ip| other.addresses.contains(ip)) {
                    return Err(ApiError::Conflict {
                        message: format!("address {ip} already belongs to agent {}", other.name),
                    });
                }
            }
            value(&a)
        }
        Kind::Rule => {
            let mut r: Rule = parse(v)?;
            check_name(&r.name)?;
            normalize_rule_sources(&mut r)?;
            value(&r)
        }
        Kind::InspectionRule => {
            let r: InspectionRule = parse(v)?;
            check_name(&r.name)?;
            value(&r)
        }
        Kind::Settings => {
            let s: PolicySettings = parse(v)?;
            if id != Uuid::nil() {
                return Err(bad("invalid settings id"));
            }
            value(&s)
        }
    })
}

/// A zone rule's source is its zone: empty sources become `[zone]`, anything else is refused.
pub fn normalize_rule_sources(r: &mut Rule) -> Result<(), ApiError> {
    if let Layer::Zone { zone_id } = r.layer {
        if r.sources.is_empty() {
            r.sources = vec![zone_id];
        } else if r.sources != [zone_id] {
            return Err(bad("the source of a zone rule is its zone"));
        }
    }
    Ok(())
}

fn rref(kind: ResourceKind, id: Uuid, name: &str) -> ResourceRef {
    ResourceRef {
        kind,
        id,
        name: name.to_owned(),
    }
}

/// Direct references to an entity (a referenced entity cannot be deleted).
pub fn references_to(doc: &PolicyDocument, kind: Kind, id: Uuid) -> Vec<ResourceRef> {
    let mut out = Vec::new();
    let rule = |r: &Rule| rref(ResourceKind::Rule, r.id, &r.name);
    match kind {
        Kind::Object => {
            for o in &doc.objects {
                if let NetObjectSpec::Group { members } = &o.spec
                    && members.contains(&id)
                {
                    out.push(rref(ResourceKind::Object, o.id, &o.name));
                }
            }
            out.extend(
                doc.rules
                    .iter()
                    .filter(|r| r.destinations.contains(&id))
                    .map(rule),
            );
            out.extend(
                doc.inspection_rules
                    .iter()
                    .filter(|r| r.destinations.contains(&id))
                    .map(|r| rref(ResourceKind::InspectionRule, r.id, &r.name)),
            );
        }
        Kind::Service => {
            out.extend(
                doc.rules
                    .iter()
                    .filter(|r| r.services.contains(&id))
                    .map(rule),
            );
        }
        Kind::DataClass => {
            out.extend(
                doc.rules
                    .iter()
                    .filter(|r| r.data_classes.contains(&id))
                    .map(rule),
            );
        }
        Kind::Zone => {
            out.extend(
                doc.rules
                    .iter()
                    .filter(|r| r.sources.contains(&id) || r.layer == Layer::Zone { zone_id: id })
                    .map(rule),
            );
            out.extend(
                doc.agents
                    .iter()
                    .filter(|a| a.zone_id == id)
                    .map(|a| rref(ResourceKind::Agent, a.id, &a.name)),
            );
            out.extend(
                doc.inspection_rules
                    .iter()
                    .filter(|r| r.zones.contains(&id))
                    .map(|r| rref(ResourceKind::InspectionRule, r.id, &r.name)),
            );
        }
        Kind::Agent | Kind::Rule | Kind::InspectionRule | Kind::Settings => {}
    }
    out
}

/// Blocking errors of a document: broken references, zone rule sources, group cycles,
/// duplicate agent addresses. Empty = publishable.
pub fn document_errors(doc: &PolicyDocument) -> Vec<String> {
    let mut errors = Vec::new();
    let zones: HashSet<Uuid> = doc.zones.iter().map(|z| z.id).collect();
    let objects: HashMap<Uuid, &NetObject> = doc.objects.iter().map(|o| (o.id, o)).collect();
    let services: HashSet<Uuid> = doc.services.iter().map(|s| s.id).collect();
    let classes: HashSet<Uuid> = doc.data_classes.iter().map(|c| c.id).collect();
    let mut missing = |what: &str, id: &Uuid, owner: &str| {
        errors.push(format!("{owner} references missing {what} {id}"));
    };
    for r in &doc.rules {
        let owner = format!("rule {:?}", r.name);
        if let Layer::Zone { zone_id } = r.layer
            && !zones.contains(&zone_id)
        {
            missing("zone", &zone_id, &owner);
        }
        r.sources
            .iter()
            .filter(|z| !zones.contains(z))
            .for_each(|z| missing("zone", z, &owner));
        r.destinations
            .iter()
            .filter(|o| !objects.contains_key(o))
            .for_each(|o| missing("object", o, &owner));
        r.services
            .iter()
            .filter(|s| !services.contains(s))
            .for_each(|s| missing("service", s, &owner));
        r.data_classes
            .iter()
            .filter(|c| !classes.contains(c))
            .for_each(|c| missing("data class", c, &owner));
    }
    for r in &doc.inspection_rules {
        let owner = format!("inspection rule {:?}", r.name);
        r.zones
            .iter()
            .filter(|z| !zones.contains(z))
            .for_each(|z| missing("zone", z, &owner));
        r.destinations
            .iter()
            .filter(|o| !objects.contains_key(o))
            .for_each(|o| missing("object", o, &owner));
    }
    for a in &doc.agents {
        if !zones.contains(&a.zone_id) {
            missing("zone", &a.zone_id, &format!("agent {:?}", a.name));
        }
    }
    for o in &doc.objects {
        if let NetObjectSpec::Group { members } = &o.spec {
            members
                .iter()
                .filter(|m| !objects.contains_key(m))
                .for_each(|m| missing("object", m, &format!("group {:?}", o.name)));
        }
    }
    for r in &doc.rules {
        if let Layer::Zone { zone_id } = r.layer
            && r.sources != [zone_id]
        {
            errors.push(format!(
                "rule {:?}: the source of a zone rule is its zone",
                r.name
            ));
        }
    }
    // Group cycles.
    for o in &doc.objects {
        let mut stack = vec![o.id];
        let mut seen = HashSet::new();
        let mut cycle = false;
        while let Some(id) = stack.pop() {
            if let Some(NetObjectSpec::Group { members }) = objects.get(&id).map(|x| &x.spec) {
                for m in members {
                    if *m == o.id {
                        cycle = true;
                    } else if seen.insert(*m) {
                        stack.push(*m);
                    }
                }
            }
        }
        if cycle {
            errors.push(format!("group {:?} contains itself (cycle)", o.name));
        }
    }
    for a in &doc.agents {
        for ip in &a.addresses {
            if !doc
                .settings
                .internal_networks
                .iter()
                .any(|n| n.contains(ip))
            {
                errors.push(format!(
                    "agent {:?}: address {ip} is outside the internal networks",
                    a.name
                ));
            }
        }
    }
    let mut owners: HashMap<std::net::IpAddr, &str> = HashMap::new();
    for a in &doc.agents {
        for ip in &a.addresses {
            if let Some(other) = owners.insert(*ip, &a.name) {
                errors.push(format!(
                    "address {ip} shared by agents {other:?} and {:?}",
                    a.name
                ));
            }
        }
    }
    errors
}
