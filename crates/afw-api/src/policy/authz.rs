//! Rights of the MCP administration agent on policy changes (EF-51) and detection of the
//! widening changes that need a human approval (EF-52).
//!
//! Every change is checked when it is made AND again, as a diff against the current published
//! revision, when the session is published (the delegation may have changed in between).

use std::collections::{BTreeSet, HashSet};

use afw_core::api::Role;
use std::net::IpAddr;

use afw_core::policy::{
    Action, Agent, DataCategory, InspectionRule, Layer, NetObject, NetObjectSpec, PolicyDocument,
    Rule, Zone, ZoneMode,
};
use ipnet::IpNet;
use serde_json::Value;
use uuid::Uuid;

use super::engine::{layer_zone, object_closure, resolve_objects};
use super::model::{Kind, get, parse};
use crate::auth::Principal;
use crate::error::ApiError;

fn forbidden(msg: impl Into<String>) -> ApiError {
    ApiError::Forbidden(msg.into())
}

/// Zones the MCP agent may modify, computed from the published policy AND the draft: its own
/// zone in either is excluded, a zone must be delegated in both.
struct McpScope {
    own: HashSet<Uuid>,
    delegated: HashSet<Uuid>,
}

impl McpScope {
    fn new(
        p: &Principal,
        published: &PolicyDocument,
        draft: &PolicyDocument,
    ) -> Result<Self, ApiError> {
        let (own_pub, del_pub) = p.zone_scope(published);
        let (own_draft, del_draft) = p.zone_scope(draft);
        // Fail closed: an MCP agent unknown to the published policy has no rights.
        let own_pub =
            own_pub.ok_or_else(|| forbidden("MCP agent is not an agent of the current policy"))?;
        let mut own = HashSet::from([own_pub]);
        own.extend(own_draft);
        let del_draft: HashSet<Uuid> = del_draft.into_iter().collect();
        let delegated = del_pub
            .into_iter()
            .filter(|z| del_draft.contains(z))
            .collect();
        Ok(Self { own, delegated })
    }

    fn require(&self, zone: Uuid) -> Result<(), ApiError> {
        if self.own.contains(&zone) {
            Err(forbidden("the MCP agent cannot modify its own zone"))
        } else if self.delegated.contains(&zone) {
            Ok(())
        } else {
            Err(forbidden("zone not delegated to the MCP agent"))
        }
    }

    fn require_rule(&self, r: &Rule) -> Result<(), ApiError> {
        let zone = layer_zone(&r.layer)
            .ok_or_else(|| forbidden("the MCP agent cannot modify the baseline"))?;
        self.require(zone)?;
        r.sources.iter().try_for_each(|z| self.require(*z))
    }

    fn require_inspection(&self, r: &InspectionRule) -> Result<(), ApiError> {
        if r.zones.is_empty() {
            return Err(forbidden("inspection rule covering every zone"));
        }
        r.zones.iter().try_for_each(|z| self.require(*z))
    }

    /// An object, service or data class may be changed only when every rule using it (directly
    /// or through a group) is in a zone the agent may modify.
    fn require_users(&self, doc: &PolicyDocument, kind: Kind, id: Uuid) -> Result<(), ApiError> {
        let ids: HashSet<Uuid> = match kind {
            Kind::Object => object_closure(doc, id),
            _ => HashSet::from([id]),
        };
        for r in &doc.rules {
            let used = match kind {
                Kind::Object => r.destinations.iter().any(|d| ids.contains(d)),
                Kind::Service => r.services.contains(&id),
                Kind::DataClass => r.data_classes.contains(&id),
                _ => false,
            };
            if used {
                self.require_rule(r).map_err(|_| {
                    forbidden(format!(
                        "used by rule {:?} outside the delegated zones",
                        r.name
                    ))
                })?;
            }
        }
        if kind == Kind::Object {
            for r in &doc.inspection_rules {
                if r.destinations.iter().any(|d| ids.contains(d)) {
                    self.require_inspection(r)?;
                }
            }
        }
        Ok(())
    }
}

/// Checks one change (`before` → `after`) of entity `kind`/`id`. Admin: always allowed. MCP
/// agent: EF-51. Any other role: refused.
#[allow(clippy::too_many_arguments)]
pub fn check_change(
    p: &Principal,
    published: &PolicyDocument,
    draft_before: &PolicyDocument,
    draft_after: &PolicyDocument,
    kind: Kind,
    id: Uuid,
    before: Option<&Value>,
    after: Option<&Value>,
) -> Result<(), ApiError> {
    p.require_policy_write()?;
    if p.role == Role::Admin {
        return Ok(());
    }
    if p.role != Role::McpAgent {
        return Err(forbidden("policy write requires admin"));
    }
    let scope = McpScope::new(p, published, draft_before)?;
    let both = |f: &dyn Fn(&Value) -> Result<(), ApiError>| -> Result<(), ApiError> {
        before.map(f).transpose()?;
        after.map(f).transpose()?;
        Ok(())
    };
    match kind {
        Kind::Settings => Err(forbidden("the MCP agent cannot change global settings")),
        Kind::Zone => {
            scope.require(id)?;
            let flag = |v: Option<&Value>| -> Result<Option<bool>, ApiError> {
                v.map(|v| parse::<Zone>(v.clone()).map(|z| z.delegated_to_mcp))
                    .transpose()
            };
            if flag(before)? != flag(after)? && before.is_some() && after.is_some() {
                return Err(forbidden("only a human can change a zone's MCP delegation"));
            }
            Ok(())
        }
        Kind::Agent => {
            if p.agent_id == Some(id) {
                return Err(forbidden("the MCP agent cannot modify itself"));
            }
            both(&|v| scope.require(parse::<Agent>(v.clone())?.zone_id))?;
            // Addresses decide which agent (thus which zone) traffic belongs to, and what is
            // internal for every zone: human-only.
            if let Some(after) = after {
                let addresses = |v: Option<&Value>| -> Result<Vec<IpAddr>, ApiError> {
                    Ok(v.map(|v| parse::<Agent>(v.clone()))
                        .transpose()?
                        .map(|a| a.addresses)
                        .unwrap_or_default())
                };
                if addresses(Some(after))? != addresses(before)? {
                    return Err(forbidden("only a human can set agent addresses"));
                }
            }
            let admin = |v: Option<&Value>| -> Result<bool, ApiError> {
                Ok(v.map(|v| parse::<Agent>(v.clone()))
                    .transpose()?
                    .is_some_and(|a| a.mcp_admin))
            };
            if admin(after)? && !admin(before)? {
                return Err(forbidden("only a human can grant MCP administration"));
            }
            Ok(())
        }
        Kind::Rule => both(&|v| scope.require_rule(&parse::<Rule>(v.clone())?)),
        Kind::InspectionRule => {
            both(&|v| scope.require_inspection(&parse::<InspectionRule>(v.clone())?))
        }
        Kind::Object | Kind::Service | Kind::DataClass => {
            if kind == Kind::Object {
                // A category (internal, llm_provider, cloud_metadata) changes the implicit
                // decisions of every zone, used by a rule or not: human-only.
                let categorized = |v: Option<&Value>| -> Result<bool, ApiError> {
                    Ok(v.map(|v| parse::<NetObject>(v.clone()))
                        .transpose()?
                        .is_some_and(|o| o.category.is_some()))
                };
                if categorized(before)? || categorized(after)? {
                    return Err(forbidden("only a human can manage objects with a category"));
                }
            }
            if before.is_none() && get(published, kind, id).is_none() {
                // A new entity is used by nothing yet; rules adding it are checked themselves.
                return Ok(());
            }
            scope.require_users(published, kind, id)?;
            scope.require_users(draft_before, kind, id)?;
            scope.require_users(draft_after, kind, id)
        }
    }
}

/// Why an accept rule is a "widening" (EF-52), if it is one.
fn widening_reason(r: &Rule, doc: &PolicyDocument) -> Option<String> {
    if r.action != Action::Accept || !r.enabled {
        return None;
    }
    if r.destinations.is_empty() {
        return Some(format!("rule {:?} accepts any destination", r.name));
    }
    let objects = resolve_objects(doc, &r.destinations);
    for id in &objects {
        let Some(o) = doc.objects.iter().find(|o| o.id == *id) else {
            continue;
        };
        let broad = match &o.spec {
            NetObjectSpec::Any => true,
            NetObjectSpec::Domain { pattern } => broad_domain(pattern),
            _ => false,
        };
        if broad {
            return Some(format!(
                "rule {:?} accepts the broad destination {:?}",
                r.name, o.name
            ));
        }
    }
    let (v4, v6) = coverage(doc, &objects);
    if v4 > MAX_PUBLIC_V4 || v6 > MAX_V6 {
        return Some(format!(
            "rule {:?} accepts a wide address space ({v4} public IPv4, {v6} IPv6 addresses)",
            r.name
        ));
    }
    for c in &r.data_classes {
        if doc
            .data_classes
            .iter()
            .any(|d| d.id == *c && d.category == DataCategory::Secret)
        {
            return Some(format!("rule {:?} lets secrets out", r.name));
        }
    }
    None
}

/// `*` or a wildcard over a public suffix (`*.com`, `*.co.uk`).
pub fn broad_domain(pattern: &str) -> bool {
    match pattern.strip_prefix("*.") {
        None => pattern == "*",
        Some(rest) => psl::domain_str(rest).is_none(),
    }
}

/// More than a /8 of public IPv4 addresses, or more than a /32 of IPv6.
const MAX_PUBLIC_V4: u128 = 1 << 24;
const MAX_V6: u128 = 1 << 96;

type Interval = (u128, u128);

fn bounds(net: &IpNet) -> (bool, Interval) {
    match net {
        IpNet::V4(n) => (
            true,
            (
                u32::from(n.network()) as u128,
                u32::from(n.broadcast()) as u128,
            ),
        ),
        IpNet::V6(n) => (false, (u128::from(n.network()), u128::from(n.broadcast()))),
    }
}

fn ip(a: IpAddr) -> (bool, u128) {
    match a {
        IpAddr::V4(a) => (true, u32::from(a) as u128),
        IpAddr::V6(a) => (false, u128::from(a)),
    }
}

fn merge(mut v: Vec<Interval>) -> Vec<Interval> {
    v.sort();
    let mut out: Vec<Interval> = Vec::new();
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1.saturating_add(1) => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

fn subtract(v: Vec<Interval>, holes: &[Interval]) -> Vec<Interval> {
    let mut cur = v;
    for &(hs, he) in holes {
        let mut next = Vec::new();
        for (s, e) in cur {
            if he < s || hs > e {
                next.push((s, e));
                continue;
            }
            if s < hs {
                next.push((s, hs - 1));
            }
            if e > he {
                next.push((he + 1, e));
            }
        }
        cur = next;
    }
    cur
}

fn count(v: &[Interval]) -> u128 {
    v.iter().fold(0u128, |acc, (s, e)| {
        acc.saturating_add((e - s).saturating_add(1))
    })
}

/// Addresses covered by the union of the objects' networks, ranges and hosts: public IPv4
/// (outside the policy's internal networks) and IPv6.
fn coverage(doc: &PolicyDocument, objects: &BTreeSet<Uuid>) -> (u128, u128) {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    let mut push = |is_v4: bool, iv: Interval| if is_v4 { v4.push(iv) } else { v6.push(iv) };
    for o in doc.objects.iter().filter(|o| objects.contains(&o.id)) {
        match &o.spec {
            NetObjectSpec::Network { cidr } => {
                let (f, iv) = bounds(cidr);
                push(f, iv);
            }
            NetObjectSpec::Host { ip: a } => {
                let (f, x) = ip(*a);
                push(f, (x, x));
            }
            NetObjectSpec::Range { start, end } => {
                let ((f, s), (g, e)) = (ip(*start), ip(*end));
                if f == g && s <= e {
                    push(f, (s, e));
                }
            }
            _ => {}
        }
    }
    let internal: Vec<Interval> = merge(
        doc.settings
            .internal_networks
            .iter()
            .map(bounds)
            .filter(|(f, _)| *f)
            .map(|(_, iv)| iv)
            .collect(),
    );
    (count(&subtract(merge(v4), &internal)), count(&merge(v6)))
}

/// What decides a rule's effect: the rule, its resolved destinations and its data classes.
fn rule_fingerprint(r: &Rule, doc: &PolicyDocument) -> Value {
    let objects: BTreeSet<Uuid> = resolve_objects(doc, &r.destinations);
    let objects: Vec<Value> = objects
        .into_iter()
        .map(|id| get(doc, Kind::Object, id).unwrap_or(Value::Null))
        .collect();
    let classes: Vec<Value> = r
        .data_classes
        .iter()
        .map(|id| get(doc, Kind::DataClass, *id).unwrap_or(Value::Null))
        .collect();
    serde_json::json!({"rule": r, "objects": objects, "classes": classes})
}

/// Widening changes of `draft` against `published`: accept rules that are broad in the draft
/// and new or different (rule, destinations or classes) from the published state. Removing a
/// baseline rule is a widening too.
pub fn widenings(published: &PolicyDocument, draft: &PolicyDocument) -> Vec<String> {
    let mut reasons = Vec::new();
    for r in &draft.rules {
        let Some(reason) = widening_reason(r, draft) else {
            continue;
        };
        let unchanged = published
            .rules
            .iter()
            .find(|p| p.id == r.id)
            .is_some_and(|p| rule_fingerprint(p, published) == rule_fingerprint(r, draft));
        if !unchanged {
            reasons.push(reason);
        }
    }
    for z in &draft.zones {
        let was_observe = published
            .zones
            .iter()
            .any(|p| p.id == z.id && p.mode == ZoneMode::Observe);
        if z.mode == ZoneMode::Observe && !was_observe {
            reasons.push(format!(
                "zone {:?} switched to observe mode (nothing denied)",
                z.name
            ));
        }
    }
    for p in &published.rules {
        if p.layer == Layer::Baseline && !draft.rules.iter().any(|r| r.id == p.id) {
            reasons.push(format!("baseline rule {:?} removed", p.name));
        }
    }
    reasons
}
