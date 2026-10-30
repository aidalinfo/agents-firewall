//! Rights of the MCP administration agent on policy changes (EF-51) and detection of the
//! widening changes that need a human approval (EF-52).
//!
//! Every change is checked when it is made AND again, as a diff against the current published
//! revision, when the session is published (the delegation may have changed in between).

use std::collections::{BTreeSet, HashSet};

use afw_core::api::Role;
use afw_core::policy::{
    Action, Agent, DataCategory, InspectionRule, Layer, NetObjectSpec, PolicyDocument, Rule, Zone,
};
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
    for id in resolve_objects(doc, &r.destinations) {
        let Some(o) = doc.objects.iter().find(|o| o.id == id) else {
            continue;
        };
        let broad = match &o.spec {
            NetObjectSpec::Any => true,
            NetObjectSpec::Domain { pattern } => {
                pattern == "*"
                    || pattern
                        .strip_prefix("*.")
                        .is_some_and(|rest| !rest.contains('.'))
            }
            NetObjectSpec::Network { cidr } => cidr.prefix_len() == 0,
            _ => false,
        };
        if broad {
            return Some(format!(
                "rule {:?} accepts the broad destination {:?}",
                r.name, o.name
            ));
        }
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
    for p in &published.rules {
        if p.layer == Layer::Baseline && !draft.rules.iter().any(|r| r.id == p.id) {
            reasons.push(format!("baseline rule {:?} removed", p.name));
        }
    }
    reasons
}
