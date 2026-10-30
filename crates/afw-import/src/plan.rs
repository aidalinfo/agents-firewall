//! Import plan: the resources to create or update, applied by the API inside one session.

use std::collections::BTreeSet;

use afw_core::api::IntentPolicy;
use afw_core::policy::{
    DataClass, Layer, NetObject, NetObjectSpec, PolicyDocument, Rule, Service, Zone,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::report::ImportReport;

/// What happens to the imported zone.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZoneChange {
    Create,
    Update,
    Unchanged,
}

/// Result of an import. Every id is final: rules reference objects, services, data classes and
/// the zone by these ids (new ones, or ids of reused existing resources).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ImportPlan {
    /// Objects to create, or existing groups to update (ids in `updated`). Leaf objects come
    /// before the groups that reference them. Reused unchanged objects are not listed.
    pub objects: Vec<NetObject>,
    /// Services to create.
    pub services: Vec<Service>,
    /// Data classes to create.
    pub data_classes: Vec<DataClass>,
    /// The imported zone (new or existing, with the requested mode).
    pub zone: Zone,
    pub zone_change: ZoneChange,
    /// Rules to create: baseline (denied hosts, scoped to the zone) then zone rules (content
    /// rules from the matrix, then destination accepts). Default deny is the implicit cleanup.
    pub rules: Vec<Rule>,
    /// Intent policy for the Hermes plugin (ADR 0015). Not a session resource: served by
    /// `GET /intent-policy`; the CLI stores it separately.
    pub intent_policy: IntentPolicy,
    pub report: ImportReport,
    /// Ids of existing objects updated by the plan.
    pub updated: BTreeSet<Uuid>,
}

/// One operation to apply through the API inside an open session, in order.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "op", content = "resource", rename_all = "snake_case")]
pub enum SessionChange {
    CreateService(Service),
    CreateObject(NetObject),
    UpdateObject(NetObject),
    CreateDataClass(DataClass),
    CreateZone(Zone),
    UpdateZone(Zone),
    CreateRule(Rule),
}

impl SessionChange {
    /// HTTP method and path (under `/api/v1`) of the operation.
    pub fn endpoint(&self) -> (&'static str, String) {
        match self {
            SessionChange::CreateService(_) => ("POST", "/services".into()),
            SessionChange::CreateObject(_) => ("POST", "/objects".into()),
            SessionChange::UpdateObject(o) => ("PUT", format!("/objects/{}", o.id)),
            SessionChange::CreateDataClass(_) => ("POST", "/data-classes".into()),
            SessionChange::CreateZone(_) => ("POST", "/zones".into()),
            SessionChange::UpdateZone(z) => ("PUT", format!("/zones/{}", z.id)),
            SessionChange::CreateRule(_) => ("POST", "/rules".into()),
        }
    }
}

impl ImportPlan {
    /// Operations in dependency order: services, leaf objects, groups, data classes, zone,
    /// rules (baseline first, then zone rules by position).
    pub fn to_session_changes(&self) -> Vec<SessionChange> {
        let mut out = Vec::new();
        out.extend(
            self.services
                .iter()
                .cloned()
                .map(SessionChange::CreateService),
        );
        let is_group = |o: &NetObject| matches!(o.spec, NetObjectSpec::Group { .. });
        let object_change = |o: &NetObject| {
            if self.updated.contains(&o.id) {
                SessionChange::UpdateObject(o.clone())
            } else {
                SessionChange::CreateObject(o.clone())
            }
        };
        out.extend(
            self.objects
                .iter()
                .filter(|o| !is_group(o))
                .map(object_change),
        );
        out.extend(
            self.objects
                .iter()
                .filter(|o| is_group(o))
                .map(object_change),
        );
        out.extend(
            self.data_classes
                .iter()
                .cloned()
                .map(SessionChange::CreateDataClass),
        );
        match self.zone_change {
            ZoneChange::Create => out.push(SessionChange::CreateZone(self.zone.clone())),
            ZoneChange::Update => out.push(SessionChange::UpdateZone(self.zone.clone())),
            ZoneChange::Unchanged => {}
        }
        let mut rules: Vec<&Rule> = self.rules.iter().collect();
        rules.sort_by_key(|r| (r.layer != Layer::Baseline, r.position));
        out.extend(rules.into_iter().cloned().map(SessionChange::CreateRule));
        out
    }

    /// `false` when a `deny`/`gate` of the source is not enforced by the plan
    /// (`report.blocking`): the CLI must not publish such a plan without review.
    pub fn is_safe(&self) -> bool {
        self.report.blocking.is_empty()
    }

    /// Policy fragment sent to `POST /sessions/{id}/import`: objects (created or updated),
    /// services, data classes, the zone and the rules. `agents` is empty and `settings` is the
    /// default value: both are placeholders the API must ignore (an import never changes
    /// agents nor settings). The intent policy is not part of it (`PUT /intent-policy`).
    pub fn to_policy_fragment(&self) -> PolicyDocument {
        PolicyDocument {
            objects: self.objects.clone(),
            services: self.services.clone(),
            data_classes: self.data_classes.clone(),
            zones: vec![self.zone.clone()],
            agents: Vec::new(),
            rules: self.rules.clone(),
            inspection_rules: Vec::new(),
            settings: Default::default(),
        }
    }

    /// The document `base` would become once the plan is applied (dry run, tests).
    pub fn merged_into(&self, base: &PolicyDocument) -> PolicyDocument {
        let mut doc = base.clone();
        for o in &self.objects {
            match doc.objects.iter_mut().find(|x| x.id == o.id) {
                Some(x) => *x = o.clone(),
                None => doc.objects.push(o.clone()),
            }
        }
        doc.services.extend(self.services.iter().cloned());
        doc.data_classes.extend(self.data_classes.iter().cloned());
        match doc.zones.iter_mut().find(|z| z.id == self.zone.id) {
            Some(z) => *z = self.zone.clone(),
            None => doc.zones.push(self.zone.clone()),
        }
        doc.rules.extend(self.rules.iter().cloned());
        doc
    }
}
