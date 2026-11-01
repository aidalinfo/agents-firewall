//! Generic access to the entities of a [`PolicyDocument`] by kind and id, as JSON values.

use afw_core::api::{ResourceKind, ResourceRef};
use afw_core::policy::{
    Agent, DataClass, InspectionRule, NetObject, PolicyDocument, PolicySettings, Rule, Service,
    Zone,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use uuid::Uuid;

use crate::error::ApiError;

/// Kind of policy entity. `Settings` is a singleton with the nil id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Object,
    Service,
    DataClass,
    Zone,
    Agent,
    Rule,
    InspectionRule,
    Settings,
}

pub const ALL_KINDS: [Kind; 8] = [
    Kind::Zone,
    Kind::Object,
    Kind::Service,
    Kind::DataClass,
    Kind::Agent,
    Kind::Rule,
    Kind::InspectionRule,
    Kind::Settings,
];

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Object => "object",
            Kind::Service => "service",
            Kind::DataClass => "data_class",
            Kind::Zone => "zone",
            Kind::Agent => "agent",
            Kind::Rule => "rule",
            Kind::InspectionRule => "inspection_rule",
            Kind::Settings => "settings",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        ALL_KINDS.into_iter().find(|k| k.as_str() == s)
    }

    pub fn resource(self) -> ResourceKind {
        match self {
            Kind::Object => ResourceKind::Object,
            Kind::Service => ResourceKind::Service,
            Kind::DataClass => ResourceKind::DataClass,
            Kind::Zone => ResourceKind::Zone,
            Kind::Agent => ResourceKind::Agent,
            Kind::Rule => ResourceKind::Rule,
            Kind::InspectionRule => ResourceKind::InspectionRule,
            Kind::Settings => ResourceKind::Settings,
        }
    }
}

trait Entity: Serialize + DeserializeOwned {
    fn id(&self) -> Uuid;
}

macro_rules! entity {
    ($($t:ty),*) => { $( impl Entity for $t { fn id(&self) -> Uuid { self.id } } )* };
}
entity!(
    NetObject,
    Service,
    DataClass,
    Zone,
    Agent,
    Rule,
    InspectionRule
);

fn to_value<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("policy types serialize to JSON")
}

fn find<T: Entity>(v: &[T], id: Uuid) -> Option<Value> {
    v.iter().find(|x| x.id() == id).map(to_value)
}

fn upsert<T: Entity>(v: &mut Vec<T>, value: Value) -> Result<(), ApiError> {
    let item: T =
        serde_json::from_value(value).map_err(|e| ApiError::BadRequest(format!("invalid: {e}")))?;
    match v.iter_mut().find(|x| x.id() == item.id()) {
        Some(slot) => *slot = item,
        None => v.push(item),
    }
    Ok(())
}

fn all<T: Entity>(v: &[T]) -> Vec<(Uuid, Value)> {
    v.iter().map(|x| (x.id(), to_value(x))).collect()
}

/// Entity `id` of `kind` in `doc`, as JSON.
pub fn get(doc: &PolicyDocument, kind: Kind, id: Uuid) -> Option<Value> {
    match kind {
        Kind::Object => find(&doc.objects, id),
        Kind::Service => find(&doc.services, id),
        Kind::DataClass => find(&doc.data_classes, id),
        Kind::Zone => find(&doc.zones, id),
        Kind::Agent => find(&doc.agents, id),
        Kind::Rule => find(&doc.rules, id),
        Kind::InspectionRule => find(&doc.inspection_rules, id),
        Kind::Settings => id.is_nil().then(|| to_value(&doc.settings)),
    }
}

/// Inserts or replaces an entity (`None` removes it). Errors on a value of the wrong shape.
pub fn set(
    doc: &mut PolicyDocument,
    kind: Kind,
    id: Uuid,
    value: Option<Value>,
) -> Result<(), ApiError> {
    let Some(value) = value else {
        match kind {
            Kind::Object => doc.objects.retain(|x| x.id != id),
            Kind::Service => doc.services.retain(|x| x.id != id),
            Kind::DataClass => doc.data_classes.retain(|x| x.id != id),
            Kind::Zone => doc.zones.retain(|x| x.id != id),
            Kind::Agent => doc.agents.retain(|x| x.id != id),
            Kind::Rule => doc.rules.retain(|x| x.id != id),
            Kind::InspectionRule => doc.inspection_rules.retain(|x| x.id != id),
            Kind::Settings => doc.settings = PolicySettings::default(),
        }
        return Ok(());
    };
    match kind {
        Kind::Object => upsert(&mut doc.objects, value),
        Kind::Service => upsert(&mut doc.services, value),
        Kind::DataClass => upsert(&mut doc.data_classes, value),
        Kind::Zone => upsert(&mut doc.zones, value),
        Kind::Agent => upsert(&mut doc.agents, value),
        Kind::Rule => upsert(&mut doc.rules, value),
        Kind::InspectionRule => upsert(&mut doc.inspection_rules, value),
        Kind::Settings => {
            doc.settings = serde_json::from_value(value)
                .map_err(|e| ApiError::BadRequest(format!("invalid: {e}")))?;
            Ok(())
        }
    }
}

/// Every entity of `kind` (settings: one entry with the nil id).
pub fn list(doc: &PolicyDocument, kind: Kind) -> Vec<(Uuid, Value)> {
    match kind {
        Kind::Object => all(&doc.objects),
        Kind::Service => all(&doc.services),
        Kind::DataClass => all(&doc.data_classes),
        Kind::Zone => all(&doc.zones),
        Kind::Agent => all(&doc.agents),
        Kind::Rule => all(&doc.rules),
        Kind::InspectionRule => all(&doc.inspection_rules),
        Kind::Settings => vec![(Uuid::nil(), to_value(&doc.settings))],
    }
}

/// Display name of an entity value.
pub fn name_of(kind: Kind, value: Option<&Value>) -> String {
    if kind == Kind::Settings {
        return "settings".to_owned();
    }
    value
        .and_then(|v| v.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

pub fn resource_ref(kind: Kind, id: Uuid, value: Option<&Value>) -> ResourceRef {
    ResourceRef {
        kind: kind.resource(),
        id,
        name: name_of(kind, value),
    }
}

/// Parses a JSON value into a policy type, as a 400 on failure.
pub fn parse<T: DeserializeOwned>(value: Value) -> Result<T, ApiError> {
    serde_json::from_value(value).map_err(|e| ApiError::BadRequest(format!("invalid body: {e}")))
}

pub fn value<T: Serialize>(v: &T) -> Value {
    to_value(v)
}
