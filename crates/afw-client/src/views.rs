//! Response types decoded tolerantly.
//!
//! The rule listing may return either plain `Rule`s or rule *views* (the rule flattened with
//! display fields such as `number` and `hits`). `Rule` refuses unknown fields, so the view
//! fields are split off before decoding the rule (ADR 0025).

use afw_core::api::{Approval, Revision};
use afw_core::policy::{NetObject, Rule};
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use crate::ClientError;

/// Fields a rule view may add next to the rule itself.
const RULE_VIEW_FIELDS: &[&str] = &[
    "number",
    "hits",
    "last_hit_at",
    "expired",
    "locked_by",
    "pending_change",
];

/// A rule as listed by the API, with its optional display fields.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleEntry {
    pub rule: Rule,
    /// Displayed global number, when the API provides it.
    pub number: Option<u32>,
    /// Hits reported by the gateways, when the API provides them.
    pub hits: Option<u64>,
    /// Other display fields (`last_hit_at`, `expired`, `locked_by`, `pending_change`…).
    pub view: Map<String, Value>,
    /// The JSON object as received.
    pub raw: Value,
}

impl RuleEntry {
    /// Decodes a `Rule` or a rule view.
    pub fn from_value(raw: Value) -> Result<Self, ClientError> {
        let Value::Object(mut obj) = raw.clone() else {
            return Err(decode("a rule must be a JSON object"));
        };
        let mut view = Map::new();
        for f in RULE_VIEW_FIELDS {
            if let Some(v) = obj.remove(*f) {
                view.insert((*f).to_string(), v);
            }
        }
        let rule: Rule =
            serde_json::from_value(Value::Object(obj)).map_err(|e| decode(&e.to_string()))?;
        Ok(Self {
            rule,
            number: view
                .get("number")
                .and_then(Value::as_u64)
                .map(|n| n as u32),
            hits: view.get("hits").and_then(Value::as_u64),
            view,
            raw,
        })
    }
}

impl Serialize for RuleEntry {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.raw.serialize(s)
    }
}

/// Result of `POST /sessions/{id}/allow-from-log` (EF-42).
#[derive(Clone, Debug, PartialEq)]
pub struct AllowOutcome {
    pub rule: RuleEntry,
    pub created_object: Option<NetObject>,
    pub raw: Value,
}

impl AllowOutcome {
    pub(crate) fn from_value(raw: Value) -> Result<Self, ClientError> {
        let rule = RuleEntry::from_value(
            raw.get("rule")
                .cloned()
                .ok_or_else(|| decode("missing `rule`"))?,
        )?;
        let created_object = match raw.get("created_object") {
            None | Some(Value::Null) => None,
            Some(v) => Some(serde_json::from_value(v.clone()).map_err(|e| decode(&e.to_string()))?),
        };
        Ok(Self {
            rule,
            created_object,
            raw,
        })
    }
}

impl Serialize for AllowOutcome {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.raw.serialize(s)
    }
}

/// Result of `POST /sessions/{id}/publish`: a new revision (201) or, for a widening change
/// requested by the MCP agent, the human approval it now waits for (202, EF-52).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PublishOutcome {
    Published { revision: Revision },
    PendingApproval { approval: Approval },
}

fn decode(message: &str) -> ClientError {
    ClientError::Decode {
        status: 200,
        message: message.to_string(),
    }
}
