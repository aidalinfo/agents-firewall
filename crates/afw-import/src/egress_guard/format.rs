//! Reconstructed egress-guard « v2 egress-first » format (see
//! `examples/egress-guard/guardrails.example.yaml` and ADR 0026). Every struct collects unknown
//! fields in `extra` so they can be reported, never silently ignored.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_yaml::{Mapping, Value};

pub(crate) type Extra = BTreeMap<String, Value>;

#[derive(Deserialize, Debug, Default)]
pub(crate) struct Root {
    #[serde(default)]
    pub version: Option<Value>,
    #[serde(default)]
    pub profile: Option<Value>,
    #[serde(default)]
    pub name: Option<Value>,
    #[serde(default)]
    pub description: Option<Value>,
    #[serde(default)]
    pub senders: Option<Value>,
    #[serde(default)]
    pub tiers: Option<Mapping>,
    #[serde(default)]
    pub data_classes: Option<Mapping>,
    #[serde(default)]
    pub destinations: Option<Destinations>,
    #[serde(default)]
    pub matrix: Option<Mapping>,
    #[serde(default)]
    pub action_classes: Option<Mapping>,
    #[serde(default)]
    pub logging: Option<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Deserialize, Debug, Default)]
pub(crate) struct Destinations {
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub allow: Vec<HostEntry>,
    #[serde(default)]
    pub deny: Vec<HostEntry>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum HostEntry {
    Bare(String),
    Full(HostSpec),
}

#[derive(Deserialize, Debug)]
pub(crate) struct HostSpec {
    pub host: String,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl HostEntry {
    pub fn parts(&self) -> (&str, Option<&str>, &[u16], Option<&str>, Option<&Extra>) {
        match self {
            HostEntry::Bare(h) => (h, None, &[], None, None),
            HostEntry::Full(s) => (
                &s.host,
                s.tier.as_deref(),
                &s.ports,
                s.comment.as_deref(),
                Some(&s.extra),
            ),
        }
    }
}

#[derive(Deserialize, Debug, Default)]
pub(crate) struct TierSpec {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Deserialize, Debug, Default)]
pub(crate) struct DataClassSpec {
    #[serde(default, alias = "label")]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub patterns: Vec<PatternEntry>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum PatternEntry {
    Bare(String),
    Full(PatternSpec),
}

#[derive(Deserialize, Debug)]
pub(crate) struct PatternSpec {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(alias = "pattern")]
    pub regex: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Deserialize, Debug, Default)]
pub(crate) struct ActionClassSpec {
    #[serde(default, alias = "label")]
    pub name: Option<String>,
    /// Known field without equivalent in the intent policy format (kept out of warnings).
    #[allow(dead_code)]
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(flatten)]
    pub extra: Extra,
}
