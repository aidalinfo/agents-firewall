//! Policy model: objects, services, data classes, zones, agents, rules, inspection rules and
//! settings. A [`PolicyDocument`] is the complete publishable set (plan §3.1).

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Network object: a destination (or group of destinations) referenced by rules.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NetObject {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub category: Option<DestCategory>,
    pub spec: NetObjectSpec,
}

/// What a network object matches.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetObjectSpec {
    /// Exact domain or wildcard (`*.example.com` matches sub-domains only).
    Domain {
        pattern: String,
    },
    Host {
        ip: IpAddr,
    },
    Network {
        #[schemars(with = "String")]
        cidr: IpNet,
    },
    /// Inclusive address range.
    Range {
        start: IpAddr,
        end: IpAddr,
    },
    Group {
        members: Vec<Uuid>,
    },
    Any,
}

/// Destination category. `LlmProvider` carries the data-class exemption (EF-25).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DestCategory {
    LlmProvider,
    CloudMetadata,
    Internal,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Service {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub comment: String,
    pub protocol: L4Proto,
    /// Empty = any port.
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub app: Option<AppMatch>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum L4Proto {
    Tcp,
    Udp,
    Any,
}

/// Inclusive port range.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

/// Application-level match (method and path prefixes apply to HTTP/HTTPS only).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AppMatch {
    pub proto: AppProto,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AppProto {
    Http,
    Https,
    Dns,
    Ssh,
    Tls,
    Other,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DataClass {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub comment: String,
    pub category: DataCategory,
    pub detectors: Vec<Detector>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    Secret,
    Infra,
    Commercial,
    Personal,
    Custom,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Detector {
    /// Built-in detector of `afw-dlp`, by id (e.g. `aws_access_key`).
    Builtin {
        id: String,
    },
    Regex {
        name: String,
        pattern: String,
    },
}

/// A zone groups agents (VLAN-like). A rule's source is always a zone, never an agent.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Zone {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub comment: String,
    pub mode: ZoneMode,
    #[serde(default)]
    pub delegated_to_mcp: bool,
}

/// `Observe`: denials are logged but the flow is allowed (EF-12).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ZoneMode {
    Enforce,
    Observe,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Agent {
    pub id: Uuid,
    pub name: String,
    pub zone_id: Uuid,
    pub kind: AgentKind,
    #[serde(default)]
    pub gateway_id: Option<Uuid>,
    /// Source addresses identifying the agent on the gateway's internal network.
    #[serde(default)]
    pub addresses: Vec<IpAddr>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub hermes: bool,
    #[serde(default)]
    pub mcp_admin: bool,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    DockerCompose,
    Coolify,
    Kubernetes,
    Container,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Rule {
    pub id: Uuid,
    pub name: String,
    pub layer: Layer,
    #[serde(default)]
    pub section: Option<String>,
    pub position: u32,
    /// Zones. Empty = all zones, allowed only in the baseline layer.
    #[serde(default)]
    pub sources: Vec<Uuid>,
    /// Objects. Empty = any.
    #[serde(default)]
    pub destinations: Vec<Uuid>,
    /// Services. Empty = any.
    #[serde(default)]
    pub services: Vec<Uuid>,
    /// Data classes. Empty = no content condition.
    #[serde(default)]
    pub data_classes: Vec<Uuid>,
    pub action: Action,
    #[serde(default)]
    pub track: Track,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub comment: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Layer {
    Baseline,
    Zone { zone_id: Uuid },
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Accept,
    Deny,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum Track {
    None,
    Log,
    #[default]
    Detailed,
    Capture,
}

/// TLS inspection rule. Implicit default when nothing matches: `Inspect` (EF-09).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InspectionRule {
    pub id: Uuid,
    pub name: String,
    pub position: u32,
    /// Empty = all zones.
    #[serde(default)]
    pub zones: Vec<Uuid>,
    /// Empty = any destination.
    #[serde(default)]
    pub destinations: Vec<Uuid>,
    pub action: InspectionAction,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum InspectionAction {
    #[default]
    Inspect,
    Bypass,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PolicySettings {
    #[schemars(with = "Vec<String>")]
    pub internal_networks: Vec<IpNet>,
    pub max_buffered_body: u64,
    pub max_stored_body: u64,
    pub retention_days: Retention,
}

impl Default for PolicySettings {
    fn default() -> Self {
        let internal_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
            .iter()
            .map(|n| n.parse().expect("valid built-in CIDR"))
            .collect();
        Self {
            internal_networks,
            max_buffered_body: 1024 * 1024,
            max_stored_body: 256 * 1024,
            retention_days: Retention::default(),
        }
    }
}

/// Retention in days per kind of stored data.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Retention {
    pub flows: u32,
    pub http: u32,
    pub captures: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            flows: 30,
            http: 14,
            captures: 7,
        }
    }
}

/// The complete publishable policy.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PolicyDocument {
    #[serde(default)]
    pub objects: Vec<NetObject>,
    #[serde(default)]
    pub services: Vec<Service>,
    #[serde(default)]
    pub data_classes: Vec<DataClass>,
    #[serde(default)]
    pub zones: Vec<Zone>,
    #[serde(default)]
    pub agents: Vec<Agent>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub inspection_rules: Vec<InspectionRule>,
    #[serde(default)]
    pub settings: PolicySettings,
}

/// Sort key of a rule for numbering: (layer order, zone name, zone id, position, rule id).
type RankKey = (u8, String, Uuid, u32, Uuid);

impl PolicyDocument {
    /// Displayed rule numbers (global rank, starting at 1): baseline rules by position, then
    /// each zone layer ordered by zone name (then zone id), its rules by position. Ties on
    /// position are broken by rule id so numbering is deterministic. Disabled and expired
    /// rules are numbered too.
    pub fn rule_numbers(&self) -> BTreeMap<Uuid, u32> {
        let zone_name = |id: &Uuid| -> String {
            self.zones
                .iter()
                .find(|z| z.id == *id)
                .map(|z| z.name.clone())
                .unwrap_or_default()
        };
        // Sort key: (0 for baseline / 1 for zone, zone name, zone id, position, rule id).
        let mut keyed: Vec<(RankKey, Uuid)> = self
            .rules
            .iter()
            .map(|r| {
                let key = match r.layer {
                    Layer::Baseline => (0, String::new(), Uuid::nil(), r.position, r.id),
                    Layer::Zone { zone_id } => (1, zone_name(&zone_id), zone_id, r.position, r.id),
                };
                (key, r.id)
            })
            .collect();
        keyed.sort();
        keyed
            .into_iter()
            .enumerate()
            .map(|(i, (_, id))| (id, i as u32 + 1))
            .collect()
    }
}
